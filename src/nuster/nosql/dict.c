/*
 * nuster nosql dict functions.
 *
 * Copyright (C) Jiang Wenyuan, < koubunen AT gmail DOT com >
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <types/global.h>

#include <nuster/nuster.h>


static int _nst_nosql_dict_alloc(uint64_t size) {
    int i;
    int entry_size = sizeof(struct nst_nosql_entry*);
    int block_size = global.nuster.nosql.memory->block_size;

    nuster.nosql->dict[0].size  = size / entry_size;
    nuster.nosql->dict[0].used  = 0;
    nuster.nosql->dict[0].entry = nst_nosql_memory_alloc(block_size);

    if(!nuster.nosql->dict[0].entry) {
        return NST_ERR;
    }

    for(i = 1; i < size / block_size; i++) {
        if(!nst_nosql_memory_alloc(block_size)) {
            return NST_ERR;
        }
    }

    for(i = 0; i < nuster.nosql->dict[0].size; i++) {
        nuster.nosql->dict[0].entry[i] = NULL;
    }

    return nst_shctx_init((&nuster.nosql->dict[0]));
}

int nst_nosql_dict_init() {
    int block_size = global.nuster.nosql.memory->block_size;
    int dict_size = global.nuster.nosql.dict_size;
    int size = (block_size + dict_size - 1) / block_size * block_size;

    return _nst_nosql_dict_alloc(size);
}

static int _nst_nosql_dict_rehashing() {
    return 0;
    //return nuster.nosql->rehash_idx != -1;
}

/*
 * Check entry validity, free the entry if its invalid,
 * If its invalid set entry->data->invalid to true,
 * entry->data is freed by _nosql_data_cleanup
 */
void nst_nosql_dict_cleanup() {
    struct nst_nosql_entry *entry = nuster.nosql->dict[0].entry[nuster.nosql->cleanup_idx];

    struct nst_nosql_entry *prev  = entry;

    if(!nuster.nosql->dict[0].used) {
        return;
    }

    while(entry) {

        if(nst_nosql_entry_invalid(entry)) {
            struct nst_nosql_entry *tmp = entry;

            if(entry->data) {
                entry->data->invalid = 1;
            }

            if(prev == entry) {
                nuster.nosql->dict[0].entry[nuster.nosql->cleanup_idx] = entry->next;

                prev = entry->next;
            } else {
                prev->next = entry->next;
            }

            entry = entry->next;

            nst_nosql_memory_free(tmp->buf.area);
            nst_nosql_memory_free(tmp->key.data);
            nst_nosql_memory_free(tmp);

            nuster.nosql->dict[0].used--;
        } else {
            prev  = entry;
            entry = entry->next;
        }
    }

    nuster.nosql->cleanup_idx++;

    /* if we have checked the whole dict */
    if(nuster.nosql->cleanup_idx == nuster.nosql->dict[0].size) {
        nuster.nosql->cleanup_idx = 0;
    }
}

/*
 * Add a new nst_nosql_entry to nosql_dict
 */
struct nst_nosql_entry *nst_nosql_dict_set(struct nst_nosql_ctx *ctx) {

    struct nst_nosql_dict  *dict  = NULL;
    struct nst_nosql_data  *data  = NULL;
    struct nst_nosql_entry *entry = NULL;

    struct nst_key key = { .data = NULL };
    struct buffer buf  = { .area = NULL };
    int idx;

    dict = _nst_nosql_dict_rehashing() ? &nuster.nosql->dict[1] : &nuster.nosql->dict[0];

    idx = ctx->rule->key->idx;

    key.size = ctx->keys[idx].size;
    key.hash = ctx->keys[idx].hash;
    key.data = nst_nosql_memory_alloc(key.size);

    if(!key.data) {
        goto err;
    }

    memcpy(key.data, ctx->keys[idx].data, key.size);

    buf.size = ctx->txn.buf->data;
    buf.data = ctx->txn.buf->data;
    buf.area = nst_nosql_memory_alloc(buf.size);

    if(!buf.area) {
        goto err;
    }

    memcpy(buf.area, ctx->txn.buf->area, buf.data);

    entry = nst_nosql_memory_alloc(sizeof(*entry));

    if(!entry) {
        goto err;
    }

    data = nst_nosql_data_new();

    if(!data) {
        goto err;
    }

    memset(entry, 0, sizeof(*entry));

    idx = key.hash % dict->size;

    /* prepend entry to dict->entry[idx] */
    entry->next      = dict->entry[idx];
    dict->entry[idx] = entry;
    dict->used++;

    /* init entry */
    entry->data   = data;
    entry->state  = NST_NOSQL_ENTRY_STATE_CREATING;
    entry->expire = 0;
    entry->rule   = ctx->rule;
    entry->pid    = ctx->pid;
    entry->key    = key;

    entry->header_len = ctx->txn.res.header_len;

    entry->buf = buf;

    entry->host.ptr = buf.area + (ctx->txn.req.host.ptr - ctx->txn.buf->area);
    entry->host.len = ctx->txn.req.host.len;

    entry->path.ptr = buf.area + (ctx->txn.req.path.ptr - ctx->txn.buf->area);
    entry->path.len = ctx->txn.req.path.len;

    return entry;

err:

    nst_nosql_memory_free(key.data);
    nst_nosql_memory_free(buf.area);
    nst_nosql_memory_free(entry);

    return NULL;
}

/*
 * Get entry
 */
struct nst_nosql_entry *nst_nosql_dict_get(struct nst_key *key) {
    int i, idx;
    struct nst_nosql_entry *entry = NULL;

    if(nuster.nosql->dict[0].used + nuster.nosql->dict[1].used == 0) {
        return NULL;
    }

    for(i = 0; i <= 1; i++) {
        idx   = key->hash % nuster.nosql->dict[i].size;
        entry = nuster.nosql->dict[i].entry[idx];

        while(entry) {

            if(entry->key.hash == key->hash
                    && entry->key.size == key->size
                    && !memcmp(entry->key.data, key->data, key->size)) {
                /* check expire
                 * change state only, leave the free stuff to cleanup
                 * */
                if(entry->state == NST_NOSQL_ENTRY_STATE_VALID
                        && nst_nosql_dict_entry_expired(entry)) {

                    entry->state         = NST_NOSQL_ENTRY_STATE_EXPIRED;
                    entry->data->invalid = 1;
                    entry->data          = NULL;
                    entry->expire        = 0;

                    return NULL;
                }

                return entry;
            }

            entry = entry->next;
        }

        if(!_nst_nosql_dict_rehashing()) {
            return NULL;
        }
    }

    return NULL;
}

int nst_nosql_dict_set_from_disk(char *file, char *meta, struct nst_key *key) {
    int idx;
    struct nst_nosql_dict  *dict  = NULL;
    struct nst_nosql_entry *entry = NULL;
    uint64_t hash = nst_persist_meta_get_hash(meta);

    dict = _nst_nosql_dict_rehashing() ? &nuster.nosql->dict[1] : &nuster.nosql->dict[0];

    entry = nst_nosql_memory_alloc(sizeof(*entry));

    if(!entry) {
        return NST_ERR;
    }

    memset(entry, 0, sizeof(*entry));

    entry->file = nst_nosql_memory_alloc(strlen(file));

    if(!entry->file) {
        return NST_ERR;
    }

    idx = hash % dict->size;
    /* prepend entry to dict->entry[idx] */
    entry->next      = dict->entry[idx];
    dict->entry[idx] = entry;
    dict->used++;

    /* init entry */
    entry->state  = NST_NOSQL_ENTRY_STATE_INVALID;
    entry->expire = nst_persist_meta_get_expire(meta);
    memcpy(entry->file, file, strlen(file));

    entry->header_len = nst_persist_meta_get_header_len(meta);

    return NST_OK;
}

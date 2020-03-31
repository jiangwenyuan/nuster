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
    int entry_size = sizeof(struct nst_dict_entry*);
    int block_size = global.nuster.nosql.memory->block_size;

    nuster.nosql->dict.size  = size / entry_size;
    nuster.nosql->dict.used  = 0;
    nuster.nosql->dict.entry = nst_nosql_memory_alloc(block_size);

    if(!nuster.nosql->dict.entry) {
        return NST_ERR;
    }

    for(i = 1; i < size / block_size; i++) {
        if(!nst_nosql_memory_alloc(block_size)) {
            return NST_ERR;
        }
    }

    for(i = 0; i < nuster.nosql->dict.size; i++) {
        nuster.nosql->dict.entry[i] = NULL;
    }

    return nst_shctx_init((&nuster.nosql->dict));
}

int nst_nosql_dict_init() {
    int block_size = global.nuster.nosql.memory->block_size;
    int dict_size = global.nuster.nosql.dict_size;
    int size = (block_size + dict_size - 1) / block_size * block_size;

    return _nst_nosql_dict_alloc(size);
}

/*
 * Check entry validity, free the entry if its invalid,
 * If its invalid set entry->data->invalid to true,
 * entry->data is freed by _nosql_data_cleanup
 */
void nst_nosql_dict_cleanup() {
    struct nst_dict_entry *entry = nuster.nosql->dict.entry[nuster.nosql->cleanup_idx];

    struct nst_dict_entry *prev  = entry;

    if(!nuster.nosql->dict.used) {
        return;
    }

    while(entry) {

        if(nst_dict_entry_invalid(entry)) {
            struct nst_dict_entry *tmp = entry;

            if(entry->data) {
                entry->data->invalid = 1;
            }

            if(prev == entry) {
                nuster.nosql->dict.entry[nuster.nosql->cleanup_idx] = entry->next;
                prev = entry->next;
            } else {
                prev->next = entry->next;
            }

            entry = entry->next;

            nst_nosql_memory_free(tmp->buf.area);
            nst_nosql_memory_free(tmp->key.data);
            nst_nosql_memory_free(tmp);

            nuster.nosql->dict.used--;
        } else {
            prev  = entry;
            entry = entry->next;
        }
    }

    nuster.nosql->cleanup_idx++;

    /* if we have checked the whole dict */
    if(nuster.nosql->cleanup_idx == nuster.nosql->dict.size) {
        nuster.nosql->cleanup_idx = 0;
    }
}

struct nst_dict_entry *nst_nosql_dict_set(struct nst_nosql_ctx *ctx) {
    struct nst_dict *dict  = NULL;
    struct nst_data  *data  = NULL;
    struct nst_dict_entry *entry = NULL;
    struct nst_key key = { .data = NULL };
    struct buffer buf  = { .area = NULL };
    int idx;

    dict = &nuster.nosql->dict;

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

    memset(entry, 0, sizeof(*entry));

    if(ctx->rule->disk != NST_DISK_ONLY) {
        data = nst_nosql_data_new();

        if(!data) {
            goto err;
        }
    }

    idx = key.hash % dict->size;

    /* prepend entry to dict->entry[idx] */
    entry->next      = dict->entry[idx];
    dict->entry[idx] = entry;
    dict->used++;

    /* init entry */
    entry->data   = data;
    entry->state  = NST_DICT_ENTRY_STATE_CREATING;
    entry->expire = 0;
    entry->pid    = ctx->pid;
    entry->file   = NULL;
    entry->ttl    = ctx->rule->ttl;

    entry->key    = key;
    entry->rule   = ctx->rule;

    entry->extend[0] = ctx->rule->extend[0];
    entry->extend[1] = ctx->rule->extend[1];
    entry->extend[2] = ctx->rule->extend[2];
    entry->extend[3] = ctx->rule->extend[3];

    entry->header_len = ctx->txn.res.header_len;

    entry->buf = buf;

    entry->host.ptr = buf.area + (ctx->txn.req.host.ptr - ctx->txn.buf->area);
    entry->host.len = ctx->txn.req.host.len;

    entry->path.ptr = buf.area + (ctx->txn.req.path.ptr - ctx->txn.buf->area);
    entry->path.len = ctx->txn.req.path.len;

    entry->etag.ptr = buf.area + (ctx->txn.res.etag.ptr - ctx->txn.buf->area);
    entry->etag.len = ctx->txn.res.etag.len;

    entry->last_modified.ptr = buf.area + (ctx->txn.res.last_modified.ptr - ctx->txn.buf->area);
    entry->last_modified.len = ctx->txn.res.last_modified.len;

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
struct nst_dict_entry *nst_nosql_dict_get(struct nst_key *key) {
    struct nst_dict_entry  *entry = NULL;
    int                     idx;

    if(nuster.nosql->dict.used == 0) {
        return NULL;
    }

    idx   = key->hash % nuster.nosql->dict.size;
    entry = nuster.nosql->dict.entry[idx];

    while(entry) {

        if(entry->key.hash == key->hash
                && entry->key.size == key->size
                && !memcmp(entry->key.data, key->data, key->size)) {
            /* check expire
             * change state only, leave the free stuff to cleanup
             * */
            if(entry->state == NST_DICT_ENTRY_STATE_VALID
                    && nst_dict_entry_expired(entry)) {

                entry->state         = NST_DICT_ENTRY_STATE_EXPIRED;
                entry->data->invalid = 1;
                entry->data          = NULL;
                entry->expire        = 0;

                return NULL;
            }

            return entry;
        }

        entry = entry->next;
    }

    return NULL;
}

int nst_nosql_dict_set_from_disk(struct nst_key *key, char *file, char *meta) {
    int idx;
    struct nst_dict  *dict  = NULL;
    struct nst_dict_entry *entry = NULL;

    key->hash = nst_persist_meta_get_hash(meta);

    dict = &nuster.nosql->dict;

    entry = nst_nosql_memory_alloc(sizeof(*entry));

    if(!entry) {
        return NST_ERR;
    }

    memset(entry, 0, sizeof(*entry));

    entry->file = nst_nosql_memory_alloc(strlen(file));

    if(!entry->file) {
        return NST_ERR;
    }

    idx = key->hash % dict->size;
    /* prepend entry to dict->entry[idx] */
    entry->next      = dict->entry[idx];
    dict->entry[idx] = entry;
    dict->used++;

    /* init entry */
    entry->state  = NST_DICT_ENTRY_STATE_INVALID;
    entry->key    = *key;
    entry->expire = nst_persist_meta_get_expire(meta);
    memcpy(entry->file, file, strlen(file));

    entry->header_len = nst_persist_meta_get_header_len(meta);

    return NST_OK;
}

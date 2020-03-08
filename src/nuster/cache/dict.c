/*
 * nuster cache dict functions.
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

#include <nuster/memory.h>
#include <nuster/shctx.h>
#include <nuster/nuster.h>
#include <nuster/persist.h>

static int _nst_cache_dict_alloc(uint64_t size) {
    int i;
    int entry_size = sizeof(struct nst_cache_entry*);
    int block_size = global.nuster.cache.memory->block_size;

    nuster.cache->dict[0].size  = size / entry_size;
    nuster.cache->dict[0].used  = 0;
    nuster.cache->dict[0].entry = nst_cache_memory_alloc(block_size);

    if(!nuster.cache->dict[0].entry) {
        return NST_ERR;
    }

    for(i = 1; i < size / block_size; i++) {

        if(!nst_cache_memory_alloc(block_size)) {
            return NST_ERR;
        }
    }

    for(i = 0; i < nuster.cache->dict[0].size; i++) {
        nuster.cache->dict[0].entry[i] = NULL;
    }

    return nst_shctx_init((&nuster.cache->dict[0]));
}

int nst_cache_dict_init() {
    int block_size = global.nuster.cache.memory->block_size;
    int dict_size = global.nuster.cache.dict_size;
    int size = (block_size + dict_size - 1) / block_size * block_size;

    return _nst_cache_dict_alloc(size);
}

static int _nst_cache_dict_rehashing() {
    return 0;
    //return nuster.cache->rehash_idx != -1;
}

/*
 * Check entry validity, free the entry if its invalid,
 * If its invalid set entry->data->invalid to true,
 * entry->data is freed by _cache_data_cleanup
 */
void nst_cache_dict_cleanup() {
    struct nst_cache_entry *entry = nuster.cache->dict[0].entry[nuster.cache->cleanup_idx];

    struct nst_cache_entry *prev  = entry;

    if(!nuster.cache->dict[0].used) {
        return;
    }

    while(entry) {

        if(nst_cache_entry_invalid(entry)) {
            struct nst_cache_entry *tmp = entry;

            if(entry->data) {
                entry->data->invalid = 1;
            }

            if(prev == entry) {
                nuster.cache->dict[0].entry[nuster.cache->cleanup_idx] = entry->next;
                prev = entry->next;
            } else {
                prev->next = entry->next;
            }

            entry = entry->next;
            nst_cache_memory_free(tmp->host.data);
            nst_cache_memory_free(tmp->path.data);
            nst_cache_memory_free(tmp);
            nuster.cache->dict[0].used--;
        } else {
            prev  = entry;
            entry = entry->next;
        }

    }

    nuster.cache->cleanup_idx++;

    /* if we have checked the whole dict */
    if(nuster.cache->cleanup_idx == nuster.cache->dict[0].size) {
        nuster.cache->cleanup_idx = 0;
    }

}

struct nst_cache_entry *nst_cache_dict_set(struct nst_cache_ctx *ctx) {
    struct nst_cache_dict  *dict  = NULL;
    struct nst_cache_data  *data  = NULL;
    struct nst_cache_entry *entry = NULL;
    int idx;
    struct nst_key *key;

    idx = ctx->rule->key->idx;
    key = &(ctx->keys[idx]);

    dict = _nst_cache_dict_rehashing() ? &nuster.cache->dict[1] : &nuster.cache->dict[0];

    entry = nst_cache_memory_alloc(sizeof(*entry));

    if(!entry) {
        return NULL;
    }

    memset(entry, 0, sizeof(*entry));

    if(ctx->rule->disk != NST_DISK_ONLY) {
        data = nst_cache_data_new();

        if(!data) {
            nst_cache_memory_free(entry);
            return NULL;
        }
    }

    idx = key->hash % dict->size;
    /* prepend entry to dict->entry[idx] */
    entry->next      = dict->entry[idx];
    dict->entry[idx] = entry;
    dict->used++;

    /* init entry */
    entry->data   = data;
    entry->state  = NST_CACHE_ENTRY_STATE_CREATING;
    entry->expire = 0;
    entry->pid    = ctx->pid;
    entry->file   = NULL;
    entry->ttl    = ctx->rule->ttl;

    entry->key  = *key;
    key->data   = NULL;
    entry->rule = ctx->rule;

    entry->extend[0] = ctx->rule->extend[0];
    entry->extend[1] = ctx->rule->extend[1];
    entry->extend[2] = ctx->rule->extend[2];
    entry->extend[3] = ctx->rule->extend[3];

    entry->header_len = ctx->header_len;

    entry->host.data   = ctx->req.host.data;
    entry->host.len    = ctx->req.host.len;
    ctx->req.host.data = NULL;

    entry->path.data   = ctx->req.path.data;
    entry->path.len    = ctx->req.path.len;
    ctx->req.path.data = NULL;

    entry->etag.data   = ctx->res.etag.data;
    entry->etag.len    = ctx->res.etag.len;
    ctx->res.etag.data = NULL;

    entry->last_modified.data   = ctx->res.last_modified.data;
    entry->last_modified.len    = ctx->res.last_modified.len;
    ctx->res.last_modified.data = NULL;

    return entry;
}

/*
 * Get entry
 */

struct nst_cache_entry *nst_cache_dict_get(struct nst_key *key) {
    int i, idx;
    struct nst_cache_entry *entry = NULL;

    if(nuster.cache->dict[0].used + nuster.cache->dict[1].used == 0) {
        return NULL;
    }

    for(i = 0; i <= 1; i++) {
        idx   = key->hash % nuster.cache->dict[i].size;
        entry = nuster.cache->dict[i].entry[idx];

        while(entry) {

            if(entry->key.hash == key->hash && entry->key.size == key->size
                    && !memcmp(entry->key.data, key->data, key->size)) {

                int expired = nst_cache_entry_expired(entry);

                uint64_t max = 1000 * entry->expire + 1000 * entry->ttl * entry->extend[3] / 100;

                entry->atime = get_current_timestamp();

                if(expired && entry->extend[0] != 0xFF && entry->atime <= max
                        && entry->access[3] > entry->access[2]
                        && entry->access[2] > entry->access[1]) {

                    entry->expire    += entry->ttl;

                    entry->access[0] += entry->access[1];
                    entry->access[0] += entry->access[2];
                    entry->access[0] += entry->access[3];
                    entry->access[1]  = 0;
                    entry->access[2]  = 0;
                    entry->access[3]  = 0;
                    entry->extended  += 1;

                    if(entry->file) {
                        nst_persist_update_expire(entry->file, entry->expire);
                    }

                    expired = 0;
                }

                /* check expire
                 * change state only, leave the free stuff to cleanup
                 * */
                if(entry->state == NST_CACHE_ENTRY_STATE_VALID && expired) {
                    entry->state         = NST_CACHE_ENTRY_STATE_EXPIRED;
                    entry->data->invalid = 1;
                    entry->data          = NULL;
                    entry->expire        = 0;
                    entry->access[0]     = 0;
                    entry->access[1]     = 0;
                    entry->access[2]     = 0;
                    entry->access[3]     = 0;
                    entry->extended      = 0;

                    return NULL;
                }

                return entry;
            }

            entry = entry->next;
        }

        if(!_nst_cache_dict_rehashing()) {
            return NULL;
        }

    }

    return NULL;
}

int nst_cache_dict_set_from_disk(char *file, char *meta, struct nst_key *key, struct nst_str *host,
        struct nst_str *path) {

    struct nst_cache_dict  *dict  = NULL;
    struct nst_cache_entry *entry = NULL;
    int idx;
    uint64_t hash = nst_persist_meta_get_hash(meta);

    uint64_t ttl_extend = nst_persist_meta_get_ttl_extend(meta);

    dict = _nst_cache_dict_rehashing() ? &nuster.cache->dict[1] : &nuster.cache->dict[0];

    entry = nst_cache_memory_alloc(sizeof(*entry));

    if(!entry) {
        return NST_ERR;
    }

    memset(entry, 0, sizeof(*entry));

    entry->file = nst_cache_memory_alloc(strlen(file));

    if(!entry->file) {
        return NST_ERR;
    }

    idx = hash % dict->size;
    /* prepend entry to dict->entry[idx] */
    entry->next      = dict->entry[idx];
    dict->entry[idx] = entry;
    dict->used++;

    /* init entry */
    entry->state  = NST_CACHE_ENTRY_STATE_INVALID;
    entry->key   = *key;
    entry->expire = nst_persist_meta_get_expire(meta);
    memcpy(entry->file, file, strlen(file));

    entry->header_len = nst_persist_meta_get_header_len(meta);

    entry->host.data  = host->data;
    entry->host.len   = host->len;

    entry->path.data  = path->data;
    entry->path.len   = path->len;

    entry->extend[0] = *( uint8_t *)(&ttl_extend);
    entry->extend[1] = *((uint8_t *)(&ttl_extend) + 1);
    entry->extend[2] = *((uint8_t *)(&ttl_extend) + 2);
    entry->extend[3] = *((uint8_t *)(&ttl_extend) + 3);

    entry->ttl = ttl_extend >> 32;

    return NST_OK;
}


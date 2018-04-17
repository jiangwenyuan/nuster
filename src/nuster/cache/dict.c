/*
 * Cache dict functions.
 *
 * Copyright (C) [Jiang Wenyuan](https://github.com/jiangwenyuan), < koubunen AT gmail DOT com >
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


static int _nst_cache_dict_resize(uint64_t size) {
    struct nst_cache_dict dict;

    dict.size  = size;
    dict.used  = 0;
    dict.entry = malloc(sizeof(struct nst_cache_entry*) * size);

    if(dict.entry) {
        int i;
        for(i = 0; i < size; i++) {
            dict.entry[i] = NULL;
        }
        if(!nuster.cache->dict[0].entry) {
            nuster.cache->dict[0] = dict;
            return 1;
        } else {
            nuster.cache->dict[1] = dict;
            nuster.cache->rehash_idx = 0;
            return 1;
        }
    }
    return 0;
}

static int _nst_cache_dict_alloc(uint64_t size) {
    int i, entry_size = sizeof(struct nst_cache_entry*);

    nuster.cache->dict[0].size  = size / entry_size;
    nuster.cache->dict[0].used  = 0;
    nuster.cache->dict[0].entry = nuster_memory_alloc(global.nuster.cache.memory, global.nuster.cache.memory->block_size);
    if(!nuster.cache->dict[0].entry) return 0;

    for(i = 1; i < size / global.nuster.cache.memory->block_size; i++) {
        if(!nuster_memory_alloc(global.nuster.cache.memory, global.nuster.cache.memory->block_size)) return 0;
    }
    for(i = 0; i < nuster.cache->dict[0].size; i++) {
        nuster.cache->dict[0].entry[i] = NULL;
    }
    return nuster_shctx_init((&nuster.cache->dict[0]));
}

int nst_cache_dict_init() {
    if(global.nuster.cache.share) {
        int size = (global.nuster.cache.memory->block_size + global.nuster.cache.dict_size - 1) / global.nuster.cache.memory->block_size * global.nuster.cache.memory->block_size;
        return _nst_cache_dict_alloc(size);
    } else {
        return _nst_cache_dict_resize(NST_CACHE_DEFAULT_DICT_SIZE);
    }
}

static int _nst_cache_dict_rehashing() {
    return global.nuster.cache.share == NUSTER_STATUS_OFF && nuster.cache->rehash_idx != -1;
}

/*
 * Rehash dict if cache->dict[0] is almost full
 */
void nst_cache_dict_rehash() {
    if(_nst_cache_dict_rehashing()) {
        int max_empty = 10;
        struct nst_cache_entry *entry = NULL;

        /* check max_empty entryies */
        while(!nuster.cache->dict[0].entry[nuster.cache->rehash_idx]) {
            nuster.cache->rehash_idx++;
            max_empty--;
            if(nuster.cache->rehash_idx >= nuster.cache->dict[0].size) {
                return;
            }
            if(!max_empty) {
                return;
            }
        }

        /* move all entries in this bucket to dict[1] */
        entry = nuster.cache->dict[0].entry[nuster.cache->rehash_idx];
        while(entry) {
            int idx = entry->hash % nuster.cache->dict[1].size;
            struct nst_cache_entry *entry_next = entry->next;

            entry->next = nuster.cache->dict[1].entry[idx];
            nuster.cache->dict[1].entry[idx] = entry;
            nuster.cache->dict[1].used++;
            nuster.cache->dict[0].used--;
            entry = entry_next;
        }
        nuster.cache->dict[0].entry[nuster.cache->rehash_idx] = NULL;
        nuster.cache->rehash_idx++;

        /* have we rehashed the whole dict? */
        if(nuster.cache->dict[0].used == 0) {
            free(nuster.cache->dict[0].entry);
            nuster.cache->dict[0]       = nuster.cache->dict[1];
            nuster.cache->rehash_idx    = -1;
            nuster.cache->cleanup_idx   = 0;
            nuster.cache->dict[1].entry = NULL;
            nuster.cache->dict[1].size  = 0;
            nuster.cache->dict[1].used  = 0;
        }
    } else {
        /* should we rehash? */
        if(global.nuster.cache.share) return;
        if(nuster.cache->dict[0].used >= nuster.cache->dict[0].size * NST_CACHE_DEFAULT_LOAD_FACTOR) {
            _nst_cache_dict_resize(nuster.cache->dict[0].size * NST_CACHE_DEFAULT_GROWTH_FACTOR);
        }
    }
}

static int _nst_cache_dict_entry_expired(struct nst_cache_entry *entry) {
    if(entry->expire == 0) {
        return 0;
    } else {
        return entry->expire <= get_current_timestamp() / 1000;
    }
}

static int _nst_cache_entry_invalid(struct nst_cache_entry *entry) {
    /* check state */
    if(entry->state == NST_CACHE_ENTRY_STATE_INVALID) {
        return 1;
    } else if(entry->state == NST_CACHE_ENTRY_STATE_EXPIRED) {
        return 1;
    }
    /* check expire */
    return _nst_cache_dict_entry_expired(entry);
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
        if(_nst_cache_entry_invalid(entry)) {
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
            nst_cache_memory_free(global.nuster.cache.pool.chunk, tmp->key);
            nst_cache_memory_free(global.nuster.cache.pool.chunk, tmp->host.data);
            nst_cache_memory_free(global.nuster.cache.pool.chunk, tmp->path.data);
            nst_cache_memory_free(global.nuster.cache.pool.entry, tmp);
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

/*
 * Add a new nst_cache_entry to cache_dict
 */
struct nst_cache_entry *nst_cache_dict_set(const char *key, uint64_t hash, struct nst_cache_ctx *ctx) {
    struct nst_cache_dict  *dict  = NULL;
    struct nst_cache_data  *data  = NULL;
    struct nst_cache_entry *entry = NULL;
    int idx;

    dict = _nst_cache_dict_rehashing() ? &nuster.cache->dict[1] : &nuster.cache->dict[0];

    entry = nst_cache_memory_alloc(global.nuster.cache.pool.entry, sizeof(*entry));
    if(!entry) {
        return NULL;
    }

    data = nst_cache_data_new();
    if(!data) {
        nst_cache_memory_free(global.nuster.cache.pool.entry, entry);
        return NULL;
    }

    idx = hash % dict->size;
    /* prepend entry to dict->entry[idx] */
    entry->next      = dict->entry[idx];
    dict->entry[idx] = entry;
    dict->used++;

    /* init entry */
    entry->data   = data;
    entry->state  = NST_CACHE_ENTRY_STATE_CREATING;
    entry->key    = nst_cache_memory_alloc(global.nuster.cache.pool.chunk, strlen(key) + 1);
    if(entry->key) {
        entry->key = memcpy(entry->key, key, strlen(key) + 1);
    }
    entry->hash   = hash;
    entry->expire = 0;
    entry->rule   = ctx->rule;
    entry->pid    = ctx->pid;

    entry->host.data   = ctx->req.host.data;
    entry->host.len    = ctx->req.host.len;
    ctx->req.host.data = NULL;

    entry->path.data   = ctx->req.path.data;
    entry->path.len    = ctx->req.path.len;
    ctx->req.path.data = NULL;

    return entry;
}

/*
 * Get entry
 */
struct nst_cache_entry *nst_cache_dict_get(const char *key, uint64_t hash) {
    int i, idx;
    struct nst_cache_entry *entry = NULL;

    if(nuster.cache->dict[0].used + nuster.cache->dict[1].used == 0) {
        return NULL;
    }

    for(i = 0; i <= 1; i++) {
        idx   = hash % nuster.cache->dict[i].size;
        entry = nuster.cache->dict[i].entry[idx];
        while(entry) {
            if(entry->hash == hash && !strcmp(entry->key, key)) {
                /* check expire
                 * change state only, leave the free stuff to cleanup
                 * */
                if(entry->state == NST_CACHE_ENTRY_STATE_VALID && _nst_cache_dict_entry_expired(entry)) {
                    entry->state         = NST_CACHE_ENTRY_STATE_EXPIRED;
                    entry->data->invalid = 1;
                    entry->data          = NULL;
                    entry->expire        = 0;
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


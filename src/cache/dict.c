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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <types/global.h>
#include <nuster/cache.h>

//#include <proto/cache.h>

#include <import/xxhash.h>


static int _cache_dict_resize(uint64_t size) {
    struct cache_dict dict;

    dict.size  = size;
    dict.used  = 0;
    dict.entry = malloc(sizeof(struct cache_entry*) * size);

    if(dict.entry) {
        int i;
        for(i = 0; i < size; i++) {
            dict.entry[i] = NULL;
        }
        if(!cache->dict[0].entry) {
            cache->dict[0] = dict;
            return 1;
        } else {
            cache->dict[1] = dict;
            cache->rehash_idx = 0;
            return 1;
        }
    }
    return 0;
}

static int _cache_dict_alloc(uint64_t size) {
    int i, entry_size = sizeof(struct cache_entry*);

    cache->dict[0].size  = size / entry_size;
    cache->dict[0].used  = 0;
    cache->dict[0].entry = nuster_memory_alloc(global.cache.memory, global.cache.memory->block_size);
    if(!cache->dict[0].entry) return 0;

    for(i = 1; i < size / global.cache.memory->block_size; i++) {
        if(!nuster_memory_alloc(global.cache.memory, global.cache.memory->block_size)) return 0;
    }
    for(i = 0; i < cache->dict[0].size; i++) {
        cache->dict[0].entry[i] = NULL;
    }
    return nuster_shctx_init((&cache->dict[0]));
}

int cache_dict_init() {
    if(global.cache.share) {
        int size = (global.cache.memory->block_size + global.cache.dict_size - 1) / global.cache.memory->block_size * global.cache.memory->block_size;
        return _cache_dict_alloc(size);
    } else {
        return _cache_dict_resize(CACHE_DEFAULT_DICT_SIZE);
    }
}

static int _cache_dict_rehashing() {
    return global.cache.share == CACHE_SHARE_OFF && cache->rehash_idx != -1;
}

/*
 * Rehash dict if cache->dict[0] is almost full
 */
void cache_dict_rehash() {
    if(_cache_dict_rehashing()) {
        int max_empty = 10;
        struct cache_entry *entry = NULL;

        /* check max_empty entryies */
        while(!cache->dict[0].entry[cache->rehash_idx]) {
            cache->rehash_idx++;
            max_empty--;
            if(cache->rehash_idx >= cache->dict[0].size) {
                return;
            }
            if(!max_empty) {
                return;
            }
        }

        /* move all entries in this bucket to dict[1] */
        entry = cache->dict[0].entry[cache->rehash_idx];
        while(entry) {
            int idx = entry->hash % cache->dict[1].size;
            struct cache_entry *entry_next = entry->next;

            entry->next = cache->dict[1].entry[idx];
            cache->dict[1].entry[idx] = entry;
            cache->dict[1].used++;
            cache->dict[0].used--;
            entry = entry_next;
        }
        cache->dict[0].entry[cache->rehash_idx] = NULL;
        cache->rehash_idx++;

        /* have we rehashed the whole dict? */
        if(cache->dict[0].used == 0) {
            free(cache->dict[0].entry);
            cache->dict[0]       = cache->dict[1];
            cache->rehash_idx    = -1;
            cache->cleanup_idx   = 0;
            cache->dict[1].entry = NULL;
            cache->dict[1].size  = 0;
            cache->dict[1].used  = 0;
        }
    } else {
        /* should we rehash? */
        if(global.cache.share) return;
        if(cache->dict[0].used >= cache->dict[0].size * CACHE_DEFAULT_LOAD_FACTOR) {
            _cache_dict_resize(cache->dict[0].size * CACHE_DEFAULT_GROWTH_FACTOR);
        }
    }
}

static int _cache_dict_entry_expired(struct cache_entry *entry) {
    if(entry->expire == 0) {
        return 0;
    } else {
        return entry->expire <= get_current_timestamp_s();
    }
}

static int _cache_entry_invalid(struct cache_entry *entry) {
    /* check state */
    if(entry->state == CACHE_ENTRY_STATE_INVALID) {
        return 1;
    } else if(entry->state == CACHE_ENTRY_STATE_EXPIRED) {
        return 1;
    }
    /* check expire */
    return _cache_dict_entry_expired(entry);
}

/*
 * Check entry validity, free the entry if its invalid,
 * If its invalid set entry->data->invalid to true,
 * entry->data is freed by _cache_data_cleanup
 */
void cache_dict_cleanup() {
    struct cache_entry *entry = cache->dict[0].entry[cache->cleanup_idx];
    struct cache_entry *prev  = entry;

    if(!cache->dict[0].used) {
        return;
    }

    while(entry) {
        if(_cache_entry_invalid(entry)) {
            struct cache_entry *tmp = entry;

            if(entry->data) {
                entry->data->invalid = 1;
            }
            if(prev == entry) {
                cache->dict[0].entry[cache->cleanup_idx] = entry->next;
                prev = entry->next;
            } else {
                prev->next = entry->next;
            }
            entry = entry->next;
            cache_memory_free(global.cache.pool.chunk, tmp->key);
            cache_memory_free(global.cache.pool.chunk, tmp->host.data);
            cache_memory_free(global.cache.pool.chunk, tmp->path.data);
            cache_memory_free(global.cache.pool.entry, tmp);
            cache->dict[0].used--;
        } else {
            prev  = entry;
            entry = entry->next;
        }
    }
    cache->cleanup_idx++;

    /* if we have checked the whole dict */
    if(cache->cleanup_idx == cache->dict[0].size) {
        cache->cleanup_idx = 0;
    }
}

/*
 * Add a new cache_entry to cache_dict
 */
struct cache_entry *cache_dict_set(const char *key, uint64_t hash, struct cache_ctx *ctx) {
    struct cache_dict  *dict  = NULL;
    struct cache_data  *data  = NULL;
    struct cache_entry *entry = NULL;
    int idx;

    dict = _cache_dict_rehashing() ? &cache->dict[1] : &cache->dict[0];

    entry = cache_memory_alloc(global.cache.pool.entry, sizeof(*entry));
    if(!entry) {
        return NULL;
    }

    data = cache_data_new();
    if(!data) {
        cache_memory_free(global.cache.pool.entry, entry);
        return NULL;
    }

    idx = hash % dict->size;
    /* prepend entry to dict->entry[idx] */
    entry->next      = dict->entry[idx];
    dict->entry[idx] = entry;
    dict->used++;

    /* init entry */
    entry->data   = data;
    entry->state  = CACHE_ENTRY_STATE_CREATING;
    entry->key    = cache_memory_alloc(global.cache.pool.chunk, strlen(key) + 1);
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
struct cache_entry *cache_dict_get(const char *key, uint64_t hash) {
    int i, idx;
    struct cache_entry *entry = NULL;

    if(cache->dict[0].used + cache->dict[1].used == 0) {
        return NULL;
    }

    for(i = 0; i <= 1; i++) {
        idx   = hash % cache->dict[i].size;
        entry = cache->dict[i].entry[idx];
        while(entry) {
            if(entry->hash == hash && !strcmp(entry->key, key)) {
                /* check expire
                 * change state only, leave the free stuff to cleanup
                 * */
                if(entry->state == CACHE_ENTRY_STATE_VALID && _cache_dict_entry_expired(entry)) {
                    entry->state         = CACHE_ENTRY_STATE_EXPIRED;
                    entry->data->invalid = 1;
                    entry->data          = NULL;
                    entry->expire        = 0;
                    return NULL;
                }
                return entry;
            }
            entry = entry->next;
        }
        if(!_cache_dict_rehashing()) {
            return NULL;
        }
    }
    return NULL;
}


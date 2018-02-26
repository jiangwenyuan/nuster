/*
 * Cache stats functions.
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
#include <types/cache.h>

#include <proto/cache.h>

void cache_stats_update_used_mem(int i) {
    nuster_shctx_lock(global.cache.stats);
    global.cache.stats->used_mem += i;
    nuster_shctx_unlock(global.cache.stats);
}

int cache_stats_init() {
    global.cache.stats = nuster_memory_alloc(global.cache.memory, sizeof(struct cache_stats));
    if(!global.cache.stats) {
        return 0;
    }
    global.cache.stats->used_mem = 0;
    global.cache.stats->requests = 0;
    global.cache.stats->hits     = 0;
    return 1;
}

int cache_stats_full() {
    int i;
    nuster_shctx_lock(global.cache.stats);
    i =  global.cache.data_size <= global.cache.stats->used_mem;
    nuster_shctx_unlock(global.cache.stats);
    return i;
}

/*
 * nuster nosql stats functions.
 *
 * Copyright (C) Jiang Wenyuan, < koubunen AT gmail DOT com >
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <inttypes.h>

#include <types/global.h>

#include <proto/stream_interface.h>
#include <proto/proxy.h>

#include <nuster/nuster.h>
#include <nuster/memory.h>
#include <nuster/shctx.h>

void nst_nosql_stats_update_used_mem(int i) {
    nst_shctx_lock(global.nuster.nosql.stats);
    global.nuster.nosql.stats->used_mem += i;
    nuster_shctx_unlock(global.nuster.nosql.stats);
}

int nst_nosql_stats_full() {
    int i;

    nst_shctx_lock(global.nuster.nosql.stats);
    i =  global.nuster.nosql.data_size <= global.nuster.nosql.stats->used_mem;
    nuster_shctx_unlock(global.nuster.nosql.stats);

    return i;
}

int nst_nosql_stats_init() {
    global.nuster.nosql.stats = nst_memory_alloc(global.nuster.nosql.memory,
            sizeof(struct nst_nosql_stats));

    if(!global.nuster.nosql.stats) {
        return NST_ERR;
    }

    if(nst_shctx_init(global.nuster.nosql.stats) != NST_OK) {
        return NST_ERR;
    }

    global.nuster.nosql.stats->used_mem = 0;

    return NST_OK;
}


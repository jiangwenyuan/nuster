/*
 * nuster persist related functions.
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
#include <nuster/file.h>
#include <nuster/persist.h>


char *nuster_persist_create(struct nuster_memory *m, uint64_t hash) {
    char *p = nuster_memory_alloc(m, NUSTER_FILE_LEN + 1);

    if(p) {
        sprintf(p, "%s/%"PRIx64"/%02"PRIx64"/%016"PRIx64,
                global.nuster.cache.directory, hash >> 60, hash >> 56, hash);

        nuster_debug("[CACHE] Path: %s\n", p);

        if(nuster_create_path(p) == NUSTER_ERR) {
            return NULL;
        }

        sprintf(p + NUSTER_PATH_LEN, "/%"PRIx64"-%"PRIx64,
                get_current_timestamp() * random() * random() & hash,
                get_current_timestamp());

        nuster_debug("[CACHE] File: %s\n", p);
    }

    return p;
}


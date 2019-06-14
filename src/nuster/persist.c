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
#include <nuster/persist.h>


int nuster_persist_create(char*);

char *nuster_persist_make_path(struct nuster_memory *p, uint64_t hash) {
    char *path = NULL;

    path = nuster_memory_alloc(p, NUSTER_FILE_LENGTH + 1);

    if(path) {
        sprintf(path, "%s/%"PRIx64"/%02"PRIx64"/%016"PRIx64,
                global.nuster.cache.directory, hash >> 60, hash >> 56, hash);
    }

    return path;
}

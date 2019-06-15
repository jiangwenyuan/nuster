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

#include <dirent.h>

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

static int
_persist_valid(struct persist *disk, struct buffer *key, uint64_t hash) {

    int ret;

    disk->fd = nuster_persist_open_read(disk->file);

    if(disk->fd == -1) {
        goto err;
    }

    ret = read(disk->fd, disk->meta, 48);

    if(ret != 48) {
        goto err;
    }

    if(memcmp(disk->meta, "NUSTER", 6) !=0) {
        goto err;
    }

    if(nuster_persist_meta_get_expire(disk->meta) > get_current_timestamp()) {
        goto err;
    }

    if(nuster_persist_meta_get_hash(disk->meta) == hash
            && nuster_persist_meta_get_key_len(disk->meta) == key->data
            && memcmp(disk->meta + NUSTER_PERSIST_META_INDEX_KEY,
                key->area, key->data) == 0) {

        return NUSTER_OK;
    }

err:
    close(disk->fd);
    return NUSTER_ERR;
}


int
nuster_persist_exists(struct persist *disk, struct buffer *key, uint64_t hash) {

    if(disk->file) {
        return _persist_valid(disk, key, hash);
    } else {

        struct dirent *de;
        DIR *dir;

        disk->file = nuster_memory_alloc(global.nuster.cache.memory,
                NUSTER_FILE_LEN + 1);

        sprintf(disk->file, "%s/%"PRIx64"/%02"PRIx64"/%016"PRIx64,
                global.nuster.cache.directory, hash >> 60, hash >> 56, hash);

        dir = opendir(disk->file);

        if(!dir) {
            return NUSTER_ERR;
        }

        while((de = readdir(dir)) != NULL) {

            if (strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0) {
                memcpy(disk->file + NUSTER_PATH_LEN, "/", 1);
                memcpy(disk->file + NUSTER_PATH_LEN + 1, de->d_name,
                        strlen(de->d_name));

                if(_persist_valid(disk, key, hash) == NUSTER_OK) {
                    closedir(dir);
                    return NUSTER_OK;
                }
            }
        }

        closedir(dir);
        return NUSTER_ERR;
    }
}


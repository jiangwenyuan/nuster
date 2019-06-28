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
#include <nuster/nuster.h>

char *nuster_persist_alloc(struct nuster_memory *m) {
    return nuster_memory_alloc(m, NUSTER_PERSIST_PATH_FILE_LEN + 1);
}

int nuster_persist_init(char *path, uint64_t hash, char *dir) {
    sprintf(path, "%s/%"PRIx64"/%02"PRIx64"/%016"PRIx64, dir,
            hash >> 60, hash >> 56, hash);

    nuster_debug("[CACHE] Path: %s\n", path);

    if(nuster_create_path(path) != NUSTER_OK) {
        return NUSTER_ERR;
    }

    sprintf(path + NUSTER_PERSIST_PATH_HASH_LEN, "/%"PRIx64"-%"PRIx64,
            get_current_timestamp() * random() * random() & hash,
            get_current_timestamp());

    nuster_debug("[CACHE] File: %s\n", path);

    return NUSTER_OK;
}

static int
_persist_valid(struct persist *disk, struct buffer *key, uint64_t hash) {

    char *buf;
    int ret;

    disk->fd = nuster_persist_open(disk->file);

    if(disk->fd == -1) {
        goto err;
    }

    ret = pread(disk->fd, disk->meta, NUSTER_PERSIST_META_SIZE, 0);

    if(ret != NUSTER_PERSIST_META_SIZE) {
        goto err;
    }

    if(memcmp(disk->meta, "NUSTER", 6) !=0) {
        goto err;
    }

    if(nuster_persist_meta_check_expire(disk->meta) != NUSTER_OK) {
        goto err;
    }

    if(nuster_persist_meta_get_hash(disk->meta) != hash
            || nuster_persist_meta_get_key_len(disk->meta) != key->data) {

        goto err;
    }

    buf = malloc(key->data);

    if(!buf) {
        goto err;
    }

    ret = pread(disk->fd, buf, key->data, NUSTER_PERSIST_POS_KEY);

    if(ret != key->data) {
        goto err;
    }

    if(memcmp(key->area, buf, key->data) != 0) {
        goto err;
    }

    free(buf);
    return NUSTER_OK;

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

        if(nuster.cache->disk.loaded) {
            return NUSTER_ERR;
        }

        disk->file = nuster_memory_alloc(global.nuster.cache.memory,
                NUSTER_PERSIST_PATH_FILE_LEN + 1);

        sprintf(disk->file, "%s/%"PRIx64"/%02"PRIx64"/%016"PRIx64,
                global.nuster.cache.directory, hash >> 60, hash >> 56, hash);

        dir = opendir(disk->file);

        if(!dir) {
            return NUSTER_ERR;
        }

        while((de = readdir(dir)) != NULL) {

            if (strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0) {
                memcpy(disk->file + NUSTER_PERSIST_PATH_HASH_LEN, "/", 1);
                memcpy(disk->file + NUSTER_PERSIST_PATH_HASH_LEN + 1,
                        de->d_name, strlen(de->d_name));

                if(_persist_valid(disk, key, hash) == NUSTER_OK) {
                    closedir(dir);
                    return NUSTER_OK;
                }
            }
        }

        closedir(dir);
        nuster_memory_free(global.nuster.cache.memory, disk->file);
        return NUSTER_ERR;
    }
}

DIR *nuster_persist_opendir_by_idx(char *path, int idx) {
    memset(path, 0, NUSTER_PERSIST_PATH_FILE_LEN);
    sprintf(path, "%s/%x/%02x", global.nuster.cache.directory, idx / 16, idx);

    return opendir(path);
}

struct dirent *nuster_persist_dir_next(DIR *dir) {
    return readdir(dir);
}

int nuster_persist_get_meta(int fd, char *meta) {
    int ret;

    ret = pread(fd, meta, NUSTER_PERSIST_META_SIZE, 0);

    if(ret != NUSTER_PERSIST_META_SIZE) {
        return NUSTER_ERR;
    }

    if(memcmp(meta, "NUSTER", 6) !=0) {
        return NUSTER_ERR;
    }

    if(nuster_persist_meta_check_expire(meta) != NUSTER_OK) {
        return NUSTER_ERR;
    }

    return NUSTER_OK;
}

struct buffer *nuster_persist_get_key(int fd, char *meta) {

    struct buffer *key;

    key = nuster_memory_alloc(global.nuster.cache.memory, sizeof(*key));

    if(!key) {
        goto err;
    }

    key->size = nuster_persist_meta_get_key_len(meta);

    key->area = nuster_memory_alloc(global.nuster.cache.memory, key->size);

    if(!key->area) {
        goto err;
    }

    key->head = 0;

    key->data = pread(fd, key->area, key->size, NUSTER_PERSIST_POS_KEY);

    if(!b_full(key)) {
        goto err;
    }

    return key;

err:
    if(key) {
        if(key->area) {
            nuster_memory_free(global.nuster.cache.memory, key->area);
        }

        nuster_memory_free(global.nuster.cache.memory, key);
    }

    return NULL;
}

void nuster_persist_cleanup(char *path, struct dirent *de1) {
    DIR *dir2;
    struct dirent *de2;
    int fd, ret;
    char meta[NUSTER_PERSIST_META_SIZE];

    if (strcmp(de1->d_name, ".") == 0
            || strcmp(de1->d_name, "..") == 0) {

        return;
    }

    memcpy(path + NUSTER_PERSIST_PATH_BASE_LEN, "/", 1);
    memcpy(path + NUSTER_PERSIST_PATH_BASE_LEN + 1, de1->d_name,
            strlen(de1->d_name));

    dir2 = opendir(path);

    if(!dir2) {
        return;
    }

    while((de2 = readdir(dir2)) != NULL) {

        if(strcmp(de2->d_name, ".") != 0
                && strcmp(de2->d_name, "..") != 0) {

            memcpy(path + NUSTER_PERSIST_PATH_HASH_LEN, "/", 1);
            memcpy(path + NUSTER_PERSIST_PATH_HASH_LEN + 1, de2->d_name,
                    strlen(de2->d_name));

            fd = nuster_persist_open(path);

            if(fd == -1) {
                closedir(dir2);
                return;
            }

            ret = pread(fd, meta, NUSTER_PERSIST_META_SIZE, 0);

            if(ret != NUSTER_PERSIST_META_SIZE) {
                continue;
            }

            if(memcmp(meta, "NUSTER", 6) !=0) {
                continue;
            }

            /* cache is complete */
            if(nuster_persist_meta_check_expire(meta) != NUSTER_OK) {
                unlink(path);
                close(fd);
                continue;
            }

            close(fd);

        }
    }

    closedir(dir2);

}

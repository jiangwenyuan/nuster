/*
 * include/nuster/persist.h
 * nuster persist related functions.
 *
 * Copyright (C) Jiang Wenyuan, < koubunen AT gmail DOT com >
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef _NUSTER_PERSIST_H
#define _NUSTER_PERSIST_H

#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

/*
   Offset       Length(bytes)   Content
   0            6               NUSTER
   6            1               Mode: NUSTER_DISK_*, 1, 2, 3
   7            1               Version: 1
   8 * 1        8               hash
   8 * 2        8               expire time
   8 * 3        8               cache length
   8 * 4        8               header length
   8 * 5        8               key length
   8 * 6        key_len         key
   48 + key_len cache_len       cache
 */

#define NUSTER_PERSIST_VERSION                  1

#define NUSTER_PERSIST_META_INDEX_HASH          8 * 1
#define NUSTER_PERSIST_META_INDEX_EXPIRE        8 * 2
#define NUSTER_PERSIST_META_INDEX_CACHE_LEN     8 * 3
#define NUSTER_PERSIST_META_INDEX_HEADER_LEN    8 * 4
#define NUSTER_PERSIST_META_INDEX_KEY_LEN       8 * 5
#define NUSTER_PERSIST_META_INDEX_KEY           8 * 6

/*
 * DIR/a/4a/60322ec3e2428e4a/16ae92496e1-71fabeefebdaaedb
 */

/* strlen("/0/00/") + 16, without '\0' */
#define NUSTER_PATH_LEN strlen(global.nuster.cache.directory) + 22

/* 1 + 11 + 1 + 16, without '\0'  */
#define NUSTER_FILE_LENGTH NUSTER_PATH_LEN + 29

char *nuster_persist_create(struct nuster_memory *p, uint64_t hash);

static inline int nuster_persist_open(const char *pathname) {
    return open(pathname, O_CREAT | O_WRONLY, 0600);
}

static inline void nuster_persist_meta_set_hash(char *p, uint64_t v) {
    *(uint64_t *)(p + NUSTER_PERSIST_META_INDEX_HASH) = v;
}

static inline void nuster_persist_meta_set_expire(char *p, uint64_t v) {
    *(uint64_t *)(p + NUSTER_PERSIST_META_INDEX_EXPIRE) = v;
}

static inline void nuster_persist_meta_set_cache_len(char *p, uint64_t v) {
    *(uint64_t *)(p + NUSTER_PERSIST_META_INDEX_CACHE_LEN) = v;
}

static inline void nuster_persist_meta_set_header_len(char *p, uint64_t v) {
    *(uint64_t *)(p + NUSTER_PERSIST_META_INDEX_HEADER_LEN) = v;
}

static inline void nuster_persist_meta_set_key_len(char *p, uint64_t v) {
    *(uint64_t *)(p + NUSTER_PERSIST_META_INDEX_KEY_LEN) = v;
}

static inline void
nuster_persist_meta_init(char *p, char mode, uint64_t hash, uint64_t expire,
        uint64_t cache_len, uint64_t header_len, uint64_t key_len) {

    memcpy(p, "NUSTER", 6);
    p[6] = mode;
    p[7] = (char)NUSTER_PERSIST_VERSION;

    nuster_persist_meta_set_hash(p, hash);
    nuster_persist_meta_set_expire(p, expire);
    nuster_persist_meta_set_cache_len(p, cache_len);
    nuster_persist_meta_set_header_len(p, header_len);
    nuster_persist_meta_set_key_len(p, key_len);
}

#endif /* _NUSTER_PERSIST_H */

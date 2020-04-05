/*
 * include/nuster/disk.h
 * nuster disk related functions.
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

#ifndef _NUSTER_DISK_H
#define _NUSTER_DISK_H

#include <nuster/common.h>
#include <nuster/key.h>

#define NST_DISK_VERSION  4

/*
   Offset              Length(bytes)           Content
   0                   6                       NUSTER
   6                   1                       mode: not used
   7                   1                       version
   8 * 1               8                       hash
   8 * 2               8                       expire time
   8 * 3               8                       header length
   8 * 4               8                       payload length
   8 * 5               8                       key length
   8 * 6               8                       host length
   8 * 7               8                       path length
   8 * 8               8                       etag length
   8 * 9               8                       last-modified length
   8 * 10              8                       ttl: 4, extend: 4
   8 * 11              40                      reserved
   8 * 16              key_len                 key
   + key_len           host_len                host
   + host_len          path_len                path
   + path_len          etag_len                etag
   + etag_len          last_modified_len       last_modified
   + last_modified_len header_len              header
   header + header_len payload_len             payload
 */

#define NST_DISK_META_POS_HASH               8 * 1
#define NST_DISK_META_POS_EXPIRE             8 * 2
#define NST_DISK_META_POS_HEADER_LEN         8 * 3
#define NST_DISK_META_POS_PAYLOAD_LEN        8 * 4
#define NST_DISK_META_POS_KEY_LEN            8 * 5
#define NST_DISK_META_POS_HOST_LEN           8 * 6
#define NST_DISK_META_POS_PATH_LEN           8 * 7
#define NST_DISK_META_POS_ETAG_LEN           8 * 8
#define NST_DISK_META_POS_LAST_MODIFIED_LEN  8 * 9
#define NST_DISK_META_POS_TTL_EXTEND         8 * 10


#define NST_DISK_META_SIZE                   8 * 16
#define NST_DISK_POS_KEY                     NST_DISK_META_SIZE

enum {
    NST_DISK_APPLET_ERROR    = -1,
    NST_DISK_APPLET_DONE     =  0,
    NST_DISK_APPLET_HEADER,
    NST_DISK_APPLET_PAYLOAD,
    NST_DISK_APPLET_EOM,
};

typedef struct nst_disk_data {
    char               *file;               /* disk file */
    int                 fd;
    int                 offset;
    char                meta[NST_DISK_META_SIZE];
} nst_disk_data_t;


typedef struct nst_disk {
    nst_memory_t       *memory;
    hpx_ist_t           root;               /* persist root directory */
    int                 loaded;
    int                 idx;
    DIR                *dir;
    nst_dirent_t       *de;
    char               *file;
} nst_disk_t;

/* /0/00: 5 */
static inline int
nst_disk_path_base_len(hpx_ist_t root) {
    return root.len + 5;
}

/* /0/00/00322ec3e2428e4a: 5 + 1 + 16 */
static inline int
nst_disk_path_hash_len(hpx_ist_t root) {
    return root.len + 22;
}

/* /0/00/00322ec3e2428e4a/71fabeefebdaaedb-16ae92496e1: 22 + 1 + 16 + 1 + 11 */
static inline int
nst_disk_path_file_len(hpx_ist_t root) {
    return root.len + 51;
}

int nst_disk_mkdir(char *path);
int nst_disk_data_init(hpx_ist_t root, char *path, uint64_t hash);

static inline int
nst_disk_data_create(const char *pathname) {
    return open(pathname, O_CREAT | O_WRONLY, 0600);
}

static inline int
nst_disk_open(const char *pathname) {
    return open(pathname, O_RDONLY);
}

static inline void
nst_disk_meta_set_hash(char *p, uint64_t v) {
    *(uint64_t *)(p + NST_DISK_META_POS_HASH) = v;
}

static inline uint64_t
nst_disk_meta_get_hash(char *p) {
    return *(uint64_t *)(p + NST_DISK_META_POS_HASH);
}

static inline void
nst_disk_meta_set_expire(char *p, uint64_t v) {
    *(uint64_t *)(p + NST_DISK_META_POS_EXPIRE) = v;
}

static inline uint64_t
nst_disk_meta_get_expire(char *p) {
    return *(uint64_t *)(p + NST_DISK_META_POS_EXPIRE);
}

static inline int
nst_disk_meta_check_expire(char *p) {
    uint64_t expire = *(uint64_t *)(p + NST_DISK_META_POS_EXPIRE);

    if(expire == 0) {
        return NST_OK;
    }

    if(expire * 1000 > get_current_timestamp()) {
        return NST_OK;
    } else {
        return NST_ERR;
    }
}

static inline void
nst_disk_meta_set_payload_len(char *p, uint64_t v) {
    *(uint64_t *)(p + NST_DISK_META_POS_PAYLOAD_LEN) = v;
}

static inline uint64_t
nst_disk_meta_get_payload_len(char *p) {
    return *(uint64_t *)(p + NST_DISK_META_POS_PAYLOAD_LEN);
}

static inline void
nst_disk_meta_set_header_len(char *p, uint64_t v) {
    *(uint64_t *)(p + NST_DISK_META_POS_HEADER_LEN) = v;
}

static inline uint64_t
nst_disk_meta_get_header_len(char *p) {
    return *(uint64_t *)(p + NST_DISK_META_POS_HEADER_LEN);
}

static inline void
nst_disk_meta_set_key_len(char *p, uint64_t v) {
    *(uint64_t *)(p + NST_DISK_META_POS_KEY_LEN) = v;
}

static inline uint64_t
nst_disk_meta_get_key_len(char *p) {
    return *(uint64_t *)(p + NST_DISK_META_POS_KEY_LEN);
}

static inline void
nst_disk_meta_set_host_len(char *p, uint64_t v) {
    *(uint64_t *)(p + NST_DISK_META_POS_HOST_LEN) = v;
}

static inline uint64_t
nst_disk_meta_get_host_len(char *p) {
    return *(uint64_t *)(p + NST_DISK_META_POS_HOST_LEN);
}

static inline void
nst_disk_meta_set_path_len(char *p, uint64_t v) {
    *(uint64_t *)(p + NST_DISK_META_POS_PATH_LEN) = v;
}

static inline uint64_t
nst_disk_meta_get_path_len(char *p) {
    return *(uint64_t *)(p + NST_DISK_META_POS_PATH_LEN);
}

static inline void
nst_disk_meta_set_etag_len(char *p, uint64_t v) {
    *(uint64_t *)(p + NST_DISK_META_POS_ETAG_LEN) = v;
}

static inline uint64_t
nst_disk_meta_get_etag_len(char *p) {
    return *(uint64_t *)(p + NST_DISK_META_POS_ETAG_LEN);
}

static inline void
nst_disk_meta_set_last_modified_len(char *p, uint64_t v) {
    *(uint64_t *)(p + NST_DISK_META_POS_LAST_MODIFIED_LEN) = v;
}

static inline uint64_t
nst_disk_meta_get_last_modified_len(char *p) {
    return *(uint64_t *)(p + NST_DISK_META_POS_LAST_MODIFIED_LEN);
}

static inline void
nst_disk_meta_set_ttl_extend(char *p, uint64_t v) {
    *(uint64_t *)(p + NST_DISK_META_POS_TTL_EXTEND) = v;
}

static inline uint64_t
nst_disk_meta_get_ttl_extend(char *p) {
    return *(uint64_t *)(p + NST_DISK_META_POS_TTL_EXTEND);
}

static inline int
nst_disk_get_header_pos(char *p) {
    return (int)(NST_DISK_META_SIZE
            + nst_disk_meta_get_key_len(p)
            + nst_disk_meta_get_host_len(p)
            + nst_disk_meta_get_path_len(p)
            + nst_disk_meta_get_etag_len(p)
            + nst_disk_meta_get_last_modified_len(p));
}

static inline void
nst_disk_meta_init(char *p, char mode, uint64_t hash, uint64_t expire, uint64_t header_len,
        uint64_t payload_len, uint64_t key_len, uint64_t host_len, uint64_t path_len,
        uint64_t etag_len, uint64_t last_modified_len, uint64_t ttl_extend) {

    memcpy(p, "NUSTER", 6);
    p[6] = mode;
    p[7] = (char)NST_DISK_VERSION;

    nst_disk_meta_set_hash(p, hash);
    nst_disk_meta_set_expire(p, expire);
    nst_disk_meta_set_header_len(p, header_len);
    nst_disk_meta_set_payload_len(p, payload_len);
    nst_disk_meta_set_key_len(p, key_len);
    nst_disk_meta_set_host_len(p, host_len);
    nst_disk_meta_set_path_len(p, path_len);
    nst_disk_meta_set_etag_len(p, etag_len);
    nst_disk_meta_set_last_modified_len(p, last_modified_len);
    nst_disk_meta_set_ttl_extend(p, ttl_extend);
}

static inline void
nst_disk_meta_init2(char *p, uint64_t hash, uint64_t expire, uint64_t header_len,
        uint64_t payload_len, uint64_t key_len, uint64_t host_len, uint64_t path_len,
        uint64_t etag_len, uint64_t last_modified_len, uint64_t ttl_extend) {

    memcpy(p, "NUSTER", 6);
    p[6] = 0;
    p[7] = (char)NST_DISK_VERSION;

    nst_disk_meta_set_hash(p, hash);
    nst_disk_meta_set_expire(p, expire);
    nst_disk_meta_set_header_len(p, header_len);
    nst_disk_meta_set_payload_len(p, payload_len);
    nst_disk_meta_set_key_len(p, key_len);
    nst_disk_meta_set_host_len(p, host_len);
    nst_disk_meta_set_path_len(p, path_len);
    nst_disk_meta_set_etag_len(p, etag_len);
    nst_disk_meta_set_last_modified_len(p, last_modified_len);
    nst_disk_meta_set_ttl_extend(p, ttl_extend);
}

int nst_disk_exists(hpx_ist_t root, nst_disk_data_t *disk, nst_key_t *key);

static inline int
nst_disk_write(nst_disk_data_t *disk, char *buf, int len) {
    ssize_t ret = pwrite(disk->fd, buf, len, disk->offset);

    if(ret != len) {
        return NST_ERR;
    }

    disk->offset += len;

    return NST_OK;
}

static inline int
nst_disk_write_meta(nst_disk_data_t *disk) {
    disk->offset = 0;

    return nst_disk_write(disk, disk->meta, NST_DISK_META_SIZE);
}

static inline int
nst_disk_write_key(nst_disk_data_t *disk, nst_key_t *key) {
    disk->offset = NST_DISK_POS_KEY;

    return nst_disk_write(disk, key->data, key->size);
}

static inline int
nst_disk_write_host(nst_disk_data_t *disk, hpx_ist_t host) {

    disk->offset = NST_DISK_POS_KEY + nst_disk_meta_get_key_len(disk->meta);

    return nst_disk_write(disk, host.ptr, host.len);
}

static inline int
nst_disk_write_path(nst_disk_data_t *disk, hpx_ist_t path) {

    disk->offset = NST_DISK_POS_KEY
        + nst_disk_meta_get_key_len(disk->meta)
        + nst_disk_meta_get_host_len(disk->meta);

    return nst_disk_write(disk, path.ptr, path.len);
}

static inline int
nst_disk_write_etag(nst_disk_data_t *disk, hpx_ist_t etag) {

    disk->offset = NST_DISK_POS_KEY
        + nst_disk_meta_get_key_len(disk->meta)
        + nst_disk_meta_get_host_len(disk->meta)
        + nst_disk_meta_get_path_len(disk->meta);

    return nst_disk_write(disk, etag.ptr, etag.len);
}

static inline int
nst_disk_write_last_modified(nst_disk_data_t *disk, hpx_ist_t lm) {

    disk->offset = NST_DISK_POS_KEY
        + nst_disk_meta_get_key_len(disk->meta)
        + nst_disk_meta_get_host_len(disk->meta)
        + nst_disk_meta_get_path_len(disk->meta)
        + nst_disk_meta_get_etag_len(disk->meta);

    return nst_disk_write(disk, lm.ptr, lm.len);
}

void nst_disk_load(char *path, nst_dirent_t *de1, char **meta, char **key);
int nst_disk_get_meta(int fd, char *meta);
int nst_disk_get_key(int fd, char *meta, nst_key_t *key);
int nst_disk_get_host(int fd, char *meta, hpx_ist_t host);
int nst_disk_get_path(int fd, char *meta, hpx_ist_t path);
int nst_disk_get_etag(int fd, char *meta, hpx_ist_t etag);
int nst_disk_get_last_modified(int fd, char *meta, hpx_ist_t last_modified);

DIR *nst_disk_opendir_by_idx(hpx_ist_t root, char *path, int idx);
void nst_disk_cleanup(hpx_ist_t root, char *path, nst_dirent_t *de);
nst_dirent_t *nst_disk_dir_next(DIR *dir);
int nst_disk_valid(nst_disk_data_t *disk, nst_key_t *key);
int nst_disk_purge_by_key(hpx_ist_t root, nst_disk_data_t *disk, nst_key_t *key);
int nst_disk_purge_by_path(char *path);
void nst_disk_update_expire(char *file, uint64_t expire);

int nst_disk_init(hpx_ist_t root, nst_disk_t *disk, nst_memory_t *memory);

int nst_disk_store_init(nst_disk_t *disk, nst_disk_data_t *data, nst_key_t *key,
        nst_http_txn_t *txn, uint64_t ttl_extend);

static inline int
nst_disk_store_add(nst_disk_t *disk, nst_disk_data_t *data, char *buf, int len) {
    if(nst_disk_write(data, buf, len) != NST_OK) {
        if(data->fd) {
            close(data->fd);
        }

        nst_memory_free(disk->memory, data->file);

        data->file = NULL;

        return NST_ERR;
    }

    return NST_OK;
}

int
nst_disk_store_end(nst_disk_t *disk, nst_disk_data_t *data, nst_http_txn_t *txn, uint64_t expire);

#endif /* _NUSTER_DISK_H */

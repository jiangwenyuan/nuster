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


#define NST_DISK_VERSION  6

/*
   Offset              Length(bytes)           Content
   0                   6                       NUSTER
   6                   1                       mode: not used
   7                   1                       version
   8 * 1               8                       hash
   8 * 2               20                      uuid
   8 * 2 + 20          4                       key length
   8 * 5               8                       expire time
   8 * 6               8                       header length
   8 * 7               8                       payload length
   8 * 8               8                       proxy name len: 4, rule name len: 4
   8 * 9               8                       host len: 4, path len: 4
   8 * 10              8                       etag, on|off: 4, length: 4
   8 * 11              8                       last-modified: on|off: 4, length: 4
   8 * 12              8                       ttl: 4, extend: 4
   8 * 13              8                       stale: 4, inactive: 4
   8 * 14              20                      reserved
   NST_DISK_META_SIZE  key_len                 key
   + key_len           proxy_len               proxy
   + proxy_len         rule_len                rule
   + rule_len          host_len                host
   + host_len          path_len                path
   + path_len          etag_len                etag
   + etag_len          last_modified_len       last_modified
   + last_modified_len header_len              header
   + header_len        payload_len             payload
   + payload_len       TLR/EOT                 [optional]
   */

#define NST_DISK_META_POS_HASH                  8 * 1
#define NST_DISK_META_POS_UUID                  8 * 2
#define NST_DISK_META_POS_KEY_LEN               8 * 2  + 20
#define NST_DISK_META_POS_EXPIRE                8 * 5
#define NST_DISK_META_POS_HEADER_LEN            8 * 6
#define NST_DISK_META_POS_PAYLOAD_LEN           8 * 7
#define NST_DISK_META_POS_PROXY_LEN             8 * 8
#define NST_DISK_META_POS_RULE_LEN              8 * 8  + 4
#define NST_DISK_META_POS_HOST_LEN              8 * 9
#define NST_DISK_META_POS_PATH_LEN              8 * 9  + 4
#define NST_DISK_META_POS_ETAG_PROP             8 * 10
#define NST_DISK_META_POS_ETAG_LEN              8 * 10 + 4
#define NST_DISK_META_POS_LAST_MODIFIED_PROP    8 * 11
#define NST_DISK_META_POS_LAST_MODIFIED_LEN     8 * 11 + 4
#define NST_DISK_META_POS_TTL_EXTEND            8 * 12
#define NST_DISK_META_POS_STALE                 8 * 13
#define NST_DISK_META_POS_INACTIVE              8 * 13 + 4

#define NST_DISK_META_SIZE                      8 * 16
#define NST_DISK_POS_KEY                        NST_DISK_META_SIZE

#define NST_DISK_FILE_LEN                       NST_KEY_UUID_LEN * 2

enum {
    NST_DISK_APPLET_ERROR    = -1,
    NST_DISK_APPLET_DONE     =  0,
    NST_DISK_APPLET_HEADER,
    NST_DISK_APPLET_PAYLOAD,
    NST_DISK_APPLET_EOP,
    NST_DISK_APPLET_END,
};

typedef struct nst_disk_object {
    char               *file;               /* disk file */
    int                 fd;
    uint64_t            offset;
    char                meta[NST_DISK_META_SIZE];
} nst_disk_obj_t;


typedef struct nst_disk {
    nst_shmem_t        *shmem;
    hpx_ist_t           root;               /* disk root directory */
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

/*
 * temp:  /.tmp/20-bytes-random + 20-bytes-timestamp
 * final: /5/5a/5ab66d8c3b4bdca6a5e9538943c40f6ba45beb7a   6 + 40 + 1
 */
static inline int
nst_disk_path_file_len(hpx_ist_t root) {
    return root.len + 47;
}

static inline int
nst_disk_file_remove(const char *file) {
    return remove(file);
}

static inline int
nst_disk_file_create(const char *pathname) {
    return open(pathname, O_CREAT | O_WRONLY, 0600);
}

static inline int
nst_disk_file_open(const char *pathname) {
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
nst_disk_meta_set_uuid(char *p, unsigned char *uuid) {
    memcpy(p + NST_DISK_META_POS_UUID, uuid, NST_KEY_UUID_LEN);
}

static inline char *
nst_disk_meta_get_uuid(char *p) {
    return (char *)(p + NST_DISK_META_POS_UUID);
}

static inline void
nst_disk_meta_set_key_len(char *p, uint32_t v) {
    *(uint32_t *)(p + NST_DISK_META_POS_KEY_LEN) = v;
}

static inline uint32_t
nst_disk_meta_get_key_len(char *p) {
    return *(uint32_t *)(p + NST_DISK_META_POS_KEY_LEN);
}

static inline void
nst_disk_meta_set_expire(char *p, uint64_t v) {
    *(uint64_t *)(p + NST_DISK_META_POS_EXPIRE) = v;
}

static inline uint64_t
nst_disk_meta_get_expire(char *p) {
    return *(uint64_t *)(p + NST_DISK_META_POS_EXPIRE);
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
nst_disk_meta_set_payload_len(char *p, uint64_t v) {
    *(uint64_t *)(p + NST_DISK_META_POS_PAYLOAD_LEN) = v;
}

static inline uint64_t
nst_disk_meta_get_payload_len(char *p) {
    return *(uint64_t *)(p + NST_DISK_META_POS_PAYLOAD_LEN);
}

static inline void
nst_disk_meta_set_proxy_len(char *p, uint32_t v) {
    *(uint32_t *)(p + NST_DISK_META_POS_PROXY_LEN) = v;
}

static inline uint32_t
nst_disk_meta_get_proxy_len(char *p) {
    return *(uint32_t *)(p + NST_DISK_META_POS_PROXY_LEN);
}

static inline void
nst_disk_meta_set_rule_len(char *p, uint32_t v) {
    *(uint32_t *)(p + NST_DISK_META_POS_RULE_LEN) = v;
}

static inline uint32_t
nst_disk_meta_get_rule_len(char *p) {
    return *(uint32_t *)(p + NST_DISK_META_POS_RULE_LEN);
}

static inline void
nst_disk_meta_set_host_len(char *p, uint32_t v) {
    *(uint32_t *)(p + NST_DISK_META_POS_HOST_LEN) = v;
}

static inline uint32_t
nst_disk_meta_get_host_len(char *p) {
    return *(uint32_t *)(p + NST_DISK_META_POS_HOST_LEN);
}

static inline void
nst_disk_meta_set_path_len(char *p, uint32_t v) {
    *(uint32_t *)(p + NST_DISK_META_POS_PATH_LEN) = v;
}

static inline uint32_t
nst_disk_meta_get_path_len(char *p) {
    return *(uint32_t *)(p + NST_DISK_META_POS_PATH_LEN);
}

static inline void
nst_disk_meta_set_etag_prop(char *p, uint32_t v) {
    *(uint32_t *)(p + NST_DISK_META_POS_ETAG_PROP) = v;
}

static inline uint32_t
nst_disk_meta_get_etag_prop(char *p) {
    return *(uint32_t *)(p + NST_DISK_META_POS_ETAG_PROP);
}

static inline void
nst_disk_meta_set_etag_len(char *p, uint32_t v) {
    *(uint32_t *)(p + NST_DISK_META_POS_ETAG_LEN) = v;
}

static inline uint32_t
nst_disk_meta_get_etag_len(char *p) {
    return *(uint32_t *)(p + NST_DISK_META_POS_ETAG_LEN);
}

static inline void
nst_disk_meta_set_last_modified_prop(char *p, uint32_t v) {
    *(uint32_t *)(p + NST_DISK_META_POS_LAST_MODIFIED_PROP) = v;
}

static inline uint32_t
nst_disk_meta_get_last_modified_prop(char *p) {
    return *(uint32_t *)(p + NST_DISK_META_POS_LAST_MODIFIED_PROP);
}

static inline void
nst_disk_meta_set_last_modified_len(char *p, uint32_t v) {
    *(uint32_t *)(p + NST_DISK_META_POS_LAST_MODIFIED_LEN) = v;
}

static inline uint32_t
nst_disk_meta_get_last_modified_len(char *p) {
    return *(uint32_t *)(p + NST_DISK_META_POS_LAST_MODIFIED_LEN);
}

static inline void
nst_disk_meta_set_ttl_extend(char *p, uint64_t v) {
    *(uint64_t *)(p + NST_DISK_META_POS_TTL_EXTEND) = v;
}

static inline uint64_t
nst_disk_meta_get_ttl_extend(char *p) {
    return *(uint64_t *)(p + NST_DISK_META_POS_TTL_EXTEND);
}

static inline void
nst_disk_meta_set_stale(char *p, int32_t v) {
    *(int32_t *)(p + NST_DISK_META_POS_STALE) = v;
}

static inline int32_t
nst_disk_meta_get_stale(char *p) {
    return *(int32_t *)(p + NST_DISK_META_POS_STALE);
}

static inline void
nst_disk_meta_set_inactive(char *p, int32_t v) {
    *(int32_t *)(p + NST_DISK_META_POS_INACTIVE) = v;
}

static inline int32_t
nst_disk_meta_get_inactive(char *p) {
    return *(int32_t *)(p + NST_DISK_META_POS_INACTIVE);
}

static inline int
nst_disk_meta_check_expire(char *p) {
    uint64_t  expire = nst_disk_meta_get_expire(p);
    uint64_t  now    = nst_time_now_ms();

    if(expire == 0) {
        return NST_OK;
    }

    if(expire * 1000 > now) {
        return NST_OK;
    }

    return NST_ERR;
}

static inline int
nst_disk_meta_check_stale(char *p) {
    uint64_t  expire = nst_disk_meta_get_expire(p);
    uint64_t  now    = nst_time_now_ms();
    int32_t   stale  = nst_disk_meta_get_stale(p);

    if(stale == 0) {
        return NST_OK;
    }

    if(expire + stale > now / 1000) {
        return NST_OK;
    }

    return NST_ERR;
}

static inline int
nst_disk_pos_proxy(nst_disk_obj_t *obj) {
    return NST_DISK_POS_KEY + nst_disk_meta_get_key_len(obj->meta);
}

static inline int
nst_disk_pos_rule(nst_disk_obj_t *obj) {
    return NST_DISK_POS_KEY
        + nst_disk_meta_get_key_len(obj->meta)
        + nst_disk_meta_get_proxy_len(obj->meta);
}

static inline int
nst_disk_pos_host(nst_disk_obj_t *obj) {
    return NST_DISK_POS_KEY
        + nst_disk_meta_get_key_len(obj->meta)
        + nst_disk_meta_get_proxy_len(obj->meta)
        + nst_disk_meta_get_rule_len(obj->meta);
}

static inline int
nst_disk_pos_path(nst_disk_obj_t *obj) {
    return NST_DISK_POS_KEY
        + nst_disk_meta_get_key_len(obj->meta)
        + nst_disk_meta_get_proxy_len(obj->meta)
        + nst_disk_meta_get_rule_len(obj->meta)
        + nst_disk_meta_get_host_len(obj->meta);
}

static inline int
nst_disk_pos_etag(nst_disk_obj_t *obj) {
    return NST_DISK_POS_KEY
        + nst_disk_meta_get_key_len(obj->meta)
        + nst_disk_meta_get_proxy_len(obj->meta)
        + nst_disk_meta_get_rule_len(obj->meta)
        + nst_disk_meta_get_host_len(obj->meta)
        + nst_disk_meta_get_path_len(obj->meta);
}

static inline int
nst_disk_pos_last_modified(nst_disk_obj_t *obj) {
    return NST_DISK_POS_KEY
        + nst_disk_meta_get_key_len(obj->meta)
        + nst_disk_meta_get_proxy_len(obj->meta)
        + nst_disk_meta_get_rule_len(obj->meta)
        + nst_disk_meta_get_host_len(obj->meta)
        + nst_disk_meta_get_path_len(obj->meta)
        + nst_disk_meta_get_etag_len(obj->meta);
}

static inline int
nst_disk_pos_header(nst_disk_obj_t *obj) {
    return NST_DISK_META_SIZE
        + nst_disk_meta_get_key_len(obj->meta)
        + nst_disk_meta_get_proxy_len(obj->meta)
        + nst_disk_meta_get_rule_len(obj->meta)
        + nst_disk_meta_get_host_len(obj->meta)
        + nst_disk_meta_get_path_len(obj->meta)
        + nst_disk_meta_get_etag_len(obj->meta)
        + nst_disk_meta_get_last_modified_len(obj->meta);
}

static inline int
nst_disk_write(nst_disk_obj_t *obj, char *buf, int len) {
    ssize_t ret = pwrite(obj->fd, buf, len, obj->offset);

    if(ret != len) {
        return NST_ERR;
    }

    obj->offset += len;

    return NST_OK;
}

static inline int
nst_disk_write_meta(nst_disk_obj_t *obj) {
    obj->offset = 0;

    return nst_disk_write(obj, obj->meta, NST_DISK_META_SIZE);
}

static inline int
nst_disk_write_key(nst_disk_obj_t *obj, nst_key_t *key) {
    obj->offset = NST_DISK_POS_KEY;

    return nst_disk_write(obj, key->data, key->size);
}

static inline int
nst_disk_write_proxy(nst_disk_obj_t *obj, hpx_ist_t proxy) {
    obj->offset = nst_disk_pos_proxy(obj);

    return nst_disk_write(obj, proxy.ptr, proxy.len);
}

static inline int
nst_disk_write_rule(nst_disk_obj_t *obj, hpx_ist_t rule) {
    obj->offset = nst_disk_pos_rule(obj);

    return nst_disk_write(obj, rule.ptr, rule.len);
}

static inline int
nst_disk_write_host(nst_disk_obj_t *obj, hpx_ist_t host) {
    obj->offset = nst_disk_pos_host(obj);

    return nst_disk_write(obj, host.ptr, host.len);
}

static inline int
nst_disk_write_path(nst_disk_obj_t *obj, hpx_ist_t path) {
    obj->offset = nst_disk_pos_path(obj);

    return nst_disk_write(obj, path.ptr, path.len);
}

static inline int
nst_disk_write_etag(nst_disk_obj_t *obj, hpx_ist_t etag) {
    obj->offset = nst_disk_pos_etag(obj);

    return nst_disk_write(obj, etag.ptr, etag.len);
}

static inline int
nst_disk_write_last_modified(nst_disk_obj_t *obj, hpx_ist_t lm) {
    obj->offset = nst_disk_pos_last_modified(obj);

    return nst_disk_write(obj, lm.ptr, lm.len);
}

int nst_disk_read_key(nst_disk_t *disk, nst_disk_obj_t *obj, nst_key_t *key);
int nst_disk_read_proxy(nst_disk_obj_t *obj, hpx_ist_t proxy);
int nst_disk_read_rule(nst_disk_obj_t *obj, hpx_ist_t rule);
int nst_disk_read_host(nst_disk_obj_t *obj, hpx_ist_t host);
int nst_disk_read_path(nst_disk_obj_t *obj, hpx_ist_t path);
int nst_disk_read_etag(nst_disk_obj_t *obj, hpx_ist_t etag);
int nst_disk_read_last_modified(nst_disk_obj_t *obj, hpx_ist_t last_modified);

int nst_disk_init(nst_disk_t *disk, hpx_ist_t root, nst_shmem_t *shmem, int clean_temp, void *data);
void nst_disk_load(nst_core_t *core);
void nst_disk_cleanup(nst_core_t *core);
int nst_disk_purge_by_key(nst_disk_obj_t *disk, nst_key_t *key, hpx_ist_t root);
int nst_disk_purge_by_path(char *path);
void nst_disk_update_expire(char *file, uint64_t expire);

int nst_disk_obj_create(nst_disk_t *disk, nst_disk_obj_t *obj, nst_key_t *key,
        nst_http_txn_t *txn, nst_rule_prop_t *prop);

static inline int
nst_disk_obj_append(nst_disk_t *disk, nst_disk_obj_t *obj, char *buf, int len) {

    if(nst_disk_write(obj, buf, len) != NST_OK) {
        if(obj->fd != -1) {
            close(obj->fd);
            obj->fd = -1;
        }

        if(obj->file) {
            remove(obj->file);
            nst_shmem_free(disk->shmem, obj->file);
            obj->file = NULL;
        }

        return NST_ERR;
    }

    return NST_OK;
}

int
nst_disk_obj_finish(nst_disk_t *disk, nst_disk_obj_t *obj, nst_key_t *key, nst_http_txn_t *txn,
        uint64_t expire);

static inline void
nst_disk_obj_abort(nst_disk_t *disk, nst_disk_obj_t *obj) {
    if(obj->fd != -1) {
        close(obj->fd);
        obj->fd = -1;
    }

    if(obj->file) {
        remove(obj->file);
        nst_shmem_free(disk->shmem, obj->file);
        obj->file = NULL;
    }
}

int nst_disk_obj_valid(nst_disk_obj_t *disk, nst_key_t *key);
int nst_disk_obj_exists(nst_disk_t *disk, nst_disk_obj_t *obj, nst_key_t *key);

#ifdef USE_THREAD
void *nst_disk_load_thread(void *core);
#endif

#endif /* _NUSTER_DISK_H */

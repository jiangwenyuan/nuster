/*
 * include/nuster/common.h
 * This file defines everything related to nuster common.
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

#ifndef _NUSTER_COMMON_H
#define _NUSTER_COMMON_H

#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/time.h>

#if defined NUSTER_USE_PTHREAD || defined USE_PTHREAD_PSHARED
#include <pthread.h>
#else
#ifdef USE_SYSCALL_FUTEX
#include <unistd.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#endif
#endif

#include <common/mini-clist.h>
#include <types/acl.h>
#include <types/global.h>
#include <import/xxhash.h>

#define NST_OK          0
#define NST_ERR         1

#define NST_DEFAULT_TTL                 0
#define NST_DEFAULT_SIZE                1024 * 1024
#define NST_DEFAULT_CHUNK_SIZE          32
#define NST_DEFAULT_DICT_SIZE           NST_DEFAULT_SIZE
#define NST_DEFAULT_DATA_SIZE           NST_DEFAULT_SIZE
#define NST_DEFAULT_DICT_CLEANER        100
#define NST_DEFAULT_DATA_CLEANER        100
#define NST_DEFAULT_DISK_CLEANER        100
#define NST_DEFAULT_DISK_LOADER         100
#define NST_DEFAULT_DISK_SAVER          100

enum {
    NST_STATUS_UNDEFINED = -1,
    NST_STATUS_OFF       =  0,
    NST_STATUS_ON        =  1,
};

enum {
    NST_MODE_CACHE = 1,
    NST_MODE_NOSQL,
};

enum nst_key_element_type {
    /* method: GET, POST... */
    NST_KEY_ELEMENT_METHOD = 1,

    /* scheme: http, https */
    NST_KEY_ELEMENT_SCHEME,

    /* host: Host header */
    NST_KEY_ELEMENT_HOST,

    /* uri: first slash to end of the url */
    NST_KEY_ELEMENT_URI,

    /* path: first slach to question mark */
    NST_KEY_ELEMENT_PATH,

    /* delimiter: '?' or '' */
    NST_KEY_ELEMENT_DELIMITER,

    /*query: question mark to end of the url, or empty */
    NST_KEY_ELEMENT_QUERY,

    /* param: query key/value pair */
    NST_KEY_ELEMENT_PARAM,

    /* header */
    NST_KEY_ELEMENT_HEADER,

    /* cookie */
    NST_KEY_ELEMENT_COOKIE,

    /* body */
    NST_KEY_ELEMENT_BODY,
};

enum {
    NST_RULE_DISABLED = 0,
    NST_RULE_ENABLED  = 1,
};

enum {
    /* no disk persistence */
    NST_DISK_OFF    = 0,

    /* disk persistence only, do not cache in memory */
    NST_DISK_ONLY,

    /* persist the response on disk before return to client */
    NST_DISK_SYNC,

    /* cache in memory first and persist on disk later */
    NST_DISK_ASYNC,
};

struct nst_key_element {
    enum nst_key_element_type  type;
    char                      *data;
};

struct nst_rule_key {
    char                      *name;
    struct nst_key_element   **data;           /* parsed key */
    int                        idx;

    struct nst_rule_key       *next;
};

struct nst_rule_code {
    struct nst_rule_code      *next;
    int                        code;
};

struct nst_rule_config {
    struct list                list;          /* list linked to from the proxy */

    int                        id;            /* same for identical names */
    char                      *name;          /* cache name for logging */
    struct nst_rule_key        key;
    struct nst_rule_code      *code;          /* code */
    uint32_t                   ttl;           /* ttl: seconds, 0: not expire */
    int                        disk;          /* NST_DISK_* */
    int                        etag;          /* etag on|off */
    int                        last_modified; /* last_modified on|off */

    /*
     * auto ttl extend
     *        ctime                   expire
     *        |<-        ttl        ->|
     * extend |  -  |  0  |  1  |  2  |  3  |
     * access |  0  |  1  |  2  |  3  |
     *
     * access is splited into 4 parts:
     * 0: ctime ~ expire - extend[0 + 1 + 2] * ttl
     * 1: expire - extend[0 + 1 + 2] * ttl ~ expire - extend[1 + 2] * ttl
     * 2: expire - extend[1 + 2] * ttl ~ expire - extend[2] * ttl
     * 3: expire - extend[2] * ttl ~ expire
     *
     * Automatic ttl extend happens if:
     * 1. access[3] >= access[2] >= access[1]
     * 2. expire <= atime <= expire + extend[3] * ttl
     */
    uint8_t                    extend[4];

    struct acl_cond           *cond;          /* acl condition to meet */
};


struct nst_key {
    uint32_t                   size;
    char                      *data;
    uint64_t                   hash;
};

struct nst_rule {
    int                        uuid;          /* unique rule ID */
    int                        idx;           /* index in specific proxy */
    int                        id;            /* same for identical names */

    int                        state;         /* enabled or disabled */

    char                      *name;          /* rule name for logging */
    struct nst_rule_key       *key;
    struct nst_rule_code      *code;          /* code */
    uint32_t                   ttl;           /* ttl: seconds, 0: not expire */
    int                        disk;          /* NST_DISK_* */
    int                        etag;          /* etag on|off */
    int                        last_modified; /* last_modified on|off */
    uint8_t                    extend[4];
    struct acl_cond           *cond;          /* acl condition to meet */

    struct nst_rule           *next;
};

struct nst_flt_conf {
    int status;
    int pid;
};


/* get current timestamp in milliseconds */
static inline uint64_t get_current_timestamp() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

const char *nst_parse_size(const char *text, uint64_t *ret);
const char *nst_parse_time(const char *text, int len, unsigned *ret);

void nst_debug(struct stream *s, const char *fmt, ...);
void nst_debug2(const char *fmt, ...);
void nst_debug_key(struct nst_key *key);

static inline void nst_key_init() {
    trash.head = 0;
    trash.data = 0;
    memset(trash.area, 0, trash.size);
}

static inline int nst_key_cat(const char *ptr, int len) {
    if(trash.data + len > trash.size) {
        return NST_ERR;
    }

    memcpy(trash.area + trash.data, ptr, len);
    trash.data += len;

    return NST_OK;
}

static inline int nst_key_catist(struct ist v) {
    /* additional one NULL delimiter */
    if(trash.data + v.len + 1 > trash.size) {
        return NST_ERR;
    }

    memcpy(trash.area + trash.data, v.ptr, v.len);
    trash.data += v.len + 1;

    return NST_OK;
}

static inline int nst_key_catdel() {
    if(trash.data + 1 > trash.size) {
        return NST_ERR;
    }

    trash.data += 1;

    return NST_OK;
}

int nst_test_rule(struct nst_rule *rule, struct stream *s, int res);

static inline void nst_hash(struct nst_key *key) {
    key->hash = XXH64(key->data, key->size, 0);
}

#endif /* _NUSTER_COMMON_H */

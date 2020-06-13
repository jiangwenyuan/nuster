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

typedef struct dirent                   nst_dirent_t;

typedef struct sample_fetch_kw_list     hpx_sample_fetch_kw_list_t;
typedef struct stream_interface         hpx_stream_interface_t;
typedef struct http_hdr_ctx             hpx_http_hdr_ctx_t;
typedef enum   http_meth_t              hpx_http_meth_t;
typedef enum   htx_blk_type             hpx_htx_blk_type_t;
typedef struct flt_conf                 hpx_flt_conf_t;
typedef struct http_msg                 hpx_http_msg_t;
typedef struct acl_cond                 hpx_acl_cond_t;
typedef struct http_txn                 hpx_http_txn_t;
typedef struct my_regex                 hpx_my_regex_t;
typedef struct channel                  hpx_channel_t;
typedef struct flt_ops                  hpx_flt_ops_t;
typedef struct htx_blk                  hpx_htx_blk_t;
typedef struct htx_ret                  hpx_htx_ret_t;
typedef struct session                  hpx_session_t;
typedef struct buffer                   hpx_buffer_t;
typedef struct stream                   hpx_stream_t;
typedef struct appctx                   hpx_appctx_t;
typedef struct applet                   hpx_applet_t;
typedef struct htx_sl                   hpx_htx_sl_t;
typedef struct filter                   hpx_filter_t;
typedef struct sample                   hpx_sample_t;
typedef struct proxy                    hpx_proxy_t;
typedef struct list                     hpx_list_t;
typedef struct ist                      hpx_ist_t;
typedef struct htx                      hpx_htx_t;
typedef struct arg                      hpx_arg_t;

typedef struct nst_core                 nst_core_t;

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <dirent.h>
#include <inttypes.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>


#if defined NUSTER_USE_PTHREAD || defined USE_PTHREAD_PSHARED
#include <pthread.h>
#else
#ifdef USE_SYSCALL_FUTEX
#include <unistd.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#endif
#endif


#define NST_OK                          0
#define NST_ERR                         1

#define NST_DEFAULT_TTL                 0
#define NST_DEFAULT_SIZE                1024 * 1024
#define NST_DEFAULT_CHUNK_SIZE          32
#define NST_DEFAULT_DICT_SIZE           NST_DEFAULT_SIZE
#define NST_DEFAULT_DATA_SIZE           NST_DEFAULT_SIZE
#define NST_DEFAULT_DICT_CLEANER        1000
#define NST_DEFAULT_DATA_CLEANER        1000
#define NST_DEFAULT_DISK_CLEANER        100
#define NST_DEFAULT_DISK_LOADER         100
#define NST_DEFAULT_DISK_SAVER          100
#define NST_DEFAULT_KEY                "method.scheme.host.uri"
#define NST_DEFAULT_CODE               "200"

enum {
    NST_STATUS_UNDEFINED        = -1,
    NST_STATUS_OFF              =  0,
    NST_STATUS_ON               =  1,
};

enum {
    NST_MODE_CACHE              = 1,
    NST_MODE_NOSQL              = 2,
};

enum {
    NST_RULE_DISABLED           = 0,
    NST_RULE_ENABLED            = 1,
};

enum {
    NST_TIME_OK                 = 0,
    NST_TIME_OVER               = 1,
    NST_TIME_ERR                = 2,
};

enum {
    NST_STORE_MEMORY_ON         = 0x0001,
    NST_STORE_MEMORY_OFF        = 0x0002,
    NST_STORE_DISK_ON           = 0x0004,
    NST_STORE_DISK_OFF          = 0x0008,
    NST_STORE_DISK_SYNC         = 0x0010,
};

enum nst_key_element_type {
    /* method: GET, POST... */
    NST_KEY_ELEMENT_METHOD      = 1,

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

typedef struct nst_key_element {
    enum nst_key_element_type  type;
    char                      *data;
} nst_key_element_t;

typedef struct nst_rule_key {
    struct nst_rule_key       *next;

    char                      *name;
    nst_key_element_t        **data;           /* parsed key */
    int                        idx;
} nst_rule_key_t;

typedef struct nst_rule_code {
    struct nst_rule_code      *next;

    int                        code;
} nst_rule_code_t;

typedef struct nst_rule_config {
    hpx_list_t                 list;          /* list linked to from the proxy */

    char                      *name;          /* cache name for logging */
    char                      *proxy;         /* proxy name */
    nst_rule_key_t             key;
    nst_rule_code_t           *code;          /* code */
    uint8_t                    store;
    int                        ttl;           /* ttl: seconds, 0: not expire, -1: auto */
    int                        etag;          /* etag on|off */
    int                        last_modified; /* last_modified on|off */
    int                        wait;          /* -1: not wait, 0: wait forever, > 0, wait seconds */
    int                        inactive;      /* 0: disabled, > 0: inactive seconds */

    /*
     *  -1: do not use stale
     *   0: use stale while updating
     * > 0: keep for N seconds if update failed and use stale
     */
    int                        stale;

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

    hpx_acl_cond_t            *cond;          /* acl condition to meet */
} nst_rule_config_t;

typedef struct nst_rule_prop {
    hpx_ist_t                  pid;           /* proxy name */
    hpx_ist_t                  rid;           /* rule name */
    uint8_t                    store;
    int                        ttl;
    int                        etag;
    int                        last_modified;
    uint8_t                    extend[4];
    int                        wait;
    int                        inactive;
    int                        stale;
    int                        status_code;
} nst_rule_prop_t;

typedef struct nst_rule {
    struct nst_rule           *next;

    int                        uuid;          /* unique rule ID */
    int                        idx;           /* index in specific proxy */

    int                        state;         /* enabled or disabled */

    nst_rule_key_t            *key;
    nst_rule_code_t           *code;          /* code */

    nst_rule_prop_t            prop;

    hpx_acl_cond_t            *cond;          /* acl condition to meet */
} nst_rule_t;

typedef struct nst_flt_conf {
    int                       status;
    int                       pid;
} nst_flt_conf_t;


/* get current timestamp in milliseconds */
static inline uint64_t
nst_time_now_ms() {
    struct timespec  ts;

    clock_gettime(CLOCK_REALTIME, &ts);

    return (uint64_t) ts.tv_sec * 1000 + (uint64_t) ts.tv_nsec / 1000000;
}

/* get current timestamp in nanoseconds */
static inline uint64_t
nst_time_now_ns() {
    struct timespec  ts;

    clock_gettime(CLOCK_REALTIME, &ts);

    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

const char *nst_parse_size(const char *text, uint64_t *ret);
int nst_parse_time(const char *text, int len, uint32_t *ret);

void nst_debug(hpx_stream_t *s, const char *fmt, ...);
void nst_debug_beg(hpx_stream_t *s, const char *fmt, ...);
void nst_debug_add(const char *fmt, ...);
void nst_debug_end(const char *fmt, ...);

#endif /* _NUSTER_COMMON_H */

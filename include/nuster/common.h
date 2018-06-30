/*
 * include/nuster/common.h
 * This file defines everything related to nuster common.
 *
 * Copyright (C) [Jiang Wenyuan](https://github.com/jiangwenyuan), < koubunen AT gmail DOT com >
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
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

enum {
    NUSTER_STATUS_UNDEFINED = -1,
    NUSTER_STATUS_OFF       =  0,
    NUSTER_STATUS_ON        =  1,
};

enum {
    NUSTER_MODE_CACHE = 1,
    NUSTER_MODE_NOSQL,
};

enum {
    NUSTER_HTTP_200 = 0,
    NUSTER_HTTP_400,
    NUSTER_HTTP_404,
    NUSTER_HTTP_405,
    NUSTER_HTTP_500,
    NUSTER_HTTP_507,
    NUSTER_HTTP_SIZE
};

#define nuster_str_set(str)     { (char *) str, sizeof(str) - 1 }

struct nuster_str {
    char *data;
    int   len;
};

enum nuster_rule_key_type {
    NUSTER_RULE_KEY_METHOD = 1,                /* method:    GET, POST... */
    NUSTER_RULE_KEY_SCHEME,                    /* scheme:    http, https */
    NUSTER_RULE_KEY_HOST,                      /* host:      Host header   */
    NUSTER_RULE_KEY_URI,                       /* uri:       first slash to end of the url */
    NUSTER_RULE_KEY_PATH,                      /* path:      first slach to question mark */
    NUSTER_RULE_KEY_DELIMITER,                 /* delimiter: '?' or '' */
    NUSTER_RULE_KEY_QUERY,                     /* query:     question mark to end of the url, or empty */
    NUSTER_RULE_KEY_PARAM,                     /* param:     query key/value pair */
    NUSTER_RULE_KEY_HEADER,                    /* header */
    NUSTER_RULE_KEY_COOKIE,                    /* cookie */
    NUSTER_RULE_KEY_BODY,                      /* body   */
};

struct nuster_rule_key {
    enum nuster_rule_key_type  type;
    char                      *data;
};

struct nuster_rule_code {
    struct nuster_rule_code *next;
    int                      code;
};

enum {
    NUSTER_RULE_DISABLED = 0,
    NUSTER_RULE_ENABLED  = 1,
};

struct nuster_rule {
    struct list              list;       /* list linked to from the proxy */
    struct acl_cond         *cond;       /* acl condition to meet */
    char                    *name;       /* cache name for logging */
    struct nuster_rule_key **key;        /* key */
    struct nuster_rule_code *code;       /* code */
    uint32_t                *ttl;        /* ttl: seconds, 0: not expire */
    int                     *state;      /* on when start, can be turned off by manager API */
    int                      id;         /* same for identical names */
    int                      uuid;       /* unique cache-rule ID */
};

struct nuster_rule_stash {
    struct nuster_rule_stash *next;
    struct nuster_rule       *rule;
    char                     *key;
    uint64_t                  hash;
};

struct nuster_flt_conf {
    int status;
};

struct nuster_headers {
    struct nuster_str server;
    struct nuster_str date;
    struct nuster_str content_length;
    struct nuster_str content_type;
    struct nuster_str transfer_encoding;
    struct nuster_str last_modified;
    struct nuster_str expires;
    struct nuster_str cache_control;
    struct nuster_str etag;
};


/* get current timestamp in milliseconds */
static inline uint64_t get_current_timestamp() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

void nuster_debug(const char *fmt, ...);

#endif /* _NUSTER_COMMON_H */

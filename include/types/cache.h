/*
 * include/types/cache.h
 * This file defines everything related to cache.
 *
 * Copyright (C) 2017, [Jiang Wenyuan](https://github.com/jiangwenyuan), < koubunen AT gmail DOT com >
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

#ifndef _TYPES_CACHE_H
#define _TYPES_CACHE_H

#include <stdint.h>

#include <common/memory.h>

#include <types/acl.h>
#include <types/filters.h>
#include <types/obj_type.h>
#include <types/proto_http.h>
#include <types/sample.h>
#include <types/applet.h>

#define NUSTER_VERSION                HAPROXY_VERSION".1"
#define NUSTER_COPYRIGHT             "2017, Jiang Wenyuan, <koubunen AT gmail DOT com >"
#define CACHE_DEFAULT_SIZE            1024 * 1024
#define CACHE_DEFAULT_TTL             3600
#define CACHE_DEFAULT_DICT_SIZE       32
#define CACHE_DEFAULT_LOAD_FACTOR     0.75
#define CACHE_DEFAULT_GROWTH_FACTOR   2
#define CACHE_DEFAULT_KEY            "method.scheme.host.path.query.body"
#define CACHE_DEFAULT_CODE           "200"
#define CACHE_DEFAULT_KEY_SIZE        128

#define CACHE_STATUS_UNDEFINED       -1
#define CACHE_STATUS_OFF              0
#define CACHE_STATUS_ON               1

enum ck_type {
    CK_METHOD = 1,                /* method */
    CK_SCHEME,                    /* scheme */
    CK_HOST,                      /* host   */
    CK_PATH,                      /* path   */
    CK_QUERY,                     /* query  */
    CK_PARAM,                     /* param  */
    CK_HEADER,                    /* header */
    CK_COOKIE,                    /* cookie */
    CK_BODY,                      /* body   */
};

struct cache_key {
    enum ck_type  type;
    char         *data;
};

struct cache_code {
    int                code;
    struct cache_code *next;
};

struct cache_rule {
    struct list         list;       /* list linked to from the proxy */
    struct acl_cond    *cond;       /* acl condition to meet */
    char               *name;       /* cache name for logging */
    struct cache_key  **key;        /* key */
    struct cache_code  *code;       /* code */
    uint64_t            ttl;        /* ttl: seconds, 0: not expire */
};

struct cache_element {
    char                 *msg;
    int                   msg_len;
    struct cache_element *next;
};

/*
 * A cache_data contains a complete http response data,
 * and is pointed by cache_entry->data.
 * All cache_data are stored in a circular singly linked list
 */
struct cache_data {
    int                   clients;
    int                   invalid;
    struct cache_element *element;
    struct cache_data    *next;
};

/*
 * A cache_entry is an entry in cache_dict hash table
 */
#define CACHE_ENTRY_STATE_CREATING  0
#define CACHE_ENTRY_STATE_VALID     1
#define CACHE_ENTRY_STATE_INVALID   2
#define CACHE_ENTRY_STATE_EXPIRED   3
struct cache_entry {
    int                 state;
    char               *key;
    uint64_t            hash;
    struct cache_data  *data;
    uint64_t            expire;
    uint64_t            atime;
    struct cache_entry *next;
};

struct cache_dict {
    struct cache_entry **entry;
    uint64_t             size;      /* number of entries */
    uint64_t             used;      /* number of used entries */
};

struct cache_rule_stash {
    struct cache_rule       *rule;
    char                    *key;
    uint64_t                 hash;
    struct cache_rule_stash *next;
};

#define CACHE_CTX_STATE_INIT        0   /* init */
#define CACHE_CTX_STATE_CREATE      1   /* to cache */
#define CACHE_CTX_STATE_DONE        2   /* cache done */
#define CACHE_CTX_STATE_BYPASS      3   /* not cached, return to regular process */
#define CACHE_CTX_STATE_WAIT        4   /* caching, wait */
#define CACHE_CTX_STATE_HIT         5   /* cached, use cache */
#define CACHE_CTX_STATE_PASS        6   /* cache rule passed */
#define CACHE_CTX_STATE_FULL        7   /* cache full */
struct cache_ctx {
    int                      state;

    struct cache_rule       *rule;
    struct cache_rule_stash *stash;

    struct cache_entry      *entry;
    struct cache_data       *data;
    struct cache_element    *element;

};

struct cache_stats {
    uint64_t used_mem;
    uint64_t requests;
    uint64_t hits;
};

struct cache {
    struct cache_dict  dict[2];           /* 0: using, 1: rehashing */
    struct cache_data *data_head;         /* point to the circular linked list, tail->next ===  head */
    struct cache_data *data_tail;         /* and will be moved together constantly to check invalid data */

    int                rehash_idx;        /* >=0: rehashing, index, -1: not rehashing */
    int                cleanup_idx;       /* cache dict cleanup index */
};

struct cache_config {
    int status;
};


extern struct cache   *cache;
extern struct applet   cache_applet;
extern struct flt_ops  cache_filter_ops;

#endif /* _TYPES_CACHE_H */

/*
 * include/nuster/cache.h
 * This file defines everything related to nuster cache.
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

#ifndef _NUSTER_CACHE_H
#define _NUSTER_CACHE_H

#include <stdint.h>

#include <common/memory.h>

#include <types/acl.h>
#include <types/filters.h>
#include <types/obj_type.h>
#include <types/proto_http.h>
#include <types/sample.h>
#include <types/applet.h>

#include <nuster/common.h>
#include <nuster/memory.h>

#define CACHE_DEFAULT_SIZE                1024 * 1024
#define CACHE_DEFAULT_TTL                 3600
#define CACHE_DEFAULT_DICT_SIZE           32
#define CACHE_DEFAULT_LOAD_FACTOR         0.75
#define CACHE_DEFAULT_GROWTH_FACTOR       2
#define CACHE_DEFAULT_KEY                "method.scheme.host.uri"
#define CACHE_DEFAULT_CODE               "200"
#define CACHE_DEFAULT_KEY_SIZE            128
#define CACHE_DEFAULT_CHUNK_SIZE          32
#define CACHE_DEFAULT_PURGE_METHOD       "PURGE"
#define CACHE_DEFAULT_PURGE_METHOD_SIZE   16

enum {
    CACHE_STATUS_UNDEFINED = -1,
    CACHE_STATUS_OFF       =  0,
    CACHE_STATUS_ON        =  1,
    CACHE_SHARE_UNDEFINED  = -1,
    CACHE_SHARE_OFF        =  0,
    CACHE_SHARE_ON         =  1,
};

enum ck_type {
    CK_METHOD = 1,                /* method:    GET, POST... */
    CK_SCHEME,                    /* scheme:    http, https */
    CK_HOST,                      /* host:      Host header   */
    CK_URI,                       /* uri:       first slash to end of the url */
    CK_PATH,                      /* path:      first slach to question mark */
    CK_DELIMITER,                 /* delimiter: '?' or '' */
    CK_QUERY,                     /* query:     question mark to end of the url, or empty */
    CK_PARAM,                     /* param:     query key/value pair */
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

enum {
    CACHE_RULE_DISABLED = 0,
    CACHE_RULE_ENABLED  = 1,
};

struct cache_rule {
    struct list         list;       /* list linked to from the proxy */
    struct acl_cond    *cond;       /* acl condition to meet */
    char               *name;       /* cache name for logging */
    struct cache_key  **key;        /* key */
    struct cache_code  *code;       /* code */
    uint32_t           *ttl;        /* ttl: seconds, 0: not expire */
    int                *state;      /* on when start, can be turned off by manager API */
    int                 id;         /* same for identical names */
    int                 uuid;       /* unique cache-rule ID */
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
enum {
    CACHE_ENTRY_STATE_CREATING = 0,
    CACHE_ENTRY_STATE_VALID    = 1,
    CACHE_ENTRY_STATE_INVALID  = 2,
    CACHE_ENTRY_STATE_EXPIRED  = 3,
};

struct cache_entry {
    int                 state;
    char               *key;
    uint64_t            hash;
    struct cache_data  *data;
    uint64_t            expire;
    uint64_t            atime;
    struct nuster_str   host;
    struct nuster_str   path;
    struct cache_entry *next;
    struct cache_rule  *rule;        /* rule */
    int                 pid;         /* proxy uuid */
};

struct cache_dict {
    struct cache_entry **entry;
    uint64_t             size;      /* number of entries */
    uint64_t             used;      /* number of used entries */
#if defined NUSTER_USE_PTHREAD || defined USE_PTHREAD_PSHARED
    pthread_mutex_t      mutex;
#else
    unsigned int         waiters;
#endif
};

struct cache_rule_stash {
    struct cache_rule       *rule;
    char                    *key;
    uint64_t                 hash;
    struct cache_rule_stash *next;
};

enum {
    CACHE_CTX_STATE_INIT   = 0,   /* init */
    CACHE_CTX_STATE_CREATE = 1,   /* to cache */
    CACHE_CTX_STATE_DONE   = 2,   /* cache done */
    CACHE_CTX_STATE_BYPASS = 3,   /* not cached, return to regular process */
    CACHE_CTX_STATE_WAIT   = 4,   /* caching, wait */
    CACHE_CTX_STATE_HIT    = 5,   /* cached, use cache */
    CACHE_CTX_STATE_PASS   = 6,   /* cache rule passed */
    CACHE_CTX_STATE_FULL   = 7,   /* cache full */
};

struct cache_ctx {
    int                      state;

    struct cache_rule       *rule;
    struct cache_rule_stash *stash;

    struct cache_entry      *entry;
    struct cache_data       *data;
    struct cache_element    *element;

    struct {
        int                  scheme;
        struct nuster_str    host;
        struct nuster_str    uri;
        struct nuster_str    path;
        int                  delimiter;
        struct nuster_str    query;
        struct nuster_str    cookie;
    } req;
    int                      pid;         /* proxy uuid */
};

struct cache_stats {
    uint64_t        used_mem;

    struct {
        uint64_t    total;
        uint64_t    fetch;
        uint64_t    hit;
        uint64_t    abort;
    } request;
#if defined NUSTER_USE_PTHREAD || defined USE_PTHREAD_PSHARED
    pthread_mutex_t mutex;
#else
    unsigned int    waiters;
#endif
};

struct cache {
    struct cache_dict  dict[2];           /* 0: using, 1: rehashing */
    struct cache_data *data_head;         /* point to the circular linked list, tail->next ===  head */
    struct cache_data *data_tail;         /* and will be moved together constantly to check invalid data */
#if defined NUSTER_USE_PTHREAD || defined USE_PTHREAD_PSHARED
    pthread_mutex_t    mutex;
#else
    unsigned int       waiters;
#endif

    int                rehash_idx;        /* >=0: rehashing, index, -1: not rehashing */
    int                cleanup_idx;       /* cache dict cleanup index */
};

struct cache_config {
    int status;
};


extern struct cache   *cache;
extern struct applet   cache_io_applet;
extern struct applet   cache_manager_applet;
extern struct applet   cache_stats_applet;
extern struct flt_ops  cache_filter_ops;

enum {
    NUSTER_CACHE_200 = 0,
    NUSTER_CACHE_400,
    NUSTER_CACHE_404,
    NUSTER_CACHE_500,
    NUSTER_CACHE_MSG_SIZE
};

enum {
    NUSTER_CACHE_PURGE_MODE_NAME_ALL = 0,
    NUSTER_CACHE_PURGE_MODE_NAME_PROXY,
    NUSTER_CACHE_PURGE_MODE_NAME_RULE,
    NUSTER_CACHE_PURGE_MODE_PATH,
    NUSTER_CACHE_PURGE_MODE_REGEX,
    NUSTER_CACHE_PURGE_MODE_HOST,
    NUSTER_CACHE_PURGE_MODE_PATH_HOST,
    NUSTER_CACHE_PURGE_MODE_REGEX_HOST,
};

enum {
    NUSTER_CACHE_STATS_HEAD,
    NUSTER_CACHE_STATS_DATA,
    NUSTER_CACHE_STATS_DONE,
};


#include <common/config.h>

#include <types/global.h>
#include <types/proxy.h>
#include <types/filters.h>
//#include <types/cache.h>

/* dict */
int cache_dict_init();
struct cache_entry *cache_dict_get(const char *key, uint64_t hash);
struct cache_entry *cache_dict_set(const char *key, uint64_t hash, struct cache_ctx *ctx);
void cache_dict_rehash();
void cache_dict_cleanup();


/* engine */
void cache_debug(const char *fmt, ...);
void cache_init();
void cache_housekeeping();
int cache_prebuild_key(struct cache_ctx *ctx, struct stream *s, struct http_msg *msg);
char *cache_build_key(struct cache_ctx *ctx, struct cache_key **pck, struct stream *s,
        struct http_msg *msg);
char *cache_build_purge_key(struct stream *s, struct http_msg *msg);
uint64_t cache_hash_key(const char *key);
void cache_create(struct cache_ctx *ctx, char *key, uint64_t hash);
int cache_update(struct cache_ctx *ctx, struct http_msg *msg, long msg_len);
void cache_finish(struct cache_ctx *ctx);
void cache_abort(struct cache_ctx *ctx);
struct cache_data *cache_exists(const char *key, uint64_t hash);
struct cache_data *cache_data_new();
void cache_hit(struct stream *s, struct stream_interface *si,
        struct channel *req, struct channel *res, struct cache_data *data);
struct cache_rule_stash *cache_stash_rule(struct cache_ctx *ctx,
        struct cache_rule *rule, char *key, uint64_t hash);
int cache_test_rule(struct cache_rule *rule, struct stream *s, int res);
int cache_purge(struct stream *s, struct channel *req, struct proxy *px);
int cache_manager(struct stream *s, struct channel *req, struct proxy *px);


/* parser */
int cache_parse_filter(char **args, int *cur_arg, struct proxy *px,
        struct flt_conf *fconf, char **err, void *private);
int cache_parse_rule(char **args, int section, struct proxy *proxy,
        struct proxy *defpx, const char *file, int line, char **err);
const char *cache_parse_size(const char *text, uint64_t *ret);
const char *cache_parse_time(const char *text, int len, unsigned *ret);

/* cache memory */
static inline void *cache_memory_alloc(struct pool_head *pool, int size) {
    if(global.cache.share) {
        return nuster_memory_alloc(global.cache.memory, size);
    } else {
        return pool_alloc2(pool);
    }
}
static inline void cache_memory_free(struct pool_head *pool, void *p) {
    if(global.cache.share) {
        return nuster_memory_free(global.cache.memory, p);
    } else {
        return pool_free2(pool, p);
    }
}

/* stats */
void cache_stats_update_used_mem(int i);
int cache_stats_init();
int cache_stats_full();
int cache_stats(struct stream *s, struct channel *req, struct proxy *px);
void cache_stats_update_request(int state);

static inline int cache_check_uri(struct http_msg *msg) {
    const char *uri = msg->chn->buf->p + msg->sl.rq.u;

    if(!global.cache.uri) {
        return 0;
    }

    if(strlen(global.cache.uri) != msg->sl.rq.u_l) {
        return 0;
    }

    if(memcmp(uri, global.cache.uri, msg->sl.rq.u_l) != 0) {
        return 0;
    }

    return 1;
}


#endif /* _NUSTER_CACHE_H */

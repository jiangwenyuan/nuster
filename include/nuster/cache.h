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

#include <common/config.h>
#include <common/memory.h>

#include <types/global.h>
#include <types/acl.h>
#include <types/filters.h>
#include <types/applet.h>

#include <nuster/memory.h>

#define NST_CACHE_DEFAULT_SIZE                1024 * 1024
#define NST_CACHE_DEFAULT_TTL                 3600
#define NST_CACHE_DEFAULT_DICT_SIZE           32
#define NST_CACHE_DEFAULT_LOAD_FACTOR         0.75
#define NST_CACHE_DEFAULT_GROWTH_FACTOR       2
#define NST_CACHE_DEFAULT_KEY                "method.scheme.host.uri"
#define NST_CACHE_DEFAULT_CODE               "200"
#define NST_CACHE_DEFAULT_KEY_SIZE            128
#define NST_CACHE_DEFAULT_CHUNK_SIZE          32
#define NST_CACHE_DEFAULT_PURGE_METHOD       "PURGE"
#define NST_CACHE_DEFAULT_PURGE_METHOD_SIZE   16

enum {
    NST_CACHE_STATUS_UNDEFINED = -1,
    NST_CACHE_STATUS_OFF       =  0,
    NST_CACHE_STATUS_ON        =  1,
};
enum {
    NST_CACHE_SHARE_UNDEFINED  = -1,
    NST_CACHE_SHARE_OFF        =  0,
    NST_CACHE_SHARE_ON         =  1,
};

enum nst_cache_key_type {
    NST_CACHE_KEY_METHOD = 1,                /* method:    GET, POST... */
    NST_CACHE_KEY_SCHEME,                    /* scheme:    http, https */
    NST_CACHE_KEY_HOST,                      /* host:      Host header   */
    NST_CACHE_KEY_URI,                       /* uri:       first slash to end of the url */
    NST_CACHE_KEY_PATH,                      /* path:      first slach to question mark */
    NST_CACHE_KEY_DELIMITER,                 /* delimiter: '?' or '' */
    NST_CACHE_KEY_QUERY,                     /* query:     question mark to end of the url, or empty */
    NST_CACHE_KEY_PARAM,                     /* param:     query key/value pair */
    NST_CACHE_KEY_HEADER,                    /* header */
    NST_CACHE_KEY_COOKIE,                    /* cookie */
    NST_CACHE_KEY_BODY,                      /* body   */
};

struct nst_cache_key {
    enum nst_cache_key_type  type;
    char                    *data;
};

struct nst_cache_code {
    struct nst_cache_code *next;
    int                    code;
};

enum {
    NST_CACHE_RULE_DISABLED = 0,
    NST_CACHE_RULE_ENABLED  = 1,
};

struct nst_cache_rule {
    struct list             list;       /* list linked to from the proxy */
    struct acl_cond        *cond;       /* acl condition to meet */
    char                   *name;       /* cache name for logging */
    struct nst_cache_key  **key;        /* key */
    struct nst_cache_code  *code;       /* code */
    uint32_t               *ttl;        /* ttl: seconds, 0: not expire */
    int                    *state;      /* on when start, can be turned off by manager API */
    int                     id;         /* same for identical names */
    int                     uuid;       /* unique cache-rule ID */
};

struct nst_cache_element {
    struct nst_cache_element *next;
    char                     *msg;
    int                       msg_len;
};

/*
 * A nst_cache_data contains a complete http response data,
 * and is pointed by cache_entry->data.
 * All nst_cache_data are stored in a circular singly linked list
 */
struct nst_cache_data {
    int                       clients;
    int                       invalid;
    struct nst_cache_element *element;
    struct nst_cache_data    *next;
};

/*
 * A cache_entry is an entry in cache_dict hash table
 */
enum {
    NST_CACHE_ENTRY_STATE_CREATING = 0,
    NST_CACHE_ENTRY_STATE_VALID    = 1,
    NST_CACHE_ENTRY_STATE_INVALID  = 2,
    NST_CACHE_ENTRY_STATE_EXPIRED  = 3,
};

struct cache_entry {
    int                     state;
    char                   *key;
    uint64_t                hash;
    struct nst_cache_data  *data;
    uint64_t                expire;
    uint64_t                atime;
    struct nuster_str       host;
    struct nuster_str       path;
    struct cache_entry     *next;
    struct nst_cache_rule  *rule;        /* rule */
    int                     pid;         /* proxy uuid */
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
    struct nst_cache_rule   *rule;
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
    int                       state;

    struct nst_cache_rule    *rule;
    struct cache_rule_stash  *stash;

    struct cache_entry       *entry;
    struct nst_cache_data    *data;
    struct nst_cache_element *element;

    struct {
        int                   scheme;
        struct nuster_str     host;
        struct nuster_str     uri;
        struct nuster_str     path;
        int                   delimiter;
        struct nuster_str     query;
        struct nuster_str     cookie;
    } req;
    int                       pid;         /* proxy uuid */
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
    struct cache_dict      dict[2];           /* 0: using, 1: rehashing */
    struct nst_cache_data *data_head;         /* point to the circular linked list, tail->next ===  head */
    struct nst_cache_data *data_tail;         /* and will be moved together constantly to check invalid data */
#if defined NUSTER_USE_PTHREAD || defined USE_PTHREAD_PSHARED
    pthread_mutex_t        mutex;
#else
    unsigned int           waiters;
#endif

    int                    rehash_idx;        /* >=0: rehashing, index, -1: not rehashing */
    int                    cleanup_idx;       /* cache dict cleanup index */
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
char *cache_build_key(struct cache_ctx *ctx, struct nst_cache_key **pck, struct stream *s,
        struct http_msg *msg);
char *cache_build_purge_key(struct stream *s, struct http_msg *msg);
uint64_t cache_hash_key(const char *key);
void cache_create(struct cache_ctx *ctx, char *key, uint64_t hash);
int cache_update(struct cache_ctx *ctx, struct http_msg *msg, long msg_len);
void cache_finish(struct cache_ctx *ctx);
void cache_abort(struct cache_ctx *ctx);
struct nst_cache_data *cache_exists(const char *key, uint64_t hash);
struct nst_cache_data *cache_data_new();
void cache_hit(struct stream *s, struct stream_interface *si,
        struct channel *req, struct channel *res, struct nst_cache_data *data);
struct cache_rule_stash *cache_stash_rule(struct cache_ctx *ctx,
        struct nst_cache_rule *rule, char *key, uint64_t hash);
int cache_test_rule(struct nst_cache_rule *rule, struct stream *s, int res);
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

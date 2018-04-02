/*
 * include/types/cache.h
 * This file defines everything related to cache.
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

#define NUSTER_VERSION                    HAPROXY_VERSION".9"
#define NUSTER_COPYRIGHT                 "2017-2018, Jiang Wenyuan, <koubunen AT gmail DOT com >"
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

struct nst_string {
    char *data;
    int   len;
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
    struct nst_string   host;
    struct nst_string   path;
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
        struct nst_string    host;
        struct nst_string    uri;
        struct nst_string    path;
        int                  delimiter;
        struct nst_string    query;
        struct nst_string    cookie;
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


/* nuster memory */

#define NUSTER_MEMORY_BLOCK_MIN_SIZE      4096ULL
#define NUSTER_MEMORY_BLOCK_MIN_SHIFT     12
#define NUSTER_MEMORY_CHUNK_MIN_SIZE      8ULL
#define NUSTER_MEMORY_CHUNK_MIN_SHIFT     3
#define NUSTER_MEMORY_BLOCK_MAX_SIZE      1024 * 1024 * 2
#define NUSTER_MEMORY_BLOCK_MAX_SHIFT     21
#define NUSTER_MEMORY_INFO_BITMAP_BITS    32


/* start                                 alignment                   stop
 * |                                     |   |                       |
 * |_______|_0_|_...._|_M_|_0_|_..._|_N__|_*_|__0__|__...__|__N__|_*_|
 *         |              |                  |             |     |
 *         chunk        block              begin         end   <bitmap>
 *
 *
 */

/*
 * info: | bitmap: 32 | reserved: 24 | 1 | full: 1 | bitmap: 1 | inited: 1 | type: 4 |
 * info: | bitmap: 32 | reserved: 16 | 5 | full: 1 | bitmap: 1 | inited: 1 | type: 8 |
 * bitmap: points to bitmap area, doesn't change once set
 * chunk size[n]: 1<<(NUSTER_MEMORY_CHUNK_MIN_SHIFT + n)
 */
struct nuster_memory_ctrl {
    uint64_t                   info;
    uint8_t                   *bitmap;

    struct nuster_memory_ctrl *prev;
    struct nuster_memory_ctrl *next;
};

struct nuster_memory {
    uint8_t                    *start;
    uint8_t                    *stop;
    uint8_t                    *bitmap;
    char                        name[16];
#if defined NUSTER_USE_PTHREAD || defined USE_PTHREAD_PSHARED
    pthread_mutex_t             mutex;
#else
    unsigned int                waiters;
#endif

    uint32_t                    block_size;  /* max memory can be allocated */
    uint32_t                    chunk_size;  /* min memory can be allocated */
    int                         chunk_shift;
    int                         block_shift;

    int                         chunks;
    int                         blocks;
    struct nuster_memory_ctrl **chunk;
    struct nuster_memory_ctrl  *block;
    struct nuster_memory_ctrl  *empty;
    struct nuster_memory_ctrl  *full;

    struct {
        uint8_t                *begin;
        uint8_t                *free;
        uint8_t                *end;
    } data;
};

#endif /* _TYPES_CACHE_H */
/*
 * include/types/cache.h
 * This file defines everything related to cache.
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

#ifndef _PROTO_CACHE_H
#define _PROTO_CACHE_H

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

/* get current timestamp in milliseconds */
static inline uint64_t get_current_timestamp() {
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* get current timestamp in seconds */
static inline uint64_t get_current_timestamp_s() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec;
}

/* memory */
#define bit_set(bit, i) (bit |= 1 << i)
#define bit_clear(bit, i) (bit &= ~(1 << i))
#define bit_used(bit, i) (((bit) >> (i)) & 1)
#define bit_unused(bit, i) ((((bit) >> (i)) & 1) == 0)
static inline void _nuster_memory_block_set_type(struct nuster_memory_ctrl *block, uint8_t type) {
    *(uint8_t *)(&block->info) = type;
}
static inline void _nuster_memory_block_set_inited(struct nuster_memory_ctrl *block) {
    bit_set(block->info, 9);
}
static inline int _nuster_memory_block_is_inited(struct nuster_memory_ctrl *block) {
    return bit_used(block->info, 9);
}
static inline void _nuster_memory_block_set_bitmap(struct nuster_memory_ctrl *block) {
    bit_set(block->info, 10);
}
static inline void _nuster_memory_block_set_full(struct nuster_memory_ctrl *block) {
    bit_set(block->info, 11);
}
static inline int _nuster_memory_block_is_full(struct nuster_memory_ctrl *block) {
    return bit_used(block->info, 11);
}
static inline void _nuster_memory_block_clear_full(struct nuster_memory_ctrl *block) {
    bit_clear(block->info, 11);
}

struct nuster_memory *nuster_memory_create(char *name, uint64_t size, uint32_t block_size, uint32_t chunk_size);
void *nuster_memory_alloc(struct nuster_memory *memory, int size);
void nuster_memory_free(struct nuster_memory *memory, void *p);

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


/* lock, borrowed from shctx.c */
#if defined NUSTER_USE_PTHREAD || defined USE_PTHREAD_PSHARED
#include <pthread.h>
#else
#ifdef USE_SYSCALL_FUTEX
#include <unistd.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#endif
#endif

#if defined NUSTER_USE_PTHREAD || defined USE_PTHREAD_PSHARED

static inline int _nuster_shctx_init(pthread_mutex_t *mutex) {
    if(global.cache.share) {
        pthread_mutexattr_t attr;
        if(pthread_mutexattr_init(&attr)) {
            return 0;
        }
        if(pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED)) {
            return 0;
        }
        if(pthread_mutex_init(mutex, &attr)) {
            return 0;
        }
    }
    return 1;
}

#define nuster_shctx_init(shctx)   _nuster_shctx_init(&(shctx)->mutex)
#define nuster_shctx_lock(shctx)   if (global.cache.share) pthread_mutex_lock(&(shctx)->mutex)
#define nuster_shctx_unlock(shctx) if (global.cache.share) pthread_mutex_unlock(&(shctx)->mutex)

#else

#ifdef USE_SYSCALL_FUTEX
static inline void _shctx_wait4lock(unsigned int *count, unsigned int *uaddr, int value) {
    syscall(SYS_futex, uaddr, FUTEX_WAIT, value, NULL, 0, 0);
}

static inline void _shctx_awakelocker(unsigned int *uaddr) {
    syscall(SYS_futex, uaddr, FUTEX_WAKE, 1, NULL, 0, 0);
}

#else /* internal spin lock */

#if defined (__i486__) || defined (__i586__) || defined (__i686__) || defined (__x86_64__)
static inline void relax() {
    __asm volatile("rep;nop\n" ::: "memory");
}
#else /* if no x86_64 or i586 arch: use less optimized but generic asm */
static inline void relax() {
    __asm volatile("" ::: "memory");
}
#endif

static inline void _shctx_wait4lock(unsigned int *count, unsigned int *uaddr, int value) {
    int i;

    for (i = 0; i < *count; i++) {
        relax();
        relax();
    }
    *count = *count << 1;
}

#define _shctx_awakelocker(a)

#endif

#if defined (__i486__) || defined (__i586__) || defined (__i686__) || defined (__x86_64__)
static inline unsigned int xchg(unsigned int *ptr, unsigned int x) {
    __asm volatile("lock xchgl %0,%1"
            : "=r" (x), "+m" (*ptr)
            : "0" (x)
            : "memory");
    return x;
}

static inline unsigned int cmpxchg(unsigned int *ptr, unsigned int old, unsigned int new) {
    unsigned int ret;

    __asm volatile("lock cmpxchgl %2,%1"
            : "=a" (ret), "+m" (*ptr)
            : "r" (new), "0" (old)
            : "memory");
    return ret;
}

static inline unsigned char atomic_dec(unsigned int *ptr) {
    unsigned char ret;
    __asm volatile("lock decl %0\n"
            "setne %1\n"
            : "+m" (*ptr), "=qm" (ret)
            :
            : "memory");
    return ret;
}

#else /* if no x86_64 or i586 arch: use less optimized gcc >= 4.1 built-ins */
static inline unsigned int xchg(unsigned int *ptr, unsigned int x) {
    return __sync_lock_test_and_set(ptr, x);
}

static inline unsigned int cmpxchg(unsigned int *ptr, unsigned int old, unsigned int new) {
    return __sync_val_compare_and_swap(ptr, old, new);
}

static inline unsigned char atomic_dec(unsigned int *ptr) {
    return __sync_sub_and_fetch(ptr, 1) ? 1 : 0;
}

#endif

static inline void _shctx_lock(unsigned int *waiters) {
    unsigned int x;
    unsigned int count = 4;

    x = cmpxchg(waiters, 0, 1);
    if (x) {
        if (x != 2)
            x = xchg(waiters, 2);

        while (x) {
            _shctx_wait4lock(&count, waiters, 2);
            x = xchg(waiters, 2);
        }
    }
}

static inline void _shctx_unlock(unsigned int *waiters) {
    if (atomic_dec(waiters)) {
        *waiters = 0;
        _shctx_awakelocker(waiters);
    }
}

static inline int _nuster_shctx_init(unsigned int *waiters) {
    *waiters = 0;
    return 1;
}
#define nuster_shctx_init(shctx)   _nuster_shctx_init(&(shctx)->waiters)
#define nuster_shctx_lock(shctx)   if (global.cache.share) _shctx_lock(&(shctx)->waiters)
#define nuster_shctx_unlock(shctx) if (global.cache.share) _shctx_unlock(&(shctx)->waiters)

#endif

#endif /* _PROTO_CACHE_H */

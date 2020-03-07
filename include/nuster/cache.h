/*
 * include/nuster/cache.h
 * This file defines everything related to nuster cache.
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

#ifndef _NUSTER_CACHE_H
#define _NUSTER_CACHE_H

#include <dirent.h>

#include <types/stream.h>
#include <types/http_ana.h>
#include <types/channel.h>
#include <types/stream_interface.h>
#include <types/proxy.h>
#include <types/filters.h>

#include <common/memory.h>

#include <nuster/common.h>
#include <nuster/persist.h>

#define NST_CACHE_DEFAULT_LOAD_FACTOR         0.75
#define NST_CACHE_DEFAULT_GROWTH_FACTOR       2
#define NST_CACHE_DEFAULT_KEY                "method.scheme.host.uri"
#define NST_CACHE_DEFAULT_CODE               "200"
#define NST_CACHE_DEFAULT_KEY_SIZE            128
#define NST_CACHE_DEFAULT_CHUNK_SIZE          32
#define NST_CACHE_DEFAULT_PURGE_METHOD       "PURGE"
#define NST_CACHE_DEFAULT_PURGE_METHOD_SIZE   16

struct nst_cache_element {
    struct nst_str            msg;

    struct nst_cache_element *next;
};

/*
 * A nst_cache_data contains a complete http response data,
 * and is pointed by nst_cache_entry->data.
 * All nst_cache_data are stored in a circular singly linked list
 */
struct nst_cache_data {
    int                       clients;
    int                       invalid;
    struct nst_cache_element *element;

    struct nst_cache_data    *next;
};

/*
 * A nst_cache_entry is an entry in nst_cache_dict hash table
 */
enum {
    NST_CACHE_ENTRY_STATE_CREATING = 0,
    NST_CACHE_ENTRY_STATE_VALID,
    NST_CACHE_ENTRY_STATE_INVALID,
    NST_CACHE_ENTRY_STATE_EXPIRED,
};

struct nst_cache_entry {
    int                     state;
    struct buffer          *key;
    uint64_t                hash;
    struct nst_cache_data  *data;
    struct nst_str          host;
    struct nst_str          path;
    struct nst_rule        *rule;        /* rule */
    int                     pid;         /* proxy uuid */
    char                   *file;
    int                     header_len;
    struct nst_str          etag;
    struct nst_str          last_modified;

    uint64_t                expire;
    uint64_t                ctime;
    uint64_t                atime;

    /* For entries loaded from disk */
    uint32_t                ttl;
    uint8_t                 extend[4];

    /* see rule.extend */
    uint64_t                access[4];

    /* extended count  */
    int                     extended;

    struct nst_key         *key2;
    struct nst_rule2       *rule2;        /* rule */
    struct nst_cache_entry *next;
};

struct nst_cache_dict {
    struct nst_cache_entry **entry;
    uint64_t                 size;      /* number of entries */
    uint64_t                 used;      /* number of used entries */
#if defined NUSTER_USE_PTHREAD || defined USE_PTHREAD_PSHARED
    pthread_mutex_t          mutex;
#else
    unsigned int             waiters;
#endif
};

enum {
    NST_CACHE_CTX_STATE_INIT = 0,          /* init */
    NST_CACHE_CTX_STATE_BYPASS,            /* do not cached */
    NST_CACHE_CTX_STATE_WAIT,              /* caching, wait */
    NST_CACHE_CTX_STATE_HIT,               /* cached, use cache */
    NST_CACHE_CTX_STATE_HIT_DISK,          /* cached, use disk */
    NST_CACHE_CTX_STATE_PASS,              /* cache rule passed */
    NST_CACHE_CTX_STATE_FULL,              /* cache full */
    NST_CACHE_CTX_STATE_CREATE,            /* to cache */
    NST_CACHE_CTX_STATE_DISK_ONLY,         /* */
    NST_CACHE_CTX_STATE_DISK_SYNC,         /* */
    NST_CACHE_CTX_STATE_DISK_ASYNC,        /* */
    NST_CACHE_CTX_STATE_DONE,              /* cache done */
    NST_CACHE_CTX_STATE_CHECK_PERSIST,     /* check persistence */
};

struct nst_cache_ctx {
    int                       state;

    struct buffer            *key;
    uint64_t                  hash;

    struct nst_rule          *rule;

    struct nst_cache_entry   *entry;
    struct nst_cache_data    *data;
    struct nst_cache_element *element;

    struct {
        int                   scheme;
        struct nst_str        host;
        struct nst_str        uri;
        struct nst_str        path;
        int                   delimiter;
        struct nst_str        query;
        struct nst_str        cookie;
    } req;

    struct {
        struct nst_str        etag;
        struct nst_str        last_modified;
    } res;

    int                       pid;              /* proxy uuid */
    int                       full;             /* memory full */
    int                       header_len;
    uint64_t                  cache_len;

    struct persist            disk;

    int                       rule_cnt;
    int                       key_cnt;
    struct nst_rule2         *rule2;
    struct nst_key            keys[0];
};

struct nst_cache_stats {
    uint64_t        used_mem;

    struct {
        uint64_t    total;
        uint64_t    fetch;
        uint64_t    hit;
        uint64_t    abort;
    } req;

#if defined NUSTER_USE_PTHREAD || defined USE_PTHREAD_PSHARED
    pthread_mutex_t mutex;
#else
    unsigned int    waiters;
#endif
};

struct nst_cache {
    /* 0: using, 1: rehashing */
    struct nst_cache_dict  dict[2];

    /*
     * point to the circular linked list, tail->next ===  head,
     * and will be moved together constantly to check invalid data
     */
    struct nst_cache_data *data_head;
    struct nst_cache_data *data_tail;

#if defined NUSTER_USE_PTHREAD || defined USE_PTHREAD_PSHARED
    pthread_mutex_t        mutex;
#else
    unsigned int           waiters;
#endif

    /* >=0: rehashing, index, -1: not rehashing */
    int                    rehash_idx;

    /* cache dict cleanup index */
    int                    cleanup_idx;

    /* persist async index */
    int                    persist_idx;

    /* for disk_loader and disk_cleaner */
    struct {
        int                loaded;
        int                idx;
        DIR               *dir;
        struct dirent     *de;
        char              *file;
    } disk;
};

extern struct flt_ops  nst_cache_filter_ops;
extern const char *nst_cache_flt_id;

enum {
    NST_CACHE_PURGE_NAME_ALL = 0,
    NST_CACHE_PURGE_NAME_PROXY,
    NST_CACHE_PURGE_NAME_RULE,
    NST_CACHE_PURGE_PATH,
    NST_CACHE_PURGE_REGEX,
    NST_CACHE_PURGE_HOST,
    NST_CACHE_PURGE_PATH_HOST,
    NST_CACHE_PURGE_REGEX_HOST,
};

enum {
    NST_CACHE_STATS_HEAD,
    NST_CACHE_STATS_DATA,
    NST_CACHE_STATS_DONE,
};


/* dict */
int nst_cache_dict_init();
struct nst_cache_entry *nst_cache_dict_get(struct buffer *key, uint64_t hash);
struct nst_cache_entry *nst_cache_dict_get2(struct nst_key *key);
struct nst_cache_entry *nst_cache_dict_set(struct nst_cache_ctx *ctx);
struct nst_cache_entry *nst_cache_dict_set2(struct nst_cache_ctx *ctx);
void nst_cache_dict_rehash();
void nst_cache_dict_cleanup();
int nst_cache_dict_set_from_disk(char *file, char *meta, struct buffer *key,
        struct nst_str *host, struct nst_str *path);

/* engine */
void nst_cache_init();
void nst_cache_housekeeping();
int nst_cache_prebuild_key(struct nst_cache_ctx *ctx, struct stream *s,
        struct http_msg *msg);

int nst_cache_build_key(struct nst_cache_ctx *ctx,
        struct nst_rule_key **pck, struct stream *s, struct http_msg *msg);

struct buffer *nst_cache_build_purge_key(struct stream *s,
        struct http_msg *msg);

uint64_t nst_cache_hash_key(const char *key);

void nst_cache_finish(struct nst_cache_ctx *ctx);
void nst_cache_abort(struct nst_cache_ctx *ctx);
int nst_cache_exists(struct nst_cache_ctx *ctx, struct nst_rule *rule);
int nst_cache_exists2(struct nst_cache_ctx *ctx);
struct nst_cache_data *nst_cache_data_new();
void nst_cache_hit(struct stream *s, struct stream_interface *si,
        struct channel *req, struct channel *res, struct nst_cache_data *data);

void nst_cache_hit_disk(struct stream *s, struct stream_interface *si,
        struct channel *req, struct channel *res, struct nst_cache_ctx *ctx);

int nst_cache_check_uri(struct http_msg *msg);
void nst_cache_persist_cleanup();
void nst_cache_persist_load();
void nst_cache_persist_async();
void nst_cache_build_etag(struct nst_cache_ctx *ctx, struct stream *s,
        struct http_msg *msg);

void nst_cache_build_last_modified(struct nst_cache_ctx *ctx, struct stream *s,
        struct http_msg *msg);

int nst_cache_handle_conditional_req(struct nst_cache_ctx *ctx,
        struct nst_rule *rule, struct stream *s, struct http_msg *msg);
int nst_cache_handle_conditional_req2(struct nst_cache_ctx *ctx, struct stream *s,
        struct http_msg *msg);
int nst_cache_prebuild_key(struct nst_cache_ctx *ctx, struct stream *s,
        struct http_msg *msg);
int nst_cache_update(struct nst_cache_ctx *ctx, struct http_msg *msg,
        unsigned int offset, unsigned int msg_len);
int nst_cache_build_key(struct nst_cache_ctx *ctx, struct nst_rule_key **pck,
        struct stream *s, struct http_msg *msg);
int nst_cache_build_key2(struct nst_cache_ctx *ctx, struct stream *s, struct http_msg *msg);
int nst_cache_store_key(struct nst_cache_ctx *ctx, struct nst_key *key);
void nst_cache_create(struct nst_cache_ctx *ctx, struct http_msg *msg);
void nst_cache_create2(struct nst_cache_ctx *ctx, struct http_msg *msg);

/* manager */
int nst_cache_purge(struct stream *s, struct channel *req, struct proxy *px);
int nst_cache_manager(struct stream *s, struct channel *req, struct proxy *px);
int nst_cache_manager_init();

/* stats */
void nst_cache_stats_update_used_mem(int i);
int nst_cache_stats_init();
int nst_cache_stats_full();
int nst_cache_stats(struct stream *s, struct channel *req, struct proxy *px);
void nst_cache_stats_update_req(int state);

static inline int nst_cache_entry_expired(struct nst_cache_entry *entry) {

    if(entry->expire == 0) {
        return 0;
    } else {
        return entry->expire <= get_current_timestamp() / 1000;
    }

}

static inline int nst_cache_entry_invalid(struct nst_cache_entry *entry) {

    /* check state */
    if(entry->state == NST_CACHE_ENTRY_STATE_INVALID) {
        return 1;
    } else if(entry->state == NST_CACHE_ENTRY_STATE_EXPIRED) {
        return 1;
    }

    /* check expire */
    return nst_cache_entry_expired(entry);
}

#define nst_cache_key_init() nst_key_init(global.nuster.cache.memory)
#define nst_cache_key_advance(key, step)                                      \
    nst_key_advance(global.nuster.cache.memory, key, step)
#define nst_cache_key_append(key, str, len)                                   \
    nst_key_append(global.nuster.cache.memory, key, str, len)
#define nst_cache_memory_alloc(size)                                          \
    nst_memory_alloc(global.nuster.cache.memory, size)
#define nst_cache_memory_free(p) nst_memory_free(global.nuster.cache.memory, p);

#endif /* _NUSTER_CACHE_H */

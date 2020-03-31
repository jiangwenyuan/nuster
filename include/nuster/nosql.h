/*
 * include/nuster/nosql.h
 * This file defines everything related to nuster nosql.
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

#ifndef _NUSTER_NOSQL_H
#define _NUSTER_NOSQL_H

#include <nuster/common.h>
#include <nuster/dict.h>
#include <nuster/persist.h>

#define NST_NOSQL_DEFAULT_CHUNK_SIZE            32
#define NST_NOSQL_DEFAULT_LOAD_FACTOR           0.75
#define NST_NOSQL_DEFAULT_GROWTH_FACTOR         2
#define NST_NOSQL_DEFAULT_KEY_SIZE              128


enum {
    NST_NOSQL_APPCTX_STATE_INIT = 0,
    NST_NOSQL_APPCTX_STATE_WAIT,
    NST_NOSQL_APPCTX_STATE_HIT_MEMORY,
    NST_NOSQL_APPCTX_STATE_CREATE,
    NST_NOSQL_APPCTX_STATE_DELETED,
    NST_NOSQL_APPCTX_STATE_END,
    NST_NOSQL_APPCTX_STATE_DONE,
    NST_NOSQL_APPCTX_STATE_ERROR,
    NST_NOSQL_APPCTX_STATE_NOT_ALLOWED,
    NST_NOSQL_APPCTX_STATE_NOT_FOUND,
    NST_NOSQL_APPCTX_STATE_EMPTY,
    NST_NOSQL_APPCTX_STATE_FULL,
    NST_NOSQL_APPCTX_STATE_HIT_DISK,
};

enum {
    NST_NOSQL_CTX_STATE_INIT        = 0,   /* init */
    NST_NOSQL_CTX_STATE_HIT_MEMORY,        /* key exists */
    NST_NOSQL_CTX_STATE_CREATE,            /* to cache */
    NST_NOSQL_CTX_STATE_DELETE,            /* to delete */
    NST_NOSQL_CTX_STATE_DONE,              /* set done */
    NST_NOSQL_CTX_STATE_INVALID,           /* invalid */
    NST_NOSQL_CTX_STATE_FULL,              /* nosql full */
    NST_NOSQL_CTX_STATE_WAIT,              /* wait */
    NST_NOSQL_CTX_STATE_PASS,              /* rule passed */
    NST_NOSQL_CTX_STATE_HIT_DISK,
    NST_NOSQL_CTX_STATE_CHECK_PERSIST,
};

struct nst_nosql_ctx {
    int                       state;

    struct nst_dict_entry    *entry;
    struct nst_data          *data;
    struct nst_data_element  *element;

    struct nst_http_txn       txn;

    int                       pid;         /* proxy uuid */

    struct persist            disk;

    int                       rule_cnt;
    int                       key_cnt;
    struct buffer            *key;
    struct nst_rule          *rule;
    struct nst_key            keys[0];
};

struct nst_nosql {
    struct nst_dict          dict;

    /*
     * point to the circular linked list, tail->next ===  head,
     * and will be moved together constantly to check invalid data
     */
    struct nst_data       *data_head;
    struct nst_data       *data_tail;

#if defined NUSTER_USE_PTHREAD || defined USE_PTHREAD_PSHARED
    pthread_mutex_t        mutex;
#else
    unsigned int           waiters;
#endif

    /* >=0: rehashing, index, -1: not rehashing */
    int                    rehash_idx;

    /* cache dict cleanup index */
    int                    cleanup_idx;

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

extern struct flt_ops  nst_nosql_filter_ops;

/* engine */
void nst_nosql_init();
void nst_nosql_housekeeping();
int nst_nosql_check_applet(struct stream *s, struct channel *req, struct proxy *px);

struct nst_data *nst_nosql_data_new();

void nst_nosql_create(struct stream *s, struct http_msg *msg, struct nst_nosql_ctx *ctx);
int nst_nosql_exists(struct nst_nosql_ctx *ctx);
int nst_nosql_delete(struct nst_key *key);
int nst_nosql_update(struct http_msg *msg, struct nst_nosql_ctx *ctx, unsigned int offset,
        unsigned int msg_len);

int nst_nosql_finish(struct stream *s, struct http_msg *msg, struct nst_nosql_ctx *ctx);

void nst_nosql_abort(struct nst_nosql_ctx *ctx);

int nst_nosql_get_headers(struct stream *s, struct http_msg *msg, struct nst_nosql_ctx *ctx);

void nst_nosql_persist_async();
void nst_nosql_persist_cleanup();
void nst_nosql_persist_load();

/* dict */
int nst_nosql_dict_init();
struct nst_dict_entry *nst_nosql_dict_get(struct nst_key *key);
struct nst_dict_entry *nst_nosql_dict_set(struct nst_nosql_ctx *ctx);
int nst_nosql_dict_set_from_disk(struct nst_key *key, char *file, char *meta);
void nst_nosql_dict_rehash();
void nst_nosql_dict_cleanup();

#define nst_nosql_memory_alloc(size)    nst_memory_alloc(global.nuster.nosql.memory, size)
#define nst_nosql_memory_free(p)        nst_memory_free(global.nuster.nosql.memory, p)

#endif /* _NUSTER_NOSQL_H */

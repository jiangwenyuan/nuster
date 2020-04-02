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

#include <nuster/common.h>


enum {
    NST_CACHE_CTX_STATE_INIT = 0,          /* init */
    NST_CACHE_CTX_STATE_BYPASS,            /* do not cached */
    NST_CACHE_CTX_STATE_WAIT,              /* caching, wait */
    NST_CACHE_CTX_STATE_HIT_MEMORY,        /* cached, use memory */
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

    struct nst_dict_entry   *entry;
    struct nst_data          *data;
    struct nst_data_element  *element;

    struct nst_http_txn       txn;

    int                       pid;              /* proxy uuid */

    struct persist            disk;

    int                       rule_cnt;
    int                       key_cnt;
    struct buffer            *key;
    struct nst_rule          *rule;
    struct nst_key            keys[0];
};

extern struct flt_ops  nst_cache_filter_ops;
extern const char *nst_cache_flt_id;


void nst_cache_init();
void nst_cache_housekeeping();

void nst_cache_finish(struct nst_cache_ctx *ctx);
void nst_cache_abort(struct nst_cache_ctx *ctx);
int nst_cache_exists(struct nst_cache_ctx *ctx);
int nst_cache_delete(struct nst_key *key);
struct nst_data *nst_cache_data_new();
void nst_cache_hit(struct stream *s, struct stream_interface *si, struct channel *req,
        struct channel *res, struct nst_cache_ctx *ctx);

void nst_cache_persist_cleanup();
void nst_cache_persist_load();
void nst_cache_persist_async();
void nst_cache_build_etag(struct stream *s, struct http_msg *msg, struct nst_cache_ctx *ctx);

void
nst_cache_build_last_modified(struct stream *s, struct http_msg *msg, struct nst_cache_ctx *ctx);

int nst_cache_update(struct http_msg *msg, struct nst_cache_ctx *ctx,
        unsigned int offset, unsigned int len);

void nst_cache_create(struct http_msg *msg, struct nst_cache_ctx *ctx);

#define nst_cache_memory_alloc(size)    nst_memory_alloc(global.nuster.cache.memory, size)
#define nst_cache_memory_free(p)        nst_memory_free(global.nuster.cache.memory, p)

#endif /* _NUSTER_CACHE_H */

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
#include <nuster/core.h>
#include <nuster/persist.h>


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

extern struct flt_ops  nst_nosql_filter_ops;
extern const char *nst_nosql_flt_id;


void nst_nosql_init();
void nst_nosql_housekeeping();
int nst_nosql_check_applet(struct stream *s, struct channel *req, struct proxy *px);

struct nst_data *nst_nosql_data_new();

void nst_nosql_create(struct stream *s, struct http_msg *msg, struct nst_ctx *ctx);
int nst_nosql_exists(struct nst_ctx *ctx);
int nst_nosql_delete(struct nst_key *key);
int nst_nosql_update(struct http_msg *msg, struct nst_ctx *ctx, unsigned int offset,
        unsigned int msg_len);

int nst_nosql_finish(struct stream *s, struct http_msg *msg, struct nst_ctx *ctx);

void nst_nosql_abort(struct nst_ctx *ctx);

int nst_nosql_get_headers(struct stream *s, struct http_msg *msg, struct nst_ctx *ctx);

void nst_nosql_persist_async();
void nst_nosql_persist_cleanup();
void nst_nosql_persist_load();

#define nst_nosql_memory_alloc(size)    nst_memory_alloc(global.nuster.nosql.memory, size)
#define nst_nosql_memory_free(p)        nst_memory_free(global.nuster.nosql.memory, p)

#endif /* _NUSTER_NOSQL_H */

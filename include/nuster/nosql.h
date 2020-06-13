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


enum {
    NST_NOSQL_APPCTX_STATE_INIT         = 0,
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

extern hpx_flt_ops_t  nst_nosql_filter_ops;
extern const char    *nst_nosql_flt_id;


void nst_nosql_init();
void nst_nosql_housekeeping();
int nst_nosql_check_applet(hpx_stream_t *s, hpx_channel_t *req, hpx_proxy_t *px);

void nst_nosql_create(hpx_stream_t *s, hpx_http_msg_t *msg, nst_ctx_t *ctx);
int nst_nosql_append(hpx_http_msg_t *msg, nst_ctx_t *ctx, unsigned int offset, unsigned int len);
void nst_nosql_finish(hpx_stream_t *s, hpx_http_msg_t *msg, nst_ctx_t *ctx);
void nst_nosql_abort(nst_ctx_t *ctx);
int nst_nosql_exists(nst_ctx_t *ctx);
int nst_nosql_delete(nst_key_t *key);

#endif /* _NUSTER_NOSQL_H */

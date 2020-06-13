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


extern hpx_flt_ops_t  nst_cache_filter_ops;
extern const char    *nst_cache_flt_id;


void nst_cache_init();
void nst_cache_housekeeping();

void nst_cache_create(hpx_http_msg_t *msg, nst_ctx_t *ctx);
int nst_cache_append(hpx_http_msg_t *msg, nst_ctx_t *ctx, unsigned int offset, unsigned int len);
int nst_cache_finish(nst_ctx_t *ctx);
void nst_cache_abort(nst_ctx_t *ctx);
int nst_cache_exists(nst_ctx_t *ctx);
int nst_cache_delete(nst_key_t *key);
void nst_cache_hit(hpx_stream_t *s, hpx_stream_interface_t *si, hpx_channel_t *req,
        hpx_channel_t *res, nst_ctx_t *ctx);

#endif /* _NUSTER_CACHE_H */

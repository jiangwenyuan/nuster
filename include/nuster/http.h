/*
 * include/nuster/http.h
 * nuster http related functions.
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

#ifndef _NUSTER_HTTP_H
#define _NUSTER_HTTP_H

#include <nuster/common.h>
#include <nuster/memory.h>


enum {
    NST_HTTP_100 = 0,
    NST_HTTP_200,
    NST_HTTP_304,
    NST_HTTP_400,
    NST_HTTP_404,
    NST_HTTP_405,
    NST_HTTP_412,
    NST_HTTP_500,
    NST_HTTP_507,
    NST_HTTP_SIZE
};

typedef struct nst_http_code {
    int                 status;
    hpx_ist_t           code;
    hpx_ist_t           reason;
    hpx_ist_t           length;
} nst_http_code_t;

typedef struct nst_http_req {
    int                 scheme;
    hpx_ist_t           host;
    hpx_ist_t           uri;
    hpx_ist_t           path;
    int                 delimiter;
    hpx_ist_t           query;
    hpx_ist_t           cookie;
    hpx_ist_t           content_type;
} nst_http_req_t;

typedef struct nst_http_res {
    int                 header_len;
    uint64_t            payload_len;
    int                 ttl;
    hpx_ist_t           etag;
    hpx_ist_t           last_modified;
} nst_http_res_t;

typedef struct nst_http_txn {
    nst_http_req_t      req;
    nst_http_res_t      res;
} nst_http_txn_t;

int nst_http_parse_htx(hpx_stream_t *s, hpx_buffer_t *buf, nst_http_txn_t *txn);

int nst_http_find_param(char *query_beg, char *query_end, char *name, char **val, int *val_len);
int nst_http_memory_item_to_htx(nst_memory_item_t *item, hpx_htx_t *htx);

void nst_http_reply(hpx_stream_t *s, int idx);
int nst_http_reply_100(hpx_stream_t *s);
void nst_http_reply_304(hpx_stream_t *s, nst_http_txn_t *txn);

int nst_http_handle_expect(hpx_stream_t *s, hpx_htx_t *htx, hpx_http_msg_t *msg);
int nst_http_handle_conditional_req(hpx_stream_t *s, hpx_htx_t *htx, nst_http_txn_t *txn,
        nst_rule_prop_t *prop);

void nst_http_build_etag(hpx_stream_t *s, hpx_buffer_t *buf, nst_http_txn_t *txn, int etag_prop);
void nst_http_build_last_modified(hpx_stream_t *s, hpx_buffer_t *buf, nst_http_txn_t *txn,
        int last_modified_prop);

int nst_http_parse_ttl(hpx_htx_t *htx, hpx_buffer_t *buf, nst_http_txn_t *txn);


#endif /* _NUSTER_HTTP_H */

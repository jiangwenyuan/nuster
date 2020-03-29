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

#include <common/htx.h>

#include <nuster/common.h>

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

struct nst_http_code {
    int                   status;
    struct ist            code;
    struct ist            reason;
    struct ist            length;
};

struct nst_http_req {
    int                   scheme;
    struct ist            host;
    struct ist            uri;
    struct ist            path;
    int                   delimiter;
    struct ist            query;
    struct ist            cookie;
    struct ist            content_type;
};

struct nst_http_res {
    int                   header_len;
    uint64_t              payload_len;
    uint64_t              content_length;
    struct ist            transfer_encoding;
    struct ist            etag;
    struct ist            last_modified;
};

struct nst_http_txn {
    struct buffer        *buf;
    struct nst_http_req   req;
    struct nst_http_res   res;
};

static inline int nst_http_txn_attach(struct nst_http_txn *txn) {
    txn->buf = alloc_trash_chunk();

    if(txn->buf) {
        return NST_OK;
    } else {
        return NST_ERR;
    }
}

static inline void nst_http_txn_detach(struct nst_http_txn *txn) {
    free_trash_chunk(txn->buf);
}

int nst_http_parse_htx(struct stream *s, struct http_msg *msg, struct nst_http_txn *txn);
int nst_http_find_param(char *query_beg, char *query_end, char *name, char **val, int *val_len);
int nst_http_data_element_to_htx(struct nst_data_element *element, struct htx *htx);

void nst_http_reply(struct stream *s, int idx);
int nst_http_reply_100(struct stream *s);
void nst_http_reply_304(struct stream *s, struct ist last_modified, struct ist etag);

int nst_http_handle_expect(struct stream *s, struct htx *htx, struct http_msg *msg);
int nst_http_handle_conditional_req(struct stream *s, struct htx *htx,
        struct ist last_modified, struct ist etag, int test_last_modified, int test_etag);

#endif /* _NUSTER_HTTP_H */

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

#include <types/global.h>
#include <inttypes.h>
#include <common/chunk.h>

#include <proto/stream_interface.h>
#include <proto/http_ana.h>

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
    int        status;
    struct ist code;
    struct ist reason;
    struct ist length;
};

int nst_http_find_param(char *query_beg, char *query_end, char *name, char **val, int *val_len);
int nst_http_data_element_to_htx(struct nst_data_element *element, struct htx *htx);

void nst_http_reply(struct stream *s, int idx);
int nst_http_reply_100(struct stream *s);
void nst_http_reply_304(struct stream *s, struct ist last_modified, struct ist etag);

int nst_http_handle_expect(struct stream *s, struct htx *htx, struct http_msg *msg);
int nst_http_handle_conditional_req(struct stream *s, struct htx *htx,
        int test_last_modified, struct ist last_modified, int test_etag, struct ist etag);

#endif /* _NUSTER_HTTP_H */

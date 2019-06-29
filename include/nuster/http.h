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

#include <proto/stream_interface.h>
#include <proto/proto_http.h>

#include <nuster/common.h>
#include <nuster/nuster.h>

enum {
    NST_HTTP_200 = 0,
    NST_HTTP_400,
    NST_HTTP_404,
    NST_HTTP_405,
    NST_HTTP_500,
    NST_HTTP_507,
    NST_HTTP_SIZE,
};

struct nst_headers {
    struct nst_str server;
    struct nst_str date;
    struct nst_str content_length;
    struct nst_str content_type;
    struct nst_str transfer_encoding;
    struct nst_str last_modified;
    struct nst_str expires;
    struct nst_str cache_control;
    struct nst_str etag;
};

extern const char *nst_http_msgs[NST_HTTP_SIZE];
extern struct buffer nst_http_msg_chunks[NST_HTTP_SIZE];
extern struct nst_headers nst_headers;

/*
 * simply response and close
 */
static inline void nst_response(struct stream *s, struct buffer *msg) {
    s->txn->flags &= ~TX_WAIT_NEXT_RQ;
    si_retnclose(&s->si[0], msg);
    if(!(s->flags & SF_ERR_MASK)) {
        s->flags |= SF_ERR_LOCAL;
    }
}


static inline void nst_res_begin(int status) {
    chunk_printf(&trash, "HTTP/1.1 %d %s\r\n", status, http_get_reason(status));
}

static inline void nst_res_header_server() {
    chunk_appendf(&trash, "%.*s: nuster\r\n", nst_headers.server.len,
            nst_headers.server.data);
}

static inline void nst_res_header_date() {
    const char mon[12][4] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul",
        "Aug", "Sep", "Oct", "Nov", "Dec" };

    const char day[7][4]  = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

    struct tm *tm;
    time_t now;
    time(&now);
    tm = gmtime(&now);
    chunk_appendf(&trash, "%.*s: %s, %02d %s %04d %02d:%02d:%02d GMT",
            nst_headers.date.len, nst_headers.date.data, day[tm->tm_wday],
            tm->tm_mday, mon[tm->tm_mon], 1900 + tm->tm_year,
            tm->tm_hour, tm->tm_min, tm->tm_sec);
}

static inline void nst_res_header_content_length(uint64_t len) {
    chunk_appendf(&trash, "%.*s: %" PRIu64 "\r\n",
            nst_headers.content_length.len,
            nst_headers.content_length.data, len);
}

static inline void nst_res_header(struct nst_str *k, struct nst_str *v) {
    chunk_appendf(&trash, "%.*s: %.*s\r\n", k->len, k->data, v->len, v->data);
}

static inline void nst_res_header_end() {
    chunk_appendf(&trash, "\r\n");
}

static inline void nst_res_header_send(struct channel *chn) {
    ci_putblk(chn, trash.area, trash.data);
}

static inline void nst_res_end(struct stream_interface *si) {
    co_skip(si_oc(si), co_data(si_oc(si)));
    si_shutr(si);
    si_ic(si)->flags |= CF_READ_NULL;
}

static inline int nst_res_send(struct channel *chn, const char *blk,
        int len) {

    return ci_putblk(chn, blk, len);
}

static inline void nst_res_simple(struct stream_interface *si, int status,
        const char *content, int len) {

    nst_res_begin(status);
    nst_res_header_content_length(len);
    nst_res_header_end();

    if(content) {
        chunk_appendf(&trash, "%.*s", len, content);
    }

    nst_res_send(si_ic(si), trash.area, trash.data);
    nst_res_end(si);
}

int nst_req_find_param(char *query_beg, char *query_end,
        char *name, char **value, int *value_len);

#endif /* _NUSTER_HTTP_H */

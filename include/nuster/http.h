/*
 * nuster http related functions.
 *
 * Copyright (C) [Jiang Wenyuan](https://github.com/jiangwenyuan), < koubunen AT gmail DOT com >
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#ifndef _NUSTER_HTTP_H
#define _NUSTER_HTTP_H

#include <types/global.h>

#include <proto/stream_interface.h>
#include <proto/proto_http.h>

#include <nuster/common.h>
#include <nuster/nuster.h>

enum {
    NUSTER_HTTP_200 = 0,
    NUSTER_HTTP_400,
    NUSTER_HTTP_404,
    NUSTER_HTTP_405,
    NUSTER_HTTP_500,
    NUSTER_HTTP_507,
    NUSTER_HTTP_SIZE
};

struct nuster_headers {
    struct nuster_str server;
    struct nuster_str date;
    struct nuster_str content_length;
    struct nuster_str content_type;
    struct nuster_str transfer_encoding;
    struct nuster_str last_modified;
    struct nuster_str expires;
    struct nuster_str cache_control;
    struct nuster_str etag;
};

extern const char *nuster_http_msgs[NUSTER_HTTP_SIZE];
extern struct chunk nuster_http_msg_chunks[NUSTER_HTTP_SIZE];
extern struct nuster_headers nuster_headers;

/*
 * simply response and close
 */
static inline void nuster_response(struct stream *s, struct chunk *msg) {
    s->txn->flags &= ~TX_WAIT_NEXT_RQ;
    stream_int_retnclose(&s->si[0], msg);
    if(!(s->flags & SF_ERR_MASK)) {
        s->flags |= SF_ERR_LOCAL;
    }
}


static inline void nuster_res_begin(int status) {
    chunk_printf(&trash, "HTTP/1.1 %d %s\r\n", status, get_reason(status));
}

static inline void nuster_res_header_server() {
    chunk_appendf(&trash, "%.*s: nuster\r\n", nuster_headers.server.len, nuster_headers.server.data);
}

static inline void nuster_res_header_date() {
    const char mon[12][4] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    const char day[7][4]  = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

    struct tm *tm;
    time_t now;
    time(&now);
    tm = gmtime(&now);
    chunk_appendf(&trash, "%.*s: %s, %02d %s %04d %02d:%02d:%02d GMT", nuster_headers.date.len, nuster_headers.date.data,
            day[tm->tm_wday], tm->tm_mday, mon[tm->tm_mon], 1900 + tm->tm_year,
            tm->tm_hour, tm->tm_min, tm->tm_sec);
}

static inline void nuster_res_header_content_length(uint64_t content_length) {
    chunk_appendf(&trash, "%.*s: %" PRIu64 "\r\n", nuster_headers.content_length.len, nuster_headers.content_length.data, content_length);
}

static inline void nuster_res_header(struct nuster_str *k, struct nuster_str *v) {
    chunk_appendf(&trash, "%.*s: %.*s\r\n", k->len, k->data, v->len, v->data);
}

static inline void nuster_res_header_end() {
    chunk_appendf(&trash, "\r\n");
}

static inline void nuster_res_header_send(struct channel *chn) {
    ci_putblk(chn, trash.str, trash.len);
}

static inline void nuster_res_end(struct stream_interface *si) {
    co_skip(si_oc(si), si_ob(si)->o);
    si_shutr(si);
    si_ic(si)->flags |= CF_READ_NULL;
}

static inline int nuster_res_send(struct channel *chn, const char *blk, int len) {
    return ci_putblk(chn, blk, len);
}

static inline void nuster_res_simple(struct stream_interface *si, int status, const char *content, int content_length) {
    nuster_res_begin(status);
    nuster_res_header_content_length(content_length);
    nuster_res_header_end();
    chunk_appendf(&trash, "%.*s", content_length, content);
    nuster_res_send(si_ic(si), trash.str, trash.len);
    nuster_res_end(si);
}

int nuster_req_find_param(char *query_beg, char *query_end, char *name, char **value, int *value_len);

#endif /* _NUSTER_HTTP_H */

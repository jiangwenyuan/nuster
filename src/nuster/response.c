/*
 * nuster response functions.
 *
 * Copyright (C) [Jiang Wenyuan](https://github.com/jiangwenyuan), < koubunen AT gmail DOT com >
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <types/global.h>

#include <proto/stream_interface.h>
#include <proto/proto_http.h>

#include <nuster/common.h>
#include <nuster/nuster.h>

static const char mon[12][4] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
static const char day[7][4]  = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

/*
 * Used by cache, should move to new one
 */
const char *nuster_http_msgs[NUSTER_HTTP_SIZE] = {
    [NUSTER_HTTP_200] =
        "HTTP/1.0 200 OK\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "200 OK\n",

    [NUSTER_HTTP_400] =
        "HTTP/1.0 400 Bad request\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "400 Bad request\n",

    [NUSTER_HTTP_404] =
        "HTTP/1.0 404 Not Found\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "404 Not Found\n",

    [NUSTER_HTTP_405] =
        "HTTP/1.0 405 Method Not Allowed\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "405 Method Not Allowed\n",

    [NUSTER_HTTP_500] =
        "HTTP/1.0 500 Internal Server Error\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "500 Internal Server Error\n",

    [NUSTER_HTTP_507] =
        "HTTP/1.0 507 Insufficient Storage\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "507 Insufficient Storage\n",
};

struct chunk nuster_http_msg_chunks[NUSTER_HTTP_SIZE];

struct nuster_headers nuster_headers = {
    .server            = nuster_str_set("Server"),
    .date              = nuster_str_set("Date"),
    .content_length    = nuster_str_set("Content-Length"),
    .content_type      = nuster_str_set("Content-Type"),
    .transfer_encoding = nuster_str_set("Transfer-Encoding"),
    .last_modified     = nuster_str_set("Last-Modified"),
    .expires           = nuster_str_set("Expires"),
    .cache_control     = nuster_str_set("Cache-Control"),
    .etag              = nuster_str_set("ETag"),
};


/*
 * simply response and close
 */
void nuster_response(struct stream *s, struct chunk *msg) {
    s->txn->flags &= ~TX_WAIT_NEXT_RQ;
    stream_int_retnclose(&s->si[0], msg);
    if(!(s->flags & SF_ERR_MASK)) {
        s->flags |= SF_ERR_LOCAL;
    }
}


void nuster_res_begin(int status) {
    chunk_printf(&trash, "HTTP/1.1 %d %s\r\n", status, get_reason(status));
}

inline void nuster_res_header_server() {
    chunk_appendf(&trash, "%.*s: nuster\r\n", nuster_headers.server.len, nuster_headers.server.data);
}

inline void nuster_res_header_date() {
    struct tm *tm;
    time_t now;
    time(&now);
    tm = gmtime(&now);
    chunk_appendf(&trash, "%.*s: %s, %02d %s %04d %02d:%02d:%02d GMT", nuster_headers.date.len, nuster_headers.date.data,
            day[tm->tm_wday], tm->tm_mday, mon[tm->tm_mon], 1900 + tm->tm_year,
            tm->tm_hour, tm->tm_min, tm->tm_sec);
}

inline void nuster_res_header_content_length(uint64_t content_length) {
    chunk_appendf(&trash, "%.*s: %" PRIu64 "\r\n", nuster_headers.content_length.len, nuster_headers.content_length.data, content_length);
}

inline void nuster_res_header(struct nuster_str *k, struct nuster_str *v) {
    chunk_appendf(&trash, "%.*s: %.*s\r\n", k->len, k->data, v->len, v->data);
}

void nuster_res_body() {
}

void nuster_res_end() {
}

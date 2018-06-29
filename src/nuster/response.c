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




enum {
    NUSTER_HEADER_SERVER,
    NUSTER_HEADER_DATE,
    NUSTER_HEADER_CONTENT_LENGTH,
    NUSTER_HEADER_CONTENT_TYPE,
    NUSTER_HEADER_TRANSFER_ENCODING,
    NUSTER_HEADER_LAST_MODIFIED,
    NUSTER_HEADER_EXPIRES,
    NUSTER_HEADER_CACHE_CONTROL,
    NUSTER_HEADER_ETAG,

    NUSTER_HEADER_SIZE,
    NUSTER_HEADER_CUSTOMIZE,
};

#define nuster_str_set(str)     { (char *) str, sizeof(str) - 1 }

const struct nuster_str nuster_headers[NUSTER_HEADER_SIZE] = {
    [NUSTER_HEADER_SERVER]            = nuster_str_set("Server"),
    [NUSTER_HEADER_DATE]              = nuster_str_set("Date"),
    [NUSTER_HEADER_CONTENT_LENGTH]    = nuster_str_set("Content-Length"),
    [NUSTER_HEADER_CONTENT_TYPE]      = nuster_str_set("Content-Type"),
    [NUSTER_HEADER_TRANSFER_ENCODING] = nuster_str_set("Transfer-Encoding"),
    [NUSTER_HEADER_LAST_MODIFIED]     = nuster_str_set("Last-Modified"),
    [NUSTER_HEADER_EXPIRES]           = nuster_str_set("Expires"),
    [NUSTER_HEADER_CACHE_CONTROL]     = nuster_str_set("Cache-Control"),
    [NUSTER_HEADER_ETAG]              = nuster_str_set("ETag"),
};



void nuster_res_begin(int status) {
    chunk_printf(&trash, "HTTP/1.1 %d %s\r\n", status, get_reason(status));
}

void nuster_res_header(int header, struct nuster_str *k, void *v) {
    struct nuster_str *t;
    struct tm *tm;
    time_t now;

    switch(header) {
        case NUSTER_HEADER_SERVER:
            chunk_appendf(&trash, "%.*s: nuster\r\n", k->len, k->data);
            break;
        case NUSTER_HEADER_DATE:
            time(&now);
            tm = gmtime(&now);
            chunk_appendf(&trash, "%s, %02d %s %04d %02d:%02d:%02d GMT",
                    day[tm->tm_wday], tm->tm_mday, mon[tm->tm_mon], 1900 + tm->tm_year,
                    tm->tm_hour, tm->tm_min, tm->tm_sec);
            break;
        case NUSTER_HEADER_CONTENT_LENGTH:
            chunk_appendf(&trash, "%.*s: %llu\r\n", k->len, k->data, *(unsigned long long *)v);
            break;
        case NUSTER_HEADER_CONTENT_TYPE:
        case NUSTER_HEADER_TRANSFER_ENCODING:
            t = (struct nuster_str *)v;
            chunk_appendf(&trash, "%.*s: %.*s\r\n", k->len, k->data, t->len, t->data);
            break;
        case NUSTER_HEADER_CUSTOMIZE:
            if(k) {
                t = (struct nuster_str *)v;
                chunk_appendf(&trash, "%.*s: %.*s\r\n", k->len, k->data, t->len, t->data);
            }
            break;
    }
}

void nuster_res_body() {
}

void nuster_res_end() {
}

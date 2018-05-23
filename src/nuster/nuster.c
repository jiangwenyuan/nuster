/*
 * nuster common functions.
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

#include <nuster/nuster.h>

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

    [NUSTER_HTTP_500] =
        "HTTP/1.0 500 Internal Server Error\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "500 Internal Server Error\n",
};

struct chunk nuster_http_msg_chunks[NUSTER_HTTP_SIZE];

struct nuster nuster = {
    .cache = NULL,
    .applet = {
        .cache_engine = {
            .obj_type = OBJ_TYPE_APPLET,
            .name     = "<NUSTER.CACHE.ENGINE>",
        },
        .cache_manager = {
            .obj_type = OBJ_TYPE_APPLET,
            .name     = "<NUSTER.CACHE.MANAGER>",
        },
        .cache_stats = {
            .obj_type = OBJ_TYPE_APPLET,
            .name     = "<NUSTER.CACHE.STATS>",
        },
        .nosql_engine = {
            .obj_type = OBJ_TYPE_APPLET,
            .name     = "<NUSTER.NOSQL.ENGINE>",
        },
    },
};

void nuster_debug(const char *fmt, ...) {
    if((global.mode & MODE_DEBUG)) {
        va_list args;
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
    }
}

void nuster_response(struct stream *s, struct chunk *msg) {
    s->txn->flags &= ~TX_WAIT_NEXT_RQ;
    stream_int_retnclose(&s->si[0], msg);
    if(!(s->flags & SF_ERR_MASK)) {
        s->flags |= SF_ERR_LOCAL;
    }
}

void nuster_init() {
    int i = 0;

    for (i = 0; i < NUSTER_HTTP_SIZE; i++) {
        nuster_http_msg_chunks[i].str = (char *)nuster_http_msgs[i];
        nuster_http_msg_chunks[i].len = strlen(nuster_http_msgs[i]);
    }

    nst_cache_init();
    nst_nosql_init();
}

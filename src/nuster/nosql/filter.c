/*
 * Cache filter related variables and functions.
 *
 * Copyright (C) [Jiang Wenyuan](https://github.com/jiangwenyuan), < koubunen AT gmail DOT com >
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <common/cfgparse.h>
#include <common/standard.h>

#include <proto/filters.h>
#include <proto/log.h>
#include <proto/stream.h>
#include <proto/proto_http.h>
#include <proto/stream_interface.h>

#include <nuster/cache.h>

static int _nst_nosql_filter_init(struct proxy *px, struct flt_conf *fconf) {
    return 0;
}

static void _nst_nosql_filter_deinit(struct proxy *px, struct flt_conf *fconf) {
}

static int _nst_nosql_filter_check(struct proxy *px, struct flt_conf *fconf) {
    return 0;
}

static int _nst_nosql_filter_attach(struct stream *s, struct filter *filter) {
    register_data_filter(s, &s->req, filter);
    //register_data_filter(s, &s->res, filter);
    return 1;
}

static void _nst_nosql_filter_detach(struct stream *s, struct filter *filter) {
}

static int _nst_nosql_filter_http_headers(struct stream *s, struct filter *filter,
        struct http_msg *msg) {
    return 1;
}

static int _nst_nosql_filter_http_forward_data(struct stream *s, struct filter *filter,
        struct http_msg *msg, unsigned int len) {
        char *data = msg->chn->buf->data;
        char *p    = msg->chn->buf->p;
        int size   = msg->chn->buf->size;

        if(p - data + len > size) {
            int right = data + size - p;
            int left  = len - right;
            fprintf(stderr, "\n==========\n%.*s\n-------------------\n", right, p);
            fprintf(stderr, "\n==========\n%.*s\n-------------------\n", left, data);
        } else {
            fprintf(stderr, "\n==========\n%.*s\n-------------------\n", len, p);
        }
    return len;
}

static int _nst_nosql_filter_http_end(struct stream *s, struct filter *filter,
        struct http_msg *msg) {
    return 1;
}

struct flt_ops nst_nosql_filter_ops = {
    /* Manage cache filter, called for each filter declaration */
    .init   = _nst_nosql_filter_init,
    .deinit = _nst_nosql_filter_deinit,
    .check  = _nst_nosql_filter_check,

    .attach = _nst_nosql_filter_attach,
    .detach = _nst_nosql_filter_detach,

    /* Filter HTTP requests and responses */
    .http_headers      = _nst_nosql_filter_http_headers,
    .http_forward_data = _nst_nosql_filter_http_forward_data,
    .http_end          = _nst_nosql_filter_http_end,

};

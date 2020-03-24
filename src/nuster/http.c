/*
 * nuster http related functions.
 *
 * Copyright (C) Jiang Wenyuan, < koubunen AT gmail DOT com >
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <nuster/http.h>

int nst_req_find_param(char *query_beg, char *query_end, char *name, char **value, int *value_len) {
    char equal   = '=';
    char and     = '&';
    char *ptr    = query_beg;
    int name_len = strlen(name);

    while(ptr + name_len + 1 < query_end) {

        if(!memcmp(ptr, name, name_len) && *(ptr + name_len) == equal) {

            if(ptr == query_beg || *(ptr - 1) == and) {
                ptr    = ptr + name_len + 1;
                *value = ptr;

                while(ptr < query_end && *ptr != and) {
                    (*value_len)++;
                    ptr++;
                }

                return NST_OK;
            }

        }

        ptr++;
    }

    return NST_ERR;
}

void nst_res_304(struct stream *s, struct ist last_modified, struct ist etag) {

    struct channel *res = &s->res;
    struct htx *htx = htx_from_buf(&res->buf);
    struct htx_sl *sl;
    struct ist code;
    int status;
    unsigned int flags = (HTX_SL_F_IS_RESP|HTX_SL_F_VER_11);
    size_t data;

    status = 304;
    code = ist("304");

    sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, ist("HTTP/1.1"), code,
            ist("Not Modified"));

    if(!sl) {
        goto fail;
    }

    sl->info.res.status = status;
    s->txn->status = status;

    if(!htx_add_header(htx, ist("Last-Modified"), last_modified)
            || !htx_add_header(htx, ist("ETag"), etag)) {

        goto fail;
    }

    if(!htx_add_endof(htx, HTX_BLK_EOH)) {
        goto fail;
    }

    if(!htx_add_endof(htx, HTX_BLK_EOM)) {
        goto fail;
    }

    data = htx->data - co_data(res);
    c_adv(res, data);
    res->total += data;

    channel_auto_read(&s->req);
    channel_abort(&s->req);
    channel_auto_close(&s->req);
    channel_htx_erase(&s->req, htxbuf(&s->req.buf));

    res->wex = tick_add_ifset(now_ms, res->wto);
    channel_auto_read(res);
    channel_auto_close(res);
    channel_shutr_now(res);
    return;

fail:
    channel_htx_truncate(res, htx);
}

void nst_res_412(struct stream *s) {

    struct channel *res = &s->res;
    struct htx *htx = htx_from_buf(&res->buf);
    struct htx_sl *sl;
    struct ist code, body;
    int status;
    unsigned int flags = (HTX_SL_F_IS_RESP|HTX_SL_F_VER_11);
    size_t data;

    status = 412;
    code = ist("412");
    body = ist("412 Precondition Failed");

    sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, ist("HTTP/1.1"), code,
            ist("Precondition Failed"));

    if(!sl) {
        goto fail;
    }

    sl->info.res.status = status;
    s->txn->status = status;

    if(!htx_add_header(htx, ist("Content-Length"), ist("23"))) {
        goto fail;
    }

    if(!htx_add_endof(htx, HTX_BLK_EOH)) {
        goto fail;
    }

    while(body.len) {
        size_t sent = htx_add_data(htx, body);

        if(!sent) {
            goto fail;
        }

        body.ptr += sent;
        body.len -= sent;
    }

    if(!htx_add_endof(htx, HTX_BLK_EOM)) {
        goto fail;
    }

    data = htx->data - co_data(res);
    c_adv(res, data);
    res->total += data;

    channel_auto_read(&s->req);
    channel_abort(&s->req);
    channel_auto_close(&s->req);
    channel_htx_erase(&s->req, htxbuf(&s->req.buf));

    res->wex = tick_add_ifset(now_ms, res->wto);
    channel_auto_read(res);
    channel_auto_close(res);
    channel_shutr_now(res);
    return;

fail:
    channel_htx_truncate(res, htx);
}

void nst_res_simple(struct stream *s, int status) {

    struct channel *res = &s->res;
    struct htx *htx = htx_from_buf(&res->buf);
    struct htx_sl *sl;
    struct ist code;
    unsigned int flags = (HTX_SL_F_IS_RESP|HTX_SL_F_VER_11);

    switch(status) {
        case 200:
            code = ist("200");
            break;
        case 500:
            code = ist("500");
            break;
        case 405:
            code = ist("405");
            break;
        case 404:
            code = ist("404");
            break;
        case 400:
            code = ist("400");
            break;
        case 507:
            code = ist("507");
            break;
        default:
            code = ist("500");
    }

    sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, ist("HTTP/1.1"), code,
            ist2(http_get_reason(status), strlen(http_get_reason(status))));

    if(!sl) {
        goto fail;
    }

    sl->info.res.status = status;
    s->txn->status = status;

    if(!htx_add_endof(htx, HTX_BLK_EOH)) {
        goto fail;
    }

    if(!htx_add_endof(htx, HTX_BLK_EOM)) {
        goto fail;
    }

    channel_add_input(res, htx->data);
    htx_to_buf(htx, &res->buf);
    return;

fail:
    channel_htx_truncate(res, htx);
}


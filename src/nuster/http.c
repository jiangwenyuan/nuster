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

#include <common/http.h>

#include <proto/http_htx.h>

#include <nuster/http.h>

struct nst_http_code nst_http_codes[NST_HTTP_SIZE] = {
    [NST_HTTP_100] = {
        .status = 100,
        .code   = IST("100"),
        .reason = IST("Continue"),
        .length = IST(""),
    },
    [NST_HTTP_200] = {
        .status = 200,
        .code   = IST("200"),
        .reason = IST("OK"),
        .length = IST("2"),
    },
    [NST_HTTP_304] = {
        .status = 304,
        .code   = IST("304"),
        .reason = IST("Not Modified"),
        .length = IST(""),
    },
    [NST_HTTP_400] = {
        .status = 400,
        .code   = IST("400"),
        .reason = IST("Bad Request"),
        .length = IST("11"),
    },
    [NST_HTTP_404] = {
        .status = 404,
        .code   = IST("404"),
        .reason = IST("Not Found"),
        .length = IST("9"),
    },
    [NST_HTTP_405] = {
        .status = 405,
        .code   = IST("405"),
        .reason = IST("Method Not Allowed"),
        .length = IST("18"),
    },
    [NST_HTTP_412] = {
        .status = 412,
        .code   = IST("412"),
        .reason = IST("Precondition Failed"),
        .length = IST("19"),
    },
    [NST_HTTP_500] = {
        .status = 500,
        .code   = IST("500"),
        .reason = IST("Internal Server Error"),
        .length = IST("21"),
    },
    [NST_HTTP_507] = {
        .status = 507,
        .code   = IST("507"),
        .reason = IST("Insufficient storage"),
        .length = IST("20"),
    },
};

int nst_http_find_param(char *query_beg, char *query_end, char *name, char **val, int *val_len) {
    char equal   = '=';
    char and     = '&';
    char *ptr    = query_beg;
    int name_len = strlen(name);

    while(ptr + name_len + 1 < query_end) {

        if(!memcmp(ptr, name, name_len) && *(ptr + name_len) == equal) {

            if(ptr == query_beg || *(ptr - 1) == and) {
                ptr  = ptr + name_len + 1;
                *val = ptr;

                while(ptr < query_end && *ptr != and) {
                    (*val)++;
                    ptr++;
                }

                return NST_OK;
            }

        }

        ptr++;
    }

    return NST_ERR;
}

int nst_http_data_element_to_htx(struct nst_data_element *element, struct htx *htx) {
    struct htx_blk *blk;
    char *ptr;
    uint32_t blksz, sz, info;
    enum htx_blk_type type;

    info = element->info;
    type = (info >> 28);
    blksz = ((type == HTX_BLK_HDR || type == HTX_BLK_TLR)
            ? (info & 0xff) + ((info >> 8) & 0xfffff)
            : info & 0xfffffff);

    blk = htx_add_blk(htx, type, blksz);

    if(!blk) {
        return NST_ERR;
    }

    blk->info = info;
    ptr = htx_get_blk_ptr(htx, blk);
    sz = htx_get_blksz(blk);
    memcpy(ptr, element->data, sz);

    return NST_OK;
}

void nst_http_reply(struct stream *s, int idx) {
    struct stream_interface *si = &s->si[1];
    struct channel *res = &s->res;
    struct htx *htx;
    struct htx_sl *sl;
    unsigned int flags;

    b_reset(&res->buf);

    htx = htx_from_buf(&res->buf);

    flags = (HTX_SL_F_IS_RESP|HTX_SL_F_VER_11|HTX_SL_F_XFER_LEN);
    sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, ist("HTTP/1.1"),
            nst_http_codes[idx].code, nst_http_codes[idx].reason);

    sl->info.res.status = nst_http_codes[idx].status;

    htx_add_header(htx, ist("Content-Length"), nst_http_codes[idx].length);

    htx_add_endof(htx, HTX_BLK_EOH);

    htx_add_data_atonce(htx, nst_http_codes[idx].reason);

    htx_add_endof(htx, HTX_BLK_EOM);

    channel_add_input(res, htx->data);

    if(!(res->flags & CF_SHUTR)) {
        res->flags |= CF_READ_NULL;
        si_shutr(si);
    }

    htx_to_buf(htx, &res->buf);
}

int nst_http_reply_100(struct stream *s) {
    struct channel *res = &s->res;
    struct htx *htx     = htx_from_buf(&res->buf);
    struct htx_sl *sl;
    size_t data;
    unsigned int flags = (HTX_SL_F_IS_RESP|HTX_SL_F_VER_11|HTX_SL_F_XFER_LEN|HTX_SL_F_BODYLESS);

    sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, ist("HTTP/1.1"),
            nst_http_codes[NST_HTTP_100].code, nst_http_codes[NST_HTTP_100].reason);

    if(!sl) {
        goto fail;
    }

    sl->info.res.status = nst_http_codes[NST_HTTP_100].status;

    if(!htx_add_endof(htx, HTX_BLK_EOH)) {
        goto fail;
    }

    data = htx->data - co_data(res);
    c_adv(res, data);
    res->total += data;

    return 0;

fail:
    channel_htx_truncate(res, htx);

    return -1;
}

void nst_http_reply_304(struct stream *s, struct ist last_modified, struct ist etag) {
    struct stream_interface *si = &s->si[1];
    struct channel *res = &s->res;
    struct htx *htx;
    struct htx_sl *sl;
    unsigned int flags = (HTX_SL_F_IS_RESP|HTX_SL_F_VER_11|HTX_SL_F_XFER_LEN|HTX_SL_F_BODYLESS);

    b_reset(&res->buf);

    htx = htx_from_buf(&res->buf);

    sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, ist("HTTP/1.1"),
            nst_http_codes[NST_HTTP_304].code, nst_http_codes[NST_HTTP_304].reason);

    sl->info.res.status = nst_http_codes[NST_HTTP_304].status;

    htx_add_header(htx, ist("Last-Modified"), last_modified);

    htx_add_header(htx, ist("ETag"), etag);

    htx_add_endof(htx, HTX_BLK_EOH);

    htx_add_endof(htx, HTX_BLK_EOM);

    channel_add_input(res, htx->data);

    if(!(res->flags & CF_SHUTR)) {
        res->flags |= CF_READ_NULL;
        si_shutr(si);
    }

    htx_to_buf(htx, &res->buf);

}

int nst_http_handle_expect(struct stream *s, struct htx *htx, struct http_msg *msg) {

    if(msg->msg_state == HTTP_MSG_BODY
            && (msg->flags & HTTP_MSGF_VER_11)
            && (msg->flags & (HTTP_MSGF_CNT_LEN|HTTP_MSGF_TE_CHNK))) {

        struct ist hdr = { .ptr = "Expect", .len = 6 };
        struct http_hdr_ctx ctx;

        ctx.blk = NULL;
        /* Expect is allowed in 1.1, look for it */
        if(http_find_header(htx, hdr, &ctx, 0)
                && unlikely(isteqi(ctx.value, ist2("100-continue", 12)))) {

            if(nst_http_reply_100(s) == -1) {
                return -1;
            }

            http_remove_header(htx, &ctx);
        }
    }

    return 0;
}

/*
 * return:
 * 1: http_headers should return 1 immediately
 * 0: http_headers should proceed
 */
int nst_http_handle_conditional_req(struct stream *s, struct htx *htx,
        int test_last_modified, struct ist last_modified, int test_etag, struct ist etag) {

    struct http_hdr_ctx hdr = { .blk = NULL };

    int if_none_match     = -1;
    int if_match          = -1;
    int if_modified_since = -1;;

    if(test_etag != NST_STATUS_ON && test_last_modified != NST_STATUS_ON) {
        return 0;
    }

    if(test_etag == NST_STATUS_ON) {

        while(http_find_header(htx, ist("If-Match"), &hdr, 0)) {

            if_match = 412;

            if(1 == hdr.value.len && *(hdr.value.ptr) == '*') {
                if_match = 200;

                break;
            }

            if(isteq(etag, hdr.value)) {
                if_match = 200;

                break;
            }
        }

        if(if_match == 412) {
            goto code412;
        }
    }

    if(test_last_modified == NST_STATUS_ON) {

        if(http_find_header(htx, ist("If-Unmodified-Since"), &hdr, 1)) {

            if(!isteq(last_modified, hdr.value)) {
                goto code412;
            }
        }
    }

    if(test_etag == NST_STATUS_ON) {

        while(http_find_header(htx, ist("If-None-Match"), &hdr, 0)) {

            if_none_match = 200;

            if(1 == hdr.value.len && *(hdr.value.ptr) == '*') {
                if_none_match = 304;

                break;
            }

            if(isteq(etag, hdr.value)) {
                if_none_match = 304;

                break;
            }
        }
    }

    if(test_last_modified == NST_STATUS_ON) {

        if(http_find_header(htx, ist("If-Modified-Since"), &hdr, 1)) {

            if(isteq(last_modified, hdr.value)) {
                if_modified_since = 304;
            } else {
                if_modified_since = 200;
            }
        }
    }

    if(if_none_match == 304 && if_modified_since != 200) {
        goto code304;
    }

    if(if_none_match != 200 && if_modified_since == 304) {
        goto code304;
    }

    return 0;

code304:

    nst_http_reply_304(s, last_modified, etag);

    return 1;

code412:

    nst_http_reply(s, NST_HTTP_412);

    return 1;
}



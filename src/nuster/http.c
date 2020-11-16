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

#include <import/xxhash.h>

#include <haproxy/stream_interface.h>
#include <haproxy/http_htx.h>
#include <haproxy/http.h>

#include <nuster/nuster.h>

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

int
nst_http_find_param(char *query_beg, char *query_end, char *name, char **val, int *val_len) {
    char   equal    = '=';
    char   and      = '&';
    char  *ptr      = query_beg;
    int    name_len = strlen(name);

    while(ptr + name_len + 1 < query_end) {

        if(!memcmp(ptr, name, name_len) && *(ptr + name_len) == equal) {

            if(ptr == query_beg || *(ptr - 1) == and) {
                ptr  = ptr + name_len + 1;
                *val = ptr;

                while(ptr < query_end && *ptr != and) {
                    (*val_len)++;
                    ptr++;
                }

                return NST_OK;
            }

        }

        ptr++;
    }

    return NST_ERR;
}

int
nst_http_memory_item_to_htx(nst_memory_item_t *item, hpx_htx_t *htx) {
    hpx_htx_blk_t      *blk;
    uint32_t            blksz, sz, info;
    char               *ptr;
    hpx_htx_blk_type_t  type;

    info  = item->info;
    type  = (info >> 28);
    blksz = ((type == HTX_BLK_HDR || type == HTX_BLK_TLR)
            ? (info & 0xff) + ((info >> 8) & 0xfffff)
            : info & 0xfffffff);

    blk = htx_add_blk(htx, type, blksz);

    if(!blk) {
        return NST_ERR;
    }

    blk->info = info;
    ptr       = htx_get_blk_ptr(htx, blk);
    sz        = htx_get_blksz(blk);

    memcpy(ptr, item->data, sz);

    return NST_OK;
}

void
nst_http_reply(hpx_stream_t *s, int idx) {
    hpx_stream_interface_t  *si  = &s->si[1];
    hpx_channel_t           *res = &s->res;
    hpx_htx_t               *htx;
    hpx_htx_sl_t            *sl;
    unsigned int             flags;

    b_reset(&res->buf);

    htx = htx_from_buf(&res->buf);

    flags = (HTX_SL_F_IS_RESP|HTX_SL_F_VER_11|HTX_SL_F_XFER_LEN);
    sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, ist("HTTP/1.1"),
            nst_http_codes[idx].code, nst_http_codes[idx].reason);

    sl->info.res.status = nst_http_codes[idx].status;

    htx_add_header(htx, ist("Content-Length"), nst_http_codes[idx].length);
    htx_add_header(htx, ist("Content-Type"), ist("text/plain"));

    htx_add_endof(htx, HTX_BLK_EOH);

    htx_add_data_atonce(htx, nst_http_codes[idx].reason);

    htx_add_endof(htx, HTX_BLK_EOM);

    channel_add_input(res, htx->data);

    if(!(res->flags & CF_SHUTR)) {
        res->flags |= CF_READ_NULL;
        si_shutr(si);
    }

    htx_to_buf(htx, &res->buf);

    si_shutr(si);
    si_shutw(si);
    si->err_type = SI_ET_NONE;
    si->state    = SI_ST_CLO;
}

int
nst_http_reply_100(hpx_stream_t *s) {
    hpx_channel_t  *res = &s->res;
    hpx_htx_t      *htx = htx_from_buf(&res->buf);
    hpx_htx_sl_t   *sl;
    size_t          data;
    unsigned int    flags;

    flags = (HTX_SL_F_IS_RESP|HTX_SL_F_VER_11|HTX_SL_F_XFER_LEN|HTX_SL_F_BODYLESS);
    sl    = htx_add_stline(htx, HTX_BLK_RES_SL, flags, ist("HTTP/1.1"),
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

void
nst_http_reply_304(hpx_stream_t *s, nst_http_txn_t *txn) {
    hpx_stream_interface_t  *si  = &s->si[1];
    hpx_channel_t           *res = &s->res;
    hpx_htx_t               *htx;
    hpx_htx_sl_t            *sl;
    unsigned int             flags;

    flags = (HTX_SL_F_IS_RESP|HTX_SL_F_VER_11|HTX_SL_F_XFER_LEN|HTX_SL_F_BODYLESS);

    b_reset(&res->buf);

    htx = htx_from_buf(&res->buf);

    sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, ist("HTTP/1.1"),
            nst_http_codes[NST_HTTP_304].code, nst_http_codes[NST_HTTP_304].reason);

    sl->info.res.status = nst_http_codes[NST_HTTP_304].status;

    htx_add_header(htx, ist("Last-Modified"), txn->res.last_modified);

    htx_add_header(htx, ist("ETag"), txn->res.etag);

    htx_add_endof(htx, HTX_BLK_EOH);

    htx_add_endof(htx, HTX_BLK_EOM);

    channel_add_input(res, htx->data);

    if(!(res->flags & CF_SHUTR)) {
        res->flags |= CF_READ_NULL;
        si_shutr(si);
    }

    htx_to_buf(htx, &res->buf);

}

int
nst_http_handle_expect(hpx_stream_t *s, hpx_htx_t *htx, hpx_http_msg_t *msg) {

    if(msg->msg_state == HTTP_MSG_BODY
            && (msg->flags & HTTP_MSGF_VER_11)
            && (msg->flags & (HTTP_MSGF_CNT_LEN|HTTP_MSGF_TE_CHNK))) {

        hpx_http_hdr_ctx_t  ctx;
        hpx_ist_t           hdr = { .ptr = "Expect", .len = 6 };

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
int
nst_http_handle_conditional_req(hpx_stream_t *s, hpx_htx_t *htx, nst_http_txn_t *txn,
        nst_rule_prop_t *prop) {

    hpx_http_hdr_ctx_t  hdr = { .blk = NULL };

    int  if_none_match      = -1;
    int  if_match           = -1;
    int  if_modified_since  = -1;;

    if(prop->etag != NST_STATUS_ON && prop->last_modified != NST_STATUS_ON) {
        return 0;
    }

    if(prop->etag == NST_STATUS_ON) {

        while(http_find_header(htx, ist("If-Match"), &hdr, 0)) {

            if_match = 412;

            if(1 == hdr.value.len && *(hdr.value.ptr) == '*') {
                if_match = 200;

                break;
            }

            if(isteq(txn->res.etag, hdr.value)) {
                if_match = 200;

                break;
            }
        }

        if(if_match == 412) {
            goto code412;
        }
    }

    if(prop->last_modified == NST_STATUS_ON) {

        hdr.blk = NULL;
        if(http_find_header(htx, ist("If-Unmodified-Since"), &hdr, 1)) {

            if(!isteq(txn->res.last_modified, hdr.value)) {
                goto code412;
            }
        }
    }

    if(prop->etag == NST_STATUS_ON) {

        hdr.blk = NULL;
        while(http_find_header(htx, ist("If-None-Match"), &hdr, 0)) {

            if_none_match = 200;

            if(1 == hdr.value.len && *(hdr.value.ptr) == '*') {
                if_none_match = 304;

                break;
            }

            if(isteq(txn->res.etag, hdr.value)) {
                if_none_match = 304;

                break;
            }
        }
    }

    if(prop->last_modified == NST_STATUS_ON) {

        hdr.blk = NULL;
        if(http_find_header(htx, ist("If-Modified-Since"), &hdr, 1)) {

            if(isteq(txn->res.last_modified, hdr.value)) {
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

    nst_http_reply_304(s, txn);

    return 1;

code412:

    nst_http_reply(s, NST_HTTP_412);

    return 1;
}

int
nst_http_parse_htx(hpx_stream_t *s, hpx_buffer_t *buf, nst_http_txn_t *txn) {
    hpx_http_hdr_ctx_t  hdr = { .blk = NULL };
    hpx_htx_t          *htx = htxbuf(&s->req.buf);
    hpx_htx_sl_t       *sl;
    hpx_ist_t           url, uri;
    char               *uri_begin, *uri_end, *ptr;

    if(buf->data) {
        return NST_OK;
    }

    txn->req.scheme = SCH_HTTP;

#ifdef USE_OPENSSL
    if(s->sess->listener->bind_conf->is_ssl) {
        txn->req.scheme = SCH_HTTPS;
    }
#endif

    if(http_find_header(htx, ist("Host"), &hdr, 1)) {
        txn->req.host.ptr = buf->area + buf->data;
        txn->req.host.len = hdr.value.len;

        chunk_istcat(buf, hdr.value);
    }

    sl  = http_get_stline(htx);
    url = htx_sl_req_uri(sl);
    uri = http_get_path(url);

    if(!uri.len || *uri.ptr != '/') {
        return NST_ERR;
    }

    txn->req.uri.ptr = buf->area + buf->data;
    txn->req.uri.len = uri.len;

    chunk_istcat(buf, uri);

    uri_begin = txn->req.uri.ptr;
    uri_end   = txn->req.uri.ptr + uri.len;

    ptr = uri_begin;

    while(ptr < uri_end && *ptr != '?') {
        ptr++;
    }

    txn->req.path.ptr = txn->req.uri.ptr;
    txn->req.path.len = ptr - uri_begin;

    txn->req.delimiter = 0;

    if(txn->req.uri.ptr) {
        txn->req.query.ptr = memchr(txn->req.uri.ptr, '?', uri.len);

        if(txn->req.query.ptr) {
            txn->req.query.ptr++;
            txn->req.query.len = uri_end - txn->req.query.ptr;

            if(txn->req.query.len) {
                txn->req.delimiter = 1;
            }
        }
    }

    hdr.blk = NULL;
    if(http_find_header(htx, ist("Cookie"), &hdr, 1)) {
        txn->req.cookie.ptr = buf->area + buf->data;
        txn->req.cookie.len = hdr.value.len;

        chunk_istcat(buf, hdr.value);
    }

    hdr.blk = NULL;
    if(http_find_header(htx, ist("Content-Type"), &hdr, 1)) {
        txn->req.content_type.ptr = buf->area + buf->data;
        txn->req.content_type.len = hdr.value.len;

        chunk_istcat(buf, hdr.value);
    }

    return NST_OK;
}

void
nst_http_build_etag(hpx_stream_t *s, hpx_buffer_t *buf, nst_http_txn_t *txn, int etag_prop) {

    hpx_http_hdr_ctx_t  hdr = { .blk = NULL };
    hpx_htx_t          *htx;

    txn->res.etag.ptr = buf->area + buf->data;
    txn->res.etag.len = 0;

    htx = htxbuf(&s->res.buf);

    if(http_find_header(htx, ist("ETag"), &hdr, 1)) {
        txn->res.etag.len = hdr.value.len;

        chunk_istcat(buf, hdr.value);
    } else {
        uint64_t t = nst_time_now_ms();

        sprintf(txn->res.etag.ptr, "\"%08x\"", XXH32(&t, 8, 0));
        txn->res.etag.len = 10;
        b_add(buf, txn->res.etag.len);

        if(etag_prop == NST_STATUS_ON) {
            http_add_header(htx, ist("Etag"), txn->res.etag);
        }
    }
}

void
nst_http_build_last_modified(hpx_stream_t *s, hpx_buffer_t *buf, nst_http_txn_t *txn,
        int last_modified_prop) {

    hpx_http_hdr_ctx_t  hdr = { .blk = NULL };
    hpx_htx_t          *htx;
    int                 len = sizeof("Mon, 01 JAN 1970 00:00:00 GMT") - 1;

    htx = htxbuf(&s->res.buf);

    txn->res.last_modified.ptr = buf->area + buf->data;
    txn->res.last_modified.len = len;

    if(http_find_header(htx, ist("Last-Modified"), &hdr, 1)) {

        if(hdr.value.len == len) {
            chunk_istcat(buf, hdr.value);
        }

    } else {
        struct tm  *tm;
        time_t      now;
        char        mon[12][4] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
            "Oct", "Nov", "Dec" };
        char        day[7][4]  = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

        time(&now);
        tm = gmtime(&now);

        sprintf(txn->res.last_modified.ptr, "%s, %02d %s %04d %02d:%02d:%02d GMT",
                day[tm->tm_wday], tm->tm_mday, mon[tm->tm_mon],
                1900 + tm->tm_year, tm->tm_hour, tm->tm_min, tm->tm_sec);

        b_add(buf, txn->res.last_modified.len);

        if(last_modified_prop == NST_STATUS_ON) {
            http_add_header(htx, ist("Last-Modified"), txn->res.last_modified);
        }
    }
}

hpx_ist_t
nst_http_parse_key_value(hpx_ist_t hdr, hpx_ist_t key) {
    int  i;

    if(hdr.len < key.len) {
        return IST_NULL;
    }

    for(i = 0; i < key.len; i++) {

        if(*(hdr.ptr + i) != *(key.ptr + i)) {
            return IST_NULL;
        }
    }

    if(*(hdr.ptr + key.len) != '=') {
        return IST_NULL;
    }

    return ist2(hdr.ptr + key.len + 1, hdr.len - key.len - 1);
}

int
nst_http_parse_ttl(hpx_htx_t *htx, hpx_buffer_t *buf, nst_http_txn_t *txn) {
    hpx_http_hdr_ctx_t  hdr     = { .blk = NULL };
    hpx_ist_t           smaxage = IST("s-maxage");
    hpx_ist_t           maxage  = IST("max-age");

    int  ret;

    while(http_find_header(htx, ist("cache-control"), &hdr, 0)) {
        hpx_ist_t  value;

        value = nst_http_parse_key_value(hdr.value, smaxage);

        if(isttest(value)) {
            ret = nst_parse_time(value.ptr, value.len, (uint32_t *)&(txn->res.ttl));

            if(ret == NST_TIME_OK && txn->res.ttl > 0) {
                return NST_OK;
            } else if(ret == NST_TIME_OVER) {
                txn->res.ttl = INT_MAX;

                return NST_OK;
            }
        }

        value = nst_http_parse_key_value(hdr.value, maxage);

        if(isttest(value)) {
            ret = nst_parse_time(value.ptr, value.len, (uint32_t *)&(txn->res.ttl));

            if(ret == NST_TIME_OK && txn->res.ttl > 0) {
                return NST_OK;
            } else if(ret == NST_TIME_OVER) {
                txn->res.ttl = INT_MAX;

                return NST_OK;
            }
        }
    }

    return NST_ERR;
}


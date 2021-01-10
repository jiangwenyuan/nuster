/*
 * nuster key functions.
 *
 * Copyright (C) Jiang Wenyuan, < koubunen AT gmail DOT com >
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <inttypes.h>

#include <import/xxhash.h>
#include <import/sha1.h>

#include <haproxy/global.h>
#include <haproxy/htx.h>
#include <haproxy/stream.h>
#include <haproxy/http_htx.h>
#include <haproxy/http.h>

#include <nuster/nuster.h>

int
nst_key_build(hpx_stream_t *s, hpx_http_msg_t *msg, nst_rule_t *rule, nst_http_txn_t *txn,
        nst_key_t *key, hpx_http_meth_t method) {

    nst_key_element_t  **pck = rule->key->data;
    nst_key_element_t   *ck  = NULL;
    hpx_buffer_t        *buf = nst_key_init();

    nst_debug_beg(s, "[rule ] key:  ");

    while((ck = *pck++)) {
        int  ret = NST_ERR;

        switch(ck->type) {
            case NST_KEY_ELEMENT_METHOD:
                nst_debug_add("method.");

                ret = nst_key_catist(buf, http_known_methods[method]);

                break;
            case NST_KEY_ELEMENT_SCHEME:
                nst_debug_add("scheme.");

                {
                    hpx_ist_t scheme = txn->req.scheme == SCH_HTTPS ? ist("HTTPS") : ist("HTTP");
                    ret = nst_key_catist(buf, scheme);
                }

                break;
            case NST_KEY_ELEMENT_HOST:
                nst_debug_add("host.");

                if(txn->req.host.ptr && txn->req.host.len) {
                    ret = nst_key_catist(buf, txn->req.host);
                } else {
                    ret = nst_key_catdel(buf);
                }

                break;
            case NST_KEY_ELEMENT_URI:
                nst_debug_add("uri.");

                if(txn->req.uri.ptr && txn->req.uri.len) {
                    ret = nst_key_catist(buf, txn->req.uri);
                } else {
                    ret = nst_key_catdel(buf);
                }

                break;
            case NST_KEY_ELEMENT_PATH:
                nst_debug_add("path.");

                if(txn->req.path.ptr && txn->req.path.len) {
                    ret = nst_key_catist(buf, txn->req.path);
                } else {
                    ret = nst_key_catdel(buf);
                }

                break;
            case NST_KEY_ELEMENT_DELIMITER:
                nst_debug_add("delimiter.");

                if(txn->req.delimiter) {
                    ret = nst_key_catist(buf, ist("?"));
                } else {
                    ret = nst_key_catdel(buf);
                }

                break;
            case NST_KEY_ELEMENT_QUERY:
                nst_debug_add("query.");

                if(txn->req.query.ptr && txn->req.query.len) {
                    ret = nst_key_catist(buf, txn->req.query);
                } else {
                    ret = nst_key_catdel(buf);
                }

                break;
            case NST_KEY_ELEMENT_PARAM:
                nst_debug_add("param_%s.", ck->data);

                if(txn->req.query.ptr && txn->req.query.len) {
                    char  *v   = NULL;
                    int    v_l = 0;

                    if(nst_http_find_param(txn->req.query.ptr,
                                txn->req.query.ptr + txn->req.query.len,
                                ck->data, &v, &v_l) == NST_OK) {

                        ret = nst_key_catist(buf, ist2(v, v_l));
                        break;
                    }
                }

                ret = nst_key_catdel(buf);
                break;
            case NST_KEY_ELEMENT_HEADER:
                {
                    hpx_htx_t          *htx = htxbuf(&s->req.buf);
                    hpx_http_hdr_ctx_t  hdr = { .blk = NULL };
                    hpx_ist_t           h   = {
                        .ptr = ck->data,
                        .len = strlen(ck->data),
                    };

                    nst_debug_add("header_%s.", ck->data);

                    while(http_find_header(htx, h, &hdr, 0)) {
                        ret = nst_key_catist(buf, hdr.value);

                        if(ret == NST_ERR) {
                            break;
                        }
                    }
                }

                ret = nst_key_catdel(buf);
                break;
            case NST_KEY_ELEMENT_COOKIE:
                nst_debug_add("cookie_%s.", ck->data);

                if(txn->req.cookie.ptr && txn->req.cookie.len) {
                    char   *v   = NULL;
                    size_t  v_l = 0;

                    if(http_extract_cookie_value(txn->req.cookie.ptr,
                                txn->req.cookie.ptr + txn->req.cookie.len,
                                ck->data, strlen(ck->data), 1, &v, &v_l)) {

                        ret = nst_key_catist(buf, ist2(v, v_l));
                        break;
                    }

                }

                ret = nst_key_catdel(buf);
                break;
            case NST_KEY_ELEMENT_BODY:
                nst_debug_add("body.");

                if(s->txn->meth == HTTP_METH_POST || s->txn->meth == HTTP_METH_PUT) {

                    int         idx;
                    hpx_htx_t  *htx = htxbuf(&msg->chn->buf);

                    for(idx = htx_get_first(htx); idx != -1; idx = htx_get_next(htx, idx)) {
                        hpx_htx_blk_t      *blk  = htx_get_blk(htx, idx);
                        hpx_htx_blk_type_t  type = htx_get_blk_type(blk);
                        uint32_t            sz   = htx_get_blksz(blk);

                        if(type != HTX_BLK_DATA) {
                            continue;
                        }

                        ret = nst_key_cat(buf, htx_get_blk_ptr(htx, blk), sz);

                        if(ret != NST_OK) {
                            break;
                        }
                    }
                }

                ret = nst_key_catdel(buf);
                break;
            default:
                ret = NST_ERR;
                break;
        }

        if(ret != NST_OK) {
            return NST_ERR;
        }
    }

    nst_debug_end("");

    key->size = buf->data;
    key->data = malloc(key->size);

    if(!key->data) {
        return NST_ERR;
    }

    memcpy(key->data, buf->area, buf->data);

    return NST_OK;
}

void
nst_key_hash(nst_key_t *key) {
    blk_SHA_CTX ctx;

    key->hash = XXH3(key->data, key->size, 0);

    blk_SHA1_Init(&ctx);
    blk_SHA1_Update(&ctx, key->data, key->size);
    blk_SHA1_Final(key->uuid, &ctx);
}

void
nst_key_debug(hpx_stream_t *s, nst_key_t *key) {

    if((global.mode & MODE_DEBUG)) {
        hpx_session_t  *sess = strm_sess(s);
        int             i;

        chunk_printf(&trash, "%08x:%s.nuster[%04x:%04x]: [key  ] raw:  |%d| ",
                s->uniq_id, s->be->id,
                objt_conn(sess->origin) ?
                (unsigned short)objt_conn(sess->origin)->handle.fd : -1,
                objt_cs(s->si[1].end) ?
                (unsigned short)objt_cs(s->si[1].end)->conn->handle.fd : -1, key->size);

        for(i = 0; i < (key->size > 1024 ? 1024 : key->size); i++) {
            char  c = key->data[i];

            if(c != 0) {
                chunk_appendf(&trash, "%c", c);
            }
        }

        if(key->size > 1024) {
            chunk_appendf(&trash, "...<truncated>");
        }

        chunk_appendf(&trash, "\n");

        chunk_appendf(&trash, "%08x:%s.nuster[%04x:%04x]: [key  ] hash: %"PRIu64"\n",
                s->uniq_id, s->be->id,
                objt_conn(sess->origin) ?
                (unsigned short)objt_conn(sess->origin)->handle.fd : -1,
                objt_cs(s->si[1].end) ?
                (unsigned short)objt_cs(s->si[1].end)->conn->handle.fd : -1, key->hash);

        chunk_appendf(&trash, "%08x:%s.nuster[%04x:%04x]: [key  ] uuid: ",
                s->uniq_id, s->be->id,
                objt_conn(sess->origin) ?
                (unsigned short)objt_conn(sess->origin)->handle.fd : -1,
                objt_cs(s->si[1].end) ?
                (unsigned short)objt_cs(s->si[1].end)->conn->handle.fd : -1);

        nst_key_uuid_stringify(key, trash.area + trash.data);
        trash.data += 40;
        chunk_appendf(&trash, "\n");
        DISGUISE(write(1, trash.area, trash.data));
    }
}


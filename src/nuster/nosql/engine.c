/*
 * nuster nosql engine functions.
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

#include <nuster/memory.h>
#include <nuster/shctx.h>
#include <nuster/nuster.h>
#include <nuster/http.h>

#include <types/global.h>
#include <types/stream.h>
#include <types/channel.h>
#include <types/proxy.h>

#include <proto/stream_interface.h>
#include <proto/proto_http.h>
#include <proto/acl.h>
#include <proto/log.h>

static void nst_nosql_engine_handler(struct appctx *appctx) {
    struct stream_interface *si       = appctx->owner;
    struct stream *s                  = si_strm(si);
    struct channel *res               = si_ic(si);
    struct nst_nosql_element *element = NULL;
    int ret;

    if(unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO)) {
        appctx->ctx.nuster.nosql_engine.data->clients--;
        return;
    }

    /* Check if the input buffer is avalaible. */
    if(res->buf.size == 0) {
        si_rx_room_blk(si);
        return;
    }

    /* check that the output is not closed */
    if(res->flags & (CF_SHUTW|CF_SHUTW_NOW)) {
        appctx->st0 = NST_NOSQL_CTX_STATE_DONE;
    }

    switch(appctx->st0) {
        case NST_NOSQL_APPCTX_STATE_CREATE:
            co_skip(si_oc(si), co_data(si_oc(si)));
            task_wakeup(s->task, TASK_WOKEN_OTHER);
            break;
        case NST_NOSQL_APPCTX_STATE_HIT:

            if(appctx->st1 == 0) {
                nst_res_begin(200);

                if(appctx->ctx.nuster.nosql_engine.data->info.flags
                        & NST_NOSQL_DATA_FLAG_CHUNKED) {

                    nst_res_header(&nst_headers.transfer_encoding,
                            &appctx->ctx.nuster.nosql_engine.data
                            ->info.transfer_encoding);
                } else {
                    nst_res_header_content_length(
                            appctx->ctx.nuster.nosql_engine.data
                            ->info.content_length);

                    if(appctx->ctx.nuster.nosql_engine.data
                            ->info.transfer_encoding.data) {

                        nst_res_header(&nst_headers.transfer_encoding,
                                &appctx->ctx.nuster.nosql_engine.data
                                ->info.transfer_encoding);
                    }
                }

                if(appctx->ctx.nuster.nosql_engine.data
                        ->info.content_type.data) {

                    nst_res_header(&nst_headers.content_type,
                            &appctx->ctx.nuster.nosql_engine.data
                            ->info.content_type);
                }

                nst_res_header_end();
                nst_res_send(si_ic(si), trash.area, trash.data);
                appctx->st1++;
            } else {

                if(appctx->ctx.nuster.nosql_engine.element) {
                    element = appctx->ctx.nuster.nosql_engine.element;

                    ret = nst_res_send(res, element->msg.data,
                            element->msg.len);

                    if(ret >= 0) {
                        appctx->ctx.nuster.nosql_engine.element = element->next;
                    } else if(ret == -2) {
                        appctx->ctx.nuster.nosql_engine.data->clients--;
                        si_shutr(si);
                        res->flags |= CF_READ_NULL;
                    }

                } else {
                    appctx->st0 = NST_NOSQL_APPCTX_STATE_DONE;
                    co_skip(si_oc(si), co_data(si_oc(si)));
                    si_shutr(si);
                    res->flags |= CF_READ_NULL;
                    appctx->ctx.nuster.nosql_engine.data->clients--;
                }
            }

            task_wakeup(s->task, TASK_WOKEN_OTHER);
            break;
        case NST_NOSQL_APPCTX_STATE_ERROR:
            appctx->st0 = NST_NOSQL_APPCTX_STATE_DONE;
            nst_res_simple(si, 500, NULL, 0);
            break;
        case NST_NOSQL_APPCTX_STATE_NOT_ALLOWED:
            appctx->st0 = NST_NOSQL_APPCTX_STATE_DONE;
            nst_res_simple(si, 405, NULL, 0);
            break;
        case NST_NOSQL_APPCTX_STATE_NOT_FOUND:
            appctx->st0 = NST_NOSQL_APPCTX_STATE_DONE;
            nst_res_simple(si, 404, NULL, 0);
            break;
        case NST_NOSQL_APPCTX_STATE_EMPTY:
            appctx->st0 = NST_NOSQL_APPCTX_STATE_DONE;
            nst_res_simple(si, 400, NULL, 0);
            break;
        case NST_NOSQL_APPCTX_STATE_FULL:
            appctx->st0 = NST_NOSQL_APPCTX_STATE_DONE;
            nst_res_simple(si, 507, NULL, 0);
            break;
        case NST_NOSQL_APPCTX_STATE_END:
            appctx->st0 = NST_NOSQL_APPCTX_STATE_DONE;
            nst_res_simple(si, 200, NULL, 0);
            break;
        case NST_NOSQL_APPCTX_STATE_WAIT:
            break;
        case NST_NOSQL_APPCTX_STATE_DONE:
            break;
        default:
            co_skip(si_oc(si), co_data(si_oc(si)));
            break;
    }

    return;
}

struct nst_nosql_data *nst_nosql_data_new() {
    struct nst_nosql_data *data =
        nst_memory_alloc(global.nuster.nosql.memory, sizeof(*data));

    nst_shctx_lock(nuster.nosql);

    if(data) {
        data->clients = 0;
        data->invalid = 0;
        data->element = NULL;

        data->info.transfer_encoding.data = NULL;
        data->info.transfer_encoding.len  = 0;
        data->info.content_type.data      = NULL;
        data->info.content_type.len       = 0;
        data->info.content_length         = 0;

        if(nuster.nosql->data_head == NULL) {
            nuster.nosql->data_head = data;
            nuster.nosql->data_tail = data;
            data->next              = data;
        } else {

            if(nuster.nosql->data_head == nuster.nosql->data_tail) {
                nuster.nosql->data_head->next = data;
                data->next                    = nuster.nosql->data_head;
                nuster.nosql->data_tail       = data;
            } else {
                data->next                    = nuster.nosql->data_head;
                nuster.nosql->data_tail->next = data;
                nuster.nosql->data_tail       = data;
            }
        }
    }

    nst_shctx_unlock(nuster.nosql);

    return data;
}

static int _nst_nosql_data_invalid(struct nst_nosql_data *data) {

    if(data->invalid) {

        if(!data->clients) {
            return 1;
        }
    }
    return 0;
}

static void _nst_nosql_data_cleanup() {
    struct nst_nosql_data *data = NULL;

    if(nuster.nosql->data_head) {

        if(nuster.nosql->data_head == nuster.nosql->data_tail) {

            if(_nst_nosql_data_invalid(nuster.nosql->data_head)) {
                data                    = nuster.nosql->data_head;
                nuster.nosql->data_head = NULL;
                nuster.nosql->data_tail = NULL;
            }

        } else {

            if(_nst_nosql_data_invalid(nuster.nosql->data_head)) {
                data                          = nuster.nosql->data_head;
                nuster.nosql->data_tail->next = nuster.nosql->data_head->next;
                nuster.nosql->data_head       = nuster.nosql->data_head->next;
            } else {
                nuster.nosql->data_tail = nuster.nosql->data_head;
                nuster.nosql->data_head = nuster.nosql->data_head->next;
            }

        }
    }

    if(data) {
        struct nst_nosql_element *element = data->element;

        while(element) {
            struct nst_nosql_element *tmp = element;
            element                       = element->next;

            if(tmp->msg.data) {
                nst_nosql_stats_update_used_mem(-tmp->msg.len);
                nst_memory_free(global.nuster.nosql.memory, tmp->msg.data);
            }

            nst_memory_free(global.nuster.nosql.memory, tmp);
        }

        if(data->info.content_type.data) {
            nst_memory_free(global.nuster.nosql.memory,
                    data->info.content_type.data);
        }

        if(data->info.transfer_encoding.data) {
            nst_memory_free(global.nuster.nosql.memory,
                    data->info.transfer_encoding.data);
        }

        nst_memory_free(global.nuster.nosql.memory, data);
    }
}

void nst_nosql_housekeeping() {

    if(global.nuster.nosql.status == NST_STATUS_ON) {
        nst_shctx_lock(&nuster.nosql->dict[0]);
        nst_nosql_dict_cleanup();
        nst_shctx_unlock(&nuster.nosql->dict[0]);
        nst_shctx_lock(nuster.nosql);
        _nst_nosql_data_cleanup();
        nst_shctx_unlock(nuster.nosql);
    }
}

void nst_nosql_init() {
    nuster.applet.nosql_engine.fct = nst_nosql_engine_handler;

    if(global.nuster.nosql.status == NST_STATUS_ON) {
        global.nuster.nosql.pool.ctx   = create_pool("np.ctx",
                sizeof(struct nst_nosql_ctx), MEM_F_SHARED);

        global.nuster.nosql.memory = nst_memory_create("nosql.shm",
                global.nuster.nosql.dict_size + global.nuster.nosql.data_size,
                global.tune.bufsize, NST_NOSQL_DEFAULT_CHUNK_SIZE);

        if(!global.nuster.nosql.memory) {
            goto shm_err;
        }

        if(nst_shctx_init(global.nuster.nosql.memory) != NST_OK) {
            goto shm_err;
        }

        nuster.nosql = nst_memory_alloc(global.nuster.nosql.memory,
                sizeof(struct nst_nosql));

        if(!nuster.nosql) {
            goto err;
        }

        nuster.nosql->dict[0].entry = NULL;
        nuster.nosql->dict[0].used  = 0;
        nuster.nosql->dict[1].entry = NULL;
        nuster.nosql->dict[1].used  = 0;
        nuster.nosql->data_head     = NULL;
        nuster.nosql->data_tail     = NULL;
        nuster.nosql->rehash_idx    = -1;
        nuster.nosql->cleanup_idx   = 0;

        if(nst_shctx_init(nuster.nosql) != NST_OK) {
            goto shm_err;
        }

        if(nst_nosql_dict_init() != NST_OK) {
            goto err;
        }

        if(nst_nosql_stats_init() != NST_OK) {
            goto err;
        }

    }

    return;

err:
    ha_alert("Out of memory when initializing nuster nosql.\n");
    exit(1);

shm_err:
    ha_alert("Error when initializing nuster nosql memory.\n");
    exit(1);
}

/*
 * return 1 if the request is done, otherwise 0
 */
int nst_nosql_check_applet(struct stream *s, struct channel *req,
        struct proxy *px) {

    if(global.nuster.nosql.status == NST_STATUS_ON
            && px->nuster.mode == NST_MODE_NOSQL) {

        struct stream_interface *si = &s->si[1];
        struct http_txn *txn        = s->txn;
        struct http_msg *msg        = &txn->req;
        struct appctx *appctx       = NULL;

        s->target = &nuster.applet.nosql_engine.obj_type;

        if(unlikely(!si_register_handler(si, objt_applet(s->target)))) {
            txn->status = 500;
            nst_response(s, &nst_http_msg_chunks[NST_HTTP_500]);
            return 1;
        } else {
            appctx      = si_appctx(si);
            appctx->st0 = NST_NOSQL_APPCTX_STATE_INIT;
            appctx->st1 = 0;
            appctx->st2 = 0;

            if(msg->msg_state < HTTP_MSG_CHUNK_SIZE) {

                if(msg->msg_state < HTTP_MSG_100_SENT) {

                    if(msg->flags & HTTP_MSGF_VER_11) {

                        struct hdr_ctx ctx;
                        ctx.idx = 0;

                        if(http_find_header2("Expect", 6, ci_head(req),
                                    &txn->hdr_idx, &ctx)
                                && unlikely(ctx.vlen == 12
                                    && strncasecmp(ctx.line+ctx.val,
                                        "100-continue", 12) == 0)) {

                            co_inject(&s->res, HTTP_100.ptr, HTTP_100.len);
                            http_remove_header2(&txn->req, &txn->hdr_idx, &ctx);
                        }
                    }

                    msg->msg_state = HTTP_MSG_100_SENT;
                }

                msg->next = msg->sov;

                if(msg->flags & HTTP_MSGF_TE_CHNK) {
                    msg->msg_state = HTTP_MSG_CHUNK_SIZE;
                } else {
                    msg->msg_state = HTTP_MSG_DATA;
                }
            }

            req->analysers &=
                (AN_REQ_HTTP_BODY | AN_REQ_FLT_HTTP_HDRS | AN_REQ_FLT_END);

            req->analysers &= ~AN_REQ_FLT_XFER_DATA;
            req->analysers |= AN_REQ_HTTP_XFER_BODY;

        }
    }

    return 0;
}

int nst_nosql_prebuild_key(struct nst_nosql_ctx *ctx, struct stream *s,
        struct http_msg *msg) {

    struct http_txn *txn = s->txn;

    char *uri_begin, *uri_end;
    struct hdr_ctx hdr;

    ctx->req.scheme = SCH_HTTP;
#ifdef USE_OPENSSL
    if(s->sess->listener->bind_conf->is_ssl) {
        ctx->req.scheme = SCH_HTTPS;
    }
#endif

    ctx->req.host.data = NULL;
    ctx->req.host.len  = 0;
    hdr.idx            = 0;

    if(http_find_header2("Host", 4, ci_head(msg->chn), &txn->hdr_idx, &hdr)) {
        ctx->req.host.data = nst_memory_alloc(global.nuster.nosql.memory,
                hdr.vlen);

        if(!ctx->req.host.data) {
            return 0;
        }

        ctx->req.host.len  = hdr.vlen;
        memcpy(ctx->req.host.data, hdr.line + hdr.val, hdr.vlen);
    }

    uri_begin          = http_txn_get_path(txn);
    uri_end            = NULL;
    ctx->req.path.data = NULL;
    ctx->req.path.len  = 0;
    ctx->req.uri.data  = NULL;
    ctx->req.uri.len   = 0;

    if(uri_begin) {
        char *ptr = uri_begin;
        uri_end   = ci_head(msg->chn) + msg->sl.rq.u + msg->sl.rq.u_l;

        while(ptr < uri_end && *ptr != '?') {
            ptr++;
        }

        ctx->req.path.len = ptr - uri_begin;
        ctx->req.uri.data = uri_begin;
        ctx->req.uri.len  = uri_end - uri_begin;

        /* extra 1 char as required by regex_exec_match2 */
        ctx->req.path.data = nst_memory_alloc(global.nuster.nosql.memory,
                ctx->req.path.len + 1);

        if(!ctx->req.path.data) {
            return 0;
        }

        memcpy(ctx->req.path.data, uri_begin, ctx->req.path.len);
    }

    ctx->req.query.data = NULL;
    ctx->req.query.len  = 0;
    ctx->req.delimiter  = 0;

    if(ctx->req.uri.data) {
        ctx->req.query.data = memchr(ctx->req.uri.data, '?',
                uri_end - ctx->req.uri.data);

        if(ctx->req.query.data) {
            ctx->req.query.data++;
            ctx->req.query.len = uri_end - ctx->req.query.data;

            if(ctx->req.query.len) {
                ctx->req.delimiter = 1;
            }
        }
    }

    ctx->req.cookie.data = NULL;
    ctx->req.cookie.len  = 0;
    hdr.idx              = 0;

    if(http_find_header2("Cookie", 6, ci_head(msg->chn), &txn->hdr_idx, &hdr)) {
        ctx->req.cookie.data = hdr.line + hdr.val;
        ctx->req.cookie.len  = hdr.vlen;
    }

    ctx->req.transfer_encoding.data = NULL;
    ctx->req.transfer_encoding.len  = 0;
    ctx->req.content_type.data      = NULL;
    ctx->req.content_type.len       = 0;

    return 1;
}

static struct buffer *_nst_key_init() {
    struct buffer *key  = nst_memory_alloc(global.nuster.nosql.memory,
            sizeof(*key));

    if(!key) {
        return NULL;
    }

    key->area = nst_memory_alloc(global.nuster.nosql.memory,
            NST_CACHE_DEFAULT_KEY_SIZE);

    if(!key->area) {
        return NULL;
    }

    key->size = NST_CACHE_DEFAULT_KEY_SIZE;
    key->data = 0;
    key->head = 0;
    memset(key->area, 0, key->size);

    return key;
}

static int _nst_key_expand(struct buffer *key) {

    if(key->size >= global.tune.bufsize) {
        goto err;
    } else {
        char *p = nst_memory_alloc(global.nuster.nosql.memory,
                key->size * 2);

        if(!p) {
            goto err;
        }

        memset(p, 0, key->size * 2);
        memcpy(p, key->area, key->size);
        nst_memory_free(global.nuster.nosql.memory, key->area);
        key->area = p;
        key->size = key->size * 2;

        return NST_OK;
    }

err:
    nst_memory_free(global.nuster.nosql.memory, key->area);
    nst_memory_free(global.nuster.nosql.memory, key);

    return NST_ERR;
}

static int _nst_key_advance(struct buffer *key, int step) {

    if(b_room(key) < step) {

        if(_nst_key_expand(key) != NST_OK) {
            return NST_ERR;
        }

    }

    key->data += step;

    return NST_OK;
}

static int _nst_key_append(struct buffer *key, char *str, int str_len) {

    if(b_room(key) < str_len + 1) {

        if(_nst_key_expand(key) != NST_OK) {
            return NST_ERR;
        }

    }

    memcpy(key->area + key->data, str, str_len);
    key->data += str_len + 1;

    return NST_OK;
}

int nst_nosql_build_key(struct nst_nosql_ctx *ctx, struct nst_rule_key **pck,
        struct stream *s, struct http_msg *msg) {

    struct http_txn *txn = s->txn;

    struct hdr_ctx hdr;

    struct nst_rule_key *ck = NULL;

    ctx->key  = _nst_key_init();

    if(!ctx->key) {
        return NST_ERR;
    }

    nst_debug("[NOSQL] Calculate key: ");

    while((ck = *pck++)) {
        int ret;

        switch(ck->type) {
            case NST_RULE_KEY_METHOD:
                nst_debug("method.");
                ret = _nst_key_append(ctx->key,
                        http_known_methods[HTTP_METH_GET].ptr,
                        http_known_methods[HTTP_METH_GET].len);
                break;
            case NST_RULE_KEY_SCHEME:
                nst_debug("scheme.");
                ret = _nst_key_append(ctx->key,
                        ctx->req.scheme == SCH_HTTPS ? "HTTPS" : "HTTP",
                        ctx->req.scheme == SCH_HTTPS ? 5 : 4);
                break;
            case NST_RULE_KEY_HOST:
                nst_debug("host.");

                if(ctx->req.host.data) {
                    ret = _nst_key_append(ctx->key, ctx->req.host.data,
                            ctx->req.host.len);
                } else {
                    ret = _nst_key_advance(ctx->key, 2);
                }

                break;
            case NST_RULE_KEY_URI:
                nst_debug("uri.");

                if(ctx->req.uri.data) {
                    ret = _nst_key_append(ctx->key, ctx->req.uri.data,
                            ctx->req.uri.len);

                } else {
                    ret = _nst_key_advance(ctx->key, 2);
                }

                break;
            case NST_RULE_KEY_PATH:
                nst_debug("path.");

                if(ctx->req.path.data) {
                    ret = _nst_key_append(ctx->key, ctx->req.path.data,
                            ctx->req.path.len);

                } else {
                    ret = _nst_key_advance(ctx->key, 2);
                }

                break;
            case NST_RULE_KEY_DELIMITER:
                nst_debug("delimiter.");

                if(ctx->req.delimiter) {
                    ret = _nst_key_append(ctx->key, "?", 1);
                } else {
                    ret = _nst_key_advance(ctx->key, 2);
                }

                break;
            case NST_RULE_KEY_QUERY:
                nst_debug("query.");

                if(ctx->req.query.data && ctx->req.query.len) {
                    ret = _nst_key_append(ctx->key, ctx->req.query.data,
                            ctx->req.query.len);

                } else {
                    ret = _nst_key_advance(ctx->key, 2);
                }

                break;
            case NST_RULE_KEY_PARAM:
                nst_debug("param_%s.", ck->data);

                if(ctx->req.query.data && ctx->req.query.len) {
                    char *v = NULL;
                    int v_l = 0;

                    if(nst_req_find_param(ctx->req.query.data,
                                ctx->req.query.data + ctx->req.query.len,
                                ck->data, &v, &v_l) == NST_OK) {

                        ret = _nst_key_append(ctx->key, v, v_l);
                        break;
                    }

                }

                ret = _nst_key_advance(ctx->key, 2);

                break;
            case NST_RULE_KEY_HEADER:
                hdr.idx = 0;
                nst_debug("header_%s.", ck->data);

                while(http_find_header2(ck->data, strlen(ck->data),
                            ci_head(msg->chn), &txn->hdr_idx, &hdr)) {

                    ret = _nst_key_append(ctx->key, hdr.line + hdr.val,
                            hdr.vlen);

                }

                ret = ret == NST_OK && _nst_key_advance(ctx->key,
                        hdr.idx == 0 ? 2 : 1);

                break;
            case NST_RULE_KEY_COOKIE:
                nst_debug("cookie_%s.", ck->data);

                if(ctx->req.cookie.data) {
                    char *v = NULL;
                    size_t v_l = 0;

                    if(http_extract_cookie_value(ctx->req.cookie.data,
                                ctx->req.cookie.data + ctx->req.cookie.len,
                                ck->data, strlen(ck->data), 1, &v, &v_l)) {

                        ret = _nst_key_append(ctx->key, v, v_l);
                        break;
                    }

                }

                break;
            case NST_RULE_KEY_BODY:
                nst_debug("body.");

                if(txn->meth == HTTP_METH_POST || txn->meth == HTTP_METH_PUT) {

                    if((s->be->options & PR_O_WREQ_BODY)
                            && ci_data(msg->chn) - msg->sov > 0) {

                        ret = _nst_key_append(ctx->key,
                                ci_head(msg->chn) + msg->sov,
                                ci_data(msg->chn) - msg->sov);

                    } else {
                        ret = _nst_key_advance(ctx->key, 2);
                    }
                }

                break;
            default:
                break;
        }

        if(ret != NST_OK) {
            return NST_ERR;
        }
    }

    nst_debug("\n");

    return NST_OK;
}

void nst_nosql_hit(struct stream *s, struct stream_interface *si,
        struct channel *req, struct channel *res, struct nst_nosql_data *data) {
}

int nst_nosql_get_headers(struct nst_nosql_ctx *ctx, struct stream *s,
        struct http_msg *msg) {

    struct http_txn *txn = s->txn;
    struct hdr_ctx hdr;

    hdr.idx = 0;
    if(http_find_header2("Content-Type", 12, ci_head(msg->chn),
                &txn->hdr_idx, &hdr)) {

        ctx->req.content_type.data =
            nst_memory_alloc(global.nuster.nosql.memory, hdr.vlen);

        if(!ctx->req.content_type.data) {
            return 0;
        }

        ctx->req.content_type.len = hdr.vlen;
        memcpy(ctx->req.content_type.data, hdr.line + hdr.val, hdr.vlen);
    }

    hdr.idx = 0;
    while(http_find_header2("Transfer-Encoding", 17, ci_head(msg->chn),
                &txn->hdr_idx, &hdr)) {

        char *p = ctx->req.transfer_encoding.data;
        int len = p
            ? ctx->req.transfer_encoding.len + hdr.vlen + 1
            : ctx->req.transfer_encoding.len + hdr.vlen;

        ctx->req.transfer_encoding.data =
            nst_memory_alloc(global.nuster.nosql.memory, len);

        if(!ctx->req.transfer_encoding.data) {

            if(p) {
                nst_memory_free(global.nuster.nosql.memory, p);
            }

            return 0;
        }

        if(p) {
            memcpy(ctx->req.transfer_encoding.data, p,
                    ctx->req.transfer_encoding.len);

            ctx->req.transfer_encoding.data[ctx->req.transfer_encoding.len] =
                ',';

            nst_memory_free(global.nuster.nosql.memory, p);
            memcpy(ctx->req.transfer_encoding.data
                    + ctx->req.transfer_encoding.len + 1,
                    hdr.line + hdr.val, hdr.vlen);

        } else {
            memcpy(ctx->req.transfer_encoding.data, hdr.line + hdr.val,
                    hdr.vlen);
        }

        ctx->req.transfer_encoding.len = len;
    }

    return 1;
}

void nst_nosql_create(struct nst_nosql_ctx *ctx, struct stream *s,
        struct http_msg *msg) {

    struct nst_nosql_entry *entry = NULL;

    /* Check if nosql is full */
    if(nst_nosql_stats_full()) {
        ctx->state = NST_NOSQL_CTX_STATE_FULL;
        return;
    }

    nst_shctx_lock(&nuster.nosql->dict[0]);
    entry = nst_nosql_dict_get(ctx->key, ctx->hash);

    if(entry) {

        if(entry->state == NST_NOSQL_ENTRY_STATE_CREATING) {
            ctx->state = NST_NOSQL_CTX_STATE_WAIT;
        } else {
            entry->state = NST_NOSQL_ENTRY_STATE_CREATING;

            if(entry->data) {
                entry->data->invalid = 1;
            }

            entry->data = nst_nosql_data_new();
            ctx->state  = NST_NOSQL_CTX_STATE_CREATE;
        }
    } else {
        ctx->state = NST_NOSQL_CTX_STATE_CREATE;
        entry = nst_nosql_dict_set(ctx);
    }

    nst_shctx_unlock(&nuster.nosql->dict[0]);

    if(!entry || !entry->data) {
        ctx->state   = NST_NOSQL_CTX_STATE_INVALID;
    } else {

        if(ctx->state == NST_NOSQL_CTX_STATE_CREATE) {
            ctx->entry   = entry;
            ctx->data    = entry->data;
            ctx->element = entry->data->element;
        }
    }
}

static struct nst_nosql_element *_nst_nosql_data_append(struct http_msg *msg,
        long msg_len) {

    struct nst_nosql_element *element =
        nst_memory_alloc(global.nuster.nosql.memory, sizeof(*element));

    if(element) {
        char *data = b_orig(&msg->chn->buf);
        char *p    = ci_head(msg->chn);
        int size   = msg->chn->buf.size;

        element->msg.data = nst_memory_alloc(global.nuster.nosql.memory,
                msg_len);

        if(!element->msg.data) {
            nst_memory_free(global.nuster.nosql.memory, element);
            return NULL;
        }

        if(p - data + msg_len > size) {
            int right = data + size - p;
            int left  = msg_len - right;
            memcpy(element->msg.data, p, right);
            memcpy(element->msg.data + right, data, left);
        } else {
            memcpy(element->msg.data, p, msg_len);
        }

        element->msg.len = msg_len;
        element->next    = NULL;
        nst_nosql_stats_update_used_mem(msg_len);
    }

    return element;
}

int nst_nosql_update(struct nst_nosql_ctx *ctx, struct http_msg *msg,
        long msg_len) {

    struct nst_nosql_element *element = _nst_nosql_data_append(msg, msg_len);

    if(element) {

        if(ctx->element) {
            ctx->element->next = element;
        } else {
            ctx->data->element = element;
        }

        ctx->element = element;

        return 1;
    } else {
        return 0;
    }
}

struct nst_nosql_data *nst_nosql_exists(struct buffer *key, uint64_t hash) {
    struct nst_nosql_entry *entry = NULL;
    struct nst_nosql_data  *data  = NULL;

    if(!key) {
        return NULL;
    }

    nst_shctx_lock(&nuster.nosql->dict[0]);
    entry = nst_nosql_dict_get(key, hash);

    if(entry && entry->state == NST_NOSQL_ENTRY_STATE_VALID) {
        data = entry->data;
        data->clients++;
    }

    nst_shctx_unlock(&nuster.nosql->dict[0]);

    return data;
}

int nst_nosql_delete(struct buffer *key, uint64_t hash) {
    struct nst_nosql_entry *entry = NULL;
    int ret = 0;

    if(!key) {
        return 0;
    }

    nst_shctx_lock(&nuster.nosql->dict[0]);
    entry = nst_nosql_dict_get(key, hash);

    if(entry) {
        entry->state = NST_NOSQL_ENTRY_STATE_INVALID;
        ret = 1;
    }

    nst_shctx_unlock(&nuster.nosql->dict[0]);

    return ret;
}

void nst_nosql_finish(struct nst_nosql_ctx *ctx, struct http_msg *msg) {

    if(msg->body_len == 0) {
        ctx->state = NST_NOSQL_CTX_STATE_INVALID;
        ctx->entry->state = NST_NOSQL_ENTRY_STATE_INVALID;
    } else {

        if(ctx->req.content_type.data) {
            ctx->entry->data->info.content_type.data =
                ctx->req.content_type.data;

            ctx->entry->data->info.content_type.len  =
                ctx->req.content_type.len;

            ctx->req.content_type.data = NULL;
        }

        if(ctx->req.transfer_encoding.data) {
            ctx->entry->data->info.transfer_encoding.data =
                ctx->req.transfer_encoding.data;

            ctx->entry->data->info.transfer_encoding.len  =
                ctx->req.transfer_encoding.len;

            ctx->req.transfer_encoding.data = NULL;
        }

        ctx->entry->data->info.content_length = msg->body_len;

        if(msg->flags & HTTP_MSGF_TE_CHNK) {
            ctx->entry->data->info.flags = NST_NOSQL_DATA_FLAG_CHUNKED;
        } else {
            ctx->entry->data->info.flags = 0;
        }

        ctx->state = NST_NOSQL_CTX_STATE_DONE;
        ctx->entry->state = NST_NOSQL_ENTRY_STATE_VALID;

        if(*ctx->rule->ttl == 0) {
            ctx->entry->expire = 0;
        } else {
            ctx->entry->expire = get_current_timestamp() / 1000
                + *ctx->rule->ttl;
        }
    }
}

void nst_nosql_abort(struct nst_nosql_ctx *ctx) {
    ctx->entry->state = NST_NOSQL_ENTRY_STATE_INVALID;
}


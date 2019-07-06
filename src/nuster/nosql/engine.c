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
        case NST_NOSQL_APPCTX_STATE_HIT_DISK:
            {
                int max = b_room(&res->buf) - global.tune.maxrewrite;

                int fd = appctx->ctx.nuster.nosql_engine.fd;
                int header_len = appctx->ctx.nuster.nosql_engine.header_len;
                uint64_t offset = appctx->ctx.nuster.nosql_engine.offset;

                char buf[16*1024] = {0};

                if(b_data(&res->buf) != 0) {
                    return;
                }

                switch(appctx->st1) {
                    case NST_PERSIST_APPLET_HEADER:
                        ret = pread(fd, buf, header_len, offset);

                        if(ret != header_len) {
                            appctx->st1 = NST_PERSIST_APPLET_ERROR;
                            break;
                        }

                        ret = ci_putblk(res, buf, ret);

                        if(ret >= 0) {
                            appctx->st1 = NST_PERSIST_APPLET_PAYLOAD;
                            appctx->ctx.nuster.nosql_engine.offset += ret;
                        } else if(ret == -2) {
                            appctx->st1 = NST_PERSIST_APPLET_ERROR;
                            si_shutr(si);
                            res->flags |= CF_READ_NULL;
                        }
                        break;
                    case NST_PERSIST_APPLET_PAYLOAD:
                        ret = pread(fd, buf, max, offset);

                        if(ret == -1) {
                            appctx->st1 = NST_PERSIST_APPLET_ERROR;
                            break;
                        }

                        if(ret == 0) {
                            close(fd);
                            appctx->st1 = NST_PERSIST_APPLET_DONE;
                            break;
                        }

                        ret = ci_putblk(res, buf, ret);

                        if(ret >= 0) {
                            appctx->st1 = NST_PERSIST_APPLET_PAYLOAD;
                            appctx->ctx.nuster.nosql_engine.offset += ret;
                        } else if(ret == -2) {
                            appctx->st1 = NST_PERSIST_APPLET_ERROR;
                            si_shutr(si);
                            res->flags |= CF_READ_NULL;
                        }
                        break;
                    case NST_PERSIST_APPLET_DONE:
                        co_skip(si_oc(si), co_data(si_oc(si)));
                        si_shutr(si);
                        res->flags |= CF_READ_NULL;
                        break;
                    case NST_PERSIST_APPLET_ERROR:
                        si_shutr(si);
                        res->flags |= CF_READ_NULL;
                        close(fd);
                        break;
                }
            }
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
    struct nst_nosql_data *data = nst_nosql_memory_alloc(sizeof(*data));

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
                nst_nosql_memory_free(tmp->msg.data);
            }

            nst_nosql_memory_free(tmp);
        }

        if(data->info.content_type.data) {
            nst_nosql_memory_free(data->info.content_type.data);
        }

        if(data->info.transfer_encoding.data) {
            nst_nosql_memory_free(data->info.transfer_encoding.data);
        }

        nst_nosql_memory_free(data);
    }
}

void nst_nosql_housekeeping() {

    if(global.nuster.nosql.status == NST_STATUS_ON && master == 1) {

        int dict_cleaner = global.nuster.nosql.dict_cleaner;
        int data_cleaner = global.nuster.nosql.data_cleaner;
        int disk_cleaner = global.nuster.nosql.disk_cleaner;
        int disk_loader  = global.nuster.nosql.disk_loader;
        int disk_saver   = global.nuster.nosql.disk_saver;

        while(dict_cleaner--) {
            nst_shctx_lock(&nuster.nosql->dict[0]);
            nst_nosql_dict_cleanup();
            nst_shctx_unlock(&nuster.nosql->dict[0]);
        }

        while(data_cleaner--) {
            nst_shctx_lock(nuster.nosql);
            _nst_nosql_data_cleanup();
            nst_shctx_unlock(nuster.nosql);
        }

        while(disk_cleaner--) {
            nst_nosql_persist_cleanup();
        }

        while(disk_loader--) {
            nst_nosql_persist_load();
        }

        while(disk_saver--) {
            nst_shctx_lock(&nuster.nosql->dict[0]);
            nst_nosql_persist_async();
            nst_shctx_unlock(&nuster.nosql->dict[0]);
        }
    }
}

void nst_nosql_init() {
    nuster.applet.nosql_engine.fct = nst_nosql_engine_handler;

    if(global.nuster.nosql.status == NST_STATUS_ON) {
        if(global.nuster.nosql.directory) {

            if(nst_persist_mkdir(global.nuster.nosql.directory) == NST_ERR) {

                ha_alert("Create `%s` failed\n", global.nuster.nosql.directory);
                exit(1);
            }
        }

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

        nuster.nosql = nst_nosql_memory_alloc(sizeof(struct nst_nosql));

        if(!nuster.nosql) {
            goto err;
        }

        memset(nuster.nosql, 0, sizeof(*nuster.nosql));

        nuster.nosql->disk.file = nst_persist_alloc(global.nuster.nosql.memory);

        if(!nuster.nosql->disk.file) {
            goto err;
        }

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
        ctx->req.host.data = nst_nosql_memory_alloc(hdr.vlen);

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
        ctx->req.path.data = nst_nosql_memory_alloc(ctx->req.path.len + 1);

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

int nst_nosql_build_key(struct nst_nosql_ctx *ctx, struct nst_rule_key **pck,
        struct stream *s, struct http_msg *msg) {

    struct http_txn *txn = s->txn;

    struct hdr_ctx hdr;

    struct nst_rule_key *ck = NULL;

    ctx->key  = nst_nosql_key_init();

    if(!ctx->key) {
        return NST_ERR;
    }

    nst_debug("[NOSQL] Calculate key: ");

    while((ck = *pck++)) {
        int ret = NST_OK;

        switch(ck->type) {
            case NST_RULE_KEY_METHOD:
                nst_debug("method.");
                ret = nst_nosql_key_append(ctx->key,
                        http_known_methods[HTTP_METH_GET].ptr,
                        http_known_methods[HTTP_METH_GET].len);
                break;
            case NST_RULE_KEY_SCHEME:
                nst_debug("scheme.");
                ret = nst_nosql_key_append(ctx->key,
                        ctx->req.scheme == SCH_HTTPS ? "HTTPS" : "HTTP",
                        ctx->req.scheme == SCH_HTTPS ? 5 : 4);
                break;
            case NST_RULE_KEY_HOST:
                nst_debug("host.");

                if(ctx->req.host.data) {
                    ret = nst_nosql_key_append(ctx->key, ctx->req.host.data,
                            ctx->req.host.len);
                } else {
                    ret = nst_nosql_key_advance(ctx->key, 2);
                }

                break;
            case NST_RULE_KEY_URI:
                nst_debug("uri.");

                if(ctx->req.uri.data) {
                    ret = nst_nosql_key_append(ctx->key, ctx->req.uri.data,
                            ctx->req.uri.len);

                } else {
                    ret = nst_nosql_key_advance(ctx->key, 2);
                }

                break;
            case NST_RULE_KEY_PATH:
                nst_debug("path.");

                if(ctx->req.path.data) {
                    ret = nst_nosql_key_append(ctx->key, ctx->req.path.data,
                            ctx->req.path.len);

                } else {
                    ret = nst_nosql_key_advance(ctx->key, 2);
                }

                break;
            case NST_RULE_KEY_DELIMITER:
                nst_debug("delimiter.");

                if(ctx->req.delimiter) {
                    ret = nst_nosql_key_append(ctx->key, "?", 1);
                } else {
                    ret = nst_nosql_key_advance(ctx->key, 2);
                }

                break;
            case NST_RULE_KEY_QUERY:
                nst_debug("query.");

                if(ctx->req.query.data && ctx->req.query.len) {
                    ret = nst_nosql_key_append(ctx->key, ctx->req.query.data,
                            ctx->req.query.len);

                } else {
                    ret = nst_nosql_key_advance(ctx->key, 2);
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

                        ret = nst_nosql_key_append(ctx->key, v, v_l);
                        break;
                    }

                }

                ret = nst_nosql_key_advance(ctx->key, 2);

                break;
            case NST_RULE_KEY_HEADER:
                hdr.idx = 0;
                nst_debug("header_%s.", ck->data);

                while(http_find_header2(ck->data, strlen(ck->data),
                            ci_head(msg->chn), &txn->hdr_idx, &hdr)) {

                    ret = nst_nosql_key_append(ctx->key, hdr.line + hdr.val,
                            hdr.vlen);

                }

                ret = ret == NST_OK && nst_nosql_key_advance(ctx->key,
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

                        ret = nst_nosql_key_append(ctx->key, v, v_l);
                        break;
                    }

                }

                break;
            case NST_RULE_KEY_BODY:
                nst_debug("body.");

                if(txn->meth == HTTP_METH_POST || txn->meth == HTTP_METH_PUT) {

                    if((s->be->options & PR_O_WREQ_BODY)
                            && ci_data(msg->chn) - msg->sov > 0) {

                        ret = nst_nosql_key_append(ctx->key,
                                ci_head(msg->chn) + msg->sov,
                                ci_data(msg->chn) - msg->sov);

                    } else {
                        ret = nst_nosql_key_advance(ctx->key, 2);
                    }
                }

                break;
            default:
                ret = NST_ERR;
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

        ctx->req.content_type.data = nst_nosql_memory_alloc(hdr.vlen);

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

        ctx->req.transfer_encoding.data = nst_nosql_memory_alloc(len);

        if(!ctx->req.transfer_encoding.data) {

            if(p) {
                nst_nosql_memory_free(p);
            }

            return 0;
        }

        if(p) {
            memcpy(ctx->req.transfer_encoding.data, p,
                    ctx->req.transfer_encoding.len);

            ctx->req.transfer_encoding.data[ctx->req.transfer_encoding.len] =
                ',';

            nst_nosql_memory_free(p);
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

    if(ctx->state == NST_NOSQL_CTX_STATE_CREATE
            && (ctx->rule->disk == NST_DISK_SYNC
                || ctx->rule->disk == NST_DISK_ONLY)) {

        ctx->disk.file = nst_nosql_memory_alloc(NST_PERSIST_PATH_FILE_LEN + 1);

        if(!ctx->disk.file) {
            return;
        }

        if(nst_persist_init(ctx->disk.file, ctx->hash,
                global.nuster.nosql.directory) != NST_OK) {

            return;
        }

        ctx->disk.fd = nst_persist_create(ctx->disk.file);

        /* write header */
        nst_res_begin(200);

        if(msg->flags & HTTP_MSGF_TE_CHNK) {

            nst_res_header(&nst_headers.transfer_encoding,
                    &ctx->req.transfer_encoding);
        } else {
            nst_res_header_content_length(msg->body_len);

            if(ctx->req.transfer_encoding.data) {

                nst_res_header(&nst_headers.transfer_encoding,
                        &ctx->req.transfer_encoding);
            }
        }

        if(ctx->req.content_type.data) {

            nst_res_header(&nst_headers.content_type, &ctx->req.content_type);
        }

        nst_res_header_end();

        nst_persist_meta_init(ctx->disk.meta, (char)ctx->rule->disk,
                ctx->hash, 0, 0, trash.data, ctx->entry->key->data);

        nst_persist_write_key(&ctx->disk, ctx->entry->key);

        ctx->disk.offset = NST_PERSIST_META_SIZE + ctx->entry->key->data;
        nst_persist_write(&ctx->disk, trash.area, trash.data);
    }
}

static struct nst_nosql_element *_nst_nosql_data_append(struct http_msg *msg,
        long msg_len) {

    struct nst_nosql_element *element =
        nst_nosql_memory_alloc(sizeof(*element));

    if(element) {
        char *data = b_orig(&msg->chn->buf);
        char *p    = ci_head(msg->chn);
        int size   = msg->chn->buf.size;

        element->msg.data = nst_nosql_memory_alloc(msg_len);

        if(!element->msg.data) {
            nst_nosql_memory_free(element);
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

    if(ctx->rule->disk == NST_DISK_ONLY)  {
        char *data = b_orig(&msg->chn->buf);
        char *p    = ci_head(msg->chn);
        int size   = msg->chn->buf.size;

        if(p - data + msg_len > size) {
            int right = data + size - p;
            int left  = msg_len - right;

            nst_persist_write(&ctx->disk, p, right);
            nst_persist_write(&ctx->disk, data, left);
        } else {
            nst_persist_write(&ctx->disk, p, msg_len);
        }
        ctx->cache_len += msg_len;
    } else {
        struct nst_nosql_element *element;

        element = _nst_nosql_data_append(msg, msg_len);

        if(element) {

            if(ctx->element) {
                ctx->element->next = element;
            } else {
                ctx->data->element = element;
            }

            ctx->element = element;

            if(ctx->rule->disk == NST_DISK_SYNC) {
                nst_persist_write(&ctx->disk, element->msg.data,
                        element->msg.len);

                ctx->cache_len += element->msg.len;
            }

            return 1;
        } else {
            return 0;
        }
    }

    return 1;
}

int nst_nosql_exists(struct nst_nosql_ctx *ctx, int mode) {
    struct nst_nosql_entry *entry = NULL;
    int ret = NST_CACHE_CTX_STATE_INIT;

    if(!ctx->key) {
        return ret;
    }

    nst_shctx_lock(&nuster.nosql->dict[0]);
    entry = nst_nosql_dict_get(ctx->key, ctx->hash);

    if(entry) {
        if(entry->state == NST_NOSQL_ENTRY_STATE_VALID) {
            ctx->data = entry->data;
            ctx->data->clients++;
            ret = NST_NOSQL_CTX_STATE_HIT;
        }

        if(entry->state == NST_NOSQL_ENTRY_STATE_INVALID && entry->file) {
            ctx->disk.file = entry->file;
            ret = NST_NOSQL_CTX_STATE_CHECK_PERSIST;
        }
    } else {
        if(mode != NST_DISK_OFF) {
            ctx->disk.file = NULL;
            //if(nuster.nosql->disk.loaded) {
            //    ret = NST_NOSQL_CTX_STATE_INIT;
            //} else {
                ret = NST_NOSQL_CTX_STATE_CHECK_PERSIST;
            //}
        }
    }

    nst_shctx_unlock(&nuster.nosql->dict[0]);

    if(ret == NST_NOSQL_CTX_STATE_CHECK_PERSIST) {
        if(ctx->disk.file) {
            if(nst_persist_valid(&ctx->disk, ctx->key, ctx->hash) == NST_OK) {

                ret = NST_NOSQL_CTX_STATE_HIT_DISK;
            } else {
                ret = NST_NOSQL_CTX_STATE_INIT;
            }
        } else {
            ctx->disk.file =
                nst_nosql_memory_alloc(NST_PERSIST_PATH_FILE_LEN + 1);

            if(!ctx->disk.file) {
                ret = NST_NOSQL_CTX_STATE_INIT;
            }

            if(nst_persist_exists(&ctx->disk, ctx->key, ctx->hash,
                        global.nuster.nosql.directory) == NST_OK) {

                ret = NST_NOSQL_CTX_STATE_HIT_DISK;
            } else {
                nst_nosql_memory_free(ctx->disk.file);
                ret = NST_NOSQL_CTX_STATE_INIT;
            }
        }
    }

    return ret;
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

        if(ctx->rule->disk == NST_DISK_ONLY) {
            ctx->entry->state = NST_NOSQL_ENTRY_STATE_INVALID;
        } else {
            ctx->entry->state = NST_NOSQL_ENTRY_STATE_VALID;
        }


        if(*ctx->rule->ttl == 0) {
            ctx->entry->expire = 0;
        } else {
            ctx->entry->expire = get_current_timestamp() / 1000
                + *ctx->rule->ttl;
        }

        if(ctx->rule->disk == NST_DISK_SYNC
                || ctx->rule->disk == NST_DISK_ONLY) {

            nst_persist_meta_set_expire(ctx->disk.meta, ctx->entry->expire);

            nst_persist_meta_set_cache_len(ctx->disk.meta, ctx->cache_len);

            nst_persist_write_meta(&ctx->disk);

            ctx->entry->file = ctx->disk.file;
        }
    }
}

void nst_nosql_abort(struct nst_nosql_ctx *ctx) {
    ctx->entry->state = NST_NOSQL_ENTRY_STATE_INVALID;
}

void nst_nosql_persist_async() {
    struct nst_nosql_entry *entry =
        nuster.nosql->dict[0].entry[nuster.nosql->persist_idx];

    if(!nuster.nosql->dict[0].used) {
        return;
    }

    while(entry) {

        if(!nst_nosql_entry_invalid(entry)
                && entry->rule->disk == NST_DISK_ASYNC
                && entry->file == NULL) {

            struct nst_nosql_element *element = entry->data->element;
            uint64_t cache_len = 0;
            struct persist disk;

            entry->file = nst_nosql_memory_alloc(NST_PERSIST_PATH_FILE_LEN + 1);

            if(!entry->file) {
                return;
            }

            if(nst_persist_init(entry->file, entry->hash,
                        global.nuster.nosql.directory) != NST_OK) {
                return;
            }

            disk.fd = nst_persist_create(entry->file);

            /* write header */
            nst_res_begin(200);

            if(entry->data->info.flags
                    & NST_NOSQL_DATA_FLAG_CHUNKED) {

                nst_res_header(&nst_headers.transfer_encoding,
                        &entry->data->info.transfer_encoding);
            } else {
                nst_res_header_content_length(entry->data->info.content_length);

                if(entry->data->info.transfer_encoding.data) {

                    nst_res_header(&nst_headers.transfer_encoding,
                            &entry->data->info.transfer_encoding);
                }
            }

            if(entry->data->info.content_type.data) {
                nst_res_header(&nst_headers.content_type,
                        &entry->data->info.content_type);
            }

            nst_res_header_end();

            nst_persist_meta_init(disk.meta, (char)entry->rule->disk,
                    entry->hash, entry->expire, 0, trash.data,
                    entry->key->data);

            nst_persist_write_key(&disk, entry->key);

            disk.offset = NST_PERSIST_META_SIZE + entry->key->data;

            nst_persist_write(&disk, trash.area, trash.data);

            while(element) {

                if(element->msg.data) {
                    nst_persist_write(&disk, element->msg.data,
                            element->msg.len);

                    cache_len += element->msg.len;
                }

                element = element->next;
            }

            nst_persist_meta_set_cache_len(disk.meta, cache_len);

            nst_persist_write_meta(&disk);

            close(disk.fd);
        }

        entry = entry->next;

    }

    nuster.nosql->persist_idx++;

    /* if we have checked the whole dict */
    if(nuster.nosql->persist_idx == nuster.nosql->dict[0].size) {
        nuster.nosql->persist_idx = 0;
    }

}

void nst_nosql_persist_load() {

    if(global.nuster.nosql.directory && !nuster.nosql->disk.loaded) {
        char *file;
        char meta[NST_PERSIST_META_SIZE];
        struct buffer *key;
        int fd;

        file = nuster.nosql->disk.file;

        if(nuster.nosql->disk.dir) {
            struct dirent *de = nst_persist_dir_next(nuster.nosql->disk.dir);

            if(de) {
                DIR *dir2;
                struct dirent *de2;

                if(strcmp(de->d_name, ".") == 0
                        || strcmp(de->d_name, "..") == 0) {

                    return;
                }

                memcpy(file + NST_PERSIST_PATH_BASE_LEN, "/", 1);
                memcpy(file + NST_PERSIST_PATH_BASE_LEN + 1, de->d_name,
                        strlen(de->d_name));

                dir2 = opendir(file);

                if(!dir2) {
                    return;
                }

                while((de2 = readdir(dir2)) != NULL) {
                    if(strcmp(de2->d_name, ".") == 0
                            || strcmp(de2->d_name, "..") == 0) {

                        continue;
                    }

                    memcpy(file + NST_PERSIST_PATH_HASH_LEN, "/", 1);
                    memcpy(file + NST_PERSIST_PATH_HASH_LEN + 1, de2->d_name,
                            strlen(de2->d_name));

                    fd = nst_persist_open(file);

                    if(fd == -1) {
                        return;
                    }

                    if(nst_persist_get_meta(fd, meta) != NST_OK) {
                        unlink(file);
                        close(fd);
                        return;
                    }

                    key = nst_nosql_memory_alloc(sizeof(*key));

                    if(!key) {
                        return;
                    }

                    key->size = nst_persist_meta_get_key_len(meta);
                    key->area = nst_nosql_memory_alloc(key->size);

                    if(!key->area) {
                        nst_nosql_memory_free(key);
                        return;
                    }

                    if(nst_persist_get_key(fd, meta, key) != NST_OK) {
                        nst_nosql_memory_free(key->area);

                        nst_nosql_memory_free(key);

                        unlink(file);
                        close(fd);
                        return;
                    }

                    nst_nosql_dict_set_from_disk(file, meta, key);

                }
            } else {
                nuster.nosql->disk.idx++;
                closedir(nuster.nosql->disk.dir);
                nuster.nosql->disk.dir = NULL;
            }
        } else {
            nuster.nosql->disk.dir = nst_persist_opendir_by_idx(file,
                    nuster.nosql->disk.idx, global.nuster.nosql.directory);

            if(!nuster.nosql->disk.dir) {
                nuster.nosql->disk.idx++;
            }
        }

        if(nuster.nosql->disk.idx == 16 * 16) {
            nuster.nosql->disk.loaded = 1;
            nuster.nosql->disk.idx    = 0;
        }

    }
}

void nst_nosql_persist_cleanup() {

    if(global.nuster.nosql.directory && nuster.nosql->disk.loaded) {
        char *file = nuster.nosql->disk.file;

        if(nuster.nosql->disk.dir) {
            struct dirent *de = nst_persist_dir_next(nuster.nosql->disk.dir);

            if(de) {
                nst_persist_cleanup(file, de);
            } else {
                nuster.nosql->disk.idx++;
                closedir(nuster.nosql->disk.dir);
                nuster.nosql->disk.dir = NULL;
            }
        } else {
            nuster.nosql->disk.dir = nst_persist_opendir_by_idx(file,
                    nuster.nosql->disk.idx, global.nuster.nosql.directory);

            if(!nuster.nosql->disk.dir) {
                nuster.nosql->disk.idx++;
            }
        }

        if(nuster.nosql->disk.idx == 16 * 16) {
            nuster.nosql->disk.idx = 0;
        }

    }
}

/*
 * nuster nosql engine functions.
 *
 * Copyright (C) [Jiang Wenyuan](https://github.com/jiangwenyuan), < koubunen AT gmail DOT com >
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

#include <types/global.h>
#include <types/stream.h>
#include <types/channel.h>
#include <types/proxy.h>

#include <proto/stream_interface.h>
#include <proto/proto_http.h>
#include <proto/acl.h>
#include <proto/log.h>

/* TODO:
 * Copied from cache/engine.c with little adjustment
 * Move to common when nosql part is fixed
 * */

static const char HTTP_100[] =
"HTTP/1.1 100 Continue\r\n\r\n";

static struct chunk http_100_chunk = {
    .str = (char *)&HTTP_100,
    .len = sizeof(HTTP_100)-1
};

static void nst_nosql_engine_handler(struct appctx *appctx) {
    struct stream_interface *si = appctx->owner;
    struct stream *s            = si_strm(si);
    struct channel *res         = si_ic(si);
    int code                    = 200;
    struct nst_nosql_element *element = NULL;
    int ret;

    char *p = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

    switch(appctx->st0) {
        case NST_NOSQL_APPCTX_STATE_CREATE:
            co_skip(si_oc(si), si_ob(si)->o);
            task_wakeup(s->task, TASK_WOKEN_OTHER);
            break;
        case NST_NOSQL_APPCTX_STATE_HIT:
            if(appctx->st1 == 0) {
                chunk_printf(&trash,
                        "HTTP/1.1 200 OK\r\n");
                if(appctx->ctx.nuster.nosql_engine.data->info.flags & NST_NOSQL_DATA_FLAG_CHUNKED) {
                    chunk_appendf(&trash, "Transfer-Encoding: %.*s\r\n",
                            appctx->ctx.nuster.nosql_engine.data->info.transfer_encoding.len,
                            appctx->ctx.nuster.nosql_engine.data->info.transfer_encoding.data);
                } else {
                    chunk_appendf(&trash,
                            "Content-Length: %"PRIu64"\r\n",
                            appctx->ctx.nuster.nosql_engine.data->info.content_length);
                    if(appctx->ctx.nuster.nosql_engine.data->info.transfer_encoding.data) {
                        chunk_appendf(&trash, "Transfer-Encoding: %.*s\r\n",
                                appctx->ctx.nuster.nosql_engine.data->info.transfer_encoding.len,
                                appctx->ctx.nuster.nosql_engine.data->info.transfer_encoding.data);
                    }
                }
                if(appctx->ctx.nuster.nosql_engine.data->info.content_type.data) {
                    chunk_appendf(&trash, "Content-Type: %.*s\r\n",
                            appctx->ctx.nuster.nosql_engine.data->info.content_type.len,
                            appctx->ctx.nuster.nosql_engine.data->info.content_type.data);
                }
                chunk_appendf(&trash, "\r\n");
                ci_putchk(si_ic(si), &trash);
                appctx->st1++;
            } else {
                if(appctx->ctx.nuster.nosql_engine.element) {
                    element = appctx->ctx.nuster.nosql_engine.element;

                    ret = ci_putblk(res, element->msg.data, element->msg.len);
                    if(ret >= 0) {
                        appctx->ctx.nuster.nosql_engine.element = element->next;
                    } else if(ret == -2) {
                        appctx->ctx.nuster.nosql_engine.data->clients--;
                        si_shutr(si);
                        res->flags |= CF_READ_NULL;
                    }
                } else {
                    appctx->st0 = NST_NOSQL_APPCTX_STATE_DONE;
                    co_skip(si_oc(si), si_ob(si)->o);
                    si_shutr(si);
                    res->flags |= CF_READ_NULL;
                    appctx->ctx.nuster.nosql_engine.data->clients--;
                }
            }
            task_wakeup(s->task, TASK_WOKEN_OTHER);

            break;
        case NST_NOSQL_APPCTX_STATE_ERROR:
            appctx->st0 = NST_NOSQL_APPCTX_STATE_DONE;
            code = NUSTER_HTTP_500;
            goto abort;
            break;
        case NST_NOSQL_APPCTX_STATE_NOT_ALLOWED:
            appctx->st0 = NST_NOSQL_APPCTX_STATE_DONE;
            code = NUSTER_HTTP_405;
            goto abort;
            break;
        case NST_NOSQL_APPCTX_STATE_NOT_FOUND:
            code = NUSTER_HTTP_404;
            goto abort;
            break;
        case NST_NOSQL_APPCTX_STATE_EMPTY:
            code = NUSTER_HTTP_400;
            goto abort;
            break;
        case NST_NOSQL_APPCTX_STATE_FULL:
            code = NUSTER_HTTP_507;
            goto abort;
            break;
        case NST_NOSQL_APPCTX_STATE_END:
            appctx->st0 = NST_NOSQL_APPCTX_STATE_DONE;
            code = NUSTER_HTTP_200;
            ci_putblk(res, p, strlen(p));
            co_skip(si_oc(si), si_ob(si)->o);
            si_shutr(si);
            res->flags |= CF_READ_NULL;
            break;
        case NST_NOSQL_APPCTX_STATE_WAIT:
            break;
        case NST_NOSQL_APPCTX_STATE_DONE:
            break;
        default:
            co_skip(si_oc(si), si_ob(si)->o);
            break;
    }

    return;

abort:
    channel_abort(&s->req);
    channel_abort(&s->res);
    nuster_response(s, &nuster_http_msg_chunks[code]);
}

struct nst_nosql_data *nst_nosql_data_new() {

    struct nst_nosql_data *data = nuster_memory_alloc(global.nuster.nosql.memory, sizeof(*data));

    nuster_shctx_lock(nuster.nosql);
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
    nuster_shctx_unlock(nuster.nosql);
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

            nst_nosql_stats_update_used_mem(-tmp->msg.len);
            nuster_memory_free(global.nuster.nosql.memory, tmp->msg.data);
            nuster_memory_free(global.nuster.nosql.memory, tmp);
        }

        if(data->info.content_type.data) {
            nuster_memory_free(global.nuster.nosql.memory, data->info.content_type.data);
        }
        if(data->info.transfer_encoding.data) {
            nuster_memory_free(global.nuster.nosql.memory, data->info.transfer_encoding.data);
        }
        nuster_memory_free(global.nuster.nosql.memory, data);
    }
}

void nst_nosql_housekeeping() {
    if(global.nuster.nosql.status == NUSTER_STATUS_ON) {
        nuster_shctx_lock(&nuster.nosql->dict[0]);
        nst_nosql_dict_cleanup();
        nuster_shctx_unlock(&nuster.nosql->dict[0]);
        nuster_shctx_lock(nuster.nosql);
        _nst_nosql_data_cleanup();
        nuster_shctx_unlock(nuster.nosql);
    }
}

void nst_nosql_init() {
    nuster.applet.nosql_engine.fct = nst_nosql_engine_handler;

    if(global.nuster.nosql.status == NUSTER_STATUS_ON) {
        global.nuster.nosql.pool.ctx   = create_pool("np.ctx", sizeof(struct nst_nosql_ctx), MEM_F_SHARED);
        global.nuster.nosql.memory = nuster_memory_create("nosql.shm", global.nuster.nosql.data_size, global.tune.bufsize, NST_NOSQL_DEFAULT_CHUNK_SIZE);
        if(!global.nuster.nosql.memory) {
            goto shm_err;
        }
        if(!nuster_shctx_init(global.nuster.nosql.memory)) {
            goto shm_err;
        }
        nuster.nosql = nuster_memory_alloc(global.nuster.nosql.memory, sizeof(struct nst_nosql));
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

        if(!nuster_shctx_init(nuster.nosql)) {
            goto shm_err;
        }

        if(!nst_nosql_dict_init()) {
            goto err;
        }

        if(!nst_nosql_stats_init()) {
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
int nst_nosql_check_applet(struct stream *s, struct channel *req, struct proxy *px) {
    if(global.nuster.nosql.status == NUSTER_STATUS_ON && px->nuster.mode == NUSTER_MODE_NOSQL) {
        struct stream_interface *si = &s->si[1];
        struct http_txn *txn        = s->txn;
        struct http_msg *msg        = &txn->req;
        struct appctx *appctx       = NULL;

        s->target = &nuster.applet.nosql_engine.obj_type;
        if(unlikely(!stream_int_register_handler(si, objt_applet(s->target)))) {
            txn->status = 500;
            nuster_response(s, &nuster_http_msg_chunks[NUSTER_HTTP_500]);
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
                        if(http_find_header2("Expect", 6, req->buf->p, &txn->hdr_idx, &ctx) &&
                                unlikely(ctx.vlen == 12 && strncasecmp(ctx.line+ctx.val, "100-continue", 12) == 0)) {
                            co_inject(&s->res, http_100_chunk.str, http_100_chunk.len);
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

            req->analysers &= (AN_REQ_HTTP_BODY | AN_REQ_FLT_HTTP_HDRS | AN_REQ_FLT_END);
            req->analysers &= ~AN_REQ_FLT_XFER_DATA;
            req->analysers |= AN_REQ_HTTP_XFER_BODY;

        }
    }
    return 0;
}

static char *_string_append(char *dst, int *dst_len, int *dst_size,
        char *src, int src_len) {

    int left     = *dst_size - *dst_len;
    int need     = src_len + 1;
    int old_size = *dst_size;

    if(left < need) {
        *dst_size += ((need - left) / NST_NOSQL_DEFAULT_KEY_SIZE + 1)  * NST_NOSQL_DEFAULT_KEY_SIZE;
    }

    if(old_size != *dst_size) {
        char *new_dst = realloc(dst, *dst_size);
        if(!new_dst) {
            free(dst);
            return NULL;
        }
        dst = new_dst;
    }

    memcpy(dst + *dst_len, src, src_len);
    *dst_len += src_len;
    dst[*dst_len] = '\0';
    return dst;
}

static char *_nst_nosql_key_append(char *dst, int *dst_len, int *dst_size,
        char *src, int src_len) {
    char *key = _string_append(dst, dst_len, dst_size, src, src_len);
    if(key) {
        return _string_append(key, dst_len, dst_size, ".", 1);
    }
    return NULL;
}

int nst_nosql_prebuild_key(struct nst_nosql_ctx *ctx, struct stream *s, struct http_msg *msg) {

    struct http_txn *txn = s->txn;

    char *url_end;
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
    if(http_find_header2("Host", 4, msg->chn->buf->p, &txn->hdr_idx, &hdr)) {
        ctx->req.host.data = nuster_memory_alloc(global.nuster.nosql.memory, hdr.vlen);
        if(!ctx->req.host.data) {
            return 0;
        }
        ctx->req.host.len  = hdr.vlen;
        memcpy(ctx->req.host.data, hdr.line + hdr.val, hdr.vlen);
    }

    ctx->req.path.data = http_get_path(txn);
    ctx->req.path.len  = 0;
    ctx->req.uri.data  = ctx->req.path.data;
    ctx->req.uri.len   = 0;
    url_end            = NULL;
    if(ctx->req.path.data) {
        char *ptr = ctx->req.path.data;
        url_end   = msg->chn->buf->p + msg->sl.rq.u + msg->sl.rq.u_l;
        while(ptr < url_end && *ptr != '?') {
            ptr++;
        }
        ctx->req.path.len = ptr - ctx->req.path.data;
        ctx->req.uri.len  = url_end - ctx->req.uri.data;
    }
    /* extra 1 char as required by regex_exec_match2 */
    ctx->req.path.data = nuster_memory_alloc(global.nuster.nosql.memory, ctx->req.path.len + 1);
    if(!ctx->req.path.data) {
        return 0;
    }
    memcpy(ctx->req.path.data, ctx->req.uri.data, ctx->req.path.len);

    ctx->req.query.data = NULL;
    ctx->req.query.len  = 0;
    ctx->req.delimiter  = 0;
    if(ctx->req.uri.data) {
        ctx->req.query.data = memchr(ctx->req.uri.data, '?', url_end - ctx->req.uri.data);
        if(ctx->req.query.data) {
            ctx->req.query.data++;
            ctx->req.query.len = url_end - ctx->req.query.data;
            if(ctx->req.query.len) {
                ctx->req.delimiter = 1;
            }
        }
    }

    ctx->req.cookie.data = NULL;
    ctx->req.cookie.len  = 0;
    hdr.idx              = 0;
    if(http_find_header2("Cookie", 6, msg->chn->buf->p, &txn->hdr_idx, &hdr)) {
        ctx->req.cookie.data = hdr.line + hdr.val;
        ctx->req.cookie.len  = hdr.vlen;
    }

    ctx->req.transfer_encoding.data = NULL;
    ctx->req.transfer_encoding.len  = 0;
    ctx->req.content_type.data      = NULL;
    ctx->req.content_type.len       = 0;

    return 1;
}

char *nst_nosql_build_key(struct nst_nosql_ctx *ctx, struct nuster_rule_key **pck, struct stream *s,
        struct http_msg *msg) {

    struct http_txn *txn = s->txn;

    struct hdr_ctx hdr;

    struct nuster_rule_key *ck = NULL;
    int key_len                = 0;
    int key_size               = NST_NOSQL_DEFAULT_KEY_SIZE;
    char *key                  = malloc(key_size);
    if(!key) {
        return NULL;
    }

    nuster_debug("[NOSQL] Calculate key: ");
    while((ck = *pck++)) {
        switch(ck->type) {
            case NUSTER_RULE_KEY_METHOD:
                nuster_debug("method.");
                key = _nst_nosql_key_append(key, &key_len, &key_size, http_known_methods[HTTP_METH_GET].name, strlen(http_known_methods[HTTP_METH_GET].name));
                break;
            case NUSTER_RULE_KEY_SCHEME:
                nuster_debug("scheme.");
                key = _nst_nosql_key_append(key, &key_len, &key_size, ctx->req.scheme == SCH_HTTPS ? "HTTPS" : "HTTP", ctx->req.scheme == SCH_HTTPS ? 5 : 4);
                break;
            case NUSTER_RULE_KEY_HOST:
                nuster_debug("host.");
                if(ctx->req.host.data) {
                    key = _nst_nosql_key_append(key, &key_len, &key_size, ctx->req.host.data, ctx->req.host.len);
                }
                break;
            case NUSTER_RULE_KEY_URI:
                nuster_debug("uri.");
                if(ctx->req.uri.data) {
                    key = _nst_nosql_key_append(key, &key_len, &key_size, ctx->req.uri.data, ctx->req.uri.len);
                }
                break;
            case NUSTER_RULE_KEY_PATH:
                nuster_debug("path.");
                if(ctx->req.path.data) {
                    key = _nst_nosql_key_append(key, &key_len, &key_size, ctx->req.path.data, ctx->req.path.len);
                }
                break;
            case NUSTER_RULE_KEY_DELIMITER:
                nuster_debug("delimiter.");
                key = _nst_nosql_key_append(key, &key_len, &key_size, ctx->req.delimiter ? "?": "", ctx->req.delimiter);
                break;
            case NUSTER_RULE_KEY_QUERY:
                nuster_debug("query.");
                if(ctx->req.query.data && ctx->req.query.len) {
                    key = _nst_nosql_key_append(key, &key_len, &key_size, ctx->req.query.data, ctx->req.query.len);
                }
                break;
            case NUSTER_RULE_KEY_PARAM:
                nuster_debug("param_%s.", ck->data);
                if(ctx->req.query.data && ctx->req.query.len) {
                    char *v = NULL;
                    int v_l = 0;
                    if(nuster_fetch_query_param(ctx->req.query.data, ctx->req.query.data + ctx->req.query.len, ck->data, &v, &v_l)) {
                        key = _nst_nosql_key_append(key, &key_len, &key_size, v, v_l);
                    }

                }
                break;
            case NUSTER_RULE_KEY_HEADER:
                hdr.idx = 0;
                nuster_debug("header_%s.", ck->data);
                if(http_find_header2(ck->data, strlen(ck->data), msg->chn->buf->p, &txn->hdr_idx, &hdr)) {
                    key = _nst_nosql_key_append(key, &key_len, &key_size, hdr.line + hdr.val, hdr.vlen);
                }
                break;
            case NUSTER_RULE_KEY_COOKIE:
                nuster_debug("header_%s.", ck->data);
                if(ctx->req.cookie.data) {
                    char *v = NULL;
                    int v_l = 0;
                    if(extract_cookie_value(ctx->req.cookie.data, ctx->req.cookie.data + ctx->req.cookie.len, ck->data, strlen(ck->data), 1, &v, &v_l)) {
                        key = _nst_nosql_key_append(key, &key_len, &key_size, v, v_l);
                    }
                }
                break;
            case NUSTER_RULE_KEY_BODY:
                nuster_debug("body.");
                if(txn->meth == HTTP_METH_POST || txn->meth == HTTP_METH_PUT) {
                    if((s->be->options & PR_O_WREQ_BODY) && msg->body_len > 0 ) {
                        key = _nst_nosql_key_append(key, &key_len, &key_size, msg->chn->buf->p + msg->sov, msg->body_len);
                    }
                }
                break;
            default:
                break;
        }
        if(!key) return NULL;
    }
    nuster_debug("\n");
    return key;
}

void nst_nosql_hit(struct stream *s, struct stream_interface *si, struct channel *req,
        struct channel *res, struct nst_nosql_data *data) {
}

int nst_nosql_get_headers(struct nst_nosql_ctx *ctx, struct stream *s, struct http_msg *msg) {
    struct http_txn *txn = s->txn;
    struct hdr_ctx hdr;

    hdr.idx = 0;
    if(http_find_header2("Content-Type", 12, msg->chn->buf->p, &txn->hdr_idx, &hdr)) {
        ctx->req.content_type.data = nuster_memory_alloc(global.nuster.nosql.memory, hdr.vlen);
        if(!ctx->req.content_type.data) {
            return 0;
        }
        ctx->req.content_type.len = hdr.vlen;
        memcpy(ctx->req.content_type.data, hdr.line + hdr.val, hdr.vlen);
    }

    hdr.idx = 0;
    while (http_find_header2("Transfer-Encoding", 17, msg->chn->buf->p, &txn->hdr_idx, &hdr)) {
        char *p = ctx->req.transfer_encoding.data;
        int len = p ? ctx->req.transfer_encoding.len + hdr.vlen + 1 : ctx->req.transfer_encoding.len + hdr.vlen;

        ctx->req.transfer_encoding.data = nuster_memory_alloc(global.nuster.nosql.memory, len);
        if(!ctx->req.transfer_encoding.data) {
            if(p) nuster_memory_free(global.nuster.nosql.memory, p);
            return 0;
        }
        if(p) {
            memcpy(ctx->req.transfer_encoding.data, p, ctx->req.transfer_encoding.len);
            ctx->req.transfer_encoding.data[ctx->req.transfer_encoding.len] = ',';
            nuster_memory_free(global.nuster.nosql.memory, p);
            memcpy(ctx->req.transfer_encoding.data + ctx->req.transfer_encoding.len + 1, hdr.line + hdr.val, hdr.vlen);
        } else {
            memcpy(ctx->req.transfer_encoding.data, hdr.line + hdr.val, hdr.vlen);
        }
        ctx->req.transfer_encoding.len = len;
    }
    return 1;
}

void nst_nosql_create(struct nst_nosql_ctx *ctx, char *key, uint64_t hash,
        struct stream *s, struct http_msg *msg) {
    struct nst_nosql_entry *entry = NULL;

    /* Check if nosql is full */
    if(nst_nosql_stats_full()) {
        ctx->state = NST_NOSQL_CTX_STATE_FULL;
        return;
    }

    nuster_shctx_lock(&nuster.nosql->dict[0]);
    entry = nst_nosql_dict_get(key, hash);
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
        entry = nst_nosql_dict_set(key, hash, ctx);
    }
    nuster_shctx_unlock(&nuster.nosql->dict[0]);

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

static struct nst_nosql_element *_nst_nosql_data_append(struct nst_nosql_element *tail,
        struct http_msg *msg, long msg_len) {

    struct nst_nosql_element *element = nuster_memory_alloc(global.nuster.nosql.memory, sizeof(*element));

    if(element) {
        char *data = msg->chn->buf->data;
        char *p    = msg->chn->buf->p;
        int size   = msg->chn->buf->size;

        element->msg.data = nuster_memory_alloc(global.nuster.nosql.memory, msg_len);
        if(!element->msg.data) return NULL;

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
        if(tail == NULL) {
            tail = element;
        } else {
            tail->next = element;
        }
        nst_nosql_stats_update_used_mem(msg_len);
    }
    return element;
}

int nst_nosql_update(struct nst_nosql_ctx *ctx, struct http_msg *msg, long msg_len) {
    struct nst_nosql_element *element = _nst_nosql_data_append(ctx->element, msg, msg_len);

    if(element) {
        if(!ctx->element) {
            ctx->data->element = element;
        }
        ctx->element = element;
        return 1;
    } else {
        return 0;
    }
}

struct nst_nosql_data *nst_nosql_exists(const char *key, uint64_t hash) {
    struct nst_nosql_entry *entry = NULL;
    struct nst_nosql_data  *data  = NULL;

    if(!key) return NULL;

    nuster_shctx_lock(&nuster.nosql->dict[0]);
    entry = nst_nosql_dict_get(key, hash);
    if(entry && entry->state == NST_NOSQL_ENTRY_STATE_VALID) {
        data = entry->data;
        data->clients++;
    }
    nuster_shctx_unlock(&nuster.nosql->dict[0]);

    return data;
}

int nst_nosql_delete(const char *key, uint64_t hash) {
    struct nst_nosql_entry *entry = NULL;
    int ret = 0;

    if(!key) return 0;

    nuster_shctx_lock(&nuster.nosql->dict[0]);
    entry = nst_nosql_dict_get(key, hash);
    if(entry) {
        entry->state = NST_NOSQL_ENTRY_STATE_INVALID;
        ret = 1;
    }
    nuster_shctx_unlock(&nuster.nosql->dict[0]);

    return ret;
}

void nst_nosql_finish(struct nst_nosql_ctx *ctx, struct http_msg *msg) {
    if(msg->body_len == 0) {
        ctx->state = NST_NOSQL_CTX_STATE_INVALID;
        ctx->entry->state = NST_NOSQL_ENTRY_STATE_INVALID;
    } else {
        if(ctx->req.content_type.data) {
            ctx->entry->data->info.content_type.data = ctx->req.content_type.data;
            ctx->entry->data->info.content_type.len  = ctx->req.content_type.len;
            ctx->req.content_type.data = NULL;
        }
        if(ctx->req.transfer_encoding.data) {
            ctx->entry->data->info.transfer_encoding.data = ctx->req.transfer_encoding.data;
            ctx->entry->data->info.transfer_encoding.len  = ctx->req.transfer_encoding.len;
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
            ctx->entry->expire = get_current_timestamp() / 1000 + *ctx->rule->ttl;
        }
    }
}

void nst_nosql_abort(struct nst_nosql_ctx *ctx) {
    ctx->entry->state = NST_NOSQL_ENTRY_STATE_INVALID;
}


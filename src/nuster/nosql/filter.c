/*
 * nuster nosql filter related variables and functions.
 *
 * Copyright (C) Jiang Wenyuan, < koubunen AT gmail DOT com >
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
#include <proto/http_ana.h>
#include <proto/stream_interface.h>

#include <nuster/memory.h>
#include <nuster/nuster.h>
#include <nuster/nosql.h>

static int _nst_nosql_filter_init(struct proxy *px, struct flt_conf *fconf) {
    fconf->flags |= FLT_CFG_FL_HTX;
    return 0;
}

static void _nst_nosql_filter_deinit(struct proxy *px, struct flt_conf *fconf) {
}

static int _nst_nosql_filter_check(struct proxy *px, struct flt_conf *fconf) {
    struct proxy *p;

    if(px->mode != PR_MODE_HTTP) {
        ha_warning("Proxy [%s]: mode should be http to enable nosql\n", px->id);
    }

    for (p = proxies_list; p; p = p->next) {

        if(p->nuster.mode == px->nuster.mode) {

            if((px->options2 & PR_O2_USE_HTX)
                    != (p->options2 & PR_O2_USE_HTX)) {

                ha_alert("nuster nosql: either use HTX or no HTX.\n");

                return 1;
            }
        }
    }

    return 0;
}

static int _nst_nosql_filter_attach(struct stream *s, struct filter *filter) {

    if(global.nuster.nosql.status != NST_STATUS_ON) {
        return 0;
    }

    if(!filter->ctx) {
        struct nst_nosql_ctx *ctx = pool_alloc(global.nuster.nosql.pool.ctx);

        if(ctx == NULL ) {
            return 0;
        }

        memset(ctx, 0, sizeof(*ctx));

        ctx->state = NST_NOSQL_CTX_STATE_INIT;
        ctx->pid   = -1;

        filter->ctx = ctx;
    }

    register_data_filter(s, &s->req, filter);
    //register_data_filter(s, &s->res, filter);
    return 1;
}

static void _nst_nosql_filter_detach(struct stream *s, struct filter *filter) {

    if(filter->ctx) {
        struct nst_nosql_ctx *ctx = filter->ctx;

        if(ctx->state == NST_NOSQL_CTX_STATE_CREATE) {
            nst_nosql_abort(ctx);
        }

        if(ctx->req.host.data) {
            nst_nosql_memory_free(ctx->req.host.data);
        }

        if(ctx->req.path.data) {
            nst_nosql_memory_free(ctx->req.path.data);
        }

        if(ctx->req.content_type.data) {
            nst_nosql_memory_free(ctx->req.content_type.data);
        }

        if(ctx->req.transfer_encoding.data) {
            nst_nosql_memory_free(ctx->req.transfer_encoding.data);
        }

        if(ctx->key) {
            nst_nosql_memory_free(ctx->key->area);
            nst_nosql_memory_free(ctx->key);
        }

        pool_free(global.nuster.nosql.pool.ctx, ctx);
    }
}

static int _nst_nosql_filter_http_headers1(struct stream *s,
        struct filter *filter, struct http_msg *msg) {

    struct stream_interface *si = &s->si[1];
    struct nst_nosql_ctx *ctx   = filter->ctx;
    struct nst_rule *rule       = NULL;
    struct proxy *px            = s->be;
    struct appctx *appctx       = si_appctx(si);
    struct channel *req         = msg->chn;
    struct channel *res         = &s->res;

    if((msg->chn->flags & CF_ISRESP)) {
        return 1;
    }

    if(s->txn->meth != HTTP_METH_GET &&
            s->txn->meth != HTTP_METH_POST &&
            s->txn->meth != HTTP_METH_DELETE) {

        appctx->st0 = NST_NOSQL_APPCTX_STATE_NOT_ALLOWED;
        return 1;
    }

    if(ctx->state == NST_NOSQL_CTX_STATE_INIT) {

        if(!nst_nosql_prebuild_key(ctx, s, msg)) {
            appctx->st0 = NST_NOSQL_APPCTX_STATE_ERROR;
            return 1;
        }

        list_for_each_entry(rule, &px->nuster.rules, list) {
            nst_debug("[nuster][nosql] Checking rule: %s\n", rule->name);

            /* build key */
            if(ctx->key) {
                nst_nosql_memory_free(ctx->key);
            }

            if(nst_nosql_build_key(ctx, rule->key, s, msg) != NST_OK) {
                appctx->st0 = NST_NOSQL_APPCTX_STATE_ERROR;
                return 1;
            }

            nst_debug("[nuster][nosql] Key: ");
            nst_debug_key(ctx->key);

            ctx->hash = nst_hash(ctx->key->area, ctx->key->data);

            nst_debug("[nuster][nosql] Hash: %"PRIu64"\n", ctx->hash);

            if(s->txn->meth == HTTP_METH_GET) {
                nst_debug("[nuster][nosql] Checking key existence: ");

                ctx->state = nst_nosql_exists(ctx, rule->disk);

                if(ctx->state == NST_NOSQL_CTX_STATE_HIT) {
                    nst_debug("EXIST\n[nuster][nosql] Hit memory\n");
                    /* OK, nosql exists */
                    break;
                }

                if(ctx->state == NST_NOSQL_CTX_STATE_HIT_DISK) {
                    nst_debug("EXIST\n[nuster][nosql] Hit disk\n");
                    /* OK, cache exists */
                    break;
                }

                nst_debug("NOT EXIST\n");
            } else if(s->txn->meth == HTTP_METH_POST) {
                nst_debug("[nuster][nosql] Checking if rule pass: ");

                if(nst_test_rule(rule, s, msg->chn->flags & CF_ISRESP) ==
                        NST_OK) {

                    nst_debug("PASS\n[nuster][nosql] To create\n");

                    if(nst_nosql_get_headers(ctx, s, msg)) {
                        ctx->state = NST_NOSQL_CTX_STATE_PASS;
                        ctx->rule  = rule;
                        ctx->pid   = px->uuid;
                    } else {
                        ctx->state = NST_NOSQL_CTX_STATE_INVALID;
                    }

                    break;
                }

                nst_debug("FAIL\n");
            } else if(s->txn->meth == HTTP_METH_DELETE) {

                if(nst_nosql_delete(ctx->key, ctx->hash)) {
                    nst_debug("[nuster][nosql] EXIST, to delete\n");
                    ctx->state = NST_NOSQL_CTX_STATE_DELETE;
                    break;
                }

                nst_debug("[nuster][nosql] NOT EXIST\n");
            }
        }
    }

    /* ctx->state should have been changed in previous stage,
     * if not, either the key does not exist for GET/DELETE
     * or all rules do not pass for POST request
     * */
    if(ctx->state == NST_NOSQL_CTX_STATE_INIT) {
        appctx->st0 = NST_NOSQL_APPCTX_STATE_NOT_FOUND;
        return 1;
    }

    if(ctx->state == NST_NOSQL_CTX_STATE_HIT) {
        appctx->st0 = NST_NOSQL_APPCTX_STATE_HIT;
        appctx->st1 = 0; /* 0: header unsent, 1: sent */
        appctx->ctx.nuster.nosql_engine.data = ctx->data;
        appctx->ctx.nuster.nosql_engine.element = ctx->data->element;

        req->analysers &= ~AN_REQ_FLT_HTTP_HDRS;
        req->analysers &= ~AN_REQ_FLT_XFER_DATA;

        req->analysers |= AN_REQ_FLT_END;
        req->analyse_exp = TICK_ETERNITY;

        res->flags |= CF_NEVER_WAIT;
    }

    if(ctx->state == NST_NOSQL_CTX_STATE_HIT_DISK) {
        appctx->ctx.nuster.nosql_engine.fd = ctx->disk.fd;
        appctx->ctx.nuster.nosql_engine.offset =
            nst_persist_get_header_pos(ctx->disk.meta);

        appctx->ctx.nuster.nosql_engine.header_len =
            nst_persist_meta_get_header_len(ctx->disk.meta);

        appctx->st0 = NST_NOSQL_APPCTX_STATE_HIT_DISK;
        appctx->st1 = NST_PERSIST_APPLET_HEADER;

        req->analysers &= ~AN_REQ_FLT_HTTP_HDRS;
        req->analysers &= ~AN_REQ_FLT_XFER_DATA;

        req->analysers |= AN_REQ_FLT_END;
        req->analyse_exp = TICK_ETERNITY;

        res->flags |= CF_NEVER_WAIT;
    }

    if(ctx->state == NST_NOSQL_CTX_STATE_PASS) {
        appctx->st0 = NST_NOSQL_APPCTX_STATE_CREATE;
        appctx->st1 = msg->sov;
        nst_nosql_create(ctx, s, msg);
    }

    if(ctx->state == NST_NOSQL_CTX_STATE_WAIT) {
        ctx->state  = NST_NOSQL_CTX_STATE_PASS;
        appctx->st0 = NST_NOSQL_APPCTX_STATE_WAIT;
        return 0;
    }

    if(ctx->state == NST_NOSQL_CTX_STATE_INVALID
            && ctx->disk.file == NULL) {
        appctx->st0 = NST_NOSQL_APPCTX_STATE_ERROR;
    }

    if(ctx->state == NST_NOSQL_CTX_STATE_DELETE) {
        appctx->st0 = NST_NOSQL_APPCTX_STATE_END;
    }

    if(ctx->state == NST_NOSQL_CTX_STATE_FULL) {
        appctx->st0 = NST_NOSQL_APPCTX_STATE_FULL;
    }

    return 1;
}

static int _nst_nosql_filter_http_headers2(struct stream *s,
        struct filter *filter, struct http_msg *msg) {

    struct stream_interface *si = &s->si[1];
    struct nst_nosql_ctx *ctx   = filter->ctx;
    struct nst_rule *rule       = NULL;
    struct proxy *px            = s->be;
    struct appctx *appctx       = si_appctx(si);
    struct channel *req         = msg->chn;
    struct channel *res         = &s->res;

    if((msg->chn->flags & CF_ISRESP)) {
        return 1;
    }

    if(s->txn->meth != HTTP_METH_GET &&
            s->txn->meth != HTTP_METH_POST &&
            s->txn->meth != HTTP_METH_DELETE) {

        appctx->st0 = NST_NOSQL_APPCTX_STATE_NOT_ALLOWED;
        return 1;
    }

    if(ctx->state == NST_NOSQL_CTX_STATE_INIT) {

        if(!nst_nosql_prebuild_key2(ctx, s, msg)) {
            appctx->st0 = NST_NOSQL_APPCTX_STATE_ERROR;
            return 1;
        }

        list_for_each_entry(rule, &px->nuster.rules, list) {
            nst_debug("[nuster][nosql] Checking rule: %s\n", rule->name);

            /* build key */
            if(ctx->key) {
                nst_nosql_memory_free(ctx->key);
            }

            if(nst_nosql_build_key2(ctx, rule->key, s, msg) != NST_OK) {
                appctx->st0 = NST_NOSQL_APPCTX_STATE_ERROR;
                return 1;
            }

            nst_debug("[nuster][nosql] Key: ");
            nst_debug_key(ctx->key);

            ctx->hash = nst_hash(ctx->key->area, ctx->key->data);

            nst_debug("[nuster][nosql] Hash: %"PRIu64"\n", ctx->hash);

            if(s->txn->meth == HTTP_METH_GET) {
                nst_debug("[nuster][nosql] Checking key existence: ");

                ctx->state = nst_nosql_exists(ctx, rule->disk);

                if(ctx->state == NST_NOSQL_CTX_STATE_HIT) {
                    nst_debug("EXIST\n[nuster][nosql] Hit memory\n");
                    /* OK, nosql exists */
                    break;
                }

                if(ctx->state == NST_NOSQL_CTX_STATE_HIT_DISK) {
                    nst_debug("EXIST\n[nuster][nosql] Hit disk\n");
                    /* OK, cache exists */
                    break;
                }

                nst_debug("NOT EXIST\n");
            } else if(s->txn->meth == HTTP_METH_POST) {
                nst_debug("[nuster][nosql] Checking if rule pass: ");

                if(nst_test_rule(rule, s, msg->chn->flags & CF_ISRESP) ==
                        NST_OK) {

                    nst_debug("PASS\n[nuster][nosql] To create\n");

                    if(nst_nosql_get_headers2(ctx, s, msg)) {
                        ctx->state = NST_NOSQL_CTX_STATE_PASS;
                        ctx->rule  = rule;
                        ctx->pid   = px->uuid;
                    } else {
                        ctx->state = NST_NOSQL_CTX_STATE_INVALID;
                    }

                    break;
                }

                nst_debug("FAIL\n");
            } else if(s->txn->meth == HTTP_METH_DELETE) {

                if(nst_nosql_delete(ctx->key, ctx->hash)) {
                    nst_debug("[nuster][nosql] EXIST, to delete\n");
                    ctx->state = NST_NOSQL_CTX_STATE_DELETE;
                    break;
                }

                nst_debug("[nuster][nosql] NOT EXIST\n");
            }
        }
    }

    /* ctx->state should have been changed in previous stage,
     * if not, either the key does not exist for GET/DELETE
     * or all rules do not pass for POST request
     * */
    if(ctx->state == NST_NOSQL_CTX_STATE_INIT) {
        appctx->st0 = NST_NOSQL_APPCTX_STATE_NOT_FOUND;
        return 1;
    }

    if(ctx->state == NST_NOSQL_CTX_STATE_HIT) {
        appctx->st0 = NST_NOSQL_APPCTX_STATE_HIT;
        appctx->st1 = 0; /* 0: header unsent, 1: sent */
        appctx->ctx.nuster.nosql_engine.data = ctx->data;
        appctx->ctx.nuster.nosql_engine.element = ctx->data->element;

        req->analysers &= ~AN_REQ_FLT_HTTP_HDRS;
        req->analysers &= ~AN_REQ_FLT_XFER_DATA;

        req->analysers |= AN_REQ_FLT_END;
        req->analyse_exp = TICK_ETERNITY;

        res->flags |= CF_NEVER_WAIT;
    }

    if(ctx->state == NST_NOSQL_CTX_STATE_HIT_DISK) {
        appctx->ctx.nuster.nosql_engine.fd = ctx->disk.fd;
        appctx->ctx.nuster.nosql_engine.offset =
            nst_persist_get_header_pos(ctx->disk.meta);

        appctx->ctx.nuster.nosql_engine.header_len =
            nst_persist_meta_get_header_len(ctx->disk.meta);

        appctx->st0 = NST_NOSQL_APPCTX_STATE_HIT_DISK;
        appctx->st1 = NST_PERSIST_APPLET_HEADER;

        req->analysers &= ~AN_REQ_FLT_HTTP_HDRS;
        req->analysers &= ~AN_REQ_FLT_XFER_DATA;

        req->analysers |= AN_REQ_FLT_END;
        req->analyse_exp = TICK_ETERNITY;

        res->flags |= CF_NEVER_WAIT;
    }

    if(ctx->state == NST_NOSQL_CTX_STATE_PASS) {
        appctx->st0 = NST_NOSQL_APPCTX_STATE_CREATE;
        appctx->st1 = msg->sov;
        nst_nosql_create2(ctx, s, msg);
    }

    if(ctx->state == NST_NOSQL_CTX_STATE_WAIT) {
        ctx->state  = NST_NOSQL_CTX_STATE_PASS;
        appctx->st0 = NST_NOSQL_APPCTX_STATE_WAIT;
        return 0;
    }

    if(ctx->state == NST_NOSQL_CTX_STATE_INVALID
            && ctx->disk.file == NULL) {
        appctx->st0 = NST_NOSQL_APPCTX_STATE_ERROR;
    }

    if(ctx->state == NST_NOSQL_CTX_STATE_DELETE) {
        appctx->st0 = NST_NOSQL_APPCTX_STATE_END;
    }

    if(ctx->state == NST_NOSQL_CTX_STATE_FULL) {
        appctx->st0 = NST_NOSQL_APPCTX_STATE_FULL;
    }

    return 1;
}

static int _nst_nosql_filter_http_headers(struct stream *s,
        struct filter *filter, struct http_msg *msg) {
    if (IS_HTX_STRM(s)) {
        return _nst_nosql_filter_http_headers2(s, filter, msg);
    } else {
        return _nst_nosql_filter_http_headers1(s, filter, msg);
    }
}

static int _nst_nosql_filter_http_forward_data(struct stream *s,
        struct filter *filter, struct http_msg *msg, unsigned int len) {

    struct stream_interface *si = &s->si[1];
    struct appctx *appctx       = si_appctx(si);
    struct nst_nosql_ctx *ctx   = filter->ctx;

    if(ctx->state == NST_NOSQL_CTX_STATE_CREATE
            && !(msg->chn->flags & CF_ISRESP)) {

        if(appctx->st1 > 0) {

            if(len > appctx->st1) {
                len = appctx->st1;
            }

            appctx->st1 -= len;
        } else {

            if(len == 0) {
                return len;
            }

            if(!nst_nosql_update(ctx, msg, len)) {
                ctx->entry->state = NST_NOSQL_ENTRY_STATE_INVALID;
                appctx->st0       = NST_NOSQL_APPCTX_STATE_FULL;
                ctx->state        = NST_NOSQL_CTX_STATE_INVALID;
            }
        }
    }

    return len;
}

static int _nst_nosql_filter_http_payload(struct stream *s,
        struct filter *filter, struct http_msg *msg,
        unsigned int offset, unsigned int len) {

    struct stream_interface *si = &s->si[1];
    struct appctx *appctx       = si_appctx(si);
    struct nst_nosql_ctx *ctx   = filter->ctx;

    if(len <= 0) {
        return 0;
    }

    if(ctx->state == NST_NOSQL_CTX_STATE_CREATE
            && !(msg->chn->flags & CF_ISRESP)) {

        if(nst_nosql_update2(ctx, msg, offset, len) != NST_OK) {
            ctx->entry->state = NST_NOSQL_ENTRY_STATE_INVALID;
            appctx->st0       = NST_NOSQL_APPCTX_STATE_FULL;
            ctx->state        = NST_NOSQL_CTX_STATE_INVALID;
        }
    }

    return len;
}

static int _nst_nosql_filter_http_end1(struct stream *s, struct filter *filter,
        struct http_msg *msg) {

    struct stream_interface *si = &s->si[1];
    struct appctx *appctx       = si_appctx(si);
    struct nst_nosql_ctx *ctx   = filter->ctx;

    if(ctx->state == NST_NOSQL_CTX_STATE_CREATE
            && !(msg->chn->flags & CF_ISRESP)) {

        nst_nosql_finish(ctx, msg);

        if(ctx->state == NST_NOSQL_CTX_STATE_DONE) {
            appctx->st0 = NST_NOSQL_APPCTX_STATE_END;
        } else {
            appctx->st0 = NST_NOSQL_APPCTX_STATE_EMPTY;
        }
    }

    return 1;
}

static int _nst_nosql_filter_http_end2(struct stream *s, struct filter *filter,
        struct http_msg *msg) {

    struct stream_interface *si = &s->si[1];
    struct appctx *appctx       = si_appctx(si);
    struct nst_nosql_ctx *ctx   = filter->ctx;

    if(ctx->state == NST_NOSQL_CTX_STATE_CREATE
            && !(msg->chn->flags & CF_ISRESP)) {

        nst_nosql_finish2(ctx, s, msg);

        if(ctx->state == NST_NOSQL_CTX_STATE_DONE) {
            appctx->st0 = NST_NOSQL_APPCTX_STATE_END;
        } else {
            appctx->st0 = NST_NOSQL_APPCTX_STATE_EMPTY;
        }
    }

    return 1;
}

static int _nst_nosql_filter_http_end(struct stream *s, struct filter *filter,
        struct http_msg *msg) {
    if (IS_HTX_STRM(s)) {
        return _nst_nosql_filter_http_end2(s, filter, msg);
    } else {
        return _nst_nosql_filter_http_end1(s, filter, msg);
    }
}

static int _nst_nosql_filter_http_chunk_trailers(struct stream *s,
        struct filter *filter, struct http_msg *msg) {

    return 1;
}

struct flt_ops nst_nosql_filter_ops = {
    /* Manage nosql filter, called for each filter declaration */
    .init   = _nst_nosql_filter_init,
    .deinit = _nst_nosql_filter_deinit,
    .check  = _nst_nosql_filter_check,

    .attach = _nst_nosql_filter_attach,
    .detach = _nst_nosql_filter_detach,

    /* Filter HTTP requests and responses */
    .http_headers      = _nst_nosql_filter_http_headers,
    .http_forward_data = _nst_nosql_filter_http_forward_data,
    .http_payload      = _nst_nosql_filter_http_payload,
    .http_end          = _nst_nosql_filter_http_end,
    .http_chunk_trailers = _nst_nosql_filter_http_chunk_trailers,

};

/*
 * nuster cache filter related variables and functions.
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

#include <types/sample.h>

#include <proto/sample.h>
#include <proto/filters.h>
#include <proto/log.h>
#include <proto/stream.h>
#include <proto/http_ana.h>
#include <proto/stream_interface.h>

#include <nuster/memory.h>
#include <nuster/cache.h>
#include <nuster/nuster.h>
#include <nuster/http.h>

static int _nst_cache_filter_init(struct proxy *px, struct flt_conf *fconf) {
    struct nst_flt_conf *conf = fconf->conf;

    fconf->flags |= FLT_CFG_FL_HTX;
    conf->pid = px->uuid;
    return 0;
}

static void _nst_cache_filter_deinit(struct proxy *px, struct flt_conf *fconf) {
    struct nst_flt_conf *conf = fconf->conf;

    if(conf) {
        free(conf);
    }

    fconf->conf = NULL;
}

static int _nst_cache_filter_check(struct proxy *px, struct flt_conf *fconf) {

    if(px->mode != PR_MODE_HTTP) {
        ha_warning("Proxy [%s]: mode should be http to enable cache\n", px->id);
    }

    return 0;
}

static int _nst_cache_filter_attach(struct stream *s, struct filter *filter) {
    struct nst_flt_conf *conf = FLT_CONF(filter);

    /* disable cache if state is not NST_STATUS_ON */
    if(global.nuster.cache.status != NST_STATUS_ON
            || conf->status != NST_STATUS_ON) {

        return 0;
    }

    if(!filter->ctx) {
        int rule_cnt = nuster.proxy[conf->pid]->rule_cnt;
        int key_cnt  = nuster.proxy[conf->pid]->key_cnt;

        int size = sizeof(struct nst_cache_ctx) + key_cnt * sizeof(struct nst_key);
        struct nst_cache_ctx *ctx = nst_cache_memory_alloc(size);

        if(ctx == NULL ) {
            return 0;
        }

        memset(ctx, 0, size);

        ctx->state    = NST_CACHE_CTX_STATE_INIT;
        ctx->pid      = conf->pid;
        ctx->rule_cnt = rule_cnt;
        ctx->key_cnt  = key_cnt;

        filter->ctx = ctx;
    }

    register_data_filter(s, &s->req, filter);
    register_data_filter(s, &s->res, filter);

    return 1;
}

static void _nst_cache_filter_detach(struct stream *s, struct filter *filter) {

    if(filter->ctx) {
        int i;
        struct nst_cache_ctx *ctx    = filter->ctx;

        nst_cache_stats_update_req(ctx->state);

        if(ctx->disk.fd > 0) {
            close(ctx->disk.fd);
        }

        if(ctx->state == NST_CACHE_CTX_STATE_CREATE) {
            nst_cache_abort(ctx);
        }

        if(ctx->req.host.data) {
            nst_cache_memory_free(ctx->req.host.data);
        }

        if(ctx->req.path.data) {
            nst_cache_memory_free(ctx->req.path.data);
        }

        for(i = 0; i < ctx->key_cnt; i++) {
            struct nst_key key = ctx->keys[i];

            if(key.data) {
                nst_cache_memory_free(ctx);
            }
        }

        nst_cache_memory_free(ctx);
    }
}

/*
 * XXX
 */
static void nst_res_304(struct stream *s, struct nst_str *last_modified,
        struct nst_str *etag) {

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

    if(!htx_add_header(htx, ist("Last-Modified"),
                ist2(last_modified->data, last_modified->len)) ||
            !htx_add_header(htx, ist("ETag"), ist2(etag->data, etag->len))) {

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

static void nst_res_412(struct stream *s) {

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

static int _nst_cache_filter_http_headers(struct stream *s,
        struct filter *filter, struct http_msg *msg) {

    struct channel *req         = msg->chn;
    struct channel *res         = &s->res;
    struct proxy *px            = s->be;
    struct stream_interface *si = &s->si[1];
    struct nst_cache_ctx *ctx   = filter->ctx;

    if(!(msg->chn->flags & CF_ISRESP)) {

        /* check http method */
        if(s->txn->meth == HTTP_METH_OTHER) {
            ctx->state = NST_CACHE_CTX_STATE_BYPASS;
        }

        /* request */
        if(ctx->state == NST_CACHE_CTX_STATE_INIT) {
            int i = 0;

            if(nst_cache_prebuild_key(ctx, s, msg) != NST_OK) {
                ctx->state = NST_CACHE_CTX_STATE_BYPASS;
                return 1;
            }

            ctx->rule = nuster.proxy[px->uuid]->rule;

            for(i = 0; i < ctx->rule_cnt; i++) {
                int idx = ctx->rule->key->idx;
                struct nst_key *key = &(ctx->keys[idx]);

                nst_debug(s, "[cache] ==== Check rule: %s ====\n", ctx->rule->name);

                if(ctx->rule->state == NST_RULE_DISABLED) {
                    nst_debug(s, "[cache] Disabled, continue.\n");
                    ctx->rule = ctx->rule->next;
                    continue;
                }

                if(key->data) {
                    nst_debug(s, "[cache] Key checked, continue.\n");
                } else {
                    /* build key */
                    if(nst_cache_build_key(ctx, s, msg) != NST_OK) {
                        ctx->state = NST_CACHE_CTX_STATE_BYPASS;
                        return 1;
                    }

                    if(nst_cache_store_key(ctx, key) != NST_OK) {
                        ctx->state = NST_CACHE_CTX_STATE_BYPASS;
                        return 1;
                    }

                    nst_debug(s, "[cache] Key: ");
                    nst_debug_key(key);

                    nst_hash(key);

                    nst_debug(s, "[cache] Hash: %"PRIu64"\n", key->hash);

                    /* check if cache exists  */
                    nst_debug(s, "[cache] Check key existence: ");
                    ctx->state = nst_cache_exists(ctx);

                    if(ctx->state == NST_CACHE_CTX_STATE_HIT) {
                        int ret;

                        nst_debug2("HIT memory\n");

                        /* OK, cache exists */

                        ret = nst_cache_handle_conditional_req(ctx, s, msg);

                        if(ret == 304) {
                            nst_res_304(s, &ctx->res.last_modified,
                                    &ctx->res.etag);

                            return 1;
                        }

                        if(ret == 412) {
                            nst_res_412(s);

                            return 1;
                        }

                        break;
                    }

                    if(ctx->state == NST_CACHE_CTX_STATE_HIT_DISK) {
                        int ret;

                        nst_debug2("HIT disk\n");

                        /* OK, cache exists */

                        if(ctx->rule->etag == NST_STATUS_ON) {
                            ctx->res.etag.len  = nst_persist_meta_get_etag_len(ctx->disk.meta);

                            ctx->res.etag.data = nst_cache_memory_alloc(ctx->res.etag.len);

                            if(!ctx->res.etag.data) {
                                goto abort_check;
                            }

                            if(nst_persist_get_etag(ctx->disk.fd, ctx->disk.meta, &ctx->res.etag)
                                    != NST_OK) {

                                goto abort_check;
                            }
                        }

                        if(ctx->rule->last_modified == NST_STATUS_ON) {
                            ctx->res.last_modified.len  =
                                nst_persist_meta_get_last_modified_len(
                                        ctx->disk.meta);

                            ctx->res.last_modified.data =
                                nst_cache_memory_alloc(ctx->res.last_modified.len);

                            if(!ctx->res.last_modified.data) {
                                goto abort_check;
                            }

                            if(nst_persist_get_last_modified(ctx->disk.fd,
                                        ctx->disk.meta, &ctx->res.last_modified)
                                    != NST_OK) {

                                goto abort_check;
                            }
                        }

                        ret = nst_cache_handle_conditional_req(ctx, s, msg);

                        if(ret == 304) {
                            nst_res_304(s, &ctx->res.last_modified,
                                    &ctx->res.etag);

                            return 1;
                        }

                        if(ret == 412) {
                            nst_res_412(s);

                            return 1;
                        }

abort_check:
                        if(ctx->res.etag.data) {
                            nst_cache_memory_free(ctx->res.etag.data);
                        }

                        if(ctx->res.last_modified.data) {
                            nst_cache_memory_free(ctx->res.last_modified.data);
                        }

                        break;
                    }

                    nst_debug2("MISS\n");

                    /* no, there's no cache yet */

                    /* test acls to see if we should cache it */
                    nst_debug(s, "[cache] Test rule ACL (req): ");

                    if(nst_test_rule(ctx->rule, s, msg->chn->flags & CF_ISRESP) == NST_OK) {
                        nst_debug2("PASS\n");
                        ctx->state = NST_CACHE_CTX_STATE_PASS;
                        break;
                    }

                    nst_debug2("FAIL\n");
                }

                ctx->rule = ctx->rule->next;
            }

        }

        if(ctx->state == NST_CACHE_CTX_STATE_HIT) {
            nst_cache_hit(s, si, req, res, ctx->data);
        }

        if(ctx->state == NST_CACHE_CTX_STATE_HIT_DISK) {
            nst_cache_hit_disk(s, si, req, res, ctx);
        }

    } else {
        /* response */

        if(ctx->state == NST_CACHE_CTX_STATE_INIT) {
            int i = 0;

            ctx->rule = nuster.proxy[px->uuid]->rule;

            for(i = 0; i < ctx->rule_cnt; i++) {
                nst_debug(s, "[cache] ==== Check rule: %s ====\n", ctx->rule->name);
                nst_debug(s, "[cache] Test rule ACL (res): ");

                /* test acls to see if we should cache it */
                if(nst_test_rule(ctx->rule, s, msg->chn->flags & CF_ISRESP) == NST_OK) {
                    nst_debug2("PASS\n");
                    ctx->state = NST_CACHE_CTX_STATE_PASS;
                    break;
                }

                nst_debug2("FAIL\n");
                ctx->rule = ctx->rule->next;
            }

        }

        if(ctx->state == NST_CACHE_CTX_STATE_PASS) {
            struct nst_rule_code *cc = ctx->rule->code;

            int valid = 0;

            /* check if code is valid */
            nst_debug(s, "[cache] Check status code: ");

            if(!cc) {
                valid = 1;
            }

            while(cc) {

                if(cc->code == s->txn->status) {
                    valid = 1;
                    break;
                }

                cc = cc->next;
            }

            if(!valid) {
                nst_debug2("FAIL\n");
                return 1;
            }

            nst_debug2("PASS\n");

            nst_cache_build_etag(ctx, s, msg);

            nst_cache_build_last_modified(ctx, s, msg);

            nst_debug(s, "[cache] To create\n");

            /* start to build cache */
            nst_cache_create(ctx, msg);
        }

    }

    return 1;
}

static int _nst_cache_filter_http_payload(struct stream *s,
        struct filter *filter, struct http_msg *msg, unsigned int offset,
        unsigned int len) {

    struct nst_cache_ctx *ctx = filter->ctx;

    int ret = len;

    if(len <= 0) {
        return 0;
    }

    if(ctx->state == NST_CACHE_CTX_STATE_CREATE
            && (msg->chn->flags & CF_ISRESP)) {

        if(nst_cache_update(ctx, msg, offset, ret) != NST_OK) {
            goto err;
        }
    }

    return ret;

err:
    ctx->entry->state = NST_CACHE_ENTRY_STATE_INVALID;
    ctx->entry->data  = NULL;
    ctx->state        = NST_CACHE_CTX_STATE_BYPASS;
    return ret;
}

static int _nst_cache_filter_http_end(struct stream *s, struct filter *filter,
        struct http_msg *msg) {

    struct nst_cache_ctx *ctx = filter->ctx;

    if(ctx->state == NST_CACHE_CTX_STATE_CREATE
            && (msg->chn->flags & CF_ISRESP)) {

        nst_cache_finish(ctx);
        nst_debug(s, "[cache] Created\n");
    }

    return 1;
}

struct flt_ops nst_cache_filter_ops = {
    /* Manage cache filter, called for each filter declaration */
    .init   = _nst_cache_filter_init,
    .deinit = _nst_cache_filter_deinit,
    .check  = _nst_cache_filter_check,

    .attach = _nst_cache_filter_attach,
    .detach = _nst_cache_filter_detach,

    /* Filter HTTP requests and responses */
    .http_headers      = _nst_cache_filter_http_headers,
    .http_payload      = _nst_cache_filter_http_payload,
    .http_end          = _nst_cache_filter_http_end,

};

static int nst_smp_fetch_cache_hit(const struct arg *args, struct sample *smp,
        const char *kw,  void *private) {

    struct nst_cache_ctx *ctx;
    struct filter        *filter;

    list_for_each_entry(filter, &strm_flt(smp->strm)->filters, list) {
        if(FLT_ID(filter) != nst_cache_flt_id) {
            continue;
        }

        if(!(ctx = filter->ctx)) {
            break;
        }

        smp->data.type = SMP_T_BOOL;
        smp->data.u.sint = ctx->state == NST_CACHE_CTX_STATE_HIT
            || ctx->state == NST_CACHE_CTX_STATE_HIT_DISK;;

        return 1;
    }

    return 0;
}

static struct sample_fetch_kw_list nst_sample_fetch_keywords = {
    ILH, {
        { "nuster.cache.hit", nst_smp_fetch_cache_hit, 0, NULL, SMP_T_BOOL,
            SMP_USE_HRSHP
        },
    }
};

INITCALL1(STG_REGISTER, sample_register_fetches, &nst_sample_fetch_keywords);

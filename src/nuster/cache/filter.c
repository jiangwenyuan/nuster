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

#include <nuster/nuster.h>

static int
_nst_cache_filter_init(hpx_proxy_t *px, hpx_flt_conf_t *fconf) {
    nst_flt_conf_t  *conf = fconf->conf;

    fconf->flags |= FLT_CFG_FL_HTX;
    conf->pid     = px->uuid;

    return 0;
}

static void
_nst_cache_filter_deinit(hpx_proxy_t *px, hpx_flt_conf_t *fconf) {
    nst_flt_conf_t  *conf = fconf->conf;

    if(conf) {
        free(conf);
    }

    fconf->conf = NULL;
}

static int
_nst_cache_filter_check(hpx_proxy_t *px, hpx_flt_conf_t *fconf) {

    if(px->mode != PR_MODE_HTTP) {
        ha_warning("Proxy [%s]: mode should be http to enable cache\n", px->id);
    }

    return 0;
}

static int
_nst_cache_filter_attach(hpx_stream_t *s, hpx_filter_t *filter) {
    nst_flt_conf_t  *conf = FLT_CONF(filter);

    nst_debug(s, "[cache] ===== attach =====");

    /* disable cache if state is not NST_STATUS_ON */
    if(global.nuster.cache.status != NST_STATUS_ON || conf->status != NST_STATUS_ON) {
        return 0;
    }

    if(!filter->ctx) {
        nst_ctx_t  *ctx;
        int         rule_cnt, key_cnt, size;

        rule_cnt = nuster.proxy[conf->pid]->rule_cnt;
        key_cnt  = nuster.proxy[conf->pid]->key_cnt;

        size = sizeof(nst_ctx_t) + key_cnt * sizeof(nst_key_t);

        ctx = malloc(size);

        if(ctx == NULL) {
            return 0;
        }

        memset(ctx, 0, size);

        ctx->state    = NST_CTX_STATE_INIT;
        ctx->pid      = conf->pid;
        ctx->rule_cnt = rule_cnt;
        ctx->key_cnt  = key_cnt;

        if(nst_http_txn_attach(&ctx->txn) != NST_OK) {
            free(ctx);

            return 0;
        }

        filter->ctx = ctx;
    }

    register_data_filter(s, &s->req, filter);
    register_data_filter(s, &s->res, filter);

    return 1;
}

static void
_nst_cache_filter_detach(hpx_stream_t *s, hpx_filter_t *filter) {

    if(filter->ctx) {
        nst_ctx_t  *ctx = filter->ctx;
        int         i;

        nst_stats_update_cache(ctx->state);

        if(ctx->state == NST_CTX_STATE_HIT_MEMORY) {
            ctx->store.ring.data->clients--;
        }

        if(ctx->state == NST_CTX_STATE_CREATE) {
            nst_cache_abort(ctx);
        }

        for(i = 0; i < ctx->key_cnt; i++) {
            nst_key_t key = ctx->keys[i];

            if(key.data) {
                free(key.data);
            }
        }

        nst_http_txn_detach(&ctx->txn);

        free(ctx);
    }

    nst_debug(s, "[cache] ===== detach =====");
}

static int
_nst_cache_filter_http_headers(hpx_stream_t *s, hpx_filter_t *filter, hpx_http_msg_t *msg) {
    hpx_channel_t           *req = msg->chn;
    hpx_channel_t           *res = &s->res;
    hpx_proxy_t             *px  = s->be;
    hpx_stream_interface_t  *si  = &s->si[1];
    nst_ctx_t               *ctx = filter->ctx;
    hpx_htx_t               *htx;

    if(!(msg->chn->flags & CF_ISRESP)) {
        /* request */

        /* check http method */
        if(s->txn->meth == HTTP_METH_OTHER) {
            ctx->state = NST_CTX_STATE_BYPASS;
        }

        if(ctx->state == NST_CTX_STATE_INIT) {
            int  i = 0;

            if(nst_http_parse_htx(s, msg, &ctx->txn) != NST_OK) {
                ctx->state = NST_CTX_STATE_BYPASS;

                return 1;
            }

            ctx->rule = nuster.proxy[px->uuid]->rule;

            for(i = 0; i < ctx->rule_cnt; i++) {
                int         idx = ctx->rule->key->idx;
                nst_key_t  *key = &(ctx->keys[idx]);

                nst_debug(s, "[rule ] ----- %s", ctx->rule->name);

                if(ctx->rule->state == NST_RULE_DISABLED) {
                    nst_debug(s, "[rule ] disabled, continue.");
                    ctx->rule = ctx->rule->next;

                    continue;
                }

                if(nst_store_memory_off(ctx->rule->store) && nst_store_disk_off(ctx->rule->store)) {
                    nst_debug(s, "[rule ] memory off and disk off, continue.");
                    ctx->rule = ctx->rule->next;

                    continue;
                }

                if(!key->data) {
                    /* build key */
                    if(nst_key_build(s, msg, ctx->rule, &ctx->txn, key, s->txn->meth) != NST_OK) {
                        ctx->state = NST_CTX_STATE_BYPASS;

                        return 1;
                    }

                    nst_key_hash(key);
                }

                nst_key_debug(s, key);

                /* check if cache exists  */
                nst_debug_beg(s, "[cache] Check key existence: ");

                ctx->state = nst_cache_exists(ctx);

                if(ctx->state == NST_CTX_STATE_HIT_MEMORY || ctx->state == NST_CTX_STATE_HIT_DISK) {
                    /* OK, cache exists */

                    if(ctx->state == NST_CTX_STATE_HIT_MEMORY) {
                        nst_debug_end("HIT memory");
                    } else {
                        nst_debug_end("HIT disk");
                    }

                    htx = htxbuf(&req->buf);

                    if(nst_http_handle_conditional_req(s, htx, ctx->txn.res.last_modified,
                                ctx->txn.res.etag, ctx->rule->last_modified, ctx->rule->etag)) {

                        return 1;
                    }

                    break;
                }

                nst_debug_end("MISS");

                /* no, there's no cache yet */

                /* test acls to see if we should cache it */
                nst_debug_beg(s, "[cache] Test rule ACL (req): ");

                if(nst_test_rule(s, ctx->rule, msg->chn->flags & CF_ISRESP) == NST_OK) {
                    nst_debug_end("PASS");
                    ctx->state = NST_CTX_STATE_PASS;

                    break;
                }

                nst_debug_end("FAIL");

                ctx->rule = ctx->rule->next;
            }
        }

        if(ctx->state == NST_CTX_STATE_HIT_MEMORY || ctx->state == NST_CTX_STATE_HIT_DISK) {
            nst_cache_hit(s, si, req, res, ctx);
        }

    } else {
        /* response */

        if(ctx->state == NST_CTX_STATE_INIT) {
            int  i = 0;

            ctx->rule = nuster.proxy[px->uuid]->rule;

            for(i = 0; i < ctx->rule_cnt; i++) {
                nst_debug(s, "[cache] ==== Check rule: %s ====", ctx->rule->name);
                nst_debug_beg(s, "[cache] Test rule ACL (res): ");

                /* test acls to see if we should cache it */
                if(nst_test_rule(s, ctx->rule, msg->chn->flags & CF_ISRESP) == NST_OK) {
                    nst_debug_end("PASS");
                    ctx->state = NST_CTX_STATE_PASS;

                    break;
                }

                nst_debug_end("FAIL");
                ctx->rule = ctx->rule->next;
            }

        }

        if(ctx->state == NST_CTX_STATE_PASS) {
            nst_rule_code_t  *cc    = ctx->rule->code;
            int               valid = 0;

            /* check if code is valid */
            nst_debug_beg(s, "[cache] Check status code: ");

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
                nst_debug_end("FAIL");

                return 1;
            }

            nst_debug_end("PASS");

            nst_cache_build_etag(s, msg, ctx);

            nst_cache_build_last_modified(s, msg, ctx);

            nst_debug(s, "[cache] To create");

            /* start to build cache */
            nst_cache_create(msg, ctx);
        }

    }

    return 1;
}

static int
_nst_cache_filter_http_payload(hpx_stream_t *s, hpx_filter_t *filter, hpx_http_msg_t *msg,
        unsigned int offset, unsigned int len) {

    nst_ctx_t  *ctx = filter->ctx;

    if(len <= 0) {
        return 0;
    }

    if(ctx->state == NST_CTX_STATE_CREATE && (msg->chn->flags & CF_ISRESP)) {

        if(nst_cache_update(msg, ctx, offset, len) != NST_OK) {
            goto err;
        }

    }

    return len;

err:
    ctx->entry->state            = NST_DICT_ENTRY_STATE_INVALID;
    ctx->entry->store.ring.data  = NULL;
    ctx->state                   = NST_CTX_STATE_BYPASS;

    return len;
}

static int
_nst_cache_filter_http_end(hpx_stream_t *s, hpx_filter_t *filter, hpx_http_msg_t *msg) {

    nst_ctx_t  *ctx = filter->ctx;

    if(ctx->state == NST_CTX_STATE_CREATE && (msg->chn->flags & CF_ISRESP)) {
        nst_cache_finish(ctx);
        nst_debug(s, "[cache] Created");
    }

    return 1;
}

hpx_flt_ops_t nst_cache_filter_ops = {
    /* Manage cache filter, called for each filter declaration */
    .init   = _nst_cache_filter_init,
    .deinit = _nst_cache_filter_deinit,
    .check  = _nst_cache_filter_check,

    .attach = _nst_cache_filter_attach,
    .detach = _nst_cache_filter_detach,

    /* Filter HTTP requests and responses */
    .http_headers = _nst_cache_filter_http_headers,
    .http_payload = _nst_cache_filter_http_payload,
    .http_end     = _nst_cache_filter_http_end,

};

static int
nst_smp_fetch_cache_hit(const hpx_arg_t *args, hpx_sample_t *smp, const char *kw, void *private) {

    nst_ctx_t *ctx;
    hpx_filter_t        *filter;

    list_for_each_entry(filter, &strm_flt(smp->strm)->filters, list) {
        if(FLT_ID(filter) != nst_cache_flt_id) {
            continue;
        }

        if(!(ctx = filter->ctx)) {
            break;
        }

        smp->data.type = SMP_T_BOOL;
        smp->data.u.sint = ctx->state == NST_CTX_STATE_HIT_MEMORY
            || ctx->state == NST_CTX_STATE_HIT_DISK;;

        return 1;
    }

    return 0;
}

static hpx_sample_fetch_kw_list_t nst_sample_fetch_keywords = {
    ILH, {
        { "nuster.cache.hit", nst_smp_fetch_cache_hit, 0, NULL, SMP_T_BOOL, SMP_USE_HRSHP },
    }
};

INITCALL1(STG_REGISTER, sample_register_fetches, &nst_sample_fetch_keywords);

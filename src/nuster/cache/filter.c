/*
 * Cache filter related variables and functions.
 *
 * Copyright (C) [Jiang Wenyuan](https://github.com/jiangwenyuan), < koubunen AT gmail DOT com >
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>

#include <common/time.h>
#include <common/tools.h>
#include <common/cfgparse.h>
#include <common/mini-clist.h>
#include <common/standard.h>

#include <types/channel.h>
#include <types/filters.h>
#include <types/global.h>
#include <types/proxy.h>
#include <types/stream.h>
#include <types/proto_http.h>
#include <nuster/cache.h>

#include <proto/filters.h>
#include <proto/hdr_idx.h>
#include <proto/log.h>
#include <proto/stream.h>
#include <proto/proto_http.h>
#include <proto/stream_interface.h>
//#include <proto/cache.h>


static int cache_filter_init(struct proxy *px, struct flt_conf *fconf) {
    return 0;
}

static void cache_filter_deinit(struct proxy *px, struct flt_conf *fconf) {
    struct cache_config *conf = fconf->conf;

    if(conf) {
        free(conf);
    }
    fconf->conf = NULL;
}

static int cache_filter_check(struct proxy *px, struct flt_conf *fconf) {
    if(px->mode != PR_MODE_HTTP) {
        Warning("Proxy [%s] : mode should be http to enable cache\n", px->id);
    }
    return 0;
}

static int cache_filter_attach(struct stream *s, struct filter *filter) {
    struct cache_config *conf = FLT_CONF(filter);

    /* disable cache if state is not NST_CACHE_STATUS_ON */
    if(global.cache.status != NST_CACHE_STATUS_ON || conf->status != NST_CACHE_STATUS_ON) {
        return 0;
    }
    if(!filter->ctx) {
        struct nst_cache_ctx *ctx = pool_alloc2(global.cache.pool.ctx);
        if(ctx == NULL ) {
            return 0;
        }
        ctx->state   = NST_CACHE_CTX_STATE_INIT;
        ctx->rule    = NULL;
        ctx->stash   = NULL;
        ctx->entry   = NULL;
        ctx->data    = NULL;
        ctx->element = NULL;
        ctx->pid     = -1;
        filter->ctx  = ctx;
    }
    register_data_filter(s, &s->req, filter);
    register_data_filter(s, &s->res, filter);
    return 1;
}

static void cache_filter_detach(struct stream *s, struct filter *filter) {
    if(filter->ctx) {
        struct nst_cache_rule_stash *stash = NULL;
        struct nst_cache_ctx *ctx          = filter->ctx;

        cache_stats_update_request(ctx->state);

        if(ctx->state == NST_CACHE_CTX_STATE_CREATE) {
            cache_abort(ctx);
        }
        while(ctx->stash) {
            stash      = ctx->stash;
            ctx->stash = ctx->stash->next;
            free(stash->key);
            pool_free2(global.cache.pool.stash, stash);
        }
        if(ctx->req.host.data) {
            cache_memory_free(global.cache.pool.chunk, ctx->req.host.data);
        }
        if(ctx->req.path.data) {
            cache_memory_free(global.cache.pool.chunk, ctx->req.path.data);
        }
        pool_free2(global.cache.pool.ctx, ctx);
    }
}

static int cache_filter_http_headers(struct stream *s, struct filter *filter,
        struct http_msg *msg) {

    struct channel *req         = msg->chn;
    struct channel *res         = &s->res;
    struct proxy *px            = s->be;
    struct stream_interface *si = &s->si[1];
    struct nst_cache_ctx *ctx       = filter->ctx;
    struct nst_cache_rule *rule = NULL;
    char *key                   = NULL;
    uint64_t hash               = 0;

    if(!(msg->chn->flags & CF_ISRESP)) {

        nst_cache_housekeeping();

        /* check http method */
        if(s->txn->meth == HTTP_METH_OTHER) {
            ctx->state = NST_CACHE_CTX_STATE_BYPASS;
        }

        /* request */
        if(ctx->state == NST_CACHE_CTX_STATE_INIT) {
            if(!nst_cache_prebuild_key(ctx, s, msg)) {
                return 1;
            }
            list_for_each_entry(rule, &px->cache_rules, list) {
                nuster_debug("[CACHE] Checking rule: %s\n", rule->name);
                /* disabled? */
                if(*rule->state == NST_CACHE_RULE_DISABLED) {
                    continue;
                }
                /* build key */
                key = nst_cache_build_key(ctx, rule->key, s, msg);
                if(!key) {
                    return 1;
                }
                nuster_debug("[CACHE] Got key: %s\n", key);
                hash = nst_cache_hash_key(key);

                /* stash key */
                if(!cache_stash_rule(ctx, rule, key, hash)) {
                    return 1;
                }
                /* check if cache exists  */
                nuster_debug("[CACHE] Checking key existence: ");
                ctx->data = cache_exists(key, hash);
                if(ctx->data) {
                    nuster_debug("EXIST\n[CACHE] Hit\n");
                    /* OK, cache exists */
                    ctx->state = NST_CACHE_CTX_STATE_HIT;
                    break;
                }
                nuster_debug("NOT EXIST\n");
                /* no, there's no cache yet */

                /* test acls to see if we should cache it */
                nuster_debug("[CACHE] [REQ] Checking if rule pass: ");
                if(cache_test_rule(rule, s, msg->chn->flags & CF_ISRESP)) {
                    nuster_debug("PASS\n");
                    ctx->state = NST_CACHE_CTX_STATE_PASS;
                    ctx->rule  = rule;
                    break;
                }
                nuster_debug("FAIL\n");
            }
        }

        if(ctx->state == NST_CACHE_CTX_STATE_HIT) {
            cache_hit(s, si, req, res, ctx->data);
        }

    } else {
        /* response */
        if(ctx->state == NST_CACHE_CTX_STATE_INIT) {
            nuster_debug("[CACHE] [RES] Checking if rule pass: ");
            list_for_each_entry(rule, &px->cache_rules, list) {
                /* test acls to see if we should cache it */
                if(cache_test_rule(rule, s, msg->chn->flags & CF_ISRESP)) {
                    nuster_debug("PASS\n");
                    ctx->state = NST_CACHE_CTX_STATE_PASS;
                    ctx->rule  = rule;
                    break;
                }
                nuster_debug("FAIL\n");
            }
        }

        if(ctx->state == NST_CACHE_CTX_STATE_PASS) {
            struct nst_cache_rule_stash *stash = ctx->stash;
            struct nst_cache_code *cc      = ctx->rule->code;
            int valid                      = 0;

            ctx->pid = px->uuid;

            /* check if code is valid */
            nuster_debug("[CACHE] [RES] Checking status code: ");
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
                nuster_debug("FAIL\n");
                return 1;
            }

            /* get cache key */
            while(stash) {
                if(ctx->stash->rule == ctx->rule) {
                    key  = stash->key;
                    hash = stash->hash;
                    break;
                }
                stash = stash->next;
            }

            if(!key) {
                return 1;
            }

            nuster_debug("PASS\n[CACHE] To create\n");

            /* start to build cache */
            nst_cache_create(ctx, key, hash);
        }

    }

    return 1;
}

static int cache_filter_http_forward_data(struct stream *s, struct filter *filter,
        struct http_msg *msg, unsigned int len) {

    struct nst_cache_ctx *ctx = filter->ctx;

    if(ctx->state == NST_CACHE_CTX_STATE_CREATE && (msg->chn->flags & CF_ISRESP)) {
        if(!nst_cache_update(ctx, msg, len)) {
            ctx->entry->state = NST_CACHE_ENTRY_STATE_INVALID;
            ctx->state        = NST_CACHE_CTX_STATE_PASS;
        }
    }
    return len;
}

static int cache_filter_http_end(struct stream *s, struct filter *filter,
        struct http_msg *msg) {

    struct nst_cache_ctx *ctx = filter->ctx;

    if(ctx->state == NST_CACHE_CTX_STATE_CREATE && (msg->chn->flags & CF_ISRESP)) {
        cache_finish(ctx);
    }
    return 1;
}

struct flt_ops cache_filter_ops = {
    /* Manage cache filter, called for each filter declaration */
    .init   = cache_filter_init,
    .deinit = cache_filter_deinit,
    .check  = cache_filter_check,

    .attach = cache_filter_attach,
    .detach = cache_filter_detach,

    /* Filter HTTP requests and responses */
    .http_headers      = cache_filter_http_headers,
    .http_forward_data = cache_filter_http_forward_data,
    .http_end          = cache_filter_http_end,

};

/* Declare the config parser for "cache" keyword */
static struct cfg_kw_list cfg_kws = {ILH, {
    { CFG_LISTEN, "cache-rule", cache_parse_rule}, { 0, NULL, NULL }, }
};

/* Declare the filter parser for "cache" keyword */
static struct flt_kw_list flt_kws = { "CACHE", { }, {
    { "cache", cache_parse_filter, NULL }, { NULL, NULL, NULL }, }
};

__attribute__((constructor)) static void __flt_cache_init(void) {
    cfg_register_keywords(&cfg_kws);
    flt_register_keywords(&flt_kws);
}

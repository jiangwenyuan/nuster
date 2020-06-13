/*
 * nuster sample related variables and functions.
 *
 * Copyright (C) Jiang Wenyuan, < koubunen AT gmail DOT com >
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/filters.h>
#include <haproxy/sample.h>

#include <nuster/nuster.h>

static int
nst_sample_fetch_cache_hit(const hpx_arg_t *args, hpx_sample_t *smp, const char *kw, void *p) {
    hpx_filter_t  *filter;
    nst_ctx_t     *ctx;

    list_for_each_entry(filter, &strm_flt(smp->strm)->filters, list) {
        int  hit;

        if(FLT_ID(filter) != nst_cache_flt_id) {
            continue;
        }

        if(!(ctx = filter->ctx)) {
            break;
        }

        hit = ctx->state == NST_CTX_STATE_HIT_MEMORY || ctx->state == NST_CTX_STATE_HIT_DISK;;

        smp->data.type   = SMP_T_BOOL;
        smp->data.u.sint = hit;

        return 1;
    }

    return 0;
}

static int
nst_sample_fetch_host(const hpx_arg_t *args, hpx_sample_t *smp, const char *kw, void *p) {
    hpx_filter_t  *filter;
    nst_ctx_t     *ctx;

    list_for_each_entry(filter, &strm_flt(smp->strm)->filters, list) {

        if(FLT_ID(filter) != nst_cache_flt_id && FLT_ID(filter) != nst_nosql_flt_id) {
            continue;
        }

        if(!(ctx = filter->ctx)) {
            break;
        }

        smp->data.type = SMP_T_STR;
        smp->flags     = SMP_F_CONST;

        if(!ctx->txn.req.host.len) {
            return 0;
        }

        smp->data.u.str.area = ctx->txn.req.host.ptr;
        smp->data.u.str.data = ctx->txn.req.host.len;

        return 1;
    }

    return 0;
}

static int
nst_sample_fetch_uri(const hpx_arg_t *args, hpx_sample_t *smp, const char *kw, void *p) {
    hpx_filter_t  *filter;
    nst_ctx_t     *ctx;

    list_for_each_entry(filter, &strm_flt(smp->strm)->filters, list) {

        if(FLT_ID(filter) != nst_cache_flt_id && FLT_ID(filter) != nst_nosql_flt_id) {
            continue;
        }

        if(!(ctx = filter->ctx)) {
            break;
        }

        smp->data.type = SMP_T_STR;
        smp->flags     = SMP_F_CONST;

        if(!ctx->txn.req.uri.len) {
            return 0;
        }

        smp->data.u.str.area = ctx->txn.req.uri.ptr;
        smp->data.u.str.data = ctx->txn.req.uri.len;

        return 1;
    }

    return 0;
}

static int
nst_sample_fetch_path(const hpx_arg_t *args, hpx_sample_t *smp, const char *kw, void *p) {
    hpx_filter_t  *filter;
    nst_ctx_t     *ctx;

    list_for_each_entry(filter, &strm_flt(smp->strm)->filters, list) {

        if(FLT_ID(filter) != nst_cache_flt_id && FLT_ID(filter) != nst_nosql_flt_id) {
            continue;
        }

        if(!(ctx = filter->ctx)) {
            break;
        }

        smp->data.type = SMP_T_STR;
        smp->flags     = SMP_F_CONST;

        if(!ctx->txn.req.path.len) {
            return 0;
        }

        smp->data.u.str.area = ctx->txn.req.path.ptr;
        smp->data.u.str.data = ctx->txn.req.path.len;

        return 1;
    }

    return 0;
}

static int
nst_sample_fetch_query(const hpx_arg_t *args, hpx_sample_t *smp, const char *kw, void *p) {
    hpx_filter_t    *filter;
    nst_ctx_t       *ctx;

    list_for_each_entry(filter, &strm_flt(smp->strm)->filters, list) {

        if(FLT_ID(filter) != nst_cache_flt_id) {
            continue;
        }

        if(!(ctx = filter->ctx)) {
            break;
        }

        smp->data.type = SMP_T_STR;
        smp->flags     = SMP_F_CONST;

        if(!ctx->txn.req.query.len) {
            return 0;
        }

        smp->data.u.str.area = ctx->txn.req.query.ptr;
        smp->data.u.str.data = ctx->txn.req.query.len;

        return 1;
    }

    return 0;
}

static hpx_sample_fetch_kw_list_t nst_sample_fetch_keywords = {
    ILH, {
        { "nuster.cache.hit", nst_sample_fetch_cache_hit, 0, NULL, SMP_T_BOOL, SMP_USE_HRSHP },
        { "nuster.host",      nst_sample_fetch_host,      0, NULL, SMP_T_STR,  SMP_USE_HRSHP },
        { "nuster.uri",       nst_sample_fetch_uri,       0, NULL, SMP_T_STR,  SMP_USE_HRSHP },
        { "nuster.path",      nst_sample_fetch_path,      0, NULL, SMP_T_STR,  SMP_USE_HRSHP },
        { "nuster.query",     nst_sample_fetch_query,     0, NULL, SMP_T_STR,  SMP_USE_HRSHP },
        { /* END */ },
    }
};

INITCALL1(STG_REGISTER, sample_register_fetches, &nst_sample_fetch_keywords);

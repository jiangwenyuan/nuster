/*
 * nuster cache stats functions.
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

#include <types/global.h>

#include <proto/stream_interface.h>
#include <proto/proxy.h>

#include <nuster/nuster.h>
#include <nuster/memory.h>
#include <nuster/shctx.h>

void nst_cache_stats_update_used_mem(int i) {
    nst_shctx_lock(global.nuster.cache.stats);
    global.nuster.cache.stats->used_mem += i;
    nst_shctx_unlock(global.nuster.cache.stats);
}

void nst_cache_stats_update_req(int state) {
    nst_shctx_lock(global.nuster.cache.stats);
    global.nuster.cache.stats->req.total++;

    switch(state) {
        case NST_CACHE_CTX_STATE_HIT:
        case NST_CACHE_CTX_STATE_HIT_DISK:
            global.nuster.cache.stats->req.hit++;
            break;
        case NST_CACHE_CTX_STATE_CREATE:
            global.nuster.cache.stats->req.abort++;
            break;
        case NST_CACHE_CTX_STATE_DONE:
            global.nuster.cache.stats->req.fetch++;
            break;
        default:
            break;
    }

    nst_shctx_unlock(global.nuster.cache.stats);
}

int nst_cache_stats_full() {
    int i;

    nst_shctx_lock(global.nuster.cache.stats);
    i =  global.nuster.cache.data_size <= global.nuster.cache.stats->used_mem;
    nst_shctx_unlock(global.nuster.cache.stats);

    return i;
}

/*
 * return 1 if the req is done, otherwise 0
 */

int nst_cache_stats(struct stream *s, struct channel *req, struct proxy *px) {
    struct stream_interface *si = &s->si[1];
    struct http_txn *txn        = s->txn;
    struct http_msg *msg        = &txn->req;
    struct appctx *appctx       = NULL;

    if(global.nuster.cache.status != NST_STATUS_ON) {
        return 0;
    }

    /* GET stats uri */
    if(txn->meth == HTTP_METH_GET && nst_cache_check_uri(msg) == NST_OK) {
        s->target = &nuster.applet.cache_stats.obj_type;

        if(unlikely(!si_register_handler(si, objt_applet(s->target)))) {
            return 1;
        } else {
            appctx      = si_appctx(si);
            appctx->st0 = NST_CACHE_STATS_HEAD;
            appctx->st1 = proxies_list->uuid;
            appctx->st2 = 0;

            req->analysers &= (AN_REQ_HTTP_BODY | AN_REQ_FLT_HTTP_HDRS | AN_REQ_FLT_END);
            req->analysers &= ~AN_REQ_FLT_XFER_DATA;
            req->analysers |= AN_REQ_HTTP_XFER_BODY;
        }
    }

    return 0;
}

int _nst_cache_stats_head(struct appctx *appctx, struct stream *s, struct stream_interface *si,
        struct channel *res) {

    struct htx *res_htx;

    struct htx_sl *sl;
    unsigned int flags;

    res_htx = htx_from_buf(&res->buf);

    flags = (HTX_SL_F_IS_RESP|HTX_SL_F_VER_11|HTX_SL_F_XFER_ENC|HTX_SL_F_XFER_LEN|HTX_SL_F_CHNK);
    sl = htx_add_stline(res_htx, HTX_BLK_RES_SL, flags, ist("HTTP/1.1"), ist("200"), ist("OK"));

    if(!sl) {
        goto full;
    }

    sl->info.res.status = 200;

    if(!htx_add_header(res_htx, ist("Cache-Control"), ist("no-cache"))) {
        goto full;
    }

    if(!htx_add_header(res_htx, ist("Content-Type"), ist("text/plain"))) {
        goto full;
    }

    if(!htx_add_endof(res_htx, HTX_BLK_EOH)) {
        goto full;
    }

    channel_add_input(&s->res, res_htx->data);

    chunk_reset(&trash);

    chunk_appendf(&trash, "**GLOBAL**\n");
    chunk_appendf(&trash, "global.nuster.cache.data.size: %"PRIu64"\n",
            global.nuster.cache.data_size);

    chunk_appendf(&trash, "global.nuster.cache.dict.size: %"PRIu64"\n",
            global.nuster.cache.dict_size);

    chunk_appendf(&trash, "global.nuster.cache.uri: %s\n",
            global.nuster.cache.uri);

    chunk_appendf(&trash, "global.nuster.cache.purge_method: %.*s\n",
            (int)strlen(global.nuster.cache.purge_method) - 1,
            global.nuster.cache.purge_method);

    chunk_appendf(&trash, "global.nuster.cache.stats.used_mem: %"PRIu64"\n",
            global.nuster.cache.stats->used_mem);

    chunk_appendf(&trash, "global.nuster.cache.stats.req_total: %"PRIu64"\n",
            global.nuster.cache.stats->req.total);

    chunk_appendf(&trash, "global.nuster.cache.stats.req_hit: %"PRIu64"\n",
            global.nuster.cache.stats->req.hit);

    chunk_appendf(&trash, "global.nuster.cache.stats.req_fetch: %"PRIu64"\n",
            global.nuster.cache.stats->req.fetch);

    chunk_appendf(&trash, "global.nuster.cache.stats.req_abort: %"PRIu64"\n",
            global.nuster.cache.stats->req.abort);

    chunk_appendf(&trash, "\n**PERSISTENCE**\n");

    if(global.nuster.cache.root) {
        chunk_appendf(&trash, "global.nuster.cache.dir: %s\n", global.nuster.cache.root);
        chunk_appendf(&trash, "global.nuster.cache.loaded: %s\n",
            nuster.cache->disk.loaded ? "yes" : "no");
    }

    if(trash.data >= channel_htx_recv_max(res, res_htx)) {
        goto full;
    }

    if(!htx_add_data_atonce(res_htx, ist2(trash.area, trash.data))) {
        goto full;
    }

    channel_add_input(res, trash.data);

    return 1;

full:
    htx_reset(res_htx);
    si_rx_room_blk(si);

    return 0;
}

int _nst_cache_stats_data(struct appctx *appctx, struct stream *s,
        struct stream_interface *si, struct channel *res) {

    struct htx *htx;

    struct proxy *p;

    htx = htx_from_buf(&res->buf);

    chunk_reset(&trash);

    p = proxies_list;
    while(p) {
        struct nst_rule *rule = NULL;

        if(htx_almost_full(htx)) {
            si_rx_room_blk(si);

            return 0;
        }

        if(p->uuid != appctx->st1) {
            goto next;
        }

        if(p->cap & PR_CAP_BE && p->nuster.mode == NST_MODE_CACHE) {

            rule = nuster.proxy[p->uuid]->rule;

            chunk_printf(&trash, "\n**PROXY %s %d**\n", p->id, p->uuid);

            if(!htx_add_data_atonce(htx, ist2(trash.area, trash.data))) {
                si_rx_room_blk(si);

                return 0;
            }

            channel_add_input(res, trash.data);

            while(rule) {
                if(htx_almost_full(htx)) {
                    si_rx_room_blk(si);

                    return 0;
                }

                if(rule->uuid == appctx->st2) {

                    chunk_printf(&trash, "%s.rule.%s: ", p->id, rule->name);

                    chunk_appendf(&trash, "state=%s ttl=%"PRIu32" disk=%s\n",
                            rule->state == NST_RULE_ENABLED ? "on" : "off",
                            rule->ttl,
                            rule->disk == NST_DISK_OFF ? "off"
                            : rule->disk == NST_DISK_ONLY ? "only"
                            : rule->disk == NST_DISK_SYNC ? "sync"
                            : rule->disk == NST_DISK_ASYNC ? "async"
                            : "invalid");

                    if(trash.data >= channel_htx_recv_max(res, htx)) {
                        si_rx_room_blk(si);

                        return 0;
                    }

                    if(!htx_add_data_atonce(htx, ist2(trash.area, trash.data))) {
                        si_rx_room_blk(si);

                        return 0;
                    }

                    channel_add_input(res, trash.data);

                    appctx->st2++;
                }

                rule = rule->next;
            }
        }

        appctx->st1 = p->next ? p->next->uuid : 0;

next:
        p = p->next;
    }

    return 1;
}

static void nst_cache_stats_handler(struct appctx *appctx) {
    struct stream_interface *si = appctx->owner;
    struct channel *req         = si_oc(si);
    struct channel *res         = si_ic(si);
    struct stream *s            = si_strm(si);

    struct htx *req_htx, *res_htx;

    res_htx = htx_from_buf(&res->buf);

    if(appctx->st0 == NST_CACHE_STATS_HEAD) {

        if(_nst_cache_stats_head(appctx, s, si, res)) {
            appctx->st0 = NST_CACHE_STATS_DATA;
        }
    }

    if(appctx->st0 == NST_CACHE_STATS_DATA) {

        if(_nst_cache_stats_data(appctx, s, si, res)) {
            appctx->st0 = NST_CACHE_STATS_DONE;
        }
    }

    if(appctx->st0 == NST_CACHE_STATS_DONE) {

        if (!htx_add_endof(res_htx, HTX_BLK_EOM)) {
            si_rx_room_blk(si);
            goto out;
        }

        channel_add_input(&s->res, 1);

        if (!(res->flags & CF_SHUTR)) {
            res->flags |= CF_READ_NULL;
            si_shutr(si);
        }

        /* eat the whole request */
        if (co_data(req)) {
            req_htx = htx_from_buf(&req->buf);
            co_htx_skip(req, req_htx, co_data(req));
            htx_to_buf(req_htx, &req->buf);
        }
    }

out:
    htx_to_buf(res_htx, &res->buf);
    if(!channel_is_empty(res)) {
        si_stop_get(si);
    }
}

int nst_cache_stats_init() {
    global.nuster.cache.stats =
        nst_cache_memory_alloc(sizeof(struct nst_cache_stats));

    if(!global.nuster.cache.stats) {
        return NST_ERR;
    }

    if(nst_shctx_init(global.nuster.cache.stats) != NST_OK) {
        return NST_ERR;
    }

    global.nuster.cache.stats->used_mem  = 0;
    global.nuster.cache.stats->req.total = 0;
    global.nuster.cache.stats->req.fetch = 0;
    global.nuster.cache.stats->req.hit   = 0;
    global.nuster.cache.stats->req.abort = 0;
    nuster.applet.cache_stats.fct        = nst_cache_stats_handler;

    return NST_OK;
}


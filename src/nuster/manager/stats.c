/*
 * nuster stats functions.
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

void
nst_stats_update_cache(int state) {
    nst_shctx_lock(global.nuster.stats);

    global.nuster.stats->cache.total++;

    switch(state) {
        case NST_CTX_STATE_HIT_MEMORY:
        case NST_CTX_STATE_HIT_DISK:
            global.nuster.stats->cache.hit++;
            break;
        case NST_CTX_STATE_CREATE:
            global.nuster.stats->cache.abort++;
            break;
        case NST_CTX_STATE_DONE:
            global.nuster.stats->cache.fetch++;
            break;
        default:
            break;
    }

    nst_shctx_unlock(global.nuster.stats);
}

void
nst_stats_update_nosql(int state) {
    nst_shctx_lock(global.nuster.stats);

    global.nuster.stats->nosql.total++;

    switch(state) {
        case NST_CTX_STATE_HIT_MEMORY:
        case NST_CTX_STATE_HIT_DISK:
            global.nuster.stats->nosql.get++;
            break;
        case NST_CTX_STATE_CREATE:
            global.nuster.stats->nosql.post++;
            break;
        case NST_CTX_STATE_DELETE:
            global.nuster.stats->nosql.delete++;
            break;
        default:
            break;
    }

    nst_shctx_unlock(global.nuster.stats);
}

/*
 * return 1 if the req is done, otherwise 0
 */

int
nst_stats_applet(hpx_stream_t *s, hpx_channel_t *req, hpx_proxy_t *px) {
    hpx_stream_interface_t  *si = &s->si[1];
    hpx_appctx_t            *appctx;

    s->target = &nuster.applet.stats.obj_type;

    if(unlikely(!si_register_handler(si, objt_applet(s->target)))) {
        return 1;
    } else {
        appctx      = si_appctx(si);
        appctx->st0 = NST_STATS_HEADER;
        appctx->st1 = px->uuid;
        appctx->st2 = 0;

        req->analysers &= (AN_REQ_HTTP_BODY | AN_REQ_FLT_HTTP_HDRS | AN_REQ_FLT_END);
        req->analysers &= ~AN_REQ_FLT_XFER_DATA;
        req->analysers |= AN_REQ_HTTP_XFER_BODY;

        return 1;
    }

}

static int
_nst_stats_header(hpx_appctx_t *appctx, hpx_stream_interface_t *si, hpx_htx_t *htx) {
    hpx_stream_t  *s = si_strm(si);
    hpx_htx_sl_t  *sl;
    unsigned int  flags;

    flags = (HTX_SL_F_IS_RESP|HTX_SL_F_VER_11|HTX_SL_F_XFER_ENC|HTX_SL_F_XFER_LEN|HTX_SL_F_CHNK);
    sl    = htx_add_stline(htx, HTX_BLK_RES_SL, flags, ist("HTTP/1.1"), ist("200"), ist("OK"));

    if(!sl) {
        goto full;
    }

    sl->info.res.status = 200;

    if(!htx_add_header(htx, ist("Cache-Control"), ist("no-cache"))) {
        goto full;
    }

    if(!htx_add_header(htx, ist("Content-Type"), ist("text/plain"))) {
        goto full;
    }

    if(!htx_add_endof(htx, HTX_BLK_EOH)) {
        goto full;
    }

    channel_add_input(&s->res, htx->data);

    return 1;

full:
    htx_reset(htx);
    si_rx_room_blk(si);

    return 0;
}

static int
_nst_stats_putdata(hpx_channel_t *chn, hpx_htx_t *htx, hpx_buffer_t *chk) {

    if(chk->data >= channel_htx_recv_max(chn, htx)) {
        return 0;
    }

    if(!htx_add_data_atonce(htx, ist2(chk->area, chk->data))) {
        return 0;
    }

    channel_add_input(chn, chk->data);
    chk->data = 0;

    return 1;
}

static int
_getMaxPaddingLen() {
    hpx_proxy_t  *p;
    int           max = 32;

    p = proxies_list;

    while(p) {

        if((p->cap & PR_CAP_BE)
                && (p->nuster.mode == NST_MODE_CACHE || p->nuster.mode == NST_MODE_NOSQL)) {

            nst_rule_t  *rule = NULL;
            int          s1   = strlen(p->id);

            rule = nuster.proxy[p->uuid]->rule;

            while(rule) {
                int  s2 = s1 + 8 + strlen(rule->name);

                if(s2 > max) {
                    max = s2;
                }

                rule = rule->next;
            }
        }

        p = p->next;
    }

    return max;
}

static int
_nst_stats_payload(hpx_appctx_t *appctx, hpx_stream_interface_t *si, hpx_htx_t *htx) {
    hpx_channel_t  *res = si_ic(si);
    int             len = _getMaxPaddingLen();

    chunk_reset(&trash);

    chunk_appendf(&trash, "**NUSTER**\n");

    chunk_appendf(&trash, "%-*s%s\n", len, "nuster.cache:",
            global.nuster.cache.status == NST_STATUS_ON ? "on" : "off");

    chunk_appendf(&trash, "%-*s%s\n", len, "nuster.nosql:",
            global.nuster.nosql.status == NST_STATUS_ON ? "on" : "off");

    chunk_appendf(&trash, "%-*s%s\n", len, "nuster.manager:",
            global.nuster.manager.status == NST_STATUS_ON ? "on" : "off");

    if(global.nuster.manager.status == NST_STATUS_ON) {
        chunk_appendf(&trash, "\n**MANAGER**\n");

        chunk_appendf(&trash, "%-*s%s\n", len, "manager.uri:", global.nuster.manager.uri.ptr);

        chunk_appendf(&trash, "%-*s%s\n", len, "manager.purge_method:",
                global.nuster.manager.purge_method.ptr);
    }

    chunk_appendf(&trash, "\n**MEMORY**\n");

    chunk_appendf(&trash, "%-*s%"PRIu64"\n", len, "memory.common.total:",
            global.nuster.memory->total);

    chunk_appendf(&trash, "%-*s%"PRIu64"\n", len, "memory.common.used:",
            global.nuster.memory->used);

    if(global.nuster.cache.status == NST_STATUS_ON) {
        chunk_appendf(&trash, "%-*s%"PRIu64"\n", len, "memory.cache.total:",
                global.nuster.cache.memory->total);

        chunk_appendf(&trash, "%-*s%"PRIu64"\n", len, "memory.cache.used:",
                global.nuster.cache.memory->used);
    }

    if(global.nuster.nosql.status == NST_STATUS_ON) {
        chunk_appendf(&trash, "%-*s%"PRIu64"\n", len, "memory.nosql.total:",
                global.nuster.nosql.memory->total);

        chunk_appendf(&trash, "%-*s%"PRIu64"\n", len, "memory.nosql.used:",
                global.nuster.nosql.memory->used);
    }

    if(global.nuster.cache.root.len || global.nuster.nosql.root.len) {
        chunk_appendf(&trash, "\n**PERSISTENCE**\n");
    }

    if(global.nuster.cache.root.len) {
        chunk_appendf(&trash, "%-*s%s\n", len, "persistence.cache.dir:",
                global.nuster.cache.root.ptr);

        chunk_appendf(&trash, "%-*s%s\n", len, "persistence.cache.loaded:",
            nuster.cache->store.disk.loaded ? "yes" : "no");
    }

    if(global.nuster.nosql.root.len) {
        chunk_appendf(&trash, "%-*s%s\n", len, "persistence.nosql.dir:",
                global.nuster.nosql.root.ptr);

        chunk_appendf(&trash, "%-*s%s\n", len, "persistence.nosql.loaded:",
            nuster.nosql->store.disk.loaded ? "yes" : "no");
    }

    if(global.nuster.cache.status == NST_STATUS_ON || global.nuster.nosql.status == NST_STATUS_ON) {
        chunk_appendf(&trash, "\n**STATISTICS**\n");
    }

    if(global.nuster.cache.status == NST_STATUS_ON) {
        chunk_appendf(&trash, "%-*s%"PRIu64"\n", len, "statistics.cache.total:",
                global.nuster.stats->cache.total);

        chunk_appendf(&trash, "%-*s%"PRIu64"\n", len, "statistics.cache.hit:",
                global.nuster.stats->cache.hit);

        chunk_appendf(&trash, "%-*s%"PRIu64"\n", len, "statistics.cache.fetch:",
                global.nuster.stats->cache.fetch);

        chunk_appendf(&trash, "%-*s%"PRIu64"\n", len, "statistics.cache.abort:",
                global.nuster.stats->cache.abort);
    }

    if(global.nuster.nosql.status == NST_STATUS_ON) {
        chunk_appendf(&trash, "%-*s%"PRIu64"\n", len, "statistics.nosql.total:",
                global.nuster.stats->nosql.total);

        chunk_appendf(&trash, "%-*s%"PRIu64"\n", len, "statistics.nosql.get:",
                global.nuster.stats->nosql.get);

        chunk_appendf(&trash, "%-*s%"PRIu64"\n", len, "statistics.nosql.post:",
                global.nuster.stats->nosql.post);

        chunk_appendf(&trash, "%-*s%"PRIu64"\n", len, "statistics.nosql.delete:",
                global.nuster.stats->nosql.delete);
    }

    if(!_nst_stats_putdata(res, htx, &trash)) {
        goto full;
    }

    return 1;

full:
    si_rx_room_blk(si);

    return 0;
}

static int
_nst_stats_proxy(hpx_appctx_t *appctx, hpx_stream_interface_t *si, hpx_htx_t *htx) {
    hpx_channel_t  *res = si_ic(si);
    hpx_proxy_t    *p;
    int             len = _getMaxPaddingLen();

    chunk_reset(&trash);

    p = proxies_list;

    while(p) {
        nst_rule_t  *rule = NULL;

        if(htx_almost_full(htx)) {
            si_rx_room_blk(si);

            return 0;
        }

        if(p->uuid != appctx->st1) {
            goto next;
        }

        if((p->cap & PR_CAP_BE)
                && (p->nuster.mode == NST_MODE_CACHE || p->nuster.mode == NST_MODE_NOSQL)) {

            rule = nuster.proxy[p->uuid]->rule;

            while(rule) {

                if(htx_almost_full(htx)) {
                    si_rx_room_blk(si);

                    return 0;
                }

                if(rule->uuid == appctx->st2) {
                    int  i = len - strlen(p->id) - 8 - strlen(rule->name);

                    if(rule->idx == 0) {
                        chunk_printf(&trash, "\n**PROXY %s %s**\n",
                                p->nuster.mode == NST_MODE_CACHE ? "cache" : "nosql",
                                p->id);
                    }

                    chunk_appendf(&trash, "%s.rule.%s: ", p->id, rule->name);

                    while(i--) {
                        chunk_appendf(&trash, " ");
                    }

                    chunk_appendf(&trash, "state=%-4sdisk=%-6sttl=%"PRIu32"\n",
                            rule->state == NST_RULE_ENABLED ? "on" : "off",
                            rule->disk == NST_DISK_OFF ? "off"
                            : rule->disk == NST_DISK_ONLY ? "only"
                            : rule->disk == NST_DISK_SYNC ? "sync"
                            : rule->disk == NST_DISK_ASYNC ? "async"
                            : "invalid",
                            rule->ttl
                            );

                    if(!_nst_stats_putdata(res, htx, &trash)) {
                        goto full;
                    }

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

full:
    si_rx_room_blk(si);

    return 0;
}

static void
nst_stats_handler(hpx_appctx_t *appctx) {
    hpx_stream_interface_t  *si  = appctx->owner;
    hpx_channel_t           *req = si_oc(si);
    hpx_channel_t           *res = si_ic(si);
    hpx_stream_t            *s   = si_strm(si);
    hpx_htx_t               *req_htx, *res_htx;

    req_htx = htx_from_buf(&req->buf);
    res_htx = htx_from_buf(&res->buf);

    if(appctx->st0 == NST_STATS_HEADER) {

        if(_nst_stats_header(appctx, si, res_htx)) {
            appctx->st0 = NST_STATS_PAYLOAD;
        }
    }

    if(appctx->st0 == NST_STATS_PAYLOAD) {

        if(_nst_stats_payload(appctx, si, res_htx)) {
            appctx->st0 = NST_STATS_PROXY;
        }
    }

    if(appctx->st0 == NST_STATS_PROXY) {

        if(_nst_stats_proxy(appctx, si, res_htx)) {
            appctx->st0 = NST_STATS_DONE;
        }
    }

    if(appctx->st0 == NST_STATS_DONE) {

        if(!htx_add_endof(res_htx, HTX_BLK_EOM)) {
            si_rx_room_blk(si);

            goto out;
        }

        channel_add_input(&s->res, 1);

        if(!(res->flags & CF_SHUTR)) {
            res->flags |= CF_READ_NULL;
            si_shutr(si);
        }

        /* eat the whole request */
        if(co_data(req)) {
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

int
nst_stats_init() {
    global.nuster.stats = nst_memory_alloc(global.nuster.memory, sizeof(nst_stats_t));

    if(!global.nuster.stats) {
        return NST_ERR;
    }

    memset(global.nuster.stats, 0, sizeof(nst_stats_t));

    if(nst_shctx_init(global.nuster.stats) != NST_OK) {
        return NST_ERR;
    }

    nuster.applet.stats.fct = nst_stats_handler;

    return NST_OK;
}


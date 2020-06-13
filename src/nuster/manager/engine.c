/*
 * nuster manager functions.
 *
 * Copyright (C) Jiang Wenyuan, < koubunen AT gmail DOT com >
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/http.h>
#include <haproxy/proxy.h>
#include <haproxy/http_htx.h>
#include <haproxy/stream_interface.h>

#include <nuster/nuster.h>

static int
_nst_manager_set_state_ttl(hpx_stream_t *s, hpx_channel_t *req, hpx_proxy_t *px,
        int state, int ttl) {

    hpx_http_hdr_ctx_t  hdr = { .blk = NULL };
    hpx_proxy_t        *p;
    hpx_htx_t          *htx = htxbuf(&s->req.buf);
    int                 found, method, ret;

    method = NST_MANAGER_RULE;
    ret    = NST_HTTP_400;

    if(state == -1 && ttl == -1) {
        goto end;
    }

    if(http_find_header(htx, ist("name"), &hdr, 0)) {

        if(isteq(hdr.value, ist("*"))) {
            method = NST_MANAGER_ALL;
            found  = 1;
        }

        p = proxies_list;

        while(p) {
            nst_rule_t *rule = NULL;

            if(p->nuster.mode == NST_MODE_CACHE || p->nuster.mode == NST_MODE_NOSQL) {

                if(method != NST_MANAGER_ALL && strlen(p->id) == hdr.value.len
                        && !memcmp(hdr.value.ptr, p->id, hdr.value.len)) {

                    method = NST_MANAGER_PROXY;
                    found  = 1;
                }

                rule = nuster.proxy[p->uuid]->rule;

                while(rule) {

                    if(method != NST_MANAGER_RULE) {
                        rule->state    = state == -1 ? rule->state    : state;
                        rule->prop.ttl = ttl   == -1 ? rule->prop.ttl : ttl;
                    } else if(isteq(rule->prop.rid, hdr.value)) {
                        rule->state    = state == -1 ? rule->state    : state;
                        rule->prop.ttl = ttl   == -1 ? rule->prop.ttl : ttl;
                        found          = 1;
                    }

                    rule = rule->next;
                }

                if(method == NST_MANAGER_PROXY) {
                    break;
                }

            }

            p = p->next;
        }

        if(found) {
            ret = NST_HTTP_200;
        } else {
            ret = NST_HTTP_404;
        }
    }

end:

    nst_http_reply(s, ret);

    return 1;
}

static int
_nst_manager_check_uri(hpx_http_msg_t *msg) {
    hpx_htx_sl_t  *sl;
    hpx_htx_t     *htx;
    hpx_ist_t      url, uri;

    if(!global.nuster.manager.uri.len) {
        return NST_ERR;
    }

    htx = htxbuf(&msg->chn->buf);
    sl  = http_get_stline(htx);
    url = htx_sl_req_uri(sl);
    uri = http_get_path(url);

    if(!isteq(global.nuster.manager.uri, uri)) {
        return NST_ERR;
    }

    return NST_OK;
}

static inline int
_nst_manager_check_purge_method(hpx_http_txn_t *txn, hpx_http_msg_t *msg) {
    hpx_http_meth_t  meth = txn->meth;
    hpx_htx_t       *htx  = htxbuf(&msg->chn->buf);
    hpx_htx_sl_t    *sl   = http_get_stline(htx);

    if(meth == HTTP_METH_OTHER && isteqi(htx_sl_req_meth(sl), global.nuster.manager.purge_method)) {
        return NST_OK;
    } else {
        return NST_ERR;
    }
}

/*
 * return 1 if the request is done, otherwise 0
 */
int
nst_manager(hpx_stream_t *s, hpx_channel_t *req, hpx_proxy_t *px) {
    hpx_http_hdr_ctx_t  hdr = { .blk = NULL };
    hpx_http_txn_t     *txn = s->txn;
    hpx_http_msg_t     *msg = &txn->req;
    hpx_htx_t          *htx = htxbuf(&s->req.buf);

    if(global.nuster.manager.status != NST_STATUS_ON) {
        return 0;
    }

    if(global.nuster.cache.status == NST_STATUS_OFF
            && global.nuster.nosql.status == NST_STATUS_OFF) {

        return 0;
    }

    if(_nst_manager_check_purge_method(txn, msg) == NST_OK) {
        /* single uri */
        return nst_purger_basic(s, req, px);
    } else {
        if(_nst_manager_check_uri(msg) == NST_OK) {

            if(txn->meth == HTTP_METH_GET) {
                /* stats */
                return nst_stats_applet(s, req, px);
            } else if(txn->meth == HTTP_METH_POST) {
                int  state = -1;
                int  ttl   = -1;

                /* manager */
                if(http_find_header(htx, ist("state"), &hdr, 0)) {

                    if(isteq(hdr.value, ist("enable"))) {
                        state = NST_RULE_ENABLED;
                    } else if(isteq(hdr.value, ist("disable"))) {
                        state = NST_RULE_DISABLED;
                    }
                }

                hdr.blk = NULL;

                if(http_find_header(htx, ist("ttl"), &hdr, 0)) {
                    int  ret = nst_parse_time(hdr.value.ptr, hdr.value.len, (unsigned *)&ttl);

                    if(ret == NST_TIME_ERR) {
                        ttl = -1;
                    } else if(ret == NST_TIME_OVER) {
                        ttl = INT_MAX;
                    }
                }

                return _nst_manager_set_state_ttl(s, req, px, state, ttl);
            } else if(txn->meth == HTTP_METH_DELETE) {
                /* purge */
                return nst_purger_advanced(s, req, px);
            } else {
                return 0;
            }
        } else {
            return 0;
        }
    }

    return 1;
}

void
nst_manager_init() {
    nst_purger_init();

    if(nst_stats_init() != NST_OK) {
        ha_alert("Out of memory when initializing stats.\n");
        exit(1);
    }
}

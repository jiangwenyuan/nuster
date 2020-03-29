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

#include <types/global.h>

#include <proto/http_ana.h>
#include <proto/stream_interface.h>
#include <proto/proxy.h>
#include <proto/http_htx.h>
#include <common/htx.h>

#include <nuster/nuster.h>

static int _nst_manager_set_state_ttl(struct stream *s, struct channel *req, struct proxy *px,
        int state, int ttl) {

    int found, mode = NST_MANAGER_NAME_RULE;
    struct proxy *p;

    struct htx *htx = htxbuf(&s->req.buf);
    struct http_hdr_ctx hdr = { .blk = NULL };
    int ret = NST_HTTP_400;

    if(state == -1 && ttl == -1) {
        goto end;
    }

    if(http_find_header(htx, ist("name"), &hdr, 0)) {

        if(isteq(hdr.value, ist("*"))) {
            found = 1;
            mode  = NST_MANAGER_NAME_ALL;
        }

        p = proxies_list;

        while(p) {
            struct nst_rule *rule = NULL;

            if((p->cap & PR_CAP_BE)
                    && (p->nuster.mode == NST_MODE_CACHE || p->nuster.mode == NST_MODE_NOSQL)) {

                if(mode != NST_MANAGER_NAME_ALL && strlen(p->id) == hdr.value.len
                        && !memcmp(hdr.value.ptr, p->id, hdr.value.len)) {

                    found = 1;
                    mode  = NST_MANAGER_NAME_PROXY;
                }

                rule = nuster.proxy[p->uuid]->rule;

                while(rule) {

                    if(mode != NST_MANAGER_NAME_RULE) {
                        rule->state = state == -1 ? rule->state : state;
                        rule->ttl   = ttl   == -1 ? rule->ttl   : ttl;
                    } else if(strlen(rule->name) == hdr.value.len
                            && !memcmp(hdr.value.ptr, rule->name, hdr.value.len)) {

                        rule->state = state == -1 ? rule->state : state;
                        rule->ttl   = ttl   == -1 ? rule->ttl   : ttl;
                        found       = 1;
                    }

                    rule = rule->next;
                }

                if(mode == NST_MANAGER_NAME_PROXY) {
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

static int _nst_manager_check_uri(struct http_msg *msg) {
    struct htx *htx;
    struct htx_sl *sl;
    struct ist url, uri;

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

static inline int _nst_manager_check_purge_method(struct http_txn *txn, struct http_msg *msg) {

    struct htx *htx = htxbuf(&msg->chn->buf);
    struct htx_sl *sl = http_get_stline(htx);

    if(txn->meth == HTTP_METH_OTHER
        && isteqi(htx_sl_req_meth(sl), global.nuster.manager.purge_method)) {
        return NST_OK;
    } else {
        return NST_ERR;
    }
}

/*
 * return 1 if the request is done, otherwise 0
 */
int nst_manager(struct stream *s, struct channel *req, struct proxy *px) {
    struct http_txn *txn = s->txn;
    struct http_msg *msg = &txn->req;
    struct htx *htx      = htxbuf(&s->req.buf);

    struct http_hdr_ctx hdr = { .blk = NULL };

    if(global.nuster.manager.status != NST_STATUS_ON) {
        return 0;
    }

    if(px->nuster.mode != NST_MODE_CACHE && px->nuster.mode != NST_MODE_NOSQL) {
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
                int state = -1;
                int ttl   = -1;

                /* manager */
                if(http_find_header(htx, ist("state"), &hdr, 0)) {

                    if(isteq(hdr.value, ist("enable"))) {
                        state = NST_RULE_ENABLED;
                    } else if(isteq(hdr.value, ist("disable"))) {
                        state = NST_RULE_DISABLED;
                    }
                }

                if(http_find_header(htx, ist("ttl"), &hdr, 0)) {
                    nst_parse_time(hdr.value.ptr, hdr.value.len, (unsigned *)&ttl);
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

void nst_manager_init() {
    nst_purger_init();

    if(nst_stats_init() != NST_OK) {
        ha_alert("Out of memory when initializing stats.\n");
        exit(1);
    }
}

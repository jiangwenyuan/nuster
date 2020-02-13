/*
 * nuster cache manager functions.
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
#include <nuster/memory.h>
#include <nuster/shctx.h>
#include <nuster/http.h>

/*
 * purge cache by key
 */
int _nst_cache_purge_by_key(struct buffer *key, uint64_t hash) {
    struct nst_cache_entry *entry = NULL;
    int ret;

    nst_shctx_lock(&nuster.cache->dict[0]);
    entry = nst_cache_dict_get(key, hash);

    if(entry) {

        if(entry->state == NST_CACHE_ENTRY_STATE_VALID) {
            entry->state         = NST_CACHE_ENTRY_STATE_EXPIRED;
            entry->data->invalid = 1;
            entry->data          = NULL;
            entry->expire        = 0;
            ret                  = 200;
        }

        if(entry->file) {
            ret = nst_persist_purge_by_path(entry->file);
        }
    } else {
        ret = 404;
    }

    nst_shctx_unlock(&nuster.cache->dict[0]);

    if(!nuster.cache->disk.loaded && global.nuster.cache.root){
        struct persist disk;

        disk.file = nst_cache_memory_alloc(
                nst_persist_path_file_len(global.nuster.cache.root) + 1);

        if(!disk.file) {
            ret = 500;
        } else {
            ret = nst_persist_purge_by_key(global.nuster.cache.root,
                    &disk, key, hash);
        }

        nst_cache_memory_free(disk.file);
    }

    return ret;
}

int nst_cache_purge(struct stream *s, struct channel *req, struct proxy *px) {
    struct http_txn *txn = s->txn;
    struct http_msg *msg = &txn->req;

    struct buffer *key = nst_cache_build_purge_key(s, msg);

    if(!key) {
        txn->status = 500;
        nst_response(s, &nst_http_msg_chunks[NST_HTTP_500]);
    } else {
        uint64_t hash = nst_hash(key->area, key->data);
        txn->status = _nst_cache_purge_by_key(key, hash);

        if(txn->status == 200) {
            nst_response(s, &nst_http_msg_chunks[NST_HTTP_200]);
        } else {
            nst_response(s, &nst_http_msg_chunks[NST_HTTP_404]);
        }
    }

    return 1;
}

int nst_cache_purge2(struct stream *s, struct channel *req, struct proxy *px) {
    struct http_txn *txn = s->txn;
    struct http_msg *msg = &txn->req;

    struct buffer *key = nst_cache_build_purge_key2(s, msg);

    if(!key) {
        txn->status = 500;
        htx_reply_and_close(s, txn->status, htx_error_message(s));
    } else {
        uint64_t hash = nst_hash(key->area, key->data);
        txn->status = _nst_cache_purge_by_key(key, hash);

        if(txn->status == 200) {
            htx_reply_and_close(s, txn->status, htx_error_message(s));
        } else {
            htx_reply_and_close(s, txn->status, htx_error_message(s));
        }
    }

    return 1;
}

int _nst_cache_manager_state_ttl(struct stream *s, struct channel *req,
        struct proxy *px, int state, int ttl) {

    struct http_txn *txn = s->txn;
    struct http_msg *msg = &txn->req;
    int found, mode      = NST_CACHE_PURGE_NAME_RULE;
    struct hdr_ctx ctx;
    struct proxy *p;

    if(state == -1 && ttl == -1) {
        return 400;
    }

    ctx.idx = 0;
    if(http_find_header2("name", 4, ci_head(msg->chn), &txn->hdr_idx, &ctx)) {

        if(ctx.vlen == 1 && !memcmp(ctx.line + ctx.val, "*", 1)) {
            found = 1;
            mode  = NST_CACHE_PURGE_NAME_ALL;
        }

        p = proxies_list;
        while(p) {
            struct nst_rule *rule = NULL;

            if(mode != NST_CACHE_PURGE_NAME_ALL
                    && strlen(p->id) == ctx.vlen
                    && !memcmp(ctx.line + ctx.val, p->id, ctx.vlen)) {

                found = 1;
                mode  = NST_CACHE_PURGE_NAME_PROXY;
            }

            list_for_each_entry(rule, &p->nuster.rules, list) {

                if(mode != NST_CACHE_PURGE_NAME_RULE) {
                    *rule->state = state == -1 ? *rule->state : state;
                    *rule->ttl   = ttl   == -1 ? *rule->ttl   : ttl;
                } else if(strlen(rule->name) == ctx.vlen
                        && !memcmp(ctx.line + ctx.val, rule->name, ctx.vlen)) {

                    *rule->state = state == -1 ? *rule->state : state;
                    *rule->ttl   = ttl   == -1 ? *rule->ttl   : ttl;
                    found        = 1;
                }
            }

            if(mode == NST_CACHE_PURGE_NAME_PROXY) {
                break;
            }

            p = p->next;
        }

        if(found) {
            return 200;
        } else {
            return 404;
        }
    }

    return 400;
}

int _nst_cache_manager_state_ttl2(struct stream *s, struct channel *req,
        struct proxy *px, int state, int ttl) {

    int found, mode      = NST_CACHE_PURGE_NAME_RULE;
    struct proxy *p;

    struct htx *htx = htxbuf(&s->req.buf);
    struct http_hdr_ctx hdr2 = { .blk = NULL };

    if(state == -1 && ttl == -1) {
        return 400;
    }

    if(http_find_header(htx, ist("name"), &hdr2, 0)) {

        if(hdr2.value.len == 1 && !memcmp(hdr2.value.ptr, "*", 1)) {
            found = 1;
            mode  = NST_CACHE_PURGE_NAME_ALL;
        }

        p = proxies_list;
        while(p) {
            struct nst_rule *rule = NULL;

            if(mode != NST_CACHE_PURGE_NAME_ALL
                    && strlen(p->id) == hdr2.value.len
                    && !memcmp(hdr2.value.ptr, p->id, hdr2.value.len)) {

                found = 1;
                mode  = NST_CACHE_PURGE_NAME_PROXY;
            }

            list_for_each_entry(rule, &p->nuster.rules, list) {

                if(mode != NST_CACHE_PURGE_NAME_RULE) {
                    *rule->state = state == -1 ? *rule->state : state;
                    *rule->ttl   = ttl   == -1 ? *rule->ttl   : ttl;
                } else if(strlen(rule->name) == hdr2.value.len
                        && !memcmp(hdr2.value.ptr, rule->name, hdr2.value.len)) {

                    *rule->state = state == -1 ? *rule->state : state;
                    *rule->ttl   = ttl   == -1 ? *rule->ttl   : ttl;
                    found        = 1;
                }
            }

            if(mode == NST_CACHE_PURGE_NAME_PROXY) {
                break;
            }

            p = p->next;
        }

        if(found) {
            return 200;
        } else {
            return 404;
        }
    }

    return 400;
}

static inline int _nst_cache_manager_purge_method(struct http_txn *txn,
        struct http_msg *msg) {

    return txn->meth == HTTP_METH_OTHER &&
            memcmp(ci_head(msg->chn), global.nuster.cache.purge_method,
                    strlen(global.nuster.cache.purge_method)) == 0;
}

static inline int _nst_cache_manager_purge_method2(struct http_txn *txn,
        struct http_msg *msg) {

    struct htx *htx = htxbuf(&msg->chn->buf);
    struct htx_sl *sl = http_get_stline(htx);

    // parser.c:345: memcpy(global.nuster.cache.purge_method + 5, " ", 1);
    return txn->meth == HTTP_METH_OTHER
        && isteqi(htx_sl_req_meth(sl), ist2(global.nuster.cache.purge_method,
                    strlen(global.nuster.cache.purge_method) - 1));
}

int _nst_cache_manager_purge(struct stream *s, struct channel *req,
        struct proxy *px) {

    struct stream_interface *si = &s->si[1];
    struct http_txn *txn        = s->txn;
    struct http_msg *msg        = &txn->req;
    struct appctx *appctx       = NULL;
    int mode                    = NST_CACHE_PURGE_NAME_RULE;
    int st1                     = 0;
    char *host                  = NULL;
    char *path                  = NULL;
    struct my_regex *regex      = NULL;
    char *error                 = NULL;
    char *regex_str             = NULL;
    int host_len                = 0;
    int path_len                = 0;
    struct hdr_ctx ctx;
    struct proxy *p;

    ctx.idx = 0;
    if(http_find_header2("x-host", 6, ci_head(msg->chn), &txn->hdr_idx, &ctx)) {
        host     = ctx.line + ctx.val;
        host_len = ctx.vlen;
    }

    ctx.idx = 0;
    if(http_find_header2("name", 4, ci_head(msg->chn), &txn->hdr_idx, &ctx)) {

        if(ctx.vlen == 1 && !memcmp(ctx.line + ctx.val, "*", 1)) {
            mode = NST_CACHE_PURGE_NAME_ALL;
            goto purge;
        }

        p = proxies_list;
        while(p) {
            struct nst_rule *rule = NULL;

            if(p->nuster.mode == NST_MODE_CACHE) {

                if(mode != NST_CACHE_PURGE_NAME_ALL
                        && strlen(p->id) == ctx.vlen
                        && !memcmp(ctx.line + ctx.val, p->id, ctx.vlen)) {

                    mode = NST_CACHE_PURGE_NAME_PROXY;
                    st1  = p->uuid;
                    goto purge;
                }

                list_for_each_entry(rule, &p->nuster.rules, list) {

                    if(strlen(rule->name) == ctx.vlen
                            && !memcmp(ctx.line + ctx.val, rule->name,
                                ctx.vlen)) {

                        mode = NST_CACHE_PURGE_NAME_RULE;
                        st1  = rule->id;
                        goto purge;
                    }
                }
            }

            p = p->next;
        }

        goto notfound;
    } else if(http_find_header2("path", 4, ci_head(msg->chn),
                &txn->hdr_idx, &ctx)) {

        path      = ctx.line + ctx.val;
        path_len  = ctx.vlen;
        mode      = host ? NST_CACHE_PURGE_PATH_HOST : NST_CACHE_PURGE_PATH;
    } else if(http_find_header2("regex", 5, ci_head(msg->chn), &txn->hdr_idx,
                &ctx)) {

        regex_str = malloc(ctx.vlen + 1);

        if(!regex_str) {
            goto err;
        }

        memcpy(regex_str, ctx.line + ctx.val, ctx.vlen);
        regex_str[ctx.vlen] = '\0';

        if(!(regex = regex_comp(regex_str, 1, 0, &error))) {
            goto err;
        }

        free(regex_str);
        regex_free(regex);

        mode = host ? NST_CACHE_PURGE_REGEX_HOST : NST_CACHE_PURGE_REGEX;
    } else if(host) {
        mode = NST_CACHE_PURGE_HOST;
    } else {
        goto badreq;
    }

purge:
    s->target = &nuster.applet.cache_manager.obj_type;

    if(unlikely(!si_register_handler(si, objt_applet(s->target)))) {
        goto err;
    } else {
        appctx      = si_appctx(si);
        memset(&appctx->ctx.nuster.cache_manager, 0,
                sizeof(appctx->ctx.nuster.cache_manager));

        appctx->st0 = mode;
        appctx->st1 = st1;
        appctx->st2 = 0;

        if(mode == NST_CACHE_PURGE_HOST
                || mode == NST_CACHE_PURGE_PATH_HOST
                || mode == NST_CACHE_PURGE_REGEX_HOST) {

            appctx->ctx.nuster.cache_manager.host.data =
                nst_cache_memory_alloc(host_len);

            appctx->ctx.nuster.cache_manager.host.len  = host_len;

            if(!appctx->ctx.nuster.cache_manager.host.data) {
                goto err;
            }

            memcpy(appctx->ctx.nuster.cache_manager.host.data, host, host_len);
        }

        if(mode == NST_CACHE_PURGE_PATH || mode == NST_CACHE_PURGE_PATH_HOST) {

            appctx->ctx.nuster.cache_manager.path.data =
                nst_cache_memory_alloc(path_len);

            appctx->ctx.nuster.cache_manager.path.len  = path_len;

            if(!appctx->ctx.nuster.cache_manager.path.data) {
                goto err;
            }

            memcpy(appctx->ctx.nuster.cache_manager.path.data, path, path_len);
        } else if(mode == NST_CACHE_PURGE_REGEX ||
                mode == NST_CACHE_PURGE_REGEX_HOST) {

            appctx->ctx.nuster.cache_manager.regex = regex;
        }

        req->analysers &=
            (AN_REQ_HTTP_BODY | AN_REQ_FLT_HTTP_HDRS | AN_REQ_FLT_END);

        req->analysers &= ~AN_REQ_FLT_XFER_DATA;
        req->analysers |= AN_REQ_HTTP_XFER_BODY;
    }

    return 0;

notfound:
    return 404;

err:
    free(error);
    free(regex_str);

    if(regex) {
        regex_free(regex);
    }

    return 500;

badreq:
    return 400;
}

int _nst_cache_manager_purge2(struct stream *s, struct channel *req,
        struct proxy *px) {

    struct stream_interface *si = &s->si[1];
    struct appctx *appctx       = NULL;
    int mode                    = NST_CACHE_PURGE_NAME_RULE;
    int st1                     = 0;
    char *host                  = NULL;
    char *path                  = NULL;
    struct my_regex *regex      = NULL;
    char *error                 = NULL;
    char *regex_str             = NULL;
    int host_len                = 0;
    int path_len                = 0;
    struct proxy *p;

    struct htx *htx = htxbuf(&s->req.buf);
    struct http_hdr_ctx hdr2 = { .blk = NULL };

    if(http_find_header(htx, ist("x-host"), &hdr2, 0)) {
        host     = hdr2.value.ptr;
        host_len = hdr2.value.len;
    }

    if(http_find_header(htx, ist("name"), &hdr2, 0)) {

        if(hdr2.value.len == 1 && !memcmp(hdr2.value.ptr, "*", 1)) {
            mode = NST_CACHE_PURGE_NAME_ALL;
            goto purge;
        }

        p = proxies_list;
        while(p) {
            struct nst_rule *rule = NULL;

            if(p->nuster.mode == NST_MODE_CACHE) {

                if(mode != NST_CACHE_PURGE_NAME_ALL
                        && strlen(p->id) == hdr2.value.len
                        && !memcmp(hdr2.value.ptr, p->id, hdr2.value.len)) {

                    mode = NST_CACHE_PURGE_NAME_PROXY;
                    st1  = p->uuid;
                    goto purge;
                }

                list_for_each_entry(rule, &p->nuster.rules, list) {

                    if(strlen(rule->name) == hdr2.value.len
                            && !memcmp(hdr2.value.ptr, rule->name,
                                hdr2.value.len)) {

                        mode = NST_CACHE_PURGE_NAME_RULE;
                        st1  = rule->id;
                        goto purge;
                    }
                }
            }

            p = p->next;
        }

        goto notfound;
    } else if(http_find_header(htx, ist("path"), &hdr2, 0)) {
        path      = hdr2.value.ptr;
        path_len  = hdr2.value.len;
        mode      = host ? NST_CACHE_PURGE_PATH_HOST : NST_CACHE_PURGE_PATH;
    } else if(http_find_header(htx, ist("regex"), &hdr2, 0)) {

        regex_str = malloc(hdr2.value.len + 1);

        if(!regex_str) {
            goto err;
        }

        memcpy(regex_str, hdr2.value.ptr, hdr2.value.len);
        regex_str[hdr2.value.len] = '\0';

        if(!(regex = regex_comp(regex_str, 1, 0, &error))) {
            goto err;
        }

        free(regex_str);
        regex_free(regex);

        mode = host ? NST_CACHE_PURGE_REGEX_HOST : NST_CACHE_PURGE_REGEX;
    } else if(host) {
        mode = NST_CACHE_PURGE_HOST;
    } else {
        goto badreq;
    }

purge:
    s->target = &nuster.applet.cache_manager.obj_type;

    if(unlikely(!si_register_handler(si, objt_applet(s->target)))) {
        goto err;
    } else {
        appctx      = si_appctx(si);
        memset(&appctx->ctx.nuster.cache_manager, 0,
                sizeof(appctx->ctx.nuster.cache_manager));

        appctx->st0 = mode;
        appctx->st1 = st1;
        appctx->st2 = 0;

        if(mode == NST_CACHE_PURGE_HOST
                || mode == NST_CACHE_PURGE_PATH_HOST
                || mode == NST_CACHE_PURGE_REGEX_HOST) {

            appctx->ctx.nuster.cache_manager.host.data =
                nst_cache_memory_alloc(host_len);

            appctx->ctx.nuster.cache_manager.host.len  = host_len;

            if(!appctx->ctx.nuster.cache_manager.host.data) {
                goto err;
            }

            memcpy(appctx->ctx.nuster.cache_manager.host.data, host, host_len);
        }

        if(mode == NST_CACHE_PURGE_PATH || mode == NST_CACHE_PURGE_PATH_HOST) {

            appctx->ctx.nuster.cache_manager.path.data =
                nst_cache_memory_alloc(path_len);

            appctx->ctx.nuster.cache_manager.path.len  = path_len;

            if(!appctx->ctx.nuster.cache_manager.path.data) {
                goto err;
            }

            memcpy(appctx->ctx.nuster.cache_manager.path.data, path, path_len);
        } else if(mode == NST_CACHE_PURGE_REGEX ||
                mode == NST_CACHE_PURGE_REGEX_HOST) {

            appctx->ctx.nuster.cache_manager.regex = regex;
        }

        req->analysers &=
            (AN_REQ_HTTP_BODY | AN_REQ_FLT_HTTP_HDRS | AN_REQ_FLT_END);

        req->analysers &= ~AN_REQ_FLT_XFER_DATA;
        req->analysers |= AN_REQ_HTTP_XFER_BODY;
    }

    return 0;

notfound:
    return 404;

err:
    free(error);
    free(regex_str);

    if(regex) {
        regex_free(regex);
    }

    return 500;

badreq:
    return 400;
}

/*
 * return 1 if the request is done, otherwise 0
 */
int nst_cache_manager(struct stream *s, struct channel *req, struct proxy *px) {
    struct http_txn *txn = s->txn;
    struct http_msg *msg = &txn->req;
    int state            = -1;
    int ttl              = -1;
    struct hdr_ctx ctx;

    if(global.nuster.cache.status != NST_STATUS_ON) {
        return 0;
    }

    if(txn->meth == HTTP_METH_POST) {

        /* POST */
        if(nst_cache_check_uri(msg) == NST_OK) {
            /* manager uri */
            ctx.idx = 0;
            if(http_find_header2("state", 5, ci_head(msg->chn),
                        &txn->hdr_idx, &ctx)) {

                if(ctx.vlen == 6 && !memcmp(ctx.line + ctx.val, "enable", 6)) {
                    state = NST_RULE_ENABLED;
                } else if(ctx.vlen == 7
                        && !memcmp(ctx.line + ctx.val, "disable", 7)) {

                    state = NST_RULE_DISABLED;
                }
            }

            ctx.idx = 0;
            if(http_find_header2("ttl", 3, ci_head(msg->chn),
                        &txn->hdr_idx, &ctx)) {

                nst_parse_time(ctx.line + ctx.val, ctx.vlen, (unsigned *)&ttl);
            }

            txn->status = _nst_cache_manager_state_ttl(s, req, px, state, ttl);
        } else {
            return 0;
        }
    } else if(_nst_cache_manager_purge_method(txn, msg)) {

        /* purge */
        if(nst_cache_check_uri(msg) == NST_OK) {

            /* manager uri */
            txn->status = _nst_cache_manager_purge(s, req, px);

            if(txn->status == 0) {
                return 0;
            }
        } else {
            /* single uri */
            return nst_cache_purge(s, req, px);
        }
    } else {
        return 0;
    }

    switch(txn->status) {
        case 200:
            nst_response(s, &nst_http_msg_chunks[NST_HTTP_200]);
            break;
        case 400:
            nst_response(s, &nst_http_msg_chunks[NST_HTTP_400]);
            break;
        case 404:
            nst_response(s, &nst_http_msg_chunks[NST_HTTP_404]);
            break;
        case 500:
            nst_response(s, &nst_http_msg_chunks[NST_HTTP_500]);
            break;
        default:
            nst_response(s, &nst_http_msg_chunks[NST_HTTP_400]);
    }
    return 1;
}

int nst_cache_manager2(struct stream *s, struct channel *req, struct proxy *px) {
    struct http_txn *txn = s->txn;
    struct http_msg *msg = &txn->req;
    int state            = -1;
    int ttl              = -1;
    struct htx *htx = htxbuf(&s->req.buf);
    struct http_hdr_ctx hdr2 = { .blk = NULL };

    if(global.nuster.cache.status != NST_STATUS_ON) {
        return 0;
    }

    if(txn->meth == HTTP_METH_POST) {

        /* POST */
        if(nst_cache_check_uri2(msg) == NST_OK) {
            /* manager uri */
            if(http_find_header(htx, ist("state"), &hdr2, 0)) {

                if(hdr2.value.len == 6
                        && !memcmp(hdr2.value.ptr, "enable", 6)) {

                    state = NST_RULE_ENABLED;
                } else if(hdr2.value.len == 7
                        && !memcmp(hdr2.value.ptr, "disable", 7)) {

                    state = NST_RULE_DISABLED;
                }
            }

            if(http_find_header(htx, ist("ttl"), &hdr2, 0)) {

                nst_parse_time(hdr2.value.ptr, hdr2.value.len, (unsigned *)&ttl);
            }

            txn->status = _nst_cache_manager_state_ttl2(s, req, px, state, ttl);
        } else {
            return 0;
        }
    } else if(_nst_cache_manager_purge_method2(txn, msg)) {

        /* purge */
        if(nst_cache_check_uri2(msg) == NST_OK) {

            /* manager uri */
            txn->status = _nst_cache_manager_purge2(s, req, px);

            if(txn->status == 0) {
                return 0;
            }
        } else {
            /* single uri */
            return nst_cache_purge2(s, req, px);
        }
    } else {
        return 0;
    }

    switch(txn->status) {
        case 200:
            htx_reply_and_close(s, txn->status, htx_error_message(s));
            break;
        case 400:
            htx_reply_and_close(s, txn->status, htx_error_message(s));
            break;
        case 404:
            htx_reply_and_close(s, txn->status, htx_error_message(s));
            break;
        case 500:
            htx_reply_and_close(s, txn->status, htx_error_message(s));
            break;
        default:
            htx_reply_and_close(s, txn->status, htx_error_message(s));
    }
    return 1;
}


static int _nst_cache_manager_should_purge(struct nst_cache_entry *entry,
        struct appctx *appctx) {

    int ret = 0;
    switch(appctx->st0) {
        case NST_CACHE_PURGE_NAME_ALL:
            ret = 1;
            break;
        case NST_CACHE_PURGE_NAME_PROXY:
            ret = entry->pid == appctx->st1;
            break;
        case NST_CACHE_PURGE_NAME_RULE:
            ret = entry->rule && entry->rule->id == appctx->st1;
            break;
        case NST_CACHE_PURGE_PATH:
            ret = entry->path.len == appctx->ctx.nuster.cache_manager.path.len
                && !memcmp(entry->path.data,
                        appctx->ctx.nuster.cache_manager.path.data,
                        entry->path.len);

            break;
        case NST_CACHE_PURGE_REGEX:
            ret = regex_exec(appctx->ctx.nuster.cache_manager.regex,
                    entry->path.data);

            break;
        case NST_CACHE_PURGE_HOST:
            ret = entry->host.len == appctx->ctx.nuster.cache_manager.host.len
                && !memcmp(entry->host.data,
                        appctx->ctx.nuster.cache_manager.host.data,
                        entry->host.len);

            break;
        case NST_CACHE_PURGE_PATH_HOST:
            ret = entry->path.len == appctx->ctx.nuster.cache_manager.path.len
                && entry->host.len == appctx->ctx.nuster.cache_manager.host.len
                && !memcmp(entry->path.data,
                        appctx->ctx.nuster.cache_manager.path.data,
                        entry->path.len)
                && !memcmp(entry->host.data,
                        appctx->ctx.nuster.cache_manager.host.data,
                        entry->host.len);

            break;
        case NST_CACHE_PURGE_REGEX_HOST:
            ret = entry->host.len == appctx->ctx.nuster.cache_manager.host.len
                && !memcmp(entry->host.data,
                        appctx->ctx.nuster.cache_manager.host.data,
                        entry->host.len)
                && regex_exec(appctx->ctx.nuster.cache_manager.regex,
                        entry->path.data);

            break;
    }

    return ret;
}

static void nst_cache_manager_handler1(struct appctx *appctx) {
    struct nst_cache_entry *entry = NULL;
    struct stream_interface *si   = appctx->owner;
    struct channel *res           = si_ic(si);
    struct stream *s              = si_strm(si);
    int max                       = 1000;
    uint64_t start                = get_current_timestamp();

    while(1) {
        nst_shctx_lock(&nuster.cache->dict[0]);

        while(appctx->st2 < nuster.cache->dict[0].size && max--) {
            entry = nuster.cache->dict[0].entry[appctx->st2];

            while(entry) {

                if(_nst_cache_manager_should_purge(entry, appctx)) {
                    if(entry->state == NST_CACHE_ENTRY_STATE_VALID) {

                        entry->state         = NST_CACHE_ENTRY_STATE_INVALID;
                        entry->data->invalid = 1;
                        entry->data          = NULL;
                        entry->expire        = 0;
                    }

                    if(entry->file) {
                        nst_persist_purge_by_path(entry->file);
                    }
                }

                entry = entry->next;
            }

            appctx->st2++;
        }

        nst_shctx_unlock(&nuster.cache->dict[0]);

        if(get_current_timestamp() - start > 1) {
            break;
        }

        max = 1000;
    }

    task_wakeup(s->task, TASK_WOKEN_OTHER);

    if(appctx->st2 == nuster.cache->dict[0].size) {
        ci_putblk(res, nst_http_msgs[NST_HTTP_200],
                strlen(nst_http_msgs[NST_HTTP_200]));

        co_skip(si_oc(si), co_data(si_oc(si)));
        si_shutr(si);
        res->flags |= CF_READ_NULL;
    }
}

static void nst_cache_manager_handler2(struct appctx *appctx) {
    struct nst_cache_entry *entry = NULL;
    struct stream_interface *si   = appctx->owner;
    struct stream *s              = si_strm(si);
    int max                       = 1000;
    uint64_t start                = get_current_timestamp();
    struct http_txn *txn = s->txn;

    while(1) {
        nst_shctx_lock(&nuster.cache->dict[0]);

        while(appctx->st2 < nuster.cache->dict[0].size && max--) {
            entry = nuster.cache->dict[0].entry[appctx->st2];

            while(entry) {

                if(_nst_cache_manager_should_purge(entry, appctx)) {
                    if(entry->state == NST_CACHE_ENTRY_STATE_VALID) {

                        entry->state         = NST_CACHE_ENTRY_STATE_INVALID;
                        entry->data->invalid = 1;
                        entry->data          = NULL;
                        entry->expire        = 0;
                    }

                    if(entry->file) {
                        nst_persist_purge_by_path(entry->file);
                    }
                }

                entry = entry->next;
            }

            appctx->st2++;
        }

        nst_shctx_unlock(&nuster.cache->dict[0]);

        if(get_current_timestamp() - start > 1) {
            break;
        }

        max = 1000;
    }

    task_wakeup(s->task, TASK_WOKEN_OTHER);

    if(appctx->st2 == nuster.cache->dict[0].size) {
        txn->status = 200;
        htx_reply_and_close(s, txn->status, htx_error_message(s));
    }
}

static void nst_cache_manager_handler(struct appctx *appctx) {
    struct stream_interface *si = appctx->owner;
    struct stream *s = si_strm(si);

    if (IS_HTX_STRM(s)) {
        return nst_cache_manager_handler2(appctx);
    } else {
        return nst_cache_manager_handler1(appctx);
    }
}

static void nst_cache_manager_release_handler(struct appctx *appctx) {

    if(appctx->ctx.nuster.cache_manager.regex) {
        regex_free(appctx->ctx.nuster.cache_manager.regex);
        free(appctx->ctx.nuster.cache_manager.regex);
    }

    if(appctx->ctx.nuster.cache_manager.host.data) {
        nst_cache_memory_free(appctx->ctx.nuster.cache_manager.host.data);
    }

    if(appctx->ctx.nuster.cache_manager.path.data) {
        nst_cache_memory_free(appctx->ctx.nuster.cache_manager.path.data);
    }
}

int nst_cache_manager_init() {
    nuster.applet.cache_manager.fct     = nst_cache_manager_handler;
    nuster.applet.cache_manager.release = nst_cache_manager_release_handler;

    return 1;
}

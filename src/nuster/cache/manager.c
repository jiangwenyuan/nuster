/*
 * Cache manager functions.
 *
 * Copyright (C) [Jiang Wenyuan](https://github.com/jiangwenyuan), < koubunen AT gmail DOT com >
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <types/global.h>

#include <proto/proto_http.h>
#include <proto/stream_interface.h>
#include <proto/proxy.h>

#include <nuster/nuster.h>
#include <nuster/memory.h>
#include <nuster/shctx.h>

/*
 * purge cache by key
 */
int _nst_cache_purge_by_key(const char *key, uint64_t hash) {
    struct nst_cache_entry *entry = NULL;
    int ret;

    nuster_shctx_lock(&nuster.cache->dict[0]);
    entry = nst_cache_dict_get(key, hash);
    if(entry && entry->state == NST_CACHE_ENTRY_STATE_VALID) {
        entry->state         = NST_CACHE_ENTRY_STATE_EXPIRED;
        entry->data->invalid = 1;
        entry->data          = NULL;
        entry->expire        = 0;
        ret                  = 200;
    } else {
        ret = 404;
    }
    nuster_shctx_unlock(&nuster.cache->dict[0]);

    return ret;
}

int nst_cache_purge(struct stream *s, struct channel *req, struct proxy *px) {
    struct http_txn *txn = s->txn;
    struct http_msg *msg = &txn->req;


    if(txn->meth == HTTP_METH_OTHER &&
            memcmp(msg->chn->buf->p, global.nuster.cache.purge_method, strlen(global.nuster.cache.purge_method)) == 0) {

        char *key = nst_cache_build_purge_key(s, msg);
        if(!key) {
            txn->status = 500;
            nuster_response(s, &nuster_http_msg_chunks[NUSTER_HTTP_500]);
        } else {
            uint64_t hash = nst_cache_hash_key(key);
            txn->status = _nst_cache_purge_by_key(key, hash);
            if(txn->status == 200) {
                nuster_response(s, &nuster_http_msg_chunks[NUSTER_HTTP_200]);
            } else {
                nuster_response(s, &nuster_http_msg_chunks[NUSTER_HTTP_404]);
            }
        }
        return 1;
    }
    return 0;
}

int _nst_cache_manager_state_ttl(struct stream *s, struct channel *req, struct proxy *px, int state, int ttl) {
    struct http_txn *txn = s->txn;
    struct http_msg *msg = &txn->req;
    int found, mode      = NST_CACHE_PURGE_NAME_RULE;
    struct hdr_ctx ctx;
    struct proxy *p;

    if(state == -1 && ttl == -1) {
        return 400;
    }

    ctx.idx = 0;
    if(http_find_header2("name", 4, msg->chn->buf->p, &txn->hdr_idx, &ctx)) {
        if(ctx.vlen == 1 && !memcmp(ctx.line + ctx.val, "*", 1)) {
            found = 1;
            mode  = NST_CACHE_PURGE_NAME_ALL;
        }
        p = proxy;
        while(p) {
            struct nuster_rule *rule = NULL;

            if(mode != NST_CACHE_PURGE_NAME_ALL && strlen(p->id) == ctx.vlen && !memcmp(ctx.line + ctx.val, p->id, ctx.vlen)) {
                found = 1;
                mode  = NST_CACHE_PURGE_NAME_PROXY;
            }

            list_for_each_entry(rule, &p->nuster.rules, list) {
                if(mode != NST_CACHE_PURGE_NAME_RULE) {
                    *rule->state = state == -1 ? *rule->state : state;
                    *rule->ttl   = ttl   == -1 ? *rule->ttl   : ttl;
                } else if(strlen(rule->name) == ctx.vlen && !memcmp(ctx.line + ctx.val, rule->name, ctx.vlen)) {
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

static inline int _nst_cache_manager_purge_method(struct http_txn *txn, struct http_msg *msg) {
    return txn->meth == HTTP_METH_OTHER &&
            memcmp(msg->chn->buf->p, global.nuster.cache.purge_method, strlen(global.nuster.cache.purge_method)) == 0;
}

int _nst_cache_manager_purge(struct stream *s, struct channel *req, struct proxy *px) {
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
    if(http_find_header2("x-host", 6, msg->chn->buf->p, &txn->hdr_idx, &ctx)) {
        host     = ctx.line + ctx.val;
        host_len = ctx.vlen;
    }

    ctx.idx = 0;
    if(http_find_header2("name", 4, msg->chn->buf->p, &txn->hdr_idx, &ctx)) {
        if(ctx.vlen == 1 && !memcmp(ctx.line + ctx.val, "*", 1)) {
            mode = NST_CACHE_PURGE_NAME_ALL;
            goto purge;
        }

        p = proxy;
        while(p) {
            struct nuster_rule *rule = NULL;

            if(mode != NST_CACHE_PURGE_NAME_ALL && strlen(p->id) == ctx.vlen && !memcmp(ctx.line + ctx.val, p->id, ctx.vlen)) {
                mode = NST_CACHE_PURGE_NAME_PROXY;
                st1  = p->uuid;
                goto purge;
            }

            list_for_each_entry(rule, &p->nuster.rules, list) {
                if(strlen(rule->name) == ctx.vlen && !memcmp(ctx.line + ctx.val, rule->name, ctx.vlen)) {
                    mode = NST_CACHE_PURGE_NAME_RULE;
                    st1  = rule->id;
                    goto purge;
                }
            }
            p = p->next;
        }

        goto notfound;
    } else if(http_find_header2("path", 4, msg->chn->buf->p, &txn->hdr_idx, &ctx)) {
        path      = ctx.line + ctx.val;
        path_len  = ctx.vlen;
        mode      = host ? NST_CACHE_PURGE_PATH_HOST : NST_CACHE_PURGE_PATH;
    } else if(http_find_header2("regex", 5, msg->chn->buf->p, &txn->hdr_idx, &ctx)) {
        regex_str = malloc(ctx.vlen + 1);
        regex     = calloc(1, sizeof(*regex));
        if(!regex_str || !regex) {
            goto err;
        }

        memcpy(regex_str, ctx.line + ctx.val, ctx.vlen);
        regex_str[ctx.vlen] = '\0';

        if (!regex_comp(regex_str, regex, 1, 0, &error)) {
            goto err;
        }
        free(regex_str);

        mode = host ? NST_CACHE_PURGE_REGEX_HOST : NST_CACHE_PURGE_REGEX;
    } else if(host) {
        mode = NST_CACHE_PURGE_HOST;
    } else {
        goto badreq;
    }

purge:
    s->target = &nuster.applet.cache_manager.obj_type;
    if(unlikely(!stream_int_register_handler(si, objt_applet(s->target)))) {
        goto err;
    } else {
        appctx      = si_appctx(si);
        memset(&appctx->ctx.nuster.cache_manager, 0, sizeof(appctx->ctx.nuster.cache_manager));
        appctx->st0 = mode;
        appctx->st1 = st1;
        appctx->st2 = 0;

        if(mode == NST_CACHE_PURGE_HOST ||
                mode == NST_CACHE_PURGE_PATH_HOST ||
                mode == NST_CACHE_PURGE_REGEX_HOST) {
            appctx->ctx.nuster.cache_manager.host     = nuster_memory_alloc(global.nuster.cache.memory, host_len);
            appctx->ctx.nuster.cache_manager.host_len = host_len;
            if(!appctx->ctx.nuster.cache_manager.host) {
                goto err;
            }
            memcpy(appctx->ctx.nuster.cache_manager.host, host, host_len);
        }

        if(mode == NST_CACHE_PURGE_PATH ||
                mode == NST_CACHE_PURGE_PATH_HOST) {
            appctx->ctx.nuster.cache_manager.path     = nuster_memory_alloc(global.nuster.cache.memory, path_len);
            appctx->ctx.nuster.cache_manager.path_len = path_len;
            if(!appctx->ctx.nuster.cache_manager.path) {
                goto err;
            }
            memcpy(appctx->ctx.nuster.cache_manager.path, path, path_len);
        } else if(mode == NST_CACHE_PURGE_REGEX ||
                mode == NST_CACHE_PURGE_REGEX_HOST) {
            appctx->ctx.nuster.cache_manager.regex = regex;
        }

        req->analysers &= (AN_REQ_HTTP_BODY | AN_REQ_FLT_HTTP_HDRS | AN_REQ_FLT_END);
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

    if(global.nuster.cache.status != NUSTER_STATUS_ON) {
        return 0;
    }

    if(txn->meth == HTTP_METH_POST) {
        /* POST */
        if(nst_cache_check_uri(msg)) {
            /* manager uri */
            ctx.idx = 0;
            if(http_find_header2("state", 5, msg->chn->buf->p, &txn->hdr_idx, &ctx)) {
                if(ctx.vlen == 6 && !memcmp(ctx.line + ctx.val, "enable", 6)) {
                    state = NUSTER_RULE_ENABLED;
                } else if(ctx.vlen == 7 && !memcmp(ctx.line + ctx.val, "disable", 7)) {
                    state = NUSTER_RULE_DISABLED;
                }
            }
            ctx.idx = 0;
            if(http_find_header2("ttl", 3, msg->chn->buf->p, &txn->hdr_idx, &ctx)) {
                nuster_parse_time(ctx.line + ctx.val, ctx.vlen, (unsigned *)&ttl);
            }

            txn->status = _nst_cache_manager_state_ttl(s, req, px, state, ttl);
        } else {
            return 0;
        }
    } else if(_nst_cache_manager_purge_method(txn, msg)) {
        /* purge */
        if(nst_cache_check_uri(msg)) {
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
            nuster_response(s, &nuster_http_msg_chunks[NUSTER_HTTP_200]);
            break;
        case 400:
            nuster_response(s, &nuster_http_msg_chunks[NUSTER_HTTP_400]);
            break;
        case 404:
            nuster_response(s, &nuster_http_msg_chunks[NUSTER_HTTP_404]);
            break;
        case 500:
            nuster_response(s, &nuster_http_msg_chunks[NUSTER_HTTP_500]);
            break;
        default:
            nuster_response(s, &nuster_http_msg_chunks[NUSTER_HTTP_400]);
    }
    return 1;
}


static int _nst_cache_manager_should_purge(struct nst_cache_entry *entry, struct appctx *appctx) {
    int ret = 0;
    switch(appctx->st0) {
        case NST_CACHE_PURGE_NAME_ALL:
            ret = 1;
            break;
        case NST_CACHE_PURGE_NAME_PROXY:
            ret = entry->pid == appctx->st1;
            break;
        case NST_CACHE_PURGE_NAME_RULE:
            ret = entry->rule->id == appctx->st1;
            break;
        case NST_CACHE_PURGE_PATH:
            ret = entry->path.len == appctx->ctx.nuster.cache_manager.path_len &&
                !memcmp(entry->path.data, appctx->ctx.nuster.cache_manager.path, entry->path.len);
            break;
        case NST_CACHE_PURGE_REGEX:
            ret = regex_exec(appctx->ctx.nuster.cache_manager.regex, entry->path.data);
            break;
        case NST_CACHE_PURGE_HOST:
            ret = entry->host.len == appctx->ctx.nuster.cache_manager.host_len &&
                !memcmp(entry->host.data, appctx->ctx.nuster.cache_manager.host, entry->host.len);
            break;
        case NST_CACHE_PURGE_PATH_HOST:
            ret = entry->path.len == appctx->ctx.nuster.cache_manager.path_len &&
                entry->host.len == appctx->ctx.nuster.cache_manager.host_len &&
                !memcmp(entry->path.data, appctx->ctx.nuster.cache_manager.path, entry->path.len) &&
                !memcmp(entry->host.data, appctx->ctx.nuster.cache_manager.host, entry->host.len);
            break;
        case NST_CACHE_PURGE_REGEX_HOST:
            ret = entry->host.len == appctx->ctx.nuster.cache_manager.host_len &&
                !memcmp(entry->host.data, appctx->ctx.nuster.cache_manager.host, entry->host.len) &&
                regex_exec(appctx->ctx.nuster.cache_manager.regex, entry->path.data);
            break;
    }
    return ret;
}

static void nst_cache_manager_handler(struct appctx *appctx) {
    struct nst_cache_entry *entry = NULL;
    struct stream_interface *si   = appctx->owner;
    struct channel *res           = si_ic(si);
    struct stream *s              = si_strm(si);
    int max                       = 1000;
    uint64_t start                = get_current_timestamp();

    while(1) {
        nuster_shctx_lock(&nuster.cache->dict[0]);
        while(appctx->st2 < nuster.cache->dict[0].size && max--) {
            entry = nuster.cache->dict[0].entry[appctx->st2];
            while(entry) {
                if(entry->state == NST_CACHE_ENTRY_STATE_VALID && _nst_cache_manager_should_purge(entry, appctx)) {
                    entry->state         = NST_CACHE_ENTRY_STATE_INVALID;
                    entry->data->invalid = 1;
                    entry->data          = NULL;
                    entry->expire        = 0;
                }
                entry = entry->next;
            }
            appctx->st2++;
        }
        nuster_shctx_unlock(&nuster.cache->dict[0]);
        if(get_current_timestamp() - start > 1) break;
        max = 1000;
    }
    task_wakeup(s->task, TASK_WOKEN_OTHER);

    if(appctx->st2 == nuster.cache->dict[0].size) {
        bi_putblk(res, nuster_http_msgs[NUSTER_HTTP_200], strlen(nuster_http_msgs[NUSTER_HTTP_200]));
        bo_skip(si_oc(si), si_ob(si)->o);
        si_shutr(si);
        res->flags |= CF_READ_NULL;
    }
}

static void nst_cache_manager_release_handler(struct appctx *appctx) {
    if(appctx->ctx.nuster.cache_manager.regex) {
        regex_free(appctx->ctx.nuster.cache_manager.regex);
        free(appctx->ctx.nuster.cache_manager.regex);
    }
    if(appctx->ctx.nuster.cache_manager.host) {
        nuster_memory_free(global.nuster.cache.memory, appctx->ctx.nuster.cache_manager.host);
    }
    if(appctx->ctx.nuster.cache_manager.path) {
        nuster_memory_free(global.nuster.cache.memory, appctx->ctx.nuster.cache_manager.path);
    }
}

int nst_cache_manager_init() {
    nuster.applet.cache_manager.fct     = nst_cache_manager_handler;
    nuster.applet.cache_manager.release = nst_cache_manager_release_handler;
    return 1;
}

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

/*
 * purge cache by key
 */
int nst_purger_basic(struct stream *s, struct channel *req, struct proxy *px) {
    struct http_msg *msg = &s->txn->req;
    struct nst_key key;
    int ret;

    struct nst_http_txn txn;

    if(nst_http_txn_attach(&txn) != NST_OK) {
        goto err;
    }

    if((px->cap & PR_CAP_BE)
            && (px->nuster.mode == NST_MODE_CACHE || px->nuster.mode == NST_MODE_NOSQL)) {

        struct nst_rule *rule = nuster.proxy[px->uuid]->rule;

        if(nst_http_parse_htx(s, msg, &txn) != NST_OK) {
            goto err;
        }

        while(rule) {
            nst_debug(s, "[manager] ==== Check rule: %s ====\n", rule->name);

            if(nst_key_build(s, msg, rule, &txn, &key, HTTP_METH_GET) != NST_OK) {
                goto err;
            }

            nst_key_hash(&key);
            nst_debug(s, "[manager] Key: ");

            nst_key_debug(&key);
            nst_debug(s, "[manager] Hash: %"PRIu64"\n", key.hash);

            if(px->nuster.mode == NST_MODE_CACHE) {
                ret = nst_cache_delete(&key);
            } else {
                ret = nst_nosql_delete(&key);
            }

            if(ret == 0) {
                nst_http_reply(s, NST_HTTP_404);
            } else if(ret == 1) {
                nst_http_reply(s, NST_HTTP_200);
            } else {
                nst_http_reply(s, NST_HTTP_500);
            }

            goto end;

            rule = rule->next;
        }
    }

err:
    nst_http_reply(s, NST_HTTP_500);

end:
    nst_http_txn_detach(&txn);

    if(key.data) {
        free(key.data);
    }

    return 1;
}

int nst_purger_advanced(struct stream *s, struct channel *req, struct proxy *px) {
    struct stream_interface *si = &s->si[1];
    struct appctx *appctx       = NULL;
    int mode                    = NST_MANAGER_NAME_RULE;
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
    struct http_hdr_ctx hdr = { .blk = NULL };

    if(http_find_header(htx, ist("x-host"), &hdr, 0)) {
        host     = hdr.value.ptr;
        host_len = hdr.value.len;
    }

    if(http_find_header(htx, ist("name"), &hdr, 0)) {

        if(isteq(hdr.value, ist("*"))) {
            mode = NST_MANAGER_NAME_ALL;

            goto purge;
        }

        p = proxies_list;

        while(p) {
            struct nst_rule *rule = NULL;

            if((p->cap & PR_CAP_BE)
                    && (p->nuster.mode == NST_MODE_CACHE || p->nuster.mode == NST_MODE_NOSQL)) {

                if(mode != NST_MANAGER_NAME_ALL && strlen(p->id) == hdr.value.len
                        && !memcmp(hdr.value.ptr, p->id, hdr.value.len)) {

                    mode = NST_MANAGER_NAME_PROXY;
                    st1  = p->uuid;

                    goto purge;
                }

                rule = nuster.proxy[p->uuid]->rule;

                while(rule) {

                    if(strlen(rule->name) == hdr.value.len
                            && !memcmp(hdr.value.ptr, rule->name, hdr.value.len)) {

                        mode = NST_MANAGER_NAME_RULE;
                        st1  = rule->id;

                        goto purge;
                    }

                    rule = rule->next;
                }
            }

            p = p->next;
        }

        goto notfound;
    } else if(http_find_header(htx, ist("path"), &hdr, 0)) {
        path      = hdr.value.ptr;
        path_len  = hdr.value.len;
        mode      = host ? NST_MANAGER_PATH_HOST : NST_MANAGER_PATH;
    } else if(http_find_header(htx, ist("regex"), &hdr, 0)) {

        regex_str = malloc(hdr.value.len + 1);

        if(!regex_str) {
            goto err;
        }

        memcpy(regex_str, hdr.value.ptr, hdr.value.len);
        regex_str[hdr.value.len] = '\0';

        if(!(regex = regex_comp(regex_str, 1, 0, &error))) {
            goto err;
        }

        free(regex_str);
        regex_free(regex);

        mode = host ? NST_MANAGER_REGEX_HOST : NST_MANAGER_REGEX;
    } else if(host) {
        mode = NST_MANAGER_HOST;
    } else {
        goto badreq;
    }

purge:
    s->target = &nuster.applet.purger.obj_type;

    if(unlikely(!si_register_handler(si, objt_applet(s->target)))) {
        goto err;
    } else {
        struct buffer buf = { .area = NULL };

        appctx      = si_appctx(si);
        memset(&appctx->ctx.nuster.manager, 0, sizeof(appctx->ctx.nuster.manager));

        appctx->st0 = mode;
        appctx->st1 = st1;
        appctx->st2 = 0;

        buf.size = host_len + path_len;
        buf.data = 0;
        buf.area = nst_cache_memory_alloc(buf.size);

        if(!buf.area) {
            goto err;
        }

        if(mode == NST_MANAGER_HOST || mode == NST_MANAGER_PATH_HOST
                || mode == NST_MANAGER_REGEX_HOST) {

            appctx->ctx.nuster.manager.host.ptr = buf.area + buf.data;
            appctx->ctx.nuster.manager.host.len = host_len;

            chunk_memcat(&buf, host, host_len);
        }

        if(mode == NST_MANAGER_PATH || mode == NST_MANAGER_PATH_HOST) {

            appctx->ctx.nuster.manager.path.ptr = buf.area + buf.data;
            appctx->ctx.nuster.manager.path.len = path_len;

            chunk_memcat(&buf, path, path_len);
        } else if(mode == NST_MANAGER_REGEX || mode == NST_MANAGER_REGEX_HOST) {
            appctx->ctx.nuster.manager.regex = regex;
        }

        appctx->ctx.nuster.manager.buf = buf;

        req->analysers &= (AN_REQ_HTTP_BODY | AN_REQ_FLT_HTTP_HDRS | AN_REQ_FLT_END);
        req->analysers &= ~AN_REQ_FLT_XFER_DATA;
        req->analysers |= AN_REQ_HTTP_XFER_BODY;
    }

    return 0;

notfound:
    nst_http_reply(s, NST_HTTP_404);

    return 1;

err:
    free(error);
    free(regex_str);

    if(regex) {
        regex_free(regex);
    }

    nst_http_reply(s, NST_HTTP_500);

    return 1;

badreq:
    nst_http_reply(s, NST_HTTP_400);

    return 1;
}

int nst_purger_check(struct appctx *appctx, struct nst_dict_entry *entry) {
    int ret = 0;

    switch(appctx->st0) {
        case NST_MANAGER_NAME_ALL:
            ret = 1;

            break;
        case NST_MANAGER_NAME_PROXY:
            ret = entry->pid == appctx->st1;

            break;
        case NST_MANAGER_NAME_RULE:
            ret = entry->rule && entry->rule->id == appctx->st1;

            break;
        case NST_MANAGER_PATH:
            ret = isteq(entry->path, appctx->ctx.nuster.manager.path);

            break;
        case NST_MANAGER_REGEX:
            ret = regex_exec2(appctx->ctx.nuster.manager.regex, entry->path.ptr, entry->path.len);

            break;
        case NST_MANAGER_HOST:
            ret = isteq(entry->host, appctx->ctx.nuster.manager.host);

            break;
        case NST_MANAGER_PATH_HOST:
            ret = isteq(entry->path, appctx->ctx.nuster.manager.path)
                && isteq(entry->host, appctx->ctx.nuster.manager.host);

            break;
        case NST_MANAGER_REGEX_HOST:
            ret = isteq(entry->host, appctx->ctx.nuster.manager.host)
                && regex_exec2(appctx->ctx.nuster.manager.regex, entry->path.ptr, entry->path.len);

            break;
    }

    return ret;
}

static void nst_purger_handler(struct appctx *appctx) {
    struct nst_dict_entry *entry = NULL;
    struct stream_interface *si   = appctx->owner;

    struct stream *s = si_strm(si);
    uint64_t start   = get_current_timestamp();

    int max = 1000;

    while(1) {
        nst_shctx_lock(&nuster.cache->dict);

        while(appctx->st2 < nuster.cache->dict.size && max--) {
            entry = nuster.cache->dict.entry[appctx->st2];

            while(entry) {

                if(nst_purger_check(appctx, entry)) {
                    if(entry->state == NST_DICT_ENTRY_STATE_VALID) {

                        entry->state         = NST_DICT_ENTRY_STATE_INVALID;
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

        nst_shctx_unlock(&nuster.cache->dict);

        if(get_current_timestamp() - start > 1) {
            break;
        }

        max = 1000;
    }

    task_wakeup(s->task, TASK_WOKEN_OTHER);

    if(appctx->st2 == nuster.cache->dict.size) {
        nst_http_reply(s, NST_HTTP_200);
    }
}

static void nst_purger_release_handler(struct appctx *appctx) {

    if(appctx->ctx.nuster.manager.regex) {
        regex_free(appctx->ctx.nuster.manager.regex);
        free(appctx->ctx.nuster.manager.regex);
    }

    nst_cache_memory_free(appctx->ctx.nuster.manager.buf.area);
}

void nst_purger_init() {
    nuster.applet.purger.fct     = nst_purger_handler;
    nuster.applet.purger.release = nst_purger_release_handler;
}

/*
 * nuster purger functions.
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
 * purge by key
 */
int
nst_purger_basic(hpx_stream_t *s, hpx_channel_t *req, hpx_proxy_t *px) {
    hpx_http_msg_t     *msg  = &s->txn->req;
    hpx_proxy_t        *p    = proxies_list;
    nst_http_txn_t      txn;
    nst_key_t           key  = { .data = NULL };
    int                 ret  = NST_HTTP_500;

    if(nst_http_txn_attach(&txn) != NST_OK) {
        goto err;
    }

    if(nst_http_parse_htx(s, msg, &txn) != NST_OK) {
        goto err;
    }

    while(p) {
        if(p->nuster.mode == NST_MODE_CACHE || p->nuster.mode == NST_MODE_NOSQL) {

            nst_rule_t  *rule = nuster.proxy[p->uuid]->rule;

            while(rule) {
                nst_debug(s, "[rule ] ----- %s", rule->name);

                if(key.data) {
                    free(key.data);
                }

                if(nst_key_build(s, msg, rule, &txn, &key, HTTP_METH_GET) != NST_OK) {
                    goto err;
                }

                nst_key_hash(&key);

                nst_key_debug(s, &key);

                if(global.nuster.cache.status == NST_STATUS_ON
                        && p->nuster.mode == NST_MODE_CACHE) {

                    ret = nst_cache_delete(&key);
                }

                if(global.nuster.nosql.status == NST_STATUS_ON
                        && p->nuster.mode == NST_MODE_NOSQL) {

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

        p = p->next;
    }

err:
    nst_http_reply(s, ret);

end:
    nst_http_txn_detach(&txn);

    if(key.data) {
        free(key.data);
    }

    return 1;
}

int
nst_purger_advanced(hpx_stream_t *s, hpx_channel_t *req, hpx_proxy_t *px) {
    hpx_stream_interface_t  *si  = &s->si[1];
    hpx_htx_t               *htx = htxbuf(&s->req.buf);
    hpx_http_hdr_ctx_t       hdr = { .blk = NULL };
    hpx_proxy_t             *p;
    hpx_appctx_t            *appctx;
    hpx_my_regex_t          *regex;
    char                    *regex_str, *error, *host, *path;
    int                      host_len, path_len, method, st1, mode;

    regex     = NULL;
    regex_str = error = host = path  = NULL;
    host_len  = 0;
    path_len  = 0;
    method    = NST_MANAGER_NAME_RULE;
    st1       = 0;
    mode      = 0;

    if(http_find_header(htx, ist("mode"), &hdr, 0)) {

        if(isteq(hdr.value, ist("cache"))) {
            mode = NST_MODE_CACHE;
        } else if(isteq(hdr.value, ist("nosql"))) {
            mode = NST_MODE_NOSQL;
        } else {
            goto badreq;
        }
    }

    hdr.blk = NULL;

    if(http_find_header(htx, ist("nuster-host"), &hdr, 0)) {
        host     = hdr.value.ptr;
        host_len = hdr.value.len;
    } else if(http_find_header(htx, ist("host"), &hdr, 0)) {
        host     = hdr.value.ptr;
        host_len = hdr.value.len;
    }

    hdr.blk = NULL;

    if(http_find_header(htx, ist("name"), &hdr, 0)) {

        p = proxies_list;

        while(p) {
            nst_rule_t *rule = NULL;

            if(p->nuster.mode == NST_MODE_CACHE || p->nuster.mode == NST_MODE_NOSQL) {

                if(strlen(p->id) == hdr.value.len && !memcmp(hdr.value.ptr, p->id, hdr.value.len)) {

                    method = NST_MANAGER_NAME_PROXY;
                    st1    = p->uuid;
                    mode   = p->nuster.mode;

                    goto purge;
                }

                rule = nuster.proxy[p->uuid]->rule;

                while(rule) {

                    if(strlen(rule->name) == hdr.value.len
                            && !memcmp(hdr.value.ptr, rule->name, hdr.value.len)) {

                        method = NST_MANAGER_NAME_RULE;
                        st1    = rule->id;
                        mode   = p->nuster.mode;

                        goto purge;
                    }

                    rule = rule->next;
                }
            }

            p = p->next;
        }

        goto notfound;
    } else if(http_find_header(htx, ist("path"), &hdr, 0)) {
        path     = hdr.value.ptr;
        path_len = hdr.value.len;
        method   = host ? NST_MANAGER_PATH_HOST : NST_MANAGER_PATH;
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

        method = host ? NST_MANAGER_REGEX_HOST : NST_MANAGER_REGEX;
    } else if(host) {
        method = NST_MANAGER_HOST;
    } else {
        goto badreq;
    }

purge:

    if(mode == 0 && (method != NST_MANAGER_NAME_PROXY || method != NST_MANAGER_NAME_RULE)) {
        goto badreq;
    }

    if(mode == NST_MODE_CACHE && global.nuster.cache.status == NST_STATUS_OFF) {
        goto err;
    }

    if(mode == NST_MODE_NOSQL && global.nuster.nosql.status == NST_STATUS_OFF) {
        goto err;
    }

    s->target = &nuster.applet.purger.obj_type;

    if(unlikely(!si_register_handler(si, objt_applet(s->target)))) {
        goto err;
    } else {
        hpx_buffer_t buf = { .area = NULL };

        appctx      = si_appctx(si);
        memset(&appctx->ctx.nuster.manager, 0, sizeof(appctx->ctx.nuster.manager));

        appctx->st0 = method;
        appctx->st1 = st1;

        if(mode == NST_MODE_CACHE) {
            appctx->ctx.nuster.manager.dict = &nuster.cache->dict;
        } else {
            appctx->ctx.nuster.manager.dict = &nuster.nosql->dict;
        }

        if(method == NST_MANAGER_HOST || method == NST_MANAGER_PATH_HOST
                || method == NST_MANAGER_REGEX_HOST || method == NST_MANAGER_PATH) {

            buf.size = host_len + path_len;
            buf.data = 0;
            buf.area = nst_memory_alloc(appctx->ctx.nuster.manager.dict->memory, buf.size);

            if(!buf.area) {
                goto err;
            }
        }

        if(method == NST_MANAGER_HOST || method == NST_MANAGER_PATH_HOST
                || method == NST_MANAGER_REGEX_HOST) {

            appctx->ctx.nuster.manager.host.ptr = buf.area + buf.data;
            appctx->ctx.nuster.manager.host.len = host_len;

            chunk_memcat(&buf, host, host_len);
        }

        if(method == NST_MANAGER_PATH || method == NST_MANAGER_PATH_HOST) {

            appctx->ctx.nuster.manager.path.ptr = buf.area + buf.data;
            appctx->ctx.nuster.manager.path.len = path_len;

            chunk_memcat(&buf, path, path_len);
        } else if(method == NST_MANAGER_REGEX || method == NST_MANAGER_REGEX_HOST) {
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

    if(error) {
        free(error);
    }

    if(regex_str) {
        free(regex_str);
    }

    if(regex) {
        regex_free(regex);
    }

    nst_http_reply(s, NST_HTTP_500);

    return 1;

badreq:
    nst_http_reply(s, NST_HTTP_400);

    return 1;
}

int
nst_purger_check(hpx_appctx_t *appctx, nst_dict_entry_t *entry) {
    int  ret = 0;

    switch(appctx->st0) {
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

static void
nst_purger_handler(hpx_appctx_t *appctx) {
    nst_dict_entry_t        *entry  = NULL;
    hpx_stream_interface_t  *si     = appctx->owner;
    hpx_stream_t            *s      = si_strm(si);
    nst_dict_t              *dict   = appctx->ctx.nuster.manager.dict;
    uint64_t                 start  = get_current_timestamp();
    int                      max    = 1000;

    while(1) {

        while(appctx->ctx.nuster.manager.idx < dict->size && max--) {
            nst_shctx_lock(dict);

            entry = dict->entry[appctx->ctx.nuster.manager.idx];

            while(entry) {

                if(nst_purger_check(appctx, entry)) {
                    if(entry->state == NST_DICT_ENTRY_STATE_VALID) {

                        entry->state  = NST_DICT_ENTRY_STATE_INVALID;
                        entry->expire = 0;

                        if(entry->store.ring.data) {
                            entry->store.ring.data->invalid = 1;
                            entry->store.ring.data          = NULL;
                        }

                        if(entry->store.disk.file) {
                            nst_disk_purge_by_path(entry->store.disk.file);
                        }
                    }
                }

                entry = entry->next;

                if(get_current_timestamp() - start > 10) {
                    break;
                }
            }

            if(entry == NULL) {
                appctx->ctx.nuster.manager.idx++;
            }

            nst_shctx_unlock(dict);
        }

        if(get_current_timestamp() - start > 20) {
            break;
        }

        max = 1000;
    }

    task_wakeup(s->task, TASK_WOKEN_OTHER);

    if(appctx->ctx.nuster.manager.idx == dict->size) {
        nst_http_reply(s, NST_HTTP_200);
    }
}

static void
nst_purger_release_handler(hpx_appctx_t *appctx) {

    if(appctx->ctx.nuster.manager.regex) {
        regex_free(appctx->ctx.nuster.manager.regex);
    }

    nst_memory_free(appctx->ctx.nuster.manager.dict->memory, appctx->ctx.nuster.manager.buf.area);
}

void
nst_purger_init() {
    nuster.applet.purger.fct     = nst_purger_handler;
    nuster.applet.purger.release = nst_purger_release_handler;
}

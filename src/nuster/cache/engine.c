/*
 * nuster cache engine functions.
 *
 * Copyright (C) Jiang Wenyuan, < koubunen AT gmail DOT com >
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <proto/log.h>
#include <proto/proto_http.h>
#include <proto/raw_sock.h>
#include <proto/stream_interface.h>
#include <proto/acl.h>
#include <proto/proxy.h>

#ifdef USE_OPENSSL
#include <proto/ssl_sock.h>
#include <types/ssl_sock.h>
#endif

#include <nuster/memory.h>
#include <nuster/shctx.h>
#include <nuster/nuster.h>
#include <nuster/http.h>
#include <nuster/file.h>
#include <nuster/persist.h>


/*
 * The cache applet acts like the backend to send cached http data
 */
static void nst_cache_engine_handler(struct appctx *appctx) {
    struct nst_cache_element *element = NULL;
    struct stream_interface *si       = appctx->owner;
    struct channel *res               = si_ic(si);
    /* struct stream *s                  = si_strm(si); */
    int ret;

    if(unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO)) {
        appctx->ctx.nuster.cache_engine.data->clients--;
        return;
    }

    /* Check if the input buffer is avalaible. */
    if(res->buf.size == 0) {
        si_rx_room_blk(si);
        return;
    }

    /* check that the output is not closed */
    if(res->flags & (CF_SHUTW|CF_SHUTW_NOW)) {
        appctx->ctx.nuster.cache_engine.element = NULL;
    }

    if(appctx->ctx.nuster.cache_engine.element) {
        /*
        if(appctx->ctx.nuster.cache_engine.element
        == appctx->ctx.nuster.cache_engine.data->element) {
            s->res.analysers = 0;
            s->res.analysers |= (AN_RES_WAIT_HTTP | AN_RES_HTTP_PROCESS_BE
            | AN_RES_HTTP_XFER_BODY);
        }
        */
        element = appctx->ctx.nuster.cache_engine.element;

        ret = ci_putblk(res, element->msg.data, element->msg.len);

        if(ret >= 0) {
            appctx->ctx.nuster.cache_engine.element = element->next;
        } else if(ret == -2) {
            appctx->ctx.nuster.cache_engine.data->clients--;
            si_shutr(si);
            res->flags |= CF_READ_NULL;
        }

    } else {
        co_skip(si_oc(si), co_data(si_oc(si)));
        si_shutr(si);
        res->flags |= CF_READ_NULL;
        appctx->ctx.nuster.cache_engine.data->clients--;
    }

}

/*
 * The cache disk applet acts like the backend to send cached http data
 */
static void nst_cache_disk_engine_handler(struct appctx *appctx) {
    struct stream_interface *si = appctx->owner;
    struct channel *res         = si_ic(si);

    int ret;
    int max = b_room(&res->buf) - global.tune.maxrewrite;

    int fd = appctx->ctx.nuster.cache_disk_engine.fd;
    int header_len = appctx->ctx.nuster.cache_disk_engine.header_len;
    uint64_t offset = appctx->ctx.nuster.cache_disk_engine.offset;

    char buf[16*1024] = {0};

    if(unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO)) {
        return;
    }

    /* Check if the input buffer is avalaible. */
    if(res->buf.size == 0) {
        si_rx_room_blk(si);
        return;
    }

    /* check that the output is not closed */
    if(res->flags & (CF_SHUTW|CF_SHUTW_NOW)) {
    }

    if(b_data(&res->buf) != 0) {
        return;
    }

    switch(appctx->st0) {
        case NST_PERSIST_APPLET_HEADER:
            ret = pread(fd, buf, header_len, offset);

            if(ret != header_len) {
                appctx->st0 = NST_PERSIST_APPLET_ERROR;
                break;
            }

            ret = ci_putblk(res, buf, ret);

            if(ret >= 0) {
                appctx->st0 = NST_PERSIST_APPLET_PAYLOAD;
                appctx->ctx.nuster.cache_disk_engine.offset += ret;
            } else if(ret == -2) {
                appctx->st0 = NST_PERSIST_APPLET_ERROR;
                si_shutr(si);
                res->flags |= CF_READ_NULL;
            }
            break;
        case NST_PERSIST_APPLET_PAYLOAD:
            ret = pread(fd, buf, max, offset);

            if(ret == -1) {
                appctx->st0 = NST_PERSIST_APPLET_ERROR;
                break;
            }

            if(ret == 0) {
                close(fd);
                appctx->st0 = NST_PERSIST_APPLET_DONE;
                break;
            }

            ret = ci_putblk(res, buf, ret);

            if(ret >= 0) {
                appctx->st0 = NST_PERSIST_APPLET_PAYLOAD;
                appctx->ctx.nuster.cache_disk_engine.offset += ret;
            } else if(ret == -2) {
                appctx->st0 = NST_PERSIST_APPLET_ERROR;
                si_shutr(si);
                res->flags |= CF_READ_NULL;
            }
            break;
        case NST_PERSIST_APPLET_DONE:
            co_skip(si_oc(si), co_data(si_oc(si)));
            si_shutr(si);
            res->flags |= CF_READ_NULL;
            break;
        case NST_PERSIST_APPLET_ERROR:
            si_shutr(si);
            res->flags |= CF_READ_NULL;
            close(fd);
            break;
    }

}

/*
 * Cache the keys which calculated in request for response use
 */
struct nst_rule_stash *nst_cache_stash_rule(struct nst_cache_ctx *ctx,
        struct nst_rule *rule) {

    struct nst_rule_stash *stash = pool_alloc(global.nuster.cache.pool.stash);

    if(stash) {
        stash->rule = rule;
        stash->key  = ctx->key;
        stash->hash = ctx->hash;

        if(ctx->stash) {
            stash->next = ctx->stash;
        } else {
            stash->next = NULL;
        }

        ctx->stash = stash;
    }

    return stash;
}

static struct buffer *_nst_key_init() {
    struct buffer *key  = nst_memory_alloc(global.nuster.cache.memory,
            sizeof(*key));

    if(!key) {
        return NULL;
    }

    key->area = nst_memory_alloc(global.nuster.cache.memory,
            NST_CACHE_DEFAULT_KEY_SIZE);

    if(!key->area) {
        return NULL;
    }

    key->size = NST_CACHE_DEFAULT_KEY_SIZE;
    key->data = 0;
    key->head = 0;
    memset(key->area, 0, key->size);

    return key;
}

static int _nst_key_expand(struct buffer *key) {

    if(key->size >= global.tune.bufsize) {
        goto err;
    } else {
        char *p = nst_memory_alloc(global.nuster.cache.memory,
                key->size * 2);

        if(!p) {
            goto err;
        }

        memset(p, 0, key->size * 2);
        memcpy(p, key->area, key->size);
        nst_memory_free(global.nuster.cache.memory, key->area);
        key->area = p;
        key->size = key->size * 2;

        return NST_OK;
    }

err:
    nst_memory_free(global.nuster.cache.memory, key->area);
    nst_memory_free(global.nuster.cache.memory, key);

    return NST_ERR;
}

static int _nst_key_advance(struct buffer *key, int step) {

    if(b_room(key) < step) {

        if(_nst_key_expand(key) != NST_OK) {
            return NST_ERR;
        }

    }

    key->data += step;

    return NST_OK;
}

static int _nst_key_append(struct buffer *key, char *str, int str_len) {

    if(b_room(key) < str_len + 1) {

        if(_nst_key_expand(key) != NST_OK) {
            return NST_ERR;
        }

    }

    memcpy(key->area + key->data, str, str_len);
    key->data += str_len + 1;

    return NST_OK;
}

int nst_cache_check_uri(struct http_msg *msg) {
    const char *uri = ci_head(msg->chn) + msg->sl.rq.u;

    if(!global.nuster.cache.uri) {
        return NST_ERR;
    }

    if(strlen(global.nuster.cache.uri) != msg->sl.rq.u_l) {
        return NST_ERR;
    }

    if(memcmp(uri, global.nuster.cache.uri, msg->sl.rq.u_l) != 0) {
        return NST_ERR;
    }

    return NST_OK;
}

/*
 * create a new nst_cache_data and insert it to cache->data list
 */
struct nst_cache_data *nst_cache_data_new() {

    struct nst_cache_data *data =
        nst_memory_alloc(global.nuster.cache.memory, sizeof(*data));

    nuster_shctx_lock(nuster.cache);

    if(data) {
        data->clients  = 0;
        data->invalid  = 0;
        data->element  = NULL;

        if(nuster.cache->data_head == NULL) {
            nuster.cache->data_head = data;
            nuster.cache->data_tail = data;
            data->next              = data;
        } else {

            if(nuster.cache->data_head == nuster.cache->data_tail) {
                nuster.cache->data_head->next = data;
                data->next                    = nuster.cache->data_head;
                nuster.cache->data_tail       = data;
            } else {
                data->next                    = nuster.cache->data_head;
                nuster.cache->data_tail->next = data;
                nuster.cache->data_tail       = data;
            }
        }
    }

    nuster_shctx_unlock(nuster.cache);

    return data;
}

/*
 * Append partial http response data
 */
static struct nst_cache_element *_nst_cache_data_append(struct http_msg *msg,
        long msg_len) {

    struct nst_cache_element *element =
        nst_memory_alloc(global.nuster.cache.memory, sizeof(*element));

    if(element) {
        char *data = b_orig(&msg->chn->buf);
        char *p    = ci_head(msg->chn);
        int size   = msg->chn->buf.size;

        char *msg_data = nst_memory_alloc(global.nuster.cache.memory,
                msg_len);

        if(!msg_data) {
            nst_memory_free(global.nuster.cache.memory, element);
            return NULL;
        }

        if(p - data + msg_len > size) {
            int right = data + size - p;
            int left  = msg_len - right;
            memcpy(msg_data, p, right);
            memcpy(msg_data + right, data, left);
        } else {
            memcpy(msg_data, p, msg_len);
        }

        element->msg.data = msg_data;
        element->msg.len  = msg_len;
        element->next     = NULL;
        nst_cache_stats_update_used_mem(msg_len);
    }

    return element;
}


static int _nst_cache_data_invalid(struct nst_cache_data *data) {

    if(data->invalid) {

        if(!data->clients) {
            return 1;
        }
    }

    return 0;
}

/*
 * free invalid nst_cache_data
 */
static void _nst_cache_data_cleanup() {
    struct nst_cache_data *data = NULL;

    if(nuster.cache->data_head) {

        if(nuster.cache->data_head == nuster.cache->data_tail) {

            if(_nst_cache_data_invalid(nuster.cache->data_head)) {
                data                    = nuster.cache->data_head;
                nuster.cache->data_head = NULL;
                nuster.cache->data_tail = NULL;
            }

        } else {

            if(_nst_cache_data_invalid(nuster.cache->data_head)) {
                data                          = nuster.cache->data_head;
                nuster.cache->data_tail->next = nuster.cache->data_head->next;
                nuster.cache->data_head       = nuster.cache->data_head->next;
            } else {
                nuster.cache->data_tail = nuster.cache->data_head;
                nuster.cache->data_head = nuster.cache->data_head->next;
            }

        }

    }

    if(data) {
        struct nst_cache_element *element = data->element;

        while(element) {
            struct nst_cache_element *tmp = element;
            element                       = element->next;

            if(tmp->msg.data) {
                nst_cache_stats_update_used_mem(-tmp->msg.len);
                nst_memory_free(global.nuster.cache.memory, tmp->msg.data);
            }

            nst_memory_free(global.nuster.cache.memory, tmp);
        }

        nst_memory_free(global.nuster.cache.memory, data);
    }
}

void nst_cache_housekeeping() {

    if(global.nuster.cache.status == NST_STATUS_ON) {
        int dict_cleaner = 1;
        int data_cleaner = 1;
        int disk_cleaner = 1;
        int disk_loader  = 1;
        int disk_saver   = 1;

        if(global.mode & MODE_MWORKER) {
            if(master == 1) {
                dict_cleaner = global.nuster.cache.dict_cleaner;
                data_cleaner = global.nuster.cache.data_cleaner;
                disk_cleaner = global.nuster.cache.disk_cleaner;
                disk_loader  = global.nuster.cache.disk_loader;
                disk_saver   = global.nuster.cache.disk_saver;
            } else {
                dict_cleaner = 0;
                data_cleaner = 0;
                disk_cleaner = 0;
                disk_loader  = 0;
                disk_saver   = 0;
            }
        }

        while(dict_cleaner--) {
            nst_cache_dict_rehash();
            nuster_shctx_lock(&nuster.cache->dict[0]);
            nst_cache_dict_cleanup();
            nuster_shctx_unlock(&nuster.cache->dict[0]);
        }

        while(data_cleaner--) {
            nuster_shctx_lock(nuster.cache);
            _nst_cache_data_cleanup();
            nuster_shctx_unlock(nuster.cache);
        }

        while(disk_cleaner--) {
            nst_cache_persist_cleanup();
        }

        while(disk_loader--) {
            nst_cache_persist_load();
        }

        while(disk_saver--) {
            nuster_shctx_lock(&nuster.cache->dict[0]);
            nst_cache_persist_async();
            nuster_shctx_unlock(&nuster.cache->dict[0]);
        }

    }
}

void nst_cache_init() {

    nuster.applet.cache_engine.fct = nst_cache_engine_handler;
    nuster.applet.cache_disk_engine.fct = nst_cache_disk_engine_handler;

    if(global.nuster.cache.status == NST_STATUS_ON) {

        if(global.nuster.cache.share == NST_STATUS_UNDEFINED) {

            if(global.nbproc == 1) {
                global.nuster.cache.share = NST_STATUS_OFF;
            } else {
                global.nuster.cache.share = NST_STATUS_ON;
            }
        }

        if(global.nuster.cache.directory) {

            if(nst_create_path(global.nuster.cache.directory) ==
                    NST_ERR) {

                ha_alert("Create `%s` failed\n", global.nuster.cache.directory);
                exit(1);
            }
        }

        global.nuster.cache.pool.stash = create_pool("cp.stash",
                sizeof(struct nst_rule_stash), MEM_F_SHARED);

        global.nuster.cache.pool.ctx   = create_pool("cp.ctx",
                sizeof(struct nst_cache_ctx), MEM_F_SHARED);

        if(global.nuster.cache.share) {
            global.nuster.cache.memory = nst_memory_create("cache.shm",
                    global.nuster.cache.dict_size
                    + global.nuster.cache.data_size, global.tune.bufsize,
                    NST_CACHE_DEFAULT_CHUNK_SIZE);

            if(!global.nuster.cache.memory) {
                goto shm_err;
            }

            if(nuster_shctx_init(global.nuster.cache.memory) != NST_OK) {
                goto shm_err;
            }

            nuster.cache = nst_memory_alloc(global.nuster.cache.memory,
                    sizeof(struct nst_cache));

        } else {
            global.nuster.cache.memory = nst_memory_create("cache.shm",
                    NST_CACHE_DEFAULT_SIZE, 0, 0);

            if(!global.nuster.cache.memory) {
                goto shm_err;
            }

            if(nuster_shctx_init(global.nuster.cache.memory) != NST_OK) {
                goto shm_err;
            }

            global.nuster.cache.pool.data    = create_pool("cp.data",
                    sizeof(struct nst_cache_data), MEM_F_SHARED);

            global.nuster.cache.pool.element = create_pool("cp.element",
                    sizeof(struct nst_cache_element), MEM_F_SHARED);

            global.nuster.cache.pool.chunk   = create_pool("cp.chunk",
                    global.tune.bufsize, MEM_F_SHARED);

            global.nuster.cache.pool.entry   = create_pool("cp.entry",
                    sizeof(struct nst_cache_entry), MEM_F_SHARED);

            nuster.cache = malloc(sizeof(struct nst_cache));
        }

        if(!nuster.cache) {
            goto err;
        }

        memset(nuster.cache, 0, sizeof(*nuster.cache));

        nuster.cache->disk.file = nst_persist_alloc(
                global.nuster.cache.memory);

        if(!nuster.cache->disk.file) {
            goto err;
        }

        if(nuster_shctx_init(nuster.cache) != NST_OK) {
            goto shm_err;
        }

        if(nst_cache_dict_init() != NST_OK) {
            goto err;
        }

        if(nst_cache_stats_init() !=NST_OK) {
            goto err;
        }

        if(!nst_cache_manager_init()) {
            goto err;
        }

        nst_debug("[CACHE] on, data_size=%llu\n",
                global.nuster.cache.data_size);
    }

    return;

err:
    ha_alert("Out of memory when initializing cache.\n");
    exit(1);

shm_err:
    ha_alert("Error when initializing cache.\n");
    exit(1);
}

int nst_cache_prebuild_key(struct nst_cache_ctx *ctx, struct stream *s,
        struct http_msg *msg) {

    struct http_txn *txn = s->txn;

    char *uri_begin, *uri_end;
    struct hdr_ctx hdr;

    ctx->req.scheme = SCH_HTTP;

#ifdef USE_OPENSSL
    if(s->sess->listener->bind_conf->is_ssl) {
        ctx->req.scheme = SCH_HTTPS;
    }
#endif

    ctx->req.host.data = NULL;
    ctx->req.host.len  = 0;
    hdr.idx            = 0;

    if(http_find_header2("Host", 4, ci_head(msg->chn), &txn->hdr_idx, &hdr)) {
        ctx->req.host.data = nst_memory_alloc(global.nuster.cache.memory,
                hdr.vlen);

        if(!ctx->req.host.data) {
            return NST_ERR;
        }

        ctx->req.host.len  = hdr.vlen;
        memcpy(ctx->req.host.data, hdr.line + hdr.val, hdr.vlen);
    }

    uri_begin          = http_txn_get_path(txn);
    uri_end            = NULL;
    ctx->req.path.data = NULL;
    ctx->req.path.len  = 0;
    ctx->req.uri.data  = NULL;
    ctx->req.uri.len   = 0;

    if(uri_begin) {
        char *ptr = uri_begin;
        uri_end   = ci_head(msg->chn) + msg->sl.rq.u + msg->sl.rq.u_l;

        while(ptr < uri_end && *ptr != '?') {
            ptr++;
        }

        ctx->req.path.len = ptr - uri_begin;
        ctx->req.uri.data = uri_begin;
        ctx->req.uri.len  = uri_end - uri_begin;

        /* extra 1 char as required by regex_exec_match2 */
        ctx->req.path.data = nst_memory_alloc(global.nuster.cache.memory,
                ctx->req.path.len + 1);

        if(!ctx->req.path.data) {
            return NST_ERR;
        }

        memcpy(ctx->req.path.data, uri_begin, ctx->req.path.len);
    }

    ctx->req.query.data = NULL;
    ctx->req.query.len  = 0;
    ctx->req.delimiter  = 0;

    if(ctx->req.uri.data) {
        ctx->req.query.data = memchr(ctx->req.uri.data, '?',
                uri_end - ctx->req.uri.data);

        if(ctx->req.query.data) {
            ctx->req.query.data++;
            ctx->req.query.len = uri_end - ctx->req.query.data;

            if(ctx->req.query.len) {
                ctx->req.delimiter = 1;
            }
        }
    }

    ctx->req.cookie.data = NULL;
    ctx->req.cookie.len  = 0;
    hdr.idx              = 0;

    if(http_find_header2("Cookie", 6, ci_head(msg->chn), &txn->hdr_idx, &hdr)) {
        ctx->req.cookie.data = hdr.line + hdr.val;
        ctx->req.cookie.len  = hdr.vlen;
    }

    return NST_OK;
}

int nst_cache_build_key(struct nst_cache_ctx *ctx, struct nst_rule_key **pck,
        struct stream *s,
        struct http_msg *msg) {

    struct http_txn *txn = s->txn;
    struct hdr_ctx hdr;
    struct nst_rule_key *ck = NULL;

    ctx->key  = _nst_key_init();
    if(!ctx->key) {
        return NST_ERR;
    }

    nst_debug("[CACHE] Calculate key: ");

    while((ck = *pck++)) {
        int ret;

        switch(ck->type) {
            case NST_RULE_KEY_METHOD:
                nst_debug("method.");
                ret = _nst_key_append(ctx->key,
                        http_known_methods[txn->meth].ptr,
                        http_known_methods[txn->meth].len);

                break;
            case NST_RULE_KEY_SCHEME:
                nst_debug("scheme.");
                ret = _nst_key_append(ctx->key,
                        ctx->req.scheme == SCH_HTTPS ? "HTTPS" : "HTTP",
                        ctx->req.scheme == SCH_HTTPS ? 5 : 4);

                break;
            case NST_RULE_KEY_HOST:
                nst_debug("host.");

                if(ctx->req.host.data) {
                    ret = _nst_key_append(ctx->key, ctx->req.host.data,
                            ctx->req.host.len);
                } else {
                    ret = _nst_key_advance(ctx->key, 2);
                }

                break;
            case NST_RULE_KEY_URI:
                nst_debug("uri.");

                if(ctx->req.uri.data) {
                    ret = _nst_key_append(ctx->key, ctx->req.uri.data,
                            ctx->req.uri.len);

                } else {
                    ret = _nst_key_advance(ctx->key, 2);
                }

                break;
            case NST_RULE_KEY_PATH:
                nst_debug("path.");

                if(ctx->req.path.data) {
                    ret = _nst_key_append(ctx->key, ctx->req.path.data,
                            ctx->req.path.len);

                } else {
                    ret = _nst_key_advance(ctx->key, 2);
                }

                break;
            case NST_RULE_KEY_DELIMITER:
                nst_debug("delimiter.");

                if(ctx->req.delimiter) {
                    ret = _nst_key_append(ctx->key, "?", 1);
                } else {
                    ret = _nst_key_advance(ctx->key, 2);
                }

                break;
            case NST_RULE_KEY_QUERY:
                nst_debug("query.");

                if(ctx->req.query.data && ctx->req.query.len) {
                    ret = _nst_key_append(ctx->key, ctx->req.query.data,
                            ctx->req.query.len);

                } else {
                    ret = _nst_key_advance(ctx->key, 2);
                }

                break;
            case NST_RULE_KEY_PARAM:
                nst_debug("param_%s.", ck->data);

                if(ctx->req.query.data && ctx->req.query.len) {
                    char *v = NULL;
                    int v_l = 0;
                    if(nst_req_find_param(ctx->req.query.data,
                                ctx->req.query.data + ctx->req.query.len,
                                ck->data, &v, &v_l) == NST_OK) {

                        ret = _nst_key_append(ctx->key, v, v_l);
                        break;
                    }

                }

                ret = _nst_key_advance(ctx->key, 2);
                break;
            case NST_RULE_KEY_HEADER:
                hdr.idx = 0;
                nst_debug("header_%s.", ck->data);

                while (http_find_header2(ck->data, strlen(ck->data),
                            ci_head(msg->chn), &txn->hdr_idx, &hdr)) {

                    ret = _nst_key_append(ctx->key, hdr.line + hdr.val,
                            hdr.vlen);

                }

                ret = ret == NST_OK && _nst_key_advance(ctx->key,
                        hdr.idx == 0 ? 2 : 1);

                break;
            case NST_RULE_KEY_COOKIE:
                nst_debug("cookie_%s.", ck->data);

                if(ctx->req.cookie.data) {
                    char *v = NULL;
                    size_t v_l = 0;

                    if(http_extract_cookie_value(ctx->req.cookie.data,
                                ctx->req.cookie.data + ctx->req.cookie.len,
                                ck->data, strlen(ck->data), 1, &v, &v_l)) {

                        ret = _nst_key_append(ctx->key, v, v_l);
                        break;
                    }

                }

                ret = _nst_key_advance(ctx->key, 2);
                break;
            case NST_RULE_KEY_BODY:
                nst_debug("body.");

                if(txn->meth == HTTP_METH_POST || txn->meth == HTTP_METH_PUT) {

                    if((s->be->options & PR_O_WREQ_BODY)
                            && ci_data(msg->chn) - msg->sov > 0) {

                        ret = _nst_key_append(ctx->key,
                                ci_head(msg->chn) + msg->sov,
                                ci_data(msg->chn) - msg->sov);

                    } else {
                        ret = _nst_key_advance(ctx->key, 2);
                    }
                }
                break;
            default:
                break;
        }
        if(ret != NST_OK) {
            return NST_ERR;
        }
    }

    nst_debug("\n");
    return NST_OK;
}

struct buffer *nst_cache_build_purge_key(struct stream *s,
        struct http_msg *msg) {

    struct http_txn *txn = s->txn;
    int https;
    char *path_beg, *url_end;
    struct hdr_ctx ctx;
    int ret;
    struct buffer *key;

    /* method.scheme.host.uri */
    key = _nst_key_init();
    if(!key) {
        return NULL;
    }

    ret = _nst_key_append(key, "GET", 3);
    if(ret != NST_OK) {
        return NULL;
    }

    https = 0;
#ifdef USE_OPENSSL
    if(s->sess->listener->bind_conf->is_ssl) {
        https = 1;
    }
#endif

    ret = _nst_key_append(key, https ? "HTTPS": "HTTP",
            strlen(https ? "HTTPS": "HTTP"));
    if(ret != NST_OK) {
        return NULL;
    }

    ctx.idx  = 0;
    if(http_find_header2("Host", 4, ci_head(msg->chn), &txn->hdr_idx, &ctx)) {
        ret = _nst_key_append(key, ctx.line + ctx.val, ctx.vlen);
        if(ret != NST_OK) {
            return NULL;
        }
    }

    path_beg = http_txn_get_path(txn);
    url_end  = NULL;
    if(path_beg) {
        url_end = ci_head(msg->chn) + msg->sl.rq.u + msg->sl.rq.u_l;
        ret     = _nst_key_append(key, path_beg, url_end - path_beg);
        if(ret != NST_OK) {
            return NULL;
        }
    }

    return key;
}

/*
 * Check if valid cache exists
 */
int nst_cache_exists(struct nst_cache_ctx *ctx, int mode) {
    struct nst_cache_entry *entry = NULL;
    int ret = NST_CACHE_CTX_STATE_INIT;

    if(!ctx->key) {
        return ret;
    }

    nuster_shctx_lock(&nuster.cache->dict[0]);
    entry = nst_cache_dict_get(ctx->key, ctx->hash);

    if(entry) {

        /*
         * before disk, entry is set to valid after response is cached to memory
         * now we can save cache to both memory and disk, and we can also save
         * cache to disk only.
         * To keep from big changes, we still use valid to indicate the cache is
         * in memory, and use another *file to indicate the disk persistence.
         * So if valid, return memory cache
         * if invalid and file is set, return disk cache
         * if entry is null, check disk and return cache if exists
         * Since valid only indicates whether or not cached is in memory, the
         * state is set to invalid even if the cache is successfully saved to
         * disk in disk_only mode
         */
        if(entry->state == NST_CACHE_ENTRY_STATE_VALID) {
            ctx->data = entry->data;
            ctx->data->clients++;
            ret = NST_CACHE_CTX_STATE_HIT;
        }

        if(entry->state == NST_CACHE_ENTRY_STATE_INVALID && entry->file) {
            ctx->disk.file = entry->file;
            ret = NST_CACHE_CTX_STATE_CHECK_PERSIST;
        }
    } else {
        if(mode != NST_DISK_OFF) {
            ctx->disk.file = NULL;
            if(nuster.cache->disk.loaded) {
                ret = NST_CACHE_CTX_STATE_INIT;
            } else {
                ret = NST_CACHE_CTX_STATE_CHECK_PERSIST;
            }
        }
    }

    nuster_shctx_unlock(&nuster.cache->dict[0]);

    if(ret == NST_CACHE_CTX_STATE_CHECK_PERSIST) {
        if(ctx->disk.file) {
            if(nuster_persist_valid(&ctx->disk, ctx->key, ctx->hash) ==
                    NST_OK) {

                ret = NST_CACHE_CTX_STATE_HIT_DISK;
            } else {
                ret = NST_CACHE_CTX_STATE_INIT;
            }
        } else {
            ctx->disk.file = nst_memory_alloc(global.nuster.cache.memory,
                    NST_PERSIST_PATH_FILE_LEN + 1);

            if(!ctx->disk.file) {
                ret = NST_CACHE_CTX_STATE_INIT;
            }

            if(nst_persist_exists(&ctx->disk, ctx->key, ctx->hash,
                        global.nuster.cache.directory) == NST_OK) {

                ret = NST_CACHE_CTX_STATE_HIT_DISK;
            } else {
                nst_memory_free(global.nuster.cache.memory, ctx->disk.file);
                ret = NST_CACHE_CTX_STATE_INIT;
            }
        }
    }

    return ret;
}

/*
 * Start to create cache,
 * if cache does not exist, add a new nst_cache_entry
 * if cache exists but expired, add a new nst_cache_data to the entry
 * otherwise, set the corresponding state: bypass, wait
 */
void nst_cache_create(struct nst_cache_ctx *ctx) {
    struct nst_cache_entry *entry = NULL;

    nuster_shctx_lock(&nuster.cache->dict[0]);
    entry = nst_cache_dict_get(ctx->key, ctx->hash);

    if(entry) {

        if(entry->state == NST_CACHE_ENTRY_STATE_CREATING) {
            ctx->state = NST_CACHE_CTX_STATE_WAIT;
        } else if(entry->state == NST_CACHE_ENTRY_STATE_VALID) {
            ctx->state = NST_CACHE_CTX_STATE_HIT;
        } else if(entry->state == NST_CACHE_ENTRY_STATE_EXPIRED
                || entry->state == NST_CACHE_ENTRY_STATE_INVALID) {

            entry->state = NST_CACHE_ENTRY_STATE_CREATING;

            if(ctx->rule->disk != NST_DISK_ONLY) {
                entry->data = nst_cache_data_new();

                if(!entry->data) {
                    entry->state = NST_CACHE_ENTRY_STATE_INVALID;
                    ctx->state   = NST_CACHE_CTX_STATE_BYPASS;
                    ctx->full    = 1;
                } else {
                    ctx->state   = NST_CACHE_CTX_STATE_CREATE;
                    ctx->entry   = entry;
                    ctx->data    = entry->data;
                    ctx->element = entry->data->element;
                }
            } else {
                ctx->state = NST_CACHE_CTX_STATE_CREATE;
                ctx->entry = entry;
            }

        } else {
            ctx->state = NST_CACHE_CTX_STATE_BYPASS;
        }
    } else {
        entry = nst_cache_dict_set(ctx);

        if(entry) {
            ctx->state = NST_CACHE_CTX_STATE_CREATE;
            ctx->entry = entry;
            ctx->data  = entry->data;

            if(ctx->data) {
                ctx->element = entry->data->element;
            }
        } else {
            ctx->state = NST_CACHE_CTX_STATE_BYPASS;
            ctx->full  = 1;
        }
    }

    nuster_shctx_unlock(&nuster.cache->dict[0]);

    if(ctx->state == NST_CACHE_CTX_STATE_CREATE
            && (ctx->rule->disk == NST_DISK_SYNC
                || ctx->rule->disk == NST_DISK_ONLY)) {

        ctx->disk.file = nst_memory_alloc(global.nuster.cache.memory,
                NST_PERSIST_PATH_FILE_LEN + 1);

        if(!ctx->disk.file) {
            return;
        }

        if(nst_persist_init(ctx->disk.file, ctx->hash,
                global.nuster.cache.directory) != NST_OK) {
            return;
        }


        ctx->disk.fd = nst_persist_create(ctx->disk.file);

        nst_persist_meta_init(ctx->disk.meta, (char)ctx->rule->disk,
                ctx->hash, 0, 0, ctx->header_len, ctx->entry->key->data);

        nst_persist_write_key(&ctx->disk, ctx->entry->key);
    }
}

/*
 * Add partial http data to nst_cache_data
 */
int nst_cache_update(struct nst_cache_ctx *ctx, struct http_msg *msg,
        long msg_len) {

    struct nst_cache_element *element;

    if(ctx->rule->disk == NST_DISK_ONLY)  {
        char *data = b_orig(&msg->chn->buf);
        char *p    = ci_head(msg->chn);
        int size   = msg->chn->buf.size;

        if(p - data + msg_len > size) {
            int right = data + size - p;
            int left  = msg_len - right;

            nst_persist_write(&ctx->disk, p, right);
            nst_persist_write(&ctx->disk, data, left);
        } else {
            nst_persist_write(&ctx->disk, p, msg_len);
        }
        ctx->cache_len += msg_len;
    } else {

        element = _nst_cache_data_append(msg, msg_len);

        if(element) {

            if(ctx->element) {
                ctx->element->next = element;
            } else {
                ctx->data->element = element;
            }

            ctx->element = element;

            if(ctx->rule->disk == NST_DISK_SYNC) {
                nst_persist_write(&ctx->disk, element->msg.data,
                        element->msg.len);

                ctx->cache_len += element->msg.len;
            }

        } else {
            ctx->full = 1;

            return NST_ERR;
        }
    }

    return NST_OK;
}

/*
 * cache done
 */
void nst_cache_finish(struct nst_cache_ctx *ctx) {
    ctx->state = NST_CACHE_CTX_STATE_DONE;

    if(ctx->rule->disk == NST_DISK_ONLY) {
        ctx->entry->state = NST_CACHE_ENTRY_STATE_INVALID;
    } else {
        ctx->entry->state = NST_CACHE_ENTRY_STATE_VALID;
    }

    if(*ctx->rule->ttl == 0) {
        ctx->entry->expire = 0;
    } else {
        ctx->entry->expire = get_current_timestamp() / 1000 + *ctx->rule->ttl;
    }

    if(ctx->rule->disk == NST_DISK_SYNC
            || ctx->rule->disk == NST_DISK_ONLY) {

        nst_persist_meta_set_expire(ctx->disk.meta, ctx->entry->expire);

        nst_persist_meta_set_cache_len(ctx->disk.meta, ctx->cache_len);

        nst_persist_write_meta(&ctx->disk);

        ctx->entry->file = ctx->disk.file;
    }
}

void nst_cache_abort(struct nst_cache_ctx *ctx) {
    ctx->entry->state = NST_CACHE_ENTRY_STATE_INVALID;
}

/*
 * Create cache applet to handle the request
 */
void nst_cache_hit(struct stream *s, struct stream_interface *si,
        struct channel *req, struct channel *res, struct nst_cache_data *data) {

    struct appctx *appctx = NULL;

    /*
     * set backend to nuster.applet.cache_engine
     */
    s->target = &nuster.applet.cache_engine.obj_type;

    if(unlikely(!si_register_handler(si, objt_applet(s->target)))) {
        /* return to regular process on error */
        data->clients--;
        s->target = NULL;
    } else {
        appctx = si_appctx(si);
        memset(&appctx->ctx.nuster.cache_engine, 0,
                sizeof(appctx->ctx.nuster.cache_engine));

        appctx->ctx.nuster.cache_engine.data    = data;
        appctx->ctx.nuster.cache_engine.element = data->element;

        req->analysers &= ~AN_REQ_FLT_HTTP_HDRS;
        req->analysers &= ~AN_REQ_FLT_XFER_DATA;

        req->analysers |= AN_REQ_FLT_END;
        req->analyse_exp = TICK_ETERNITY;

        res->flags |= CF_NEVER_WAIT;
    }
}

/*
 * Create cache disk applet to handle the request
 */
void nst_cache_hit_disk(struct stream *s, struct stream_interface *si,
        struct channel *req, struct channel *res, struct nst_cache_ctx *ctx) {

    struct appctx *appctx = NULL;

    /*
     * set backend to nuster.applet.cache_disk_engine
     */
    s->target = &nuster.applet.cache_disk_engine.obj_type;

    if(unlikely(!si_register_handler(si, objt_applet(s->target)))) {
        /* return to regular process on error */
        s->target = NULL;
    } else {
        appctx = si_appctx(si);
        memset(&appctx->ctx.nuster.cache_disk_engine, 0,
                sizeof(appctx->ctx.nuster.cache_disk_engine));

        appctx->ctx.nuster.cache_disk_engine.fd = ctx->disk.fd;
        appctx->ctx.nuster.cache_disk_engine.offset =
            nst_persist_get_header_pos(ctx->disk.meta);

        appctx->ctx.nuster.cache_disk_engine.header_len =
            nst_persist_meta_get_header_len(ctx->disk.meta);

        appctx->st0 = NST_PERSIST_APPLET_HEADER;

        req->analysers &= ~AN_REQ_FLT_HTTP_HDRS;
        req->analysers &= ~AN_REQ_FLT_XFER_DATA;

        req->analysers |= AN_REQ_FLT_END;
        req->analyse_exp = TICK_ETERNITY;

        res->flags |= CF_NEVER_WAIT;
    }
}

void nst_cache_persist_async() {
    struct nst_cache_entry *entry =
        nuster.cache->dict[0].entry[nuster.cache->persist_idx];

    if(!nuster.cache->dict[0].used) {
        return;
    }

    while(entry) {

        if(!nst_cache_entry_invalid(entry)
                && entry->rule->disk == NST_DISK_ASYNC
                && entry->file == NULL) {

            struct nst_cache_element *element = entry->data->element;
            uint64_t cache_len = 0;
            struct persist disk;

            entry->file = nst_memory_alloc(global.nuster.cache.memory,
                    NST_PERSIST_PATH_FILE_LEN + 1);

            if(!entry->file) {
                return;
            }

            if(nst_persist_init(entry->file, entry->hash,
                        global.nuster.cache.directory) != NST_OK) {
                return;
            }

            disk.fd = nst_persist_create(entry->file);

            nst_persist_meta_init(disk.meta, (char)entry->rule->disk,
                    entry->hash, entry->expire, 0, entry->header_len,
                    entry->key->data);

            nst_persist_write_key(&disk, entry->key);

            while(element) {

                if(element->msg.data) {
                    nst_persist_write(&disk, element->msg.data,
                            element->msg.len);

                    cache_len += element->msg.len;
                }

                element = element->next;
            }

            nst_persist_meta_set_cache_len(disk.meta, cache_len);

            nst_persist_write_meta(&disk);

            close(disk.fd);
        }

        entry = entry->next;

    }

    nuster.cache->persist_idx++;

    /* if we have checked the whole dict */
    if(nuster.cache->persist_idx == nuster.cache->dict[0].size) {
        nuster.cache->persist_idx = 0;
    }

}

void nst_cache_persist_load() {

    if(global.nuster.cache.directory && !nuster.cache->disk.loaded) {
        char *file;
        char meta[NST_PERSIST_META_SIZE];
        struct buffer *key;
        int fd;

        file = nuster.cache->disk.file;

        if(nuster.cache->disk.dir) {
            struct dirent *de = nuster_persist_dir_next(nuster.cache->disk.dir);

            if(de) {
                DIR *dir2;
                struct dirent *de2;

                if(strcmp(de->d_name, ".") == 0
                        || strcmp(de->d_name, "..") == 0) {

                    return;
                }

                memcpy(file + NST_PERSIST_PATH_BASE_LEN, "/", 1);
                memcpy(file + NST_PERSIST_PATH_BASE_LEN + 1, de->d_name,
                        strlen(de->d_name));

                dir2 = opendir(file);

                if(!dir2) {
                    return;
                }

                while((de2 = readdir(dir2)) != NULL) {
                    if(strcmp(de2->d_name, ".") == 0
                            || strcmp(de2->d_name, "..") == 0) {

                        continue;
                    }

                    memcpy(file + NST_PERSIST_PATH_HASH_LEN, "/", 1);
                    memcpy(file + NST_PERSIST_PATH_HASH_LEN + 1, de2->d_name,
                            strlen(de2->d_name));

                    fd = nst_persist_open(file);

                    if(fd == -1) {
                        return;
                    }

                    if(nst_persist_get_meta(fd, meta) != NST_OK) {
                        unlink(file);
                        close(fd);
                        return;
                    }

                    key = nst_memory_alloc(global.nuster.cache.memory,
                            sizeof(*key));

                    if(!key) {
                        return;
                    }

                    key->size = nst_persist_meta_get_key_len(meta);
                    key->area = nst_memory_alloc(global.nuster.cache.memory,
                            key->size);

                    if(!key->area) {
                        nst_memory_free(global.nuster.cache.memory, key);
                        return;
                    }

                    if(nuster_persist_get_key(fd, meta, key) != NST_OK) {
                        nst_memory_free(global.nuster.cache.memory,
                                key->area);

                        nst_memory_free(global.nuster.cache.memory, key);

                        unlink(file);
                        close(fd);
                        return;
                    }

                    nst_cache_dict_set_from_disk(file, meta, key);

                }
            } else {
                nuster.cache->disk.idx++;
                closedir(nuster.cache->disk.dir);
                nuster.cache->disk.dir = NULL;
            }
        } else {
            nuster.cache->disk.dir = nst_persist_opendir_by_idx(file,
                    nuster.cache->disk.idx, global.nuster.cache.directory);

            if(!nuster.cache->disk.dir) {
                nuster.cache->disk.idx++;
            }
        }

        if(nuster.cache->disk.idx == 16 * 16) {
            nuster.cache->disk.loaded = 1;
            nuster.cache->disk.idx    = 0;
        }

    }
}

void nst_cache_persist_cleanup() {

    if(global.nuster.cache.directory && nuster.cache->disk.loaded) {
        char *file = nuster.cache->disk.file;

        if(nuster.cache->disk.dir) {
            struct dirent *de = nuster_persist_dir_next(nuster.cache->disk.dir);

            if(de) {
                nuster_persist_cleanup(file, de);
            } else {
                nuster.cache->disk.idx++;
                closedir(nuster.cache->disk.dir);
                nuster.cache->disk.dir = NULL;
            }
        } else {
            nuster.cache->disk.dir = nst_persist_opendir_by_idx(file,
                    nuster.cache->disk.idx, global.nuster.cache.directory);

            if(!nuster.cache->disk.dir) {
                nuster.cache->disk.idx++;
            }
        }

        if(nuster.cache->disk.idx == 16 * 16) {
            nuster.cache->disk.idx = 0;
        }

    }
}

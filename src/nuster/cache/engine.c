/*
 * Cache engine functions.
 *
 * Copyright (C) [Jiang Wenyuan](https://github.com/jiangwenyuan), < koubunen AT gmail DOT com >
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <types/applet.h>
#include <types/cli.h>
#include <types/global.h>

#include <proto/filters.h>
#include <proto/log.h>
#include <proto/proto_http.h>
#include <proto/sample.h>
#include <proto/raw_sock.h>
#include <proto/stream_interface.h>
#include <proto/acl.h>
#include <proto/proxy.h>

#include <import/xxhash.h>

#ifdef USE_OPENSSL
#include <proto/ssl_sock.h>
#include <types/ssl_sock.h>
#endif

#include <nuster/shctx.h>
#include <nuster/cache.h>

static const char *cache_msgs[NUSTER_CACHE_MSG_SIZE] = {
    [NUSTER_CACHE_200] =
        "HTTP/1.0 200 OK\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "OK\n",

    [NUSTER_CACHE_400] =
        "HTTP/1.0 400 Bad request\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Bad request\n",

    [NUSTER_CACHE_404] =
        "HTTP/1.0 404 Not Found\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Not Found\n",

    [NUSTER_CACHE_500] =
        "HTTP/1.0 500 Server Error\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Server Error\n",
};

struct chunk cache_msg_chunks[NUSTER_CACHE_MSG_SIZE];

/*
 * Cache the keys which calculated in request for response use
 */
struct nst_cache_rule_stash *nst_cache_stash_rule(struct nst_cache_ctx *ctx,
        struct nst_cache_rule *rule, char *key, uint64_t hash) {

    struct nst_cache_rule_stash *stash = pool_alloc2(global.cache.pool.stash);

    if(stash) {
        stash->rule = rule;
        stash->key  = key;
        stash->hash = hash;
        if(ctx->stash) {
            stash->next = ctx->stash;
        } else {
            stash->next = NULL;
        }
        ctx->stash = stash;
    }
    return stash;
}

int nst_cache_test_rule(struct nst_cache_rule *rule, struct stream *s, int res) {
    int ret;

    /* no acl defined */
    if(!rule->cond) {
        return 1;
    }

    if(res) {
        ret = acl_exec_cond(rule->cond, s->be, s->sess, s, SMP_OPT_DIR_RES|SMP_OPT_FINAL);
    } else {
        ret = acl_exec_cond(rule->cond, s->be, s->sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
    }
    ret = acl_pass(ret);
    if(rule->cond->pol == ACL_COND_UNLESS) {
        ret = !ret;
    }

    if(ret) {
        return 1;
    }
    return 0;
}

static char *_string_append(char *dst, int *dst_len, int *dst_size,
        char *src, int src_len) {

    int left     = *dst_size - *dst_len;
    int need     = src_len + 1;
    int old_size = *dst_size;

    if(left < need) {
        *dst_size += ((need - left) / NST_CACHE_DEFAULT_KEY_SIZE + 1)  * NST_CACHE_DEFAULT_KEY_SIZE;
    }

    if(old_size != *dst_size) {
        char *new_dst = realloc(dst, *dst_size);
        if(!new_dst) {
            free(dst);
            return NULL;
        }
        dst = new_dst;
    }

    memcpy(dst + *dst_len, src, src_len);
    *dst_len += src_len;
    dst[*dst_len] = '\0';
    return dst;
}

static char *_nst_cache_key_append(char *dst, int *dst_len, int *dst_size,
        char *src, int src_len) {
    char *key = _string_append(dst, dst_len, dst_size, src, src_len);
    if(key) {
        return _string_append(dst, dst_len, dst_size, ".", 1);
    }
    return NULL;
}

static int _nst_cache_find_param_value_by_name(char *query_beg, char *query_end,
        char *name, char **value, int *value_len) {

    char equal   = '=';
    char and     = '&';
    char *ptr    = query_beg;
    int name_len = strlen(name);

    while(ptr + name_len + 1 < query_end) {
        if(!memcmp(ptr, name, name_len) && *(ptr + name_len) == equal) {
            if(ptr == query_beg || *(ptr - 1) == and) {
                ptr    = ptr + name_len + 1;
                *value = ptr;
                while(ptr < query_end && *ptr != and) {
                    (*value_len)++;
                    ptr++;
                }
                return 1;
            }
        }
        ptr++;
    }
    return 0;
}

/*
 * create a new nst_cache_data and insert it to cache->data list
 */
struct nst_cache_data *nst_cache_data_new() {

    struct nst_cache_data *data = nst_cache_memory_alloc(global.cache.pool.data, sizeof(*data));

    nuster_shctx_lock(cache);
    if(data) {
        data->clients  = 0;
        data->invalid  = 0;
        data->element  = NULL;

        if(cache->data_head == NULL) {
            cache->data_head = data;
            cache->data_tail = data;
            data->next       = data;
        } else {
            if(cache->data_head == cache->data_tail) {
                cache->data_head->next = data;
                data->next             = cache->data_head;
                cache->data_tail       = data;
            } else {
                data->next             = cache->data_head;
                cache->data_tail->next = data;
                cache->data_tail       = data;
            }
        }
    }
    nuster_shctx_unlock(cache);
    return data;
}

/*
 * Append partial http response data
 */
static struct nst_cache_element *_nst_cache_data_append(struct nst_cache_element *tail,
        struct http_msg *msg, long msg_len) {

    struct nst_cache_element *element = nst_cache_memory_alloc(global.cache.pool.element, sizeof(*element));

    if(element) {
        char *data = msg->chn->buf->data;
        char *p    = msg->chn->buf->p;
        int size   = msg->chn->buf->size;

        element->msg = nst_cache_memory_alloc(global.cache.pool.chunk, msg_len);
        if(!element->msg) return NULL;

        if(p - data + msg_len > size) {
            int right = data + size - p;
            int left  = msg_len - right;
            memcpy(element->msg, p, right);
            memcpy(element->msg + right, data, left);
        } else {
            memcpy(element->msg, p, msg_len);
        }
        element->msg_len = msg_len;
        element->next    = NULL;
        if(tail == NULL) {
            tail = element;
        } else {
            tail->next = element;
        }
        nst_cache_stats_update_used_mem(msg_len);
    }
    return element;
}


static int _cache_data_invalid(struct nst_cache_data *data) {
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

    if(cache->data_head) {
        if(cache->data_head == cache->data_tail) {
            if(_cache_data_invalid(cache->data_head)) {
                data             = cache->data_head;
                cache->data_head = NULL;
                cache->data_tail = NULL;
            }
        } else {
            if(_cache_data_invalid(cache->data_head)) {
                data                   = cache->data_head;
                cache->data_tail->next = cache->data_head->next;
                cache->data_head       = cache->data_head->next;
            } else {
                cache->data_tail       = cache->data_head;
                cache->data_head       = cache->data_head->next;
            }
        }
    }

    if(data) {
        struct nst_cache_element *element = data->element;
        while(element) {
            struct nst_cache_element *tmp = element;
            element                   = element->next;

            nst_cache_stats_update_used_mem(-tmp->msg_len);
            nst_cache_memory_free(global.cache.pool.chunk, tmp->msg);
            nst_cache_memory_free(global.cache.pool.element, tmp);
        }
        nst_cache_memory_free(global.cache.pool.data, data);
    }
}

void nst_cache_housekeeping() {
    if(global.cache.status == NST_CACHE_STATUS_ON) {
        nst_cache_dict_rehash();
        nuster_shctx_lock(&cache->dict[0]);
        nst_cache_dict_cleanup();
        nuster_shctx_unlock(&cache->dict[0]);
        nuster_shctx_lock(cache);
        _nst_cache_data_cleanup();
        nuster_shctx_unlock(cache);
    }
}

void nst_cache_init() {
    int i, uuid;
    struct proxy *p;

    if(global.cache.status == NST_CACHE_STATUS_ON) {
        if(global.cache.share == NST_CACHE_STATUS_UNDEFINED) {
            if(global.nbproc == 1) {
                global.cache.share = NST_CACHE_SHARE_OFF;
            } else {
                global.cache.share = NST_CACHE_SHARE_ON;
            }
        }

        global.cache.pool.stash   = create_pool("cp.stash", sizeof(struct nst_cache_rule_stash), MEM_F_SHARED);
        global.cache.pool.ctx     = create_pool("cp.ctx", sizeof(struct nst_cache_ctx), MEM_F_SHARED);

        if(global.cache.share) {
            global.cache.memory = nuster_memory_create("cache.shm", global.cache.dict_size + global.cache.data_size, global.tune.bufsize, NST_CACHE_DEFAULT_CHUNK_SIZE);
            if(!global.cache.memory) {
                goto shm_err;
            }
            if(!nuster_shctx_init(global.cache.memory)) {
                goto shm_err;
            }
            cache = nuster_memory_alloc(global.cache.memory, sizeof(struct cache));
        } else {
            global.cache.memory = nuster_memory_create("cache.shm", NST_CACHE_DEFAULT_SIZE, 0, 0);
            if(!global.cache.memory) {
                goto shm_err;
            }
            if(!nuster_shctx_init(global.cache.memory)) {
                goto shm_err;
            }
            global.cache.pool.data    = create_pool("cp.data", sizeof(struct nst_cache_data), MEM_F_SHARED);
            global.cache.pool.element = create_pool("cp.element", sizeof(struct nst_cache_element), MEM_F_SHARED);
            global.cache.pool.chunk   = create_pool("cp.chunk", global.tune.bufsize, MEM_F_SHARED);
            global.cache.pool.entry   = create_pool("cp.entry", sizeof(struct nst_cache_entry), MEM_F_SHARED);

            cache = malloc(sizeof(struct cache));
        }
        if(!cache) {
            goto err;
        }
        cache->dict[0].entry = NULL;
        cache->dict[0].used  = 0;
        cache->dict[1].entry = NULL;
        cache->dict[1].used  = 0;
        cache->data_head     = NULL;
        cache->data_tail     = NULL;
        cache->rehash_idx    = -1;
        cache->cleanup_idx   = 0;

        if(!nuster_shctx_init(cache)) {
            goto shm_err;
        }

        if(!nst_cache_dict_init()) {
            goto err;
        }

        if(!nst_cache_stats_init()) {
            goto err;
        }

        for (i = 0; i < NUSTER_CACHE_MSG_SIZE; i++) {
            cache_msg_chunks[i].str = (char *)cache_msgs[i];
            cache_msg_chunks[i].len = strlen(cache_msgs[i]);
        }

        /* init cache rule */
        i = uuid = 0;
        p = proxy;
        while(p) {
            struct nst_cache_rule *rule = NULL;
            uint32_t ttl;

            list_for_each_entry(rule, &p->cache_rules, list) {
                struct proxy *pt;

                rule->uuid   = uuid++;
                rule->state  = nuster_memory_alloc(global.cache.memory, sizeof(*rule->state));
                if(!rule->state) {
                    goto err;
                }
                *rule->state = NST_CACHE_RULE_ENABLED;
                ttl          = *rule->ttl;
                free(rule->ttl);
                rule->ttl    = nuster_memory_alloc(global.cache.memory, sizeof(*rule->ttl));
                if(!rule->ttl) {
                    goto err;
                }
                *rule->ttl   = ttl;

                pt = proxy;
                while(pt) {
                    struct nst_cache_rule *rt = NULL;
                    list_for_each_entry(rt, &pt->cache_rules, list) {
                        if(rt == rule) goto out;
                        if(!strcmp(rt->name, rule->name)) {
                            Alert("cache-rule with same name=[%s] found.\n", rule->name);
                            rule->id = rt->id;
                            goto out;
                        }
                    }
                    pt = pt->next;
                }

out:
                if(rule->id == -1) {
                    rule->id = i++;
                }
            }
            p = p->next;
        }

        nuster_debug("[CACHE] on, data_size=%llu\n", global.cache.data_size);
    }
    return;
err:
    Alert("Out of memory when initializing cache.\n");
    exit(1);
shm_err:
    Alert("Error when initializing cache.\n");
    exit(1);
}

int nst_cache_prebuild_key(struct nst_cache_ctx *ctx, struct stream *s, struct http_msg *msg) {

    struct http_txn *txn = s->txn;

    char *url_end;
    struct hdr_ctx hdr;

    ctx->req.scheme = SCH_HTTP;
#ifdef USE_OPENSSL
    if(s->sess->listener->xprt == &ssl_sock) {
        ctx->req.scheme = SCH_HTTPS;
    }
#endif

    ctx->req.host.data = NULL;
    ctx->req.host.len  = 0;
    hdr.idx            = 0;
    if(http_find_header2("Host", 4, msg->chn->buf->p, &txn->hdr_idx, &hdr)) {
        ctx->req.host.data = nst_cache_memory_alloc(global.cache.pool.chunk, hdr.vlen);
        if(!ctx->req.host.data) {
            return 0;
        }
        ctx->req.host.len  = hdr.vlen;
        memcpy(ctx->req.host.data, hdr.line + hdr.val, hdr.vlen);
    }

    ctx->req.path.data = http_get_path(txn);
    ctx->req.path.len  = 0;
    ctx->req.uri.data  = ctx->req.path.data;
    ctx->req.uri.len   = 0;
    url_end            = NULL;
    if(ctx->req.path.data) {
        char *ptr = ctx->req.path.data;
        url_end   = msg->chn->buf->p + msg->sl.rq.u + msg->sl.rq.u_l;
        while(ptr < url_end && *ptr != '?') {
            ptr++;
        }
        ctx->req.path.len = ptr - ctx->req.path.data;
        ctx->req.uri.len  = url_end - ctx->req.uri.data;
    }
    /* extra 1 char as required by regex_exec_match2 */
    ctx->req.path.data = nst_cache_memory_alloc(global.cache.pool.chunk, ctx->req.path.len + 1);
    if(!ctx->req.path.data) {
        return 0;
    }
    memcpy(ctx->req.path.data, ctx->req.uri.data, ctx->req.path.len);

    ctx->req.query.data = NULL;
    ctx->req.query.len  = 0;
    ctx->req.delimiter  = 0;
    if(ctx->req.uri.data) {
        ctx->req.query.data = memchr(ctx->req.uri.data, '?', url_end - ctx->req.uri.data);
        if(ctx->req.query.data) {
            ctx->req.query.data++;
            ctx->req.query.len = url_end - ctx->req.query.data;
            if(ctx->req.query.len) {
                ctx->req.delimiter = 1;
            }
        }
    }

    ctx->req.cookie.data = NULL;
    ctx->req.cookie.len  = 0;
    hdr.idx              = 0;
    if(http_find_header2("Cookie", 6, msg->chn->buf->p, &txn->hdr_idx, &hdr)) {
        ctx->req.cookie.data = hdr.line + hdr.val;
        ctx->req.cookie.len  = hdr.vlen;
    }

    return 1;
}

char *nst_cache_build_key(struct nst_cache_ctx *ctx, struct nst_cache_key **pck, struct stream *s,
        struct http_msg *msg) {

    struct http_txn *txn = s->txn;

    struct hdr_ctx hdr;

    struct nst_cache_key *ck = NULL;
    int key_len          = 0;
    int key_size         = NST_CACHE_DEFAULT_KEY_SIZE;
    char *key            = malloc(key_size);
    if(!key) {
        return NULL;
    }

    nuster_debug("[CACHE] Calculate key: ");
    while((ck = *pck++)) {
        switch(ck->type) {
            case NST_CACHE_KEY_METHOD:
                nuster_debug("method.");
                key = _nst_cache_key_append(key, &key_len, &key_size, http_known_methods[txn->meth].name, strlen(http_known_methods[txn->meth].name));
                break;
            case NST_CACHE_KEY_SCHEME:
                nuster_debug("scheme.");
                key = _nst_cache_key_append(key, &key_len, &key_size, ctx->req.scheme == SCH_HTTPS ? "HTTPS" : "HTTP", ctx->req.scheme == SCH_HTTPS ? 5 : 4);
                break;
            case NST_CACHE_KEY_HOST:
                nuster_debug("host.");
                if(ctx->req.host.data) {
                    key = _nst_cache_key_append(key, &key_len, &key_size, ctx->req.host.data, ctx->req.host.len);
                }
                break;
            case NST_CACHE_KEY_URI:
                nuster_debug("uri.");
                if(ctx->req.uri.data) {
                    key = _nst_cache_key_append(key, &key_len, &key_size, ctx->req.uri.data, ctx->req.uri.len);
                }
                break;
            case NST_CACHE_KEY_PATH:
                nuster_debug("path.");
                if(ctx->req.path.data) {
                    key = _nst_cache_key_append(key, &key_len, &key_size, ctx->req.path.data, ctx->req.path.len);
                }
                break;
            case NST_CACHE_KEY_DELIMITER:
                nuster_debug("delimiter.");
                key = _nst_cache_key_append(key, &key_len, &key_size, ctx->req.delimiter ? "?": "", ctx->req.delimiter);
                break;
            case NST_CACHE_KEY_QUERY:
                nuster_debug("query.");
                if(ctx->req.query.data && ctx->req.query.len) {
                    key = _nst_cache_key_append(key, &key_len, &key_size, ctx->req.query.data, ctx->req.query.len);
                }
                break;
            case NST_CACHE_KEY_PARAM:
                nuster_debug("param_%s.", ck->data);
                if(ctx->req.query.data && ctx->req.query.len) {
                    char *v = NULL;
                    int v_l = 0;
                    if(_nst_cache_find_param_value_by_name(ctx->req.query.data, ctx->req.query.data + ctx->req.query.len, ck->data, &v, &v_l)) {
                        key = _nst_cache_key_append(key, &key_len, &key_size, v, v_l);
                    }

                }
                break;
            case NST_CACHE_KEY_HEADER:
                hdr.idx = 0;
                nuster_debug("header_%s.", ck->data);
                if(http_find_header2(ck->data, strlen(ck->data), msg->chn->buf->p, &txn->hdr_idx, &hdr)) {
                    key = _nst_cache_key_append(key, &key_len, &key_size, hdr.line + hdr.val, hdr.vlen);
                }
                break;
            case NST_CACHE_KEY_COOKIE:
                nuster_debug("header_%s.", ck->data);
                if(ctx->req.cookie.data) {
                    char *v = NULL;
                    int v_l = 0;
                    if(extract_cookie_value(ctx->req.cookie.data, ctx->req.cookie.data + ctx->req.cookie.len, ck->data, strlen(ck->data), 1, &v, &v_l)) {
                        key = _nst_cache_key_append(key, &key_len, &key_size, v, v_l);
                    }
                }
                break;
            case NST_CACHE_KEY_BODY:
                nuster_debug("body.");
                if(txn->meth == HTTP_METH_POST || txn->meth == HTTP_METH_PUT) {
                    if((s->be->options & PR_O_WREQ_BODY) && msg->body_len > 0 ) {
                        key = _nst_cache_key_append(key, &key_len, &key_size, msg->chn->buf->p + msg->sov, msg->body_len);
                    }
                }
                break;
            default:
                break;
        }
        if(!key) return NULL;
    }
    nuster_debug("\n");
    return key;
}

uint64_t nst_cache_hash_key(const char *key) {
    return XXH64(key, strlen(key), 0);
}

char *nst_cache_build_purge_key(struct stream *s, struct http_msg *msg) {
    struct http_txn *txn = s->txn;
    int https;
    char *path_beg, *url_end;
    struct hdr_ctx ctx;
    int key_len  = 0;

    /* method.scheme.host.uri */
    int key_size = NST_CACHE_DEFAULT_KEY_SIZE;
    char *key    = malloc(key_size);
    if(!key) {
        return NULL;
    }

    key = _nst_cache_key_append(key, &key_len, &key_size, "GET", 3);

    https = 0;
#ifdef USE_OPENSSL
    if(s->sess->listener->xprt == &ssl_sock) {
        https = 1;
    }
#endif

    key = _nst_cache_key_append(key, &key_len, &key_size, https ? "HTTPS": "HTTP", strlen(https ? "HTTPS": "HTTP"));
    if(!key) return NULL;

    ctx.idx  = 0;
    if(http_find_header2("Host", 4, msg->chn->buf->p, &txn->hdr_idx, &ctx)) {
        key = _nst_cache_key_append(key, &key_len, &key_size, ctx.line + ctx.val, ctx.vlen);
        if(!key) return NULL;
    }

    path_beg = http_get_path(txn);
    url_end  = NULL;
    if(path_beg) {
        url_end = msg->chn->buf->p + msg->sl.rq.u + msg->sl.rq.u_l;
        key     = _nst_cache_key_append(key, &key_len, &key_size, path_beg, url_end - path_beg);
        if(!key) return NULL;
    }
    return key;
}

/*
 * Check if valid cache exists
 */
struct nst_cache_data *nst_cache_exists(const char *key, uint64_t hash) {
    struct nst_cache_entry *entry = NULL;
    struct nst_cache_data  *data  = NULL;

    if(!key) return NULL;

    nuster_shctx_lock(&cache->dict[0]);
    entry = nst_cache_dict_get(key, hash);
    if(entry && entry->state == NST_CACHE_ENTRY_STATE_VALID) {
        data = entry->data;
        data->clients++;
    }
    nuster_shctx_unlock(&cache->dict[0]);

    return data;
}

/*
 * Start to create cache,
 * if cache does not exist, add a new nst_cache_entry
 * if cache exists but expired, add a new nst_cache_data to the entry
 * otherwise, set the corresponding state: bypass, wait
 */
void nst_cache_create(struct nst_cache_ctx *ctx, char *key, uint64_t hash) {
    struct nst_cache_entry *entry = NULL;

    /* Check if cache is full */
    if(nst_cache_stats_full()) {
        ctx->state = NST_CACHE_CTX_STATE_FULL;
        return;
    }

    nuster_shctx_lock(&cache->dict[0]);
    entry = nst_cache_dict_get(key, hash);
    if(entry) {
        if(entry->state == NST_CACHE_ENTRY_STATE_CREATING) {
            ctx->state = NST_CACHE_CTX_STATE_WAIT;
        } else if(entry->state == NST_CACHE_ENTRY_STATE_VALID) {
            ctx->state = NST_CACHE_CTX_STATE_HIT;
        } else if(entry->state == NST_CACHE_ENTRY_STATE_EXPIRED || entry->state == NST_CACHE_ENTRY_STATE_INVALID) {
            entry->state = NST_CACHE_ENTRY_STATE_CREATING;
            entry->data = nst_cache_data_new();
            if(!entry->data) {
                ctx->state = NST_CACHE_CTX_STATE_BYPASS;
                return;
            }
            ctx->state = NST_CACHE_CTX_STATE_CREATE;
        } else {
            ctx->state = NST_CACHE_CTX_STATE_BYPASS;
        }
    } else {
        entry = nst_cache_dict_set(key, hash, ctx);
        if(entry) {
            ctx->state = NST_CACHE_CTX_STATE_CREATE;
        } else {
            ctx->state = NST_CACHE_CTX_STATE_BYPASS;
            return;
        }
    }
    nuster_shctx_unlock(&cache->dict[0]);
    ctx->entry   = entry;
    ctx->data    = entry->data;
    ctx->element = entry->data->element;
}

/*
 * Add partial http data to nst_cache_data
 */
int nst_cache_update(struct nst_cache_ctx *ctx, struct http_msg *msg, long msg_len) {
    struct nst_cache_element *element = _nst_cache_data_append(ctx->element, msg, msg_len);

    if(element) {
        if(!ctx->element) {
            ctx->data->element = element;
        }
        ctx->element = element;
        return 1;
    } else {
        return 0;
    }
}

/*
 * cache done
 */
void nst_cache_finish(struct nst_cache_ctx *ctx) {
    ctx->state = NST_CACHE_CTX_STATE_DONE;
    ctx->entry->state = NST_CACHE_ENTRY_STATE_VALID;
    if(*ctx->rule->ttl == 0) {
        ctx->entry->expire = 0;
    } else {
        ctx->entry->expire = get_current_timestamp() / 1000 + *ctx->rule->ttl;
    }
}

void nst_cache_abort(struct nst_cache_ctx *ctx) {
    ctx->entry->state = NST_CACHE_ENTRY_STATE_INVALID;
}

/*
 * Create cache applet to handle the request
 */
void nst_cache_hit(struct stream *s, struct stream_interface *si, struct channel *req,
        struct channel *res, struct nst_cache_data *data) {

    struct appctx *appctx = NULL;

    /*
     * set backend to cache_io_applet
     */
    s->target = &cache_io_applet.obj_type;
    if(unlikely(!stream_int_register_handler(si, objt_applet(s->target)))) {
        /* return to regular process on error */
        data->clients--;
        s->target = NULL;
    } else {
        appctx = si_appctx(si);
        memset(&appctx->ctx.cache, 0, sizeof(appctx->ctx.cache));
        appctx->ctx.cache.data    = data;
        appctx->ctx.cache.element = data->element;

        req->analysers &= ~AN_REQ_FLT_HTTP_HDRS;
        req->analysers &= ~AN_REQ_FLT_XFER_DATA;

        req->analysers |= AN_REQ_FLT_END;
        req->analyse_exp = TICK_ETERNITY;

        res->flags |= CF_NEVER_WAIT;
    }
}

/*
 * The cache applet acts like the backend to send cached http data
 */
static void nst_cache_io_handler(struct appctx *appctx) {
    struct stream_interface *si   = appctx->owner;
    struct channel *res           = si_ic(si);
    struct stream *s              = si_strm(si);
    struct nst_cache_element *element = NULL;
    int ret;

    if(appctx->ctx.cache.element) {
        if(appctx->ctx.cache.element == appctx->ctx.cache.data->element) {
            s->res.analysers = 0;
            s->res.analysers |= (AN_RES_WAIT_HTTP | AN_RES_HTTP_PROCESS_BE | AN_RES_HTTP_XFER_BODY);
        }
        element = appctx->ctx.cache.element;

        ret = bi_putblk(res, element->msg, element->msg_len);
        if(ret >= 0) {
            appctx->ctx.cache.element = element->next;
        } else if(ret == -2) {
            appctx->ctx.cache.data->clients--;
            si_shutr(si);
            res->flags |= CF_READ_NULL;
        }
    } else {
        bo_skip(si_oc(si), si_ob(si)->o);
        si_shutr(si);
        res->flags |= CF_READ_NULL;
        appctx->ctx.cache.data->clients--;
    }
}

struct applet cache_io_applet = {
    .obj_type = OBJ_TYPE_APPLET,
    .name = "<CACHE>",
    .fct = nst_cache_io_handler,
    .release = NULL,
};

__attribute__((constructor)) static void __cache_init(void) { }


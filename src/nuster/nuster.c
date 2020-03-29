/*
 * nuster common functions.
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
#include <types/http_htx.h>

#include <proto/stream_interface.h>
#include <proto/proxy.h>
#include <proto/log.h>
#include <proto/acl.h>
#include <proto/http_htx.h>

#include <nuster/nuster.h>

struct nuster nuster = {
    .cache = NULL,
    .nosql = NULL,
    .applet = {
        .cache = {
            .obj_type = OBJ_TYPE_APPLET,
            .name     = "<NUSTER.CACHE.ENGINE>",
        },
        .purger = {
            .obj_type = OBJ_TYPE_APPLET,
            .name     = "<NUSTER.MANAGER.PURGER>",
        },
        .stats = {
            .obj_type = OBJ_TYPE_APPLET,
            .name     = "<NUSTER.MANAGER.STATS>",
        },
        .nosql = {
            .obj_type = OBJ_TYPE_APPLET,
            .name     = "<NUSTER.NOSQL.ENGINE>",
        },
    },
    .proxy = NULL,
};

static void nst_proxy_init() {
    struct proxy *px1;
    int i, uuid, proxy_cnt;
    struct nst_memory *memory;

    /* new rule init */
    global.nuster.memory = nst_memory_create("nuster.shm", NST_DEFAULT_SIZE,
            global.tune.bufsize, NST_CACHE_DEFAULT_CHUNK_SIZE);

    if(!global.nuster.memory) {
        goto err;
    }

    if(nst_shctx_init(global.nuster.memory) != NST_OK) {
        goto err;
    }

    memory = global.nuster.memory;

    i = proxy_cnt = 0;

    px1 = proxies_list;

    while(px1) {
        struct nst_rule_config *r1 = NULL;

        list_for_each_entry(r1, &px1->nuster.rules, list) {
            struct proxy *px2;

            px2 = proxies_list;

            while(px2) {
                struct nst_rule_config *r2 = NULL;

                list_for_each_entry(r2, &px2->nuster.rules, list) {

                    if(r2 == r1) {
                        goto out;
                    }

                    if(!strcmp(r2->name, r1->name)) {
                        ha_alert("nuster rule with same name=[%s] found.\n", r1->name);
                        r1->id = r2->id;
                        goto out;
                    }
                }

                px2 = px2->next;
            }

out:
            if(r1->id == -1) {
                r1->id = i++;
            }
        }

        proxy_cnt++;
        px1 = px1->next;
    }

    nuster.proxy = nst_memory_alloc(memory, proxy_cnt * sizeof(struct nst_proxy *));

    if(!nuster.proxy) {
        goto err;
    }

    memset(nuster.proxy, 0, proxy_cnt * sizeof(struct nst_proxy *));

    i = uuid = 0;

    px1 = proxies_list;

    while(px1) {
        if(px1->nuster.mode == NST_MODE_CACHE || px1->nuster.mode == NST_MODE_NOSQL) {
            struct nst_rule_config *rc = NULL;

            struct nst_rule *rule = NULL;
            struct nst_rule *tail = NULL;
            struct nst_proxy *px  = NULL;

            nuster.proxy[px1->uuid] = nst_memory_alloc(memory, sizeof(struct nst_proxy));

            px = nuster.proxy[px1->uuid];

            if(!px) {
                goto err;
            }

            memset(px, 0, sizeof(struct nst_proxy));

            list_for_each_entry(rc, &px1->nuster.rules, list) {
                struct nst_rule_key *key = NULL;

                rule = nst_memory_alloc(memory, sizeof(struct nst_rule));

                if(!rule) {
                    goto err;
                }

                rule->uuid  = uuid++;
                rule->idx   = px->rule_cnt++;
                rule->id    = rc->id;
                rule->state = NST_RULE_ENABLED;
                rule->name  = rc->name;

                key = px->key;

                while(key) {
                    if(strcmp(key->name, rc->key.name) == 0) {
                        break;
                    }

                    key = key->next;
                }

                if(key) {
                    rule->key = key;
                } else {
                    key = nst_memory_alloc(memory, sizeof(struct nst_rule_key));

                    if(!key) {
                        goto err;
                    }

                    key->name = rc->key.name;
                    key->data = rc->key.data;
                    key->idx  = px->key_cnt++;
                    key->next = NULL;

                    if(px->key) {
                        key->next = px->key;
                    }

                    px->key = key;
                }

                rule->key = key;

                rule->code = rc->code;
                rule->ttl  = rc->ttl;
                rule->disk = rc->disk;
                rule->etag = rc->etag;

                rule->last_modified = rc->last_modified;

                rule->extend[0] = rc->extend[0];
                rule->extend[1] = rc->extend[1];
                rule->extend[2] = rc->extend[2];
                rule->extend[3] = rc->extend[3];

                rule->cond = rc->cond;

                rule->next = NULL;

                if(px->rule) {
                    tail->next = rule;
                } else {
                    px->rule = rule;
                }

                tail = rule;
            }
        }

        px1 = px1->next;
    }

    return;

err:
    ha_alert("Out of memory when initializing rules.\n");
    exit(1);
}

void nuster_init() {

    if(!(global.mode & MODE_MWORKER)) {
        ha_alert("[nuster] Not in master-worker mode."
                "Add master-worker to conf file  or run with -W.\n");
        exit(1);
    }

    nst_proxy_init();

    nst_manager_init();

    nst_cache_init();
    nst_nosql_init();
}

int nst_test_rule(struct nst_rule *rule, struct stream *s, int res) {
    int ret;

    /* no acl defined */
    if(!rule->cond) {
        return NST_OK;
    }

    if(res) {
        ret = acl_exec_cond(rule->cond, s->be, s->sess, s,
                SMP_OPT_DIR_RES|SMP_OPT_FINAL);
    } else {
        ret = acl_exec_cond(rule->cond, s->be, s->sess, s,
                SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
    }

    ret = acl_pass(ret);

    if(rule->cond->pol == ACL_COND_UNLESS) {
        ret = !ret;
    }

    if(ret) {
        return NST_OK;
    }

    return NST_ERR;
}

void nst_debug(struct stream *s, const char *fmt, ...) {

    if((global.mode & MODE_DEBUG)) {
        va_list args;
        struct session *sess = strm_sess(s);

        fprintf(stderr, "%08x:%s.nuster[%04x:%04x]: ",
                s->uniq_id, s->be->id,
                objt_conn(sess->origin) ?
                (unsigned short)objt_conn(sess->origin)->handle.fd : -1,
                objt_cs(s->si[1].end) ?
                (unsigned short)objt_cs(s->si[1].end)->conn->handle.fd : -1);

        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
    }
}

void nst_debug2(const char *fmt, ...) {

    if((global.mode & MODE_DEBUG)) {
        va_list args;
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
    }
}

void nst_key_debug(struct nst_key *key) {

    if((global.mode & MODE_DEBUG)) {
        int i;

        for(i = 0; i < key->size; i++) {
            char c = key->data[i];

            if(c != 0) {
                fprintf(stderr, "%c", c);
            }
        }

        fprintf(stderr, "\n");
    }
}

int nst_key_build(struct stream *s, struct http_msg *msg, struct nst_rule *rule,
        struct nst_http_txn *txn, struct nst_key *key, enum http_meth_t method) {

    struct nst_key_element *ck = NULL;
    struct nst_key_element **pck = rule->key->data;

    struct buffer *buf = nst_key_init();

    nst_debug(s, "Calculate key: ");

    while((ck = *pck++)) {
        int ret = NST_ERR;

        switch(ck->type) {
            case NST_KEY_ELEMENT_METHOD:
                nst_debug2("method.");

                ret = nst_key_catist(buf, http_known_methods[method]);

                break;
            case NST_KEY_ELEMENT_SCHEME:
                nst_debug2("scheme.");

                {
                    struct ist scheme = txn->req.scheme == SCH_HTTPS ? ist("HTTPS") : ist("HTTP");
                    ret = nst_key_catist(buf, scheme);
                }

                break;
            case NST_KEY_ELEMENT_HOST:
                nst_debug2("host.");

                if(txn->req.host.len) {
                    ret = nst_key_catist(buf, txn->req.host);
                } else {
                    ret = nst_key_catdel(buf);
                }

                break;
            case NST_KEY_ELEMENT_URI:
                nst_debug2("uri.");

                if(txn->req.uri.len) {
                    ret = nst_key_catist(buf, txn->req.uri);
                } else {
                    ret = nst_key_catdel(buf);
                }

                break;
            case NST_KEY_ELEMENT_PATH:
                nst_debug2("path.");

                if(txn->req.path.len) {
                    ret = nst_key_catist(buf, txn->req.path);
                } else {
                    ret = nst_key_catdel(buf);
                }

                break;
            case NST_KEY_ELEMENT_DELIMITER:
                nst_debug2("delimiter.");

                if(txn->req.delimiter) {
                    ret = nst_key_catist(buf, ist("?"));
                } else {
                    ret = nst_key_catdel(buf);
                }

                break;
            case NST_KEY_ELEMENT_QUERY:
                nst_debug2("query.");

                if(txn->req.query.len) {
                    ret = nst_key_catist(buf, txn->req.query);
                } else {
                    ret = nst_key_catdel(buf);
                }

                break;
            case NST_KEY_ELEMENT_PARAM:
                nst_debug2("param_%s.", ck->data);

                if(txn->req.query.len) {
                    char *v = NULL;
                    int v_l = 0;

                    if(nst_http_find_param(txn->req.query.ptr,
                                txn->req.query.ptr + txn->req.query.len,
                                ck->data, &v, &v_l) == NST_OK) {

                        ret = nst_key_catist(buf, ist2(v, v_l));
                        break;
                    }
                }

                ret = nst_key_catdel(buf);
                break;
            case NST_KEY_ELEMENT_HEADER:
                {
                    struct htx *htx = htxbuf(&s->req.buf);
                    struct http_hdr_ctx hdr = { .blk = NULL };
                    struct ist h = {
                        .ptr = ck->data,
                        .len = strlen(ck->data),
                    };

                    nst_debug2("header_%s.", ck->data);

                    while(http_find_header(htx, h, &hdr, 0)) {
                        ret = nst_key_catist(buf, hdr.value);

                        if(ret == NST_ERR) {
                            break;
                        }
                    }
                }

                ret = nst_key_catdel(buf);
                break;
            case NST_KEY_ELEMENT_COOKIE:
                nst_debug2("cookie_%s.", ck->data);

                if(txn->req.cookie.len) {
                    char *v = NULL;
                    size_t v_l = 0;

                    if(http_extract_cookie_value(txn->req.cookie.ptr,
                                txn->req.cookie.ptr + txn->req.cookie.len,
                                ck->data, strlen(ck->data), 1, &v, &v_l)) {

                        ret = nst_key_catist(buf, ist2(v, v_l));
                        break;
                    }

                }

                ret = nst_key_catdel(buf);
                break;
            case NST_KEY_ELEMENT_BODY:
                nst_debug2("body.");

                if(s->txn->meth == HTTP_METH_POST || s->txn->meth == HTTP_METH_PUT) {

                    int pos;
                    struct htx *htx = htxbuf(&msg->chn->buf);

                    for(pos = htx_get_first(htx); pos != -1; pos = htx_get_next(htx, pos)) {
                        struct htx_blk *blk = htx_get_blk(htx, pos);
                        uint32_t        sz  = htx_get_blksz(blk);
                        enum htx_blk_type type = htx_get_blk_type(blk);

                        if(type != HTX_BLK_DATA) {
                            continue;
                        }

                        ret = nst_key_cat(buf, htx_get_blk_ptr(htx, blk), sz);

                        if(ret != NST_OK) {
                            break;
                        }
                    }
                }

                ret = nst_key_catdel(buf);
                break;
            default:
                ret = NST_ERR;
                break;
        }

        if(ret != NST_OK) {
            return NST_ERR;
        }
    }

    nst_debug2("\n");

    key->size = buf->data;
    key->data = malloc(key->size);

    if(!key->data) {
        return NST_ERR;
    }

    memcpy(key->data, buf->area, buf->data);

    return NST_OK;
}


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

nuster_t  nuster = {
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

static void
_nst_proxy_init() {
    hpx_proxy_t   *px1;
    nst_memory_t  *memory;
    int            uuid, proxy_cnt;

    /* new rule init */
    global.nuster.memory = nst_memory_create("nuster.shm", NST_DEFAULT_SIZE,
            global.tune.bufsize, NST_DEFAULT_CHUNK_SIZE);

    if(!global.nuster.memory) {
        goto err;
    }

    if(nst_shctx_init(global.nuster.memory) != NST_OK) {
        goto err;
    }

    memory = global.nuster.memory;

    proxy_cnt = 0;

    px1 = proxies_list;

    while(px1) {
        nst_rule_config_t  *r1 = NULL;

        list_for_each_entry(r1, &px1->nuster.rules, list) {
            hpx_proxy_t  *px2;

            px2 = proxies_list;

            while(px2) {
                nst_rule_config_t  *r2 = NULL;

                list_for_each_entry(r2, &px2->nuster.rules, list) {

                    if(r2 == r1) {
                        break;
                    }

                    if(!strcmp(r2->name, r1->name)) {
                        ha_alert("nuster rule with same name=[%s] found.\n", r1->name);

                        exit(1);
                    }
                }

                px2 = px2->next;
            }
        }

        proxy_cnt++;
        px1 = px1->next;
    }

    nuster.proxy = nst_memory_alloc(memory, proxy_cnt * sizeof(nst_proxy_t *));

    if(!nuster.proxy) {
        goto err;
    }

    memset(nuster.proxy, 0, proxy_cnt * sizeof(nst_proxy_t *));

    uuid = 0;

    px1 = proxies_list;

    while(px1) {
        if(px1->nuster.mode == NST_MODE_CACHE || px1->nuster.mode == NST_MODE_NOSQL) {
            nst_rule_config_t  *rc   = NULL;
            nst_rule_t         *rule = NULL;
            nst_rule_t         *tail = NULL;
            nst_proxy_t        *px   = NULL;

            nuster.proxy[px1->uuid] = nst_memory_alloc(memory, sizeof(nst_proxy_t));

            px = nuster.proxy[px1->uuid];

            if(!px) {
                goto err;
            }

            memset(px, 0, sizeof(nst_proxy_t));

            list_for_each_entry(rc, &px1->nuster.rules, list) {
                nst_rule_key_t  *key = NULL;

                rule = nst_memory_alloc(memory, sizeof(nst_rule_t));

                if(!rule) {
                    goto err;
                }

                rule->next  = NULL;
                rule->uuid  = uuid++;
                rule->idx   = px->rule_cnt++;
                rule->state = NST_RULE_ENABLED;

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
                    key = nst_memory_alloc(memory, sizeof(nst_rule_key_t));

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

                rule->key  = key;
                rule->code = rc->code;

                rule->prop.pid           = ist2(rc->proxy, strlen(rc->proxy));
                rule->prop.rid           = ist2(rc->name, strlen(rc->name));
                rule->prop.ttl           = rc->ttl;
                rule->prop.store         = rc->store;
                rule->prop.etag          = rc->etag;
                rule->prop.last_modified = rc->last_modified;
                rule->prop.extend[0]     = rc->extend[0];
                rule->prop.extend[1]     = rc->extend[1];
                rule->prop.extend[2]     = rc->extend[2];
                rule->prop.extend[3]     = rc->extend[3];
                rule->prop.wait          = rc->wait;

                rule->cond = rc->cond;

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

void
nuster_init() {

    if(!(global.mode & MODE_MWORKER)) {
        ha_alert("[nuster] Not in master-worker mode."
                "Add master-worker to conf file  or run with -W.\n");

        exit(1);
    }

    _nst_proxy_init();

    nst_manager_init();

    nst_cache_init();
    nst_nosql_init();
}

int
nst_test_rule(hpx_stream_t *s, nst_rule_t *rule, int res) {
    int  ret;

    /* no acl defined */
    if(!rule->cond) {
        return NST_OK;
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
        return NST_OK;
    }

    return NST_ERR;
}

void
nst_debug(hpx_stream_t *s, const char *fmt, ...) {

    if((global.mode & MODE_DEBUG)) {
        va_list         args;
        hpx_session_t  *sess = strm_sess(s);

        chunk_printf(&trash, "%08x:%s.nuster[%04x:%04x]: ", s->uniq_id, s->be->id,
                objt_conn(sess->origin) ?
                (unsigned short)objt_conn(sess->origin)->handle.fd : -1,
                objt_cs(s->si[1].end) ?
                (unsigned short)objt_cs(s->si[1].end)->conn->handle.fd : -1);

        va_start(args, fmt);
        trash.data += vsprintf(trash.area + trash.data, fmt, args);
        trash.area[trash.data++] = '\n';
        va_end(args);
        shut_your_big_mouth_gcc(write(1, trash.area, trash.data));
    }
}

void
nst_debug_beg(hpx_stream_t *s, const char *fmt, ...) {

    if((global.mode & MODE_DEBUG)) {
        va_list         args;
        hpx_session_t  *sess = strm_sess(s);

        chunk_printf(&trash, "%08x:%s.nuster[%04x:%04x]: ", s->uniq_id, s->be->id,
                objt_conn(sess->origin) ?
                (unsigned short)objt_conn(sess->origin)->handle.fd : -1,
                objt_cs(s->si[1].end) ?
                (unsigned short)objt_cs(s->si[1].end)->conn->handle.fd : -1);

        va_start(args, fmt);
        trash.data += vsprintf(trash.area + trash.data, fmt, args);
        va_end(args);
    }
}

void
nst_debug_add(const char *fmt, ...) {

    if((global.mode & MODE_DEBUG)) {
        va_list         args;

        va_start(args, fmt);
        trash.data += vsprintf(trash.area + trash.data, fmt, args);
        va_end(args);
    }
}

void
nst_debug_end(const char *fmt, ...) {

    if((global.mode & MODE_DEBUG)) {
        va_list         args;

        va_start(args, fmt);
        trash.data += vsprintf(trash.area + trash.data, fmt, args);
        va_end(args);
        trash.area[trash.data++] = '\n';
        shut_your_big_mouth_gcc(write(1, trash.area, trash.data));
    }
}


/*
 * nuster common functions.
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

#include <proto/stream_interface.h>
#include <proto/proxy.h>
#include <proto/log.h>
#include <proto/acl.h>

#include <nuster/memory.h>
#include <nuster/nuster.h>
#include <nuster/http.h>

struct nuster nuster = {
    .cache = NULL,
    .nosql = NULL,
    .applet = {
        .cache_engine = {
            .obj_type = OBJ_TYPE_APPLET,
            .name     = "<NUSTER.CACHE.ENGINE>",
        },
        .cache_manager = {
            .obj_type = OBJ_TYPE_APPLET,
            .name     = "<NUSTER.CACHE.MANAGER>",
        },
        .cache_stats = {
            .obj_type = OBJ_TYPE_APPLET,
            .name     = "<NUSTER.CACHE.STATS>",
        },
        .nosql_engine = {
            .obj_type = OBJ_TYPE_APPLET,
            .name     = "<NUSTER.NOSQL.ENGINE>",
        },
    },
};

void nuster_debug(const char *fmt, ...) {
    if((global.mode & MODE_DEBUG)) {
        va_list args;
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
    }
}

void nuster_init() {
    int i, uuid;
    struct proxy *p;

    for (i = 0; i < NUSTER_HTTP_SIZE; i++) {
        nuster_http_msg_chunks[i].str = (char *)nuster_http_msgs[i];
        nuster_http_msg_chunks[i].len = strlen(nuster_http_msgs[i]);
    }

    nst_cache_init();
    nst_nosql_init();


    /* init rule */
    i = uuid = 0;
    p = proxies_list;
    while(p) {
        struct nuster_rule *rule = NULL;
        uint32_t ttl;
        struct nuster_memory *m  = NULL;

        list_for_each_entry(rule, &p->nuster.rules, list) {
            struct proxy *pt;

            if(global.nuster.cache.status == NUSTER_STATUS_ON && p->nuster.mode == NUSTER_MODE_CACHE) {
                m = global.nuster.cache.memory;
            } else if(global.nuster.nosql.status == NUSTER_STATUS_ON && p->nuster.mode == NUSTER_MODE_NOSQL) {
                m = global.nuster.nosql.memory;
            } else {
                continue;
            }

            rule->uuid  = uuid++;
            rule->state = nuster_memory_alloc(m, sizeof(*rule->state));

            if(!rule->state) {
                goto err;
            }
            *rule->state = NUSTER_RULE_ENABLED;
            ttl          = *rule->ttl;
            free(rule->ttl);
            rule->ttl    = nuster_memory_alloc(m, sizeof(*rule->ttl));

            if(!rule->ttl) {
                goto err;
            }
            *rule->ttl = ttl;

            pt = proxies_list;
            while(pt) {
                struct nuster_rule *rt = NULL;
                list_for_each_entry(rt, &pt->nuster.rules, list) {
                    if(rt == rule) goto out;
                    if(!strcmp(rt->name, rule->name)) {
                        ha_alert("nuster rule with same name=[%s] found.\n", rule->name);
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

    return;

err:
    ha_alert("Out of memory when initializing rules.\n");
    exit(1);
}

int nuster_test_rule(struct nuster_rule *rule, struct stream *s, int res) {
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


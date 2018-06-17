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

const char *nuster_http_msgs[NUSTER_HTTP_SIZE] = {
    [NUSTER_HTTP_200] =
        "HTTP/1.0 200 OK\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "200 OK\n",

    [NUSTER_HTTP_400] =
        "HTTP/1.0 400 Bad request\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "400 Bad request\n",

    [NUSTER_HTTP_404] =
        "HTTP/1.0 404 Not Found\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "404 Not Found\n",

    [NUSTER_HTTP_405] =
        "HTTP/1.0 405 Method Not Allowed\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "405 Method Not Allowed\n",

    [NUSTER_HTTP_500] =
        "HTTP/1.0 500 Internal Server Error\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "500 Internal Server Error\n",

    [NUSTER_HTTP_507] =
        "HTTP/1.0 507 Insufficient Storage\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "507 Insufficient Storage\n",
};

struct chunk nuster_http_msg_chunks[NUSTER_HTTP_SIZE];

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

void nuster_response(struct stream *s, struct chunk *msg) {
    s->txn->flags &= ~TX_WAIT_NEXT_RQ;
    stream_int_retnclose(&s->si[0], msg);
    if(!(s->flags & SF_ERR_MASK)) {
        s->flags |= SF_ERR_LOCAL;
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

        list_for_each_entry(rule, &p->nuster.rules, list) {
            struct proxy *pt;

            rule->uuid  = uuid++;
            rule->state = nuster_memory_alloc(p->nuster.mode == NUSTER_MODE_CACHE ?
                    global.nuster.cache.memory : global.nuster.nosql.memory, sizeof(*rule->state));

            if(!rule->state) {
                goto err;
            }
            *rule->state = NUSTER_RULE_ENABLED;
            ttl          = *rule->ttl;
            free(rule->ttl);
            rule->ttl    = nuster_memory_alloc(p->nuster.mode == NUSTER_MODE_CACHE ?
                    global.nuster.cache.memory : global.nuster.nosql.memory, sizeof(*rule->ttl));

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

int nuster_fetch_query_param(char *query_beg, char *query_end,
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


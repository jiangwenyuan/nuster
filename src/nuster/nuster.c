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
        .cache_disk_engine = {
            .obj_type = OBJ_TYPE_APPLET,
            .name     = "<NUSTER.CACHE.ENGINE2>",
        },
    },
};

void nst_debug(const char *fmt, ...) {

    if((global.mode & MODE_DEBUG)) {
        va_list args;
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
    }
}

void nst_debug_key(struct buffer *key) {

    if((global.mode & MODE_DEBUG)) {
        int i;
        for(i = 0; i < key->data; i++) {
            char c = key->area[i];
            if(c != 0) {
                printf("%c", c);
            }
        }
        printf("\n");
    }
}

void nuster_init() {
    int i, uuid;
    struct proxy *p;

    if(!(global.mode & MODE_MWORKER)) {
        ha_alert("[nuster] Not in master-worker mode."
                "Add master-worker to conf file  or run with -W.\n");
        exit(1);
    }

    for(i = 0; i < NST_HTTP_SIZE; i++) {
        nst_http_msg_chunks[i].area = (char *)nst_http_msgs[i];
        nst_http_msg_chunks[i].data = strlen(nst_http_msgs[i]);
    }

    nst_cache_init();
    nst_nosql_init();


    /* init rule */
    i = uuid = 0;
    p = proxies_list;

    while(p) {
        struct nst_rule *rule = NULL;
        uint32_t ttl;
        struct nst_memory *m  = NULL;

        list_for_each_entry(rule, &p->nuster.rules, list) {
            struct proxy *pt;

            if(global.nuster.cache.status == NST_STATUS_ON
                    && p->nuster.mode == NST_MODE_CACHE) {
                m = global.nuster.cache.memory;
            } else if(global.nuster.nosql.status == NST_STATUS_ON
                    && p->nuster.mode == NST_MODE_NOSQL) {
                m = global.nuster.nosql.memory;
            } else {
                continue;
            }

            rule->uuid  = uuid++;
            rule->state = nst_memory_alloc(m, sizeof(*rule->state));

            if(!rule->state) {
                goto err;
            }

            *rule->state = NST_RULE_ENABLED;
            ttl          = *rule->ttl;
            free(rule->ttl);
            rule->ttl    = nst_memory_alloc(m, sizeof(*rule->ttl));

            if(!rule->ttl) {
                goto err;
            }

            *rule->ttl = ttl;

            pt = proxies_list;

            while(pt) {
                struct nst_rule *rt = NULL;
                list_for_each_entry(rt, &pt->nuster.rules, list) {
                    if(rt == rule) goto out;
                    if(!strcmp(rt->name, rule->name)) {
                        ha_alert("nuster rule with same name=[%s] found.\n",
                                rule->name);
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

struct buffer *nst_key_init(struct nst_memory *memory) {
    struct buffer *key  = nst_memory_alloc(memory, sizeof(*key));

    if(!key) {
        return NULL;
    }

    key->area = nst_memory_alloc(memory, NST_CACHE_DEFAULT_KEY_SIZE);

    if(!key->area) {
        nst_memory_free(memory, key);
        return NULL;
    }

    key->size = NST_CACHE_DEFAULT_KEY_SIZE;
    key->data = 0;
    key->head = 0;
    memset(key->area, 0, key->size);

    return key;
}

static int
_nst_key_expand(struct nst_memory *memory, struct buffer *key, int need) {

    if(key->size >= global.tune.bufsize) {
        goto err;
    } else {
        int new_size = key->size;
        char *p;

        for(; new_size <= global.tune.bufsize; new_size *= 2) {
            if(new_size >= need + key->data) {
                break;
            }
        }

        p = nst_memory_alloc(memory, new_size);

        if(!p) {
            goto err;
        }

        memset(p, 0, new_size);
        memcpy(p, key->area, key->size);
        nst_memory_free(memory, key->area);
        key->area = p;
        key->size = new_size;

        return NST_OK;
    }

err:
    nst_memory_free(memory, key->area);
    nst_memory_free(memory, key);

    return NST_ERR;
}

int nst_key_advance(struct nst_memory *memory, struct buffer *key, int step) {

    if(b_room(key) < step) {

        if(_nst_key_expand(memory, key, step) != NST_OK) {
            return NST_ERR;
        }

    }

    key->data += step;

    return NST_OK;
}

int nst_key_append(struct nst_memory *memory, struct buffer *key, char *str,
        int str_len) {

    if(b_room(key) < str_len + 1) {

        if(_nst_key_expand(memory, key, str_len + 1) != NST_OK) {
            return NST_ERR;
        }

    }

    memcpy(key->area + key->data, str, str_len);
    key->data += str_len + 1;

    return NST_OK;
}

int nst_ci_send(struct channel *chn, int len) {
    if(unlikely(channel_input_closed(chn))) {
        return -2;
    }

    b_add(&chn->buf, len);
    channel_add_input(chn, len);
    return len;
}

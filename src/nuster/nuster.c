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
#include <nuster/shctx.h>

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
    .proxy = NULL,
};

void nuster_init() {
    int i, uuid, proxy_cnt;
    struct proxy *p;
    struct nst_memory *memory;

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

    i = uuid = proxy_cnt = 0;
    p = proxies_list;

    while(p) {
        proxy_cnt++;

        p = p->next;
    }

    nuster.proxy = nst_memory_alloc(memory, proxy_cnt * sizeof(struct nst_proxy *));

    if(!nuster.proxy) {
        goto err;
    }

    memset(nuster.proxy, 0, proxy_cnt * sizeof(struct nst_proxy *));

    p = proxies_list;

    while(p) {
        if(p->nuster.mode == NST_MODE_CACHE || p->nuster.mode == NST_MODE_NOSQL) {
            struct nst_rule *rule = NULL;
            struct nst_rule2 *rule2 = NULL;
            struct nst_rule2 *rule2_tail = NULL;

            nuster.proxy[p->uuid] = nst_memory_alloc(memory, sizeof(struct nst_proxy));

            if(!nuster.proxy[p->uuid]) {
                goto err;
            }

            memset(nuster.proxy[p->uuid], 0, sizeof(struct nst_proxy));

            list_for_each_entry(rule, &p->nuster.rules, list) {
                struct nst_key2 *key = NULL;

                rule2 = nst_memory_alloc(memory, sizeof(struct nst_rule2));

                if(!rule2) {
                    goto err;
                }

                rule2->uuid  = uuid++;
                rule2->idx   = nuster.proxy[p->uuid]->rule_cnt++;
                rule2->id    = rule->id;
                rule2->state = NST_RULE_ENABLED;
                rule2->name  = rule->name;

                key = nuster.proxy[p->uuid]->key;

                while(key) {
                    if(strcmp(key->name, rule->raw_key) == 0) {
                        break;
                    }

                    key = key->next;
                }

                if(key) {
                    rule2->key = key;
                } else {
                    key = nst_memory_alloc(memory, sizeof(struct nst_key2));

                    if(!key) {
                        goto err;
                    }

                    key->name = rule->raw_key;
                    key->data = rule->key;
                    key->idx  = nuster.proxy[p->uuid]->key_cnt++;
                    key->next = NULL;

                    if(nuster.proxy[p->uuid]->key) {
                        key->next = nuster.proxy[p->uuid]->key;
                    }

                    nuster.proxy[p->uuid]->key = key;
                }

                rule2->key = key;

                rule2->code = rule->code;
                rule2->ttl  = *rule->ttl;
                rule2->disk = rule->disk;
                rule2->etag = rule->etag;

                rule2->last_modified = rule->last_modified;

                rule2->extend[0] = rule->extend[0];
                rule2->extend[1] = rule->extend[1];
                rule2->extend[2] = rule->extend[2];
                rule2->extend[3] = rule->extend[3];

                rule2->cond = rule->cond;

                rule2->next = NULL;

                if(nuster.proxy[p->uuid]->rule) {
                    rule2_tail->next = rule2;
                } else {
                    nuster.proxy[p->uuid]->rule = rule2;
                }

                rule2_tail = rule2;
            }
        }

        p = p->next;
    }

    return;

err:
    ha_alert("Out of memory when initializing rules.\n");
    exit(1);
}

int nst_test_rule2(struct nst_rule2 *rule, struct stream *s, int res) {
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

void nst_debug_key(struct buffer *key) {

    if((global.mode & MODE_DEBUG)) {
        int i;

        for(i = 0; i < key->data; i++) {
            char c = key->area[i];

            if(c != 0) {
                fprintf(stderr, "%c", c);
            }
        }

        fprintf(stderr, "\n");
    }
}

void nst_debug_key2(struct nst_key *key) {

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


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

void nuster_proxy_init() {
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
    int i;

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

    nuster_proxy_init();

    return;

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


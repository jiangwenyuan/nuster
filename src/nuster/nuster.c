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

#include <haproxy/global.h>
#include <haproxy/proxy.h>
#include <haproxy/errors.h>

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
    hpx_proxy_t  *px1;
    nst_shmem_t  *shmem;
    int           uuid, proxy_cnt;

    /* new rule init */
    global.nuster.shmem = nst_shmem_create("nuster.shm", NST_DEFAULT_SIZE,
            global.tune.bufsize, NST_DEFAULT_CHUNK_SIZE);

    if(!global.nuster.shmem) {
        goto err;
    }

    if(nst_shctx_init(global.nuster.shmem) != NST_OK) {
        goto err;
    }

    shmem = global.nuster.shmem;

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

        proxy_cnt = MAX(proxy_cnt, px1->uuid + 1);
        px1 = px1->next;
    }

    nuster.proxy = nst_shmem_alloc(shmem, proxy_cnt * sizeof(nst_proxy_t *));

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

            nuster.proxy[px1->uuid] = nst_shmem_alloc(shmem, sizeof(nst_proxy_t));

            px = nuster.proxy[px1->uuid];

            if(!px) {
                goto err;
            }

            memset(px, 0, sizeof(nst_proxy_t));

            list_for_each_entry(rc, &px1->nuster.rules, list) {
                nst_rule_key_t  *key = NULL;

                rule = nst_shmem_alloc(shmem, sizeof(nst_rule_t));

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
                    key = nst_shmem_alloc(shmem, sizeof(nst_rule_key_t));

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
                rule->prop.stale         = rc->stale;
                rule->prop.inactive      = rc->inactive;

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

void
nuster_handle_chroot() {
    hpx_ist_t     root;
    nst_shmem_t  *shmem;
    nst_disk_t   *disk;
    int           clean_temp;

    root       = global.nuster.cache.root;
    clean_temp = global.nuster.cache.clean_temp;
    shmem      = global.nuster.cache.shmem;
    disk       = &nuster.cache->store.disk;

    if(nst_disk_init(disk, root, shmem, clean_temp, nuster.cache) != NST_OK) {
        goto err;
    }

    root       = global.nuster.nosql.root;
    clean_temp = global.nuster.nosql.clean_temp;
    shmem      = global.nuster.nosql.shmem;
    disk       = &nuster.nosql->store.disk;

    if(nst_disk_init(disk, root, shmem, clean_temp, nuster.nosql) != NST_OK) {
        goto err;
    }

    return;

err:
    ha_alert("[nuster] Failed init disk.\n");

    exit(1);
}


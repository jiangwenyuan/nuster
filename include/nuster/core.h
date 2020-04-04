/*
 * include/nuster/core.h
 * This file defines everything related to nuster core.
 *
 * Copyright (C) Jiang Wenyuan, < koubunen AT gmail DOT com >
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef _NUSTER_CORE_H
#define _NUSTER_CORE_H

#include <nuster/common.h>
#include <nuster/store.h>
#include <nuster/http.h>
#include <nuster/key.h>
#include <nuster/dict.h>


enum {
    NST_CTX_STATE_INIT = 0,          /* init */
    NST_CTX_STATE_BYPASS,            /* do not cache */
    NST_CTX_STATE_WAIT,              /* caching, wait */
    NST_CTX_STATE_HIT_MEMORY,        /* hit, use memory */
    NST_CTX_STATE_HIT_DISK,          /* hit, use disk */
    NST_CTX_STATE_PASS,              /* rule pass */
    NST_CTX_STATE_FULL,              /* full */
    NST_CTX_STATE_CREATE,            /* to cache */
    NST_CTX_STATE_DELETE,            /* to delete */
    NST_CTX_STATE_DONE,              /* cache done */
    NST_CTX_STATE_INVALID,           /* invalid */
    NST_CTX_STATE_CHECK_PERSIST,     /* check persistence */
};

typedef struct nst_proxy {
    nst_rule_t                  *rule;
    nst_rule_key_t              *key;

    int                         rule_cnt;
    int                         key_cnt;
} nst_proxy_t;

typedef struct nst_ctx {
    int                         state;

    nst_dict_entry_t           *entry;

    nst_http_txn_t              txn;

    int                         pid;              /* proxy uuid */

    struct {
        struct {
            nst_ring_data_t    *data;
            nst_ring_item_t    *item;
        } ring;
        nst_disk_data_t         disk;
    } store;


    int                         rule_cnt;
    int                         key_cnt;
    hpx_buffer_t               *key;
    nst_rule_t                 *rule;
    nst_key_t                   keys[0];
} nst_ctx_t;

typedef struct nst_core {
    nst_memory_t               *memory;
    hpx_ist_t                   root;

    nst_dict_t                  dict;
    nst_store_t                 store;
} nst_core_t;

int nst_test_rule(hpx_stream_t *s, nst_rule_t *rule, int res);

#endif /* _NUSTER_CORE_H */

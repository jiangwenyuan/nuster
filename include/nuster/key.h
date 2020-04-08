/*
 * include/nuster/key.h
 * This file defines everything related to nuster key.
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

#ifndef _NUSTER_KEY_H
#define _NUSTER_KEY_H

#include <import/xxhash.h>

#include <nuster/common.h>

typedef struct nst_key {
    uint32_t            size;
    char               *data;
    uint64_t            hash;
    unsigned char       uuid[20];
} nst_key_t;

static inline hpx_buffer_t *
nst_key_init() {
    hpx_buffer_t  *key = get_trash_chunk();

    memset(key->area, 0, key->size);

    return key;
}

static inline int
nst_key_cat(hpx_buffer_t *key, const char *ptr, int len) {
    if(key->data + len > key->size) {
        return NST_ERR;
    }

    memcpy(key->area + key->data, ptr, len);
    key->data += len;

    return NST_OK;
}

static inline int
nst_key_catist(hpx_buffer_t *key, hpx_ist_t v) {
    /* additional one NULL delimiter */
    if(key->data + v.len + 1 > key->size) {
        return NST_ERR;
    }

    memcpy(key->area + key->data, v.ptr, v.len);
    key->data += v.len + 1;

    return NST_OK;
}

static inline int
nst_key_catdel(hpx_buffer_t *key) {
    if(key->data + 1 > key->size) {
        return NST_ERR;
    }

    key->data += 1;

    return NST_OK;
}

/*
 * It's the caller's reponsibility to allocate str and zero termination
 */
static inline void
nst_key_uuid_stringify(nst_key_t *key, char *str){
    int  i;

    for(i = 0; i < 20; i++) {
        sprintf((char*)&(str[i*2]), "%02x", key->uuid[i]);
    }
}

void nst_key_hash(nst_key_t *key);

void nst_key_debug(nst_key_t *key);

int nst_key_build(hpx_stream_t *s, hpx_http_msg_t *msg, nst_rule_t *rule, nst_http_txn_t *txn,
        nst_key_t *key, enum http_meth_t method);

#endif /* _NUSTER_KEY_H */

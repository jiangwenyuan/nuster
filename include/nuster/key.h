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

#include <stdlib.h>
#include <stdio.h>

#include <import/xxhash.h>

#include <nuster/http.h>

struct nst_key {
    uint32_t    size;
    char       *data;
    uint64_t    hash;
};

static inline struct buffer *nst_key_init() {
    struct buffer *key = get_trash_chunk();

    memset(key->area, 0, key->size);

    return key;
}

static inline int nst_key_cat(struct buffer *key, const char *ptr, int len) {
    if(key->data + len > key->size) {
        return NST_ERR;
    }

    memcpy(key->area + key->data, ptr, len);
    key->data += len;

    return NST_OK;
}

static inline int nst_key_catist(struct buffer *key, struct ist v) {
    /* additional one NULL delimiter */
    if(key->data + v.len + 1 > key->size) {
        return NST_ERR;
    }

    memcpy(key->area + key->data, v.ptr, v.len);
    key->data += v.len + 1;

    return NST_OK;
}

static inline int nst_key_catdel(struct buffer *key) {
    if(key->data + 1 > key->size) {
        return NST_ERR;
    }

    key->data += 1;

    return NST_OK;
}

static inline void nst_key_hash(struct nst_key *key) {
    key->hash = XXH64(key->data, key->size, 0);
}

void nst_key_debug(struct nst_key *key);

int nst_key_build(struct stream *s, struct http_msg *msg, struct nst_rule *rule,
        struct nst_http_txn *txn, struct nst_key *key, enum http_meth_t method);

#endif /* _NUSTER_KEY_H */

/*
 * include/nuster/dict.h
 * This file defines everything related to nuster dict.
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

#ifndef _NUSTER_DICT_H
#define _NUSTER_DICT_H

#include <nuster/common.h>
#include <nuster/http.h>
#include <nuster/key.h>

/*
 * A nst_dict_entry is an entry in nst_dict hash table
 */
enum {
    NST_DICT_ENTRY_STATE_INIT      = 0,
    NST_DICT_ENTRY_STATE_VALID,
    NST_DICT_ENTRY_STATE_INVALID,
    NST_DICT_ENTRY_STATE_EXPIRED,
};

typedef struct nst_dict_entry {
    struct nst_dict_entry      *next;

    int                         state;

    nst_key_t                   key;
    nst_rule_t                 *rule;           /* rule */

    hpx_buffer_t                buf;

    hpx_ist_t                   host;
    hpx_ist_t                   path;
    hpx_ist_t                   etag;
    hpx_ist_t                   last_modified;

    int                         pid;            /* proxy uuid */
    int                         header_len;

    uint64_t                    expire;
    uint64_t                    ctime;
    uint64_t                    atime;

    /* For entries loaded from disk */
    uint32_t                    ttl;
    uint8_t                     extend[4];

    /* see rule.extend */
    uint64_t                    access[4];

    /* extended count  */
    int                         extended;

    struct {
        struct {
            nst_ring_data_t    *data;
            nst_ring_item_t    *item;
        } ring;
        struct {
            char               *file;
        } disk;
    } store;
} nst_dict_entry_t;

typedef struct nst_dict {
    nst_memory_t               *memory;

    nst_dict_entry_t          **entry;
    uint64_t                    size;           /* number of entries */
    uint64_t                    used;           /* number of used entries */

    uint64_t                    cleanup_idx;

    uint64_t                    async_idx;

#if defined NUSTER_USE_PTHREAD || defined USE_PTHREAD_PSHARED
    pthread_mutex_t             mutex;
#else
    unsigned int                waiters;
#endif
} nst_dict_t;

static inline int
nst_dict_entry_expired(nst_dict_entry_t *entry) {

    if(entry->expire == 0) {
        return 0;
    } else {
        return entry->expire <= get_current_timestamp() / 1000;
    }

}

static inline int
nst_dict_entry_invalid(nst_dict_entry_t *entry) {

    /* check state */
    if(entry->state == NST_DICT_ENTRY_STATE_INVALID) {
        return 1;
    } else if(entry->state == NST_DICT_ENTRY_STATE_EXPIRED) {
        return 1;
    }

    /* check expire */
    return nst_dict_entry_expired(entry);
}

int nst_dict_init(nst_dict_t *dict, nst_memory_t *memory, uint64_t dict_size);

nst_dict_entry_t *nst_dict_get(nst_dict_t *dict, nst_key_t *key);
nst_dict_entry_t *nst_dict_set(nst_dict_t *dict, nst_key_t *key, nst_http_txn_t *txn,
        nst_rule_t *rule, int pid, int mode);

int nst_dict_set_from_disk(nst_dict_t *dict, hpx_buffer_t *buf, hpx_ist_t host, hpx_ist_t path,
        nst_key_t *key, char *file, char *meta);

nst_dict_entry_t *nst_dict_get2(nst_dict_t *dict, nst_key_t *key);
nst_dict_entry_t *nst_dict_set2(nst_dict_t *dict, nst_key_t *key, nst_http_txn_t *txn,
        nst_rule_t *rule, int pid);

int nst_dict_set_from_disk2(nst_dict_t *dict, hpx_buffer_t *buf, hpx_ist_t host, hpx_ist_t path,
        nst_key_t *key, char *file, char *meta);

void nst_dict_cleanup(nst_dict_t *dict);

#endif /* _NUSTER_DICT_H */

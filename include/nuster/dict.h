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
#include <nuster/persist.h>
#include <nuster/http.h>

/*
 * A nst_dict_entry is an entry in nst_dict hash table
 */
enum {
    NST_DICT_ENTRY_STATE_CREATING = 0,
    NST_DICT_ENTRY_STATE_VALID,
    NST_DICT_ENTRY_STATE_INVALID,
    NST_DICT_ENTRY_STATE_EXPIRED,
};

struct nst_dict_entry {
    int                     state;

    struct nst_key          key;
    struct nst_rule        *rule;        /* rule */
    struct nst_data        *data;

    struct buffer           buf;

    struct ist              host;
    struct ist              path;
    struct ist              etag;
    struct ist              last_modified;

    int                     pid;         /* proxy uuid */
    char                   *file;
    int                     header_len;

    uint64_t                expire;
    uint64_t                ctime;
    uint64_t                atime;

    /* For entries loaded from disk */
    uint32_t                ttl;
    uint8_t                 extend[4];

    /* see rule.extend */
    uint64_t                access[4];

    /* extended count  */
    int                     extended;

    struct nst_dict_entry  *next;
};

struct nst_dict {
    struct nst_dict_entry **entry;
    uint64_t                 size;      /* number of entries */
    uint64_t                 used;      /* number of used entries */
#if defined NUSTER_USE_PTHREAD || defined USE_PTHREAD_PSHARED
    pthread_mutex_t          mutex;
#else
    unsigned int             waiters;
#endif
};

static inline int nst_dict_entry_expired(struct nst_dict_entry *entry) {

    if(entry->expire == 0) {
        return 0;
    } else {
        return entry->expire <= get_current_timestamp() / 1000;
    }

}

static inline int nst_dict_entry_invalid(struct nst_dict_entry *entry) {

    /* check state */
    if(entry->state == NST_DICT_ENTRY_STATE_INVALID) {
        return 1;
    } else if(entry->state == NST_DICT_ENTRY_STATE_EXPIRED) {
        return 1;
    }

    /* check expire */
    return nst_dict_entry_expired(entry);
}

#endif /* _NUSTER_DICT_H */

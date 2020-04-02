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
#include <nuster/dict.h>

struct nst_proxy {
    struct nst_rule     *rule;
    struct nst_rule_key *key;

    int                  rule_cnt;
    int                  key_cnt;
};

struct nst_data_element {
    struct nst_data_element   *next;

    int                        info;
    char                       data[0];
};

/*
 * A nst_data contains a complete http response data,
 * and is pointed by nst_entry->data.
 * All nst_data are stored in a circular singly linked list
 */
struct nst_data {
    int                       clients;
    int                       invalid;
    struct nst_data_element  *element;

    struct nst_data          *next;
};

struct nst_ctx {
    int                       state;

    struct nst_dict_entry   *entry;
    struct nst_data          *data;
    struct nst_data_element  *element;

    struct nst_http_txn       txn;

    int                       pid;              /* proxy uuid */

    struct persist            disk;

    int                       rule_cnt;
    int                       key_cnt;
    struct buffer            *key;
    struct nst_rule          *rule;
    struct nst_key            keys[0];
};

struct nst_core {
    struct nst_dict        dict;

    /*
     * point to the circular linked list, tail->next ===  head,
     * and will be moved together constantly to check invalid data
     */
    struct nst_data       *data_head;
    struct nst_data       *data_tail;

#if defined NUSTER_USE_PTHREAD || defined USE_PTHREAD_PSHARED
    pthread_mutex_t        mutex;
#else
    unsigned int           waiters;
#endif

    /* >=0: rehashing, index, -1: not rehashing */
    int                    rehash_idx;

    /* cache dict cleanup index */
    int                    cleanup_idx;

    /* persist async index */
    int                    persist_idx;

    /* for disk_loader and disk_cleaner */
    struct {
        int                loaded;
        int                idx;
        DIR               *dir;
        struct dirent     *de;
        char              *file;
    } disk;
};

static inline int nst_data_invalid(struct nst_data *data) {

    if(data->invalid) {

        if(!data->clients) {
            return 1;
        }
    }

    return 0;
}

int nst_test_rule(struct stream *s, struct nst_rule *rule, int res);

#endif /* _NUSTER_CORE_H */

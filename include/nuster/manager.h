/*
 * include/nuster/manager.h
 * This file defines everything related to nuster manager.
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

#ifndef _NUSTER_MANAGER_H
#define _NUSTER_MANAGER_H

#include <types/stream.h>
#include <types/http_ana.h>
#include <types/channel.h>
#include <types/stream_interface.h>
#include <types/proxy.h>
#include <types/filters.h>

#include <common/memory.h>

#include <nuster/common.h>
#include <nuster/persist.h>

#define NST_MANAGER_DEFAULT_PURGE_METHOD "PURGE"
#define NST_MANAGER_DEFAULT_URI          "/nuster"

struct nst_stats {
    struct {
        uint64_t    total;
        uint64_t    fetch;
        uint64_t    hit;
        uint64_t    abort;
    } cache;

#if defined NUSTER_USE_PTHREAD || defined USE_PTHREAD_PSHARED
    pthread_mutex_t mutex;
#else
    unsigned int    waiters;
#endif
};

enum {
    NST_MANAGER_NAME_ALL = 0,
    NST_MANAGER_NAME_PROXY,
    NST_MANAGER_NAME_RULE,
    NST_MANAGER_PATH,
    NST_MANAGER_REGEX,
    NST_MANAGER_HOST,
    NST_MANAGER_PATH_HOST,
    NST_MANAGER_REGEX_HOST,
};

enum {
    NST_STATS_HEADER,
    NST_STATS_PAYLOAD,
    NST_STATS_PROXY,
    NST_STATS_DONE,
};


/* manager */
int nst_manager(struct stream *s, struct channel *req, struct proxy *px);
void nst_manager_init();

/* stats */
int nst_stats_init();
int nst_stats_applet(struct stream *s, struct channel *req, struct proxy *px);
void nst_stats_update_cache(int state);

/* purger */
void nst_purger_init();
int nst_purger_check(struct nst_cache_entry *entry, struct appctx *appctx);
int nst_purger_basic(struct stream *s, struct channel *req, struct proxy *px);
int nst_purger_advanced(struct stream *s, struct channel *req, struct proxy *px);

#endif /* _NUSTER_MANAGER_H */

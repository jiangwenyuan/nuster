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

#include <nuster/common.h>


#define NST_MANAGER_DEFAULT_PURGE_METHOD        "PURGE"
#define NST_MANAGER_DEFAULT_URI                 "/nuster"

enum {
    NST_MANAGER_ALL           = 0,
    NST_MANAGER_PROXY,
    NST_MANAGER_RULE,
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

typedef struct nst_stats {
    struct {
        uint64_t                total;
        uint64_t                fetch;
        uint64_t                hit;
        uint64_t                abort;
        uint64_t                bypass;
        uint64_t                bytes;
    } cache;

    struct {
        uint64_t                total;
        uint64_t                get;
        uint64_t                post;
        uint64_t                delete;
        uint64_t                abort;
    } nosql;

#if defined NUSTER_USE_PTHREAD || defined USE_PTHREAD_PSHARED
    pthread_mutex_t             mutex;
#else
    unsigned int                waiters;
#endif
} nst_stats_t;


/* manager */
int nst_manager(hpx_stream_t *s, hpx_channel_t *req, hpx_proxy_t *px);
void nst_manager_init();

/* stats */
int nst_stats_init();
int nst_stats_applet(hpx_stream_t *s, hpx_channel_t *req, hpx_proxy_t *px);
void nst_stats_update_cache(int state, uint64_t bytes);
void nst_stats_update_nosql(hpx_http_meth_t meth);

/* purger */
void nst_purger_init();
int nst_purger_check(hpx_appctx_t *appctx, nst_dict_entry_t *entry);
int nst_purger_basic(hpx_stream_t *s, hpx_channel_t *req, hpx_proxy_t *px);
int nst_purger_advanced(hpx_stream_t *s, hpx_channel_t *req, hpx_proxy_t *px);

#endif /* _NUSTER_MANAGER_H */

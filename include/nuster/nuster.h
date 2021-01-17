/*
 * include/nuster/nuster.h
 * This file defines everything related to nuster.
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

#ifndef _NUSTER_H
#define _NUSTER_H

#define NUSTER_VERSION    "5.4.0.24-dev"
#define NUSTER_COPYRIGHT  "2017-present, Jiang Wenyuan, <koubunen AT gmail DOT com >"

#include <haproxy/applet-t.h>

#include <nuster/common.h>
#include <nuster/shctx.h>
#include <nuster/shmem.h>
#include <nuster/http.h>
#include <nuster/key.h>
#include <nuster/store.h>
#include <nuster/core.h>
#include <nuster/cache.h>
#include <nuster/nosql.h>
#include <nuster/manager.h>


typedef struct nuster {
    nst_core_t                 *cache;
    nst_core_t                 *nosql;

    struct {
        hpx_applet_t            cache;
        hpx_applet_t            nosql;
        hpx_applet_t            purger;
        hpx_applet_t            stats;
    } applet;

    nst_proxy_t               **proxy;
} nuster_t;

extern nuster_t nuster;


void nuster_init();

/* parser */
int nuster_parse_global_cache(const char *file, int linenum, char **args);
int nuster_parse_global_nosql(const char *file, int linenum, char **args);
int nuster_parse_global_manager(const char *file, int linenum, char **args);

static inline void
nuster_housekeeping() {
    nst_cache_housekeeping();
    nst_nosql_housekeeping();
}

static inline int
nuster_check_applet(hpx_stream_t *s, hpx_channel_t *req, hpx_proxy_t *px) {
    return nst_manager(s, req, px) || nst_nosql_check_applet(s, req, px);
}

void nuster_handle_chroot();

#endif /* _NUSTER_H */

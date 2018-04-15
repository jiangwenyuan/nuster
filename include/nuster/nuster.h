/*
 * include/nuster/nuster.h
 * This file defines everything related to nuster.
 *
 * Copyright (C) [Jiang Wenyuan](https://github.com/jiangwenyuan), < koubunen AT gmail DOT com >
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _NUSTER_H
#define _NUSTER_H

#define NUSTER_VERSION     HAPROXY_VERSION".9"
#define NUSTER_COPYRIGHT  "2017-2018, Jiang Wenyuan, <koubunen AT gmail DOT com >"

#include <nuster/cache.h>

#include <common/chunk.h>
#include <types/stream.h>
#include <types/applet.h>

enum {
    NUSTER_HTTP_200 = 0,
    NUSTER_HTTP_400,
    NUSTER_HTTP_404,
    NUSTER_HTTP_500,
    NUSTER_HTTP_SIZE
};

struct nuster {
    struct nst_cache *cache;
    struct {
        struct {
            struct applet engine;
            struct applet manager;
            struct applet stats;
        } cache;
    } applet;
};

extern struct nuster nuster;

extern const char *nuster_http_msgs[NUSTER_HTTP_SIZE];
extern struct chunk nuster_http_msg_chunks[NUSTER_HTTP_SIZE];

void nuster_init();
void nuster_response(struct stream *s, struct chunk *msg);

#endif /* _NUSTER_H */

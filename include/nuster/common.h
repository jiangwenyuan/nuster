/*
 * include/nuster/common.h
 * This file defines everything related to nuster common.
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

#ifndef _NUSTER_COMMON_H
#define _NUSTER_COMMON_H


#define NUSTER_VERSION                    HAPROXY_VERSION".9"
#define NUSTER_COPYRIGHT                 "2017-2018, Jiang Wenyuan, <koubunen AT gmail DOT com >"

struct nst_string {
    char *data;
    int   len;
};


/* get current timestamp in milliseconds */
static inline uint64_t get_current_timestamp() {
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* get current timestamp in seconds */
static inline uint64_t get_current_timestamp_s() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec;
}

#endif /* _NUSTER_COMMON_H */

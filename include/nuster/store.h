/*
 * include/nuster/store.h
 * This file defines everything related to nuster store.
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

#ifndef _NUSTER_STORE_H
#define _NUSTER_STORE_H

#include <nuster/common.h>
#include <nuster/ring.h>
#include <nuster/disk.h>

typedef struct nst_store {
    nst_ring_t              ring;
    nst_disk_t              disk;
} nst_store_t;



static inline int
nst_store_init(hpx_ist_t root, nst_store_t *store, nst_memory_t *memory) {

    if(nst_ring_init(&store->ring, memory) != NST_OK) {
        return NST_ERR;
    }

    if(nst_disk_init(root, &store->disk, memory) != NST_OK) {
        return NST_ERR;
    }

    return NST_OK;
}

static inline int
nst_store_memory_on(uint8_t t) {
    return t & NST_STORE_MEMORY_ON;
}

static inline int
nst_store_memory_off(uint8_t t) {
    return t & NST_STORE_MEMORY_OFF;
}

static inline int
nst_store_disk_on(uint8_t t) {
    return t & NST_STORE_DISK_ON;
}

static inline int
nst_store_disk_off(uint8_t t) {
    return t & NST_STORE_DISK_OFF;
}

static inline int
nst_store_disk_async(uint8_t t) {
    return t & NST_STORE_DISK_ASYNC;
}

#endif /* _NUSTER_STORE_H */

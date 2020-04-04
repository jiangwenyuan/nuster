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

typedef struct nst_store {
    nst_ring_t              ring;
} nst_store_t;



static inline int
nst_store_init(nst_store_t *store, nst_memory_t *memory) {
    return nst_ring_init(&store->ring, memory);
}

#endif /* _NUSTER_STORE_H */

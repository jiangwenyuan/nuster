/*
 * include/nuster/persist.h
 * nuster persist related functions.
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

#ifndef _NUSTER_PERSIST_H
#define _NUSTER_PERSIST_H

#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

/*
   Offset       Length(bytes)   Content
   0            6               NUSTER
   6            1               Mode: NUSTER_DISK_*, 1, 2, 3
   7            1               Version: 1
   24           8               hash
   8            8               expire time
   16           8               cache length
   16           8               header length
   32           8               key length
   36           A               key
   36+A         B               cache
 */

#define NUSTER_PERSIST_META_VERSION             1
#define NUSTER_PERSIST_META_INDEX_HASH          8
#define NUSTER_PERSIST_META_INDEX_EXPIRE        16
#define NUSTER_PERSIST_META_INDEX_CACHE_LENGTH  24
#define NUSTER_PERSIST_META_INDEX_HEADER_LENGTH 32
#define NUSTER_PERSIST_META_INDEX_KEY_LENGTH    40
#define NUSTER_PERSIST_META_INDEX_KEY           48

int nuster_persist_create(char*);

#endif /* _NUSTER_PERSIST_H */

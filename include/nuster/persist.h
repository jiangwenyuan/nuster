/*
 * nuster persist related functions.
 *
 * Copyright (C) [Jiang Wenyuan](https://github.com/jiangwenyuan), < koubunen AT gmail DOT com >
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
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
   8            8               expire time
   16           8               cache length
   16           8               header length
   32           8               key length
   24           8               key hash
   36           A               key
   36+A         B               cache
 */

#define NUSTER_PERSIST_META_VERSION   1
#define NUSTER_PERSIST_META_INDEX_KEY 48

int nuster_persist_create(char*);

#endif /* _NUSTER_PERSIST_H */

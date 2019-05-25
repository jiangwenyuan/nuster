/*
 * nuster file related functions.
 *
 * Copyright (C) [Jiang Wenyuan](https://github.com/jiangwenyuan), < koubunen AT gmail DOT com >
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#ifndef _NUSTER_FILE_H
#define _NUSTER_FILE_H

#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

/* DIR/a/4a/60322ec3e2428e4a/16ae92496e1-71fabeefebdaaedb */
#define NUSTER_PATH_LENGTH strlen(global.nuster.cache.directory) + 22 /* strlen("/0/00/") + 16, without '\0' */
#define NUSTER_FILE_LENGTH NUSTER_PATH_LENGTH + 29 /* 1 + 11 + 1 + 16, without '\0'  */

int nuster_create_path(char*);

#endif /* _NUSTER_FILE_H */

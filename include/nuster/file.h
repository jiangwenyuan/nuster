/*
 * include/nuster/file.h
 * nuster file related functions.
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

#ifndef _NUSTER_FILE_H
#define _NUSTER_FILE_H

#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

/*
 * DIR/a/4a/60322ec3e2428e4a/16ae92496e1-71fabeefebdaaedb
 */

/* strlen("/0/00/") + 16, without '\0' */
#define NUSTER_PATH_LENGTH strlen(global.nuster.cache.directory) + 22

/* 1 + 11 + 1 + 16, without '\0'  */
#define NUSTER_FILE_LENGTH NUSTER_PATH_LENGTH + 29

int nuster_create_path(char*);

#endif /* _NUSTER_FILE_H */

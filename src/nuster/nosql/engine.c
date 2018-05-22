/*
 * nuster nosql engine functions.
 *
 * Copyright (C) [Jiang Wenyuan](https://github.com/jiangwenyuan), < koubunen AT gmail DOT com >
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <nuster/memory.h>
#include <nuster/shctx.h>
#include <nuster/nuster.h>

#include <types/global.h>
#include <types/stream.h>
#include <types/channel.h>
#include <types/proxy.h>

/*
 * return 1 if the request is done, otherwise 0
 */
int nst_nosql_check_applet(struct stream *s, struct channel *req, struct proxy *px) {
    if(global.nuster.nosql.status == NUSTER_STATUS_ON && px->nuster.mode == NUSTER_MODE_NOSQL) {
        nuster_response(s, &nuster_http_msg_chunks[NUSTER_HTTP_200]);
        return 1;
    }
    return 0;
}

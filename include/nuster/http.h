/*
 * include/nuster/http.h
 * nuster http related functions.
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

#ifndef _NUSTER_HTTP_H
#define _NUSTER_HTTP_H

#include <types/global.h>
#include <inttypes.h>
#include <common/chunk.h>

#include <proto/stream_interface.h>
#include <proto/http_ana.h>

#include <nuster/common.h>
#include <nuster/nuster.h>

/*
static inline void nst_res_header_date(struct buffer *header) {
    const char mon[12][4] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul",
        "Aug", "Sep", "Oct", "Nov", "Dec" };

    const char day[7][4]  = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

    struct tm *tm;
    time_t now;
    time(&now);
    tm = gmtime(&now);
    chunk_appendf(header, "%.*s: %s, %02d %s %04d %02d:%02d:%02d GMT\r\n",
            nst_headers.date.len, nst_headers.date.data, day[tm->tm_wday],
            tm->tm_mday, mon[tm->tm_mon], 1900 + tm->tm_year,
            tm->tm_hour, tm->tm_min, tm->tm_sec);
}
*/

int nst_req_find_param(char *query_beg, char *query_end, char *name, char **value, int *value_len);

void nst_res_simple(struct stream *s, int status);
void nst_res_304(struct stream *s, struct ist last_modified, struct ist etag);
void nst_res_412(struct stream *s);

#endif /* _NUSTER_HTTP_H */

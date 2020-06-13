/*
 * nuster misc functions.
 *
 * Copyright (C) Jiang Wenyuan, < koubunen AT gmail DOT com >
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/global.h>
#include <haproxy/stream.h>
#include <haproxy/acl.h>

#include <nuster/nuster.h>


int
nst_test_rule(hpx_stream_t *s, nst_rule_t *rule, int res) {
    int  ret;

    /* no acl defined */
    if(!rule->cond) {
        return NST_OK;
    }

    if(res) {
        ret = acl_exec_cond(rule->cond, s->be, s->sess, s, SMP_OPT_DIR_RES|SMP_OPT_FINAL);
    } else {
        ret = acl_exec_cond(rule->cond, s->be, s->sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
    }

    ret = acl_pass(ret);

    if(rule->cond->pol == ACL_COND_UNLESS) {
        ret = !ret;
    }

    if(ret) {
        return NST_OK;
    }

    return NST_ERR;
}

void
nst_debug(hpx_stream_t *s, const char *fmt, ...) {

    if((global.mode & MODE_DEBUG)) {
        va_list         args;
        hpx_session_t  *sess = strm_sess(s);

        chunk_printf(&trash, "%08x:%s.nuster[%04x:%04x]: ", s->uniq_id, s->be->id,
                objt_conn(sess->origin) ?
                (unsigned short)objt_conn(sess->origin)->handle.fd : -1,
                objt_cs(s->si[1].end) ?
                (unsigned short)objt_cs(s->si[1].end)->conn->handle.fd : -1);

        va_start(args, fmt);
        trash.data += vsprintf(trash.area + trash.data, fmt, args);
        trash.area[trash.data++] = '\n';
        va_end(args);
        DISGUISE(write(1, trash.area, trash.data));
    }
}

void
nst_debug_beg(hpx_stream_t *s, const char *fmt, ...) {

    if((global.mode & MODE_DEBUG)) {
        va_list         args;
        hpx_session_t  *sess = strm_sess(s);

        chunk_printf(&trash, "%08x:%s.nuster[%04x:%04x]: ", s->uniq_id, s->be->id,
                objt_conn(sess->origin) ?
                (unsigned short)objt_conn(sess->origin)->handle.fd : -1,
                objt_cs(s->si[1].end) ?
                (unsigned short)objt_cs(s->si[1].end)->conn->handle.fd : -1);

        va_start(args, fmt);
        trash.data += vsprintf(trash.area + trash.data, fmt, args);
        va_end(args);
    }
}

void
nst_debug_add(const char *fmt, ...) {

    if((global.mode & MODE_DEBUG)) {
        va_list  args;

        va_start(args, fmt);
        trash.data += vsprintf(trash.area + trash.data, fmt, args);
        va_end(args);
    }
}

void
nst_debug_end(const char *fmt, ...) {

    if((global.mode & MODE_DEBUG)) {
        va_list  args;

        va_start(args, fmt);
        trash.data += vsprintf(trash.area + trash.data, fmt, args);
        va_end(args);
        trash.area[trash.data++] = '\n';
        DISGUISE(write(1, trash.area, trash.data));
    }
}


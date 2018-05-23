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

#include <proto/stream_interface.h>
#include <proto/proto_http.h>

static const char HTTP_100[] =
"HTTP/1.1 100 Continue\r\n\r\n";

static struct chunk http_100_chunk = {
    .str = (char *)&HTTP_100,
    .len = sizeof(HTTP_100)-1
};

static void nst_nosql_engine_handler(struct appctx *appctx) {
    struct stream_interface *si = appctx->owner;
    struct stream *s            = si_strm(si);
    struct channel *res         = si_ic(si);

    if(s->txn->req.msg_state == HTTP_MSG_DATA) {
        co_skip(si_oc(si), si_ob(si)->o);
    }
    if(s->txn->req.msg_state == HTTP_MSG_DONE) {
        ci_putblk(res, nuster_http_msgs[NUSTER_HTTP_200], strlen(nuster_http_msgs[NUSTER_HTTP_200]));
        co_skip(si_oc(si), si_ob(si)->o);
        si_shutr(si);
        res->flags |= CF_READ_NULL;
    }
}

void nst_nosql_init() {
    nuster.applet.nosql_engine.fct = nst_nosql_engine_handler;
}

/*
 * return 1 if the request is done, otherwise 0
 */
int nst_nosql_check_applet(struct stream *s, struct channel *req, struct proxy *px) {
    if(global.nuster.nosql.status == NUSTER_STATUS_ON && px->nuster.mode == NUSTER_MODE_NOSQL) {
        struct stream_interface *si = &s->si[1];
        struct http_txn *txn = s->txn;
        struct http_msg *msg = &txn->req;
        struct appctx *appctx       = NULL;

        s->target = &nuster.applet.nosql_engine.obj_type;
        if(unlikely(!stream_int_register_handler(si, objt_applet(s->target)))) {
            return 1;
        } else {
            appctx      = si_appctx(si);
            appctx->st0 = 0;
            appctx->st1 = 0;
            appctx->st2 = 0;

            if(msg->msg_state < HTTP_MSG_CHUNK_SIZE) {
                if(msg->msg_state < HTTP_MSG_100_SENT) {
                    if(msg->flags & HTTP_MSGF_VER_11) {
                        struct hdr_ctx ctx;
                        ctx.idx = 0;
                        if(http_find_header2("Expect", 6, req->buf->p, &txn->hdr_idx, &ctx) &&
                                unlikely(ctx.vlen == 12 && strncasecmp(ctx.line+ctx.val, "100-continue", 12) == 0)) {
                            co_inject(&s->res, http_100_chunk.str, http_100_chunk.len);
                            http_remove_header2(&txn->req, &txn->hdr_idx, &ctx);
                        }
                    }
                    msg->msg_state = HTTP_MSG_100_SENT;
                }
                msg->next = msg->sov;

                if(msg->flags & HTTP_MSGF_TE_CHNK) {
                    msg->msg_state = HTTP_MSG_CHUNK_SIZE;
                } else {
                    msg->msg_state = HTTP_MSG_DATA;
                }
            }

            req->analysers &= (AN_REQ_HTTP_BODY | AN_REQ_FLT_HTTP_HDRS | AN_REQ_FLT_END);
            req->analysers &= ~AN_REQ_FLT_XFER_DATA;
            req->analysers |= AN_REQ_HTTP_XFER_BODY;

        }
    }
    return 0;
}

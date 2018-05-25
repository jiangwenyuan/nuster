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
#include <proto/log.h>

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

static int _nst_nosql_dict_alloc(uint64_t size) {
    int i, entry_size = sizeof(struct nst_nosql_entry*);

    nuster.nosql->dict[0].size  = size / entry_size;
    nuster.nosql->dict[0].used  = 0;
    nuster.nosql->dict[0].entry = nuster_memory_alloc(global.nuster.nosql.memory, global.nuster.nosql.memory->block_size);
    if(!nuster.nosql->dict[0].entry) return 0;

    for(i = 1; i < size / global.nuster.nosql.memory->block_size; i++) {
        if(!nuster_memory_alloc(global.nuster.nosql.memory, global.nuster.nosql.memory->block_size)) return 0;
    }
    for(i = 0; i < nuster.nosql->dict[0].size; i++) {
        nuster.nosql->dict[0].entry[i] = NULL;
    }
    return nuster_shctx_init((&nuster.nosql->dict[0]));
}

struct nst_nosql_data *nst_nosql_data_new() {

    struct nst_nosql_data *data = nuster_memory_alloc(global.nuster.nosql.memory, sizeof(*data));

    nuster_shctx_lock(nuster.nosql);
    if(data) {
        data->clients  = 0;
        data->invalid  = 0;
        data->element  = NULL;

        if(nuster.nosql->data_head == NULL) {
            nuster.nosql->data_head = data;
            nuster.nosql->data_tail = data;
            data->next              = data;
        } else {
            if(nuster.nosql->data_head == nuster.nosql->data_tail) {
                nuster.nosql->data_head->next = data;
                data->next                    = nuster.nosql->data_head;
                nuster.nosql->data_tail       = data;
            } else {
                data->next                    = nuster.nosql->data_head;
                nuster.nosql->data_tail->next = data;
                nuster.nosql->data_tail       = data;
            }
        }
    }
    nuster_shctx_unlock(nuster.nosql);
    return data;
}

void nst_nosql_init() {
    nuster.applet.nosql_engine.fct = nst_nosql_engine_handler;

    if(global.nuster.nosql.status == NUSTER_STATUS_ON) {
        global.nuster.nosql.memory = nuster_memory_create("nosql.shm", global.nuster.nosql.data_size, global.tune.bufsize, NST_NOSQL_DEFAULT_CHUNK_SIZE);
        if(!global.nuster.nosql.memory) {
            goto shm_err;
        }
        if(!nuster_shctx_init(global.nuster.nosql.memory)) {
            goto shm_err;
        }
        nuster.nosql = nuster_memory_alloc(global.nuster.nosql.memory, sizeof(struct nst_nosql));
        if(!nuster.nosql) {
            goto err;
        }

        nuster.nosql->dict[0].entry = NULL;
        nuster.nosql->dict[0].used  = 0;
        nuster.nosql->dict[1].entry = NULL;
        nuster.nosql->dict[1].used  = 0;
        nuster.nosql->data_head     = NULL;
        nuster.nosql->data_tail     = NULL;
        nuster.nosql->rehash_idx    = -1;
        nuster.nosql->cleanup_idx   = 0;

        if(!nuster_shctx_init(nuster.nosql)) {
            goto shm_err;
        }

        if(!nst_nosql_dict_init()) {
            goto err;
        }
    }
    return;
err:
    ha_alert("Out of memory when initializing nuster nosql.\n");
    exit(1);
shm_err:
    ha_alert("Error when initializing nuster nosql memory.\n");
    exit(1);
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

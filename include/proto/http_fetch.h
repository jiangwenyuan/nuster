/*
<<<<<<< HEAD:include/proto/mux_pt.h
 * include/proto/mux_pt.h
 * This file contains the pass-though mux function prototypes
 *
 * Copyright (C) 2017 Willy Tarreau - w@1wt.eu
=======
 * include/proto/http_fetch.h
 * This file contains the minimally required http sample fetch declarations.
 *
 * Copyright (C) 2000-2018 Willy Tarreau - w@1wt.eu
>>>>>>> v2.1.3:include/proto/http_fetch.h
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

<<<<<<< HEAD:include/proto/mux_pt.h
#ifndef _PROTO_MUX_PT_H
#define _PROTO_MUX_PT_H

#include <common/config.h>
#include <types/connection.h>

extern const struct mux_ops mux_pt_ops;

#endif /* _PROTO_MUX_PT_H */
=======
#ifndef _PROTO_HTTP_FETCH_H
#define _PROTO_HTTP_FETCH_H

#include <common/config.h>
#include <common/htx.h>
#include <types/arg.h>
#include <types/channel.h>
#include <types/sample.h>

struct htx *smp_prefetch_htx(struct sample *smp, struct channel *chn, int vol);
int val_hdr(struct arg *arg, char **err_msg);


#endif /* _PROTO_HTTP_FETCH_H */
>>>>>>> v2.1.3:include/proto/http_fetch.h

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */

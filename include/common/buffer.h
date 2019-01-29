/*
 * include/common/buffer.h
 * Buffer management definitions, macros and inline functions.
 *
 * Copyright (C) 2000-2012 Willy Tarreau - w@1wt.eu
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

#ifndef _COMMON_BUFFER_H
#define _COMMON_BUFFER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common/buf.h>
#include <common/chunk.h>
#include <common/config.h>
#include <common/ist.h>
#include <common/istbuf.h>
#include <common/memory.h>


/* an element of the <buffer_wq> list. It represents an object that need to
 * acquire a buffer to continue its process. */
struct buffer_wait {
	void *target;              /* The waiting object that should be woken up */
	int (*wakeup_cb)(void *);  /* The function used to wake up the <target>, passed as argument */
	struct list list;          /* Next element in the <buffer_wq> list */
};

extern struct pool_head *pool_head_buffer;
extern struct list buffer_wq;
__decl_hathreads(extern HA_SPINLOCK_T buffer_wq_lock);

int init_buffer();
void buffer_dump(FILE *o, struct buffer *b, int from, int to);

/*****************************************************************/
/* These functions are used to compute various buffer area sizes */
/*****************************************************************/

/* Return 1 if the buffer has less than 1/4 of its capacity free, otherwise 0 */
static inline int buffer_almost_full(const struct buffer *buf)
{
	if (b_is_null(buf))
		return 0;

	return b_almost_full(buf);
}

/**************************************************/
/* Functions below are used for buffer allocation */
/**************************************************/

/* Allocates a buffer and assigns it to *buf. If no memory is available,
 * ((char *)1) is assigned instead with a zero size. No control is made to
 * check if *buf already pointed to another buffer. The allocated buffer is
 * returned, or NULL in case no memory is available.
 */
static inline struct buffer *b_alloc(struct buffer *buf)
{
	char *area;

	*buf = BUF_WANTED;
	area = pool_alloc_dirty(pool_head_buffer);
	if (unlikely(!area))
		return NULL;

	buf->area = area;
	buf->size = pool_head_buffer->size;
	return buf;
}

/* Allocates a buffer and assigns it to *buf. If no memory is available,
 * ((char *)1) is assigned instead with a zero size. No control is made to
 * check if *buf already pointed to another buffer. The allocated buffer is
 * returned, or NULL in case no memory is available. The difference with
 * b_alloc() is that this function only picks from the pool and never calls
 * malloc(), so it can fail even if some memory is available.
 */
static inline struct buffer *b_alloc_fast(struct buffer *buf)
{
	char *area;

	*buf = BUF_WANTED;
	area = pool_get_first(pool_head_buffer);
	if (unlikely(!area))
		return NULL;

	buf->area = area;
	buf->size = pool_head_buffer->size;
	return buf;
}

/* Releases buffer <buf> (no check of emptiness) */
static inline void __b_drop(struct buffer *buf)
{
	pool_free(pool_head_buffer, buf->area);
}

/* Releases buffer <buf> if allocated. */
static inline void b_drop(struct buffer *buf)
{
	if (buf->size)
		__b_drop(buf);
}

/* Releases buffer <buf> if allocated, and marks it empty. */
static inline void b_free(struct buffer *buf)
{
	b_drop(buf);
	*buf = BUF_NULL;
}

/* Ensures that <buf> is allocated. If an allocation is needed, it ensures that
 * there are still at least <margin> buffers available in the pool after this
 * allocation so that we don't leave the pool in a condition where a session or
 * a response buffer could not be allocated anymore, resulting in a deadlock.
 * This means that we sometimes need to try to allocate extra entries even if
 * only one buffer is needed.
 *
 * We need to lock the pool here to be sure to have <margin> buffers available
 * after the allocation, regardless how many threads that doing it in the same
 * time. So, we use internal and lockless memory functions (prefixed with '__').
 */
static inline struct buffer *b_alloc_margin(struct buffer *buf, int margin)
{
	char *area;
	ssize_t idx;
	unsigned int cached;

	if (buf->size)
		return buf;

	cached = 0;
	idx = pool_get_index(pool_head_buffer);
	if (idx >= 0)
		cached = pool_cache[tid][idx].count;

	*buf = BUF_WANTED;

#ifndef CONFIG_HAP_LOCKLESS_POOLS
	HA_SPIN_LOCK(POOL_LOCK, &pool_head_buffer->lock);
#endif

	/* fast path */
	if ((pool_head_buffer->allocated - pool_head_buffer->used + cached) > margin) {
		area = __pool_get_first(pool_head_buffer);
		if (likely(area)) {
#ifndef CONFIG_HAP_LOCKLESS_POOLS
			HA_SPIN_UNLOCK(POOL_LOCK, &pool_head_buffer->lock);
#endif
			goto done;
		}
	}

	/* slow path, uses malloc() */
	area = __pool_refill_alloc(pool_head_buffer, margin);

#ifndef CONFIG_HAP_LOCKLESS_POOLS
	HA_SPIN_UNLOCK(POOL_LOCK, &pool_head_buffer->lock);
#endif

	if (unlikely(!area))
		return NULL;

 done:
	buf->area = area;
	buf->size = pool_head_buffer->size;
	return buf;
}


/* Offer a buffer currently belonging to target <from> to whoever needs one.
 * Any pointer is valid for <from>, including NULL. Its purpose is to avoid
 * passing a buffer to oneself in case of failed allocations (e.g. need two
 * buffers, get one, fail, release it and wake up self again). In case of
 * normal buffer release where it is expected that the caller is not waiting
 * for a buffer, NULL is fine.
 */
void __offer_buffer(void *from, unsigned int threshold);

static inline void offer_buffers(void *from, unsigned int threshold)
{
	HA_SPIN_LOCK(BUF_WQ_LOCK, &buffer_wq_lock);
	if (LIST_ISEMPTY(&buffer_wq)) {
		HA_SPIN_UNLOCK(BUF_WQ_LOCK, &buffer_wq_lock);
		return;
	}
	__offer_buffer(from, threshold);
	HA_SPIN_UNLOCK(BUF_WQ_LOCK, &buffer_wq_lock);
}



void __offer_buffer(void *from, unsigned int threshold);

static inline void offer_buffers(void *from, unsigned int threshold)
{
	HA_SPIN_LOCK(BUF_WQ_LOCK, &buffer_wq_lock);
	if (LIST_ISEMPTY(&buffer_wq)) {
		HA_SPIN_UNLOCK(BUF_WQ_LOCK, &buffer_wq_lock);
		return;
	}
	__offer_buffer(from, threshold);
	HA_SPIN_UNLOCK(BUF_WQ_LOCK, &buffer_wq_lock);
}

/*************************************************************************/
/* functions used to manipulate strings and blocks with wrapping buffers */
/*************************************************************************/

/* returns > 0 if the first <n> characters of buffer <b> starting at
 * offset <o> relative to b->p match <ist>. (empty strings do match). It is
 * designed to be use with reasonably small strings (ie matches a single byte
 * per iteration). This function is usable both with input and output data. To
 * be used like this depending on what to match :
 * - input contents  :  b_isteq(b, 0, b->i, ist);
 * - output contents :  b_isteq(b, -b->o, b->o, ist);
 * Return value :
 *   >0 : the number of matching bytes
 *   =0 : not enough bytes (or matching of empty string)
 *   <0 : non-matching byte found
 */
static inline int b_isteq(const struct buffer *b, unsigned int o, size_t n, const struct ist ist)
{
	struct ist r = ist;
	const char *p;
	const char *end = b->data + b->size;

	if (n < r.len)
		return 0;

	p = b_ptr(b, o);
	while (r.len--) {
		if (*p++ != *r.ptr++)
			return -1;
		if (unlikely(p == end))
			p = b->data;
	}
	return ist.len;
}

/* "eats" string <ist> from the input region of buffer <b>. Wrapping data is
 * explicitly supported. It matches a single byte per iteration so strings
 * should remain reasonably small. Returns :
 *   > 0 : number of bytes matched and eaten
 *   = 0 : not enough bytes (or matching an empty string)
 *   < 0 : non-matching byte found
 */
static inline int bi_eat(struct buffer *b, const struct ist ist)
{
	int ret = b_isteq(b, 0, b->i, ist);
	if (ret > 0)
		bi_del(b, ret);
	return ret;
}

/* injects string <ist> into the input region of buffer <b> provided that it
 * fits. Wrapping is supported. It's designed for small strings as it only
 * writes a single byte per iteration. Returns the number of characters copied
 * (ist.len), 0 if it temporarily does not fit or -1 if it will never fit. It
 * will only modify the buffer upon success. In all cases, the contents are
 * copied prior to reporting an error, so that the destination at least
 * contains a valid but truncated string.
 */
static inline int bi_istput(struct buffer *b, const struct ist ist)
{
	const char *end = b->data + b->size;
	struct ist r = ist;
	char *p;

	if (r.len > (size_t)(b->size - b->i - b->o))
		return r.len < b->size ? 0 : -1;

	p = b_ptr(b, b->i);
	b->i += r.len;
	while (r.len--) {
		*p++ = *r.ptr++;
		if (unlikely(p == end))
			p = b->data;
	}
	return ist.len;
}


/* injects string <ist> into the output region of buffer <b> provided that it
 * fits. Input data is assumed not to exist and will silently be overwritten.
 * Wrapping is supported. It's designed for small strings as it only writes a
 * single byte per iteration. Returns the number of characters copied (ist.len),
 * 0 if it temporarily does not fit or -1 if it will never fit. It will only
 * modify the buffer upon success. In all cases, the contents are copied prior
 * to reporting an error, so that the destination at least contains a valid
 * but truncated string.
 */
static inline int bo_istput(struct buffer *b, const struct ist ist)
{
	const char *end = b->data + b->size;
	struct ist r = ist;
	char *p;

	if (r.len > (size_t)(b->size - b->o))
		return r.len < b->size ? 0 : -1;

	p = b->p;
	b->o += r.len;
	b->p = b_ptr(b, r.len);
	while (r.len--) {
		*p++ = *r.ptr++;
		if (unlikely(p == end))
			p = b->data;
	}
	return ist.len;
}


#endif /* _COMMON_BUFFER_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */

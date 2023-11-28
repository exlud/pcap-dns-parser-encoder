/*
 * copied from libnl/include/netlink/list.h under LGPL
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 */

#ifndef DNS_LIST_H
#define DNS_LIST_H

#ifdef __cplusplus
extern "C" {
#endif

struct dlist_head {
  struct dlist_head *	next;
  struct dlist_head *	prev;
};

static inline void INIT_DLIST_HEAD(struct dlist_head * list)
{
  list->next = list;
  list->prev = list;
}

static inline void __dlist_add(struct dlist_head * obj, struct dlist_head * prev, struct dlist_head * next)
{
  prev->next = obj;
  obj->prev = prev;
  next->prev = obj;
  obj->next = next;
}

static inline void dlist_add_tail(struct dlist_head * obj, struct dlist_head * head)
{
  __dlist_add(obj, head->prev, head);
}

static inline void dlist_add_head(struct dlist_head * obj, struct dlist_head * head)
{
  __dlist_add(obj, head, head->next);
}

static inline void dlist_del(struct dlist_head * obj)
{
  obj->next->prev = obj->prev;
  obj->prev->next = obj->next;
}

static inline int dlist_empty(struct dlist_head *head)
{
  return head->next == head;
}

#define dlist_container_of(ptr, type, member) ({			\
        const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
        (type *)( (char *)__mptr - ((size_t) &((type *)0)->member));})

#define dlist_entry(ptr, type, member) \
	dlist_container_of(ptr, type, member)

#define dlist_at_tail(pos, head, member) \
	((pos)->member.next == (head))

#define dlist_at_head(pos, head, member) \
	((pos)->member.prev == (head))

#define DLIST_HEAD(name) \
	struct dlist_head name = { &(name), &(name) }

#define dlist_first_entry(head, type, member)			\
	dlist_entry((head)->next, type, member)

#define dlist_for_each_entry(pos, head, member)				\
	for (pos = dlist_entry((head)->next, typeof(*pos), member);	\
	     &(pos)->member != (head); 	\
	     (pos) = dlist_entry((pos)->member.next, typeof(*(pos)), member))

#define dlist_for_each_entry_safe(pos, n, head, member)			\
	for (pos = dlist_entry((head)->next, typeof(*pos), member),	\
		n = dlist_entry(pos->member.next, typeof(*pos), member);	\
	     &(pos)->member != (head); 					\
	     pos = n, n = dlist_entry(n->member.next, typeof(*n), member))

#define dlist_init_head(head) \
	do { (head)->next = (head); (head)->prev = (head); } while (0)

#ifdef __cplusplus
}
#endif

#endif

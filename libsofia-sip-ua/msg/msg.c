/*
 * This file is part of the Sofia-SIP package
 *
 * Copyright (C) 2005 Nokia Corporation.
 *
 * Contact: Pekka Pessi <pekka.pessi@nokia.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 */

/**@internal @file msg.c Message object implementation.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Thu Jun  8 19:28:55 2000 ppessi
 */

#include "config.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>

#include <assert.h>

#include <sofia-sip/su_alloc.h>		/* XXX */
#include <sofia-sip/su.h>
#include <sofia-sip/su_debug.h>

#include "msg_internal.h"
#include "sofia-sip/msg_parser.h"
#include "sofia-sip/msg_mclass.h"

#ifdef SOFIA_MSG_DEBUG_TRACE

#define CAPACITY 50000 // Size of the Hash Table

typedef struct Ht_item Ht_item;
struct Ht_item {
  void* address;
};

typedef struct LinkedList LinkedList;
 
// Define the Linkedlist here
struct LinkedList {
    Ht_item* item; 
    LinkedList* next;
};
LinkedList* allocate_list () {
    // Allocates memory for a Linkedlist pointer
    LinkedList* list = (LinkedList*) malloc (sizeof(LinkedList));
    list->item = NULL;
    list->next = NULL;
    return list;
}
 
LinkedList* linkedlist_insert(LinkedList* list, Ht_item* item) {
    // Inserts the item onto the Linked List
    if (!list) {
        LinkedList* head = allocate_list();
        head->item = item;
        head->next = NULL;
        list = head;
        return list;
    } 
     
    else if (list->next == NULL) {
        LinkedList* node = allocate_list();
        node->item = item;
        node->next = NULL;
        list->next = node;
        return list;
    }
 
    LinkedList* temp = list;
    while (temp->next->next) {
        temp = temp->next;
    }
     
    LinkedList* node = allocate_list();
    node->item = item;
    node->next = NULL;
    temp->next = node;
     
    return list;
}
Ht_item* linkedlist_remove(LinkedList* list) {
    // Removes the head from the linked list
    // and returns the item of the popped element
    if (!list)
        return NULL;
    if (!list->next)
        return NULL;
    LinkedList* node = list->next;
    LinkedList* temp = list;
    temp->next = NULL;
    list = node;
    Ht_item* it = NULL;
    memcpy(temp->item, it, sizeof(Ht_item));
    free(temp->item);
    free(temp);
    return it;
}
 
void free_linkedlist(LinkedList* list) {
    LinkedList* temp = list;
    while (list) {
        temp = list;
        list = list->next;
        free(temp->item);
        free(temp);
    }
}

typedef struct HashTable HashTable;
struct HashTable {
  Ht_item** items;
  LinkedList** overflow_buckets;
  int size;
  int count;
};

Ht_item* create_item(void* address) {
  Ht_item* item = (Ht_item*) malloc(sizeof(Ht_item));
  item->address = address;
  return item;
}
void free_item(Ht_item* item) {
    free(item);
}
LinkedList** create_overflow_buckets(HashTable* table) {
    // Create the overflow buckets; an array of linkedlists
    LinkedList** buckets = (LinkedList**) calloc (table->size, sizeof(LinkedList*));
    for (int i=0; i<table->size; i++)
                   buckets[i] = NULL;
    return buckets;
}
 
void free_overflow_buckets(HashTable* table) {
    // Free all the overflow bucket lists
    LinkedList** buckets = table->overflow_buckets;
    for (int i=0; i<table->size; i++)
          free_linkedlist(buckets[i]);
    free(buckets);
}
 
HashTable* create_table(int size) {
    // Creates a new HashTable
    HashTable* table = (HashTable*) malloc (sizeof(HashTable));
    table->size = size;
    table->count = 0;
    table->items = (Ht_item**) calloc (table->size, sizeof(Ht_item*));
    for (int i=0; i<table->size; i++)
        table->items[i] = NULL;
    table->overflow_buckets = create_overflow_buckets(table);
    return table;
}
void free_table(HashTable* table) {
    // Frees the table
    for (int i=0; i<table->size; i++) {
        Ht_item* item = table->items[i];
        if (item != NULL)
            free_item(item);
    }
    free_overflow_buckets(table);
    free(table->items);
    free(table);
}

unsigned long hash_function(void* address) {
  return (unsigned long) address % CAPACITY;
}
void handle_collision(HashTable* table, unsigned long index, Ht_item* item) {
    LinkedList* head = table->overflow_buckets[index];
 
    if (head == NULL) {
        // We need to create the list
        head = allocate_list();
        head->item = item;
        table->overflow_buckets[index] = head;
        return;
    }
    else {
        // Insert to the list
        table->overflow_buckets[index] = linkedlist_insert(head, item);
        return;
    }
}
 
void ht_insert(HashTable* table, void* address ) {
    // Create the item
    Ht_item* item = create_item(address);
    unsigned long index = hash_function(address);
    Ht_item* current_item = table->items[index];
     
    if (current_item == NULL) {
      // Key does not exist.
      if (table->count == table->size) {
          // Hash Table Full
          SU_DEBUG_9(("ht_insert - %s\n", "hash table full")) ;
          return;
      }
        
      // Insert directly
      table->items[index] = item; 
      table->count++;
    }
    else {
      // Scenario 2: Collision
      // We will handle case this a bit later
      handle_collision(table, index, item);
      return;
    }
}
int ht_exists(HashTable* table, void* address) {
    int index = hash_function(address);
    Ht_item* item = table->items[index];
    LinkedList* head = table->overflow_buckets[index];
 
    // Ensure that we move to items which are not NULL
    while (item != NULL) {
        if (item->address == address)
            return 1;
        if (head == NULL)
            return 0;
        item = head->item;
        head = head->next;
    }
    return 0;
}
void ht_delete(HashTable* table, void* address) {
    // Deletes an item from the table
    int index = hash_function(address);
    Ht_item* item = table->items[index];
    LinkedList* head = table->overflow_buckets[index];
 
    if (item == NULL) {
        // Does not exist. Return
        return;
    }
    else {
        if (head == NULL && item->address == address) {
            // No collision chain. Remove the item
            // and set table index to NULL
            table->items[index] = NULL;
            free_item(item);
            table->count--;
            return;
        }
        else if (head != NULL) {
            // Collision Chain exists
            if (item->address == address) {
                // Remove this item and set the head of the list
                // as the new item
                 
                free_item(item);
                LinkedList* node = head;
                head = head->next;
                node->next = NULL;
                table->items[index] = create_item(node->item->address);
                free_linkedlist(node);
                table->overflow_buckets[index] = head;
                return;
            }
 
            LinkedList* curr = head;
            LinkedList* prev = NULL;
             
            while (curr) {
                if (curr->item->address == address) {
                    if (prev == NULL) {
                        // First element of the chain. Remove the chain
                        free_linkedlist(head);
                        table->overflow_buckets[index] = NULL;
                        return;
                    }
                    else {
                        // This is somewhere in the chain
                        prev->next = curr->next;
                        curr->next = NULL;
                        free_linkedlist(curr);
                        table->overflow_buckets[index] = head;
                        return;
                    }
                }
                curr = curr->next;
                prev = curr;
            }
 
        }
    }
}

void print_table(HashTable* table) {
  for (int i=0; i < table->size; i++) {
    if (table->items[i]) {
      SU_DEBUG_9(("msg_t* - %p\n", table->items[i]->address)) ;
      if (table->overflow_buckets[i]) {
        printf(" => Overflow Bucket => ");
        LinkedList* head = table->overflow_buckets[i];
        while (head) {
          SU_DEBUG_9(("msg_t* - %p\n",  head->item->address)) ;
          head = head->next;
        }
      }
    }
  }
}
HashTable* dbgTable = NULL;
int debugging_on = 1;

SOFIAPUBFUN usize_t sofia_msg_count() {
  return dbgTable ? dbgTable->count : 0;
}
SOFIAPUBFUN void stop_sofia_msg_counting() {
  if (dbgTable) {
    debugging_on = 0;
    free_table(dbgTable);
    dbgTable = NULL;
  }
}
SOFIAPUBFUN void sofia_dump_msgs() {
  SU_DEBUG_9(("sofia_dump_msgs - %s\n", "starting")) ;
  if (dbgTable) print_table(dbgTable);
  SU_DEBUG_9(("sofia_dump_msgs - %s\n", "completed")) ;
}

#endif
/** Increment the reference count.
 *
 * @relatesalso msg_s
 *
 * Increases the reference count of a message. The message is not freed
 * until all the references have been destroyed.
 *
 * @param msg  message of which a reference is created
 *
 * @return A pointer to a message
 */
msg_t *msg_ref(msg_t *msg)
{
#ifdef SOFIA_MSG_DEBUG_TRACE  
   SU_DEBUG_9(("msg_ref: %p, refcount before is %ld\n", (void*)msg, su_home_refcount(msg->m_home))) ;
#endif
  return (msg_t *)su_home_ref(msg->m_home);
}

/*
static void msg_destructor(void *_msg)
{
  msg_t *msg = _msg;

  if (msg->m_parent)
    su_home_unref(msg->m_parent->m_home);
}
*/

/** Decrease the reference count.
 *
 * @relatesalso msg_s
 *
 * Decreases the reference count of a message. The message is freed
 * if the reference count reaches zero.
 *
 * @param msg message of which a reference is created
 *
 * @return A pointer to a message
 */
void msg_unref(msg_t *msg)
{
#ifdef SOFIA_MSG_DEBUG_TRACE  
  unsigned long count = su_home_refcount(msg->m_home) ; 
#endif

  su_home_unref(msg->m_home);

#ifdef SOFIA_MSG_DEBUG_TRACE  
  SU_DEBUG_9(("msg_unref: %p, refcount is now %ld\n", (void*)msg, count - 1)) ;
#endif
}

/**
 * Create a message.
 *
 * @relatesalso msg_s
 *
 * @param mc    message class
 * @param flags message control flags
 */
msg_t *msg_create(msg_mclass_t const *mc, int flags)
{
  msg_t *msg = su_home_new(sizeof(*msg) + mc->mc_msize);

  if (msg) {
    if ((flags & MSG_FLG_THRDSAFE) &&
	su_home_threadsafe(msg->m_home) < 0) {
      su_home_unref(msg->m_home);
      return NULL;
    }

    msg->m_refs++;
    msg->m_tail = &msg->m_chain;
    msg->m_addrinfo.ai_addrlen = sizeof(msg->m_addr);
    msg->m_addrinfo.ai_addr = &msg->m_addr->su_sa;
    msg->m_maxsize = 0;

    flags &= MSG_FLG_USERMASK;

    msg->m_class = mc;
    msg->m_oflags = flags;
    msg->m_object = (void *)(msg + 1);
    msg->m_object->msg_size = mc->mc_msize;
    msg->m_object->msg_flags = mc->mc_flags | flags;
    msg->m_object->msg_common->h_class = (void *)mc;
  }
#ifdef SOFIA_MSG_DEBUG_TRACE
  if (debugging_on) {
    if (NULL == dbgTable) dbgTable = create_table(CAPACITY);
    ht_insert(dbgTable, (void*) msg);
    SU_DEBUG_9(("msg_create: %p, active msg count now %d\n", (void*)msg, sofia_msg_count())) ;
  }
#endif
  return msg;
}

/**Increment a message reference count.
 *
 * @relatesalso msg_s
 *
 * Creates a reference to a message.  The
 * referenced message is not freed until all the references have been
 * destroyed.
 *
 * @param msg   message of which a reference is created
 *
 * @return
 * A pointer to a message.
 */
msg_t *msg_ref_create(msg_t *msg)
{
  if (msg) {
    su_home_mutex_lock(msg->m_home);
    msg->m_refs++;
    su_home_mutex_unlock(msg->m_home);
  }
#ifdef SOFIA_MSG_DEBUG_TRACE
  SU_DEBUG_9(("msg_ref_create: message %p, refcount now %d\n", (void *) msg, msg->m_refs));
#endif
  return msg;
}

/**Set a message parent.
 *
 * @relatesalso msg_s
 *
 * Set a parent for a message. The parent message is not destroyed until all
 * its kids have been destroyed - each kid keeps a reference to its parent
 * message.
 *
 * @param kid  child message
 * @param dad  parent message
 */
void msg_set_parent(msg_t *kid, msg_t *dad)
{
  if (kid) {
    msg_t *step_dad = kid->m_parent;

    if (dad && step_dad && step_dad != dad)
      msg_ref_destroy(step_dad);

    kid->m_parent = msg_ref_create(dad);
  }
}

/** Destroy a reference to a message.
 *
 * @relatesalso msg_s
 *
 * @param ref pointer to msg object
 *
 * @deprecated Use msg_destroy() instead.
 */
void msg_ref_destroy(msg_t *ref)
{
  msg_destroy(ref);
}

/**Deinitialize and free a message.
 *
 * @relatesalso msg_s
 *
 * @param msg  message to be destroyed
 */
void msg_destroy(msg_t *msg)
{
  msg_t *parent;

  for (; msg; msg = parent) {
    int refs;
    su_home_mutex_lock(msg->m_home);
    parent = msg->m_parent;
    if (msg->m_refs)
      msg->m_refs--;
    refs = msg->m_refs;
    su_home_mutex_unlock(msg->m_home);

#ifdef SOFIA_MSG_DEBUG_TRACE
    SU_DEBUG_9(("msg_destroy: message %p, decremented refcount, refcount now %d\n", 
      (void *) msg, msg->m_refs));
#endif
    if (refs)
      break;
    su_home_zap(msg->m_home);

#ifdef SOFIA_MSG_DEBUG_TRACE
    ht_delete(dbgTable, (void *)msg);
    SU_DEBUG_9(("msg_destroy: actually destroyed message %p, total msgs: %d\n", (void *) msg, sofia_msg_count()));
#endif
  }
}

/* Message object routines */

/**Retrieve public message structure.
 *
 * Get a pointer to the public message structure.
 *
 * @param msg pointer to msg object
 *
 * @returns
 * A pointer to the public message structure, or NULL if none.
 */
msg_pub_t *msg_object(msg_t const *msg)
{
  if (msg)
    return msg->m_object;
  else
    return NULL;
}

/**Retrieve public message structure of given type.
 *
 * @relatesalso msg_s
 *
 * Get a pointer to the public message structure of the
 * given protocol.
 *
 * @param msg pointer to msg object
 * @param tag tag of public message structure
 *
 * @returns
 * A pointer to the public message structure, or NULL if there is none or
 * the message is not for desired protocol.
 */
msg_pub_t *msg_public(msg_t const *msg, void *tag)
{
  if (msg && msg->m_class->mc_tag == tag)
    return msg->m_object;
  else
    return NULL;
}

/**Retrieve message class.
 *
 * @relatesalso msg_s
 *
 * Get a pointer to the message class object
 * (factory object for the message).
 *
 * @param msg pointer to msg object
 *
 * @returns
 * A pointer to the message class, or NULL if none.
 */
msg_mclass_t const *msg_mclass(msg_t const *msg)
{
  if (msg)
    return msg->m_class;
  else
    return NULL;
}

/* Address management */

/** Zero the message address.
 *
 * @relatesalso msg_s
 *
 * Zero the address and addressinfo structures associated with the message.
 *
 * @sa msg_addrinfo(), msg_set_address(), msg_get_address(), msg_addr_copy().
 */
void msg_addr_zero(msg_t *msg)
{
  memset(&msg->m_addr, 0, sizeof(msg->m_addr));
  memset(&msg->m_addrinfo, 0, sizeof(msg->m_addrinfo));

  msg->m_addrinfo.ai_addrlen = sizeof(msg->m_addr);
  msg->m_addrinfo.ai_addr = &msg->m_addr->su_sa;
}

/** Get pointer to socket address structure.
 *
 * @relatesalso msg_s
 *
 * @deprecated Use msg_get_address() or msg_set_address() instead.
 */
su_sockaddr_t *msg_addr(msg_t *msg)
{
  return msg ? msg->m_addr : 0;
}

/** Get message address.
 *
 * @relatesalso msg_s
 *
 * Copy the socket address associated with the message to the supplied
 * socket address struture.
 *
 * @param msg pointer to msg object
 * @param su pointer to socket address structure
 * @param return_len return parameter value for length
 *                    of socket address structure
 *
 * @sa msg_addrinfo(), msg_set_address(), msg_addr_zero(), msg_addr_copy().
 */
int msg_get_address(msg_t *msg, su_sockaddr_t *su, socklen_t *return_len)
{
  if (msg && return_len && *return_len >= msg->m_addrinfo.ai_addrlen) {
    *return_len = (socklen_t)msg->m_addrinfo.ai_addrlen;
    if (su)
      memcpy(su, msg->m_addr, msg->m_addrinfo.ai_addrlen);
    return 0;
  }
  if (msg)
    msg->m_errno = EFAULT;
  return -1;
}

/** Set message address.
 *
 * @relatesalso msg_s
 *
 * Copy the supplied socket address to the socket address structure
 * associated with the message.
 *
 * @param msg pointer to msg object
 * @param su pointer to socket address structure
 * @param sulen length of socket address structure
 *
 * @sa msg_addrinfo(), msg_get_address(), msg_addr_zero(), msg_addr_copy().
 */
int msg_set_address(msg_t *msg, su_sockaddr_t const *su, socklen_t sulen)
{
  if (sulen < (sizeof msg->m_addr) && msg && su) {
    memcpy(msg->m_addr, su, msg->m_addrinfo.ai_addrlen = sulen);
    msg->m_addrinfo.ai_family = su->su_family;
    return 0;
  }
  if (msg)
    msg->m_errno = EFAULT;
  return -1;
}

/** Get addrinfo structure.
 *
 * @relatesalso msg_s
 *
 * Get pointer to the addrinfo structure associated with the message.
 *
 * @param msg pointer to msg object
 *
 * @retval pointer to addrinfo structure
 * @retval NULL if msg is NULL
 *
 * @sa msg_get_address(), msg_set_address(), msg_addr_zero(), msg_addr_copy().
 */
su_addrinfo_t *msg_addrinfo(msg_t *msg)
{
  return msg ? &msg->m_addrinfo : 0;
}

/**Copy message address.
 *
 * @relatesalso msg_s
 *
 * Copy the addrinfo and socket address structures from @a src to the @a dst
 * message object.
 *
 * @param dst pointer to destination message object
 * @param src pointer to source message object
 *
 * @sa msg_addrinfo(), msg_get_address(), msg_set_address(), msg_addr_zero().
 */
void msg_addr_copy(msg_t *dst, msg_t const *src)
{
  dst->m_addrinfo = src->m_addrinfo;
  dst->m_addrinfo.ai_next = NULL;
  dst->m_addrinfo.ai_canonname = NULL;
  memcpy(dst->m_addrinfo.ai_addr = &dst->m_addr->su_sa,
	 src->m_addr, src->m_addrinfo.ai_addrlen);
  if (dst->m_addrinfo.ai_addrlen < sizeof(dst->m_addr))
    memset((char *)dst->m_addr + dst->m_addrinfo.ai_addrlen, 0,
	   sizeof(dst->m_addr) - dst->m_addrinfo.ai_addrlen);
}


/** Get error classification flags.
 *
 * @relatesalso msg_s
 *
 * If the message parser fails to parse certain headers in the message, it
 * sets the corresponding extract error flags. The flags corresponding to
 * each header are stored in the message parser (msg_mclass_t) structure.
 * They are set when the header is added to the parser table.
 *
 * The SIP flags are defined in <sofia-sip/sip_headers.h>. For well-known
 * SIP headers, the flags for each header are listed in a separate text file
 * (sip_bad_mask) read by msg_parser.awk.
 *
 * The flags can be used directly by NTA (the mask triggering 400 response
 * is set with NTATAG_BAD_REQ_MASK(), the mask triggering response messages
 * to be dropped is set with NTATAG_BAD_RESP_MASK()). Alternatively the
 * application can check them based on the method or required SIP features.
 *
 * @sa msg_mclass_insert_with_mask(), NTATAG_BAD_REQ_MASK(),
 * NTATAG_BAD_RESP_MASK().
 */
unsigned msg_extract_errors(msg_t const *msg)
{
  return msg ? msg->m_extract_err : (unsigned)-1;
}


/** Get error number associated with message.
 *
 * @relatesalso msg_s
 *
 * @param msg pointer to msg object
 *
 */
int msg_errno(msg_t const *msg)
{
  return msg ? msg->m_errno : EINVAL;
}

/** Set error number associated with message.
 *
 * @relatesalso msg_s
 *
 * @param msg pointer to msg object
 * @param err error value (as defined in <sofia-sip/su_errno.h>).
 *
 */
void msg_set_errno(msg_t *msg, int err)
{
  if (msg)
    msg->m_errno = err;
}

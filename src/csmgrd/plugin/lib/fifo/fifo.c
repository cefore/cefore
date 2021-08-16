/*
 * Copyright (c) 2016-2021, National Institute of Information and Communications
 * Technology (NICT). All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the NICT nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NICT AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE NICT OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * fifo.c
 */

/*
	fifo.c is a primitive FIFO implementation.
*/

/****************************************************************************************
 Include Files
 ****************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <csmgrd/csmgrd_plugin.h>
#include "cache_replace_lib.h"

/****************************************************************************************
 Macros
 ****************************************************************************************/



/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

/***** structure for listing content entries *****/
typedef struct _FifofT_Entry {
	unsigned char 	*key;					/* key of content entry 					*/

	int 			key_len;				/* length of key 							*/
    int             valid;
    int             next;
    int             prev;
} FifofT_Entry;

/****************************************************************************************
 State Variables
 ****************************************************************************************/

static int cache_cap = 0;					/* Maximum number of entries that can be 	*/
											/* listed (it is the same value as the 		*/
											/* maximum value of the cache table) 		*/

/* pointers of functions which stores and removes the content entry into/from the cache */
/* table (implementation of the functions are in a plugin which uses this library) 		*/
static int (*store_api)(CsmgrdT_Content_Entry*);
static void (*remove_api)(unsigned char*, int);

static int              fifo_head_index, fifo_tail_index;
static int              cache_count;        /* number of cache entries                  */
static FifofT_Entry*     cache_entry_list;   /* list for cache entry                     */
static int*             empty_entry_list;   /* list for empty cache entry               */

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

static void fifo_store_entry (CsmgrdT_Content_Entry* entry, int index);
static void fifo_remove_entry (int index, int is_removed);
static void fifo_set (int new_index);
static void fifo_relink_neighbors_of (int hole_idx);

/****************************************************************************************
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Init API
----------------------------------------------------------------------------------------*/
int 							/* If the error occurs, this value is a negative value	*/
init (
	int capacity, 							/* Maximum number of entries that can be 	*/
											/* listed (it is the same value as the 		*/
											/* maximum value of the cache table) 		*/
	int (*store)(CsmgrdT_Content_Entry*), 	/* store a content entry API 				*/
	void (*remove)(unsigned char*, int)		/* remove a content entry API 				*/
) {
    int i;
    cache_count = 0;
    
	/* Records the capacity of cache		*/
	if (capacity < 1) {
		fprintf (stderr, "[FIFO LIB] Invalid Cacacity\n");
		return (-1);
	}
	cache_cap = capacity;

	/* Records store and remove APIs 		*/
	if ((store == NULL) || (remove == NULL)) {
		fprintf (stderr, "[FIFO LIB] Not specified store or remove API\n");
		return (-1);
	}
	store_api 	= store;
	remove_api 	= remove;
    
	/* Creates the memory pool 				*/
    cache_entry_list = (FifofT_Entry*) calloc (cache_cap, sizeof (FifofT_Entry));
    empty_entry_list = (int*) calloc (cache_cap, sizeof (int));
    memset (cache_entry_list, 0, sizeof (FifofT_Entry) * cache_cap);
    for (i = 0; i < cache_cap; i++) {
        empty_entry_list[i] = i;
        cache_entry_list[i].next = -1;
        cache_entry_list[i].prev = -1;
    }
    fifo_tail_index = -1;
    fifo_head_index = -1;
    
    /* Creates lookup table */
    crlib_lookup_table_init (capacity);
    
	return (0);
}

/*--------------------------------------------------------------------------------------
	Destroy API
----------------------------------------------------------------------------------------*/
void
destroy (
	void
) {
    cache_count = 0;
	cache_cap 		= 0;
	store_api 		= NULL;
	remove_api 		= NULL;

	for (int i=0; i< cache_cap; i++) {
		if (cache_entry_list[i].key != NULL) {
			free (cache_entry_list[i].key);
		}
	}

    free (cache_entry_list);
    free (empty_entry_list);
    fifo_head_index = -1;
    fifo_tail_index = -1;
    crlib_lookup_table_destroy ();
}

/*--------------------------------------------------------------------------------------
	Insert API
----------------------------------------------------------------------------------------*/
void
insert (
	CsmgrdT_Content_Entry* entry			/* content entry 							*/
) {
    if (cache_count >= cache_cap) {
    	fifo_remove_entry (fifo_tail_index, 0);
    }
	fifo_store_entry (entry, empty_entry_list[cache_count]);
}

/*--------------------------------------------------------------------------------------
	Erase API
----------------------------------------------------------------------------------------*/
void
erase (
	unsigned char* key, 					/* key of content entry removed from cache 	*/
											/* table									*/
	int key_len								/* length of the key 						*/
) {
    int index = crlib_lookup_table_search (key, key_len);
    if (index < 0) {
        fprintf (stderr, "[FIFO LIB] failed to erace\n");
        return;
    }
    fifo_remove_entry (index, 1);
}

/*--------------------------------------------------------------------------------------
	Hit API
----------------------------------------------------------------------------------------*/
void
hit (
	unsigned char* key, 					/* key of the content entry hits in the 	*/
											/* cache table 								*/
	int key_len								/* length of the key 						*/
) {
    // NOTHING TO DO
	return;
}

/*--------------------------------------------------------------------------------------
	Miss API
----------------------------------------------------------------------------------------*/
void
miss (
	unsigned char* key, 					/* key of the content entry fails to hit 	*/
											/* in the cache table						*/
	int key_len								/* length of the key 						*/
) {
    // NOTHING TO DO
	return;
}

/*--------------------------------------------------------------------------------------
	Status API
----------------------------------------------------------------------------------------*/
void
status (
	void* arg								/* state information						*/
) {
	// TODO
	return;
}


/*--------------------------------------------------------------------------------------
	Static Functions
----------------------------------------------------------------------------------------*/
static void fifo_store_entry (
	CsmgrdT_Content_Entry* entry,
    int index
) {
    unsigned char 	key[CsmgrdC_Key_Max];
    int 			key_len;
    FifofT_Entry*    rsentry;
	unsigned char* q;
    
    key_len = csmgrd_name_chunknum_concatenate (
                    entry->name, entry->name_len, entry->chnk_num, key);
    rsentry = &cache_entry_list[index];
    rsentry->key_len = key_len;
  	q = calloc (1, key_len);
    memcpy (q, key, key_len);
	rsentry->key = q;
    fifo_set (index);
    crlib_lookup_table_add (rsentry->key, rsentry->key_len, index);
    (*store_api)(entry);
    cache_count++;
}

static void fifo_remove_entry (
    int index,
    int is_removed
) {
    FifofT_Entry* rsentry;
    fifo_relink_neighbors_of (index);
    rsentry = &cache_entry_list[index];
    crlib_lookup_table_remove (rsentry->key, rsentry->key_len);
	if (!is_removed) {
		(*remove_api)(rsentry->key, rsentry->key_len);
	}

	free (rsentry->key);
    memset (rsentry, 0, sizeof (FifofT_Entry));
    cache_count--;
    empty_entry_list[cache_count] = index;
}

static void fifo_relink_neighbors_of (int hole_idx) {
    /* [prev](.next)-> <-(.prev)[hole](.next)-> <-(.prev)[next] */
    /* Re-link the next and previous entries of the hole entry (i.e., to be removed or replaced) */
    int prev_idx = cache_entry_list[hole_idx].prev;
    int next_idx = cache_entry_list[hole_idx].next;
    if (hole_idx == fifo_head_index) {
        fifo_head_index = next_idx;
    } else {
    cache_entry_list[prev_idx].next = next_idx;
    }
    if (hole_idx == fifo_tail_index) {
        fifo_tail_index = prev_idx;
    } else {
        cache_entry_list[next_idx].prev = prev_idx;
    }
}

static void fifo_set (int new_index) {
    int old_head_index = fifo_head_index;
    cache_entry_list[new_index].prev = -1;
    cache_entry_list[new_index].next = old_head_index;
    fifo_head_index = new_index;
    if (old_head_index >= 0) {
        cache_entry_list[old_head_index].prev = new_index;
    } else { // add as the first entry
        fifo_tail_index = new_index;
    }
}

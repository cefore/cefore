/*
 * Copyright (c) 2016, National Institute of Information and Communications
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
 * lru.c
 */

/*
	lru.c is a primitive LRU implementation.
*/

/****************************************************************************************
 Include Files
 ****************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <csmgrd/csmgrd_plugin.h>


/****************************************************************************************
 Macros
 ****************************************************************************************/


/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

/***** structure for listing content entries *****/
typedef struct _LruT_Entry {

	struct _LruT_Entry* 	next;			/* pointer to next entry 					*/
	struct _LruT_Entry* 	prev;			/* pointer to previous entry 				*/

	unsigned char 	key[CsmgrdC_Key_Max];	/* key of content entry 					*/
	int 			key_len;				/* length of key 							*/

} LruT_Entry;

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

static int				lru_entry_num;		/* number of entries listed 				*/
static LruT_Entry* 		lru_head = NULL;	/* pointer to entry at the top of the list	*/
static LruT_Entry* 		lru_tail = NULL;	/* pointer to entry at the tail of the list	*/


/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Updates the LRU list
----------------------------------------------------------------------------------------*/
static void
lru_list_update (
	int index,								/* index of the hash table which content 	*/
											/* entry is cached							*/
	const unsigned char* key, 				/* key of the cached content entry 			*/
	int key_len								/* length of key 							*/
);

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

	/* Inits variables 						*/
	lru_entry_num 	= 0;
	lru_head 		= NULL;
	lru_tail 		= NULL;
	cache_cap 		= 0;
	store_api 		= NULL;
	remove_api 		= NULL;

	/* Records the capacity of cache		*/
	if (capacity < 1) {
		fprintf (stderr, "[LRU LIB] Invalid Cacacity\n");
		return (-1);
	}
	cache_cap = capacity;

	/* Records store and remove APIs 		*/
	if ((store == NULL) || (remove == NULL)) {
		fprintf (stderr, "[LRU LIB] Not specified store or remove API\n");
		return (-1);
	}
	store_api 	= store;
	remove_api 	= remove;

	return (0);
}

/*--------------------------------------------------------------------------------------
	Destroy API
----------------------------------------------------------------------------------------*/
void
destroy (
	void
) {

	/* Inits variables 				*/
	lru_entry_num 	= 0;
	cache_cap 		= 0;
	store_api 		= NULL;
	remove_api 		= NULL;

	return;
}

/*--------------------------------------------------------------------------------------
	Insert API
----------------------------------------------------------------------------------------*/
void
insert (
	CsmgrdT_Content_Entry* entry			/* content entry 							*/
) {
	int index;
	LruT_Entry* lru_work;
	unsigned char 	trg_key[CsmgrdC_Key_Max];
	int 			trg_key_len;

	/* Creates the key 		*/
	trg_key_len = csmgrd_name_chunknum_concatenate (
					entry->name, entry->name_len, entry->chnk_num, trg_key);

	/* Stores the entry and updates the list 	*/
	index = (*store_api)(entry);

	if (index > -1) {
#ifdef CefC_Debug_Lru
		{
			int i;
			
			fprintf (stderr, "# insert\n");
			
			for (i = 0 ; i < trg_key_len ; i++) {
				fprintf (stderr, "%02X ", trg_key[i]);
			}
			fprintf (stderr, "\n");
		}
#endif // CefC_Debug_Lru
		lru_list_update (index, trg_key, trg_key_len);
		return;
	}
	
#ifdef CefC_Debug_Lru
	{
		int i;
		
		fprintf (stderr, "# remove\n");
		
		for (i = 0 ; i < lru_tail->key_len ; i++) {
			fprintf (stderr, "%02X ", lru_tail->key[i]);
		}
		fprintf (stderr, "\n");
	}
#endif // CefC_Debug_Lru
	
	/* Removes the tail entry from the cache 	*/
	(*remove_api)(lru_tail->key, lru_tail->key_len);
	
	/* Updates the list 		*/
	lru_work = lru_tail;
	if ((memcmp (lru_head->key, lru_work->key, lru_head->key_len) == 0) &&
		(lru_head->key_len == lru_work->key_len)) {
		lru_head = NULL;
		lru_tail = NULL;
	} else {
		lru_work->prev->next = NULL;
		lru_tail = lru_work->prev;
	}
	
	free (lru_work);
	lru_entry_num--;
	
#ifdef CefC_Debug_Lru
	{
		int i;
		
		fprintf (stderr, "# insert\n");
		
		for (i = 0 ; i < trg_key_len ; i++) {
			fprintf (stderr, "%02X ", trg_key[i]);
		}
		fprintf (stderr, "\n");
	}
#endif // CefC_Debug_Lru
	/* Stores the entry and updates the list 	*/
	index = (*store_api)(entry);
	if (index > -1) {
		lru_list_update (index, trg_key, trg_key_len);
	}

	return;
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
	LruT_Entry* lru_work = lru_head;
	
	/* Deletes the entry of the specified key from the list 	*/
	while (lru_work) {

		if ((memcmp (key, lru_work->key, key_len) == 0) &&
			(key_len == lru_work->key_len)) {

			if (lru_work->next == NULL) {
				lru_tail = lru_work->prev;
			} else {
				lru_work->next->prev = lru_work->prev;
			}
			
			if (lru_work->prev == NULL) {
				lru_head = lru_work->next;
			} else {
				lru_work->prev->next = lru_work->next;
			}
#ifdef CefC_Debug_Lru
			{
				int i;
				
				fprintf (stderr, "# erace\n");
				
				for (i = 0 ; i < lru_work->key_len ; i++) {
					fprintf (stderr, "%02X ", lru_work->key[i]);
				}
				fprintf (stderr, "\n\n");
			}
#endif // CefC_Debug_Lru
			free (lru_work);
			return;
		}
		lru_work = lru_work->next;
	}

	return;
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
	LruT_Entry* lru_work;
	
	if (lru_head) {
		if ((memcmp (lru_head->key, key, key_len) == 0) &&
			(lru_head->key_len == key_len)) {
#ifdef CefC_Debug_Lru
			{
				int i;
				
				fprintf (stderr, "# hit\n");
				
				for (i = 0 ; i < lru_head->key_len ; i++) {
					fprintf (stderr, "%02X ", lru_head->key[i]);
				}
				fprintf (stderr, "\n");
			}
#endif // CefC_Debug_Lru
			return;
		}
	} else {
		return;
	}
	lru_work = lru_head->next;

	/* Moves the entry of the specified key to the top of the list 	*/
	while (lru_work) {
		if ((memcmp (lru_work->key, key, key_len)) ||
			(lru_work->key_len != key_len)) {
			lru_work = lru_work->next;
		} else {

			if (lru_work->next == NULL) {
				lru_tail = lru_work->prev;
			}
			lru_work->prev->next = lru_work->next;

			if (lru_work->next) {
				lru_work->next->prev = lru_work->prev;
			}

			lru_work->next = lru_head;
			lru_head->prev = lru_work;
			lru_head = lru_work;
			lru_work->prev = NULL;
#ifdef CefC_Debug_Lru
			{
				int i;
				
				fprintf (stderr, "# hit\n");
				
				for (i = 0 ; i < lru_head->key_len ; i++) {
					fprintf (stderr, "%02X ", lru_head->key[i]);
				}
				fprintf (stderr, "\n");
			}
#endif // CefC_Debug_Lru
			return;
		}
	}

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
	// TODO
#ifdef CefC_Debug_Lru
	{
		int i;
		
		fprintf (stderr, "# miss\n");
		
		for (i = 0 ; i < key_len ; i++) {
			fprintf (stderr, "%02X ", key[i]);
		}
		fprintf (stderr, "\n");
	}
#endif // CefC_Debug_Lru
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
	Update the LRU list
----------------------------------------------------------------------------------------*/
static void
lru_list_update (
	int index,								/* index of the hash table which content 	*/
											/* entry is cached							*/
	const unsigned char* key, 				/* key of the cached content entry 			*/
	int key_len								/* length of key 							*/
) {

	LruT_Entry* lru_work;

	if (lru_head) {
		if ((memcmp (lru_head->key, key, key_len) == 0) &&
			(lru_head->key_len == key_len)) {
			return;
		}
		lru_work = lru_head->next;
	} else {
		lru_work = lru_head;
	}

	/* Moves the entry of the specified key to the top of the list 	*/
	while (lru_work) {
		if ((memcmp (lru_work->key, key, key_len)) ||
			(lru_work->key_len != key_len)) {
			lru_work = lru_work->next;
		} else {
			if (lru_work->next == NULL) {
				lru_tail = lru_work->prev;
			}
			lru_work->prev->next = lru_work->next;

			if (lru_work->next) {
				lru_work->next->prev = lru_work->prev;
			}

			lru_work->next = lru_head;
			lru_head->prev = lru_work;
			lru_head = lru_work;
			lru_work->prev = NULL;

			return;
		}
	}

	/* Creates the new entry and inserts to the top of the list		*/
	lru_work = (LruT_Entry*) calloc (1, sizeof (LruT_Entry));
	if (lru_work == NULL) {
		return;
	}
	lru_work->prev = NULL;
	if (lru_head) {
		lru_head->prev = lru_work;
	}
	lru_work->next 	= lru_head;
	lru_head = lru_work;
	lru_entry_num++;

	if (lru_work->next == NULL) {
		lru_tail = lru_work;
	}
	lru_work->key_len = key_len;
	memcpy (lru_work->key, key, key_len);

	return;
}

/*
 * Copyright (c) 2016-2023, National Institute of Information and Communications
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
 * lfu.c
 */

/*
	lfu.c is a primitive LFU implementation, 
    which is a low-overhead approximation of LRU.
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

#define LfuC_Max_Frequency 10


/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

/***** structure for listing content entries *****/
typedef struct {
	unsigned char 	*key;					/* key of content entry 					*/

	int 			key_len;				/* length of key 							*/
    int             freq;
    int             track;
} LfuT_Entry;

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

static int              max_freq;         /* position of hand                         */
static CefT_Rngque*     rings[LfuC_Max_Frequency];
static int              counts[LfuC_Max_Frequency];
static CefT_Mp_Handle   lfu_mp;

static int              cache_count;        /* number of cache entries                  */

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

static void lfu_store_entry(CsmgrdT_Content_Entry* entry);
static void lfu_remove_entry(LfuT_Entry* entry, int is_removed);
static int  lfu_get_min_freq_ring_having_entry();
static int  lfu_is_already_cached(CsmgrdT_Content_Entry* entry);


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
    max_freq = 0;
    cache_count = 0;
    
	/* Records the capacity of cache		*/
	if (capacity < 1) {
		fprintf (stderr, "[LFU LIB] Invalid Cacacity\n");
		return (-1);
	}
	cache_cap = capacity;

	/* Records store and remove APIs 		*/
	if ((store == NULL) || (remove == NULL)) {
		fprintf (stderr, "[LFU LIB] Not specified store or remove API\n");
		return (-1);
	}
	store_api 	= store;
	remove_api 	= remove;
    
    /* Creates lookup table */
    crlib_lookup_table_init(capacity);
    
	/* Creates the memory pool 				*/
    lfu_mp = cef_mpool_init("LfuEntry", sizeof(LfuT_Entry), capacity);
    for (i = 0; i < LfuC_Max_Frequency; i++) {
        rings[i] = cef_rngque_create(capacity);
        counts[i] = 0;
    }

	return (0);
}

/*--------------------------------------------------------------------------------------
	Destroy API
----------------------------------------------------------------------------------------*/
void
destroy (
	void
) {
    max_freq = 0;
    cache_count = 0;
	cache_cap 		= 0;
	store_api 		= NULL;
	remove_api 		= NULL;
	if (lfu_mp) {
		cef_mpool_destroy (lfu_mp);
	}
    crlib_lookup_table_destroy();
}

/*--------------------------------------------------------------------------------------
	Insert API
----------------------------------------------------------------------------------------*/
void
insert (
	CsmgrdT_Content_Entry* entry			/* content entry 							*/
) {
    int removing_freq;
    if (lfu_is_already_cached(entry)) {
        fprintf(stderr, "[LFU LIB] insert: ERROR: specified entry is already cached.\n");
        return;
    }
    if (cache_count >= cache_cap) {
        LfuT_Entry* victim_entry;
        while (1) {
            removing_freq = lfu_get_min_freq_ring_having_entry();
            victim_entry = (LfuT_Entry*)cef_rngque_pop(rings[removing_freq]);
            {
                fprintf(stderr, "[LFU LIB] %s:  FREQ:%d=%d, ", __func__, victim_entry->freq, removing_freq); 
                crlib_force_print_name(victim_entry->key, victim_entry->key_len); 
                fprintf (stderr, "\n"); 
            }
            victim_entry->track--;
            if (removing_freq == victim_entry->freq) break;
            if (victim_entry->track <= 0) cef_mpool_free(lfu_mp, victim_entry);
        }
        lfu_remove_entry(victim_entry, 0);
        if (victim_entry->track <= 0) cef_mpool_free(lfu_mp, victim_entry);
    }
    lfu_store_entry(entry);
}

/*--------------------------------------------------------------------------------------
	Erase API
----------------------------------------------------------------------------------------*/
void
erase (
	unsigned char* key, 				
    	/* key of content entry removed from cache 	*/
											/* table									*/
	int key_len								/* length of the key 						*/
) {
    LfuT_Entry* entry = (LfuT_Entry*) crlib_lookup_table_search_v(key, key_len);
    if (entry == NULL) {
        fprintf(stderr, "[LFU LIB] failed to erace\n");
        return;
    }
    lfu_remove_entry(entry, 1);
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
    int preFreq, proFreq;
    LfuT_Entry* entry = (LfuT_Entry*) crlib_lookup_table_search_v(key, key_len);
    if (entry == NULL) {
        fprintf(stderr, "[LFU LIB] failed to erace\n");
        return;
    }
    if (entry->freq >= LfuC_Max_Frequency - 1) return;
    preFreq = entry->freq;
    proFreq = entry->freq + 1;
    cef_rngque_push(rings[proFreq], entry);
    entry->freq = proFreq;
    entry->track++;
    counts[preFreq]--;
    counts[proFreq]++;
    if (proFreq > max_freq) max_freq = proFreq;
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
static void lfu_store_entry(
	CsmgrdT_Content_Entry* entry
) {
    unsigned char 	key[CsmgrdC_Key_Max];
    int 			key_len;
    LfuT_Entry*   rsentry;
	unsigned char* q;
    
    key_len = csmgrd_name_chunknum_concatenate (
                    entry->name, entry->name_len, entry->chunk_num, key);
    rsentry = (LfuT_Entry*)cef_mpool_alloc(lfu_mp);
    rsentry->key_len = key_len;
  	q = calloc(1, key_len);
    memcpy(q, key, key_len);
	rsentry->key = q;
    rsentry->freq = 0;
    rsentry->track = 1;
    cef_rngque_push(rings[0], rsentry);
    counts[0]++;
    cache_count++;
    crlib_lookup_table_add_v(rsentry->key, rsentry->key_len, rsentry);
    (*store_api)(entry);
}

static void lfu_remove_entry(
    LfuT_Entry* entry,
    int is_removed
) {
    crlib_lookup_table_remove(entry->key, entry->key_len);
    counts[entry->freq]--;
    cache_count--;
    entry->freq = -1;
    if (!is_removed) (*remove_api)(entry->key, entry->key_len);

	free(entry->key);
}

static int lfu_get_min_freq_ring_having_entry() {
    int freq = 0;
    while (counts[freq] == 0) {
        freq++;
        if (freq > max_freq) return -1;
    }
    return freq;
}

static int lfu_is_already_cached(CsmgrdT_Content_Entry* entry) {
    unsigned char 	key[CsmgrdC_Key_Max];
    int 			key_len;
    
    key_len = csmgrd_name_chunknum_concatenate (
                    entry->name, entry->name_len, entry->chunk_num, key);
    LfuT_Entry* tmpentry = (LfuT_Entry*) crlib_lookup_table_search_v(key, key_len);
    return tmpentry != NULL;
}


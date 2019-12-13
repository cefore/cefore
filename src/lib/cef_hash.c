/*
 * Copyright (c) 2016-2019, National Institute of Information and Communications
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
 * cef_hash.c
 */

#define __CEF_HASH_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <limits.h>
#include <openssl/md5.h>

#include <cefore/cef_hash.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/
#define CefC_Max_KLen 				1024
#define CefC_Cleanup_Wmin	 		16
#define CefC_Cleanup_Smin	 		0
#define CefC_Cleanup_Smax	 		4

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

typedef struct CefT_Hash_Table {
	uint32_t 		hash;
	unsigned char 	key[CefC_Max_KLen + 1];
	void* 			elem;
	uint32_t 		klen;
	uint8_t			opt_f;
} CefT_Hash_Table;

typedef struct CefT_Hash {
	uint32_t 			seed;
	CefT_Hash_Table*	tbl;
	uint32_t 			elem_max;			/* Prime numbers larger than the user defined maximum size */
	uint32_t 			elem_num;
	uint32_t 			def_elem_max;		/* User defined maximum size	*/

	uint32_t 			cleanup_mwin;
	uint32_t 			cleanup_cwin;
	uint32_t 			cleanup_step;
} CefT_Hash;

typedef struct CefT_List_Hash_Cell {
	unsigned char* 			key;
	void* 					elem;
	uint32_t 				klen;
	struct CefT_List_Hash_Cell*	next;
} CefT_List_Hash_Cell;

typedef struct CefT_List_Hash {
	CefT_List_Hash_Cell**	tbl;
	uint32_t 			elem_max;
	uint32_t 			elem_num;
} CefT_List_Hash;


/****************************************************************************************
 State Variables
 ****************************************************************************************/


/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/
static uint32_t
cef_hash_number_create (
	uint32_t hash,
	const unsigned char* key,
	uint32_t klen
);
static uint32_t
cef_lhash_number_create (
	const unsigned char* key,
	uint32_t klen
);

/****************************************************************************************
 ****************************************************************************************/
CefT_Hash_Handle
cef_hash_tbl_create (
	uint32_t table_size
) {
	CefT_Hash* ht = NULL;
	int i, n;
	int flag;
	int def_tbl_size = table_size;
	
	/* A prime number larger than the maximum size defined by the user	*/
	/* is set as the table size.										*/
	/* The maximum size defined by the user is set to "def_elem_max".	*/
	for (i = table_size ; i > 1 ; i++) {
		flag = 0;
		
		for (n = 2 ; n < table_size ; n++) {
			if (table_size % n == 0) {
				flag = 1;
				break;
			}
		}
		if (flag) {
			table_size++;
		} else {
			break;
		}
	}
	
	if (table_size > UINT_MAX) {
		return ((CefT_Hash_Handle) NULL);
	}

	ht = (CefT_Hash*) malloc (sizeof (CefT_Hash));
	if (ht == NULL) {
		return ((CefT_Hash_Handle) NULL);
	}
	memset (ht, 0, sizeof (CefT_Hash));

	ht->tbl = (CefT_Hash_Table*) malloc (sizeof (CefT_Hash_Table) * table_size);
	if (ht->tbl == NULL) {
		free (ht);
		return ((CefT_Hash_Handle) NULL);
	}
	memset (ht->tbl, 0, sizeof (CefT_Hash_Table) * table_size);

	srand ((unsigned) time (NULL));
	ht->seed = (uint32_t)(rand () + 1);
	ht->elem_max = table_size;
	ht->def_elem_max = def_tbl_size;
	ht->cleanup_step = CefC_Cleanup_Smin;
	ht->cleanup_mwin = CefC_Cleanup_Wmin;
	ht->cleanup_cwin = 0;

	return ((CefT_Hash_Handle) ht);
}

void
cef_hash_tbl_destroy (
	CefT_Hash_Handle handle
) {
	CefT_Hash* ht = (CefT_Hash*) handle;

	if (ht == NULL) {
		return;
	}
	free (ht->tbl);
	free (ht);

	return;
}

int
cef_hash_tbl_item_set (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen,
	void* elem
) {
	CefT_Hash* ht = (CefT_Hash*) handle;
	uint32_t hash;
	uint32_t index;
	uint32_t i;
	uint32_t empty_index;
	uint32_t empty_ff = 0;

	if ((klen > CefC_Max_KLen) || (ht == NULL)) {
		return (CefC_Hash_Faile);
	}
	ht->cleanup_step = CefC_Cleanup_Smin;
	ht->cleanup_mwin = CefC_Cleanup_Wmin;
	ht->cleanup_cwin = 0;

	hash = cef_hash_number_create (ht->seed, key, klen);
	index = hash % ht->elem_max;
	if (ht->tbl[index].klen == 0) {
		ht->tbl[index].hash = hash;
		ht->tbl[index].elem = elem;
		ht->tbl[index].klen = klen;
		memcpy (ht->tbl[index].key, key, klen);
		ht->elem_num++;
		return (index);
	}

	for (i = index + 1 ; i < ht->elem_max ; i++) {
		if (ht->tbl[i].klen == 0) {
			ht->tbl[i].hash = hash;
			ht->tbl[i].elem = elem;
			ht->tbl[i].klen = klen;
			memcpy (ht->tbl[i].key, key, klen);
			ht->elem_num++;
			return (i);
		}
		if ((ht->tbl[i].hash == hash) &&
			(ht->tbl[i].klen == klen) &&
			(memcmp(ht->tbl[i].key, key, klen) == 0)) {
			ht->tbl[i].elem = elem;
			
			return (i);
		}
		if ((ht->tbl[i].klen == -1) && 
			(empty_ff == 0)){
			empty_index = i;
			empty_ff = 1;
		}
	}

	for (i = 0 ; i < index ; i++) {
		if (ht->tbl[i].klen == 0) {
			ht->tbl[i].hash = hash;
			ht->tbl[i].elem = elem;
			ht->tbl[i].klen = klen;
			memcpy (ht->tbl[i].key, key, klen);
			ht->elem_num++;
			return (i);
		}
		if ((ht->tbl[i].hash == hash) &&
			(ht->tbl[i].klen == klen) &&
			(memcmp(ht->tbl[i].key, key, klen) == 0)) {
			ht->tbl[i].elem = elem;
			return (i);
		}
		if ((ht->tbl[i].klen == -1) && 
			(empty_ff == 0)){
			empty_index = i;
			empty_ff = 1;
		}
	}
	
	if (empty_ff) {
		ht->tbl[empty_index].hash = hash;
		ht->tbl[empty_index].elem = elem;
		ht->tbl[empty_index].klen = klen;
		memcpy (ht->tbl[empty_index].key, key, klen);
		ht->elem_num++;
		return (empty_index);
	}
	return (CefC_Hash_Faile);
}

int
cef_hash_tbl_item_set_for_app (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen,
	uint8_t opt,
	void* elem
) {
	CefT_Hash* ht = (CefT_Hash*) handle;
	uint32_t hash;
	uint32_t index;
	uint32_t i;
	uint32_t empty_index;
	uint32_t empty_ff = 0;

	/*--------------------------*/
	/* Temporary Implimentation */
	/*--------------------------*/

	if ((klen > CefC_Max_KLen) || (ht == NULL)) {
		return (CefC_Hash_Faile);
	}
	ht->cleanup_step = CefC_Cleanup_Smin;
	ht->cleanup_mwin = CefC_Cleanup_Wmin;
	ht->cleanup_cwin = 0;

	hash = cef_hash_number_create (ht->seed, key, klen);
	index = hash % ht->elem_max;

	if (ht->tbl[index].klen == 0) {
		ht->tbl[index].hash = hash;
		ht->tbl[index].elem = elem;
		ht->tbl[index].klen = klen;
		ht->tbl[index].opt_f = opt;
		memcpy (ht->tbl[index].key, key, klen);
		ht->elem_num++;
		return (index);
	}

	for (i = index + 1 ; i < ht->elem_max ; i++) {
		if (ht->tbl[i].klen == 0) {
			ht->tbl[i].hash = hash;
			ht->tbl[i].elem = elem;
			ht->tbl[i].klen = klen;
			ht->tbl[i].opt_f = opt;
			memcpy (ht->tbl[i].key, key, klen);
			ht->elem_num++;
			return (i);
		}
		if ((ht->tbl[i].hash == hash) &&
			(ht->tbl[i].klen == klen) &&
			(memcmp(ht->tbl[i].key, key, klen) == 0)) {
			return (CefC_Hash_Faile);
		}
		if ((ht->tbl[i].klen == -1) && 
			(empty_ff == 0)){
			empty_index = i;
			empty_ff = 1;
		}
	}

	for (i = 0 ; i < index ; i++) {
		if (ht->tbl[i].klen == 0) {
			ht->tbl[i].hash = hash;
			ht->tbl[i].elem = elem;
			ht->tbl[i].klen = klen;
			ht->tbl[i].opt_f = opt;
			memcpy (ht->tbl[i].key, key, klen);
			ht->elem_num++;
			return (i);
		}
		if ((ht->tbl[i].hash == hash) &&
			(ht->tbl[i].klen == klen) &&
			(memcmp(ht->tbl[i].key, key, klen) == 0)) {
			return (CefC_Hash_Faile);
		}
		if ((ht->tbl[i].klen == -1) && 
			(empty_ff == 0)){
			empty_index = i;
			empty_ff = 1;
		}
	}

	if (empty_ff) {
		ht->tbl[empty_index].hash = hash;
		ht->tbl[empty_index].elem = elem;
		ht->tbl[empty_index].klen = klen;
		ht->tbl[empty_index].opt_f = opt;
		memcpy (ht->tbl[empty_index].key, key, klen);
		ht->elem_num++;
		return (empty_index);
	}

	return (CefC_Hash_Faile);
}

void* 
cef_hash_tbl_item_set_prg (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen,
	void* elem
) {
	CefT_Hash* ht = (CefT_Hash*) handle;
	uint32_t hash;
	uint32_t index;
	void* old_elem = (void*) NULL;
	
	if ((klen > CefC_Max_KLen) || (ht == NULL)) {
		return ((void*) NULL);
	}
	hash = cef_hash_number_create (ht->seed, key, klen);
	index = hash % ht->elem_max;
	
	if (ht->tbl[index].klen != 0 && ht->tbl[index].klen != -1) {
		old_elem = ht->tbl[index].elem;
	}
	ht->tbl[index].hash = hash;
	ht->tbl[index].elem = elem;
	ht->tbl[index].klen = klen;
	memcpy (ht->tbl[index].key, key, klen);
	
	return (old_elem);
}

void* 
cef_hash_tbl_item_get_prg (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen
) {
	CefT_Hash* ht = (CefT_Hash*) handle;
	uint32_t hash;
	uint32_t index;
	
	if ((klen > CefC_Max_KLen) || (ht == NULL)) {
		return ((void*) NULL);
	}
	
	hash = cef_hash_number_create (ht->seed, key, klen);
	index = hash % ht->elem_max;
	
	if (ht->tbl[index].hash == hash) {
		if ((ht->tbl[index].klen == klen) && 
			(memcmp (key, ht->tbl[index].key, klen) == 0)) {
			return ((void*) ht->tbl[index].elem);
		}
	}
	
	return ((void*) NULL);
}

uint32_t
cef_hash_tbl_hashv_get (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen
) {
	CefT_Hash* ht = (CefT_Hash*) handle;

	if ((klen > CefC_Max_KLen) || (ht == NULL)) {
		return (0);
	}
	return (cef_hash_number_create (ht->seed, key, klen));
}

void*
cef_hash_tbl_item_get (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen
) {
	CefT_Hash* ht = (CefT_Hash*) handle;
	uint32_t hash;
	uint32_t index;
	uint32_t i;

	if ((klen > CefC_Max_KLen) || (ht == NULL)) {
		return ((void*) NULL);
	}

	hash = cef_hash_number_create (ht->seed, key, klen);
	index = hash % ht->elem_max;

	if ((ht->tbl[index].hash == hash) &&
		(ht->tbl[index].klen == klen) &&
		(memcmp(ht->tbl[index].key, key, klen) == 0)) {
		return ((void*) ht->tbl[index].elem);
	}

	for (i = index + 1 ; i < ht->elem_max ; i++) {
		if(ht->tbl[i].klen == 0){
			return ((void*) NULL);
		}
		if ((ht->tbl[i].hash == hash) &&
			(ht->tbl[i].klen == klen) &&
			(memcmp(ht->tbl[i].key, key, klen) == 0)) {
			return ((void*) ht->tbl[i].elem);
		}
	}

	for (i = 0 ; i < index ; i++) {
		if(ht->tbl[i].klen == 0){
			return ((void*) NULL);
		}
		if ((ht->tbl[i].hash == hash) &&
			(ht->tbl[i].klen == klen) &&
			(memcmp(ht->tbl[i].key, key, klen) == 0)) {
			return ((void*) ht->tbl[i].elem);
		}
	}

	return ((void*) NULL);
}

void*
cef_hash_tbl_item_get_for_app (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen
) {
	CefT_Hash* ht = (CefT_Hash*) handle;
	uint32_t hash;
	uint32_t i;
	uint32_t entry_klen = 0;

	/*--------------------------*/
	/* Temporary Implimentation */
	/*--------------------------*/

	if ((klen > CefC_Max_KLen) || (ht == NULL)) {
		return ((void*) NULL);
	}
	
	/* for exact match */
	hash = cef_hash_number_create (ht->seed, key, klen);

	for (i = 0 ; i < ht->elem_max ; i++) {
		if (ht->tbl[i].klen == 0 || ht->tbl[i].klen == -1)
			continue;
		
		if (ht->tbl[i].opt_f) {
			/* prefix match */
			entry_klen = ht->tbl[i].klen;
			if ((entry_klen <= klen) &&
				(memcmp (ht->tbl[i].key, key, entry_klen) == 0)) {
				if (entry_klen == klen) {
					return ((void*) ht->tbl[i].elem);
				} else if (entry_klen + 5 <= klen) {
					/* eg) ccn:/test, ccn:/test/a */
					/*                         ^^ */
					/* separator(4) and prefix(more than 1) */
					if ((key[entry_klen] == 0x00) &&
						(key[entry_klen + 1] == 0x01)) {
						return ((void*) ht->tbl[i].elem);
					}
				} else {
					continue;
				}
			}
		} else {
			/* exact match */
			if ((ht->tbl[i].hash == hash) &&
				(ht->tbl[i].klen == klen) &&
				(memcmp (ht->tbl[i].key, key, klen) == 0)) {
				return ((void*) ht->tbl[i].elem);
			}
		}
	}

	return ((void*) NULL);
}


void*
cef_hash_tbl_item_get_from_index (
	CefT_Hash_Handle handle,
	uint32_t index
) {
	CefT_Hash* ht = (CefT_Hash*) handle;

	if (index > ht->elem_max) {
		return ((void*) NULL);
	}

	return ((void*) ht->tbl[index].elem);
}

void*
cef_hash_tbl_item_remove (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen
) {
	CefT_Hash* ht = (CefT_Hash*) handle;
	uint32_t hash;
	uint32_t index;
	uint32_t i;
	void* rtc = (void*) NULL;
	int removed_f = 0;
	int si;
	uint32_t removed_indx;

	if ((klen > CefC_Max_KLen) || (ht == NULL)) {
		return (CefC_Hash_False);
	}

	hash = cef_hash_number_create (ht->seed, key, klen);
	index = hash % ht->elem_max;

	if ((ht->tbl[index].hash == hash) &&
		(ht->tbl[index].klen == klen) &&
		(memcmp(ht->tbl[index].key, key, klen) == 0)) {
		ht->tbl[index].hash = 0;
		ht->tbl[index].klen = -1;
		ht->tbl[index].opt_f = 0;
		ht->elem_num--;
		rtc = (void*) ht->tbl[index].elem;
		ht->tbl[index].elem = NULL;
		removed_f = 1;
		removed_indx = index;
		goto ENDFUNC;
	}

	for (i = index + 1 ; i < ht->elem_max ; i++) {
		if(ht->tbl[i].klen == 0){
			rtc = (void*) NULL;
			goto ENDFUNC;
		}
		if ((ht->tbl[i].hash == hash) &&
			(ht->tbl[i].klen == klen) &&
			(memcmp(ht->tbl[i].key, key, klen) == 0)) {
			ht->tbl[i].hash = 0;
			ht->tbl[i].klen = -1;
			ht->tbl[i].opt_f = 0;
			ht->elem_num--;
			rtc = (void*) ht->tbl[i].elem;
			ht->tbl[i].elem = NULL;
			removed_f = 1;
			removed_indx = i;
			goto ENDFUNC;
		}
	}

	for (i = 0 ; i < index ; i++) {
		if(ht->tbl[i].klen == 0){
			return ((void*) NULL);
		}
		if ((ht->tbl[i].hash == hash) &&
			(ht->tbl[i].klen == klen) &&
			(memcmp(ht->tbl[i].key, key, klen) == 0)) {
			ht->tbl[i].hash = 0;
			ht->tbl[i].klen = -1;
			ht->tbl[i].opt_f = 0;
			ht->elem_num--;
			rtc = (void*) ht->tbl[i].elem;
			ht->tbl[i].elem = NULL;
			removed_f = 1;
			removed_indx = i;
			goto ENDFUNC;
		}
	}

ENDFUNC:
	if(removed_f == 1){
		/* compaction */
		if(removed_indx == (ht->elem_max-1)){
			if(ht->tbl[0].klen == 0){
				ht->tbl[removed_indx].klen = 0;
			}
		} else {
			if(ht->tbl[removed_indx+1].klen == 0){
				ht->tbl[removed_indx].klen = 0;
			}
		}
		if(ht->tbl[removed_indx].klen == 0){
			for(si = (removed_indx-1); si >= 0; si--){
				if(ht->tbl[si].klen == -1){
					ht->tbl[si].klen = 0;
				} else {
					break;
				}
			}
			if(ht->tbl[0].klen == 0){
				for(si = (ht->elem_max-1); si > removed_indx; si--){
					if(ht->tbl[si].klen == -1){
						ht->tbl[si].klen = 0;
					} else {
						break;
					}
				}
			}
		}
	}
	return (rtc);
}

void*
cef_hash_tbl_item_check_from_index (
	CefT_Hash_Handle handle,
	uint32_t* index
) {
	CefT_Hash* ht = (CefT_Hash*) handle;
	uint32_t i;

	if (*index > ht->elem_max) {
		return ((void*) NULL);
	}

	for (i = *index ; i < ht->elem_max ; i++) {
		if (ht->tbl[i].klen != 0 && ht->tbl[i].klen != -1){
			*index = i;
			return ((void*) ht->tbl[i].elem);
		}
	}
	*index = 0;
	return ((void*) NULL);
}

void*
cef_hash_tbl_item_remove_from_index (
	CefT_Hash_Handle handle,
	uint32_t index
) {
	CefT_Hash* ht = (CefT_Hash*) handle;
	void* rtc = (void*) NULL;

	if (index > ht->elem_max) {
		return ((void*) NULL);
	}

	if (ht->tbl[index].klen != 0 && ht->tbl[index].klen != -1) {
		ht->tbl[index].hash = 0;
		ht->tbl[index].klen = -1;
		ht->elem_num--;
		rtc = (void*) ht->tbl[index].elem;
		ht->tbl[index].elem = NULL;
		return (rtc);
	}

	return ((void*) NULL);
}

int
cef_hash_tbl_item_num_get (
	CefT_Hash_Handle handle
) {
	return ((int)(((CefT_Hash*) handle)->elem_num));
}

/* Get user defined maximum size	*/
int
cef_hash_tbl_def_max_get (
	CefT_Hash_Handle handle
) {
	return ((int)(((CefT_Hash*) handle)->def_elem_max));
}

int
cef_hash_tbl_item_max_idx_get (
	CefT_Hash_Handle handle
) {
	return ((int)(((CefT_Hash*) handle)->elem_max));
}

void*
cef_hash_tbl_elem_get (
	CefT_Hash_Handle handle,
	uint32_t* index
) {
	CefT_Hash* ht = (CefT_Hash*) handle;
	uint32_t i;

	if (*index > ht->elem_max) {
		return ((void*) NULL);
	}

	for (i = *index ; i < ht->elem_max ; i++) {
		if (ht->tbl[i].klen != 0 && ht->tbl[i].klen != -1) {
			*index = i;
			return ((void*) ht->tbl[i].elem);
		}
	}

	for (i = 0 ; i < *index ; i++) {
		if (ht->tbl[i].klen != 0 && ht->tbl[i].klen != -1) {
			*index = i;
			return ((void*) ht->tbl[i].elem);
		}
	}
	*index = 0;
	
	return ((void*) NULL);
}

void*
cef_hash_tbl_no_col_item_get (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen
) {
	CefT_Hash* ht = (CefT_Hash*) handle;
	uint32_t hash;
	uint32_t index;

	if ((klen > CefC_Max_KLen) || (ht == NULL)) {
		return ((void*) NULL);
	}

	hash = cef_hash_number_create (ht->seed, key, klen);
	index = hash % ht->elem_max;

	if ((ht->tbl[index].hash == hash) &&
		(ht->tbl[index].klen == klen) && 
		(memcmp(ht->tbl[index].key, key, klen) == 0)) {
		return ((void*) ht->tbl[index].elem);
	}
	return ((void*) NULL);
}

void* 
cef_hash_tbl_item_check (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen
) {
	CefT_Hash* ht = (CefT_Hash*) handle;

	
	if ((klen > CefC_Max_KLen) || (ht == NULL)) {
		return ((void*) NULL);
	}
	
	return ((void*) cef_hash_tbl_item_get(handle, key, klen));
}
int
cef_hash_tbl_item_check_exact (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen
) {
	CefT_Hash* ht = (CefT_Hash*) handle;

	
	if ((klen > CefC_Max_KLen) || (ht == NULL)) {
		return (-1);
	}
	if(cef_hash_tbl_item_get(handle, key, klen) == NULL){
		return (-1);
	} else {
		return (1);
	}
}
CefT_Hash_Handle
cef_lhash_tbl_create (
	uint32_t table_size
) {
	CefT_List_Hash* ht = NULL;
	int i, n;
	int flag;
	
	for (i = table_size ; i > 1 ; i++) {
		flag = 0;
		
		for (n = 2 ; n < table_size ; n++) {
			if (table_size % n == 0) {
				flag = 1;
				break;
			}
		}
		if (flag) {
			table_size++;
		} else {
			break;
		}
	}

	if (table_size > 1048576) {
		return ((CefT_Hash_Handle) NULL);
	}

	ht = (CefT_List_Hash*) malloc (sizeof (CefT_List_Hash));
	if (ht == NULL) {
		return ((CefT_Hash_Handle) NULL);
	}
	memset (ht, 0, sizeof (CefT_List_Hash));

	ht->tbl = (CefT_List_Hash_Cell**) malloc (sizeof (CefT_List_Hash_Cell *) * table_size);
	if (ht->tbl == NULL) {
		free (ht);
		return ((CefT_Hash_Handle) NULL);
	}
	memset (ht->tbl, 0, sizeof (CefT_List_Hash_Cell*) * table_size);
	
	ht->elem_max = table_size;

	return ((CefT_Hash_Handle) ht);
}
CefT_Hash_Handle
cef_lhash_tbl_create_u32 (
	uint32_t table_size
) {
	CefT_List_Hash* ht = NULL;
	int i, n;
	int flag;
	
	for (i = table_size ; i > 1 ; i++) {
		flag = 0;
		
		for (n = 2 ; n < table_size ; n++) {
			if (table_size % n == 0) {
				flag = 1;
				break;
			}
		}
		if (flag) {
			table_size++;
		} else {
			break;
		}
	}

	if (table_size > UINT_MAX) {
		table_size = UINT_MAX;
	}

	ht = (CefT_List_Hash*) malloc (sizeof (CefT_List_Hash));
	if (ht == NULL) {
		return ((CefT_Hash_Handle) NULL);
	}
	memset (ht, 0, sizeof (CefT_List_Hash));

	ht->tbl = (CefT_List_Hash_Cell**) malloc (sizeof (CefT_List_Hash_Cell *) * table_size);
	if (ht->tbl == NULL) {
		free (ht);
		return ((CefT_Hash_Handle) NULL);
	}
	memset (ht->tbl, 0, sizeof (CefT_List_Hash_Cell*) * table_size);
	
	ht->elem_max = table_size;

	return ((CefT_Hash_Handle) ht);
}

void
cef_lhash_tbl_destroy ( 
	CefT_Hash_Handle handle
) {
	CefT_List_Hash* ht = (CefT_List_Hash*) handle;
	uint32_t i;
	
	if (ht == NULL) {
		return;
	}
	for (i = 0 ; i < ht->elem_max ; i++) {
		CefT_List_Hash_Cell* cp;
		CefT_List_Hash_Cell* wcp;
		cp = ht->tbl[i];
		while (cp != NULL) {
			wcp = cp->next;
			free(cp);
			cp = wcp;
		}
	}
	free (ht->tbl);
	free (ht);

	return;
}

int
cef_lhash_tbl_item_set (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen,
	void* elem
) {
	CefT_List_Hash* ht = (CefT_List_Hash*) handle;
	uint32_t hash;
	uint32_t index;
	CefT_List_Hash_Cell* cp;
	CefT_List_Hash_Cell* wcp;

	if ((klen > CefC_Max_KLen) || (ht == NULL)) {
		return (CefC_Hash_Faile);
	}
	
	hash = cef_lhash_number_create (key, klen);
	index = hash % ht->elem_max;

	if(ht->tbl[index] == NULL){
		ht->tbl[index] = (CefT_List_Hash_Cell* )calloc(1, sizeof(CefT_List_Hash_Cell) + klen);
		if (ht->tbl[index] == NULL) {
			return (-1);
		}
		ht->tbl[index]->key = ((unsigned char*)ht->tbl[index]) + sizeof(CefT_List_Hash_Cell);
		cp = ht->tbl[index];
		cp->elem = elem;
		cp->klen = klen;
		memcpy (cp->key, key, klen);
		ht->elem_num++;
		return (0);
	} else {
		/* exist check & replace */
		for (cp = ht->tbl[index]; cp != NULL; cp = cp->next) {
			if((cp->klen == klen) &&
			   (memcmp (cp->key, key, klen) == 0)){
				cp->elem = elem;
				return (0);
		   }
		}
		/* insert */
		wcp = ht->tbl[index];
		ht->tbl[index] = (CefT_List_Hash_Cell* )calloc(1, sizeof(CefT_List_Hash_Cell) + klen);
		if (ht->tbl[index] == NULL) {
			return (-1);
		}
		ht->tbl[index]->key = ((unsigned char*)ht->tbl[index]) + sizeof(CefT_List_Hash_Cell);
		cp = ht->tbl[index];
		cp->next = wcp;
		cp->elem = elem;
		cp->klen = klen;
		memcpy (cp->key, key, klen);
		ht->elem_num++;
		return (0);
	}
}

void*
cef_lhash_tbl_item_get (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen
) {
	CefT_List_Hash* ht = (CefT_List_Hash*) handle;
	uint32_t hash;
	uint32_t index;
	CefT_List_Hash_Cell* cp;

	if ((klen > CefC_Max_KLen) || (ht == NULL)) {
		return ((void*) NULL);
	}

	hash = cef_lhash_number_create (key, klen);
	index = hash % ht->elem_max;

	cp = ht->tbl[index];
	if(cp == NULL){
		return (NULL);
	} 
	for (cp = ht->tbl[index]; cp != NULL; cp = cp->next) {
		if((cp->klen == klen) &&
		   (memcmp (cp->key, key, klen) == 0)){
		   	return ((void*) cp->elem);
		}
	}
	return (NULL);
}

void*
cef_lhash_tbl_item_remove (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen
) {
	CefT_List_Hash* ht = (CefT_List_Hash*) handle;
	uint32_t hash;
	uint32_t index;
	void* ret_elem;
	CefT_List_Hash_Cell* cp;
	CefT_List_Hash_Cell* wcp;

	if ((klen > CefC_Max_KLen) || (ht == NULL)) {
		return (CefC_Hash_False);
	}

	hash = cef_lhash_number_create (key, klen);
	index = hash % ht->elem_max;
	
	cp = ht->tbl[index];
	if(cp == NULL){
		return (NULL);
	}
	if (cp != NULL) {
		if((cp->klen == klen) &&
		   (memcmp (cp->key, key, klen) == 0)){
		   	ht->tbl[index] = cp->next;
			ht->elem_num--;
		   	ret_elem = cp->elem;
		   	free(cp);
		   	return ((void *)ret_elem);
		} else {
			cp = ht->tbl[index];
			for (; cp->next != NULL; cp = cp->next) {
				if((cp->next->klen == klen) &&
				   (memcmp (cp->next->key, key, klen) == 0)){
				   	wcp = cp->next;
				   	cp->next = cp->next->next;
					ht->elem_num--;
				   	ret_elem = wcp->elem;
		   			free(wcp);
		   			return ((void *)ret_elem);
				}
			}
		}
	}

	return (NULL);
}

/****************************************************************************************
 ****************************************************************************************/

static uint32_t
cef_hash_number_create (
	uint32_t hash,
	const unsigned char* key,
	uint32_t klen
) {
#if 0
	int i;
	char* p = (char*) key;

	hash += p[0];
	hash += p[klen - 1];
	hash += p[(klen - 1) / 2];

	for (i = 0 ; i < klen ; i++) {
		hash = hash * 33 + p[i];
	}
#endif
	unsigned char out[MD5_DIGEST_LENGTH];
	
	MD5 (key, klen, out);
	memcpy (&hash, &out[12], sizeof (uint32_t));

	return (hash);
}

static uint32_t
cef_lhash_number_create (
	const unsigned char* key,
	uint32_t klen
) {
	uint32_t hash;
	unsigned char out[MD5_DIGEST_LENGTH];
	
	MD5 (key, klen, out);
	memcpy (&hash, &out[12], sizeof (uint32_t));

	return (hash);
}

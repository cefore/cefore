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
 * cef_hash.c
 */

#define __CEF_HASH_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <cefore/cef_hash.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/
#define CefC_Max_KLen 				1024
#define CefC_Cleanup_Wmin	 		16
#define CefC_Cleanup_Smin	 		0
#define CefC_Cleanup_Smax	 		4

static const uint32_t CEF_OFFSET_BASIS_32 = 2166136261U;
static const uint32_t CEF_PRIME_32 = 16777619U;

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

typedef struct CefT_Hash_Table {
	uint32_t 		hash;
	unsigned char 	key[CefC_Max_KLen + 1];
	void* 			elem;
	uint32_t 		klen;
} CefT_Hash_Table;

typedef struct CefT_Hash {
	uint32_t 			seed;
	CefT_Hash_Table*	tbl;
	uint32_t 			elem_max;
	uint32_t 			elem_num;

	uint32_t 			cleanup_mwin;
	uint32_t 			cleanup_cwin;
	uint32_t 			cleanup_step;
} CefT_Hash;

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
static void
cef_hash_cleanup (
	CefT_Hash* ht
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

	if ((klen > CefC_Max_KLen) || (ht == NULL)) {
		return (CefC_Hash_Faile);
	}
	if (ht->elem_num > ht->elem_max - 1) {
		cef_hash_cleanup (ht);
		return (CefC_Hash_Faile);
	}
	ht->cleanup_step = CefC_Cleanup_Smin;
	ht->cleanup_mwin = CefC_Cleanup_Wmin;
	ht->cleanup_cwin = 0;

	hash = cef_hash_number_create (ht->seed, key, klen);
	index = hash % ht->elem_max;

	if (ht->tbl[index].hash == 0) {
		ht->tbl[index].hash = hash;
		ht->tbl[index].elem = elem;
		ht->tbl[index].klen = klen;
		memcpy (ht->tbl[index].key, key, klen);
		ht->elem_num++;
		return (index);
	}

	if ((ht->tbl[index].hash == hash) &&
		(ht->tbl[index].klen == klen)) {

		ht->tbl[index].elem = elem;
		return (index);
	}
	for (i = index + 1 ; i < ht->elem_max ; i++) {
		if (ht->tbl[i].hash == 0) {
			ht->tbl[i].hash = hash;
			ht->tbl[i].elem = elem;
			ht->tbl[i].klen = klen;
			memcpy (ht->tbl[i].key, key, klen);
			ht->elem_num++;
			return (i);
		}
		if ((ht->tbl[i].hash == hash) &&
			(ht->tbl[i].klen == klen)) {
			ht->tbl[i].elem = elem;
			return (i);
		}
	}

	for (i = 0 ; i < index ; i++) {
		if (ht->tbl[i].hash == 0) {
			ht->tbl[i].hash = hash;
			ht->tbl[i].elem = elem;
			ht->tbl[i].klen = klen;
			memcpy (ht->tbl[i].key, key, klen);
			ht->elem_num++;
			return (i);
		}
		if ((ht->tbl[i].hash == hash) &&
			(ht->tbl[i].klen == klen)) {
			ht->tbl[i].elem = elem;
			return (i);
		}
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
	
	if (ht->tbl[index].hash) {
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
		(ht->tbl[index].klen == klen)) {
		return ((void*) ht->tbl[index].elem);
	}

	for (i = index + 1 ; i < ht->elem_max ; i++) {
		if ((ht->tbl[i].hash == hash) &&
			(ht->tbl[i].klen == klen)) {
			return ((void*) ht->tbl[i].elem);
		}
	}

	for (i = 0 ; i < index ; i++) {
		if ((ht->tbl[i].hash == hash) &&
			(ht->tbl[i].klen == klen)) {
			return ((void*) ht->tbl[i].elem);
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

	if ((klen > CefC_Max_KLen) || (ht == NULL)) {
		return (CefC_Hash_False);
	}

	hash = cef_hash_number_create (ht->seed, key, klen);
	index = hash % ht->elem_max;

	if ((ht->tbl[index].hash == hash) &&
		(ht->tbl[index].klen == klen)) {
		ht->tbl[index].hash = 0;
		ht->elem_num--;
		return ((void*) ht->tbl[index].elem);
	}

	for (i = index + 1 ; i < ht->elem_max ; i++) {
		if ((ht->tbl[i].hash == hash) &&
			(ht->tbl[i].klen == klen)) {
			ht->tbl[i].hash = 0;
			ht->elem_num--;
			return ((void*) ht->tbl[i].elem);
		}
	}

	for (i = 0 ; i < index ; i++) {
		if ((ht->tbl[i].hash == hash) &&
			(ht->tbl[i].klen == klen)) {
			ht->tbl[i].hash = 0;
			ht->elem_num--;
			return ((void*) ht->tbl[i].elem);
		}
	}

	return ((void*) NULL);
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
		if (ht->tbl[i].hash) {
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

	if (index > ht->elem_max) {
		return ((void*) NULL);
	}

	if (ht->tbl[index].hash) {
		ht->tbl[index].hash = 0;
		ht->elem_num--;
		return ((void*) ht->tbl[index].elem);
	}

	return ((void*) NULL);
}

int
cef_hash_tbl_item_num_get (
	CefT_Hash_Handle handle
) {
	return ((int)(((CefT_Hash*) handle)->elem_num));
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
		if (ht->tbl[i].hash) {
			*index = i;
			return ((void*) ht->tbl[i].elem);
		}
	}

	for (i = 0 ; i < *index ; i++) {
		if (ht->tbl[i].hash) {
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
		(ht->tbl[index].klen == klen)) {
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
	uint32_t i;
	
	if ((klen > CefC_Max_KLen) || (ht == NULL)) {
		return ((void*) NULL);
	}
	
	for (i = 0 ; i < ht->elem_max ; i++) {
		if (ht->tbl[i].hash) {
			if (memcmp (key, ht->tbl[i].key, klen) == 0) {
				return ((void*) ht->tbl[i].elem);
			}
		}
	}
	return ((void*) NULL);
}
int
cef_hash_tbl_item_check_exact (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen
) {
	CefT_Hash* ht = (CefT_Hash*) handle;
	uint32_t i;
	
	if ((klen > CefC_Max_KLen) || (ht == NULL)) {
		return (-1);
	}
	
	for (i = 0 ; i < ht->elem_max ; i++) {
		if (ht->tbl[i].hash) {
			if ((ht->tbl[i].klen == klen) && 
				(memcmp (key, ht->tbl[i].key, klen) == 0)) {
				return (1);
			}
		}
	}
	return (-1);
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
	size_t i;
	
	hash = CEF_OFFSET_BASIS_32;
	for (i = 0 ; i < klen ; i++) {
	    hash = (CEF_PRIME_32 * hash) ^ (key[i]);
	}
	
	return (hash);
}

static void
cef_hash_cleanup (
	CefT_Hash* ht
) {
	uint32_t hash;
	uint32_t index;
	uint32_t i, n;

	ht->cleanup_cwin++;
	if (ht->cleanup_cwin > ht->cleanup_mwin) {;
		index = CefC_Cleanup_Wmin;
		for (i = 0 ; i < ht->cleanup_step ; i++) {
			index *= CefC_Cleanup_Wmin;
		}
		if (ht->cleanup_step < CefC_Cleanup_Smax) {
			ht->cleanup_step++;
		}
		ht->cleanup_cwin = 0;
	} else {
		return;
	}
	
	for (i = 0 ; i < ht->elem_max ; i++) {
		if (ht->tbl[i].hash == 0) {
			continue;
		}
		hash = cef_hash_number_create (
			ht->seed, ht->tbl[i].key, ht->tbl[i].klen);
		index = hash % ht->elem_max;
		
		for (n = 0 ; n < ht->elem_max ; n++) {
			if ((i == n) || (ht->tbl[i].hash != ht->tbl[n].hash)) {
				continue;
			}
			ht->elem_num--;
			
			if (n == index) {
				ht->tbl[i].hash = 0;
				break;
			} else if (i == index) {
				ht->tbl[n].hash = 0;
			} else if (i < index) {
				if (i < n) {
					ht->tbl[n].hash = 0;
				} else {
					ht->tbl[i].hash = 0;
					break;
				}
			} else {
				if ((n > index) && (i > n)) {
					ht->tbl[i].hash = 0;
					break;
				} else {
					ht->tbl[n].hash = 0;
				}
			}
		}
	}
	return;
}

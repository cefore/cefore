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
 * cef_csmgr_stat.c
 */

#define __CEF_CSMGR_STAT_SOURCE__


/****************************************************************************************
 Include Files
 ****************************************************************************************/

#include <openssl/md5.h>

#include <cefore/cef_csmgr_stat.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/


/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/


typedef struct {
	
	uint32_t 			capacity;
	uint16_t			cached_con_num;
	CsmgrT_Stat* 		rcds[CsmgrT_Stat_Max];
	
} CsmgrT_Stat_Table;

/****************************************************************************************
 State Variables
 ****************************************************************************************/


/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

static CsmgrT_Stat* 
csmgrd_stat_content_lookup (
	CsmgrT_Stat_Table* tbl, 
	const unsigned char* name, 
	uint16_t name_len, 
	int* create_f
);
static CsmgrT_Stat* 
csmgrd_stat_content_search (
	CsmgrT_Stat_Table* tbl, 
	const unsigned char* name, 
	uint16_t name_len
);
static CsmgrT_Stat* 
csmgrd_stat_content_salvage (
	CsmgrT_Stat_Table* tbl, 
	const unsigned char* name, 
	uint16_t name_len, 
	int* start_index
);
static uint32_t
csmgrd_stat_hash_number_create (
	const unsigned char* key, 
	uint16_t klen
);

/****************************************************************************************
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Creates the Csmgrd Stat Handle
----------------------------------------------------------------------------------------*/
CsmgrT_Stat_Handle 
csmgrd_stat_handle_create (
	void 
) {
	CsmgrT_Stat_Table* tbl;
	int i;
	
	tbl = (CsmgrT_Stat_Table*) malloc (sizeof (CsmgrT_Stat_Table));
	if (tbl == NULL) {
		return (CsmgrC_Invalid);
	}
	memset (tbl, 0, sizeof (CsmgrT_Stat_Table));
	
	for (i = 0 ; i < CsmgrT_Stat_Max ; i++) {
		tbl->rcds[i] = (CsmgrT_Stat*) malloc (sizeof (CsmgrT_Stat));
		
		if (tbl->rcds[i] == NULL) {
			free (tbl);
			return (CsmgrC_Invalid);
		}
		memset (tbl->rcds[i], 0, sizeof (CsmgrT_Stat));
	}
	
	return ((CsmgrT_Stat_Handle) tbl);
}

/*--------------------------------------------------------------------------------------
	Destroy the Csmgrd Stat Handle
----------------------------------------------------------------------------------------*/
void 
csmgrd_stat_handle_destroy (
	CsmgrT_Stat_Handle hdl
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	int i;
	
	if (tbl) {
		for (i = 0 ; i < CsmgrT_Stat_Max ; i++) {
			if (tbl->rcds[i]) {
				free (tbl->rcds[i]);
			}
		}
		
		free (tbl);
	}
	return;
}
/*--------------------------------------------------------------------------------------
	Access the content information
----------------------------------------------------------------------------------------*/
CsmgrT_Stat* 
csmgrd_stat_content_info_access (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	CsmgrT_Stat* rcd = NULL;
	uint64_t nowt;
	struct timeval tv;
	
	if (!tbl) {
		return (NULL);
	}
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000 + tv.tv_usec;
	
	rcd = csmgrd_stat_content_search (tbl, name, name_len);
	
	if (rcd) {
		if ((rcd->cob_num == 0) || (nowt > rcd->expiry)){
			rcd->expire_f = 1;
		}
	}
	
	return (rcd);
}
/*--------------------------------------------------------------------------------------
	Obtain the content information
----------------------------------------------------------------------------------------*/
CsmgrT_Stat* 
csmgrd_stat_content_info_get (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	CsmgrT_Stat* rcd = NULL;
	uint32_t min_seq = 0;
	uint32_t max_seq = CsmgrT_Stat_Seq_Max;
	uint32_t i, n;
	uint64_t mask;
	uint64_t nowt;
	struct timeval tv;
	
	if (!tbl) {
		return (NULL);
	}
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000 + tv.tv_usec;
	
	rcd = csmgrd_stat_content_search (tbl, name, name_len);
	
	if (rcd) {
		if ((rcd->cob_num == 0) || (nowt > rcd->expiry)){
			rcd->expire_f = 1;
			return (NULL);
		}
		
		for (i = 0 ; i < CsmgrT_Map_Max ; i++) {
			if (rcd->cob_map[i]) {
				mask = 0x0000000000000001;
				for (n = 0 ; n < 64 ; n++) {
					if (rcd->cob_map[i] & mask) {
						min_seq = i * 64 + n;
						break;
					}
					mask <<= 1;
				}
				break;
			}
		}
		for (i = CsmgrT_Map_Max - 1 ; i != 0xFFFFFFFF ; i--) {
			if (rcd->cob_map[i]) {
				mask = 0x8000000000000000;
				for (n = 0 ; n < 64 ; n++) {
					if (rcd->cob_map[i] & mask) {
						max_seq = i * 64 + (64 - n) - 1;
						break;
					}
					mask >>= 1;
				}
				break;
			}
		}
		rcd->min_seq = min_seq;
		rcd->max_seq = max_seq;
	}
	
	return (rcd);
}
/*--------------------------------------------------------------------------------------
	Obtain the content information
----------------------------------------------------------------------------------------*/
int 
csmgrd_stat_content_info_gets (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len, 
	int partial_match_f, 
	CsmgrT_Stat* ret[CefstatC_MaxUri]
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	CsmgrT_Stat* rcd = NULL;
	
	uint32_t min_seq = 0;
	uint32_t max_seq = CsmgrT_Stat_Seq_Max;
	uint32_t i, n;
	uint64_t mask;
	int index = 0;
	int num = 0;
	uint64_t nowt;
	struct timeval tv;
	
	if (!tbl) {
		return (0);
	}
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000 + tv.tv_usec;
	
	if (!partial_match_f) {
		if (!name_len) {
			return (0);
		}
		
		rcd = csmgrd_stat_content_search (tbl, name, name_len);
		
		if (!rcd) {
			return (0);
		}
		
		if ((rcd->cob_num == 0) || (nowt > rcd->expiry)){
			rcd->expire_f = 1;
			return (0);
		}
		
		for (i = 0 ; i < CsmgrT_Map_Max ; i++) {
			if (rcd->cob_map[i]) {
				mask = 0x0000000000000001;
				for (n = 0 ; n < 64 ; n++) {
					if (rcd->cob_map[i] & mask) {
						min_seq = i * 64 + n;
						break;
					}
					mask <<= 1;
				}
				break;
			}
		}
		for (i = CsmgrT_Map_Max - 1 ; i != 0xFFFFFFFF ; i--) {
			if (rcd->cob_map[i]) {
				mask = 0x8000000000000000;
				for (n = 0 ; n < 64 ; n++) {
					if (rcd->cob_map[i] & mask) {
						max_seq = i * 64 + (64 - n) - 1;
						break;
					}
					mask >>= 1;
				}
				break;
			}
		}
		rcd->min_seq = min_seq;
		rcd->max_seq = max_seq;
		
		ret[0] = rcd;
		
		return (1);
	}
	
	do {
		rcd = csmgrd_stat_content_salvage (tbl, name, name_len, &index);
		
		if (!rcd) {
			break;
		}
		
		if ((rcd->cob_num == 0) || (nowt > rcd->expiry)){
			rcd->expire_f = 1;
			continue;
		}
		
		for (i = 0 ; i < CsmgrT_Map_Max ; i++) {
			if (rcd->cob_map[i]) {
				mask = 0x0000000000000001;
				for (n = 0 ; n < 64 ; n++) {
					if (rcd->cob_map[i] & mask) {
						min_seq = i * 64 + n;
						break;
					}
					mask <<= 1;
				}
				break;
			}
		}
		for (i = CsmgrT_Map_Max - 1 ; i != 0xFFFFFFFF ; i--) {
			if (rcd->cob_map[i]) {
				mask = 0x8000000000000000;
				for (n = 0 ; n < 64 ; n++) {
					if (rcd->cob_map[i] & mask) {
						max_seq = i * 64 + (64 - n) - 1;
						break;
					}
					mask >>= 1;
				}
				break;
			}
		}
		rcd->min_seq = min_seq;
		rcd->max_seq = max_seq;
		
		ret[num] = rcd;
		num++;
		
	} while (rcd);
	
	return (num);
}
/*--------------------------------------------------------------------------------------
	Obtain the expred lifetime content information
----------------------------------------------------------------------------------------*/
CsmgrT_Stat* 
csmgrd_stat_expired_content_info_get (
	CsmgrT_Stat_Handle hdl, 
	int* index
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	uint64_t nowt;
	struct timeval tv;
	int i;
	
	if (!tbl) {
		return (0);
	}
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000 + tv.tv_usec;
	
	for (i = *index ; i < CsmgrT_Stat_Max ; i++) {
		if ((tbl->rcds[i]->hash) && (nowt > tbl->rcds[i]->expiry)) {
			tbl->rcds[i]->expire_f = 1;
			*index += 1;
			return (tbl->rcds[i]);
		}
	}
	
	return (NULL);
}
/*--------------------------------------------------------------------------------------
	Update cached Cob status
----------------------------------------------------------------------------------------*/
void 
csmgrd_stat_cob_update (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len, 
	uint32_t seq, 
	uint32_t cob_size, 
	uint64_t expiry, 
	uint64_t cached_time, 
	struct in_addr node
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	CsmgrT_Stat* rcd;
	uint64_t mask = 1;
	uint16_t x;
	int create_f = 0;
	
	if ((!tbl) || (seq > CsmgrT_Stat_Seq_Max)) {
		return;
	}
	
	rcd = csmgrd_stat_content_lookup (tbl, name, name_len, &create_f);
	if (!rcd) {
		return;
	}
	x = seq / 64;
	mask <<= (seq % 64);
	
	if (create_f) {
		tbl->cached_con_num++;
	}
	
	if (rcd->cob_num < 1) {
		rcd->expiry 		= expiry;
		rcd->cached_time 	= cached_time;
		rcd->node 			= node;
	}
	
	if (!(rcd->cob_map[x] & mask)) {
		rcd->cob_num++;
		rcd->con_size += cob_size;
	}
	rcd->cob_map[x] |= mask;
	
	return;
}
/*--------------------------------------------------------------------------------------
	Remove the specified cached Cob status
----------------------------------------------------------------------------------------*/
int 
csmgrd_stat_cob_remove (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len, 
	uint32_t seq, 
	uint32_t cob_size
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	CsmgrT_Stat* rcd;
	uint64_t mask = 1;
	uint16_t x;
	int index;
	
	if ((!tbl) || (seq > CsmgrT_Stat_Seq_Max)) {
		return (-1);
	}
	
	rcd = csmgrd_stat_content_search (tbl, name, name_len);
	if (!rcd) {
		return (-1);
	}
	
	x = seq / 64;
	mask <<= (seq % 64);
	
	if (rcd->cob_map[x] & mask) {
		rcd->cob_num--;
		rcd->con_size -= cob_size;
	}
	rcd->cob_map[x] &= ~mask;
	
	if (rcd->cob_num == 0) {
		index = rcd->index;
		tbl->cached_con_num--;
		memset (rcd, 0, sizeof (CsmgrT_Stat));
		return (index);
	}
	
	return (-1);
}
/*--------------------------------------------------------------------------------------
	Update access count
----------------------------------------------------------------------------------------*/
void 
csmgrd_stat_access_count_update (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	CsmgrT_Stat* rcd;
	
	if (!tbl) {
		return;
	}
	
	rcd = csmgrd_stat_content_search (tbl, name, name_len);
	if (!rcd) {
		return;
	}
	rcd->access++;
	
	return;
}

/*--------------------------------------------------------------------------------------
	Update cache capacity
----------------------------------------------------------------------------------------*/
void 
csmgrd_stat_cache_capacity_update (
	CsmgrT_Stat_Handle hdl, 
	uint32_t capacity
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	int i;
	
	if (!tbl) {
		return;
	}
	for (i = 0 ; i < CsmgrT_Stat_Max ; i++) {
		memset (tbl->rcds[i], 0, sizeof (CsmgrT_Stat));
	}
	tbl->cached_con_num = 0;
	tbl->capacity = capacity;
	
	return;
}

/*--------------------------------------------------------------------------------------
	Update content expire time
----------------------------------------------------------------------------------------*/
void 
csmgrd_stat_content_lifetime_update (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len, 
	uint64_t expiry
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	CsmgrT_Stat* rcd;
	
	if (!tbl) {
		return;
	}
	rcd = csmgrd_stat_content_search (tbl, name, name_len);
	if (!rcd) {
		return;
	}
	rcd->expiry = expiry;
	
	return;
}
/*--------------------------------------------------------------------------------------
	Init the valiables of the specified content
----------------------------------------------------------------------------------------*/
CsmgrT_Stat* 
csmgrd_stat_content_info_init (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	CsmgrT_Stat* rcd;
	int create_f = 0;
	
	if (!tbl) {
		return (NULL);
	}
	
	rcd = csmgrd_stat_content_lookup (tbl, name, name_len, &create_f);
	if (!rcd) {
		return (NULL);
	}
	
	if (create_f) {
		tbl->cached_con_num++;
	}
	
	return (rcd);
}
/*--------------------------------------------------------------------------------------
	Deletes the content information
----------------------------------------------------------------------------------------*/
void 
csmgrd_stat_content_info_delete (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	CsmgrT_Stat* rcd = NULL;
	
	if (!tbl) {
		return;
	}
	
	rcd = csmgrd_stat_content_search (tbl, name, name_len);
	
	if (rcd) {
		tbl->cached_con_num--;
		memset (rcd, 0, sizeof (CsmgrT_Stat));
		rcd->name_len = 0xFFFF;
	}
	return;
}
/*--------------------------------------------------------------------------------------
	Obtains the number of cached content
----------------------------------------------------------------------------------------*/
uint16_t 
csmgrd_stat_cached_con_num_get (
	CsmgrT_Stat_Handle hdl
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	
	if (!tbl) {
		return (0);
	}
	return (tbl->cached_con_num);
}

/*--------------------------------------------------------------------------------------
	Obtains the Cache capacity
----------------------------------------------------------------------------------------*/
uint32_t 
csmgrd_stat_cache_capacity_get (
	CsmgrT_Stat_Handle hdl
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	
	if (!tbl) {
		return (0);
	}
	return (tbl->capacity);
}

/****************************************************************************************
 ****************************************************************************************/

static CsmgrT_Stat* 
csmgrd_stat_content_lookup (
	CsmgrT_Stat_Table* tbl, 
	const unsigned char* name, 
	uint16_t name_len, 
	int* create_f
) {
	uint32_t hash;
	uint32_t i, n;
	int find_f = 0;
	
	if (create_f) {
		*create_f = 0;
	}
	
	if ((!name_len) || (!tbl)) {
		return (NULL);
	}
	
	hash = csmgrd_stat_hash_number_create (name, name_len);
	i = hash % CsmgrT_Stat_Max;
	
	if (tbl->rcds[i]->hash == hash) {
		if ((tbl->rcds[i]->name_len == name_len) && 
			(memcmp (tbl->rcds[i]->name, name, name_len) == 0)) {
			return (tbl->rcds[i]);
		}
	}
	
	if (tbl->rcds[i]->name_len == 0 || tbl->rcds[i]->name_len == 0xFFFF) {
		memset (tbl->rcds[i], 0, sizeof (CsmgrT_Stat));
		tbl->rcds[i]->hash 		= hash;
		tbl->rcds[i]->index 	= (uint16_t) i;
		tbl->rcds[i]->name_len 	= name_len;
		memcpy (tbl->rcds[i]->name, name, name_len);
		
		if (create_f) {
			*create_f = 1;
		}
		return (tbl->rcds[i]);
	}
	
	for (n = i + 1 ; n < CsmgrT_Stat_Max ; n++) {
		if (tbl->rcds[i]->name_len == 0) {
			find_f = 1;
			break;
		}
		if ((tbl->rcds[n]->name_len == name_len) && 
			(memcmp (tbl->rcds[n]->name, name, name_len) == 0)) {
			return (tbl->rcds[n]);
		}
	}
	if (find_f == 0) {
		for (n = 0 ; n < i ; n++) {
			if (tbl->rcds[i]->name_len == 0) {
				find_f = 1;
				break;
			}
			if ((tbl->rcds[n]->name_len == name_len) && 
				(memcmp (tbl->rcds[n]->name, name, name_len) == 0)) {
				return (tbl->rcds[n]);
			}
		}
	}
	
	if (find_f == 1) {
		memset (tbl->rcds[n], 0, sizeof (CsmgrT_Stat));
		tbl->rcds[n]->hash 		= hash;
		tbl->rcds[n]->name_len 	= name_len;
		memcpy (tbl->rcds[n]->name, name, name_len);
		
		if (create_f) {
			*create_f = 1;
		}
		return (tbl->rcds[n]);
	}
	
	return (NULL);
}

static CsmgrT_Stat* 
csmgrd_stat_content_search (
	CsmgrT_Stat_Table* tbl, 
	const unsigned char* name, 
	uint16_t name_len
) {
	uint32_t hash;
	uint32_t i, n;
	
	if ((!name_len) || (!tbl)) {
		return (NULL);
	}
	
	hash = csmgrd_stat_hash_number_create (name, name_len);
	i = hash % CsmgrT_Stat_Max;
	
	if (tbl->rcds[i]->hash == hash) {
		if ((tbl->rcds[i]->name_len == name_len) && 
			(memcmp (tbl->rcds[i]->name, name, name_len) == 0)) {
			return (tbl->rcds[i]);
		}
	}
	for (n = i + 1 ; n < CsmgrT_Stat_Max ; n++) {
		if (tbl->rcds[n]->name_len == 0) {
			return (NULL);
		}
		
		if ((tbl->rcds[n]->name_len == name_len) && 
			(memcmp (tbl->rcds[n]->name, name, name_len) == 0)) {
			return (tbl->rcds[n]);
		}
	}
	for (n = 0 ; n < i ; n++) {
		if (tbl->rcds[n]->name_len == 0) {
			return (NULL);
		}
		
		if ((tbl->rcds[n]->name_len == name_len) && 
			(memcmp (tbl->rcds[n]->name, name, name_len) == 0)) {
			return (tbl->rcds[n]);
		}
	}
	
	return (NULL);
}

static CsmgrT_Stat* 
csmgrd_stat_content_salvage (
	CsmgrT_Stat_Table* tbl, 
	const unsigned char* name, 
	uint16_t name_len, 
	int* start_index
) {
	int i;
	
	if ((!tbl) ||
		((name_len > 0) && (!name))){
		return (NULL);
	}
	
	for (i = *start_index ; i < CsmgrT_Stat_Max ; i++) {
		if (tbl->rcds[i]->hash) {
			if ((name_len == 0) || 
				(memcmp (tbl->rcds[i]->name, name, name_len) == 0)) {
				*start_index = i + 1;
				return (tbl->rcds[i]);
			}
		}
	}
	
	return (NULL);
}

static uint32_t
csmgrd_stat_hash_number_create (
	const unsigned char* key, 
	uint16_t klen
) {
	unsigned char out[MD5_DIGEST_LENGTH];
	uint32_t hash;
	
	MD5 (key, klen, out);
	memcpy (&hash, &out[12], sizeof (uint32_t));
	
	return (hash);
}


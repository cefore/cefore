/*
 * Copyright (c) 2016-2020, National Institute of Information and Communications
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
	uint32_t			cached_cob_num;
	CsmgrT_Stat** 		rcds;

} CsmgrT_Stat_Table;

/****************************************************************************************
 State Variables
 ****************************************************************************************/


/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

static CsmgrT_Stat* 
csmgr_stat_content_lookup (
	CsmgrT_Stat_Table* tbl, 
	const unsigned char* name, 
	uint16_t name_len, 
	int* create_f
);
static CsmgrT_Stat* 
csmgr_stat_content_search (
	CsmgrT_Stat_Table* tbl, 
	const unsigned char* name, 
	uint16_t name_len
);
static CsmgrT_Stat* 
csmgr_stat_content_salvage (
	CsmgrT_Stat_Table* tbl, 
	const unsigned char* name, 
	uint16_t name_len, 
	int first_f,
	int* start_index
);
static uint32_t
csmgr_stat_hash_number_create (
	const unsigned char* key, 
	uint16_t klen
);

/****************************************************************************************
 ****************************************************************************************/
static int				stat_index_mngr[CsmgrT_Stat_Max];

/*--------------------------------------------------------------------------------------
	Creates the Csmgr Stat Handle
----------------------------------------------------------------------------------------*/
CsmgrT_Stat_Handle 
csmgr_stat_handle_create (
	void 
) {
	CsmgrT_Stat_Table* tbl;

	tbl = (CsmgrT_Stat_Table*) malloc (sizeof (CsmgrT_Stat_Table));
	if (tbl == NULL) {
		return (CsmgrC_Invalid);
	}
	memset (tbl, 0, sizeof (CsmgrT_Stat_Table));
	
	tbl->rcds = (CsmgrT_Stat**) malloc (sizeof (CsmgrT_Stat*) * CsmgrT_Stat_Max);
	memset (tbl->rcds, 0, sizeof (CsmgrT_Stat*) * CsmgrT_Stat_Max);
	
	memset (stat_index_mngr, 0, sizeof(int)*CsmgrT_Stat_Max);

	return ((CsmgrT_Stat_Handle) tbl);
}

/*--------------------------------------------------------------------------------------
	Destroy the Csmgr Stat Handle
----------------------------------------------------------------------------------------*/
void 
csmgr_stat_handle_destroy (
	CsmgrT_Stat_Handle hdl
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	int i;

	if (tbl == NULL) {
		return;
	}
	for (i = 0 ; i < CsmgrT_Stat_Max ; i++) {
		CsmgrT_Stat* cp;
		CsmgrT_Stat* wcp;
		cp = tbl->rcds[i];
		while (cp != NULL) {
			wcp = cp->next;
		   	stat_index_mngr[cp->index] = 0;
			free(cp);
			cp = wcp;
		}
	}
	free (tbl->rcds);
	free (tbl);

	return;
}
/*--------------------------------------------------------------------------------------
	Access the content information
----------------------------------------------------------------------------------------*/
CsmgrT_Stat* 
csmgr_stat_content_info_access (
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
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;
	
	rcd = csmgr_stat_content_search (tbl, name, name_len);
	
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
csmgr_stat_content_info_get (
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
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;
	
	rcd = csmgr_stat_content_search (tbl, name, name_len);
	
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
csmgr_stat_content_info_gets (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len, 
	int partial_match_f, 
	CsmgrT_Stat* ret[]
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
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;
	
	if (!partial_match_f) {
		if (!name_len) {
			return (0);
		}
		
		rcd = csmgr_stat_content_search (tbl, name, name_len);
		
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
	int first_f = 1;
	do {
		rcd = csmgr_stat_content_salvage (tbl, name, name_len, first_f, &index);
		if (first_f == 1) {
			first_f = 0;
		}
		
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
csmgr_stat_expired_content_info_get (
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
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;
	
	for (i = *index ; i < CsmgrT_Stat_Max ; i++) {
		CsmgrT_Stat* cp;
		cp = tbl->rcds[i];
		while (cp != NULL) {
			if (nowt > cp->expiry) {
				if (cp->next == NULL) {
					*index += 1;
				}
				cp->expire_f = 1;
				return (cp);
			}
			cp = cp->next;
		}
	}	
	
	return (NULL);
}
/*--------------------------------------------------------------------------------------
	Update cached Cob status
----------------------------------------------------------------------------------------*/
void 
csmgr_stat_cob_update (
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
	
	rcd = csmgr_stat_content_lookup (tbl, name, name_len, &create_f);
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
		tbl->cached_cob_num++;
	}
	rcd->cob_map[x] |= mask;
	
	return;
}
/*--------------------------------------------------------------------------------------
	Remove the specified cached Cob status
----------------------------------------------------------------------------------------*/
int 
csmgr_stat_cob_remove (
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
	
	if ((!tbl) || (seq > CsmgrT_Stat_Seq_Max)) {
		return (-1);
	}
	
	rcd = csmgr_stat_content_search (tbl, name, name_len);
	if (!rcd) {
		return (-1);
	}
	
	x = seq / 64;
	mask <<= (seq % 64);
	
	if (rcd->cob_map[x] & mask) {
		rcd->cob_num--;
		rcd->con_size -= cob_size;
		tbl->cached_cob_num--;
	}
	rcd->cob_map[x] &= ~mask;
	
	if (rcd->cob_num == 0) {
		csmgr_stat_content_info_delete (hdl, name, name_len);
		return (0);
	}
	
	return (-1);
}
/*--------------------------------------------------------------------------------------
	Update access count
----------------------------------------------------------------------------------------*/
void 
csmgr_stat_access_count_update (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	CsmgrT_Stat* rcd;
	
	if (!tbl) {
		return;
	}
	
	rcd = csmgr_stat_content_search (tbl, name, name_len);
	if (!rcd) {
		return;
	}
	if(rcd->access < UINT32_MAX){
		rcd->access++;
	}
	
	return;
}

/*--------------------------------------------------------------------------------------
	Update cache capacity
----------------------------------------------------------------------------------------*/
void 
csmgr_stat_cache_capacity_update (
	CsmgrT_Stat_Handle hdl, 
	uint32_t capacity
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	int i;
	
	if (!tbl) {
		return;
	}

	for (i = 0 ; i < CsmgrT_Stat_Max ; i++) {
		CsmgrT_Stat* cp;
		CsmgrT_Stat* wcp;
		cp = tbl->rcds[i];
		while (cp != NULL) {
			wcp = cp->next;
		   	stat_index_mngr[cp->index] = 0;
			free(cp);
			cp = wcp;
		}
	}
	for (i = 0 ; i < CsmgrT_Stat_Max ; i++) {
		tbl->rcds[i] = NULL;
	}

	tbl->cached_con_num = 0;
	tbl->capacity = capacity;
	tbl->cached_cob_num = 0;
	
	return;
}

/*--------------------------------------------------------------------------------------
	Update content expire time
----------------------------------------------------------------------------------------*/
void 
csmgr_stat_content_lifetime_update (
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
	rcd = csmgr_stat_content_search (tbl, name, name_len);
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
csmgr_stat_content_info_init (
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
	
	rcd = csmgr_stat_content_lookup (tbl, name, name_len, &create_f);
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
csmgr_stat_content_info_delete (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	CsmgrT_Stat* cp;
	CsmgrT_Stat* wcp;
	uint32_t hash;
	uint32_t index;
	
	if (!tbl) {
		return;
	}
	
	hash = csmgr_stat_hash_number_create (name, name_len);
	index = hash % CsmgrT_Stat_Max;
	
	cp = tbl->rcds[index];
	if(cp == NULL){
		return;
	}
	if (cp != NULL) {
		if((cp->name_len == name_len) &&
		   (memcmp (cp->name, name, name_len) == 0)){
		   	tbl->rcds[index] = cp->next;
			tbl->cached_con_num--;
		   	stat_index_mngr[cp->index] = 0;
		   	free(cp);
		   	return;
		} else {
			cp = tbl->rcds[index];
			for (; cp->next != NULL; cp = cp->next) {
				if((cp->next->name_len == name_len) &&
				   (memcmp (cp->next->name, name, name_len) == 0)){
				   	wcp = cp->next;
				   	cp->next = cp->next->next;
					tbl->cached_con_num--;
				   	stat_index_mngr[wcp->index] = 0;
				   	free(wcp);
				   	return;
				}
			}
		}
	}

	return;
}
/*--------------------------------------------------------------------------------------
	Obtains the number of cached content
----------------------------------------------------------------------------------------*/
uint16_t 
csmgr_stat_cached_con_num_get (
	CsmgrT_Stat_Handle hdl
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	
	if (!tbl) {
		return (0);
	}
	return (tbl->cached_con_num);
}
/*--------------------------------------------------------------------------------------
	Obtains the number of cached cob
----------------------------------------------------------------------------------------*/
uint32_t 
csmgr_stat_cached_cob_num_get (
	CsmgrT_Stat_Handle hdl
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	
	if (!tbl) {
		return (0);
	}
	return (tbl->cached_cob_num);
}

/*--------------------------------------------------------------------------------------
	Obtains the Cache capacity
----------------------------------------------------------------------------------------*/
uint32_t 
csmgr_stat_cache_capacity_get (
	CsmgrT_Stat_Handle hdl
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	
	if (!tbl) {
		return (0);
	}
	return (tbl->capacity);
}
/*--------------------------------------------------------------------------------------
	Obtain the content information for publisher
----------------------------------------------------------------------------------------*/
CsmgrT_Stat* 
csmgr_stat_content_info_get_for_pub (
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
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;
	
	rcd = csmgr_stat_content_search (tbl, name, name_len);
	
	if (rcd) {
		if ((rcd->cob_num == 0) || (nowt > rcd->expiry)){
			rcd->expire_f = 1;
			return (NULL);
		}
	}
	
	return (rcd);
}
/*--------------------------------------------------------------------------------------
	Obtain the content information for publisher
----------------------------------------------------------------------------------------*/
int 
csmgr_stat_content_info_gets_for_pub (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len, 
	int partial_match_f, 
	CsmgrT_Stat* ret[]
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	CsmgrT_Stat* rcd = NULL;
	
	int index = 0;
	int num = 0;
	uint64_t nowt;
	struct timeval tv;
	
	if (!tbl) {
		return (0);
	}
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;
	
	if (!partial_match_f) {
		if (!name_len) {
			return (0);
		}
		
		rcd = csmgr_stat_content_search (tbl, name, name_len);
		
		if (!rcd) {
			return (0);
		}
		
		if ((rcd->cob_num == 0) || (nowt > rcd->expiry)){
			rcd->expire_f = 1;
			return (0);
		}
		
		ret[0] = rcd;
		
		return (1);
	}
	int first_f = 1;
	do {
		rcd = csmgr_stat_content_salvage (tbl, name, name_len, first_f, &index);
		if (first_f == 1) {
			first_f = 0;
		}
		
		if (!rcd) {
			break;
		}
		
		if ((rcd->cob_num == 0) || (nowt > rcd->expiry)){
			rcd->expire_f = 1;
			continue;
		}
		
		ret[num] = rcd;
		num++;
		
	} while (rcd);
	
	return (num);
}
/*--------------------------------------------------------------------------------------
	Update cached Cob status for publisher
----------------------------------------------------------------------------------------*/
void 
csmgr_stat_cob_update_for_pub (
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
	int create_f = 0;
	
	rcd = csmgr_stat_content_lookup (tbl, name, name_len, &create_f);
	if (!rcd) {
		return;
	}
	if (create_f) {
		tbl->cached_con_num++;
	}
	
	if (rcd->cob_num < 1) {
		rcd->expiry 		= expiry;
		rcd->cached_time 	= cached_time;
		rcd->node 			= node;
	}
	rcd->cob_num++;
	rcd->con_size += cob_size;
	tbl->cached_cob_num++;
	if (rcd->min_seq > seq) {
	 	rcd->min_seq = seq;
	}
	if (rcd->max_seq < seq) {
	 	rcd->max_seq = seq;
	}
	
	return;
}
/*--------------------------------------------------------------------------------------
	Remove the specified cached Cob status for publisher
----------------------------------------------------------------------------------------*/
int 
csmgr_stat_cob_remove_for_pub (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len, 
	uint32_t seq, 
	uint32_t cob_size
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	CsmgrT_Stat* rcd;
	
	rcd = csmgr_stat_content_search (tbl, name, name_len);
	if (!rcd) {
		return (-1);
	}
	
	rcd->cob_num--;
	rcd->con_size -= cob_size;
	tbl->cached_cob_num--;
	if (rcd->cob_num == 0) {
		csmgr_stat_content_info_delete (hdl, name, name_len);
		return (0);
	}
	
	return (-1);
}

/****************************************************************************************
 ****************************************************************************************/

static CsmgrT_Stat* 
csmgr_stat_content_lookup (
	CsmgrT_Stat_Table* tbl, 
	const unsigned char* name, 
	uint16_t name_len, 
	int* create_f
) {
	uint32_t hash;
	uint32_t index;
	CsmgrT_Stat* rcd;
	
	if (create_f) {
		*create_f = 0;
	}
	
	if ((!name_len) || (!tbl)) {
		return (NULL);
	}
	
	rcd = csmgr_stat_content_search (tbl, name, name_len);
	if (rcd) {
		return (rcd);
	}
	/* Create Content */
	if (tbl->cached_con_num == CsmgrT_Stat_Max){
		return (NULL);
	}
	hash = csmgr_stat_hash_number_create (name, name_len);
	index = hash % CsmgrT_Stat_Max;
	CsmgrT_Stat* cp;
	CsmgrT_Stat* wcp;
	if(tbl->rcds[index] == NULL){
		tbl->rcds[index] = (CsmgrT_Stat* )calloc(1, sizeof(CsmgrT_Stat) + name_len);
		tbl->rcds[index]->name = ((unsigned char*)tbl->rcds[index]) + sizeof(CsmgrT_Stat);
		cp = tbl->rcds[index];
		cp->name_len = name_len;
		memcpy (cp->name, name, name_len);
		cp->min_seq = UINT_MAX;
		cp->max_seq = 0;
		for(int i=0; i<CsmgrT_Stat_Max; i++){
			if(stat_index_mngr[i] == 0){
				stat_index_mngr[i] = 1;
				cp->index = i;
				break;
			}
		}
		if (create_f) {
			*create_f = 1;
		}
		return (cp);
	} else {
		/* insert */
		wcp = tbl->rcds[index];
		tbl->rcds[index] = (CsmgrT_Stat* )calloc(1, sizeof(CsmgrT_Stat) + name_len);
		if (tbl->rcds[index] == NULL) {
			return (NULL);
		}
		tbl->rcds[index]->name = ((unsigned char*)tbl->rcds[index]) + sizeof(CsmgrT_Stat);
		cp = tbl->rcds[index];
		cp->next = wcp;
		cp->name_len = name_len;
		memcpy (cp->name, name, name_len);
		cp->min_seq = UINT_MAX;
		cp->max_seq = 0;
		for(int i=0; i<CsmgrT_Stat_Max; i++){
			if(stat_index_mngr[i] == 0){
				stat_index_mngr[i] = 1;
				cp->index = i;
				break;
			}
		}
		if (create_f) {
			*create_f = 1;
		}
		return (cp);
	}

	return (NULL);
}

static CsmgrT_Stat* 
csmgr_stat_content_search (
	CsmgrT_Stat_Table* tbl, 
	const unsigned char* name, 
	uint16_t name_len
) {
	uint32_t hash;
	uint32_t i;
	CsmgrT_Stat* cp;
	
	if ((!name_len) || (!tbl)) {
		return (NULL);
	}
	
	hash = csmgr_stat_hash_number_create (name, name_len);
	i = hash % CsmgrT_Stat_Max;
	
	hash = csmgr_stat_hash_number_create (name, name_len);
	i = hash % CsmgrT_Stat_Max;

	cp = tbl->rcds[i];
	while (cp != NULL) {
		if((cp->name_len == name_len) &&
		   (memcmp (cp->name, name, name_len) == 0)){
			return (cp);
		}
		cp = cp->next;
	}
	
	return (NULL);
}

static CsmgrT_Stat* 
csmgr_stat_content_salvage (
	CsmgrT_Stat_Table* tbl, 
	const unsigned char* name, 
	uint16_t name_len, 
	int first_f,
	int* start_index
) {
	int i;
	static CsmgrT_Stat* procedp;
	
	if ((!tbl) ||
		((name_len > 0) && (!name))){
		return (NULL);
	}
	
	if (first_f == 1) {
		procedp = NULL;
	}
	for (i = *start_index ; i < CsmgrT_Stat_Max ; i++) {
		CsmgrT_Stat* cp;
		cp = tbl->rcds[i];
		while (cp != NULL) {
			if (procedp == cp) { 
				cp = cp->next;
				continue; //+++++ 201910xx YJK +++++
			} else {
				if ((name_len == 0) || 
					(memcmp (cp->name, name, name_len) == 0)) {
					procedp = cp;	
					if (cp->next == NULL) {
						*start_index = i + 1;
					} else {
						*start_index = i;
					}
					return (cp);
				}
			}
			cp = cp->next;
		}
	}

	return (NULL);
}

static uint32_t
csmgr_stat_hash_number_create (
	const unsigned char* key, 
	uint16_t klen
) {
	unsigned char out[MD5_DIGEST_LENGTH];
	uint32_t hash;
	
	MD5 (key, klen, out);
	memcpy (&hash, &out[12], sizeof (uint32_t));
	
	return (hash);
}


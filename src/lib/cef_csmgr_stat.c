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
 * cef_csmgr_stat.c
 */

/////#define _CS_COB_NUM //@@@@@@@@@
#ifdef _CS_COB_NUM //@@@@@+++++ Show cached_cob_num status +++++
#include <time.h>
static time_t STIME=0;
static time_t BTIME=0;
#endif //_CS_COB_NUM //@@@@@----- Show cached_cob_num status -----

#define __CEF_CSMGR_STAT_SOURCE__


/****************************************************************************************
 Include Files
 ****************************************************************************************/

#include <openssl/md5.h>

#include <cefore/cef_csmgr_stat.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

#ifndef CefC_MACOS
#define ANA_DEAD_LOCK //@@@@@@@@@@
#ifdef ANA_DEAD_LOCK //@@@@@+++++ ANA DEAD LOCK
static int xpthread_mutex_lock (const char* pname, int pline, pthread_mutex_t *mutex)
{	
	struct timespec to;
	int err;
	to.tv_sec = time(NULL) + 600;
	to.tv_nsec = 0;
	err = pthread_mutex_timedlock(mutex, &to);
	if (err != 0) {
    	fprintf(stderr, "[%s(%d)]: ------ DETECT DEAD LOCK: %s -----\n", pname, pline, strerror(err));
		exit (1);
	}
	return (0);
}
#define pthread_mutex_lock(a) xpthread_mutex_lock(__FUNCTION__, __LINE__, a)
#endif //@@@@@+++++ ANA DEAD LOCK
#endif //CefC_MACOS

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/
#if 0
typedef struct {
	
	uint64_t 			capacity;
	uint32_t			cached_con_num;
	uint64_t			cached_cob_num;
	CsmgrT_Stat** 		rcds;
	pthread_mutex_t 	stat_mutex;

} CsmgrT_Stat_Table;
#endif
/****************************************************************************************
 State Variables
 ****************************************************************************************/
static pthread_mutex_t 		csmgr_stat_mutex;

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
	
	memset (stat_index_mngr, 0, sizeof (int)*CsmgrT_Stat_Max);
	
	/* Init csmgr_stat_mutex for recursive */
    pthread_mutexattr_t attr ;
	if (pthread_mutexattr_init (&attr) < 0) {
		return (CsmgrC_Invalid);
	}
	if (pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE) < 0) {
		return (CsmgrC_Invalid);
	}
	if (pthread_mutex_init (&csmgr_stat_mutex, &attr) < 0) {
		return (CsmgrC_Invalid);
	}
	tbl->stat_mutex = csmgr_stat_mutex;

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
				free (cp->cob_map);
			free (cp);
			cp = wcp;
		}
	}
	free (tbl->rcds);
	free (tbl);

	return;
}
/*--------------------------------------------------------------------------------------
	Check if content information exists
----------------------------------------------------------------------------------------*/
CsmgrT_Stat* 
csmgr_stat_content_info_is_exist (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len,
	CsmgrT_DB_COB_MAP**	cob_map
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	CsmgrT_Stat* rcd = NULL;
	
	if (!tbl) {
		return (NULL);
	}
	pthread_mutex_lock (&tbl->stat_mutex);
	
	rcd = csmgr_stat_content_search (tbl, name, name_len);
	
	pthread_mutex_unlock (&tbl->stat_mutex);
	return (rcd);
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
	
	pthread_mutex_lock (&tbl->stat_mutex);

	rcd = csmgr_stat_content_search (tbl, name, name_len);
	
	if (rcd) {
		if ((rcd->cob_num == 0) || (nowt > rcd->expiry)) {
			rcd->expire_f = 1;
		}
	}
	
	pthread_mutex_unlock (&tbl->stat_mutex);
	return (rcd);
}
/*--------------------------------------------------------------------------------------
	Confirm existence of the content information
----------------------------------------------------------------------------------------*/
CsmgrT_Stat* 
csmgr_stat_content_is_exist (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	CsmgrT_Stat* rcd = NULL;
	
	if (!tbl) {
		return (NULL);
	}
	
	pthread_mutex_lock (&tbl->stat_mutex);
	
	rcd = csmgr_stat_content_search (tbl, name, name_len);
	
	pthread_mutex_unlock (&tbl->stat_mutex);
	
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
	uint32_t max_seq = 0;
	uint32_t i, n;
	uint64_t mask;
	uint64_t nowt;
	struct timeval tv;
	
	if (!tbl) {
		return (NULL);
	}
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;
	
	pthread_mutex_lock (&tbl->stat_mutex);
	rcd = csmgr_stat_content_search (tbl, name, name_len);
	if (rcd) {
		if ((rcd->cob_num == 0) || (nowt > rcd->expiry)) {
			rcd->expire_f = 1;
			pthread_mutex_unlock (&tbl->stat_mutex);
			return (NULL);
		}

		for (i = 0 ; i < rcd->map_max ; i++) {
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
		for (i = rcd->map_max - 1 ; i >= 0 ; i--) {
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
	
	pthread_mutex_unlock (&tbl->stat_mutex);
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
	uint32_t max_seq = 0 /*@@@= CsmgrT_Stat_Seq_Max @@@*/;
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
	
	pthread_mutex_lock (&tbl->stat_mutex);
	if (!partial_match_f) {
		if (!name_len) {
			pthread_mutex_unlock (&tbl->stat_mutex);
			return (0);
		}
		
		rcd = csmgr_stat_content_search (tbl, name, name_len);
		
		if (!rcd) {
			pthread_mutex_unlock (&tbl->stat_mutex);
			return (0);
		}
		
		if ((rcd->cob_num == 0) || (nowt > rcd->expiry)) {
			rcd->expire_f = 1;
			pthread_mutex_unlock (&tbl->stat_mutex);
			return (0);
		}
		for (i = 0 ; i < rcd->map_max ; i++) {
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
		for (i = rcd->map_max - 1 ; i >= 0 ; i--) {
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
		
		pthread_mutex_unlock (&tbl->stat_mutex);
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
		
		if ((rcd->cob_num == 0) || (nowt > rcd->expiry)) {
			rcd->expire_f = 1;
			continue;
		}
		
		for (i = 0 ; i < rcd->map_max ; i++) {
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
		for (i = rcd->map_max - 1 ; i >= 0 ; i--) {
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
	
	pthread_mutex_unlock (&tbl->stat_mutex);
	return (num);
}
/*--------------------------------------------------------------------------------------
	Obtain the content information
----------------------------------------------------------------------------------------*/
int 
csmgr_stat_content_info_gets_for_RM (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len, 
	CsmgrT_Stat* ret[]
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	CsmgrT_Stat* rcd = NULL;
	
	int index = 0;
	int num = 0;
	
	if (!tbl) {
		return (0);
	}
	
	pthread_mutex_lock (&tbl->stat_mutex);
	int first_f = 1;
	do {
		rcd = csmgr_stat_content_salvage (tbl, name, name_len, first_f, &index);
		if (first_f == 1) {
			first_f = 0;
		}
		
		if (!rcd) {
			break;
		}
		
		if (rcd->cob_num == 0) {
			continue;
		}
		
		ret[num] = rcd;
		num++;
		
	} while (rcd);
	
	pthread_mutex_unlock (&tbl->stat_mutex);
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
	
	pthread_mutex_lock (&tbl->stat_mutex);
	for (i = *index ; i < CsmgrT_Stat_Max ; i++) {
		CsmgrT_Stat* cp;
		cp = tbl->rcds[i];
		while (cp != NULL) {
			if (cp->expiry != 0 && nowt > cp->expiry) {
				if (cp->next == NULL) {
					*index += 1;
				}
				cp->expire_f = 1;
				pthread_mutex_unlock (&tbl->stat_mutex);
				return (cp);
			}
			cp = cp->next;
		}
	}	
	pthread_mutex_unlock (&tbl->stat_mutex);
	
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
	uint32_t x;
	int create_f = 0;
	
	if (!tbl) {
		return;
	}
	
	pthread_mutex_lock (&tbl->stat_mutex);
	rcd = csmgr_stat_content_lookup (tbl, name, name_len, &create_f);
	if (!rcd) {
		pthread_mutex_unlock (&tbl->stat_mutex);
		return;
	}
	x = seq / 64;
	mask <<= (seq % 64);

	if ((rcd->map_max-1) < x) {
		char *ptr;
		uint32_t map_bsize;
		map_bsize = x / CsmgrT_Add_Maps;
		if (x % CsmgrT_Add_Maps != 0) {
			map_bsize ++;
		}
		map_bsize = CsmgrT_Add_Maps + map_bsize * CsmgrT_Add_Maps;
		ptr = calloc (1, sizeof (uint64_t) * map_bsize);
		if (ptr == NULL) {
			pthread_mutex_unlock (&tbl->stat_mutex);
			return;
		}
		memcpy (ptr, rcd->cob_map, sizeof (uint64_t) * rcd->map_max);
		free (rcd->cob_map);
		rcd->cob_map = (uint64_t *) ptr;
		rcd->map_max = map_bsize;
	}

	if (create_f) {
		tbl->cached_con_num++;
	}
	/* Record cob_size for FILE/DB */
	if (rcd->cob_size == 0) {
		rcd->cob_size = cob_size;
		rcd->last_cob_size = cob_size;
		rcd->last_chnk_num = seq;
	}
	if (rcd->cob_size > cob_size) {
		rcd->last_cob_size = cob_size;
		rcd->last_chnk_num = seq;
	} else {
		if (rcd->cob_size < cob_size) {
		rcd->cob_size = cob_size;
		}
	}
	if (rcd->last_chnk_num < seq) {
		rcd->last_chnk_num = seq;
	}
	
	if (rcd->cob_num < 1) {
		rcd->node 			= node;
		rcd->cached_time	= cached_time;
#ifdef _CS_COB_NUM //@@@@@+++++ Show cached_cob_num status +++++
{
	time_t t = time (NULL);
	if(STIME==0){
	STIME=t;
	}
	BTIME=t;
}	
#endif //CS_COB_NUM //@@@@@----- Show cached_cob_num status -----
	}
	if (rcd->expiry < expiry) {
		rcd->expiry = expiry;
	}
	
	if (!(rcd->cob_map[x] & mask)) {
		rcd->cob_num++;
		rcd->con_size += cob_size;
		tbl->cached_cob_num++;
	}
	rcd->cob_map[x] |= mask;
	
#ifdef _CS_COB_NUM //@@@@@+++++ Show cached_cob_num status +++++
{
	if (tbl->cached_cob_num % 1000000 == 0) {
		time_t t = time (NULL);
		fprintf (stderr, "%ld	%ld	"FMTU64"\n", t-STIME, t-BTIME, tbl->cached_cob_num);
		BTIME=t;
	}
}	
#endif //CS_COB_NUM //@@@@@----- Show cached_cob_num status -----
	
	pthread_mutex_unlock (&tbl->stat_mutex);
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
	uint32_t x;
	
	
	pthread_mutex_lock (&tbl->stat_mutex);
	rcd = csmgr_stat_content_search (tbl, name, name_len);
	if (!rcd) {
		pthread_mutex_unlock (&tbl->stat_mutex);
		return (-1);
	}
	
	x = seq / 64;
	mask <<= (seq % 64);

	if (cob_size == 0) {
		if (seq == rcd->last_chnk_num) {
			cob_size = rcd->last_cob_size;
		} else {
			cob_size = rcd->cob_size;
		}
	}
		
	if ((rcd->map_max-1) < x) {
		pthread_mutex_unlock (&tbl->stat_mutex);
		return (-1);
	}
	if (rcd->cob_map[x] & mask) {
		rcd->cob_num--;
		rcd->con_size -= cob_size;
		tbl->cached_cob_num--;
	}
	rcd->cob_map[x] &= ~mask;
	
	if (rcd->cob_num == 0) {
		csmgr_stat_content_info_delete (hdl, name, name_len);
		pthread_mutex_unlock (&tbl->stat_mutex);
		return (0);
	}
	
	pthread_mutex_unlock (&tbl->stat_mutex);
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
	
	pthread_mutex_lock (&tbl->stat_mutex);
	rcd = csmgr_stat_content_search (tbl, name, name_len);
	if (!rcd) {
		pthread_mutex_unlock (&tbl->stat_mutex);
		return;
	}
	if (rcd->access < UINT64_MAX) {
		rcd->access++;
	}
	pthread_mutex_unlock (&tbl->stat_mutex);
	
	return;
}

/*--------------------------------------------------------------------------------------
	Update request count
----------------------------------------------------------------------------------------*/
void 
csmgr_stat_request_count_update (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	CsmgrT_Stat* rcd;
	
	if (!tbl) {
		return;
	}
	
	pthread_mutex_lock (&tbl->stat_mutex);
	rcd = csmgr_stat_content_search (tbl, name, name_len);
	if (!rcd) {
		pthread_mutex_unlock (&tbl->stat_mutex);
		return;
	}
	if (rcd->req_count < UINT64_MAX) {
		rcd->req_count++;
	}
	pthread_mutex_unlock (&tbl->stat_mutex);
	
	return;
}

/*--------------------------------------------------------------------------------------
	Update cache capacity
----------------------------------------------------------------------------------------*/
void 
csmgr_stat_cache_capacity_update (
	CsmgrT_Stat_Handle hdl, 
	uint64_t capacity
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	int i;
	
	if (!tbl) {
		return;
	}

	pthread_mutex_lock (&tbl->stat_mutex);
	for (i = 0 ; i < CsmgrT_Stat_Max ; i++) {
		CsmgrT_Stat* cp;
		CsmgrT_Stat* wcp;
		cp = tbl->rcds[i];
		while (cp != NULL) {
			wcp = cp->next;
		   	stat_index_mngr[cp->index] = 0;
			free (cp->cob_map);
			free (cp);
			cp = wcp;
		}
	}
	for (i = 0 ; i < CsmgrT_Stat_Max ; i++) {
		tbl->rcds[i] = NULL;
	}

	tbl->cached_con_num = 0;
	tbl->capacity = capacity;
	tbl->cached_cob_num = 0;
	pthread_mutex_unlock (&tbl->stat_mutex);
	
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
	pthread_mutex_lock (&tbl->stat_mutex);
	rcd = csmgr_stat_content_search (tbl, name, name_len);
	if (!rcd) {
		pthread_mutex_unlock (&tbl->stat_mutex);
		return;
	}
	rcd->expiry = expiry;
	pthread_mutex_unlock (&tbl->stat_mutex);
	
	return;
}
/*--------------------------------------------------------------------------------------
	Init the valiables of the specified content
----------------------------------------------------------------------------------------*/
CsmgrT_Stat* 
csmgr_stat_content_info_init (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len,
	CsmgrT_DB_COB_MAP**	cob_map
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	CsmgrT_Stat* rcd;
	int create_f = 0;
	
	if (!tbl) {
		return (NULL);
	}
	
	pthread_mutex_lock (&tbl->stat_mutex);
	rcd = csmgr_stat_content_lookup (tbl, name, name_len, &create_f);
	if (!rcd) {
		pthread_mutex_unlock (&tbl->stat_mutex);
		return (NULL);
	}
	
	if (create_f) {
		tbl->cached_con_num++;
	}
	pthread_mutex_unlock (&tbl->stat_mutex);
	
	return (rcd);
}
/*--------------------------------------------------------------------------------------
	Init the valiables of the specified content (for version)
----------------------------------------------------------------------------------------*/
int
csmgr_stat_content_info_version_init (
	CsmgrT_Stat_Handle hdl, 
	CsmgrT_Stat* rcd,
	unsigned char* version, 
	uint16_t ver_len
) {
	CsmgrT_Stat_Table* tbl = (CsmgrT_Stat_Table*) hdl;
	
	pthread_mutex_lock (&tbl->stat_mutex);
	rcd->ver_len = ver_len;
	if (ver_len) {
		rcd->version = (unsigned char*) malloc (ver_len);
		if (rcd->version == NULL) {
			pthread_mutex_unlock (&tbl->stat_mutex);
			return (-1);
		}
		memcpy (rcd->version, version, ver_len);
	} else {
		rcd->version = NULL;
	}
	pthread_mutex_unlock (&tbl->stat_mutex);
	return (1);
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
	
	pthread_mutex_lock (&tbl->stat_mutex);
	hash = csmgr_stat_hash_number_create (name, name_len);
	index = hash % CsmgrT_Stat_Max;
	
	cp = tbl->rcds[index];
	if (cp == NULL) {
		pthread_mutex_unlock (&tbl->stat_mutex);
		return;
	}
	if (cp != NULL) {
		if ((cp->name_len == name_len) &&
			(memcmp (cp->name, name, name_len) == 0)) {
			tbl->rcds[index] = cp->next;
			tbl->cached_con_num--;
			stat_index_mngr[cp->index] = 0;
			free (cp->cob_map);
			if (cp->version != NULL && cp->ver_len > 0) {
				free (cp->version);
			}
			free (cp);
			pthread_mutex_unlock (&tbl->stat_mutex);
			return;
		} else {
			cp = tbl->rcds[index];
			for (; cp->next != NULL; cp = cp->next) {
				if ((cp->next->name_len == name_len) &&
					(memcmp (cp->next->name, name, name_len) == 0)) {
					wcp = cp->next;
					cp->next = cp->next->next;
					tbl->cached_con_num--;
					stat_index_mngr[wcp->index] = 0;
					free (wcp->cob_map);
					if (wcp->version != NULL && wcp->ver_len > 0) {
						free (wcp->version);
					}
					free (wcp);
					pthread_mutex_unlock (&tbl->stat_mutex);
					return;
				}
			}
		}
	}
	pthread_mutex_unlock (&tbl->stat_mutex);

	return;
}
/*--------------------------------------------------------------------------------------
	Obtains the number of cached content
----------------------------------------------------------------------------------------*/
uint32_t 
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
uint64_t 
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
uint64_t 
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
	
	pthread_mutex_lock (&tbl->stat_mutex);
	rcd = csmgr_stat_content_search (tbl, name, name_len);
	
	if (rcd) {
		if ((rcd->cob_num == 0) || (nowt > rcd->expiry)) {
			rcd->expire_f = 1;
			pthread_mutex_unlock (&tbl->stat_mutex);
			return (NULL);
		}
	}
	
	pthread_mutex_unlock (&tbl->stat_mutex);
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
	
	pthread_mutex_lock (&tbl->stat_mutex);
	if (!partial_match_f) {
		if (!name_len) {
			pthread_mutex_unlock (&tbl->stat_mutex);
			return (0);
		}
		
		rcd = csmgr_stat_content_search (tbl, name, name_len);
		
		if (!rcd) {
			pthread_mutex_unlock (&tbl->stat_mutex);
			return (0);
		}
		
		if ((rcd->cob_num == 0) || (nowt > rcd->expiry)) {
			rcd->expire_f = 1;
			pthread_mutex_unlock (&tbl->stat_mutex);
			return (0);
		}
		
		ret[0] = rcd;
		
		pthread_mutex_unlock (&tbl->stat_mutex);
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
		
		if ((rcd->cob_num == 0) || (nowt > rcd->expiry)) {
			rcd->expire_f = 1;
			continue;
		}
		
		ret[num] = rcd;
		num++;
		
	} while (rcd);
	
	pthread_mutex_unlock (&tbl->stat_mutex);
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

	pthread_mutex_lock (&tbl->stat_mutex);
	rcd = csmgr_stat_content_lookup (tbl, name, name_len, &create_f);
	if (!rcd) {
		pthread_mutex_unlock (&tbl->stat_mutex);
		return;
	}
	if (create_f) {
		tbl->cached_con_num++;
	}
	
	if (rcd->cob_num < 1) {
		rcd->cached_time 	= cached_time;
		rcd->node 			= node;
	}
	if (rcd->expiry < expiry) {
		rcd->expiry = expiry;
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
	
	pthread_mutex_unlock (&tbl->stat_mutex);
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
	
	pthread_mutex_lock (&tbl->stat_mutex);
	rcd = csmgr_stat_content_search (tbl, name, name_len);
	if (!rcd) {
		pthread_mutex_unlock (&tbl->stat_mutex);
		return (-1);
	}
	
	rcd->cob_num--;
	rcd->con_size -= cob_size;
	tbl->cached_cob_num--;
	if (rcd->cob_num == 0) {
		csmgr_stat_content_info_delete (hdl, name, name_len);
		pthread_mutex_unlock (&tbl->stat_mutex);
		return (0);
	}
	
	pthread_mutex_unlock (&tbl->stat_mutex);
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
	if (tbl->cached_con_num == CsmgrT_Stat_Max) {
		return (NULL);
	}
	hash = csmgr_stat_hash_number_create (name, name_len);
	index = hash % CsmgrT_Stat_Max;
	CsmgrT_Stat* cp;
	CsmgrT_Stat* wcp;
	if (tbl->rcds[index] == NULL) {
		tbl->rcds[index] = (CsmgrT_Stat* )calloc (1, sizeof (CsmgrT_Stat) + name_len);
		tbl->rcds[index]->name = ((unsigned char*)tbl->rcds[index]) + sizeof (CsmgrT_Stat);
		cp = tbl->rcds[index];
		cp->name_len = name_len;
		memcpy (cp->name, name, name_len);
		cp->min_seq = UINT_MAX;
		cp->max_seq = 0;
		cp->tx_seq = 0;
		cp->tx_num = -1;
		cp->tx_time = 0;
		cp->cob_map = (uint64_t *) calloc (1, sizeof (uint64_t) * CsmgrT_Add_Maps);
		cp->map_max = CsmgrT_Add_Maps;
		for (int i=0; i<CsmgrT_Stat_Max; i++) {
			if (stat_index_mngr[i] == 0) {
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
		tbl->rcds[index] = (CsmgrT_Stat* )calloc (1, sizeof (CsmgrT_Stat) + name_len);
		if (tbl->rcds[index] == NULL) {
			return (NULL);
		}
		tbl->rcds[index]->name = ((unsigned char*)tbl->rcds[index]) + sizeof (CsmgrT_Stat);
		cp = tbl->rcds[index];
		cp->next = wcp;
		cp->name_len = name_len;
		memcpy (cp->name, name, name_len);
		cp->min_seq = UINT_MAX;
		cp->max_seq = 0;
		cp->tx_seq = 0;
		cp->tx_num = -1;
		cp->tx_time = 0;
		cp->cob_map = (uint64_t *) calloc (1, sizeof (uint64_t) * CsmgrT_Add_Maps/*@*/);
		cp->map_max = CsmgrT_Add_Maps;
		for (int i=0; i<CsmgrT_Stat_Max; i++) {
			if (stat_index_mngr[i] == 0) {
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

	cp = tbl->rcds[i];
	while (cp != NULL) {
		if ((cp->name_len == name_len) &&
		   (memcmp (cp->name, name, name_len) == 0)) {
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
	static int procelnum;
	int lnum;
	
	if ((!tbl) ||
		((name_len > 0) && (!name))) {
		return (NULL);
	}
	
	if (first_f == 1) {
		procelnum = -1;
	}
	for (i = *start_index ; i < CsmgrT_Stat_Max ; i++) {
		CsmgrT_Stat* cp;
		cp = tbl->rcds[i];
		lnum = 0;
		while (cp != NULL) {
			if (i == *start_index) {
				if (procelnum != -1) {
					for (int j=0; j<= procelnum; j++) {
						cp = cp->next;
						lnum ++;
					}
					procelnum = -1;
					continue;
				}
			}
			if ((name_len == 0) || 
				(memcmp (cp->name, name, name_len) == 0)) {
				if (cp->next == NULL) {
					procelnum = -1;
					*start_index = i + 1;
				} else {
					procelnum = lnum;
					*start_index = i;
				}
				return (cp);
			}
			lnum ++;
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


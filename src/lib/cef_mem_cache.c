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
 * cef_mem_cache.c
 */

#define __CEF_MEM_CACHE_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>

#include <openssl/md5.h>

#include <cefore/cef_client.h>
#include <cefore/cef_csmgr.h>
#include <cefore/cef_frame.h>
#include <cefore/cef_mem_cache.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/
#define Cef_Mstat_HashTbl_Size				1009

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

/*** listing content entries for FIFO ***/
typedef struct _FifoT_Entry {
	unsigned char* 			key;
	int 					key_len;
    int             		valid;
	struct _FifoT_Entry*	before;
 	struct _FifoT_Entry*	next;
} FifoT_Entry;

/*** content entries for memory cache ***/
typedef struct CefT_Mem_Hash_Cell {
	
	uint32_t 						hash;
	unsigned char* 					key;
	uint32_t 						klen;
	CefMemCacheT_Content_Mem_Entry* 	
								elem;
	struct CefT_Mem_Hash_Cell		*next;
} CefT_Mem_Hash_Cell;

/*** management entries for caching hash table ***/
typedef struct CefT_Mem_Hash {
	CefT_Mem_Hash_Cell**	tbl;
	uint32_t 				tabl_max;
	uint32_t 				elem_max;
	uint32_t 				elem_num;
	
} CefT_Mem_Hash;

typedef struct CefT_Mem_Hash_Stat {
	unsigned char* 				contents_name;		/* Name of Contents					*/
	uint32_t 					cname_len;			/* Length of Name					*/
	uint64_t					contents_size;		/* Total size of ContentObject		*/
	uint64_t					cob_num;			/* Number of ContentObject			*/
	uint64_t					ac_cnt;				/* Access Count of Contents			*/
	struct CefT_Mem_Hash_Stat*	next;
} CefT_Mem_Hash_Stat;

/****************************************************************************************
 State Variables
 ****************************************************************************************/

static int cache_cap = 0;					/* Maximum number of entries that can be 	*/
											/* listed (it is the same value as the 		*/
											/* maximum value of the cache table) 		*/

/* pointers of functions which stores and removes the content entry into/from the cache */
/* table (implementation of the functions are in a plugin which uses this library) 		*/

static int              fifo_hand;          /* position of hand                         */
static int              cache_count;        /* number of cache entries                  */
FifoT_Entry*			cache_entry_head;
FifoT_Entry*			cache_entry_tail;
static CefT_Hash_Handle lookup_table;       /* hash-table to look-up cache entries      */
static int              count;              /* the number of entries in lookup table    */

static CefT_Mem_Hash* 			mem_hash_tbl = NULL;	/* caching hash table			*/
static uint32_t 				mem_tabl_max;			/* max size 					*/
														/* of caching hash table		*/

static pthread_mutex_t 			cef_mem_cs_mutex = PTHREAD_MUTEX_INITIALIZER;

static int	cache_cs_expire_check_stat = 0;

static CefT_Mem_Hash_Stat*		mstat_tbl[Cef_Mstat_HashTbl_Size];

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/
/*--------------------------------------------------------------------------------------
	FIFO Functions
----------------------------------------------------------------------------------------*/
static int
cef_mem_cache_fifo_init (
		uint32_t		capacity
);
static void
cef_mem_cache_fifo_destroy (
	void
);
static void
cef_mem_cache_fifo_insert (
	CefMemCacheT_Content_Entry* entry
);
static void
cef_mem_cache_fifo_erase (
	unsigned char* key,
	int key_len
);
static void cef_mem_cache_fifo_store_entry(
	CefMemCacheT_Content_Entry* entry
);
static void cef_mem_cache_fifo_remove_entry(
	FifoT_Entry*   entry,
	int is_removed
);
static FifoT_Entry* 
cef_mem_cache_fifo_cache_entry_enqueue(unsigned char* key, int key_len);
static void 
cef_mem_cache_fifo_cache_entry_dequeue(FifoT_Entry* p);


/*--------------------------------------------------------------------------------------
	Memory Cache Functions
----------------------------------------------------------------------------------------*/
static int
cef_mem_cache_cs_create (
		uint32_t		capacity
);
static int 
cef_mem_cache_cs_store (
	CefMemCacheT_Content_Entry* new_entry
);
static void
cef_mem_cache_cs_remove (
	unsigned char* key, 
	int key_len
);
static void
cef_mem_cache_cs_destroy (
	void
);
static void
cef_mem_cache_cs_expire_check (
	void
);
static int
cef_mem_cache_cob_write (
	CefMemCacheT_Content_Entry* cob 
);
/*--------------------------------------------------------------------------------------
	Hash Functions
----------------------------------------------------------------------------------------*/
static CefT_Mem_Hash*
cef_mem_hash_tbl_create (
	uint32_t capacity
);
static uint32_t
cef_mem_hash_number_create (
	const unsigned char* key,
	uint32_t klen
);
static int 
cef_mem_cache_hash_tbl_item_set (
	const unsigned char* key,
	uint32_t klen,
	CefMemCacheT_Content_Mem_Entry* elem, 
	CefMemCacheT_Content_Mem_Entry** old_elem
);
static CefMemCacheT_Content_Mem_Entry* 
cef_mem_cache_hash_tbl_item_get (
	const unsigned char* key,
	uint32_t klen
);
static CefMemCacheT_Content_Mem_Entry* 
cef_mem_cache_hash_tbl_item_remove (
	const unsigned char* key,
	uint32_t klen
);
int
cef_mem_cache_key_create_by_Mem_Entry (
	CefMemCacheT_Content_Mem_Entry* entry,
	unsigned char* key
);
static int
cef_mem_cache_key_create (
	CefMemCacheT_Content_Entry* entry,
	unsigned char* key
);

/*--------------------------------------------------------------------------------------
	MISC. Functions
----------------------------------------------------------------------------------------*/
static int
cef_mem_cache_name_chunknum_concatenate (
	const unsigned char* name,
	uint16_t name_len,
	uint32_t chunknum,
	unsigned char* key
);

/*--------------------------------------------------------------------------------------
	Stat Functions
----------------------------------------------------------------------------------------*/
static void
cef_mem_cache_mstat_init (
	void
);
static void
cef_mem_cache_mstat_destroy (
	void
);
static void
cef_mem_cache_mstat_insert (
	unsigned char* key,
	uint32_t klen,
	uint16_t msg_len
);
static void
cef_mem_cache_mstat_remove (
	unsigned char* key,
	uint32_t klen,
	uint16_t msg_len
);
static void
cef_mem_cache_mstat_ac_cnt_inc (
	unsigned char* key,
	uint32_t klen
);
#if 0
static void
cef_mem_cache_mstat_print (
	char* msg
);
#endif

/****************************************************************************************
	Functions
 ****************************************************************************************/
/************************
	API for cef_csmgr
 ***********************/
/*--------------------------------------------------------------------------------------
	Intialize memory cache environment
----------------------------------------------------------------------------------------*/
int
cef_mem_cache_init(
		uint32_t		capacity
){
	int rtc;
	
	rtc = cef_mem_cache_cs_create (capacity);
	cef_mem_cache_mstat_init ();
	
	return rtc;
}
/*--------------------------------------------------------------------------------------
	A thread that puts a content object in the memory cache
----------------------------------------------------------------------------------------*/
void *
cef_mem_cache_put_thread (
	void *p
){
	int 						read_fd;
	CefMemCacheT_Content_Entry	entry;	
	struct pollfd 				fds[1];
	unsigned char				msg[CefC_Max_Length];
	int							msg_len;
	struct fixed_hdr* 			chp;
	uint16_t					pkt_len;
	uint16_t					hdr_len;
	uint16_t					payload_len;
	uint16_t					header_len;
	CefT_Parsed_Message 		pm;
	CefT_Parsed_Opheader 		poh;
	int							res;
	int 						chunk_field_len;

	read_fd = *(int *)p;

	pthread_t self_thread = pthread_self();
	pthread_detach(self_thread);
	
	memset(&fds, 0, sizeof(fds));
	fds[0].fd = read_fd;
	fds[0].events = POLLIN | POLLERR;

	while (1){
	    poll(fds, 1, 1);
	    if (fds[0].revents & POLLIN) {
	    	
			if((msg_len = read(read_fd, msg, sizeof(msg))) < 1){
				continue;
			}
			chp = (struct fixed_hdr*) msg;
			pkt_len = ntohs (chp->pkt_len);
			hdr_len = chp->hdr_len;
			payload_len = pkt_len - hdr_len;
			header_len 	= hdr_len;
			res = cef_frame_message_parse (
							msg, payload_len, header_len, &poh, &pm, CefC_PT_OBJECT);
			if ( pm.AppComp_num > 0 ) {
				/* Free AppComp */
				cef_frame_app_components_free ( pm.AppComp_num, pm.AppComp );
			}

			if (res < 0) {
				continue;
			}
			chunk_field_len = CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum;
			memcpy (entry.msg, msg, msg_len);
			entry.msg_len = msg_len;
			if (pm.chnk_num_f) {
				memcpy (entry.name, pm.name, pm.name_len - chunk_field_len);
				entry.name_len = pm.name_len - chunk_field_len;
			} else {
				continue;
			}
			entry.pay_len = pm.payload_len;
			entry.chnk_num = pm.chnk_num;
			entry.cache_time = poh.cachetime;
			entry.expiry = pm.expiry;
			/* entry.node does not care */
			cef_mem_cache_item_set (&entry);
	    }
	}

	pthread_exit (NULL);
	return 0;
}
/*--------------------------------------------------------------------------------------
	Thread to clear expirly content object of memory cache
----------------------------------------------------------------------------------------*/
void *
cef_mem_cache_clear_thread (
	void *p
){
	uint32_t local_cache_interval;
	uint64_t interval;
	uint64_t nowt;
	uint64_t expire_check_time;

	local_cache_interval = *(uint32_t*)p;

	pthread_t self_thread = pthread_self();
	pthread_detach(self_thread);

	interval = (uint64_t) local_cache_interval * 1000000llu;
	nowt = cef_client_present_timeus_calc ();
	expire_check_time = nowt + interval;
	
	while (1) {
		sleep(1);
		nowt = cef_client_present_timeus_calc ();
		/* Checks content expire 			*/
		if ((interval != 0) && (nowt > expire_check_time)) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Checks for expired contents.\n");
#endif // CefC_Debug
			if (cache_cs_expire_check_stat == 0){
				cache_cs_expire_check_stat = 1;
				cef_mem_cache_cs_expire_check ();
				cache_cs_expire_check_stat = 0;
			}
			/* set interval */
			expire_check_time = nowt + interval;
		}
	}

	pthread_exit (NULL);
	return 0;
}
/*--------------------------------------------------------------------------------------
	Thread to clear expirly content object of memory cache by demand
----------------------------------------------------------------------------------------*/
void *
cef_mem_cache_clear_demand_thread (
	void *p
){
	pthread_t self_thread = pthread_self();
	pthread_detach(self_thread);

	if (cache_cs_expire_check_stat == 0){
		cache_cs_expire_check_stat = 1;
		cef_mem_cache_cs_expire_check ();
		cache_cs_expire_check_stat = 0;
	}

	pthread_exit (NULL);
	return 0;
}
/*--------------------------------------------------------------------------------------
	set the cob to memry cache 
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_mem_cache_item_set (
	CefMemCacheT_Content_Entry* entry
) {
	pthread_mutex_lock (&cef_mem_cs_mutex);
	cef_mem_cache_cob_write (entry);
	pthread_mutex_unlock (&cef_mem_cs_mutex);
	return (0);
}
/*--------------------------------------------------------------------------------------
	Function to read a ContentObject from memory cache
----------------------------------------------------------------------------------------*/
CefMemCacheT_Content_Mem_Entry*
cef_mem_cache_item_get (
	unsigned char* trg_key,						/* content name							*/
	uint16_t trg_key_len						/* content name Length					*/
) {
	CefMemCacheT_Content_Mem_Entry* entry;
	uint64_t 		nowt;
	struct timeval 	tv;
	
	/* Access the specified entry 	*/
	pthread_mutex_lock (&cef_mem_cs_mutex);
	entry = cef_mem_cache_hash_tbl_item_get (trg_key, trg_key_len);
	
	if (entry) {
		
		gettimeofday (&tv, NULL);
		nowt = tv.tv_sec * 1000000llu + tv.tv_usec;
		
		if (((entry->expiry == 0) || (nowt < entry->expiry)) &&
			(nowt < entry->cache_time)) {
			pthread_mutex_unlock (&cef_mem_cs_mutex);
			cef_mem_cache_mstat_ac_cnt_inc (trg_key, trg_key_len);
			return (entry);
 		}
		else {
			pthread_mutex_unlock (&cef_mem_cs_mutex);
			{
				pthread_t th;
				if (pthread_create (&th, NULL, cef_mem_cache_clear_demand_thread, NULL) == -1) {
					cef_log_write (CefC_Log_Error, "Failed to create the new thread\n");
				}
			}
			return (0);
		}
	}
	
	pthread_mutex_unlock (&cef_mem_cs_mutex);
	
	return (0);
}
/*--------------------------------------------------------------------------------------
	Destroy memory cache resources
----------------------------------------------------------------------------------------*/
void
cef_mem_cache_destroy (
	void
) {
pthread_mutex_lock (&cef_mem_cs_mutex);
	cef_mem_cache_fifo_destroy ();
	cef_mem_cache_cs_destroy ();
pthread_mutex_unlock (&cef_mem_cs_mutex);
	pthread_mutex_destroy (&cef_mem_cs_mutex);
	
	cef_mem_cache_mstat_destroy ();
}

/****************************************************************************************
	FIFO Functions
 ****************************************************************************************/
/*--------------------------------------------------------------------------------------
	Init API
----------------------------------------------------------------------------------------*/
static int 							/* If the error occurs, this value is a negative value	*/
cef_mem_cache_fifo_init (
		uint32_t		capacity
) {
    fifo_hand = 0;
    cache_count = 0;
	/* Records the capacity of cache		*/
	if (capacity < 1) {
		fprintf (stderr, "[FIFO] Invalid Cacacity\n");
		return (-1);
	}
	cache_cap = capacity;

	/* Initialize FIFO list management unit */
	cache_entry_head = (FifoT_Entry*)NULL;
	cache_entry_tail = (FifoT_Entry*)NULL;
    
    /* Creates lookup table */
    lookup_table = cef_lhash_tbl_create_u32(capacity);
	if(lookup_table == (CefT_Hash_Handle)NULL){
		return (-1);
	}
    count = 0;
   
	return (0);
}

/*--------------------------------------------------------------------------------------
	Destroy API
----------------------------------------------------------------------------------------*/
static void
cef_mem_cache_fifo_destroy (
	void
) {
    fifo_hand = 0;
    cache_count = 0;
	cache_cap 		= 0;
	{
		FifoT_Entry* p;
		FifoT_Entry* np;
		p = cache_entry_head;
		while (p != (FifoT_Entry*)NULL){
			np = p->next;
			free(p);
			p = np;
		}
		cache_entry_head = (FifoT_Entry*)NULL;
		cache_entry_tail = (FifoT_Entry*)NULL;
	}
    cef_lhash_tbl_destroy(lookup_table);
    count = 0;
}

/*--------------------------------------------------------------------------------------
	Insert API
----------------------------------------------------------------------------------------*/
static void
cef_mem_cache_fifo_insert (
	CefMemCacheT_Content_Entry* entry	/* content entry 							*/
) {
    if (cache_count == cache_cap) {
        /* when cache is full, replace entry */
    	cef_mem_cache_fifo_remove_entry(cache_entry_head, 0);
    }
    cef_mem_cache_fifo_store_entry(entry);
}

/*--------------------------------------------------------------------------------------
	Erase API
----------------------------------------------------------------------------------------*/
static void
cef_mem_cache_fifo_erase (
	unsigned char* key, 					/* key of content entry removed from cache 	*/
											/* table									*/
	int key_len								/* length of the key 						*/
) {
	
	FifoT_Entry*	del_entry;
	void* val = cef_lhash_tbl_item_get(lookup_table, key, key_len);
    if (val == NULL) {
        fprintf(stderr, "[FIFO] failed to erace\n");
        return;
    }
	del_entry = (FifoT_Entry*) val;
    cef_mem_cache_fifo_remove_entry(del_entry, 1);
}
/*--------------------------------------------------------------------------------------
	MISC. Functions
----------------------------------------------------------------------------------------*/
static void cef_mem_cache_fifo_store_entry(
	CefMemCacheT_Content_Entry* entry
) {
    unsigned char 	key[CefMemCacheC_Key_Max];
    int 			key_len;
    FifoT_Entry*   	rsentry;
	
    
    key_len = cef_mem_cache_name_chunknum_concatenate (
                    entry->name, entry->name_len, entry->chnk_num, key);
	rsentry = cef_mem_cache_fifo_cache_entry_enqueue(key, key_len);
	if (rsentry == (FifoT_Entry*) NULL){
		return;
	}
    cef_lhash_tbl_item_set(lookup_table, rsentry->key, rsentry->key_len
    	, (void*)rsentry);
    count++;
    cef_mem_cache_cs_store(entry);
    cache_count++;
}
/*-----*/
static void cef_mem_cache_fifo_remove_entry(
	FifoT_Entry*   entry,
    int is_removed
) {
    FifoT_Entry* rsentry;
    rsentry = entry;
    cef_lhash_tbl_item_remove(lookup_table, rsentry->key, rsentry->key_len);
    count--;

    if (!is_removed) cef_mem_cache_cs_remove(rsentry->key, rsentry->key_len);
	cef_mem_cache_fifo_cache_entry_dequeue(rsentry);

	cache_count--;
	
}
static FifoT_Entry* 
cef_mem_cache_fifo_cache_entry_enqueue(unsigned char* key, int key_len) {

	FifoT_Entry*	q;
  	q = (FifoT_Entry*) calloc(1, sizeof(FifoT_Entry) + key_len);
	if(q == (FifoT_Entry*) NULL){
		return ((FifoT_Entry*) NULL);
	}
	q->key = ((unsigned char*) q) + sizeof(FifoT_Entry);
	memcpy (q->key, key, key_len);
	q->key_len = key_len;
	if(cache_entry_tail == (FifoT_Entry*)NULL){
		cache_entry_head = q;
		cache_entry_tail = q;
	} else {
		cache_entry_tail->next = q;
		q->before = cache_entry_tail;
		cache_entry_tail = q;
	}
  	return(q);
}

static void 
cef_mem_cache_fifo_cache_entry_dequeue(FifoT_Entry* p){

	 if(p->before == (FifoT_Entry*)NULL && p->next != (FifoT_Entry*)NULL){
	 	cache_entry_head = p->next;
	 	p->next->before = (FifoT_Entry*)NULL;
	 } else 
	 if(p->before == (FifoT_Entry*)NULL && p->next == (FifoT_Entry*)NULL){
	 	cache_entry_head = (FifoT_Entry*)NULL;
	 	cache_entry_tail = (FifoT_Entry*)NULL;
	 } else 
	 if(p->before != (FifoT_Entry*)NULL && p->next != (FifoT_Entry*)NULL){
	    p->before->next = p->next;
	    p->next->before = p->before;
	 } else 
	 if(p->before != (FifoT_Entry*)NULL && p->next == (FifoT_Entry*)NULL){
	    p->before->next = p->next;
	 	cache_entry_tail = p->before;
	 }
	free (p);
}

/****************************************************************************************
	Memory Cache Functions
 ****************************************************************************************/
/*--------------------------------------------------------------------------------------
	Init API
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
cef_mem_cache_cs_create (
		uint32_t		capacity
) {

	/* Creates the memory cache 		*/
	mem_hash_tbl = cef_mem_hash_tbl_create (capacity);
	if (mem_hash_tbl ==  NULL) {
		cef_log_write (CefC_Log_Error, "create mem hash table\n");
		return (-1);
	}
	if (cef_mem_cache_fifo_init (capacity) == -1) {
		cef_log_write (CefC_Log_Error, "create fifo cache\n");
		return (-1);
	}

	cef_log_write (CefC_Log_Info, "Local cache capacity : %u\n", capacity);
	
	return (0);
}
/*--------------------------------------------------------------------------------------
	Store API
----------------------------------------------------------------------------------------*/
static int 
cef_mem_cache_cs_store (
	CefMemCacheT_Content_Entry* new_entry
) {
	CefMemCacheT_Content_Mem_Entry* entry;
	CefMemCacheT_Content_Mem_Entry* old_entry = NULL;
	int key_len;
	unsigned char key[65535];
	
	/* Creates the key 		*/
	key_len = cef_mem_cache_key_create (new_entry, key);

	/* Creates the entry 		*/
	entry = 
		(CefMemCacheT_Content_Mem_Entry*) calloc (1, sizeof (CefMemCacheT_Content_Mem_Entry));
	if (entry == NULL) {
		return (-1);
	}
	entry->msg = 
		(unsigned char*) calloc (1, new_entry->msg_len);
	if (entry->msg == NULL) {
		free (entry);
		return (-1);
	}
	entry->name = 
		(unsigned char*) calloc (1, new_entry->name_len);
	if (entry->name == NULL) {
		free (entry->msg);
		free (entry);
		return (-1);
	}
	
	/* Inserts the cache entry 		*/
	memcpy (entry->msg, new_entry->msg, new_entry->msg_len);
	entry->msg_len		 = new_entry->msg_len;
	memcpy (entry->name, new_entry->name, new_entry->name_len);
	entry->name_len		 = new_entry->name_len;
	entry->pay_len		 = new_entry->pay_len;
	entry->chnk_num		 = new_entry->chnk_num;
	entry->cache_time	 = new_entry->cache_time;
	entry->expiry		 = new_entry->expiry;
	entry->node			 = new_entry->node;
	
	if (cef_mem_cache_hash_tbl_item_set (
		key, key_len, entry, &old_entry) < 0) {
		free (entry->msg);
		free (entry->name);
		free (entry);
		return (-1);
	}
	
	
	if (old_entry) {
		free (old_entry->msg);
		free (old_entry->name);
		free (old_entry);
	}
	
	return (0);
}

/*--------------------------------------------------------------------------------------
	Remove API
----------------------------------------------------------------------------------------*/
static void
cef_mem_cache_cs_remove (
	unsigned char* key, 
	int key_len
) {
	CefMemCacheT_Content_Mem_Entry* entry;
	
	/* Removes the specified entry 	*/
	entry = cef_mem_cache_hash_tbl_item_remove (key, key_len);
	
	if (entry) {
		cef_mem_cache_mstat_remove (key, key_len, entry->pay_len);
		free (entry->msg);
		free (entry->name);
		free (entry);
	}
	
	return;
}

/*--------------------------------------------------------------------------------------
	Destroy content store
----------------------------------------------------------------------------------------*/
static void
cef_mem_cache_cs_destroy (
	void
) {
	int i;
	
	if (mem_hash_tbl) {
		for (i = 0 ; i < mem_hash_tbl->tabl_max ; i++) {
			CefT_Mem_Hash_Cell* cp;
			CefT_Mem_Hash_Cell* wcp;
			cp = mem_hash_tbl->tbl[i];
			while (cp != NULL) {
				wcp = cp->next;
				free (cp->elem);
				free(cp);
				cp = wcp;
			}
		}
		free (mem_hash_tbl->tbl);
		free (mem_hash_tbl);
	}
	
	return;
}

/*--------------------------------------------------------------------------------------
	Check content expire
----------------------------------------------------------------------------------------*/
static void
cef_mem_cache_cs_expire_check (
	void
) {
	CefMemCacheT_Content_Mem_Entry* entry = NULL;
	CefMemCacheT_Content_Mem_Entry* entry1 = NULL;
	uint64_t 	nowt;
	struct timeval tv;
	int n;
	unsigned char trg_key[65535];
	int trg_key_len;
	
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;

	for (n = 0 ; n < mem_hash_tbl->tabl_max ; n++) { 
		pthread_mutex_lock (&cef_mem_cs_mutex);
		if (mem_hash_tbl->tbl[n] == NULL) {
			pthread_mutex_unlock (&cef_mem_cs_mutex);
			continue;
		}
		{
			CefT_Mem_Hash_Cell* cp;
			CefT_Mem_Hash_Cell* wcp;
			cp = mem_hash_tbl->tbl[n];
			for (; cp != NULL; cp = wcp) {
				entry = cp->elem;
				wcp = cp->next;
				if ((entry->cache_time < nowt) ||
					((entry->expiry != 0) && (entry->expiry < nowt))) {
					/* Removes the expiry cache entry 		*/
					trg_key_len = cef_mem_cache_key_create_by_Mem_Entry (entry, trg_key);
					entry1 = cef_mem_cache_hash_tbl_item_remove (trg_key, trg_key_len);
					cef_mem_cache_fifo_erase(trg_key, trg_key_len);
					cef_mem_cache_mstat_remove (trg_key, trg_key_len, entry->pay_len);
					free (entry1->msg);
					free (entry1->name);
					free (entry1);
				}
			}
		}
		pthread_mutex_unlock (&cef_mem_cs_mutex);
	}
	
	return;
}
/*--------------------------------------------------------------------------------------
	write the cobs to memry cache
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
cef_mem_cache_cob_write (
	CefMemCacheT_Content_Entry* cob 
) {
	CefMemCacheT_Content_Mem_Entry* entry;
	unsigned char 	trg_key[CefMemCacheC_Key_Max];
	int 			trg_key_len;
	uint64_t nowt;
	struct timeval tv;
	
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;
	if(cob->expiry < nowt){
		return (0);
	}

	trg_key_len = cef_mem_cache_key_create (cob, trg_key);
	entry = cef_mem_cache_hash_tbl_item_get (trg_key, trg_key_len);
#if 1
	if (entry == NULL) {
		cef_mem_cache_fifo_insert(cob);
		cef_mem_cache_mstat_insert (trg_key, trg_key_len, cob->pay_len);
	}
#else
	/* This code (#else part) enables to overwrite the old cob kept in the Local cache  */
	/* if the new cob with the same name is received.                                   */
	/* This is a tentative solution, because this kind of cached content control should */
	/* be done with the version number of each cob.                                     */
	if (entry != NULL) {
		cef_mem_cache_fifo_erase (trg_key, trg_key_len);
		cef_mem_cache_cs_remove (trg_key, trg_key_len);
	}
	cef_mem_cache_fifo_insert(cob);
	cef_mem_cache_mstat_insert (trg_key, trg_key_len, cob->pay_len);
#endif	
	return (0);
}

/****************************************************************************************
	Hash functions
 ****************************************************************************************/
/*--------------------------------------------------------------------------------------
	Create memory hash table
----------------------------------------------------------------------------------------*/
static CefT_Mem_Hash*
cef_mem_hash_tbl_create (
	uint32_t capacity
) {
	CefT_Mem_Hash* ht = NULL;
	uint64_t table_size;
	int i, n;
	int flag;

	table_size = capacity;
	
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
	
	ht = (CefT_Mem_Hash*) malloc (sizeof (CefT_Mem_Hash));
	if (ht == NULL) {
		return (NULL);
	}
	memset (ht, 0, sizeof (CefT_Mem_Hash));
	
	ht->tbl = (CefT_Mem_Hash_Cell**) malloc (sizeof (CefT_Mem_Hash_Cell*) * table_size);
	
	if (ht->tbl  == NULL) {
		free (ht->tbl);
		free (ht);
		return (NULL);
	}
	memset (ht->tbl, 0, sizeof (CefT_Mem_Hash_Cell*) * table_size);
	
	srand ((unsigned) time (NULL));
	ht->elem_max = table_size;
	ht->tabl_max = table_size;
	mem_tabl_max = ht->tabl_max;
	
	return (ht);
}
/*--------------------------------------------------------------------------------------
	Set item to memory hash table
----------------------------------------------------------------------------------------*/
static int 
cef_mem_cache_hash_tbl_item_set (
	const unsigned char* key,
	uint32_t klen,
	CefMemCacheT_Content_Mem_Entry* elem, 
	CefMemCacheT_Content_Mem_Entry** old_elem
) {
	CefT_Mem_Hash* ht = (CefT_Mem_Hash*) mem_hash_tbl;
	uint32_t hash = 0;
	uint32_t y;
	CefT_Mem_Hash_Cell* cp;
	CefT_Mem_Hash_Cell* wcp;

	*old_elem = NULL;

	hash = cef_mem_hash_number_create (key, klen);
	y = hash % ht->tabl_max;

	if(ht->tbl[y] == NULL){
		ht->tbl[y] = (CefT_Mem_Hash_Cell* )calloc(1, sizeof(CefT_Mem_Hash_Cell) + klen);
		if (ht->tbl[y] == NULL) {
			return (-1);
		}
		ht->tbl[y]->key = ((unsigned char* )ht->tbl[y]) + sizeof(CefT_Mem_Hash_Cell);
		cp = ht->tbl[y];
		cp->elem = elem;
		cp->klen = klen;
		memcpy (cp->key, key, klen);

		ht->elem_num++;
		return (1);
	} else {
		/* exist check & replace */
		for (cp = ht->tbl[y]; cp != NULL; cp = cp->next) {
			if((cp->klen == klen) &&
			   (memcmp (cp->key, key, klen) == 0)){
				*old_elem = cp->elem;
				cp->elem = elem;
				return (1);
		   }
		}
		/* insert */
		wcp = ht->tbl[y];
		ht->tbl[y] = (CefT_Mem_Hash_Cell* )calloc(1, sizeof(CefT_Mem_Hash_Cell) + klen);
		if (ht->tbl[y] == NULL) {
			return (-1);
		}
		ht->tbl[y]->key = ((unsigned char* )ht->tbl[y]) + sizeof(CefT_Mem_Hash_Cell);
		cp = ht->tbl[y];
		cp->next = wcp;
		cp->elem = elem;
		cp->klen = klen;
		memcpy (cp->key, key, klen);
		
		ht->elem_num++;
		return (1);
	}
}
/*--------------------------------------------------------------------------------------
	Get item from memory hash table
----------------------------------------------------------------------------------------*/
static CefMemCacheT_Content_Mem_Entry* 
cef_mem_cache_hash_tbl_item_get (
	const unsigned char* key,
	uint32_t klen
) {
	CefT_Mem_Hash* ht = (CefT_Mem_Hash*) mem_hash_tbl;
	uint32_t hash = 0;
	uint32_t y;
	CefT_Mem_Hash_Cell* cp;

	if ((klen > CefMemCacheC_Key_Max) || (ht == NULL)) {
		return (NULL);
	}
	hash = cef_mem_hash_number_create (key, klen);
	y = hash % ht->tabl_max;

	cp = ht->tbl[y];
	if(cp == NULL){
		return (NULL);
	} 
	for (; cp != NULL; cp = cp->next) {
		if((cp->klen == klen) &&
		   (memcmp (cp->key, key, klen) == 0)){
		   	return (cp->elem);
		}
	}
	
	return (NULL);
}

/*--------------------------------------------------------------------------------------
	Remove item from memory hash table
----------------------------------------------------------------------------------------*/
static CefMemCacheT_Content_Mem_Entry* 
cef_mem_cache_hash_tbl_item_remove (
	const unsigned char* key,
	uint32_t klen
) {
	CefT_Mem_Hash* ht = (CefT_Mem_Hash*) mem_hash_tbl;
	uint32_t hash = 0;
	uint32_t y;
	CefMemCacheT_Content_Mem_Entry* ret_elem;
	CefT_Mem_Hash_Cell* cp;
	CefT_Mem_Hash_Cell* wcp;
	
	if ((klen > CefMemCacheC_Key_Max) || (ht == NULL)) {
		return (NULL);
	}
	
	hash = cef_mem_hash_number_create (key, klen);
	y = hash % ht->tabl_max;
	
	cp = ht->tbl[y];
	if(cp == NULL){
		return (NULL);
	}
	if (cp != NULL) {
		if((cp->klen == klen) &&
		   (memcmp (cp->key, key, klen) == 0)){
		   	ht->tbl[y] = cp->next;
			ht->elem_num--;
		   	ret_elem = cp->elem;
		   	free(cp);
		   	return (ret_elem);
		} else {
			for (; cp->next != NULL; cp = cp->next) {
				if((cp->next->klen == klen) &&
				   (memcmp (cp->next->key, key, klen) == 0)){
				   	wcp = cp->next;
				   	cp->next = cp->next->next;
					ht->elem_num--;
				   	ret_elem = wcp->elem;
		   			free(wcp);
		   			return (ret_elem);
				}
			}
		}
	}
	
	return (NULL);
}

/*--------------------------------------------------------------------------------------
	Create hash number
----------------------------------------------------------------------------------------*/
static uint32_t
cef_mem_hash_number_create (
	const unsigned char* key,
	uint32_t klen
) {
	uint32_t hash;
	unsigned char out[MD5_DIGEST_LENGTH];
	
	MD5 (key, klen, out);
	memcpy (&hash, &out[12], sizeof (uint32_t));
	
	return (hash);
}
/*--------------------------------------------------------------------------------------
	Create hash key
----------------------------------------------------------------------------------------*/
int												/* length of the created key 			*/
cef_mem_cache_key_create_by_Mem_Entry (
	CefMemCacheT_Content_Mem_Entry* entry,
	unsigned char* key
) {
	uint32_t chnk_num;

	memcpy (&key[0], entry->name, entry->name_len);
	key[entry->name_len] 		= 0x00;
	key[entry->name_len + 1] 	= 0x10;
	key[entry->name_len + 2] 	= 0x00;
	key[entry->name_len + 3] 	= 0x04;
	chnk_num = htonl (entry->chnk_num);
	memcpy (&key[entry->name_len + 4], &chnk_num, sizeof (uint32_t));

	return (entry->name_len + 4 + sizeof (uint32_t));
}

/****************************************************************************************
	MISC. Functions
 ****************************************************************************************/
/*--------------------------------------------------------------------------------------
	Concatenates name and chunk number
----------------------------------------------------------------------------------------*/
static int										/* length of the created key 			*/
cef_mem_cache_name_chunknum_concatenate (
	const unsigned char* name,
	uint16_t name_len,
	uint32_t chunknum,
	unsigned char* key
) {
	uint32_t no_chunknum;

	memcpy (&key[0], name, name_len);
	key[name_len] 		= 0x00;
	key[name_len + 1] 	= 0x10;
	key[name_len + 2] 	= 0x00;
	key[name_len + 3] 	= 0x04;
	no_chunknum = htonl (chunknum);
	memcpy (&key[name_len + 4], &no_chunknum, sizeof (uint32_t));

	return (name_len + 4 + sizeof (uint32_t));
}
/*--------------------------------------------------------------------------------------
	Creates tye key from name and chunk number
----------------------------------------------------------------------------------------*/
static int												/* length of the created key 			*/
cef_mem_cache_key_create (
	CefMemCacheT_Content_Entry* entry,
	unsigned char* key
) {
	uint32_t chnk_num;

	memcpy (&key[0], entry->name, entry->name_len);
	key[entry->name_len] 		= 0x00;
	key[entry->name_len + 1] 	= 0x10;
	key[entry->name_len + 2] 	= 0x00;
	key[entry->name_len + 3] 	= 0x04;
	chnk_num = htonl (entry->chnk_num);
	memcpy (&key[entry->name_len + 4], &chnk_num, sizeof (uint32_t));

	return (entry->name_len + 4 + sizeof (uint32_t));
}
/*--------------------------------------------------------------------------------------
	Initialize stat
----------------------------------------------------------------------------------------*/
static void
cef_mem_cache_mstat_init (
	void
) {
	memset (mstat_tbl, 0, sizeof (CefT_Mem_Hash_Stat*) * Cef_Mstat_HashTbl_Size);
	
	return;
}
/*--------------------------------------------------------------------------------------
	Destroy stat
----------------------------------------------------------------------------------------*/
static void
cef_mem_cache_mstat_destroy (
	void
) {
	CefT_Mem_Hash_Stat*		mstat_p;
	CefT_Mem_Hash_Stat*		wk_mstat_p;
	int i;
	
	for (i = 0; i < Cef_Mstat_HashTbl_Size; i++) {
		mstat_p = mstat_tbl[i];
		while (mstat_p != NULL) {
			if (mstat_p->contents_name != NULL)
				free (mstat_p->contents_name);
			wk_mstat_p = mstat_p;
			mstat_p = mstat_p->next;
			free (wk_mstat_p);
		}
	}
	
	return;
}
/*--------------------------------------------------------------------------------------
	Insert stat
----------------------------------------------------------------------------------------*/
static void
cef_mem_cache_mstat_insert (
	unsigned char* key,
	uint32_t klen,
	uint16_t pay_len							/* Length of ContentObject Message		*/
) {
	CefT_Mem_Hash_Stat* mstat_p;
	uint16_t tmp_klen;
	uint32_t seqno;		/* work variable */
	uint32_t hash = 0;
	uint32_t y;
	
	tmp_klen = cef_frame_get_name_without_chunkno (key, klen, &seqno);
	if (tmp_klen == 0) {
		/* This name does not include the chunk number */
		return;
	}
	
	hash = cef_mem_hash_number_create (key, tmp_klen);
	y = hash % Cef_Mstat_HashTbl_Size;
	
	if(mstat_tbl[y] == NULL){
		mstat_tbl[y] = (CefT_Mem_Hash_Stat*)malloc (sizeof (CefT_Mem_Hash_Stat));
		mstat_p = mstat_tbl[y];
	} else {
		/* exist check & update */
		for (mstat_p = mstat_tbl[y]; mstat_p != NULL; mstat_p = mstat_p->next) {
			if (mstat_p->cname_len == tmp_klen &&
				memcmp (mstat_p->contents_name, key, tmp_klen) == 0) {
				mstat_p->contents_size += pay_len;
				mstat_p->cob_num++;
				return;
			}
			if (mstat_p->next == NULL)
				break;
		}
		/* insert */
		mstat_p->next = (CefT_Mem_Hash_Stat*)malloc (sizeof (CefT_Mem_Hash_Stat));
		mstat_p = mstat_p->next;
	}
	mstat_p->cname_len     = tmp_klen;
	mstat_p->contents_name = (unsigned char*)malloc(tmp_klen);
	memcpy (mstat_p->contents_name, key, tmp_klen);
	mstat_p->contents_size = pay_len;
	mstat_p->cob_num       = 1;
	mstat_p->ac_cnt        = 0;
	mstat_p->next          = NULL;
	
	return;
}
/*--------------------------------------------------------------------------------------
	Remove stat
----------------------------------------------------------------------------------------*/
static void
cef_mem_cache_mstat_remove (
	unsigned char* key,
	uint32_t klen,
	uint16_t pay_len							/* Length of ContentObject Payload		*/
) {
	CefT_Mem_Hash_Stat* mstat_p;
	uint16_t tmp_klen;
	uint32_t seqno;		/* work variable */
	uint32_t hash = 0;
	uint32_t y;
	
	tmp_klen = cef_frame_get_name_without_chunkno (key, klen, &seqno);
	if (tmp_klen == 0) {
		/* This name does not include the chunk number */
		return;
	}
	
	hash = cef_mem_hash_number_create (key, tmp_klen);
	y = hash % Cef_Mstat_HashTbl_Size;
	
	mstat_p = mstat_tbl[y];
	while (mstat_p != NULL) {
		if (mstat_p->cname_len == tmp_klen &&
			memcmp (mstat_p->contents_name, key, tmp_klen) == 0) {
			mstat_p->contents_size -= pay_len;
			mstat_p->cob_num--;
			
			if (mstat_p->cob_num == 0) {
				CefT_Mem_Hash_Stat*		wk_mstat_p;
				
				if (mstat_p->contents_name != NULL)
					free (mstat_p->contents_name);
				if (mstat_p != mstat_tbl[y]) {
					wk_mstat_p = mstat_p;
					mstat_p = mstat_p->next;
					free (wk_mstat_p);
				} else {
					free (mstat_p);
					mstat_tbl[y] = NULL;
				}
			}
			return;
		}
		mstat_p = mstat_p->next;
	}
	
	return;
}
/*--------------------------------------------------------------------------------------
	Get stat
----------------------------------------------------------------------------------------*/
int
cef_mem_cache_mstat_get (
	unsigned char* key,
	uint32_t klen,
	CefMemCacheT_Ccninfo* info_p
) {
	CefT_Mem_Hash_Stat* mstat_p;
	uint16_t tmp_klen;
	uint32_t seqno;		/* work variable */
	uint32_t hash = 0;
	uint32_t y;
	
	tmp_klen = cef_frame_get_name_without_chunkno (key, klen, &seqno);
	if (tmp_klen == 0) {
		/* This name does not include the chunk number */
		tmp_klen = klen;
	}
	
	hash = cef_mem_hash_number_create (key, tmp_klen);
	y = hash % Cef_Mstat_HashTbl_Size;
	
	mstat_p = mstat_tbl[y];
	while (mstat_p != NULL) {
		if (mstat_p->cname_len == tmp_klen &&
			memcmp (mstat_p->contents_name, key, tmp_klen) == 0) {
#if 0 //+++++@@@@@ CCNINFO
			info_p->con_size = mstat_p->contents_size;
			info_p->con_num  = mstat_p->cob_num;
			info_p->ac_cnt   = mstat_p->ac_cnt;
#else
			{
				uint32_t con_size;
				if (mstat_p->contents_size / 1024 > UINT32_MAX) {
					con_size = UINT32_MAX;
				} else {
					con_size = (uint32_t)(mstat_p->contents_size / 1024);
				}
				info_p->con_size = con_size;
			}
			if (mstat_p->cob_num > UINT32_MAX) {
				info_p->con_num 	= UINT32_MAX;
			} else {
				info_p->con_num 	= mstat_p->cob_num;
			}
			if (mstat_p->ac_cnt > UINT32_MAX) {
				info_p->ac_cnt 	= UINT32_MAX;
			} else {
				info_p->ac_cnt 	= mstat_p->ac_cnt;
			}
#endif //-----@@@@@ CCNINFO
			
			return (1);
		}
		mstat_p = mstat_p->next;
	}
	
	return (-1);
}
/*--------------------------------------------------------------------------------------
	Increment access count
----------------------------------------------------------------------------------------*/
static void
cef_mem_cache_mstat_ac_cnt_inc (
	unsigned char* key,
	uint32_t klen
) {
	CefT_Mem_Hash_Stat* mstat_p;
	uint16_t tmp_klen;
	uint32_t seqno;		/* work variable */
	uint32_t hash = 0;
	uint32_t y;
	
	tmp_klen = cef_frame_get_name_without_chunkno (key, klen, &seqno);
	
	hash = cef_mem_hash_number_create (key, tmp_klen);
	y = hash % Cef_Mstat_HashTbl_Size;
	
	mstat_p = mstat_tbl[y];
	while (mstat_p != NULL) {
		if (mstat_p->cname_len == tmp_klen &&
			memcmp (mstat_p->contents_name, key, tmp_klen) == 0) {
			mstat_p->ac_cnt++;
			return;
		}
		mstat_p = mstat_p->next;
	}
	
	return;
}
#if 0
/*--------------------------------------------------------------------------------------
	Print stat (for debug)
----------------------------------------------------------------------------------------*/
static void
cef_mem_cache_mstat_print (
	char* msg
) {
	CefT_Mem_Hash_Stat* mstat_p;
	int i = 0;
	int j, k;
	
	if (msg != NULL)
		fprintf(stderr, "%s\n", msg);
	
	for (k = 0; k < Cef_Mstat_HashTbl_Size; k++) {
		mstat_p = mstat_tbl[k];
		while (mstat_p != NULL) {
			fprintf (stderr, "    [%d](Hash=%d)\n", i, k);
			fprintf (stderr, "        Name : ");
			for (j = 0; j < mstat_p->cname_len;j++)
				fprintf (stderr, "%02x ", mstat_p->contents_name[j]);
			fprintf (stderr, "(%d)\n", mstat_p->cname_len);
			fprintf (stderr, "        Size : %d\n", mstat_p->contents_size);
			fprintf (stderr, "        Count: %d\n", mstat_p->cob_num);
			fprintf (stderr, "        AcCnt: %d\n", mstat_p->ac_cnt);
			
			i++;
			mstat_p = mstat_p->next;
		}
	}
	fprintf (stderr, "-------------------------------\n");
	return;
}
#endif

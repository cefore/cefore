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
 * mem_cache.c
 */
#define __CSMGRD_MEM_CACHE_SOURCE__

/*
	mem_cache.c is a primitive memory cache implementation.
*/

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif // HAVE_CONFIG_H

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

#include "mem_cache.h"
#include <cefore/cef_client.h>
#include <cefore/cef_csmgr.h>
#include <cefore/cef_frame.h>
#include <csmgrd/csmgrd_plugin.h>


/****************************************************************************************
 Macros
 ****************************************************************************************/

#ifdef __APPLE__
#define CsmgrdC_Library_Name	".dylib"
#else // __APPLE__
#define CsmgrdC_Library_Name	".so"
#endif // __APPLE__

#define MemC_Max_KLen 				1024
#define MemC_Max_Buff 				4
#define MemC_Min_Buff				4
#define MemC_CID_HexCh_size			(MD5_DIGEST_LENGTH * 2)	/* Size to store binary CID   */
															/* converted to hex character */
#define MemC_CID_KLen				(CefC_S_TLF+CefC_NWP_CID_Prefix_Len+MemC_CID_HexCh_size)

#define MemC_SEMNAME					"/cefmemsem"

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/
typedef struct {

	/********** Content Object in mem cache		***********/
	unsigned char	*msg;						/* Message								*/
	uint16_t		msg_len;					/* Message length						*/
	unsigned char	*name;						/* Content name							*/
	uint16_t		name_len;					/* Content name length					*/
	uint16_t		pay_len;					/* Payload length						*/
	uint32_t		chnk_num;					/* Chunk num							*/
	uint64_t		cache_time;					/* Cache time							*/
	uint64_t		expiry;						/* Expiry								*/
	struct in_addr	node;						/* Node address							*/

	uint64_t		ins_time;					/* Insert time							*/
} CsmgrdT_Content_Mem_Entry;

typedef struct CefT_Mem_Hash_Cell {
	
	uint32_t 					hash;
	unsigned char* 				key;
	uint32_t 					klen;
#ifdef CefC_Nwproc
	unsigned char 				cid_key[MemC_CID_KLen];
	uint32_t 					cid_klen;
#endif // CefC_Nwproc
	CsmgrdT_Content_Mem_Entry* 	elem;
	struct CefT_Mem_Hash_Cell	*next;
} CefT_Mem_Hash_Cell;

typedef struct CefT_Mem_Hash {
	CefT_Mem_Hash_Cell**	tbl;
	uint32_t 				tabl_max;
	uint64_t 				elem_max;
	uint64_t 				elem_num;
	
} CefT_Mem_Hash;

/****************************************************************************************
 State Variables
 ****************************************************************************************/

static MemT_Cache_Handle* 		hdl = NULL;
static char 					csmgr_conf_dir[PATH_MAX] = {"/usr/local/cefore"};
static CefT_Mem_Hash* 			mem_hash_tbl = NULL;
static uint32_t 				mem_tabl_max = 819200;
static pthread_mutex_t 			mem_comn_buff_mutex[MemC_Max_Buff];
static sem_t*					mem_comn_buff_sem;
static pthread_t				mem_thread_th;
static int 						mem_thread_f = 0;
static CsmgrdT_Content_Entry* 	mem_proc_cob_buff[MemC_Max_Buff]		= {0};
static int 						mem_proc_cob_buff_idx[MemC_Max_Buff] 	= {0};
static CsmgrT_Stat_Handle 		csmgr_stat_hdl;

static pthread_mutex_t 			mem_cs_mutex = PTHREAD_MUTEX_INITIALIZER;

#ifdef CefC_Ccore
static uint64_t 				ORG_cache_capacity = 0;
#endif
/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Init content store
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_cs_create (
	CsmgrT_Stat_Handle stat_hdl
);
/*--------------------------------------------------------------------------------------
	Destroy content store
----------------------------------------------------------------------------------------*/
static void
mem_cs_destroy (
	void
);
/*--------------------------------------------------------------------------------------
	Check content expire
----------------------------------------------------------------------------------------*/
static void
mem_cs_expire_check (
	void
);
/*--------------------------------------------------------------------------------------
	Function to read a ContentObject from Memory Cache
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_cache_item_get (
	unsigned char* key,							/* content name							*/
	uint16_t key_size,							/* content name Length					*/
	uint32_t seqno,								/* chunk num							*/
	int sock									/* received socket						*/
);
/*--------------------------------------------------------------------------------------
	Upload content byte steream
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_cache_item_puts (
	unsigned char* msg, 
	int msg_len
);
/*--------------------------------------------------------------------------------------
	Store API
----------------------------------------------------------------------------------------*/
static int 
mem_cs_store (
	CsmgrdT_Content_Entry* entry
);
/*--------------------------------------------------------------------------------------
	Remove API
----------------------------------------------------------------------------------------*/
static void
mem_cs_remove (
	unsigned char* key, 
	int key_len
);
/*--------------------------------------------------------------------------------------
	function for processing the received message
----------------------------------------------------------------------------------------*/
static void* 
mem_cob_process_thread (
	void* arg
);
/*--------------------------------------------------------------------------------------
	writes the cobs to memry cache
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_cache_cob_write (
	CsmgrdT_Content_Entry* cobs, 
	int cob_num
);
/*--------------------------------------------------------------------------------------
	Read config file
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_config_read (
	MemT_Config_Param* conf_param				/* Fsc config parameter					*/
);
/*--------------------------------------------------------------------------------------
	Function to increment access count
----------------------------------------------------------------------------------------*/
static void
mem_cs_ac_cnt_inc (
	unsigned char* key,							/* content name							*/
	uint16_t key_size,							/* content name Length					*/
	uint32_t seq_num							/* sequence number						*/
);
#ifdef CefC_Ccore
/*--------------------------------------------------------------------------------------
	Change cache capacity
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_change_cap (
	uint64_t cap								/* New capacity to set					*/
);
/*--------------------------------------------------------------------------------------
	Set content lifetime
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_cache_set_lifetime (
	unsigned char* name,						/* Content name							*/
	uint16_t name_len,							/* Content name length					*/
	uint64_t lifetime							/* Content Lifetime						*/
);
/*--------------------------------------------------------------------------------------
	Delete content entry
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_cache_del (
	unsigned char* name,						/* Content name							*/
	uint16_t name_len,							/* Content name length					*/
	uint32_t chunk_num							/* ChunkNumber							*/
);
#endif // CefC_Ccore

/*--------------------------------------------------------------------------------------
	Hash APIs for Memory Cahce Plugin
----------------------------------------------------------------------------------------*/
static CefT_Mem_Hash*
cef_mem_hash_tbl_create (
	uint64_t table_size
);
static uint32_t
cef_mem_hash_number_create (
	const unsigned char* key,
	uint32_t klen
);
static int 
cef_mem_hash_tbl_item_set (
	const unsigned char* key,
	uint32_t klen,
	CsmgrdT_Content_Mem_Entry* elem, 
	CsmgrdT_Content_Mem_Entry** old_elem
);
static CsmgrdT_Content_Mem_Entry* 
cef_mem_hash_tbl_item_get (
	const unsigned char* key,
	uint32_t klen
);
#ifdef CefC_Nwproc
static CsmgrdT_Content_Mem_Entry** 
cef_mem_hash_tbl_item_gets (
	const unsigned char* key,
	uint32_t klen,
	int* entry_num
);
#endif // CefC_Nwproc
static CsmgrdT_Content_Mem_Entry* 
cef_mem_hash_tbl_item_remove (
	const unsigned char* key,
	uint32_t klen
);

int
csmgrd_key_create_by_Mem_Entry (
	CsmgrdT_Content_Mem_Entry* entry,
	unsigned char* key
);
/*--------------------------------------------------------------------------------------
	get lifetime for ccninfo
----------------------------------------------------------------------------------------*/
static int										/* This value MAY be -1 if the router does not know or cannot report. */
mem_cache_lifetime_get (
	unsigned char* name,						/* content name							*/
	uint16_t name_len,							/* content name Length					*/
	uint32_t* cache_time,						/* The elapsed time (seconds) after the oldest	*/
												/* content object of the content is cached.		*/
	uint32_t* lifetime,							/* The lifetime (seconds) of a content object, 	*/
												/* which is removed first among the cached content objects.*/
	uint8_t partial_f							/* when flag is 0, exact match			*/
												/* when flag is 1, partial match		*/
);

/****************************************************************************************
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Road the cache plugin
----------------------------------------------------------------------------------------*/
int
csmgrd_memory_plugin_load (
	CsmgrdT_Plugin_Interface* cs_in, 
	const char* config_dir
) {
	CSMGRD_SET_CALLBACKS (
		mem_cs_create, mem_cs_destroy, mem_cs_expire_check, mem_cache_item_get,
		mem_cache_item_puts, mem_cs_ac_cnt_inc, mem_cache_lifetime_get);
	
#ifdef CefC_Ccore
	cs_in->cache_cap_set 		= mem_change_cap;
	cs_in->content_lifetime_set = mem_cache_set_lifetime;
	cs_in->content_cache_del	= mem_cache_del;
#endif // CefC_Ccore
	
	if (config_dir) {
		strcpy (csmgr_conf_dir, config_dir);
	}
	
	return (0);
}
/*--------------------------------------------------------------------------------------
	Init API
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_cs_create (
	CsmgrT_Stat_Handle stat_hdl
) {
	MemT_Config_Param conf_param;
	int res, i;
#ifdef CefC_Nwproc
	char algo_name_prefix[36] = {0};
#endif
	
	/* create handle 		*/
	if (hdl != NULL) {
		free (hdl);
		hdl = NULL;
	}

	/* Init logging 	*/
	csmgrd_log_init ("memcache", 1);
	csmgrd_log_init2 (csmgr_conf_dir);
#ifdef CefC_Debug
	csmgrd_dbg_init ("memcache", csmgr_conf_dir);
#endif // CefC_Debug

	hdl = (MemT_Cache_Handle*) malloc (sizeof (MemT_Cache_Handle));
	if (hdl == NULL) {
		csmgrd_log_write (CefC_Log_Error, "malloc error\n");
		return (-1);
	}
	memset (hdl, 0, sizeof (MemT_Cache_Handle));
	
	/* Reads config 		*/
	if (mem_config_read (&conf_param) < 0) {
		csmgrd_log_write (CefC_Log_Error, "[%s] read config\n", __func__);
		return (-1);
	}
	hdl->cache_capacity = conf_param.cache_capacity;
	strcpy (hdl->algo_name, conf_param.algo_name);
	hdl->algo_name_size = conf_param.algo_name_size;
	hdl->algo_cob_size = conf_param.algo_cob_size;
	hdl->cache_cobs = 0;
	
	/* Check for excessive or insufficient memory resources for cache algorithm library */
	if (strcmp (hdl->algo_name, "None") != 0) {
		if (csmgrd_cache_algo_availability_check (
				hdl->cache_capacity, hdl->algo_name, hdl->algo_name_size, hdl->algo_cob_size, "memory")
			< 0) {
			return (-1);
		}
	}
	
	/* Creates the memory cache 		*/
	mem_hash_tbl = cef_mem_hash_tbl_create (hdl->cache_capacity);
	if (mem_hash_tbl ==  NULL) {
		csmgrd_log_write (CefC_Log_Error, "Unable to create mem hash table\n");
		return (-1);
	}
	
	/* Loads the library for cache algorithm 		*/
	if (strcmp (conf_param.algo_name, "None")) {
		int rc = snprintf (hdl->algo_name, sizeof (hdl->algo_name), "%s%s", conf_param.algo_name, CsmgrdC_Library_Name);
		if ( rc < 0 ) {
			csmgrd_log_write (CefC_Log_Error, "create library for cache algorithm name\n");
			return (-1);
		}
		res = csmgrd_lib_api_get (
			hdl->algo_name, &hdl->algo_lib, &hdl->algo_apis);
		
		if (res < 0) {
			csmgrd_log_write (CefC_Log_Error, "load the lib (%s)\n", hdl->algo_name);
			return (-1);
		}
		
		if (hdl->algo_apis.init) {
			(*(hdl->algo_apis.init))(hdl->cache_capacity, mem_cs_store, mem_cs_remove);
		}
	}
	
	for (i = 0 ; i < MemC_Max_Buff ; i++) {
		if (i < MemC_Min_Buff) {
			mem_proc_cob_buff[i] = (CsmgrdT_Content_Entry*) 
				malloc (sizeof (CsmgrdT_Content_Entry) * CsmgrC_Buff_Num);
			if (mem_proc_cob_buff[i] == NULL) {
				csmgrd_log_write (CefC_Log_Error, 
					"Failed to allocation process cob buffer\n");
				return (-1);
			}
		} else {
			mem_proc_cob_buff[i] = NULL;
		}
		mem_proc_cob_buff_idx[i] = 0;
		pthread_mutex_init (&mem_comn_buff_mutex[i], NULL);
	}
	mem_comn_buff_sem = sem_open (MemC_SEMNAME, O_CREAT | O_EXCL, 0777, 0);
	if (mem_comn_buff_sem == SEM_FAILED && errno == EEXIST) {
		sem_unlink (MemC_SEMNAME);
		mem_comn_buff_sem = sem_open (MemC_SEMNAME, O_CREAT | O_EXCL, 0777, 0);
	}
	if (mem_comn_buff_sem == SEM_FAILED) {
		csmgrd_log_write (CefC_Log_Error, "Failed to create the new semaphore\n");
		return (-1);
	}
	
	if (pthread_create (&mem_thread_th, NULL, mem_cob_process_thread, hdl) == -1) {
		csmgrd_log_write (CefC_Log_Error, "Failed to create the new thread\n");
		return (-1);
	}
	mem_thread_f = 1;
	
	csmgrd_log_write (CefC_Log_Info, "Start\n");
	csmgrd_log_write (CefC_Log_Info, "Cache Capacity : "FMTU64"\n", hdl->cache_capacity);
	if (strcmp (conf_param.algo_name, "None")) {
		csmgrd_log_write (CefC_Log_Info, "Library  : %s ... OK\n", hdl->algo_name);
	} else {
		csmgrd_log_write (CefC_Log_Info, "Library  : Not Specified\n");
	}
#ifdef CefC_Nwproc
/* [Restriction]															*/
/* For renovation in FY 2018, if NWProc is enabled, only FIFO is allowed.	*/
	sprintf (algo_name_prefix, "libcsmgrd_fifo%s", CsmgrdC_Library_Name);
	if (strcmp (hdl->algo_name, algo_name_prefix) != 0) {
		csmgrd_log_write (CefC_Log_Error, 
			"Library (Invalid value CACHE_ALGORITHM=%s)\n", hdl->algo_name);
		return (-1);
	}
#endif // CefC_Nwproc

	csmgr_stat_hdl = stat_hdl;
	csmgrd_stat_cache_capacity_update (csmgr_stat_hdl, hdl->cache_capacity);
	
	return (0);
}
/*--------------------------------------------------------------------------------------
	function for processing the received message
----------------------------------------------------------------------------------------*/
static void* 
mem_cob_process_thread (
	void* arg
) {
	int i;
	
	while (mem_thread_f) {
		sem_wait (mem_comn_buff_sem);
		if (!mem_thread_f)
			break;
		for (i = 0 ; i < MemC_Max_Buff ; i++) {
			if (pthread_mutex_trylock (&mem_comn_buff_mutex[i]) != 0) {
				continue;
			}
			if (mem_proc_cob_buff_idx[i] > 0) {
#ifdef CefC_Debug
				csmgrd_dbg_write (CefC_Dbg_Fine, 
					"cob put thread starts to write %d cobs\n", mem_proc_cob_buff_idx[i]);
#endif // CefC_Debug
				pthread_mutex_lock (&mem_cs_mutex);
				mem_cache_cob_write (&mem_proc_cob_buff[i][0], mem_proc_cob_buff_idx[i]);
				pthread_mutex_unlock (&mem_cs_mutex);
				mem_proc_cob_buff_idx[i] = 0;
				if (i >= MemC_Min_Buff) {
					free (mem_proc_cob_buff[i]);
					mem_proc_cob_buff[i] = NULL;
				}
#ifdef CefC_Debug
				csmgrd_dbg_write (CefC_Dbg_Fine, 
					"cob put thread completed writing cobs\n");
#endif // CefC_Debug
			}
			pthread_mutex_unlock (&mem_comn_buff_mutex[i]);
		}
	}
	
	pthread_exit (NULL);
	
	return ((void*) NULL);
}
/*--------------------------------------------------------------------------------------
	Store API
----------------------------------------------------------------------------------------*/
static int 
mem_cs_store (
	CsmgrdT_Content_Entry* new_entry
) {
	CsmgrdT_Content_Mem_Entry* entry;
	CsmgrdT_Content_Mem_Entry* old_entry = NULL;
	int key_len;
	unsigned char key[65535];
	uint64_t 	nowt;
	struct timeval tv;
	
	/* Creates the key 		*/
	key_len = csmgrd_key_create (new_entry, key);
	
	/* Creates the entry 		*/
	entry = 
		(CsmgrdT_Content_Mem_Entry*) calloc (1, sizeof (CsmgrdT_Content_Mem_Entry));
	if (entry == NULL) {
		return (-1);
	}
	
	/* Inserts the cache entry 		*/
	entry->msg 		= new_entry->msg;
	entry->msg_len	= new_entry->msg_len;
	entry->name		= new_entry->name;
	entry->name_len = new_entry->name_len;
	entry->pay_len		 = new_entry->pay_len;
	entry->chnk_num		 = new_entry->chnk_num;
	entry->cache_time	 = new_entry->cache_time;
	entry->expiry		 = new_entry->expiry;
	entry->node			 = new_entry->node;
	entry->ins_time		 = new_entry->ins_time;
	
	if (cef_mem_hash_tbl_item_set (
		key, key_len, entry, &old_entry) < 0) {
		free (entry->msg);
		free (entry->name);
		free (entry);
		return (-1);
	}
	
	/* Updates the content information 			*/
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;
	
	csmgrd_stat_cob_update (csmgr_stat_hdl, entry->name, entry->name_len, 
		entry->chnk_num, entry->pay_len, entry->expiry, nowt, entry->node);
	
	if (old_entry) {
		free (old_entry->msg);
		free (old_entry->name);
		free (old_entry);
	} else {
		hdl->cache_cobs++;
	}	
	
	return (0);
}

/*--------------------------------------------------------------------------------------
	Remove API
----------------------------------------------------------------------------------------*/
static void
mem_cs_remove (
	unsigned char* key, 
	int key_len
) {
	CsmgrdT_Content_Mem_Entry* entry;
	
	entry = cef_mem_hash_tbl_item_remove (key, key_len);
	
	if (entry) {
		csmgrd_stat_cob_remove (
			csmgr_stat_hdl, entry->name, entry->name_len, 
			entry->chnk_num, entry->pay_len);
		free (entry->msg);
		free (entry->name);
		free (entry);
		hdl->cache_cobs--;
	}
	
	return;
}

/*--------------------------------------------------------------------------------------
	Destroy content store
----------------------------------------------------------------------------------------*/
static void
mem_cs_destroy (
	void
) {
	int i;
	void* status;

	pthread_mutex_destroy (&mem_cs_mutex);
	
	if (mem_thread_f) {
		mem_thread_f = 0;
		sem_post (mem_comn_buff_sem);	/* To avoid deadlock */
		pthread_join (mem_thread_th, &status);
	}
	sem_close (mem_comn_buff_sem);
	sem_unlink (MemC_SEMNAME);
	
	for (i = 0 ; i < MemC_Max_Buff ; i++) {
		if (mem_proc_cob_buff[i]) {
			free (mem_proc_cob_buff[i]);
		}
		pthread_mutex_destroy (&mem_comn_buff_mutex[i]);
	}
	
	if (hdl == NULL) {
		return;
	}
	if (mem_hash_tbl) {
		for (i = 0 ; i < mem_hash_tbl->tabl_max ; i++) {
			CefT_Mem_Hash_Cell* cp;
			CefT_Mem_Hash_Cell* wcp;
			cp = mem_hash_tbl->tbl[i];
			while (cp != NULL) {
				wcp = cp->next;
				free (cp->elem);
				free (cp);
				cp = wcp;
			}
		}
		free (mem_hash_tbl->tbl);
		free (mem_hash_tbl);
	}
	
	if (hdl->algo_lib) {
		if (hdl->algo_apis.destroy) {
			(*(hdl->algo_apis.destroy))();
		}
		dlclose (hdl->algo_lib);
	}
	
	if (hdl) {
		free (hdl);
		hdl = NULL;
	}
	
	return;
}

/*--------------------------------------------------------------------------------------
	Check content expire
----------------------------------------------------------------------------------------*/
static void
mem_cs_expire_check (
	void
) {
	CsmgrdT_Content_Mem_Entry* entry = NULL;
	CsmgrdT_Content_Mem_Entry* entry1 = NULL;
	uint64_t 	nowt;
	struct timeval tv;
	int n;
	unsigned char trg_key[65535];
	int trg_key_len;
	
	if (pthread_mutex_trylock (&mem_cs_mutex) != 0) {
		return;
	}
	
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;

	for (n = 0 ; n < mem_hash_tbl->tabl_max ; n++) { 
		if (mem_hash_tbl->tbl[n] == NULL) {
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
					trg_key_len = csmgrd_key_create_by_Mem_Entry (entry, trg_key);
					entry1 = cef_mem_hash_tbl_item_remove (trg_key, trg_key_len);
					if (hdl->algo_apis.erase) {
						(*(hdl->algo_apis.erase))(trg_key, trg_key_len);
					}
					hdl->cache_cobs--;
					csmgrd_stat_cob_remove (
						csmgr_stat_hdl, entry->name, entry->name_len, 
						entry->chnk_num, entry->pay_len);
					free (entry1->msg);
					free (entry1->name);
					free (entry1);
				}
			}
		}
	}
	pthread_mutex_unlock (&mem_cs_mutex);
	
	return;
}

/*--------------------------------------------------------------------------------------
	Function to read a ContentObject from memory cache
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_cache_item_get (
	unsigned char* key,							/* content name							*/
	uint16_t key_size,							/* content name Length					*/
	uint32_t seqno,								/* chunk num							*/
	int sock									/* received socket						*/
) {
	CsmgrdT_Content_Mem_Entry* entry;
	unsigned char 	trg_key[CsmgrdC_Key_Max];
	int 			trg_key_len;
	uint64_t 		nowt;
	struct timeval 	tv;
#ifdef CefC_Nwproc
	int target_num = 0;
	int i;
#endif // CefC_Nwproc
	CsmgrdT_Content_Mem_Entry** entry_p = NULL;
	int exist_f = CefC_Csmgr_Cob_NotExist;

	/* Creates the key 		*/
	trg_key_len = csmgrd_name_chunknum_concatenate (key, key_size, seqno, trg_key);
	
	/* Access the specified entry 	*/
#ifndef CefC_Nwproc
	entry = cef_mem_hash_tbl_item_get (trg_key, trg_key_len);
	
	if (entry) {
#else // CefC_Nwproc
	entry_p = cef_mem_hash_tbl_item_gets (trg_key, trg_key_len, &target_num);
	for (i = 0; i < target_num; i++) {
		
		entry = entry_p[i];
		trg_key_len = csmgrd_name_chunknum_concatenate (entry->name, entry->name_len, seqno, trg_key);
#endif // CefC_Nwproc
		
		gettimeofday (&tv, NULL);
		nowt = tv.tv_sec * 1000000llu + tv.tv_usec;
		
		if (((entry->expiry == 0) || (nowt < entry->expiry)) &&
			(nowt < entry->cache_time)) {
			pthread_mutex_lock (&mem_cs_mutex);
			if (hdl->algo_apis.hit) {
				(*(hdl->algo_apis.hit))(trg_key, trg_key_len);
			}
			
			csmgrd_stat_access_count_update (
					csmgr_stat_hdl, entry->name, entry->name_len);
			
			/* Send Cob to cefnetd */
			csmgrd_plugin_cob_msg_send (sock, entry->msg, entry->msg_len);
			exist_f = CefC_Csmgr_Cob_Exist;
			pthread_mutex_unlock (&mem_cs_mutex);
 		}
		else {
			pthread_mutex_lock (&mem_cs_mutex);
			/* Removes the expiry cache entry 		*/
			entry = cef_mem_hash_tbl_item_remove (trg_key, trg_key_len);
			
			if (hdl->algo_apis.erase) {
				(*(hdl->algo_apis.erase))(trg_key, trg_key_len);
			}
			hdl->cache_cobs--;
			
			csmgrd_stat_cob_remove (
				csmgr_stat_hdl, entry->name, entry->name_len, 
				entry->chnk_num, entry->pay_len);
			
			free (entry->msg);
			free (entry->name);
			free (entry);
			pthread_mutex_unlock (&mem_cs_mutex);
		}
	}
	
	if (entry_p != NULL) {
		free (entry_p);
	}
	return (exist_f);
	
	if (hdl->algo_apis.miss) {
		(*(hdl->algo_apis.miss))(trg_key, trg_key_len);
	}
	
	return (CefC_Csmgr_Cob_NotExist);
}
/*--------------------------------------------------------------------------------------
	Upload content byte steream
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_cache_item_puts (
	unsigned char* msg, 
	int msg_len
) {
	CsmgrdT_Content_Entry entry;
	int i;
	int res;
	int index = 0;
	int write_f = 0;
	
#ifdef CefC_Debug
	csmgrd_dbg_write (CefC_Dbg_Fine, "cob rcv thread receives %d bytes\n", msg_len);
#endif // CefC_Debug

	for (i = 0 ; i < MemC_Max_Buff ; i++) {
		
		if (pthread_mutex_trylock (&mem_comn_buff_mutex[i]) != 0) {
			continue;
		}
		
		if (mem_proc_cob_buff_idx[i] == 0) {
			if (i >= MemC_Min_Buff &&
				mem_proc_cob_buff[i] == NULL) {
				
				mem_proc_cob_buff[i] = (CsmgrdT_Content_Entry*) 
					malloc (sizeof (CsmgrdT_Content_Entry) * CsmgrC_Buff_Num);
				if (mem_proc_cob_buff[i] == NULL) {
					csmgrd_log_write (CefC_Log_Info, 
						"Failed to allocation process cob buffer(temporary)\n");
					pthread_mutex_unlock (&mem_comn_buff_mutex[i]);
					return (-1);
				}
			}

#ifdef CefC_Debug
			csmgrd_dbg_write (CefC_Dbg_Fine, 
				"cob rcv thread starts to write %d bytes to buffer#%d\n"
				, msg_len - index, i);
#endif // CefC_Debug
			while (index < msg_len) {
				res = cef_csmgr_con_entry_create (&msg[index], msg_len - index, &entry);
				
				if (res < 0) {
					break;
				}
				memcpy (
					&mem_proc_cob_buff[i][mem_proc_cob_buff_idx[i]], 
					&entry, 
					sizeof (CsmgrdT_Content_Entry));
				
				mem_proc_cob_buff_idx[i] += 1;
				index += res;
				
				if (mem_proc_cob_buff_idx[i] + 1 == CsmgrC_Buff_Num) {
					break;
				}
			}
		}
		
		if (mem_proc_cob_buff_idx[i] > 0)
			write_f++;
		pthread_mutex_unlock (&mem_comn_buff_mutex[i]);
		
		if (index >= msg_len) {
			break;
		}
	}
	if (write_f > 0)
		sem_post (mem_comn_buff_sem);
	
#ifdef CefC_Debug
	if (i == MemC_Max_Buff) {
		csmgrd_dbg_write (CefC_Dbg_Fine, 
			"cob rcv thread lost %d bytes\n", msg_len - index);
	}
#endif // CefC_Debug
	
	return (0);
}
/*--------------------------------------------------------------------------------------
	writes the cobs to memry cache
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_cache_cob_write (
	CsmgrdT_Content_Entry* cobs, 
	int cob_num
) {
	int index = 0;
	CsmgrdT_Content_Mem_Entry* entry;
	CsmgrdT_Content_Mem_Entry* old_entry = NULL;
	unsigned char 	trg_key[CsmgrdC_Key_Max];
	int 			trg_key_len;
	uint64_t nowt;
	struct timeval tv;
	
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;

	while (index < cob_num) {
		
		if (cobs[index].expiry < nowt) {
			free (cobs[index].msg);
			free (cobs[index].name);
			index++;
			continue;
		}

		if (hdl->algo_apis.insert) {
			trg_key_len = csmgrd_key_create (&cobs[index], trg_key);
			entry = cef_mem_hash_tbl_item_get (trg_key, trg_key_len);
			if (entry == NULL) {
				(*(hdl->algo_apis.insert))(&cobs[index]);
			}
		} else {
			if (hdl->cache_cobs >= hdl->cache_capacity) {
				free (cobs[index].msg);
				free (cobs[index].name);
				index++;
				continue;
			}
			/* Caches the content entry without the cache algorithm library 	*/
			entry = 
				(CsmgrdT_Content_Mem_Entry*) calloc (1, sizeof (CsmgrdT_Content_Mem_Entry));
			if (entry == NULL) {
				return (-1);
			}
			
			/* Creates the key 				*/
			trg_key_len = csmgrd_name_chunknum_concatenate (
							cobs[index].name, cobs[index].name_len, 
							cobs[index].chnk_num, trg_key);
			
			/* Inserts the cache entry 		*/
			entry->msg		= cobs[index].msg;
			entry->msg_len	= cobs[index].msg_len;
			entry->name		= cobs[index].name;
			entry->name_len	= cobs[index].name_len;
			entry->pay_len		 = cobs[index].pay_len;
			entry->chnk_num		 = cobs[index].chnk_num;
			entry->cache_time	 = cobs[index].cache_time;
			entry->expiry		 = cobs[index].expiry;
			entry->node			 = cobs[index].node;
			entry->ins_time		 = cobs[index].ins_time;
			
			if (cef_mem_hash_tbl_item_set (
				trg_key, trg_key_len, entry, &old_entry) < 0) {
				free (entry->msg);
				free (entry->name);
				free (entry);
				return (-1);
			}
			
			/* Updates the content information 			*/
			csmgrd_stat_cob_update (csmgr_stat_hdl, entry->name, entry->name_len, 
				entry->chnk_num, entry->pay_len, entry->expiry, nowt, entry->node);
			
			if (old_entry) {
				free (old_entry->msg);
				free (old_entry->name);
				free (old_entry);
			} else {
				hdl->cache_cobs++;
			}
		}
		index++;
	}
	
	return (0);
}
/*--------------------------------------------------------------------------------------
	Function to increment access count
----------------------------------------------------------------------------------------*/
static void
mem_cs_ac_cnt_inc (
	unsigned char* key,							/* content name							*/
	uint16_t key_size,							/* content name Length					*/
	uint32_t seq_num							/* sequence number						*/
) {
	CsmgrdT_Content_Mem_Entry* entry;
	
	entry = cef_mem_hash_tbl_item_get (key, key_size);
	if (!entry) {
		return;
	}
	
	pthread_mutex_lock (&mem_cs_mutex);
	if (hdl->algo_apis.hit) {
		(*(hdl->algo_apis.hit))(key, key_size);
	}
	pthread_mutex_unlock (&mem_cs_mutex);
	
	csmgrd_stat_access_count_update (
			csmgr_stat_hdl, entry->name, entry->name_len);
	
	return;
}

/*--------------------------------------------------------------------------------------
	Read config file
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_config_read (
	MemT_Config_Param* params						/* record parameters				*/
) {
	FILE*	fp = NULL;								/* file pointer						*/
	char	file_name[PATH_MAX];					/* file name						*/
	
	char	param[4096] = {0};						/* parameter						*/
	char	param_buff[4096] = {0};					/* param buff						*/
	int		len;									/* read length						*/
	
	char*	option;									/* deny option						*/
	char*	value;									/* parameter						*/
	int		res;
	
	int		i, n;
	
	/* Inits parameters		*/
	memset (params, 0, sizeof (MemT_Config_Param));
	params->cache_capacity = 819200;
	strcpy (params->algo_name, "libcsmgrd_lru");
	params->algo_name_size = 256;
	params->algo_cob_size = 2048;
	
	/* Obtains the directory path where the csmgrd's config file is located. */
	sprintf (file_name, "%s/csmgrd.conf", csmgr_conf_dir);
	
	/* Opens the config file. */
	fp = fopen (file_name, "r");
	if (fp == NULL) {
		csmgrd_log_write (CefC_Log_Error, "[%s] open %s\n", __func__, file_name);
		return (-1);
	}
	
	/* get parameter	*/
	while (fgets (param_buff, sizeof (param_buff), fp) != NULL) {
		
		/* Trims a read line 		*/
		len = strlen (param_buff);
		if ((param_buff[0] == '#') || (param_buff[0] == '\n') || (len == 0)) {
			continue;
		}
		if (param_buff[len - 1] == '\n') {
			param_buff[len - 1] = '\0';
		}
		for (i = 0, n = 0 ; i < len ; i++) {
			if (param_buff[i] != ' ') {
				param[n] = param_buff[i];
				n++;
			}
		}
		
		/* Gets option */
		value 	= param;
		option 	= strsep (&value, "=");
		
		if (value == NULL) {
			continue;
		}
		
		/* Records a parameter 			*/
		if (strcmp (option, "CACHE_ALGORITHM") == 0) {
			strcpy (params->algo_name, value);
		} else if (strcmp (option, "CACHE_ALGO_NAME_SIZE") == 0) {
			res = atoi (value);
			if (!(100 <= res && res <= 8000)) {
				csmgrd_log_write (CefC_Log_Error, 
					"CACHE_ALGO_NAME_SIZE must be between 100 and 8000 inclusive.\n");
				fclose (fp);
				return (-1);
			}
			params->algo_name_size = res;
		} else if (strcmp (option, "CACHE_ALGO_COB_SIZE") == 0) {
			res = atoi (value);
			if (!(500 <= res && res <= 65535)) {
				csmgrd_log_write (CefC_Log_Error, 
					"CACHE_ALGO_COB_SIZE must be between 500 and 65535 inclusive.\n");
				fclose (fp);
				return (-1);
			}
			params->algo_cob_size = res;
		} else if (strcmp (option, "CACHE_CAPACITY") == 0) {
			char *endptr = "";
			params->cache_capacity = strtoul (value, &endptr, 0);
			if (strcmp (endptr, "") != 0) {
				csmgrd_log_write (
					CefC_Log_Error, "[%s] Invalid value %s=%s\n", __func__, option, value);
				fclose (fp);
				return (-1);
			}
			if ((params->cache_capacity < 1) || (params->cache_capacity > 0xFFFFFFFFF)) {
				csmgrd_log_write (CefC_Log_Error, 
				"CACHE_CAPACITY must be between 1 and 68,719,476,735 (0xFFFFFFFFF) inclusive.\n");
				fclose (fp);
				return (-1);
			}
		} else {
			/* NOP */;
		}
	}
#ifdef CefC_Debug
	csmgrd_dbg_write (CefC_Dbg_Fine, "params->cache_capacity="FMTU64"\n",
						params->cache_capacity);
	csmgrd_dbg_write (CefC_Dbg_Fine, "params->algo_name=%s\n",
						params->algo_name);
	csmgrd_dbg_write (CefC_Dbg_Fine, "params->algo_name_size=%d\n",
						params->algo_name_size);
	csmgrd_dbg_write (CefC_Dbg_Fine, "params->algo_cob_size=%d\n",
						params->algo_cob_size);
#endif // CefC_Debug
	
	if (strcmp (params->algo_name, "None") != 0) {
		if (strcmp (params->algo_name, "libcsmgrd_lfu") == 0) {
			if (params->cache_capacity > 819200) {
				csmgrd_log_write (CefC_Log_Error, 
				"Cache capacity value must be less than or equal to 819200 when using algorithm lfu.\n");
				fclose (fp);
				return (-1);
			}
		} else {
			if (params->cache_capacity > 2147483647) {
				csmgrd_log_write (CefC_Log_Error, 
				"Cache capacity value must be less than or equal to 2147483647 when using algorithms lfu, fifo, etc..\n");
				fclose (fp);
				return (-1);
			}
		}
	}
	fclose (fp);
	
	return (0);
}

#ifdef CefC_Ccore
/*--------------------------------------------------------------------------------------
	Change cache capacity
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_change_cap (
	uint64_t cap								/* New capacity to set					*/
) {
	int n;
	
	if (ORG_cache_capacity == 0) {
		ORG_cache_capacity = hdl->cache_capacity;
	}
	if ((cap < 1) || (cap > 0xFFFFFFFFF)) {
		csmgrd_log_write (CefC_Log_Error, "Invalid capacity\n");
		return (-1);
	}
	if (cap > ORG_cache_capacity) {
		csmgrd_log_write (CefC_Log_Error, "Do not allow configuration beyond initial cache capacity\n");
		return (-1);
	}
	
	/* Check for excessive or insufficient memory resources for cache algorithm library */
	if (strcmp (hdl->algo_name, "None") != 0) {
		if (csmgrd_cache_algo_availability_check (
				cap, hdl->algo_name, hdl->algo_name_size, hdl->algo_cob_size, "memory")
			< 0) {
			return (-1);
		}
	}
	
	/* Recreate algorithm lib */
	if (hdl->algo_lib) {
		if (hdl->algo_apis.destroy) {
			(*(hdl->algo_apis.destroy))();
		}
	}
	
	/* Change cap */
	csmgrd_stat_cache_capacity_update (csmgr_stat_hdl, cap);
	hdl->cache_capacity = cap;
	hdl->cache_cobs = 0; 
	
	/* Destroy table */
	for (n = 0 ; n < mem_hash_tbl->tabl_max ; n++) {
		CefT_Mem_Hash_Cell* cp;
		CefT_Mem_Hash_Cell* wcp;
		cp = mem_hash_tbl->tbl[n];
		while (cp != NULL) {
			wcp = cp->next;
			free (cp->elem);
			free (cp);
			cp = wcp;
		}
	}
	free (mem_hash_tbl->tbl);
	free (mem_hash_tbl);
	
	/* Creates the memory cache 		*/
	mem_hash_tbl = cef_mem_hash_tbl_create (hdl->cache_capacity);
	if (mem_hash_tbl ==  NULL) {
		csmgrd_log_write (CefC_Log_Error, "Unable to create mem hash table\n");
		return (-1);
	}
	
	hdl->cache_cobs = 0;
	/* Recreate algorithm lib */
	if (hdl->algo_lib) {
		if (hdl->algo_apis.init) {
			(*(hdl->algo_apis.init))(cap, mem_cs_store, mem_cs_remove);
		}
	}

	
	return (0);
}
/*--------------------------------------------------------------------------------------
	Set content lifetime
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_cache_set_lifetime (
	unsigned char* name,						/* Content name							*/
	uint16_t name_len,							/* Content name length					*/
	uint64_t lifetime							/* Content Lifetime						*/
) {
	CsmgrdT_Content_Mem_Entry* entry = NULL;
	uint64_t nowt;
	struct timeval tv;
	uint64_t new_life;
	int n;
	
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;
	new_life = nowt + lifetime * 1000000llu;
	
	/* Updtes the content information */
	csmgrd_stat_content_lifetime_update (csmgr_stat_hdl, name, name_len, new_life);
	
	/* Check the cache entry information */
	for (n = 0 ; n < mem_hash_tbl->tabl_max ; n++) {
		if (mem_hash_tbl->tbl[n] == NULL) {
			continue;
		}
		{
			CefT_Mem_Hash_Cell* cp;
			cp = mem_hash_tbl->tbl[n];
			for (; cp != NULL; cp = cp->next) {
				entry = cp->elem;
				if (((entry->expiry == 0) || (nowt < entry->expiry)) &&
					(nowt < entry->cache_time)) {
					
					if (memcmp (name, entry->name, name_len)) {
						continue;
					}
					entry->expiry = new_life;
					entry->cache_time = new_life;
				}
			}
		}
	}
	
	return (0);
}
/*--------------------------------------------------------------------------------------
	Delete content entry
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_cache_del (
	unsigned char* name,						/* Content name							*/
	uint16_t name_len,							/* Content name length					*/
	uint32_t chunk_num							/* ChunkNumber							*/
) {
	CsmgrdT_Content_Mem_Entry* entry = NULL;
	unsigned char 	trg_key[CsmgrdC_Key_Max];
	int 			trg_key_len;
	
	pthread_mutex_lock (&mem_cs_mutex);
	/* Creates the key 				*/
	trg_key_len = csmgrd_name_chunknum_concatenate (
					name, name_len, chunk_num, trg_key);
	
	/* Removes the cache entry 		*/
	entry = cef_mem_hash_tbl_item_remove (trg_key, trg_key_len);
	if (entry == NULL) {
		pthread_mutex_unlock (&mem_cs_mutex);
		return (0);
	}
	
	if (hdl->algo_apis.erase) {
		(*(hdl->algo_apis.erase))(trg_key, trg_key_len);
	}
	hdl->cache_cobs--;
	
	csmgrd_stat_cob_remove (
		csmgr_stat_hdl, entry->name, entry->name_len, 
		entry->chnk_num, entry->pay_len);
	
	free (entry->msg);
	free (entry->name);
	free (entry);
	pthread_mutex_unlock (&mem_cs_mutex);

	return (0);
}
#endif // CefC_Ccore
/*--------------------------------------------------------------------------------------
	get lifetime for ccninfo
----------------------------------------------------------------------------------------*/
static int										/* This value MAY be -1 if the router does not know or cannot report. */
mem_cache_lifetime_get (
	unsigned char* name,						/* content name							*/
	uint16_t name_len,							/* content name Length					*/
	uint32_t* cache_time,						/* The elapsed time (seconds) after the oldest	*/
												/* content object of the content is cached.		*/
	uint32_t* lifetime,							/* The lifetime (seconds) of a content object, 	*/
												/* which is removed first among the cached content objects.*/
	uint8_t partial_f							/* when flag is 0, exact match			*/
												/* when flag is 1, partial match		*/
) {
	CsmgrT_Stat* rcd = NULL;
	CsmgrdT_Content_Mem_Entry* entry;
	uint64_t nowt;
	struct timeval tv;
	
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;
	
	if (partial_f != 0) {
		uint64_t idx;
		unsigned char trg_key[65535];
		int trg_key_len;
		uint64_t oldest_ins_time;
		uint64_t first_expire;
		
		rcd = csmgr_stat_content_info_get (csmgr_stat_hdl, name, name_len);
		if (!rcd || rcd->expire_f) {
			return (-1);
		}
		
		oldest_ins_time = nowt;
		first_expire = UINT64_MAX;
		
		for (idx = rcd->min_seq; idx <= rcd->max_seq; idx++) {
			trg_key_len = csmgrd_name_chunknum_concatenate (name, name_len, idx, trg_key);
			entry = cef_mem_hash_tbl_item_get (trg_key, trg_key_len);
			if (!entry) {
				continue;
			}
			if (oldest_ins_time > entry->ins_time)
				oldest_ins_time = entry->ins_time;
			if (first_expire > entry->expiry)
				first_expire = entry->expiry;
		}
		*cache_time = (uint32_t)((nowt - oldest_ins_time) / 1000000);
		if (first_expire < nowt)
			*lifetime = 0;
		else
			*lifetime = (uint32_t)((first_expire - nowt) / 1000000);
		return (1);
	} else {
		entry = cef_mem_hash_tbl_item_get (name, name_len);
		if ((!entry) ||
			(nowt > entry->expiry)) {
			return (-1);
		}
		*cache_time = (uint32_t)((nowt - entry->ins_time) / 1000000);
		*lifetime   = (uint32_t)((entry->expiry - nowt) / 1000000);
		return (1);
	}
	return (-1);
}

/****************************************************************************************
 ****************************************************************************************/
static CefT_Mem_Hash*
cef_mem_hash_tbl_create (
	uint64_t capacity
) {
	CefT_Mem_Hash* ht = NULL;
	uint64_t table_size;
	int i, n;
	int flag;

	if (capacity > INT32_MAX) {
		table_size = INT32_MAX;
	} else {
		table_size = capacity;
	}
	
	if (table_size < INT32_MAX) {
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
				if (table_size == INT32_MAX) {
					break;
				}
			} else {
				break;
			}
		}
	}
	ht = (CefT_Mem_Hash*) malloc (sizeof (CefT_Mem_Hash));
	if (ht == NULL) {
		return (NULL);
	}
	memset (ht, 0, sizeof (CefT_Mem_Hash));
	
	ht->tbl = (CefT_Mem_Hash_Cell**) calloc (sizeof (CefT_Mem_Hash_Cell*), table_size);
	
	if (ht->tbl  == NULL) {
		free (ht->tbl);
		free (ht);
		return (NULL);
	}
	memset (ht->tbl, 0, sizeof (CefT_Mem_Hash_Cell*) * table_size);
	
	srand ((unsigned) time (NULL));
	ht->elem_max = capacity;
	ht->tabl_max = table_size;
	mem_tabl_max = ht->tabl_max;
	ht->elem_num = 0;
	
	return (ht);
}	

#ifndef CefC_Nwproc
static int 
cef_mem_hash_tbl_item_set (
	const unsigned char* key,
	uint32_t klen,
	CsmgrdT_Content_Mem_Entry* elem, 
	CsmgrdT_Content_Mem_Entry** old_elem
) {
	CefT_Mem_Hash* ht = (CefT_Mem_Hash*) mem_hash_tbl;
	uint32_t hash = 0;
	uint32_t y;
	CefT_Mem_Hash_Cell* cp;
	CefT_Mem_Hash_Cell* wcp;
	*old_elem = NULL;

	hash = cef_mem_hash_number_create (key, klen);
	y = hash % ht->tabl_max;

	if (ht->tbl[y] == NULL) {
		ht->tbl[y] = (CefT_Mem_Hash_Cell* )calloc (1, sizeof (CefT_Mem_Hash_Cell) + klen);
		if (ht->tbl[y] == NULL) {
			return (-1);
		}
		ht->tbl[y]->key = ((unsigned char*)ht->tbl[y]) + sizeof (CefT_Mem_Hash_Cell);
		cp = ht->tbl[y];
		cp->elem = elem;
		cp->klen = klen;
		memcpy (cp->key, key, klen);
		ht->elem_num++;
		return (1);
	} else {
		/* exist check & replace */
		for (cp = ht->tbl[y]; cp != NULL; cp = cp->next) {
			if ((cp->klen == klen) &&
			   (memcmp (cp->key, key, klen) == 0)) {
				*old_elem = cp->elem;
				cp->elem = elem;
				return (1);
		   }
		}
		/* insert */
		wcp = ht->tbl[y];
		ht->tbl[y] = (CefT_Mem_Hash_Cell* )calloc (1, sizeof (CefT_Mem_Hash_Cell) + klen);
		if (ht->tbl[y] == NULL) {
			return (-1);
		}
		ht->tbl[y]->key = ((unsigned char*)ht->tbl[y]) + sizeof (CefT_Mem_Hash_Cell);
		cp = ht->tbl[y];
		cp->next = wcp;
		cp->elem = elem;
		cp->klen = klen;
		memcpy (cp->key, key, klen);
		
		ht->elem_num++;
		return (1);
	}
}
#else // CefC_Nwproc
static int 
cef_mem_hash_tbl_item_set (
	const unsigned char* key,
	uint32_t klen,
	CsmgrdT_Content_Mem_Entry* elem, 
	CsmgrdT_Content_Mem_Entry** old_elem
) {
	CefT_Mem_Hash* ht = (CefT_Mem_Hash*) mem_hash_tbl;
	uint32_t hash = 0;
	uint32_t y;
	CefT_Mem_Hash_Cell* cp;
	CefT_Mem_Hash_Cell* wcp;
	unsigned char cid_key[MemC_CID_KLen];
	uint32_t cid_klen;
	unsigned char key_wo_cid[MemC_Max_KLen];
	unsigned int key_wo_cid_len;

	*old_elem = NULL;
	cef_frame_separate_name_and_cid (
				(unsigned char *)key, klen, 
				key_wo_cid, &key_wo_cid_len, 
				cid_key, &cid_klen);

	hash = cef_mem_hash_number_create (key_wo_cid, key_wo_cid_len);
	y = hash % ht->tabl_max;

	if (ht->tbl[y] == NULL) {
		ht->tbl[y] = (CefT_Mem_Hash_Cell* )calloc (1, sizeof (CefT_Mem_Hash_Cell) + key_wo_cid_len);
		if (ht->tbl[y] == NULL) {
			return (-1);
		}
		ht->tbl[y]->key = ((unsigned char*)ht->tbl[y]) + sizeof (CefT_Mem_Hash_Cell);
		cp = ht->tbl[y];
		cp->elem = elem;
		cp->klen = key_wo_cid_len;
		memcpy (cp->key, key_wo_cid, key_wo_cid_len);
		cp->cid_klen = cid_klen;
		memcpy (cp->cid_key, cid_key, cid_klen);
		cp->next = NULL;
		ht->elem_num++;
		return (1);
	} else {
		/* exist check & replace */
		for (cp = ht->tbl[y]; cp != NULL; cp = cp->next) {
			if ((cp->klen == key_wo_cid_len) &&
			   (cp->cid_klen == cid_klen) &&
			   (memcmp (cp->key, key_wo_cid, key_wo_cid_len) == 0) &&
			   (memcmp (cp->cid_key, cid_key, cid_klen) == 0)) {
				*old_elem = cp->elem;
				cp->elem = elem;
				return (1);
			}
		}
		/* insert */
		wcp = ht->tbl[y];
		ht->tbl[y] = (CefT_Mem_Hash_Cell* )calloc (1, sizeof (CefT_Mem_Hash_Cell) + key_wo_cid_len);
		if (ht->tbl[y] == NULL) {
			return (-1);
		}
		ht->tbl[y]->key = ((unsigned char*)ht->tbl[y]) + sizeof (CefT_Mem_Hash_Cell);
		cp = ht->tbl[y];
		cp->next = wcp;
		cp->elem = elem;
		cp->klen = key_wo_cid_len;
		memcpy (cp->key, key_wo_cid, key_wo_cid_len);
		cp->cid_klen = cid_klen;
		memcpy (cp->cid_key, cid_key, cid_klen);
		ht->elem_num++;
		return (1);
	}
}
#endif // CefC_Nwproc

#ifndef CefC_Nwproc
static CsmgrdT_Content_Mem_Entry* 
cef_mem_hash_tbl_item_get (
	const unsigned char* key,
	uint32_t klen
) {
	CefT_Mem_Hash* ht = (CefT_Mem_Hash*) mem_hash_tbl;
	uint32_t hash = 0;
	uint32_t y;
	CefT_Mem_Hash_Cell* cp;

	if ((klen > MemC_Max_KLen) || (ht == NULL)) {
		return (NULL);
	}
	hash = cef_mem_hash_number_create (key, klen);
	y = hash % ht->tabl_max;

	cp = ht->tbl[y];
	if (cp == NULL) {
		return (NULL);
	} 
	for (; cp != NULL; cp = cp->next) {
		if ((cp->klen == klen) &&
		   (memcmp (cp->key, key, klen) == 0)) {
		   	return (cp->elem);
		}
	}
	
	return (NULL);
}
#else // CefC_Nwproc

static CsmgrdT_Content_Mem_Entry* 
cef_mem_hash_tbl_item_get (
	const unsigned char* key,
	uint32_t klen
) {
	CefT_Mem_Hash* ht = (CefT_Mem_Hash*) mem_hash_tbl;
	uint32_t hash = 0;
	uint32_t y;
	CefT_Mem_Hash_Cell* cp;
	unsigned char cid_key[MemC_CID_KLen];
	uint32_t cid_klen;
	unsigned char key_wo_cid[MemC_Max_KLen];
	unsigned int key_wo_cid_len;

	if ((klen > MemC_Max_KLen) || (ht == NULL)) {
		return (NULL);
	}
	cef_frame_separate_name_and_cid (
				(unsigned char *)key, klen, 
				key_wo_cid, &key_wo_cid_len, 
				cid_key, &cid_klen);

	hash = cef_mem_hash_number_create (key_wo_cid, key_wo_cid_len);
	y = hash % ht->tabl_max;

	cp = ht->tbl[y];
	if (cp == NULL) {
		return (NULL);
	} 
	for (; cp != NULL; cp = cp->next) {
		if ((cp->klen == key_wo_cid_len) &&
		   (cp->cid_klen == cid_klen) &&
		   (memcmp (cp->key, key_wo_cid, key_wo_cid_len) == 0) &&
		   (memcmp (cp->cid_key, cid_key, cid_klen) == 0)) {
				return (cp->elem);
		}
	}
	
	return (NULL);
}

static CsmgrdT_Content_Mem_Entry** 
cef_mem_hash_tbl_item_gets (
	const unsigned char* key,
	uint32_t klen,
	int* entry_num
) {
	CefT_Mem_Hash* ht = (CefT_Mem_Hash*) mem_hash_tbl;
	uint32_t hash = 0;
	uint32_t y;
	CefT_Mem_Hash_Cell* cp;
	unsigned char cid_key[MemC_CID_KLen];
	uint32_t cid_klen;
	unsigned char key_wo_cid[MemC_Max_KLen];
	unsigned int key_wo_cid_len;
	int elm_num = 0;
	CsmgrdT_Content_Mem_Entry** tmp_p;
	int i;

	*entry_num = 0;

	if ((klen > MemC_Max_KLen) || (ht == NULL)) {
		return (NULL);
	}
	
	cef_frame_separate_name_and_cid (
				(unsigned char *)key, klen, 
				key_wo_cid, &key_wo_cid_len, 
				cid_key, &cid_klen);
	hash = cef_mem_hash_number_create (key_wo_cid, key_wo_cid_len);
	y = hash % ht->tabl_max;

	cp = ht->tbl[y];
	if (cp == NULL) {
		return (NULL);
	} 

	if (cid_klen < CefC_NWP_CID_Prefix_Len) {
		for (; cp != NULL; cp = cp->next) {
			if ((cp->klen == key_wo_cid_len) &&
			   (memcmp (cp->key, key_wo_cid, key_wo_cid_len) == 0)) {
				elm_num++;
			}
		}
		tmp_p = (CsmgrdT_Content_Mem_Entry**)calloc (elm_num, sizeof (CsmgrdT_Content_Mem_Entry*));
		cp = ht->tbl[y];
		for (i = 0; cp != NULL; cp = cp->next) {
			if ((cp->klen == key_wo_cid_len) &&
			   (memcmp (cp->key, key_wo_cid, key_wo_cid_len) == 0)) {
				tmp_p[i] = cp->elem;
				i++;
			}
		}
		*entry_num = elm_num;
		return (tmp_p);
	}
	else {
		for (; cp != NULL; cp = cp->next) {
			if ((cp->klen == key_wo_cid_len) &&
			   (cp->cid_klen == cid_klen) &&
			   (memcmp (cp->key, key_wo_cid, key_wo_cid_len) == 0) &&
			   (memcmp (cp->cid_key, cid_key, cid_klen) == 0)) {
				tmp_p = (CsmgrdT_Content_Mem_Entry**)calloc (1, sizeof (CsmgrdT_Content_Mem_Entry*));
				*entry_num = 1;
				tmp_p[0] = cp->elem;
				return (tmp_p);
			}
		}
	}
	return (NULL);
}
#endif // CefC_Nwproc

#ifndef CefC_Nwproc
static CsmgrdT_Content_Mem_Entry* 
cef_mem_hash_tbl_item_remove (
	const unsigned char* key,
	uint32_t klen
) {
	CefT_Mem_Hash* ht = (CefT_Mem_Hash*) mem_hash_tbl;
	uint32_t hash = 0;
	uint32_t y;
	CsmgrdT_Content_Mem_Entry* ret_elem;
	CefT_Mem_Hash_Cell* cp;
	CefT_Mem_Hash_Cell* wcp;
	
	if ((klen > MemC_Max_KLen) || (ht == NULL)) {
		return (NULL);
	}
	
	hash = cef_mem_hash_number_create (key, klen);
	y = hash % ht->tabl_max;
	
	cp = ht->tbl[y];
	if (cp == NULL) {
		return (NULL);
	}
	if (cp != NULL) {
		if ((cp->klen == klen) &&
		   (memcmp (cp->key, key, klen) == 0)) {
		   	ht->tbl[y] = cp->next;
			ht->elem_num--;
		   	ret_elem = cp->elem;
		   	free (cp);
		   	return (ret_elem);
		} else {
			for (; cp->next != NULL; cp = cp->next) {
				if ((cp->next->klen == klen) &&
				   (memcmp (cp->next->key, key, klen) == 0)) {
				   	wcp = cp->next;
				   	cp->next = cp->next->next;
					ht->elem_num--;
				   	ret_elem = wcp->elem;
		   			free (wcp);
		   			return (ret_elem);
				}
			}
		}
	}
	
	return (NULL);
}

#else // CefC_Nwproc
static CsmgrdT_Content_Mem_Entry* 
cef_mem_hash_tbl_item_remove (
	const unsigned char* key,
	uint32_t klen
) {
	CefT_Mem_Hash* ht = (CefT_Mem_Hash*) mem_hash_tbl;
	uint32_t hash = 0;
	uint32_t y;
	CsmgrdT_Content_Mem_Entry* ret_elem;
	CefT_Mem_Hash_Cell* cp;
	CefT_Mem_Hash_Cell* wcp;
	unsigned char cid_key[MemC_CID_KLen];
	uint32_t cid_klen;
	unsigned char key_wo_cid[MemC_Max_KLen];
	unsigned int key_wo_cid_len;
	
	if ((klen > MemC_Max_KLen) || (ht == NULL)) {
		return (NULL);
	}
	
	cef_frame_separate_name_and_cid (
				(unsigned char *)key, klen, 
				key_wo_cid, &key_wo_cid_len, 
				cid_key, &cid_klen);

	hash = cef_mem_hash_number_create (key_wo_cid, key_wo_cid_len);
	y = hash % ht->tabl_max;
	
	cp = ht->tbl[y];
	if (cp == NULL) {
		return (NULL);
	}
	if (cp != NULL) {
		if ((cp->klen == key_wo_cid_len) &&
		   (cp->cid_klen == cid_klen) &&
		   (memcmp (cp->key, key_wo_cid, key_wo_cid_len) == 0) &&
		   (memcmp (cp->cid_key, cid_key, cid_klen) == 0)) {
			ht->tbl[y] = cp->next;
			ht->elem_num--;
			ret_elem = cp->elem;
			free (cp);
			return (ret_elem);
		} else {
			for (; cp->next != NULL; cp = cp->next) {
				if ((cp->next->klen == key_wo_cid_len) &&
				   (cp->next->cid_klen == cid_klen) &&
				   (memcmp (cp->next->key, key_wo_cid, key_wo_cid_len) == 0) &&
				    (memcmp (cp->next->cid_key, cid_key, cid_klen) == 0)) {
					wcp = cp->next;
					cp->next = cp->next->next;
					ht->elem_num--;
					ret_elem = wcp->elem;
		   			free (wcp);
		   			return (ret_elem);
				}
			}
		}
	}
	
	return (NULL);
}
#endif // CefC_Nwproc

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

int												/* length of the created key 			*/
csmgrd_key_create_by_Mem_Entry (
	CsmgrdT_Content_Mem_Entry* entry,
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

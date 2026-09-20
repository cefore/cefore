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
 * mem_cache.c
 */
#define __CSMGRD_MEM_CACHE_SOURCE__

//#define __MEMCACHE_VERSION__

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
#include <cefore/cef_hash.h>
#include <csmgrd/csmgrd_plugin.h>
#include <cefore/cef_valid.h>	/* for OpenSSL 3.x */
#include <cefore/cef_pthread.h>


/****************************************************************************************
 Macros
 ****************************************************************************************/

#ifdef __APPLE__
#define CsmgrdC_Library_Name	".dylib"
#else // __APPLE__
#define CsmgrdC_Library_Name	".so"
#endif // __APPLE__

#define MemC_Max_Buff 				4
#define MemC_Min_Buff				4
#define MemC_CID_HexCh_size			(MD5_DIGEST_LENGTH * 2)	/* Size to store binary CID   */
															/* converted to hex character */
#define MemC_CID_KLen				(CefC_S_TLF+CefC_NWP_CID_Prefix_Len+MemC_CID_HexCh_size)

#define MemC_SEMNAME					"/cefmemsem"

#define IDX_NAME					0
#define IDX_KEYID					1
#define IDX_MSGHASH					2

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/
typedef struct {

	/********** Content Object in mem cache		***********/
	unsigned char	*msg;						/* Message								*/
	uint16_t		msg_len;					/* Message length						*/
	unsigned char	*name;						/* Content name							*/
	uint16_t		name_len;					/* Content name length					*/
	CefT_HashData   keyid	;					/* KeyID 								*/
	uint16_t		keyid_len;					/* KeyID length 						*/
	CefT_HashData   MsgHash;					/* COB Hash 							*/
	uint16_t		MsgHash_len;				/* COB Hash length						*/
	uint16_t		pay_len;					/* Payload length						*/
	uint32_t		chunk_num;					/* Chunk num							*/
	uint64_t		cache_time;					/* Cache time							*/
	uint64_t		expiry;						/* Expiry								*/
	struct in_addr	node;						/* Node address							*/

	uint64_t		ins_time;					/* Insert time							*/
	uint64_t		hit_count;					/* Number of HITs per CobHash unit 		*/
} CsmgrdT_Content_Mem_Entry;

typedef struct CefT_Mem_Hash_Cell {

	uint32_t 					hash;
	unsigned char* 				key;
	uint32_t 					klen;
	CsmgrdT_Content_Mem_Entry* 	elem;
	struct CefT_Mem_Hash_Cell	*next;
} CefT_Mem_Hash_Cell;

typedef struct CefT_Mem_Hash {
	CefT_Mem_Hash_Cell**	tbl[3];
	uint32_t 				tabl_max;
} CefT_Mem_Hash;

/****************************************************************************************
 State Variables
 ****************************************************************************************/

static MemT_Cache_Handle* 		hdl = NULL;
static char 					csmgr_conf_dir[PATH_MAX] = {"/usr/local/cefore"};
static CefT_Mem_Hash* 			mem_hash_tbl = NULL;
static uint32_t 				mem_tabl_max = CefC_Default_Cache_Capacity;
static pthread_mutex_t 			mem_comn_buff_mutex[MemC_Max_Buff];
static sem_t*					mem_comn_buff_sem;
static pthread_t				mem_thread_th;
static int 						mem_thread_f = 0;
static CsmgrdT_Content_Entry* 	mem_proc_cob_buff[MemC_Max_Buff]		= {0};
static int 						mem_proc_cob_buff_idx[MemC_Max_Buff] 	= {0};
static CsmgrT_Stat_Handle 		csmgr_stat_hdl;
static pthread_t				mem_cache_delete_th;
static int						delete_pipe_fd[2];

static pthread_mutex_t 			mem_cs_mutex = PTHREAD_MUTEX_INITIALIZER;

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Init content store
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_cs_create (
	CsmgrT_Stat_Handle stat_hdl, int			//0.8.3c
);
/*--------------------------------------------------------------------------------------
	Destroy content store
----------------------------------------------------------------------------------------*/
static void
mem_cs_destroy (
//0.8.3c	void
	int		Last_Node_f
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
	int sock,									/* received socket						*/
	CsmgrdT_Plugin_APIparam_get *param			/* API parameters						*/
);

static CsmgrdT_Content_Mem_Entry*
mem_cache_item_get_msghash (
	CsmgrdT_Plugin_APIparam_get* param,
	int keyid_idx,
	unsigned char* trg_key,
	int* trg_key_len
);

static CsmgrdT_Content_Mem_Entry*
mem_cache_item_get_keyid (
	CsmgrdT_Plugin_APIparam_get* param,
	int keyid_idx,
	unsigned char* trg_key,
	int* trg_key_len
);

static CsmgrdT_Content_Mem_Entry*
mem_cache_item_get_name (
	CsmgrdT_Plugin_APIparam_get* param,
	unsigned char* trg_key,
	int* trg_key_len
);

static int
mem_cache_item_send (
	int sock,
	CsmgrdT_Content_Mem_Entry* entry,
	unsigned char* trg_key,
	int trg_key_len,
	int keyid_f
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
	int tbl_index,
	const unsigned char* key,
	uint32_t klen,
	CsmgrdT_Content_Mem_Entry* elem,
	CsmgrdT_Content_Mem_Entry **old_elem
);
static CsmgrdT_Content_Mem_Entry*
cef_mem_hash_tbl_item_get (
	int tbl_index,
	const unsigned char* key,
	uint32_t klen
);

static void
cef_mem_hash_tbl_item_remove_entry (
	CsmgrdT_Content_Mem_Entry* entry
);

static CsmgrdT_Content_Mem_Entry*
cef_mem_hash_tbl_item_remove (
	int tbl_index,
	const unsigned char* key,
	uint32_t klen
);

static int
mem_cache_delete_thread_create (
	void
);

static void *
mem_cache_delete_thread (
	void *p
);

int
mem_cache_cobhash_status_get (
	unsigned char* buf,
	uint32_t buf_size
);

int
mem_cache_index_status_get (
	unsigned char* buf,
	uint32_t buf_size
);

static int
cobhash_entry_compare (
	const void* a,
	const void* b
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
		mem_cache_item_puts, mem_cs_ac_cnt_inc, mem_cache_lifetime_get, mem_cache_cobhash_status_get, mem_cache_index_status_get);

	if (config_dir) {
		strcpy (csmgr_conf_dir, config_dir);
	}

	/* Init logging 	*/
	csmgrd_log_init ("memcache", 1);
	csmgrd_log_init2 (csmgr_conf_dir);
#ifdef CefC_Debug
	csmgrd_dbg_init ("memcache", csmgr_conf_dir);
#endif // CefC_Debug

	return (0);
}
/*--------------------------------------------------------------------------------------
	Init API
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_cs_create (
	CsmgrT_Stat_Handle stat_hdl, int first_node_f		//0.8.3c
) {
	MemT_Config_Param conf_param;
	int res, i;

	/* create handle 		*/
	if (hdl != NULL) {
		free (hdl);
		hdl = NULL;
	}

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

	if (cef_pthread_create (&mem_thread_th, NULL, mem_cob_process_thread, hdl) == -1) {
		csmgrd_log_write (CefC_Log_Error, "Failed to create the new thread\n");
		return (-1);
	}

	if (mem_cache_delete_thread_create () < 0) {
		return (-1);
	}

	csmgrd_log_write (CefC_Log_Info, "Start\n");
	csmgrd_log_write (CefC_Log_Info, "Cache Capacity : "FMTU64"\n", hdl->cache_capacity);
	if (strcmp (conf_param.algo_name, "None")) {
		csmgrd_log_write (CefC_Log_Info, "Library  : %s ... OK\n", hdl->algo_name);
	} else {
		csmgrd_log_write (CefC_Log_Info, "Library  : Not Specified\n");
	}

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

	mem_thread_f = 1;

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

#ifdef CefC_Debug
	csmgrd_dbg_write (CefC_Dbg_Fine, "%s terminate.\n", __func__);
#endif // CefC_Debug

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
	CsmgrdT_Content_Mem_Entry* old_entry;
	int key_len;
	unsigned char key[CefC_Csmgr_Key_Max];
	uint64_t 	nowt;
	struct timeval tv;

	/* Creates the key 		*/
	key_len = csmgrd_name_chunknum_concatenate (
		new_entry->name, new_entry->name_len, new_entry->chunk_num, key);

	if ( cef_mem_hash_tbl_item_get (IDX_NAME, key, key_len) != NULL) {
#ifdef CefC_Debug
char	buff_uri[CefC_NAME_MAXLEN];
cef_frame_conversion_name_to_uri(key, key_len, buff_uri);
csmgrd_dbg_write (CefC_Dbg_Fine, "%s(%d) %s, already cached.\n", __func__, __LINE__, buff_uri);
#endif	// CefC_Debug
		return (-1);
	}

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
	entry->chunk_num	 = new_entry->chunk_num;
	entry->cache_time	 = new_entry->cache_time;
	entry->expiry		 = new_entry->expiry;
	entry->node			 = new_entry->node;
	entry->ins_time		 = new_entry->ins_time;

	if (cef_mem_hash_tbl_item_set (
			IDX_NAME, key, key_len, entry, &old_entry) < 0) {
		if ( entry->msg != NULL )
			free (entry->msg);
		if ( entry->name != NULL )
			free (entry->name);
		free (entry);
#ifdef CefC_Debug
char	buff_uri[CefC_NAME_MAXLEN];
cef_frame_conversion_name_to_uri(key, key_len, buff_uri);
csmgrd_dbg_write (CefC_Dbg_Fine, "%s(%d) %s, cef_mem_hash_tbl_item_set failure.\n", __func__, __LINE__, buff_uri);
#endif	// CefC_Debug
		return (-1);
	}
	if ( old_entry != NULL ){
		if ( old_entry->msg != NULL )
			free (old_entry->msg);
		if ( old_entry->name != NULL )
			free (old_entry->name);
		free (old_entry);
	}

	/* Updates the content information 			*/
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;

	csmgrd_stat_cob_update( csmgr_stat_hdl, entry->name, entry->name_len,
		entry->chunk_num, entry->pay_len, entry->expiry, nowt, entry->node);

	hdl->cache_cobs++;

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

	entry = cef_mem_hash_tbl_item_remove ( IDX_NAME, key, key_len);

	if (entry) {
		csmgrd_stat_cob_remove (
			csmgr_stat_hdl, entry->name, entry->name_len,
			entry->chunk_num, entry->pay_len);
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
//0.8.3c	void
	int		Last_Node_f
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
		for (int tbl = 0; tbl < 3; tbl++) {
			for (i = 0 ; i < mem_hash_tbl->tabl_max ; i++) {
				CefT_Mem_Hash_Cell* cp = mem_hash_tbl->tbl[tbl][i];
				CefT_Mem_Hash_Cell* wcp;
				while (cp != NULL) {
					wcp = cp->next;
					if (tbl == IDX_MSGHASH) {
						free(cp->elem->msg);
						free(cp->elem->name);
						free(cp->elem);
					}

					free (cp);
					cp = wcp;
				}
			}
			free(mem_hash_tbl->tbl[tbl]);
		}
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
	uint64_t 	nowt;
	struct timeval tv;
	int n;
	unsigned char trg_key[CefC_Csmgr_Key_Max];
	int trg_key_len;

	if (pthread_mutex_trylock (&mem_cs_mutex) != 0) {
		return;
	}

	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;

	for (n = 0 ; n < mem_hash_tbl->tabl_max ; n++) {
		if (mem_hash_tbl->tbl[IDX_MSGHASH][n] == NULL) {
			continue;
		}
		{
			CefT_Mem_Hash_Cell* cp;
			CefT_Mem_Hash_Cell* wcp;
			cp = mem_hash_tbl->tbl[IDX_MSGHASH][n];
			for (; cp != NULL; cp = wcp) {
				entry = cp->elem;
				wcp = cp->next;
				if ((entry->cache_time < nowt) ||
					((entry->expiry != 0) && (entry->expiry < nowt))) {
					/* Removes the expiry cache entry 		*/
					cef_mem_hash_tbl_item_remove_entry(entry);
/*
#ifdef CefC_Debug
char	buff_uri[CefC_NAME_MAXLEN];
cef_frame_conversion_name_to_uri(trg_key, trg_key_len, buff_uri);
csmgrd_dbg_write (CefC_Dbg_Fine, "%s(%d) %s(key_len=%d), entry1=%p.\n", __func__, __LINE__, buff_uri, trg_key_len, entry1);
#endif	// CefC_Debug
*/
					if (hdl->algo_apis.erase) {
						trg_key_len = csmgrd_name_chunknum_concatenate (entry->name, entry->name_len, entry->chunk_num, trg_key);
						(*(hdl->algo_apis.erase))(trg_key, trg_key_len);
					}
					if ( !entry )
						continue;
					csmgrd_stat_cob_remove (
						csmgr_stat_hdl, entry->name, entry->name_len,
						entry->chunk_num, entry->pay_len);
					hdl->cache_cobs--;
					free (entry->msg);
					free (entry->name);
					free (entry);
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
	int sock,									/* received socket						*/
	CsmgrdT_Plugin_APIparam_get *param			/* API parameters						*/
) {
	CsmgrdT_Content_Mem_Entry* entry;
	unsigned char 	trg_key[CefC_Csmgr_Key_Max];
	int 			trg_key_len;
	int exist_f = CefC_Csmgr_Cob_NotExist;
	int i;

#ifdef __MEMCACHE_VERSION__
	fprintf (stderr, "--- mem_cache_item_get()\n");
#endif //__MEMCACHE_VERSION__

	/*------------------------------------------------------*/
	/* Search priority									  */
	/*   MsgHash -> KeyID -> Name						   */
	/*------------------------------------------------------*/

	/* MsgHash */
	if (param->ObjHashRestr_len > 0) {

		/* MsgHash + KeyID */
		if (param->KeyIdRestr_num > 0) {

			for (i = 0 ; i < param->KeyIdRestr_num ; i++) {

				entry = mem_cache_item_get_msghash( param, i, trg_key, &trg_key_len);

				if (entry == NULL)
					continue;

				if (mem_cache_item_send( sock, entry, trg_key, trg_key_len, 1) == CefC_Csmgr_Cob_Exist) {
					exist_f = CefC_Csmgr_Cob_Exist;
				}
			}
		}
		/* MsgHash only */
		else {
			entry = mem_cache_item_get_msghash( param, -1, trg_key, &trg_key_len);

			if (entry != NULL) {
				if (mem_cache_item_send( sock, entry, trg_key, trg_key_len, 0) == CefC_Csmgr_Cob_Exist) {
					exist_f = CefC_Csmgr_Cob_Exist;
				}
			}
		}
	}
	/* KeyID */
	else if (param->KeyIdRestr_num > 0) {

		for (i = 0 ; i < param->KeyIdRestr_num ; i++) {

			entry = mem_cache_item_get_keyid( param, i, trg_key, &trg_key_len);

			if (entry == NULL)
				continue;

			if (mem_cache_item_send( sock, entry, trg_key, trg_key_len, 1) == CefC_Csmgr_Cob_Exist) {
				exist_f = CefC_Csmgr_Cob_Exist;
			}
		}
	}
	/* Name */
	else {

		entry = mem_cache_item_get_name( param, trg_key, &trg_key_len);

		if (entry != NULL) {
			if (mem_cache_item_send( sock, entry, trg_key, trg_key_len, 0) == CefC_Csmgr_Cob_Exist) {
				exist_f = CefC_Csmgr_Cob_Exist;
			}
		}
	}

	if (exist_f != CefC_Csmgr_Cob_Exist) {
		if (hdl->algo_apis.miss) {
			(*(hdl->algo_apis.miss))(trg_key, trg_key_len);
		}
	}

	return (exist_f);
}

static CsmgrdT_Content_Mem_Entry*
mem_cache_item_get_msghash (
	CsmgrdT_Plugin_APIparam_get* param,
	int keyid_idx,
	unsigned char* trg_key,
	int* trg_key_len
) {
	CsmgrdT_Content_Mem_Entry* entry;

	*trg_key_len = MsgHash_index_key(
		&param->ObjHashRestr,
		param->ObjHashRestr_len,
		trg_key);

	entry = cef_mem_hash_tbl_item_get( IDX_MSGHASH, trg_key, *trg_key_len);

	if (entry == NULL){
#ifdef CefC_Debug
csmgrd_dbg_write( CefC_Dbg_Fine, "%s(%d) MsgHash cache miss (len=%u).\n", __func__, __LINE__, param->ObjHashRestr_len);
#endif
		return (NULL);
	}
	/* MsgHash only */
	if (keyid_idx < 0)
		return (entry);

	/* MsgHash + KeyID */
	if (entry->keyid_len != param->KeyIdRestr[keyid_idx].keyid_len){
#ifdef CefC_Debug
csmgrd_dbg_write( CefC_Dbg_Fine, "%s(%d) CobHash HIT but KeyID length mismatch " "(entry=%u, restrict=%u).\n", __func__, __LINE__, entry->keyid_len, param->KeyIdRestr[keyid_idx].keyid_len);
#endif
		return (NULL);
	}

	if (memcmp(
			&entry->keyid,
			&param->KeyIdRestr[keyid_idx].keyid,
			entry->keyid_len) != 0){
#ifdef CefC_Debug
csmgrd_dbg_write( CefC_Dbg_Fine, "%s(%d) CobHash HIT but KeyID mismatch.\n", __func__, __LINE__);
#endif
		return (NULL);
	}

	return (entry);
}

static CsmgrdT_Content_Mem_Entry*
mem_cache_item_get_keyid (
	CsmgrdT_Plugin_APIparam_get* param,
	int keyid_idx,
	unsigned char* trg_key,
	int* trg_key_len
) {
	CsmgrdT_Content_Mem_Entry* entry;

	*trg_key_len = keyid_index_key(
		param->name,
		param->name_len,
		&param->KeyIdRestr[keyid_idx].keyid,
		param->KeyIdRestr[keyid_idx].keyid_len,
		param->seqno,
		trg_key);

	entry = cef_mem_hash_tbl_item_get(
		IDX_KEYID,
		trg_key,
		*trg_key_len);

	if (entry != NULL) {
		if ((entry->keyid_len == param->KeyIdRestr[keyid_idx].keyid_len) &&
			(memcmp(
				&entry->keyid,
				&param->KeyIdRestr[keyid_idx].keyid,
				entry->keyid_len) == 0)) {
			return (entry);
		}
	}

#ifdef CefC_Debug
	{
		char buff_uri[CefC_NAME_MAXLEN];

		cef_frame_conversion_name_to_uri( param->name, param->name_len, buff_uri);

		csmgrd_dbg_write( CefC_Dbg_Fine, "%s(%d) KeyID cache miss %s " "(chunk=%u, keyid_idx=%d).\n", __func__, __LINE__, buff_uri, param->seqno, keyid_idx);
	}
#endif

	return (NULL);
}

static CsmgrdT_Content_Mem_Entry*
mem_cache_item_get_name (
	CsmgrdT_Plugin_APIparam_get* param,
	unsigned char* trg_key,
	int* trg_key_len
) {
	CsmgrdT_Content_Mem_Entry* entry;
#ifdef CefC_Debug
	char buff_uri[CefC_NAME_MAXLEN];
#endif

	*trg_key_len = name_index_key(
		param->name,
		param->name_len,
		param->seqno,
		trg_key);

	entry = cef_mem_hash_tbl_item_get(
		IDX_NAME,
		trg_key,
		*trg_key_len);

	if (entry == NULL) {
#ifdef CefC_Debug
cef_frame_conversion_name_to_uri( param->name, param->name_len, buff_uri);
csmgrd_dbg_write( CefC_Dbg_Fine, "%s(%d) Name cache miss %s (chunk=%u).\n", __func__, __LINE__, buff_uri, param->seqno);
#endif
		return (NULL);
	}

	return (entry);
}

static int
mem_cache_item_send (
	int sock,
	CsmgrdT_Content_Mem_Entry* entry,
	unsigned char* trg_key,
	int trg_key_len,
	int keyid_f
) {
	uint64_t nowt;
	struct timeval tv;

	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;

	if (((entry->expiry != 0) && (nowt >= entry->expiry)) || (nowt >= entry->cache_time)) {
#ifdef CefC_Debug
		csmgrd_dbg_write( CefC_Dbg_Fine,
			"%s(%d) Cache entry expired "
			"(chunk=%u, expiry=%" PRIu64 ", now=%" PRIu64 ").\n",
			__func__, __LINE__,
			entry->chunk_num,
			entry->expiry,
			nowt);
#endif
		return (CefC_Csmgr_Cob_NotExist);
	}

	entry->hit_count++;

	pthread_mutex_lock (&mem_cs_mutex);

	if (hdl->algo_apis.hit) {
		(*(hdl->algo_apis.hit))(trg_key, trg_key_len);
	}

	if (keyid_f) {
		csmgrd_stat_access_count_update_keyid( csmgr_stat_hdl, entry->name,entry->name_len, &entry->keyid, entry->keyid_len);
	}
	else {
		csmgrd_stat_access_count_update( csmgr_stat_hdl, entry->name, entry->name_len);
	}

	/* Send Cob to cefnetd */
	csmgrd_plugin_cob_msg_send( sock, entry->msg, entry->msg_len);
	pthread_mutex_unlock (&mem_cs_mutex);

	return (CefC_Csmgr_Cob_Exist);
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
	CsmgrdT_Content_Mem_Entry* old_entry;
	unsigned char 	trg_key[CefC_Csmgr_Key_Max];
	int 			trg_key_len = 0;
	int				name_key_len = 0;
	int				keyid_key_len = 0;
	int				MsgHash_key_len =0;
	uint64_t nowt;
	struct timeval tv;

#ifdef __MEMCACHE_VERSION__
	fprintf (stderr, "--- mem_cache_cob_write()\n");
#endif //__MEMCACHE_VERSION__

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
			trg_key_len = csmgrd_name_chunknum_concatenate (
				cobs[index].name, cobs[index].name_len, cobs[index].chunk_num, trg_key);
			entry = cef_mem_hash_tbl_item_get (IDX_NAME, trg_key, trg_key_len);
			if (entry == NULL) {
#ifdef __MEMCACHE_VERSION__
				fprintf (stderr, "  * new insert %u\n", cobs[index].chunk_num);
#endif //__MEMCACHE_VERSION__
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

			/* CobHash */
			if (cobs[index].MsgHash_len > 0) {
				MsgHash_key_len = MsgHash_index_key( &cobs[index].MsgHash, cobs[index].MsgHash_len, trg_key);
				if (cef_mem_hash_tbl_item_get( IDX_MSGHASH, trg_key, MsgHash_key_len ) != NULL) {
#ifdef CefC_Debug
char	buff_uri[CefC_NAME_MAXLEN];
cef_frame_conversion_name_to_uri(trg_key, MsgHash_key_len, buff_uri);
csmgrd_dbg_write (CefC_Dbg_Fine, "%s(%d) %s, already cached.\n", __func__, __LINE__, buff_uri);
#endif	// CefC_Debug
					free (cobs[index].msg);
					free (cobs[index].name);
					index++;
					continue;
				}
			}

			entry =
				(CsmgrdT_Content_Mem_Entry*) calloc (1, sizeof (CsmgrdT_Content_Mem_Entry));
			if (entry == NULL) {
				cef_log_write( CefC_Log_Error,
					"%s: calloc(CsmgrdT_Content_Mem_Entry) failed.\n",__func__);
				return (-1);
			}

			/* Inserts the cache entry 		*/
			entry->msg		= cobs[index].msg;
			entry->msg_len	= cobs[index].msg_len;
			entry->name		= cobs[index].name;
			entry->name_len	= cobs[index].name_len;
			entry->pay_len		 = cobs[index].pay_len;
			entry->chunk_num	 = cobs[index].chunk_num;
			entry->cache_time	 = cobs[index].cache_time;
			entry->expiry		 = cobs[index].expiry;
			entry->node			 = cobs[index].node;
			entry->ins_time		 = cobs[index].ins_time;
			entry->keyid       = cobs[index].keyid;
			entry->keyid_len   = cobs[index].keyid_len;
			entry->MsgHash    = cobs[index].MsgHash;
			entry->MsgHash_len= cobs[index].MsgHash_len;


#ifdef __MEMCACHE_VERSION__
			fprintf (stderr, "  * new insert %u\n", entry->chunk_num);
#endif //__MEMCACHE_VERSION__

/*----------------------------------------------------------*/
/* CobHash */
/*----------------------------------------------------------*/
			if (entry->MsgHash_len > 0) {
				if (cef_mem_hash_tbl_item_set (
						IDX_MSGHASH, trg_key, MsgHash_key_len, entry, &old_entry) < 0) {

#ifdef CefC_Debug
char hash_str[256];
int pos = 0;
for (int i = 0; i < MsgHash_key_len && pos < sizeof(hash_str) - 4; i++) {
	pos += snprintf(
		&hash_str[pos],
		sizeof(hash_str) - pos,
		"%02X ",
		trg_key[i]);
}

csmgrd_dbg_write( CefC_Dbg_Finer,"%s(%d) CobHash=%s already cached.\n",__func__, __LINE__, hash_str);
#endif	// CefC_Debug
					goto ERROR;
				}
#ifdef CefC_Debug
csmgrd_dbg_write( CefC_Dbg_Finer, "%s(%d) CobHash entry inserted.\n", __func__, __LINE__);
#endif
			}

/*----------------------------------------------------------*/
/* KeyID */
/*----------------------------------------------------------*/
			if ((entry->name != NULL) && (entry->name_len > 0) && (entry->keyid_len > 0)) {
				keyid_key_len = keyid_index_key( entry->name, entry->name_len, &entry->keyid, entry->keyid_len, entry->chunk_num, trg_key);
				old_entry = cef_mem_hash_tbl_item_get( IDX_KEYID, trg_key, keyid_key_len);
				if (old_entry != NULL) {
#ifdef CefC_Debug
char buff_uri[CefC_NAME_MAXLEN];

cef_frame_conversion_name_to_uri( entry->name, entry->name_len, buff_uri);

csmgrd_dbg_write( CefC_Dbg_Fine, "%s(%d) Name + KeyID already cached, " "skip insert: %s (chunk=%u).\n", __func__, __LINE__, buff_uri, entry->chunk_num);
#endif	// CefC_Debug
				}else{
					if (cef_mem_hash_tbl_item_set ( IDX_KEYID, trg_key, keyid_key_len, entry, &old_entry) < 0) {

#ifdef CefC_Debug
char key_str[512];
int pos = 0;

for (int i = 0; i < keyid_key_len && pos < sizeof(key_str) - 4; i++) {
	pos += snprintf(
		&key_str[pos],
		sizeof(key_str) - pos,
		"%02X ",
		trg_key[i]);
}

csmgrd_dbg_write( CefC_Dbg_Finer ,"%s(%d) KeyIDKey=%s cef_mem_hash_tbl_item_set failure.\n",__func__, __LINE__, key_str);
#endif	// CefC_Debug
						goto ERROR;
					}
#ifdef CefC_Debug
csmgrd_dbg_write( CefC_Dbg_Finer, "%s(%d) KeyID entry inserted.\n", __func__, __LINE__);
#endif
					csmgrd_stat_cob_update_keyid( csmgr_stat_hdl, entry->name, entry->name_len,
						(entry->keyid_len > 0) ? &entry->keyid : NULL, entry->keyid_len,
						entry->chunk_num, entry->pay_len, entry->expiry, nowt, entry->node);
				}
			}

/*----------------------------------------------------------*/
/* Name */
/*----------------------------------------------------------*/
			if ((entry->name != NULL) && (entry->name_len > 0)) {
				name_key_len = name_index_key( entry->name, entry->name_len, entry->chunk_num, trg_key);
				old_entry = cef_mem_hash_tbl_item_get( IDX_NAME, trg_key, name_key_len);
				if (old_entry != NULL) {
#ifdef CefC_Debug
char buff_uri[CefC_NAME_MAXLEN];
cef_frame_conversion_name_to_uri( entry->name, entry->name_len, buff_uri);

csmgrd_dbg_write(CefC_Dbg_Fine, "%s(%d) Name + chunk already cached, " "skip insert: %s (chunk=%u).\n", __func__, __LINE__, buff_uri, entry->chunk_num);
#endif	// CefC_Debug
				}else{
					if (cef_mem_hash_tbl_item_set (
							IDX_NAME, trg_key, name_key_len, entry, &old_entry) < 0) {
						if ( entry->msg != NULL )
							free (entry->msg);
						if ( entry->name != NULL )
							free (entry->name);
						free (entry);
#ifdef CefC_Debug
char	buff_uri[CefC_NAME_MAXLEN];
cef_frame_conversion_name_to_uri(trg_key, name_key_len, buff_uri);
csmgrd_dbg_write (CefC_Dbg_Fine, "%s(%d) %s, cef_mem_hash_tbl_item_set failure.\n", __func__, __LINE__, buff_uri);
#endif	// CefC_Debug
						goto ERROR;
					}
				/* Updates the content information 			*/
					csmgrd_stat_cob_update( csmgr_stat_hdl, entry->name, entry->name_len,
						entry->chunk_num, entry->pay_len, entry->expiry, nowt, entry->node);
				}
			}

			hdl->cache_cobs++;
		}
		index++;
		continue;

ERROR:

		cef_mem_hash_tbl_item_remove_entry( entry );
		if (entry->msg)
			free(entry->msg);

		if (entry->name)
			free(entry->name);

		free(entry);

		return (-1);
	}
#ifdef CefC_Debug
csmgrd_dbg_write( CefC_Dbg_Finer, "%s(%d) Name entry inserted.\n", __func__, __LINE__);
#endif
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

	entry = cef_mem_hash_tbl_item_get ( IDX_NAME, key, key_size);
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
	params->cache_capacity = CefC_Default_Cache_Capacity;
	strcpy (params->algo_name, "None");
	params->algo_name_size = 256;
	params->algo_cob_size = 2048;

	/* Obtains the directory path where the csmgrd's config file is located. */
#if 0 //+++++ GCC v9 +++++
	sprintf (file_name, "%s/csmgrd.conf", csmgr_conf_dir);
#else
	int sn = snprintf (file_name, sizeof(file_name), "%s/csmgrd.conf", csmgr_conf_dir);
	if (sn < 0) {
		csmgrd_log_write (CefC_Log_Error, "[%s] Config file dir path too long(%s)\n", __func__, csmgr_conf_dir);
		return (-1);
	}
#endif //-----  GCC v9 -----

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
			if (params->cache_capacity > CefC_Default_Cache_Capacity) {
				csmgrd_log_write (CefC_Log_Error,
				"Cache capacity value must be less than or equal to %d when using algorithm lfu.\n", CefC_Default_Cache_Capacity);
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
		unsigned char trg_key[CefC_Csmgr_Key_Max];
		int trg_key_len;
		uint64_t oldest_ins_time;
		uint64_t first_expire;

//0.8.3c		rcd = csmgr_stat_content_info_get (csmgr_stat_hdl, name, name_len);
		rcd = csmgrd_stat_content_info_get (csmgr_stat_hdl, name, name_len);	//0.8.3c
		if (!rcd || rcd->expire_f) {
			return (-1);
		}

		oldest_ins_time = nowt;
		first_expire = UINT64_MAX;

		for (idx = rcd->min_seq; idx <= rcd->max_seq; idx++) {
			trg_key_len = csmgrd_name_chunknum_concatenate (name, name_len, idx, trg_key);
			entry = cef_mem_hash_tbl_item_get ( IDX_NAME, trg_key, trg_key_len);
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
		entry = cef_mem_hash_tbl_item_get ( IDX_NAME, name, name_len);
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
		table_size = table_size * CefC_Hash_Coef_Cache;
		if (table_size > INT32_MAX){
			table_size = INT32_MAX;
		}
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

	for (int i = 0; i < 3; i++) {
		ht->tbl[i] = (CefT_Mem_Hash_Cell**) calloc (sizeof (CefT_Mem_Hash_Cell*), table_size);

		if (ht->tbl[i] == NULL) {
			while (--i >= 0) {
				free(ht->tbl[i]);
			}
			free(ht);
			return (NULL);
		}
	}
	//memset (ht->tbl, 0, sizeof (CefT_Mem_Hash_Cell*) * table_size);

	srand ((unsigned) time (NULL));
	ht->tabl_max = table_size;
	mem_tabl_max = ht->tabl_max;

	return (ht);
}

static int
cef_mem_hash_tbl_item_set (
	int tbl_index,
	const unsigned char* key,
	uint32_t klen,
	CsmgrdT_Content_Mem_Entry* elem,
	CsmgrdT_Content_Mem_Entry **old_elem
) {
	CefT_Mem_Hash* ht = (CefT_Mem_Hash*) mem_hash_tbl;
	uint32_t hash = 0;
	uint32_t y;
	CefT_Mem_Hash_Cell* cp;
	CefT_Mem_Hash_Cell* wcp;

	if ( old_elem )
		*old_elem = NULL;
	hash = cef_mem_hash_number_create(key, klen);
	y = hash % ht->tabl_max;

	if (ht->tbl[tbl_index][y] == NULL) {
		ht->tbl[tbl_index][y] = (CefT_Mem_Hash_Cell*)calloc( 1, sizeof(CefT_Mem_Hash_Cell) + klen);
		if (ht->tbl[tbl_index][y] == NULL)
			return (-1);

		ht->tbl[tbl_index][y]->key = ((unsigned char*)ht->tbl[tbl_index][y]) + sizeof(CefT_Mem_Hash_Cell);
		cp = ht->tbl[tbl_index][y];
		cp->elem = elem;
		cp->klen = klen;
		memcpy(cp->key, key, klen);
		return (1);
	} else {
		/* exist check & replace */
		for (cp = ht->tbl[tbl_index][y]; cp != NULL; cp = cp->next) {
			if ((cp->klen == klen) &&
			   (memcmp (cp->key, key, klen) == 0)) {
				if ( old_elem )
					*old_elem = cp->elem;
				cp->elem = elem;
				return (1);
		   }
		}
		/* insert */
		wcp = ht->tbl[tbl_index][y];

		ht->tbl[tbl_index][y] = (CefT_Mem_Hash_Cell*)calloc( 1, sizeof(CefT_Mem_Hash_Cell) + klen);

		if (ht->tbl[tbl_index][y] == NULL)
			return (-1);

		ht->tbl[tbl_index][y]->key = ((unsigned char*)ht->tbl[tbl_index][y]) + sizeof(CefT_Mem_Hash_Cell);
		cp = ht->tbl[tbl_index][y];
		cp->next = wcp;
		cp->elem = elem;
		cp->klen = klen;
		memcpy(cp->key, key, klen);

		return (1);
	}
}

static CsmgrdT_Content_Mem_Entry*
cef_mem_hash_tbl_item_get (
	int tbl_index,
	const unsigned char* key,
	uint32_t klen
) {
	CefT_Mem_Hash* ht = (CefT_Mem_Hash*) mem_hash_tbl;
	uint32_t hash = 0;
	uint32_t y;
	CefT_Mem_Hash_Cell* cp;

	if ((klen > CefC_Csmgr_Key_Max) || (ht == NULL)) {
		return (NULL);
	}
	hash = cef_mem_hash_number_create (key, klen);
	y = hash % ht->tabl_max;

	cp = ht->tbl[tbl_index][y];
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

static void
cef_mem_hash_tbl_item_remove_entry (
	CsmgrdT_Content_Mem_Entry* entry
)
{
	unsigned char 	trg_key[CefC_Csmgr_Key_Max];
	int				name_key_len;
	int				keyid_key_len;
	int				MsgHash_key_len;

	/*------------------------------*/
	/* CobHash                      */
	/*------------------------------*/
	if (entry->MsgHash_len > 0) {

		MsgHash_key_len =
			MsgHash_index_key(
				&entry->MsgHash,
				entry->MsgHash_len,
				trg_key);

		if (cef_mem_hash_tbl_item_get(
				IDX_MSGHASH,
				trg_key,
				MsgHash_key_len) == entry) {

			cef_mem_hash_tbl_item_remove(
				IDX_MSGHASH,
				trg_key,
				MsgHash_key_len);
		}
	}

	/*------------------------------*/
	/* KeyID                        */
	/*------------------------------*/
	if ((entry->name_len > 0) &&
		(entry->keyid_len > 0)) {

		keyid_key_len =
			keyid_index_key(
				entry->name,
				entry->name_len,
				&entry->keyid,
				entry->keyid_len,
				entry->chunk_num,
				trg_key);

		if (cef_mem_hash_tbl_item_get(
				IDX_KEYID,
				trg_key,
				keyid_key_len) == entry) {

			cef_mem_hash_tbl_item_remove(
				IDX_KEYID,
				trg_key,
				keyid_key_len);
		}
	}

	/*------------------------------*/
	/* Name                         */
	/*------------------------------*/
	if (entry->name_len > 0) {

		name_key_len =
			name_index_key(
				entry->name,
				entry->name_len,
				entry->chunk_num,
				trg_key);

		if (cef_mem_hash_tbl_item_get(
				IDX_NAME,
				trg_key,
				name_key_len) == entry) {

			cef_mem_hash_tbl_item_remove(
				IDX_NAME,
				trg_key,
				name_key_len);
		}
	}
}

static CsmgrdT_Content_Mem_Entry*
cef_mem_hash_tbl_item_remove (
	int tbl_index,
	const unsigned char* key,
	uint32_t klen
) {
	CefT_Mem_Hash* ht = (CefT_Mem_Hash*) mem_hash_tbl;
	uint32_t hash = 0;
	uint32_t y;
	CsmgrdT_Content_Mem_Entry* ret_elem;
	CefT_Mem_Hash_Cell* cp;
	CefT_Mem_Hash_Cell* wcp;

	if ((klen > CefC_Csmgr_Key_Max) || (ht == NULL)) {
		return (NULL);
	}

	hash = cef_mem_hash_number_create (key, klen);
	y = hash % ht->tabl_max;

	cp = ht->tbl[tbl_index][y];
	if (cp == NULL) {
		return (NULL);
	}
	if (cp != NULL) {
		if ((cp->klen == klen) &&
			(memcmp (cp->key, key, klen) == 0)) {
			ht->tbl[tbl_index][y] = cp->next;
			ret_elem = cp->elem;
			free (cp);
			return (ret_elem);
		} else {
			for (; cp->next != NULL; cp = cp->next) {
				if ((cp->next->klen == klen) &&
					(memcmp (cp->next->key, key, klen) == 0)) {
					wcp = cp->next;
					cp->next = cp->next->next;
					ret_elem = wcp->elem;
					free (wcp);
					return (ret_elem);
				}
			}
		}
	}

	return (NULL);
}


static uint32_t
cef_mem_hash_number_create (
	const unsigned char* key,
	uint32_t klen
) {
	uint32_t hash;
	unsigned char out[MD5_DIGEST_LENGTH];

//	MD5 (key, klen, out);
	cef_valid_md5( key, klen, out );	/* for Openssl 3.x */
	memcpy (&hash, &out[12], sizeof (uint32_t));

	return (hash);
}

static int
mem_cache_delete_thread_create (
	void
) {
	int flags;

	/* Create delete thread */
	delete_pipe_fd[0] = -1;
	delete_pipe_fd[1] = -1;

	if (socketpair(AF_UNIX,SOCK_DGRAM, 0, delete_pipe_fd) == -1 ) {
		cef_log_write (CefC_Log_Error, "%s pair socket creation error (%s)\n"
						, __func__, strerror(errno));
		return (-1);
	}
	/* Set caller side socket as non-blocking I/O */
	if ((flags = fcntl(delete_pipe_fd[0], F_GETFL, 0) ) < 0) {
		cef_log_write (CefC_Log_Error, "%s fcntl error (%s)\n"
						, __func__, strerror(errno));
		return (-1);
	}
	flags |= O_NONBLOCK;
	if (fcntl(delete_pipe_fd[0], F_SETFL, flags) < 0) {
		cef_log_write (CefC_Log_Error, "%s fcntl error (%s)\n"
						, __func__, strerror(errno));
		return (-1);
	}

	if (cef_pthread_create(&mem_cache_delete_th, NULL
					, &mem_cache_delete_thread, &(delete_pipe_fd[1])) == -1) {
		cef_log_write (CefC_Log_Error
						, "%s Failed to create the new thread(mem_cache_delete_thread)\n"
						, __func__);
		return (-1);
	}

	return (1);
}

static void *
mem_cache_delete_thread (
	void *p
) {
	int 					read_fd;
	struct pollfd 			fds[1];
	CsmgrT_Stat*			stat_p;
	unsigned char			buff[CefC_Max_Length*3];
	int						n;
	CsmgrdT_Content_Mem_Entry* entry = NULL;
	uint32_t				min_seq, max_seq;

	read_fd = *(int *)p;
	pthread_t self_thread = pthread_self();
	pthread_detach(self_thread);

	memset(&fds, 0, sizeof(fds));
	fds[0].fd = read_fd;
	fds[0].events = POLLIN | POLLERR;

	while (1){
		poll (fds, 1, 1);
		if (fds[0].revents & POLLIN) {
			unsigned char		del_name[CefC_Max_Length] = {0};
			uint16_t			del_name_len;
			if (read (read_fd, buff, sizeof(CsmgrT_Stat)) < sizeof(CsmgrT_Stat)) {
				continue;
			}

			stat_p = (CsmgrT_Stat*)buff;
			min_seq = stat_p->min_seq;
			max_seq = stat_p->max_seq;
			del_name_len = stat_p->name_len;
			memcpy (del_name, stat_p->name, stat_p->name_len);

			pthread_mutex_lock (&mem_cs_mutex);

#ifdef __MEMCACHE_VERSION__
			fprintf (stderr, "--- mem_cache_delete_thread()\n");
#endif //__MEMCACHE_VERSION__

			for (n = min_seq; n < max_seq; n++) {
				unsigned char 	trg_key[CefC_Csmgr_Key_Max];
				int 			trg_key_len;

				/* Creates the key */
				trg_key_len = csmgrd_name_chunknum_concatenate (del_name, del_name_len, n, trg_key);

				entry = cef_mem_hash_tbl_item_remove ( IDX_NAME, trg_key, trg_key_len);
				if (entry) {
					if (hdl->algo_apis.erase) {
						(*(hdl->algo_apis.erase))(trg_key, trg_key_len);
					}
					hdl->cache_cobs--;
					free (entry->msg);
					free (entry->name);
					free (entry);
				}
			}
#ifdef __MEMCACHE_VERSION__
			fprintf (stderr, "  + (*) cache_cobs="FMTU64"\n", hdl->cache_cobs);
#endif //__MEMCACHE_VERSION__
			pthread_mutex_unlock (&mem_cs_mutex);
		}
	}

	pthread_exit (NULL);
	return 0;
}

int
mem_cache_cobhash_status_get (
	unsigned char* buf,
	uint32_t buf_size
) {
	CefT_Mem_Hash* ht;
	CefT_Mem_Hash_Cell* cell;
	CsmgrdT_Content_Mem_Entry* entry;
	CsmgrdT_Content_Mem_Entry** entries;

	uint32_t i;
	uint32_t entry_num = 0;
	uint32_t entry_max = 0;
	uint32_t pos = 0;
	uint32_t no = 1;
	uint64_t nowt;
	struct timeval tv;

	if ((buf == NULL) || (buf_size == 0)) {
		return (-1);
	}

	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;

	ht = (CefT_Mem_Hash*) mem_hash_tbl;

	if (ht == NULL) {
		return (-1);
	}

	for (i = 0; i < ht->tabl_max; i++) {
		cell = ht->tbl[IDX_MSGHASH][i];

		while (cell != NULL) {
			if (cell->elem != NULL) {
				entry_num++;
			}

			cell = cell->next;
		}
	}

	if (entry_num == 0) {
		pos += snprintf (
			(char*)&buf[pos],
			buf_size - pos,
			"#No: Name,chunknum,CobHash,payload_size,Freshness,Elapsed Time,HitCount\n"
		);

		return ((int)pos);
	}

	entries = (CsmgrdT_Content_Mem_Entry**)
		calloc (entry_num, sizeof(CsmgrdT_Content_Mem_Entry*));

	if (entries == NULL) {
		return (-1);
	}

	entry_max = 0;

	for (i = 0; i < ht->tabl_max; i++) {
		cell = ht->tbl[IDX_MSGHASH][i];
		while (cell != NULL) {
			entry = cell->elem;

			if (entry != NULL) {
				entries[entry_max] = entry;
				entry_max++;
			}
			cell = cell->next;
		}
	}

	/* Sort */
	/* Name -> Chunk Number -> CobHash */
	qsort ( entries, entry_max, sizeof(CsmgrdT_Content_Mem_Entry*), cobhash_entry_compare );
	/* Header */
	pos += snprintf (
		(char*)&buf[pos],
		buf_size - pos,
		"#No: Name,chunknum,CobHash,payload_size,Freshness,Elapsed Time,HitCount\n"
	);

	if (pos >= buf_size) {
		free (entries);
		return ((int)buf_size);
	}

	/* Output entries */
	for (i = 0; i < entry_max; i++) {
		entry = entries[i];
		uint64_t freshness;
		uint64_t elapsed;
		char uri[CefC_NAME_MAXLEN];

		if (entry->expiry > nowt) {
			freshness = (entry->expiry - nowt) / 1000000;
		} else {
			freshness = 0;
		}

		if (nowt > entry->ins_time) {
			elapsed = (nowt - entry->ins_time) / 1000000;
		} else {
			elapsed = 0;
		}

		if (cef_frame_conversion_name_to_uri ( entry->name, entry->name_len, uri) < 0) {
			uri[0] = '\0';
		}

		pos += snprintf (
			(char*)&buf[pos],
			buf_size - pos,
			"%u: %s,%u,0x",
			no,
			uri,
			entry->chunk_num
		);

		if (pos >= buf_size) {
			free (entries);
			return ((int)pos);
		}

		for (uint16_t j = 0; j < entry->MsgHash.hash_length; j++) {
			if (pos >= buf_size) {
				free (entries);
				return ((int)pos);
			}
			pos += snprintf ( (char*)&buf[pos], buf_size - pos, "%02x", entry->MsgHash.hash_value[j] );
		}
		if (pos >= buf_size) {
			free (entries);
			return ((int)pos);
		}
		pos += snprintf (
			(char*)&buf[pos],
			buf_size - pos,
			",%u,%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
			entry->pay_len,
			freshness,
			elapsed,
			entry->hit_count
		);
		if (pos >= buf_size) {
			free (entries);
			return ((int)pos);
		}
		no++;
	}
	free (entries);
	return ((int)pos);
}

static int
cobhash_entry_compare (
	const void* a,
	const void* b
) {
	const CsmgrdT_Content_Mem_Entry* ea =
		*(const CsmgrdT_Content_Mem_Entry**)a;
	const CsmgrdT_Content_Mem_Entry* eb =
		*(const CsmgrdT_Content_Mem_Entry**)b;

	int cmp;

	/* Name */
	if (ea->name_len != eb->name_len) {
		int min_len = (ea->name_len < eb->name_len) ?
			ea->name_len : eb->name_len;

		cmp = memcmp(ea->name, eb->name, min_len);

		if (cmp != 0) {
			return (cmp);
		}

		return (ea->name_len < eb->name_len) ? -1 : 1;
	}

	cmp = memcmp(ea->name, eb->name, ea->name_len);

	if (cmp != 0) {
		return (cmp);
	}

	/* Chunk Number */
	if (ea->chunk_num < eb->chunk_num) {
		return (-1);
	}

	if (ea->chunk_num > eb->chunk_num) {
		return (1);
	}

	/* CobHash */
	if (ea->MsgHash.hash_length != eb->MsgHash.hash_length) {
		return (ea->MsgHash.hash_length < eb->MsgHash.hash_length) ?
			-1 : 1;
	}

	return (memcmp(
		ea->MsgHash.hash_value,
		eb->MsgHash.hash_value,
		ea->MsgHash.hash_length));
}

int
mem_cache_index_status_get (
	unsigned char* buf,
	uint32_t buf_size
) {
	CefT_Mem_Hash* ht;
	CefT_Mem_Hash_Cell* cell;

	uint32_t i;
	uint32_t name_num = 0;
	uint32_t keyid_num = 0;
	uint32_t cobhash_num = 0;
	uint32_t pos = 0;

	if ((buf == NULL) || (buf_size == 0)) {
		return (-1);
	}

	ht = (CefT_Mem_Hash*) mem_hash_tbl;

	if (ht == NULL) {
		return (-1);
	}

	/* Name Index */
	for (i = 0; i < ht->tabl_max; i++) {
		cell = ht->tbl[IDX_NAME][i];

		while (cell != NULL) {
			if (cell->elem != NULL) {
				name_num++;
			}

			cell = cell->next;
		}
	}

	/* KeyID Index */
	for (i = 0; i < ht->tabl_max; i++) {
		cell = ht->tbl[IDX_KEYID][i];

		while (cell != NULL) {
			if (cell->elem != NULL) {
				keyid_num++;
			}

			cell = cell->next;
		}
	}

	/* CobHash Index */
	for (i = 0; i < ht->tabl_max; i++) {
		cell = ht->tbl[IDX_MSGHASH][i];

		while (cell != NULL) {
			if (cell->elem != NULL) {
				cobhash_num++;
			}

			cell = cell->next;
		}
	}

	/* Header */
	pos += snprintf (
		(char*)&buf[pos],
		buf_size - pos,
		"#Index,Entries\n"
	);

	if (pos >= buf_size) {
		return ((int)pos);
	}

	/* Name Index */
	pos += snprintf (
		(char*)&buf[pos],
		buf_size - pos,
		"Name,%u\n",
		name_num
	);

	if (pos >= buf_size) {
		return ((int)pos);
	}

	/* KeyID Index */
	pos += snprintf (
		(char*)&buf[pos],
		buf_size - pos,
		"KeyID,%u\n",
		keyid_num
	);

	if (pos >= buf_size) {
		return ((int)pos);
	}

	/* CobHash Index */
	pos += snprintf (
		(char*)&buf[pos],
		buf_size - pos,
		"CobHash,%u\n",
		cobhash_num
	);

	if (pos >= buf_size) {
		return ((int)pos);
	}

	return ((int)pos);
}
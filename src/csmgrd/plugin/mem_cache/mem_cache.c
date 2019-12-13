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

#define MemC_Max_Conntent_Num 		512
#define MemC_Max_KLen 				1024
#define MemC_Max_Buff 				32

#define MEM_TABLE_MAX 				4

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

typedef struct CefT_Hash_Table {
	
	uint32_t 				hash;
	unsigned char 			key[MemC_Max_KLen];
	uint32_t 				klen;
	CsmgrdT_Content_Entry* 	elem;
	
} CefT_Mem_Hash_Table;


typedef struct CefT_Hash {
	
	uint32_t 				seed;
	CefT_Mem_Hash_Table**	tbl;
	uint32_t 				tabl_max;
	uint32_t 				elem_max;
	uint32_t 				elem_num;
	
} CefT_Mem_Hash;

/****************************************************************************************
 State Variables
 ****************************************************************************************/

static MemT_Cache_Handle* 		hdl = NULL;
static char 					csmgr_conf_dir[PATH_MAX] = {"/usr/local/cefore"};
static CefT_Mem_Hash* 			mem_hash_tbl = NULL;
static uint32_t 				mem_tabl_max = 65536;
static pthread_mutex_t 			mem_comn_buff_mutex[MemC_Max_Buff];
static pthread_t				mem_thread;
static int 						mem_thread_f = 0;
static CsmgrdT_Content_Entry* 	mem_proc_cob_buff[MemC_Max_Buff]		= {0};
static int 						mem_proc_cob_buff_idx[MemC_Max_Buff] 	= {0};
static CsmgrT_Stat_Handle 		csmgr_stat_hdl;

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
#endif // CefC_Ccore

/*--------------------------------------------------------------------------------------
	Hash APIs for Memory Cahce Plugin
----------------------------------------------------------------------------------------*/
static CefT_Mem_Hash*
cef_mem_hash_tbl_create (
	uint32_t table_size
);
static uint32_t
cef_mem_hash_number_create (
	uint32_t hash,
	const unsigned char* key,
	uint32_t klen
);
static int 
cef_mem_hash_tbl_item_set (
	const unsigned char* key,
	uint32_t klen,
	CsmgrdT_Content_Entry* elem, 
	CsmgrdT_Content_Entry* old_elem
);
static CsmgrdT_Content_Entry* 
cef_mem_hash_tbl_item_get (
	const unsigned char* key,
	uint32_t klen
);
static CsmgrdT_Content_Entry* 
cef_mem_hash_tbl_item_remove (
	const unsigned char* key,
	uint32_t klen
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
	CSMGRD_SET_CALLBACKS(
		mem_cs_create, mem_cs_destroy, mem_cs_expire_check, mem_cache_item_get,
		mem_cache_item_puts, mem_cs_ac_cnt_inc);
	
#ifdef CefC_Ccore
	cs_in->cache_cap_set 		= mem_change_cap;
	cs_in->content_lifetime_set = mem_cache_set_lifetime;
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
	
	/* create handle 		*/
	if (hdl != NULL) {
		free (hdl);
		hdl = NULL;
	}

	/* Init logging 	*/
	csmgrd_log_init ("memcache");
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
	hdl->capacity = conf_param.capacity;
	
	/* Creates the memory cache 		*/
	mem_hash_tbl = cef_mem_hash_tbl_create ((uint32_t) hdl->capacity);
	if (mem_hash_tbl ==  NULL) {
		csmgrd_log_write (CefC_Log_Error, "create mem hash table\n");
		return (-1);
	}
	
	/* Loads the library for cache algorithm 		*/
	if (strcmp (conf_param.algo_name, "None")) {
		sprintf (hdl->algo_name, "%s%s", conf_param.algo_name, CsmgrdC_Library_Name);
		res = csmgrd_lib_api_get (
			hdl->algo_name, &hdl->algo_lib, &hdl->algo_apis);
		
		if (res < 0) {
			csmgrd_log_write (CefC_Log_Error, "load the lib (%s)\n", hdl->algo_name);
			return (-1);
		}
		
		if (hdl->algo_apis.init) {
			(*(hdl->algo_apis.init))(hdl->capacity, mem_cs_store, mem_cs_remove);
		}
	}
	
	for (i = 0 ; i < MemC_Max_Buff ; i++) {
		mem_proc_cob_buff[i] = (CsmgrdT_Content_Entry*) 
			malloc (sizeof (CsmgrdT_Content_Entry) * CsmgrC_Buff_Num);
		if (mem_proc_cob_buff[i] == NULL) {
			csmgrd_log_write (CefC_Log_Info, 
				"Failed to allocation process cob buffer\n");
			return (-1);
		}
		mem_proc_cob_buff_idx[i] = 0;
		pthread_mutex_init (&mem_comn_buff_mutex[i], NULL);
	}
	
	if (pthread_create (&mem_thread, NULL, mem_cob_process_thread, hdl) == -1) {
		csmgrd_log_write (CefC_Log_Info, "Failed to create the new thread\n");
		return (-1);
	}
	mem_thread_f = 1;
	
	csmgrd_log_write (CefC_Log_Info, "Start\n");
	csmgrd_log_write (CefC_Log_Info, "Capacity : %d\n", hdl->capacity);
	if (strcmp (conf_param.algo_name, "None")) {
		csmgrd_log_write (CefC_Log_Info, "Library  : %s\n", hdl->algo_name);
	} else {
		csmgrd_log_write (CefC_Log_Info, "Library  : Not Specified\n");
	}
	csmgr_stat_hdl = stat_hdl;
	csmgrd_stat_cache_capacity_update (csmgr_stat_hdl, hdl->capacity);
	
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
		for (i = 0 ; i < MemC_Max_Buff ; i++) {
			pthread_mutex_lock (&mem_comn_buff_mutex[i]);
			if (mem_proc_cob_buff_idx[i] > 0) {
#ifdef CefC_Debug
				csmgrd_dbg_write (CefC_Dbg_Fine, 
					"cob put thread starts to write %d cobs\n", mem_proc_cob_buff_idx[i]);
#endif // CefC_Debug
				mem_cache_cob_write (&mem_proc_cob_buff[i][0], mem_proc_cob_buff_idx[i]);
				mem_proc_cob_buff_idx[i] = 0;
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
	CsmgrdT_Content_Entry* entry;
	CsmgrdT_Content_Entry* old_entry = NULL;
	int key_len;
	unsigned char key[65535];
	uint64_t 	nowt;
	struct timeval tv;
	
	/* Creates the key 		*/
	key_len = csmgrd_key_create (new_entry, key);
	
	/* Creates the entry 		*/
	entry = (CsmgrdT_Content_Entry*) calloc (1, sizeof (CsmgrdT_Content_Entry));
	if (entry == NULL) {
		return (-1);
	}
	memcpy (entry, new_entry, sizeof (CsmgrdT_Content_Entry));
	
	if (cef_mem_hash_tbl_item_set (key, key_len, entry, old_entry) < 0) {
		free (entry);
		return (-1);
	}
	
	/* Updates the content information 			*/
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000 + tv.tv_usec;
	
	csmgrd_stat_cob_update (csmgr_stat_hdl, entry->name, entry->name_len, 
		entry->chnk_num, entry->pay_len, entry->expiry, nowt, entry->node);
	
	if (old_entry) {
		csmgrd_stat_cob_remove (csmgr_stat_hdl, old_entry->name, 
			old_entry->name_len, old_entry->chnk_num, old_entry->pay_len);
		free (old_entry);
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
	CsmgrdT_Content_Entry* entry;
	
	/* Removes the specified entry 	*/
	entry = cef_mem_hash_tbl_item_remove (key, key_len);
	
	if (entry) {
		csmgrd_stat_cob_remove (
			csmgr_stat_hdl, entry->name, entry->name_len, 
			entry->chnk_num, entry->pay_len);
		free (entry);
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

	if (mem_thread_f) {
		mem_thread_f = 0;
		pthread_join (mem_thread, &status);
	}
	
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
		for (i = 0 ; i < MEM_TABLE_MAX ; i++) {
			free (mem_hash_tbl->tbl[i]);
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
	CsmgrdT_Content_Entry* entry = NULL;
	uint64_t 	nowt;
	struct timeval tv;
	int i, n;
	unsigned char trg_key[65535];
	int trg_key_len;
	
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000 + tv.tv_usec;
	
	for (i = 0 ; i < MEM_TABLE_MAX ; i++) {
		for (n = 0 ; n < mem_hash_tbl->elem_max ; n++) {
			if (mem_hash_tbl->tbl[i][n].hash == 0) {
				continue;
			}
			entry = mem_hash_tbl->tbl[i][n].elem;
			
			if ((entry->cache_time < nowt) ||
				((entry->expiry != 0) && (entry->expiry < nowt))) {
				
				if (hdl->algo_apis.erase) {
					trg_key_len = csmgrd_key_create (entry, trg_key);
					(*(hdl->algo_apis.erase))(trg_key, trg_key_len);
				}
				csmgrd_stat_cob_remove (
					csmgr_stat_hdl, entry->name, entry->name_len, 
					entry->chnk_num, entry->pay_len);
				
				free (entry);
				mem_hash_tbl->tbl[i][n].hash = 0;
				mem_hash_tbl->tbl[i][n].klen = 0;
				mem_hash_tbl->tbl[i][n].elem = NULL;
			}
		}
	}
	
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
	CsmgrdT_Content_Entry* entry;
	unsigned char 	trg_key[CsmgrdC_Key_Max];
	int 			trg_key_len;
	uint64_t 		nowt;
	struct timeval 	tv;
	
	/* Creates the key 		*/
	trg_key_len = csmgrd_name_chunknum_concatenate (key, key_size, seqno, trg_key);
	
	/* Access the specified entry 	*/
	entry = cef_mem_hash_tbl_item_get (trg_key, trg_key_len);
	
	if (entry) {
		
		gettimeofday (&tv, NULL);
		nowt = tv.tv_sec * 1000000 + tv.tv_usec;
		
		if (((entry->expiry == 0) || (nowt < entry->expiry)) &&
			(nowt < entry->cache_time)) {
			if (hdl->algo_apis.hit) {
				(*(hdl->algo_apis.hit))(trg_key, trg_key_len);
			}
			
			if (entry->chnk_num == 0) {
				csmgrd_stat_access_count_update (
					csmgr_stat_hdl, entry->name, entry->name_len);
			}
			
			/* Send Cob to cefnetd */
			csmgrd_plugin_cob_msg_send (sock, entry->msg, entry->msg_len);
			return (CefC_Csmgr_Cob_Exist);
 		} else {
			/* Removes the expiry cache entry 		*/
			entry = cef_mem_hash_tbl_item_remove (trg_key, trg_key_len);
			
			if (hdl->algo_apis.erase) {
				(*(hdl->algo_apis.erase))(entry->name, entry->name_len);
			}
			
			csmgrd_stat_cob_remove (
				csmgr_stat_hdl, entry->name, entry->name_len, 
				entry->chnk_num, entry->pay_len);
			
			free (entry);
		}
	}
	
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
	
#ifdef CefC_Debug
	csmgrd_dbg_write (CefC_Dbg_Fine, "cob rcv thread receives %d bytes\n", msg_len);
#endif // CefC_Debug
	
	for (i = 0 ; i < MemC_Max_Buff ; i++) {
		
		pthread_mutex_lock (&mem_comn_buff_mutex[i]);
		
		if (mem_proc_cob_buff_idx[i] == 0) {
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
		
		pthread_mutex_unlock (&mem_comn_buff_mutex[i]);
		usleep (100000);
		
		if (index >= msg_len) {
			break;
		}
	}
	
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
	CsmgrdT_Content_Entry* entry;
	CsmgrdT_Content_Entry* old_entry = NULL;
	unsigned char 	trg_key[CsmgrdC_Key_Max];
	int 			trg_key_len;
	uint64_t nowt;
	struct timeval tv;
	
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000 + tv.tv_usec;
	
	while (index < cob_num) {
		
		if (hdl->algo_apis.insert) {
			trg_key_len = csmgrd_key_create (&cobs[index], trg_key);
			entry = cef_mem_hash_tbl_item_get (trg_key, trg_key_len);
			if (entry == NULL) {
				(*(hdl->algo_apis.insert))(&cobs[index]);
			}
		} else {
			/* Caches the content entry without the cache algorithm library 	*/
			entry = 
				(CsmgrdT_Content_Entry*) calloc (1, sizeof (CsmgrdT_Content_Entry));
			if (entry == NULL) {
				return (-1);
			}
			
			/* Creates the key 				*/
			trg_key_len = csmgrd_name_chunknum_concatenate (
							cobs[index].name, cobs[index].name_len, 
							cobs[index].chnk_num, trg_key);
			
			/* Inserts the cache entry 		*/
			memcpy (entry, &cobs[index], sizeof (CsmgrdT_Content_Entry));
			
			if (cef_mem_hash_tbl_item_set (
				trg_key, trg_key_len, entry, old_entry) < 0) {
				free (entry);
				return (-1);
			}
			
			/* Updates the content information 			*/
			csmgrd_stat_cob_update (csmgr_stat_hdl, entry->name, entry->name_len, 
				entry->chnk_num, entry->pay_len, entry->expiry, nowt, entry->node);
			
			if (old_entry) {
				csmgrd_stat_cob_remove (csmgr_stat_hdl, old_entry->name, 
					old_entry->name_len, 
					old_entry->chnk_num, old_entry->pay_len);
				free (old_entry);
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
	CsmgrdT_Content_Entry* entry;
	
	entry = cef_mem_hash_tbl_item_get (key, key_size);
	if (!entry) {
		return;
	}
	
	if (hdl->algo_apis.hit) {
		(*(hdl->algo_apis.hit))(key, key_size);
	}
	
	if ((seq_num == 0) && (entry->chnk_num == 0)) {
		csmgrd_stat_access_count_update (
			csmgr_stat_hdl, entry->name, entry->name_len);
	}
	
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
	
	char	param[128] = {0};						/* parameter						*/
	char	param_buff[128] = {0};					/* param buff						*/
	int		len;									/* read length						*/
	
	char*	option;									/* deny option						*/
	char*	value;									/* parameter						*/
	
	int		i, n;
	
	/* Inits parameters		*/
	memset (params, 0, sizeof (MemT_Config_Param));
	params->capacity = 65536;
	strcpy (params->algo_name, "libcsmgrd_lru");
	
	/* Obtains the directory path where the cefnetd's config file is located. */
	sprintf (file_name, "%s/csmgrd.conf", csmgr_conf_dir);
	
	/* Opens the config file. */
	fp = fopen (file_name, "r");
	if (fp == NULL) {
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
		
		if(value == NULL){
			continue;
		}
		
		/* Records a parameter 			*/
		if (strcmp (option, "CACHE_ALGORITHM") == 0) {
			strcpy (params->algo_name, value);
		} else if (strcmp (option, "CACHE_CAPACITY") == 0) {
			params->capacity = atoi (value);
			
			if ((params->capacity < 1) || (params->capacity > 819200)) {
				csmgrd_log_write (CefC_Log_Error, 
				"CACHE_CAPACITY must be higher than 0 and lower than 819,200.\n");
				return (-1);
			}
		} else {
			/* NOP */;
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
	int i, n;
	
	if (cap > 819200) {
		/* Too large */
		return (-1);
	}
	
	/* Recreate algorithm lib */
	if (hdl->algo_lib) {
		if (hdl->algo_apis.destroy) {
			(*(hdl->algo_apis.destroy))();
		}
		if (hdl->algo_apis.init) {
			(*(hdl->algo_apis.init))(cap, mem_cs_store, mem_cs_remove);
		}
	}
	
	/* Change cap */
	hdl->capacity = cap;
	csmgrd_stat_cache_capacity_update (csmgr_stat_hdl, (uint32_t) cap);
	
	/* Destroy table */
	for (i = 0 ; i < MEM_TABLE_MAX ; i++) {
		for (n = 0 ; n < mem_hash_tbl->elem_max ; n++) {
			if (mem_hash_tbl->tbl[i][n].hash) {
				free (mem_hash_tbl->tbl[i][n].elem);
			}
		}
		free (mem_hash_tbl->tbl[i]);
	}
	free (mem_hash_tbl);
	
	/* Create table */
	mem_hash_tbl = cef_mem_hash_tbl_create ((uint32_t) hdl->capacity);
	if (mem_hash_tbl ==  NULL) {
		csmgrd_log_write (CefC_Log_Error, "create mem hash table\n");
		return (-1);
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
	CsmgrdT_Content_Entry* entry = NULL;
	uint64_t nowt;
	struct timeval tv;
	uint64_t new_life;
	int i, n;
	
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000 + tv.tv_usec;
	new_life = nowt + lifetime * 1000000;
	
	/* Updtes the content information */
	csmgrd_stat_content_lifetime_update (csmgr_stat_hdl, name, name_len, new_life);
	
	/* Check the cache entry information */
	for (i = 0 ; i < MEM_TABLE_MAX ; i++) {
		for (n = 0 ; n < mem_hash_tbl->elem_max ; n++) {
			if (mem_hash_tbl->tbl[i][n].hash == 0) {
				continue;
			}
			entry = mem_hash_tbl->tbl[i][n].elem;
			
			if (((entry->expiry == 0) || (nowt < entry->expiry)) &&
				(nowt < entry->cache_time)) {
				
				if (memcmp (name, entry->name, name_len)) {
					continue;
				}
				
				if ((entry->expiry == 0) || (new_life < entry->expiry)) {
					entry->expiry = new_life;
				}
				
				if (new_life < entry->cache_time) {
					entry->cache_time = new_life;
				}
			}
		}
	}
	
	return (0);
}
#endif // CefC_Ccore

/****************************************************************************************
 ****************************************************************************************/

static CefT_Mem_Hash*
cef_mem_hash_tbl_create (
	uint32_t table_size
) {
	CefT_Mem_Hash* ht = NULL;
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
		return (NULL);
	}
	
	ht = (CefT_Mem_Hash*) malloc (sizeof (CefT_Mem_Hash));
	if (ht == NULL) {
		return (NULL);
	}
	memset (ht, 0, sizeof (CefT_Mem_Hash));
	
	ht->tbl = (CefT_Mem_Hash_Table**) malloc (sizeof (CefT_Mem_Hash_Table*) * 8);
	
	for (i = 0 ; i < MEM_TABLE_MAX ; i++) {
		ht->tbl[i] = 
			(CefT_Mem_Hash_Table*) malloc (sizeof (CefT_Mem_Hash_Table) * table_size);
		if (ht->tbl[i]  == NULL) {
			for (n = 0 ; n < i ; n++) {
				free (ht->tbl[i]);
			}
			free (ht->tbl);
			free (ht);
			return (NULL);
		}
		memset (ht->tbl[i], 0, sizeof (CefT_Mem_Hash_Table) * table_size);
	}
	
	srand ((unsigned) time (NULL));
	ht->seed = (uint32_t)(rand () + 1);
	ht->elem_max = table_size;
	ht->tabl_max = table_size * MEM_TABLE_MAX;
	mem_tabl_max = ht->tabl_max;
	
	return (ht);
}

static int 
cef_mem_hash_tbl_item_set (
	const unsigned char* key,
	uint32_t klen,
	CsmgrdT_Content_Entry* elem, 
	CsmgrdT_Content_Entry* old_elem
) {
	CefT_Mem_Hash* ht = (CefT_Mem_Hash*) mem_hash_tbl;
	uint32_t hash = 0;
	uint32_t x, y ,z;
	uint32_t i;
	
	if ((klen > MemC_Max_KLen) || (ht == NULL)) {
		return (-1);
	}
	old_elem = NULL;
	
	hash = cef_mem_hash_number_create (ht->seed, key, klen);
	z = hash % ht->tabl_max;
	x = z / ht->elem_max;
	y = z % ht->elem_max;
	
	if (ht->tbl[x][y].hash) {
		for (i = y + 1 ; i < ht->elem_max ; i++) {
			if (ht->tbl[x][i].hash == 0) {
				y = i;
				break;
			}
		}
		if (i == ht->elem_max) {
			old_elem = ht->tbl[x][y].elem;
		}
	} else {
		ht->elem_num++;
		
		if (ht->elem_num > ht->elem_max) {
			ht->elem_num = ht->elem_max;
			return (-1);
		}
	}
	ht->tbl[x][y].hash = hash;
	ht->tbl[x][y].elem = elem;
	ht->tbl[x][y].klen = klen;
	memcpy (ht->tbl[x][y].key, key, klen);
	
	return (1);
}

static CsmgrdT_Content_Entry* 
cef_mem_hash_tbl_item_get (
	const unsigned char* key,
	uint32_t klen
) {
	CefT_Mem_Hash* ht = (CefT_Mem_Hash*) mem_hash_tbl;
	uint32_t hash = 0;
	uint32_t x, y ,z;
	uint32_t i;
	
	if ((klen > MemC_Max_KLen) || (ht == NULL)) {
		return (NULL);
	}
	
	hash = cef_mem_hash_number_create (ht->seed, key, klen);
	z = hash % ht->tabl_max;
	x = z / ht->elem_max;
	y = z % ht->elem_max;
	
	if (ht->tbl[x][y].hash == hash) {
		if ((ht->tbl[x][y].klen == klen) && 
			(memcmp (key, ht->tbl[x][y].key, klen) == 0)) {
			return (ht->tbl[x][y].elem);
		}
	}
	
	for (i = y + 1 ; i < ht->elem_max ; i++) {
		if ((ht->tbl[x][i].klen == klen) && 
			(memcmp (key, ht->tbl[x][i].key, klen) == 0)) {
			return (ht->tbl[x][i].elem);
		}
	}
	
	return (NULL);
}

static CsmgrdT_Content_Entry* 
cef_mem_hash_tbl_item_remove (
	const unsigned char* key,
	uint32_t klen
) {
	CefT_Mem_Hash* ht = (CefT_Mem_Hash*) mem_hash_tbl;
	uint32_t hash = 0;
	uint32_t x, y ,z;
	uint32_t i;
	
	if ((klen > MemC_Max_KLen) || (ht == NULL)) {
		return (NULL);
	}
	
	hash = cef_mem_hash_number_create (ht->seed, key, klen);
	z = hash % ht->tabl_max;
	x = z / ht->elem_max;
	y = z % ht->elem_max;
	
	if (ht->tbl[x][y].hash == hash) {
		if ((ht->tbl[x][y].klen == klen) && 
			(memcmp (key, ht->tbl[x][y].key, klen) == 0)) {
			
			ht->tbl[x][y].hash = 0;
			ht->tbl[x][y].klen = 0;
			ht->elem_num--;
			return (ht->tbl[x][y].elem);
		}
	}
	
	for (i = y + 1 ; i < ht->elem_max ; i++) {
		if ((ht->tbl[x][i].klen == klen) && 
			(memcmp (key, ht->tbl[x][i].key, klen) == 0)) {
			ht->tbl[x][i].hash = 0;
			ht->tbl[x][i].klen = 0;
			ht->elem_num--;
			return (ht->tbl[x][i].elem);
		}
	}
	
	return (NULL);
}

static uint32_t
cef_mem_hash_number_create (
	uint32_t hash,
	const unsigned char* key,
	uint32_t klen
) {
	unsigned char out[MD5_DIGEST_LENGTH];
	
	MD5 (key, klen, out);
	memcpy (&hash, &out[12], sizeof (uint32_t));
	
	return (hash);
}


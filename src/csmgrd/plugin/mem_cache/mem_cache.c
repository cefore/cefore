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

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

typedef struct {
	
	unsigned char	name[CefC_Max_Msg_Size];	/* Content Name							*/
	uint16_t		name_len;				/* Name Length								*/
	uint64_t		access_cnt;				/* Access count of Content					*/
	uint64_t		insert_time;			/* time that Content inserted				*/
	uint64_t		expiry;					/* The time at which the content expires	*/
	uint64_t		cache_time;				/* Recommended Cache Time					*/
	uint32_t		cache_num;				/* Cache Num								*/
	uint64_t		size;					/* content Size								*/
	u_int32_t 		min_seq_num;			/* min sequence number						*/
	u_int32_t 		max_seq_num;			/* max sequence number						*/
	u_int32_t 		snd_seq_num;
	struct in_addr	node;					/* Node address								*/
	
} MemT_Content_Entry;

/****************************************************************************************
 State Variables
 ****************************************************************************************/
static MemT_Cache_Handle* hdl = NULL;						/* Memory Cache Handle		*/
static int total_cob_num = 0;
static MemT_Ch_Pid_List child_pid_list[MemC_Max_Child_Num];
static char csmgr_conf_dir[PATH_MAX] = {"/usr/local/cefore"};

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Init content store
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_cs_create (
	void
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
	Function to read a ContentObject from FileSystem Cache
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_cache_item_get (
	unsigned char* key,							/* content name							*/
	uint16_t key_size,							/* content name Length					*/
	uint32_t seqno,								/* chunk num							*/
	int sock									/* received socket						*/
);
/*--------------------------------------------------------------------------------------
	Upload content entry
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_cache_item_put (
	CsmgrdT_Content_Entry* entry				/* content entry						*/
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

#ifdef CefC_Conping
/*--------------------------------------------------------------------------------------
	Check presence of cache
----------------------------------------------------------------------------------------*/
static int					/* It returns the negative value or NotExist if not found.	*/
mem_content_exist_check (
	unsigned char* name,						/* content name							*/
	uint16_t name_len							/* content name length					*/
);
#endif // CefC_Conping

#ifdef CefC_Contrace
/*--------------------------------------------------------------------------------------
	Create the cache information
----------------------------------------------------------------------------------------*/
static int							/* number of returned caches						*/
mem_cache_info_get (
	int* total_len,										/* length of returned status	*/
	char uris[CefstatC_MaxUri][265],					/* record created cache name	*/
	CefstatT_Cache stat[CefstatC_MaxUri]				/* record created cache status	*/
);
#endif // CefC_Contrace

/*--------------------------------------------------------------------------------------
	Read config file
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_config_read (
	MemT_Config_Param* conf_param				/* Fsc config parameter					*/
);

/*--------------------------------------------------------------------------------------
	Get Csmgrd status
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_stat_get (
	char* stat,									/* String of FS Cache status			*/
	uint16_t* stat_len,							/* String length						*/
	uint8_t cache_f,							/* Cache request flag					*/
	char uris[CefC_Csmgr_Stat_MaxUri][265],		/* Content URI							*/
	CefT_Csmgrd_Stat_Cache* cache,				/* Content information					*/
	uint16_t* cache_len							/* Length of content information		*/
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
	Send cob to cefnetd
----------------------------------------------------------------------------------------*/
static void
mem_cache_cob_send (
	unsigned char* key,							/* content name							*/
	uint16_t key_len,							/* content name Length					*/
	uint32_t seqno,								/* chunk num							*/
	int sock									/* received socket						*/
);
/*--------------------------------------------------------------------------------------
	Search free element
----------------------------------------------------------------------------------------*/
static int
mem_free_pid_index_search (
	void
);
/*--------------------------------------------------------------------------------------
	Check child pid list
----------------------------------------------------------------------------------------*/
static int
mem_child_pid_list_check (
	unsigned char* key,							/* content name							*/
	uint16_t key_len,							/* content name Length					*/
	uint32_t seqno,								/* chunk num							*/
	int sock									/* received socket						*/
);
/*--------------------------------------------------------------------------------------
	set SIGCHLD
----------------------------------------------------------------------------------------*/
static void
setup_SIGCHLD (
	void
);
/*--------------------------------------------------------------------------------------
	catch SIGCHLD
----------------------------------------------------------------------------------------*/
static void
catch_SIGCHLD (
	int sig
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
		mem_cache_item_put, mem_stat_get, mem_cs_ac_cnt_inc);
#ifdef CefC_Contrace
	cs_in->cache_info_get = mem_cache_info_get;
#endif // CefC_Contrace
#ifdef CefC_Conping
	cs_in->content_exist_check = mem_content_exist_check;
#endif // CefC_Conping
	cs_in->cache_content_get = NULL;
	
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
	void
) {
	MemT_Config_Param conf_param;
	int res;
	
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
	total_cob_num = 0;
	
	/* Reads config 		*/
	if (mem_config_read (&conf_param) < 0) {
		csmgrd_log_write (CefC_Log_Error, "[%s] read config\n", __func__);
		return (-1);
	}
	hdl->capacity = conf_param.capacity;
	
	/* Creates the memory cache 		*/
	hdl->mem_cache_table = cef_hash_tbl_create ((uint32_t) hdl->capacity);
	if (hdl->mem_cache_table == (CefT_Hash_Handle) NULL) {
		csmgrd_log_write (CefC_Log_Error, "create cob hash table\n");
		return (-1);
	}
	
	/* Creates the Content table 	*/
	hdl->mem_con_table = cef_hash_tbl_create (MemC_Max_Conntent_Num);
	if (hdl->mem_con_table == (CefT_Hash_Handle) NULL) {
		csmgrd_log_write (CefC_Log_Error, "create content hash table\n");
		return (-1);
	}
	
	/* Loads the library for cache algorithm 		*/
	if (conf_param.algo_name[0]) {
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
	
	csmgrd_log_write (CefC_Log_Info, "Start\n");
	csmgrd_log_write (CefC_Log_Info, "Capacity : %d\n", hdl->capacity);
	if (conf_param.algo_name[0]) {
		csmgrd_log_write (CefC_Log_Info, "Library  : %s\n", hdl->algo_name);
	} else {
		csmgrd_log_write (CefC_Log_Info, "Library  : Not Specified\n");
	}
	
	/* Sets SIGCHLD 		*/
	setup_SIGCHLD ();

	return (0);
}

/*--------------------------------------------------------------------------------------
	Store API
----------------------------------------------------------------------------------------*/
static int 
mem_cs_store (
	CsmgrdT_Content_Entry* entry
) {
	
	MemT_Content_Entry* con_entry;
	CsmgrdT_Content_Entry* cache_entry;
	int res, key_len;
	unsigned char key[65535];
	uint64_t 	nowt;
	struct timeval tv;
	int  new_insert_f = 1;
	
	/* Creates the key 		*/
	key_len = csmgrd_key_create (entry, key);
	
	/* Destroy the old entry if it exists 		*/
	cache_entry = cef_hash_tbl_item_remove (hdl->mem_cache_table, key, key_len);
	if (cache_entry) {
		free (cache_entry);
		new_insert_f = 0;
	} else {
		if (total_cob_num >= hdl->capacity) {
			return (-1);
		}
	}
	
	/* Creates the entry 		*/
	cache_entry = (CsmgrdT_Content_Entry*) calloc (1, sizeof (CsmgrdT_Content_Entry));
	if (cache_entry == NULL) {
		return (-1);
	}
	memcpy (cache_entry, entry, sizeof (CsmgrdT_Content_Entry));
	
	/* Stores the content entry to cache 		*/
	res = cef_hash_tbl_item_set (hdl->mem_cache_table, key, key_len, cache_entry);
	
	if (res < 0) {
		free (cache_entry);
		return (-1);
	}
	total_cob_num++;
	
	/* Updates the content information 			*/
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000 + tv.tv_usec;
	
	con_entry = (MemT_Content_Entry*) 
		cef_hash_tbl_item_get (hdl->mem_con_table, entry->name, entry->name_len);
	
	if (con_entry == NULL) {
		con_entry = (MemT_Content_Entry*) malloc (sizeof (MemT_Content_Entry));
		if (con_entry == NULL) {
			return (-1);
		}
		memcpy (con_entry->name, entry->name, entry->name_len);
		con_entry->name_len 	= entry->name_len;
		con_entry->access_cnt	= 0;
		con_entry->insert_time 	= nowt;
		con_entry->expiry 		= entry->expiry;
		con_entry->cache_time 	= entry->cache_time;
		con_entry->cache_num 	= 0;
		con_entry->size 		= 0;
		con_entry->min_seq_num 	= entry->chnk_num;
		con_entry->max_seq_num 	= entry->chnk_num;
		con_entry->snd_seq_num 	= 0;
		con_entry->node 		= entry->node;
		
		cef_hash_tbl_item_set (
			hdl->mem_con_table, entry->name, entry->name_len, con_entry);
	}
	
	if (entry->expiry < con_entry->expiry) {
		con_entry->expiry = entry->expiry;
	}
	if (entry->cache_time < con_entry->cache_time) {
		con_entry->cache_time = entry->cache_time;
	}
	if (entry->chnk_num < con_entry->min_seq_num) {
		con_entry->min_seq_num = entry->chnk_num;
	}
	if (entry->chnk_num > con_entry->max_seq_num) {
		con_entry->max_seq_num = entry->chnk_num;
	}
	
	if (new_insert_f) {
		con_entry->cache_num++;
		con_entry->size += entry->pay_len;
	}
	
	return (res);
}

/*--------------------------------------------------------------------------------------
	Remove API
----------------------------------------------------------------------------------------*/
static void
mem_cs_remove (
	unsigned char* key, 
	int key_len
) {
	CsmgrdT_Content_Entry* cache_entry;
	MemT_Content_Entry* con_entry;
	
	/* Removes the specified entry 	*/
	cache_entry = cef_hash_tbl_item_remove (hdl->mem_cache_table, key, key_len);
	total_cob_num--;
	
	if (cache_entry) {
		/* Updates the content information 			*/
		con_entry = (MemT_Content_Entry*) 
			cef_hash_tbl_item_get (hdl->mem_con_table, 
				cache_entry->name, cache_entry->name_len);
		
		if (con_entry) {
			con_entry->cache_num--;
			con_entry->size -= cache_entry->pay_len;
			
			if (con_entry->cache_num == 0) {
				con_entry = (MemT_Content_Entry*) 
					cef_hash_tbl_item_remove (hdl->mem_con_table, 
						cache_entry->name, cache_entry->name_len);
				free (con_entry);
			}
		}
		free (cache_entry);
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
	
	if (hdl == NULL) {
		return;
	}
	
	if (hdl->mem_cache_table) {
		cef_hash_tbl_destroy (hdl->mem_cache_table);
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
	CsmgrdT_Content_Entry* cache_entry = NULL;
	MemT_Content_Entry* con_entry;
	uint32_t 	index = 0;
	uint64_t 	nowt;
	struct timeval tv;
	int i;
	unsigned char trg_key[65535];
	int trg_key_len;
	
	/* Checks table num */
	if (total_cob_num == 0) {
		return;
	}
	
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000 + tv.tv_usec;
	
	/* Checks content freshness */
	for (i = 0; i < total_cob_num ; i++) {
		cache_entry = 
			(CsmgrdT_Content_Entry*) cef_hash_tbl_elem_get (hdl->mem_cache_table, &index);
		if (cache_entry == NULL) {
			break;
		}
		
		if ((cache_entry->cache_time < nowt) ||
			((cache_entry->expiry != 0) && (cache_entry->expiry < nowt))) {
			/* Removes the expiry cache entry 		*/
			cache_entry = (CsmgrdT_Content_Entry*) 
				cef_hash_tbl_item_remove_from_index (hdl->mem_cache_table, index);
			total_cob_num--;
			
			if (hdl->algo_apis.erase) {
				trg_key_len = csmgrd_key_create (cache_entry, trg_key);
				(*(hdl->algo_apis.erase))(trg_key, trg_key_len);
			}
			
			/* Updates the content information 			*/
			con_entry = (MemT_Content_Entry*) 
				cef_hash_tbl_item_get (hdl->mem_con_table, 
					cache_entry->name, cache_entry->name_len);
			
			if (con_entry) {
				con_entry->cache_num--;
				con_entry->size -= cache_entry->pay_len;
				
				if (con_entry->cache_num == 0) {
					con_entry = (MemT_Content_Entry*) 
						cef_hash_tbl_item_remove (hdl->mem_con_table, 
							cache_entry->name, cache_entry->name_len);
					free (con_entry);
				}
			}
			free (cache_entry);
		}
		index++;
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
	CsmgrdT_Content_Entry* cache_entry;
	MemT_Content_Entry* con_entry;
	unsigned char 	trg_key[CsmgrdC_Key_Max];
	int 			trg_key_len;
	uint64_t 		nowt;
	struct timeval 	tv;
	
	/* Creates the key 		*/
	trg_key_len = csmgrd_name_chunknum_concatenate (key, key_size, seqno, trg_key);
	
	/* Access the specified entry 	*/
	cache_entry = cef_hash_tbl_item_get (hdl->mem_cache_table, trg_key, trg_key_len);
	if (cache_entry) {
		
		gettimeofday (&tv, NULL);
		nowt = tv.tv_sec * 1000000 + tv.tv_usec;
		
		if (((cache_entry->expiry == 0) || (nowt < cache_entry->expiry)) &&
			(nowt < cache_entry->cache_time)) {
			if (hdl->algo_apis.hit) {
				(*(hdl->algo_apis.hit))(trg_key, trg_key_len);
			}
			
			if (cache_entry->chnk_num == 0) {
				/* Updates the content information 			*/
				con_entry = (MemT_Content_Entry*) 
					cef_hash_tbl_item_get (hdl->mem_con_table, 
						cache_entry->name, cache_entry->name_len);
				
				if (con_entry) {
					con_entry->access_cnt++;
				}
			}
			/* Send Cob to cefnetd */
			mem_cache_cob_send (key, key_size, seqno, sock);
			return (CefC_Csmgr_Cob_Exist);
		} else {
			/* Removes the expiry cache entry 		*/
			cache_entry = (CsmgrdT_Content_Entry*) 
				cef_hash_tbl_item_remove (hdl->mem_cache_table, trg_key, trg_key_len);
			total_cob_num--;
			
			if (hdl->algo_apis.erase) {
				(*(hdl->algo_apis.erase))(cache_entry->name, cache_entry->name_len);
			}
			
			/* Updates the content information 			*/
			con_entry = (MemT_Content_Entry*) 
				cef_hash_tbl_item_get (hdl->mem_con_table, 
					cache_entry->name, cache_entry->name_len);
			
			if (con_entry) {
				con_entry->cache_num--;
				con_entry->size -= cache_entry->pay_len;
				
				if (con_entry->cache_num == 0) {
					con_entry = (MemT_Content_Entry*) 
						cef_hash_tbl_item_remove (hdl->mem_con_table, 
							cache_entry->name, cache_entry->name_len);
					free (con_entry);
				}
			}
		}
	}
	
	if (hdl->algo_apis.miss) {
		(*(hdl->algo_apis.miss))(trg_key, trg_key_len);
	}
	
	return (CefC_Csmgr_Cob_NotExist);
}

/*--------------------------------------------------------------------------------------
	Upload content entry
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_cache_item_put (
	CsmgrdT_Content_Entry* entry
) {
	CsmgrdT_Content_Entry* cache_entry;
	unsigned char 	trg_key[CsmgrdC_Key_Max];
	int 			trg_key_len;
	
	if (hdl->algo_apis.insert) {
		(*(hdl->algo_apis.insert))(entry);
		return (0);
	}
	
	/* Caches the content entry without the cache algorithm library 	*/
	cache_entry = (CsmgrdT_Content_Entry*) calloc (1, sizeof (CsmgrdT_Content_Entry));
	if (cache_entry == NULL) {
		return (-1);
	}
	
	/* Creates the key 				*/
	trg_key_len = csmgrd_name_chunknum_concatenate (
					entry->name, entry->name_len, entry->chnk_num, trg_key);
	
	/* Inserts the cache entry 		*/
	memcpy (cache_entry, entry, sizeof (CsmgrdT_Content_Entry));
	cef_hash_tbl_item_set (hdl->mem_cache_table, trg_key, trg_key_len, cache_entry);
	
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
	CsmgrdT_Content_Entry* cache_entry;
	MemT_Content_Entry* con_entry;

	cache_entry = (CsmgrdT_Content_Entry*) 
		cef_hash_tbl_item_get (hdl->mem_cache_table, key, key_size);
	if (!cache_entry) {
		return;
	}
	
		if (hdl->algo_apis.hit) {
			(*(hdl->algo_apis.hit))(key, key_size);
		}
		
	if ((seq_num == 0) && (cache_entry->chnk_num == 0)) {
		/* Updates the content information 			*/
		con_entry = (MemT_Content_Entry*) cef_hash_tbl_item_get (
						hdl->mem_con_table, cache_entry->name, cache_entry->name_len);
			if (con_entry) {
				con_entry->access_cnt++;
			}
		}
	
	return;
}

#ifdef CefC_Conping
/*--------------------------------------------------------------------------------------
	Check presence of cache
----------------------------------------------------------------------------------------*/
static int					/* It returns the negative value or NotExist if not found.	*/
mem_content_exist_check (
	unsigned char* name,						/* content name							*/
	uint16_t name_len							/* content name length					*/
) {
	MemT_Content_Entry* con_entry;
	uint64_t 	nowt;
	struct timeval tv;
	
	/* Checks the content information 			*/
	con_entry = (MemT_Content_Entry*) 
		cef_hash_tbl_item_check (hdl->mem_con_table, name, name_len);
	
	if (con_entry) {
		gettimeofday (&tv, NULL);
		nowt = tv.tv_sec * 1000000 + tv.tv_usec;
		
		if (((con_entry->expiry == 0) || (nowt < con_entry->expiry)) &&
			(nowt < con_entry->cache_time)) {
			return (CefC_Csmgr_Cob_Exist);
		}
	}
	
	return (CefC_Csmgr_Cob_NotExist);
}
#endif // CefC_Conping

#ifdef CefC_Contrace
/*--------------------------------------------------------------------------------------
	Create the cache information
----------------------------------------------------------------------------------------*/
static int							/* number of returned caches						*/
mem_cache_info_get (
	int* total_len, 									/* length of returned status	*/
	char uris[CefstatC_MaxUri][265],					/* record created cache name	*/
	CefstatT_Cache stat[CefstatC_MaxUri]				/* record created cache status	*/
) {
	int idx = 0;
	MemT_Content_Entry* con_entry;
	uint32_t 	index = 0;
	uint64_t 	nowt;
	struct timeval tv;
	int con_num;
	int i;
	char name[CefC_Max_Length];
	uint16_t name_len;
	
	/* Checks table num */
	con_num = cef_hash_tbl_item_num_get (hdl->mem_con_table);
	if (con_num == 0) {
		return (0);
	}
	
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000 + tv.tv_usec;
	
	/* Checks content freshness */
	for (i = 0; i < con_num ; i++) {
		
		/* Checks the content information 			*/
		con_entry = 
			(MemT_Content_Entry*) cef_hash_tbl_elem_get (hdl->mem_con_table, &index);
		
		if (con_entry == NULL) {
			break;
		}
		
		if ((nowt > con_entry->cache_time) ||
			((con_entry->expiry != 0) && (nowt > con_entry->expiry))) {
			index++;
			continue;
		}
		
		/* create a URI string from content entry 		*/
		name_len = cef_frame_conversion_name_to_uri (
					con_entry->name, con_entry->name_len, name);
		
		if (name_len > 255) {
			index++;
			continue;
		}
		name[name_len] = 0;
		
		/* set cache status	*/
		*total_len += name_len;
		
		/* set content name	*/
		memcpy (uris[idx], name, name_len);
		
		/* set content size	*/
		stat[idx].size = con_entry->size;
		
		/* set content num	*/
		stat[idx].cob_num = con_entry->cache_num;
		
		/* set access count	*/
		stat[idx].access_cnt = con_entry->access_cnt;
		
		/* set content freshness	*/
		if (con_entry->expiry) {
			stat[idx].freshness_sec = (int)((con_entry->expiry - nowt) / 1000000);
		} else {
			stat[idx].freshness_sec = 0;
		}
		
		/* set content elapsed time	*/
		stat[idx].elapsed_time = (int)((nowt - con_entry->insert_time) / 1000000);
		
		/* set upstream address	*/
		stat[idx].upaddr = con_entry->node;
		
		/* set sequence num	*/
		stat[idx].min_seq_num = con_entry->min_seq_num;
		stat[idx].max_seq_num = con_entry->max_seq_num;
		
		idx++;
		index++;
		
		if (idx == CefstatC_MaxUri) {
			break;
		}
	}
	
	return (idx);
}
#endif // CefC_Contrace

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
	
	/* Inits paramters 		*/
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

/*--------------------------------------------------------------------------------------
	Get Csmgrd status
----------------------------------------------------------------------------------------*/
static int										/* Number of content to report status	*/
mem_stat_get (
	char* stat,									/* String of FS Cache status			*/
	uint16_t* stat_len,							/* String length						*/
	uint8_t cache_f,							/* Cache request flag					*/
	char uris[CefC_Csmgr_Stat_MaxUri][265],		/* Content URI							*/
	CefT_Csmgrd_Stat_Cache* cache,				/* Content information					*/
	uint16_t* cache_len							/* Length of content information		*/
) {
	int con_num;
	int idx = 0;
	MemT_Content_Entry* con_entry;
	uint32_t 	index = 0;
	uint64_t 	nowt;
	struct timeval tv;
	int i;
	char name[CefC_Max_Length];
	uint16_t name_len;
	
	/* Sets the number of cached contents 	*/
	con_num = cef_hash_tbl_item_num_get (hdl->mem_con_table);
	*stat_len  = sprintf (stat, 
		"*****      Cache Status Report      *****\n");
	*stat_len  += sprintf (stat + *stat_len, 
		"Number of Cached Contents      : %d\n", con_num);
	
	if ((con_num == 0) || (cache_f == 0)) {
		return (0);
	}
	
	/* Sets the details of each cached content 	*/
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000 + tv.tv_usec;
	memset (cache, 0, sizeof (CefT_Csmgrd_Stat_Cache) * CefC_Csmgr_Stat_MaxUri);
	*cache_len = 0;
	
	/* Checks content freshness */
	for (i = 0; i < con_num ; i++) {
		
		/* Checks the content information 			*/
		con_entry = 
			(MemT_Content_Entry*) cef_hash_tbl_elem_get (hdl->mem_con_table, &index);
		
		if (con_entry == NULL) {
			break;
		}
		
		if ((nowt > con_entry->cache_time) ||
			((con_entry->expiry != 0) && (nowt > con_entry->expiry))) {
			index++;
			continue;
		}
		
		/* create a URI string from content entry 		*/
		name_len = cef_frame_conversion_name_to_uri (
					con_entry->name, con_entry->name_len, name);
		
		if (name_len > 255) {
			index++;
			continue;
		}
		name[name_len] = 0;
		
		/* set cache status	*/
		*cache_len += name_len;
		
		/* set content name	*/
		memcpy (uris[idx], name, name_len);
		
		/* set content size	*/
		cache[idx].size = con_entry->size;
		
		/* set access count	*/
		cache[idx].access_cnt = (unsigned int) con_entry->access_cnt;
		
		/* set content freshness	*/
		if (con_entry->expiry) {
			cache[idx].freshness_sec = (int)((nowt - con_entry->insert_time) / 1000000);
		} else {
			cache[idx].freshness_sec = 0;
		}
		
		/* set content elapsed time	*/
		cache[idx].elapsed_time = (unsigned int)((con_entry->expiry - nowt) / 1000000);
		
		idx++;
		index++;
		
		if (idx == CefC_Csmgr_Stat_MaxUri) {
			break;
		}
	}
	
	return (idx);
}

/*--------------------------------------------------------------------------------------
	Send cob to cefnetd
----------------------------------------------------------------------------------------*/
static void
mem_cache_cob_send (
	unsigned char* key,							/* content name							*/
	uint16_t key_len,							/* content name Length					*/
	uint32_t seqno,								/* chunk num							*/
	int sock									/* received socket						*/
) {
	int i;
	uint64_t sum_len = 0;
	uint64_t next;
	int res;
	pid_t child_pid;
	unsigned char trg_key[CsmgrdC_Key_Max];
	int trg_key_len;
	CsmgrdT_Content_Entry* cache_entry;
	MemT_Content_Entry* con_entry;
	
	con_entry = (MemT_Content_Entry*) 
		cef_hash_tbl_item_get (hdl->mem_con_table, key, key_len);
	
	if (con_entry == NULL) {
		return;
	}
	trg_key_len = csmgrd_name_chunknum_concatenate (key, key_len, seqno, trg_key);
	cache_entry = cef_hash_tbl_item_get (hdl->mem_cache_table, trg_key, trg_key_len);
	if (cache_entry) {
		csmgrd_plugin_cob_msg_send (sock, cache_entry->msg, cache_entry->msg_len);
	}
	if (seqno == 0) {
		con_entry->snd_seq_num = 0;
	}
	if (seqno < con_entry->snd_seq_num) {
		return;
	}
	con_entry->snd_seq_num = seqno + 100;
	
	/* check child_pid_list */
	if (mem_child_pid_list_check (key, key_len, seqno, sock) < 0) {
		return;
	}

	/* search free element */
	if ((res = mem_free_pid_index_search ()) < 0) {
		return;
	}

	child_pid = fork ();
	/* check pid */
	if (child_pid == -1) {
		csmgrd_log_write (CefC_Log_Error, "fork (%d : %s)\n", errno, strerror (errno));
		return;
	}
	/* check child pid 	*/
	if (child_pid == 0) {
#ifdef CefC_Debug
		csmgrd_dbg_write (CefC_Dbg_Fine, "**CEF-CHILD** Enter\n");
#endif // CefC_Debug
		/* send ContentObject to cefnetd */
		for (i = 1; i < MemC_Max_Block_Num; i++) {
			/* Creates the key 		*/
			trg_key_len = csmgrd_name_chunknum_concatenate (
											key, key_len, seqno + i, trg_key);
			/* Access the specified entry 	*/
			cache_entry = cef_hash_tbl_item_get (
											hdl->mem_cache_table, trg_key, trg_key_len);
			if (cache_entry) {
				if (csmgrd_plugin_cob_msg_send (
						sock, cache_entry->msg, cache_entry->msg_len) < 0) {
					/* send error */
#ifdef CefC_Debug
					csmgrd_dbg_write (CefC_Dbg_Fine, "ERROR : Cob send error\n");
#endif // CefC_Debug
					break;
				}
				sum_len += cache_entry->msg_len;
				/* check interval */
				if (i % 3 == 0) {
					next = sum_len * 8 / MemC_Block_Send_Rate;
					usleep (next);
					sum_len = 0;
				}
			}
		}
#ifdef CefC_Debug
		csmgrd_dbg_write (CefC_Dbg_Fine, "**CEF-CHILD** Exit\n");
#endif // CefC_Debug
		exit (0);
	}
	/* set pid element */
	child_pid_list[res].child_pid = child_pid;
	memcpy (child_pid_list[res].key, key, key_len);
	child_pid_list[res].key_len = key_len;
	child_pid_list[res].seq_num = seqno;
	child_pid_list[res].sock = sock;
	return;
}

/*--------------------------------------------------------------------------------------
	Search free element
----------------------------------------------------------------------------------------*/
static int
mem_free_pid_index_search (
	void
) {
	int i;
	for (i = 0; i < MemC_Max_Child_Num; i++) {
		if (child_pid_list[i].child_pid == 0) {
			break;
		}
	}
	if (i == MemC_Max_Child_Num) {
		/* full of list */
		return (-1);
	}
	return (i);
}

/*--------------------------------------------------------------------------------------
	Check child pid list
----------------------------------------------------------------------------------------*/
static int
mem_child_pid_list_check (
	unsigned char* key,							/* content name							*/
	uint16_t key_len,							/* content name Length					*/
	uint32_t seqno,								/* chunk num							*/
	int sock									/* received socket						*/
) {
	int i;
	for (i = 0; i < MemC_Max_Child_Num; i++) {
		if ((child_pid_list[i].child_pid != 0) &&
			(child_pid_list[i].sock == sock) &&
			(child_pid_list[i].key_len == key_len) &&
			(memcmp (key, child_pid_list[i].key, key_len) == 0)) {
			/* check sequence num */
			if ((seqno >= child_pid_list[i].seq_num) &&
				(seqno < child_pid_list[i].seq_num + MemC_Max_Block_Num)) {
				/* send cob process is already running */
				return (-1);
			}
		}
	}
	return (0);
}

/*--------------------------------------------------------------------------------------
	set SIGCHLD
----------------------------------------------------------------------------------------*/
static void
setup_SIGCHLD (
	void
) {
	struct sigaction act;
	int i;
	memset (&act, 0, sizeof (act));
	act.sa_handler = catch_SIGCHLD;
	sigemptyset (&act.sa_mask);
	act.sa_flags = SA_NOCLDSTOP | SA_RESTART;
	sigaction (SIGCHLD, &act, NULL);
	for (i = 0; i < MemC_Max_Child_Num; i++) {
		child_pid_list[i].child_pid = 0;
	}
}
/*--------------------------------------------------------------------------------------
	catch SIGCHLD
----------------------------------------------------------------------------------------*/
static void
catch_SIGCHLD (
	int sig
) {
	pid_t child_pid = 0;
	int child_ret;
	int i;

	do {
		child_pid = waitpid (-1, &child_ret, WNOHANG);
		if (child_pid > 0) {
			for (i = 0; i < MemC_Max_Child_Num; i++) {
				if (child_pid == child_pid_list[i].child_pid) {
					child_pid_list[i].child_pid = 0;
				}
			}
		}
	} while (child_pid > 0);
}

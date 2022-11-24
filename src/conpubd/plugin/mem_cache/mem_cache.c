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
#define __CONPUBD_MEM_CACHE_SOURCE__

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
#include <cefore/cef_conpub.h>
#include <cefore/cef_frame.h>
#include <cefore/cef_hash.h>
#include <conpubd/conpubd_plugin.h>


/****************************************************************************************
 Macros
 ****************************************************************************************/

#define MemC_Max_KLen 				1024
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
	uint64_t		rct;						/* RCT									*/
	uint64_t		expiry;						/* Expiry								*/
	uint64_t		cachetime;					/* cachetime							*/
	struct in_addr	node;						/* Node address							*/

} ConpubdT_Content_Mem_Entry;

typedef struct CefT_Mem_Hash_Cell {
	
	uint32_t 					hash;
	unsigned char* 				key;
	uint32_t 					klen;
	ConpubdT_Content_Mem_Entry* elem;
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

static MemT_Cache_Handle* 		cobpub_hdl = NULL;
static char 					conpub_conf_dir[PATH_MAX] = {"/usr/local/cefore"};
static CefT_Mem_Hash* 			mem_hash_tbl = NULL;
static CsmgrT_Stat_Handle 		conpub_stat_hdl;

static pthread_mutex_t 			conpub_mem_cs_mutex = PTHREAD_MUTEX_INITIALIZER;

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
	int sock,									/* received socket						*/
	unsigned char* version,						/* version								*/
	uint16_t ver_len							/* length of version					*/
);
/*--------------------------------------------------------------------------------------
	Upload content byte steream
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_cache_item_puts (
	ConpubdT_Content_Entry* entry, 
	int size
);
/*--------------------------------------------------------------------------------------
	writes the cobs to memry cache
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_cache_cob_write (
	ConpubdT_Content_Entry* cobs, 
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
	Delete content entry
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_content_del (
	unsigned char* name,						/* Content name							*/
	uint16_t name_len,							/* Content name length					*/
	uint64_t cob_num							/* Total number of Cob					*/
);
/*--------------------------------------------------------------------------------------
	Retuern cached cob num
----------------------------------------------------------------------------------------*/
static uint64_t
mem_cached_cobs (
);
/*--------------------------------------------------------------------------------------
	Hash APIs for Memory Cahce Plugin
----------------------------------------------------------------------------------------*/
static CefT_Mem_Hash*
cef_mem_hash_tbl_create (
	uint64_t capacity
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
	ConpubdT_Content_Mem_Entry* elem, 
	ConpubdT_Content_Mem_Entry** old_elem
);
static ConpubdT_Content_Mem_Entry* 
cef_mem_hash_tbl_item_get (
	const unsigned char* key,
	uint32_t klen
);
static ConpubdT_Content_Mem_Entry* 
cef_mem_hash_tbl_item_remove (
	const unsigned char* key,
	uint32_t klen
);

int												/* length of the created key 			*/
conpubd_key_create_by_Mem_Entry (
	unsigned char*	name,
	uint16_t		name_len,
	uint32_t		chnk_num,
	unsigned char* key
);

/****************************************************************************************
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Road the cache plugin
----------------------------------------------------------------------------------------*/
int
conpubd_memory_plugin_load (
	ConpubdT_Plugin_Interface* cs_in, 
	const char* config_dir
) {
	CONPUBD_SET_CALLBACKS (
		mem_cs_create, mem_cs_destroy, mem_cs_expire_check, mem_cache_item_get,
		mem_cache_item_puts, mem_cs_ac_cnt_inc, mem_content_del, mem_cached_cobs);

	if (config_dir) {
		strcpy (conpub_conf_dir, config_dir);
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
	
	/* create handle 		*/
	if (cobpub_hdl != NULL) {
		free (cobpub_hdl);
		cobpub_hdl = NULL;
	}
	/* Init logging 	*/
	conpubd_log_init ("conpubd_memcache", 1);
	conpubd_log_init2 (conpub_conf_dir);
#ifdef CefC_Debug
	conpubd_dbg_init ("conpubd_memcache", conpub_conf_dir);
#endif // CefC_Debug

	cobpub_hdl = (MemT_Cache_Handle*) malloc (sizeof (MemT_Cache_Handle));
	if (cobpub_hdl == NULL) {
		conpubd_log_write (CefC_Log_Error, "malloc error\n");
		return (-1);
	}
	memset (cobpub_hdl, 0, sizeof (MemT_Cache_Handle));
	
	/* Reads config 		*/
	if (mem_config_read (&conf_param) < 0) {
		conpubd_log_write (CefC_Log_Error, "[%s] read config\n", __func__);
		return (-1);
	}
	cobpub_hdl->cache_capacity = conf_param.cache_capacity;
	cobpub_hdl->cache_cobs = 0;
	
	/* Creates the memory cache 		*/
	mem_hash_tbl = cef_mem_hash_tbl_create (cobpub_hdl->cache_capacity);
	if (mem_hash_tbl ==  NULL) {
		conpubd_log_write (CefC_Log_Error, "Unable to create mem hash table\n");
		return (-1);
	}
	
	conpubd_log_write (CefC_Log_Info, "Start\n");
	conpubd_log_write (CefC_Log_Info, "Capacity : "FMTU64"\n", cobpub_hdl->cache_capacity);
	conpub_stat_hdl = stat_hdl;
	conpubd_stat_cache_capacity_update (conpub_stat_hdl, cobpub_hdl->cache_capacity);
	
	return (0);
}
/*--------------------------------------------------------------------------------------
	Destroy content store
----------------------------------------------------------------------------------------*/
static void
mem_cs_destroy (
	void
) {
	int i;

	pthread_mutex_destroy (&conpub_mem_cs_mutex);
	
	if (cobpub_hdl == NULL) {
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
	
	if (cobpub_hdl) {
		free (cobpub_hdl);
		cobpub_hdl = NULL;
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
	ConpubdT_Content_Mem_Entry* entry = NULL;
	ConpubdT_Content_Mem_Entry* entry1 = NULL;
	uint64_t 	nowt;
	struct timeval tv;
	int n;
	unsigned char trg_key[65535];
	int trg_key_len;
	
	pthread_mutex_lock (&conpub_mem_cs_mutex);
	
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
				if (((entry->expiry != 0) && (entry->expiry < nowt))) {
					/* Removes the expiry cache entry 		*/
					trg_key_len = conpubd_key_create_by_Mem_Entry 
									(entry->name, entry->name_len, entry->chnk_num, trg_key);
					entry1 = cef_mem_hash_tbl_item_remove (trg_key, trg_key_len);
					conpubd_stat_cob_remove (
						conpub_stat_hdl, entry->name, entry->name_len, 
						entry->chnk_num, entry->pay_len);
					cobpub_hdl->cache_cobs--;
					free (entry1->msg);
					free (entry1->name);
					free (entry1);
				}
			}
		}
	}
	pthread_mutex_unlock (&conpub_mem_cs_mutex);
	
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
	int sock,									/* received socket						*/
	unsigned char* version,						/* version								*/
	uint16_t ver_len							/* length of version					*/
) {
	ConpubdT_Content_Mem_Entry* entry;
	unsigned char 	trg_key[ConpubdC_Key_Max];
	int 			trg_key_len;
	uint64_t 		nowt;
	struct timeval 	tv;
	
	/* Creates the key 		*/
	trg_key_len = conpubd_name_chunknum_concatenate (key, key_size, seqno, trg_key);
	
	/* Access the specified entry 	*/
	entry = cef_mem_hash_tbl_item_get (trg_key, trg_key_len);
	
	if (entry) {
		
		gettimeofday (&tv, NULL);
		nowt = tv.tv_sec * 1000000llu + tv.tv_usec;
		
		if (((entry->expiry == 0) || (nowt < entry->expiry))) {
			
			if (entry->chnk_num == 0) {
				conpubd_stat_access_count_update (
					conpub_stat_hdl, entry->name, entry->name_len);
			}
			/* Set cache time */
			{
				uint64_t cachetime;
				time_t timer = time (NULL);
				struct tm* local = localtime (&timer);
				time_t now_time = mktime (local);
				cachetime = (uint64_t)(now_time + entry->rct) * 1000;
				cef_frame_opheader_cachetime_update (entry->msg, cachetime);
			}
			/* Send Cob to cefnetd */
			conpubd_plugin_cob_msg_send (sock, entry->msg, entry->msg_len);
			return (0);
 		}
		else {
			pthread_mutex_lock (&conpub_mem_cs_mutex);
			/* Removes the expiry cache entry 		*/
			entry = cef_mem_hash_tbl_item_remove (trg_key, trg_key_len);
			conpubd_stat_cob_remove (
				conpub_stat_hdl, entry->name, entry->name_len, 
				entry->chnk_num, entry->pay_len);
			cobpub_hdl->cache_cobs--;
			
			free (entry->msg);
			free (entry->name);
			free (entry);
			pthread_mutex_unlock (&conpub_mem_cs_mutex);
		}
	}
	
	
	return (-1);
}
/*--------------------------------------------------------------------------------------
	Upload content byte steream
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_cache_item_puts (
	ConpubdT_Content_Entry* entry, 
	int size
) {
	int rtc = 0;
	if (entry == NULL) {
		return (rtc);
	}
	pthread_mutex_lock (&conpub_mem_cs_mutex);
	rtc = mem_cache_cob_write (entry, 1);
	pthread_mutex_unlock (&conpub_mem_cs_mutex);
	return (rtc);
}
/*--------------------------------------------------------------------------------------
	writes the cobs to memry cache
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_cache_cob_write (
	ConpubdT_Content_Entry* cobs, 
	int cob_num
) {
	int index = 0;
	ConpubdT_Content_Mem_Entry* entry;
	ConpubdT_Content_Mem_Entry* old_entry = NULL;
	unsigned char 	trg_key[ConpubdC_Key_Max];
	int 			trg_key_len;
	uint64_t nowt;
	struct timeval tv;
	int rtc;
	
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;

	while (index < cob_num) {
		
		if (cobs[index].expiry < nowt) {
			index++;
			continue;
		}

		/* Caches the content entry without the cache algorithm library 	*/
		entry = 
			(ConpubdT_Content_Mem_Entry*) calloc (1, sizeof (ConpubdT_Content_Mem_Entry));
		if (entry == NULL) {
			return (-1);
		}
		
		/* Creates the key 				*/
		trg_key_len = conpubd_name_chunknum_concatenate (
						cobs[index].name, cobs[index].name_len, 
						cobs[index].chnk_num, trg_key);
		
		/* Inserts the cache entry 		*/
		entry->msg			 = cobs[index].msg;
		entry->msg_len		 = cobs[index].msg_len;
		entry->name			 = cobs[index].name;
		entry->name_len		 = cobs[index].name_len;
		entry->pay_len		 = cobs[index].pay_len;
		entry->chnk_num		 = cobs[index].chnk_num;
		entry->rct	 		 = cobs[index].rct;
		entry->expiry		 = cobs[index].expiry;
		entry->node			 = cobs[index].node;
		rtc = cef_mem_hash_tbl_item_set (trg_key, trg_key_len, entry, &old_entry);
		if (rtc < 0) {
			free (entry->msg);
			free (entry->name);
			free (entry);
			return (rtc);
		}
		
		/* Updates the content information 			*/
		conpubd_stat_cob_update (conpub_stat_hdl, entry->name, entry->name_len, 
			entry->chnk_num, entry->pay_len, entry->expiry, nowt, entry->node);
		
		if (old_entry) {
			free (old_entry->msg);
			free (old_entry->name);
			free (old_entry);
		} else {
			cobpub_hdl->cache_cobs++;
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
	ConpubdT_Content_Mem_Entry* entry;
	
	entry = cef_mem_hash_tbl_item_get (key, key_size);
	if (!entry) {
		return;
	}
	
	if ((seq_num == 0) && (entry->chnk_num == 0)) {
		conpubd_stat_access_count_update (
			conpub_stat_hdl, entry->name, entry->name_len);
	}
	
	return;
}
/*--------------------------------------------------------------------------------------
	Delete content entry
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
mem_content_del (
	unsigned char* name,						/* Content name							*/
	uint16_t name_len,							/* Content name length					*/
	uint64_t cob_num							/* Total number of Cob					*/
) {
	
	CsmgrT_Stat* rcd = NULL;
	uint64_t 	i;
	ConpubdT_Content_Mem_Entry* entry = NULL;
	unsigned char trg_key[65535];
	int 			trg_key_len;

	pthread_mutex_lock (&conpub_mem_cs_mutex);
	/* Obtain the information of the specified content 		*/
	rcd = conpubd_stat_content_info_access (conpub_stat_hdl, name, name_len);
	if (!rcd) {
		pthread_mutex_unlock (&conpub_mem_cs_mutex);
		return (-1);
	}
	for (i=0; i< cob_num; i++) {
		trg_key_len = conpubd_key_create_by_Mem_Entry (name, name_len, (uint32_t)i, trg_key);
	entry = cef_mem_hash_tbl_item_remove (trg_key, trg_key_len);
	if (entry == NULL) {
			pthread_mutex_unlock (&conpub_mem_cs_mutex);
			return (-1);
	}
	conpubd_stat_cob_remove (
		conpub_stat_hdl, entry->name, entry->name_len, 
		entry->chnk_num, entry->pay_len);
		cobpub_hdl->cache_cobs--;
	free (entry->msg);
	free (entry->name);
	free (entry);
	}
	pthread_mutex_unlock (&conpub_mem_cs_mutex);

	return (0);
	
}
/*--------------------------------------------------------------------------------------
	Retuern cached cob num
----------------------------------------------------------------------------------------*/
static uint64_t
mem_cached_cobs (
) {
	return (cobpub_hdl->cache_cobs);
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
	
	int			i, n;
	
	/* Inits parameters		*/
	memset (params, 0, sizeof (MemT_Config_Param));
	params->cache_capacity = CefC_CnpbDefault_Contents_Capacity;
	
	/* Obtains the directory path where the conpubd's config file is located. */
#if 0 //+++++ GCC v9 +++++
	sprintf (file_name, "%s/conpubd.conf", conpub_conf_dir);
#else 
	int sn = snprintf (file_name, sizeof(file_name), "%s/conpubd.conf", conpub_conf_dir);
	if (sn < 0) {
		conpubd_log_write (
			CefC_Log_Error, "[%s] Config file dir path too long(%s)\n", __func__,  conpub_conf_dir);
		return (-1);
	}
#endif //-----  GCC v9 -----
	
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
		
		if (value == NULL) {
			continue;
		}
		
		/* Records a parameter 			*/
		if (strcmp (option, "CONTENTS_CAPACITY") == 0) {
			char *endptr = "";
			params->cache_capacity = strtoul (value, &endptr, 0);
			if (strcmp (endptr, "") != 0) {
				conpubd_log_write (
					CefC_Log_Error, "[%s] Invalid value %s=%s\n", __func__, option, value);
				fclose (fp);
				return (-1);
			}
			if (!(1 <= params->cache_capacity 
					&& 
				  params->cache_capacity <= 0xFFFFFFFFF)) {
				conpubd_log_write (CefC_Log_Error, 
				"CONTENTS_CAPACITY value must be greater than  or equal to 1 "
				"and less than or equal to 68,719,476,735(0xFFFFFFFFF).\n"); 
				fclose (fp);
				return (-1);
			}
		} else {
			/* NOP */;
		}
	}
	fclose (fp);
	
	return (0);
}

/****************************************************************************************
	Hash APIs for Memory Cahce Plugin	
 ****************************************************************************************/
/****************************************************************************************/
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
	if (table_size > INT32_MAX) {
		table_size = INT32_MAX;
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
	ht->elem_num = 0;
	
	return (ht);
}
/****************************************************************************************/
static int 
cef_mem_hash_tbl_item_set (
	const unsigned char* key,
	uint32_t klen,
	ConpubdT_Content_Mem_Entry* elem, 
	ConpubdT_Content_Mem_Entry** old_elem
) {
	CefT_Mem_Hash* ht = (CefT_Mem_Hash*) mem_hash_tbl;
	uint32_t hash = 0;
	uint32_t y;
	CefT_Mem_Hash_Cell* cp;
	CefT_Mem_Hash_Cell* wcp;

	*old_elem = NULL;
	if (ht->elem_max == ht->elem_num) {
		return (-99);
	}
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
/****************************************************************************************/
static ConpubdT_Content_Mem_Entry* 
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
/****************************************************************************************/
static ConpubdT_Content_Mem_Entry* 
cef_mem_hash_tbl_item_remove (
	const unsigned char* key,
	uint32_t klen
) {
	CefT_Mem_Hash* ht = (CefT_Mem_Hash*) mem_hash_tbl;
	uint32_t hash = 0;
	uint32_t y;
	ConpubdT_Content_Mem_Entry* ret_elem;
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
/****************************************************************************************/
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
/****************************************************************************************/
int												/* length of the created key 			*/
conpubd_key_create_by_Mem_Entry (
	unsigned char*	name,
	uint16_t		name_len,
	uint32_t		chnk_num,
	unsigned char* key
) {

	memcpy (&key[0], name, name_len);
	key[name_len] 		= 0x00;
	key[name_len + 1] 	= 0x10;
	key[name_len + 2] 	= 0x00;
	key[name_len + 3] 	= 0x04;
	chnk_num = htonl (chnk_num);
	memcpy (&key[name_len + 4], &chnk_num, sizeof (uint32_t));

	return (name_len + 4 + sizeof (uint32_t));
}

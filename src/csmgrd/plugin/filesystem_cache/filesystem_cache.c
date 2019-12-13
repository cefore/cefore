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
 * filesystem_cache.c
 */
#define __CSMGRD_FILE_SYSTEM_CACHE_SOURCE__
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
#include <sys/ipc.h> 
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "filesystem_cache.h"
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

#define FscC_Max_Buff 			32
#define FscC_Tx_Cob_Num 		256
#define FscC_File_Area			(sizeof (FscT_File_Element) * FscC_Page_Cob_Num)

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/


/****************************************************************************************
 State Variables
 ****************************************************************************************/
static FscT_Cache_Handle* hdl = NULL;						/* FileSystemCache Handle	*/
static FscT_File_Element* file_area = NULL;					/* File Element				*/


static char csmgr_conf_dir[PATH_MAX] = {"/usr/local/cefore"};

static pthread_mutex_t 			fsc_comn_buff_mutex[FscC_Max_Buff];
static pthread_t				fsc_rcv_thread;
static int 						fsc_rcv_thread_f = 0;
static unsigned char* 			fsc_tx_buffer = NULL;
static CsmgrdT_Content_Entry* 	fsc_proc_cob_buff[FscC_Max_Buff]		= {0};
static int 						fsc_proc_cob_buff_idx[FscC_Max_Buff] 	= {0};
static CsmgrT_Stat_Handle 		csmgr_stat_hdl;
static uint64_t*				fsc_tx_cob_map[CsmgrT_Stat_Max];
static uint64_t*				fsc_tx_cob_time[CsmgrT_Stat_Max];


/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Init content store
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cs_create (
	CsmgrT_Stat_Handle stat_hdl
);
/*--------------------------------------------------------------------------------------
	function for processing the received message
----------------------------------------------------------------------------------------*/
static void* 
fsc_cob_process_thread (
	void* arg
);
/*--------------------------------------------------------------------------------------
	writes the cobs to memry cache
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_cob_write (
	CsmgrdT_Content_Entry* cobs, 
	int cob_num
);
/*--------------------------------------------------------------------------------------
	Check FileSystem Cache Directory
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_root_dir_check (
	char* root_path								/* csmgr root path						*/
);
/*--------------------------------------------------------------------------------------
	Initialize FileSystemCache
----------------------------------------------------------------------------------------*/
static uint32_t						/* The return value is FSCID						*/
fsc_cache_id_create (
	FscT_Cache_Handle* hdl
);
/*--------------------------------------------------------------------------------------
	Read config file
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_config_read (
	FscT_Config_Param* conf_param				/* Fsc config parameter					*/
);
/*--------------------------------------------------------------------------------------
	Check content expire
----------------------------------------------------------------------------------------*/
static void
fsc_cs_expire_check (
	void
);
/*--------------------------------------------------------------------------------------
	delete file in this directory
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_is_file_delete (
	char* filepath								/* file path							*/
);
/*--------------------------------------------------------------------------------------
	delete directory path
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_dir_clear (
	char* filepath								/* file path							*/
);
/*--------------------------------------------------------------------------------------
	delete in this directory(recursive)
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_recursive_dir_clear (
	char* filepath								/* file path							*/
);
/*--------------------------------------------------------------------------------------
	Destroy content store
----------------------------------------------------------------------------------------*/
static void
fsc_cs_destroy (
	void
);
/*--------------------------------------------------------------------------------------
	Function to read a ContentObject from FileSystem Cache
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_item_get (
	unsigned char* key,							/* content name							*/
	uint16_t key_size,							/* content name Length					*/
	uint32_t seqno,								/* chunk num							*/
	int sock									/* received socket						*/
);
/*--------------------------------------------------------------------------------------
	Function to increment access count
----------------------------------------------------------------------------------------*/
static void
fsc_cs_ac_cnt_inc (
	unsigned char* key,							/* content name							*/
	uint16_t key_size,							/* content name Length					*/
	uint32_t seq_num							/* sequence number						*/
);
/*--------------------------------------------------------------------------------------
	Store API
----------------------------------------------------------------------------------------*/
static int
fsc_cs_store (
	CsmgrdT_Content_Entry* entry
);
/*--------------------------------------------------------------------------------------
	Remove API
----------------------------------------------------------------------------------------*/
static void
fsc_cs_remove (
	unsigned char* key,
	int key_len
);
#ifdef CefC_Ccore
/*--------------------------------------------------------------------------------------
	Change cache capacity
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_change_cap (
	uint64_t cap								/* New capacity to set					*/
);
/*--------------------------------------------------------------------------------------
	Set content lifetime
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_content_lifetime_set (
	unsigned char* name,						/* content name							*/
	uint16_t name_len,							/* content name length					*/
	uint64_t lifetime							/* Content Lifetime						*/
);
#endif // CefC_Ccore
/*--------------------------------------------------------------------------------------
	Upload content byte steream
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_item_puts (
	unsigned char* msg, 
	int msg_len
);

/****************************************************************************************
 ****************************************************************************************/
int
csmgrd_filesystem_plugin_load (
	CsmgrdT_Plugin_Interface* cs_in, 
	const char* config_dir
) {
	CSMGRD_SET_CALLBACKS(
		fsc_cs_create, fsc_cs_destroy, fsc_cs_expire_check, fsc_cache_item_get,
		fsc_cache_item_puts, fsc_cs_ac_cnt_inc);
	
#ifdef CefC_Ccore
	cs_in->cache_cap_set 		= fsc_cache_change_cap;
	cs_in->content_lifetime_set = fsc_content_lifetime_set;
#endif // CefC_Ccore
	
	if (config_dir) {
		strcpy (csmgr_conf_dir, config_dir);
	}
	
	return (0);
}
/*--------------------------------------------------------------------------------------
	Init content store
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cs_create (
	CsmgrT_Stat_Handle stat_hdl
) {
	FscT_Config_Param conf_param;
	int i;
	int res;
	
	/* Check handle */
	if (hdl) {
		free (hdl);
		hdl = NULL;
	}
	
	/* Init logging 	*/
	csmgrd_log_init ("filesystem");
#ifdef CefC_Debug
	csmgrd_dbg_init ("filesystem", csmgr_conf_dir);
#endif // CefC_Debug
	
	/* Create handle */
	hdl = (FscT_Cache_Handle*) malloc (sizeof (FscT_Cache_Handle));
	if (hdl == NULL) {
		csmgrd_log_write (CefC_Log_Error, "Failed to get memory required for startup.\n");
		return (-1);
	}
	memset (hdl, 0, sizeof (FscT_Cache_Handle));
	
	/* Read config */
	if (fsc_config_read (&conf_param) < 0) {
		csmgrd_log_write (CefC_Log_Error, "[%s] Read config error\n", __func__);
		return (-1);
	}
	hdl->cache_cob_max = conf_param.cache_cob_max;
	strcpy (hdl->fsc_root_path, conf_param.fsc_root_path);
	
	/* Check and create root directory	*/
	if (fsc_root_dir_check (hdl->fsc_root_path) < 0) {
		csmgrd_log_write (CefC_Log_Error,
			"[%s] Root dir is not exist (%s)\n" , __func__, hdl->fsc_root_path);
		hdl->fsc_root_path[0] = 0;
		return (-1);
	}
	
	/* Creates the directory to store cache files		*/
	hdl->fsc_id = fsc_cache_id_create (hdl);
	if (hdl->fsc_id == 0xFFFFFFFF) {
		csmgrd_log_write (CefC_Log_Error, "FileSystemCache init error\n");
		return (-1);
	}
	csmgrd_log_write (CefC_Log_Info, 
		"Creation the cache directory (%s) ... OK\n", hdl->fsc_cache_path);
	
	/* Initialize FscT_File_Element 	*/
	if (file_area != NULL) {
		free (file_area);
		file_area = NULL;
	}
	file_area = (FscT_File_Element*) malloc (FscC_File_Area);
	if (file_area == NULL) {
		csmgrd_log_write (CefC_Log_Error, "Failed to get memory required for startup.\n");
		return (-1);
	}
	csmgrd_log_write (CefC_Log_Info, "Creation the file area ... OK\n");
	
	/* Inits the tx buffer 		*/
	fsc_tx_buffer = 
		(unsigned char*) malloc (sizeof (unsigned char) * CefC_Csmgr_Buff_Max);
	if (fsc_tx_buffer == NULL) {
		csmgrd_log_write (CefC_Log_Error, "Failed to allocate tx buffer.\n");
		return (-1);
	}
	csmgrd_log_write (CefC_Log_Info, "Creation the tx buffer ... OK\n");
	
	/* Inits the area for recording forwarded cobs 	*/
	memset (fsc_tx_cob_map, 0, sizeof (uint64_t*) * CsmgrT_Stat_Max);
	
	for (i = 0 ; i < CsmgrT_Stat_Max ; i++) {
		fsc_tx_cob_map[i] = (uint64_t*) malloc (sizeof (uint64_t) * CsmgrT_Map_Max);
		if (fsc_tx_cob_map[i] == NULL) {
			csmgrd_log_write (CefC_Log_Info, "Creation the cob map area ... OK\n");
			return (-1);
		}
		memset (fsc_tx_cob_map[i], 0, sizeof (uint64_t) * CsmgrT_Map_Max);
	}
	memset (fsc_tx_cob_time, 0, sizeof (uint64_t*) * CsmgrT_Stat_Max);
	
	for (i = 0 ; i < CsmgrT_Stat_Max ; i++) {
		fsc_tx_cob_time[i] = (uint64_t*) malloc (sizeof (uint64_t) * CsmgrT_Map_Max);
		if (fsc_tx_cob_time[i] == NULL) {
			csmgrd_log_write (CefC_Log_Info, "Creation the cob map area ... OK\n");
			return (-1);
		}
		memset (fsc_tx_cob_time[i], 0, sizeof (uint64_t) * CsmgrT_Map_Max);
	}
	csmgrd_log_write (CefC_Log_Info, "Inits cob mapping area ... OK\n");
	
	/* Loads the library for cache algorithm 		*/
	if (strcmp (conf_param.algo_name, "None")) {
		sprintf (hdl->algo_name, "%s%s", conf_param.algo_name, CsmgrdC_Library_Name);
		res = csmgrd_lib_api_get (hdl->algo_name, &hdl->algo_lib, &hdl->algo_apis);
		if (res < 0) {
			csmgrd_log_write (CefC_Log_Error, "Load the lib (%s)\n", hdl->algo_name);
			return (-1);
		}
		csmgrd_log_write (CefC_Log_Info, "Library : %s ... OK\n", hdl->algo_name);
		if (hdl->algo_apis.init) {
			(*(hdl->algo_apis.init))(hdl->cache_cob_max, fsc_cs_store, fsc_cs_remove);
		}
	} else {
		csmgrd_log_write (CefC_Log_Info, "Library : Not Specified\n");
	}
	
	/* Creates the process buffer 		*/
	for (i = 0 ; i < FscC_Max_Buff ; i++) {
		fsc_proc_cob_buff[i] = (CsmgrdT_Content_Entry*) 
			malloc (sizeof (CsmgrdT_Content_Entry) * CsmgrC_Buff_Num);
		if (fsc_proc_cob_buff[i] == NULL) {
			csmgrd_log_write (CefC_Log_Info, 
				"Failed to allocation process cob buffer\n");
			return (-1);
		}
		fsc_proc_cob_buff_idx[i] = 0;
		pthread_mutex_init (&fsc_comn_buff_mutex[i], NULL);
	}
	csmgrd_log_write (CefC_Log_Info, "Inits rx buffer ... OK\n");
	
	/* Creates the threads 		*/
	if (pthread_create (&fsc_rcv_thread, NULL, fsc_cob_process_thread, hdl) == -1) {
		csmgrd_log_write (CefC_Log_Info, "Failed to create the new thread\n");
		return (-1);
	}
	fsc_rcv_thread_f = 1;
	csmgrd_log_write (CefC_Log_Info, "Inits rx thread ... OK\n");
	
	csmgr_stat_hdl = stat_hdl;
	csmgrd_stat_cache_capacity_update (csmgr_stat_hdl, hdl->cache_cob_max);
	
	return (0);
}
/*--------------------------------------------------------------------------------------
	function for processing the received message
----------------------------------------------------------------------------------------*/
static void* 
fsc_cob_process_thread (
	void* arg
) {
	int i;
	
	while (fsc_rcv_thread_f) {
		for (i = 0 ; i < FscC_Max_Buff ; i++) {
			pthread_mutex_lock (&fsc_comn_buff_mutex[i]);
			
			if (fsc_proc_cob_buff_idx[i] > 0) {
#ifdef CefC_Debug
				csmgrd_dbg_write (CefC_Dbg_Fine, 
					"cob put thread starts to write %d cobs\n", fsc_proc_cob_buff_idx[i]);
#endif // CefC_Debug
				fsc_cache_cob_write (&fsc_proc_cob_buff[i][0], fsc_proc_cob_buff_idx[i]);
				fsc_proc_cob_buff_idx[i] = 0;
#ifdef CefC_Debug
				csmgrd_dbg_write (CefC_Dbg_Fine, 
					"cob put thread completed writing cobs\n");
#endif // CefC_Debug
			}
			pthread_mutex_unlock (&fsc_comn_buff_mutex[i]);
		}
	}
	
	pthread_exit (NULL);
	
	return ((void*) NULL);
}
/*--------------------------------------------------------------------------------------
	writes the cobs to memry cache
----------------------------------------------------------------------------------------*/
static int 
fsc_cache_cob_write (
	CsmgrdT_Content_Entry* cobs, 
	int cob_num
) {
	int index = 0;
	uint64_t nowt;
	struct timeval tv;
	
	CsmgrT_Stat* 	rcd = NULL;
	unsigned char 	name[CsmgrT_Name_Max];
	uint16_t 		name_len = 0;
	
	int				work_con_index = -1;
	int 			prev_page_index = -1;
	int 			work_page_index;
	int 			work_pos_index;
	
	char			file_path[PATH_MAX];
	char			cont_path[PATH_MAX];
	
	FILE* 			fp = NULL;
	size_t 			ret_bytes;
	
	uint64_t 		mask;
	uint16_t 		x;
	
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000 + tv.tv_usec;
	
	if (hdl->cache_cobs >= hdl->cache_cob_max) {
		return (0);
	}
	
	while (index < cob_num) {
		
		if(cobs[index].chnk_num > CsmgrT_Stat_Seq_Max) {
			index++;
			continue;
		}
		/* Update the directory to write the received cob 		*/
		if ((cobs[index].name_len != name_len) ||
			(memcmp (cobs[index].name, name, cobs[index].name_len))) {
			
			rcd = csmgrd_stat_content_info_access (
					csmgr_stat_hdl, cobs[index].name, cobs[index].name_len);
			
			if (!rcd) {
				rcd = csmgrd_stat_content_info_init (
						csmgr_stat_hdl, cobs[index].name, cobs[index].name_len);
				if (!rcd) {
					goto NextCob;
				}
			}
			work_con_index = (int) rcd->index;
			prev_page_index = -1;
			sprintf (cont_path, "%s/%d", hdl->fsc_cache_path, work_con_index);
			
#ifdef CefC_Debug
			csmgrd_dbg_write (CefC_Dbg_Finer, 
				"cob put thread selects the content directory: %s\n", cont_path);
#endif // CefC_Debug
			memcpy (name, cobs[index].name, cobs[index].name_len);
			name_len = cobs[index].name_len;
			
			if (mkdir (cont_path, 0766) != 0) {
				if (errno == ENOENT) {
					csmgrd_log_write (CefC_Log_Error, 
						"Failed to create the cache directory for the each content\n");
					goto NextCob;
				}
				if (errno == EACCES) {
					csmgrd_log_write (CefC_Log_Error, 
						"Please make sure that you have write permission for %s.\n", 
						hdl->fsc_cache_path);
					goto NextCob;
				}
			}
		}
		
		/* Check the work cob is cached or not 		*/
		mask = 1;
		x = cobs[index].chnk_num / 64;
		mask <<= (cobs[index].chnk_num % 64);
		
		if (rcd->cob_map[x] & mask) {
			goto NextCob;
		}
		
		/* Update the page to write the received cob 		*/
		work_page_index = cobs[index].chnk_num / FscC_Page_Cob_Num;
		
		if (work_page_index != prev_page_index) {
			
			if (fp) {
#ifdef CefC_Debug
				csmgrd_dbg_write (CefC_Dbg_Finer, 
					"cob put thread writes the page: %s\n", cont_path);
#endif // CefC_Debug
				fwrite (file_area, FscC_File_Area, 1, fp);
				fclose (fp);
				fp = NULL;
			}
			
			prev_page_index = work_page_index;
			sprintf (file_path, 
				"%s/%d/%d", hdl->fsc_cache_path, work_con_index, work_page_index);
#ifdef CefC_Debug
			csmgrd_dbg_write (CefC_Dbg_Finer, 
				"cob put thread selects the content page: %s\n", file_path);
#endif // CefC_Debug
			fp = fopen (file_path, "rb");
			if (fp) {
				ret_bytes = fread (file_area, FscC_File_Area, 1, fp);
				fclose (fp);
				fp = NULL;
				if (ret_bytes < 1) {
					goto NextCob;
				}
				fp = fopen (file_path, "wb");
				if (!fp) {
					csmgrd_log_write (CefC_Log_Error, 
						"Failed to open the cache file (%s)\n", file_path);
					goto NextCob;
				}
			} else {
				fp = fopen (file_path, "wb");
				if (fp) {
					memset (file_area, 0, FscC_File_Area);
					fwrite (file_area, FscC_File_Area, 1, fp);
					fclose (fp);
					fp = fopen (file_path, "wb");
				} else {
					csmgrd_log_write (CefC_Log_Error, 
						"Failed to open the cache file (%s)\n", file_path);
					goto NextCob;
				}
			}
		}
		prev_page_index = work_page_index;
		
		/* Updates the content information 			*/
		csmgrd_stat_cob_update (csmgr_stat_hdl, cobs[index].name, cobs[index].name_len, 
				cobs[index].chnk_num, cobs[index].pay_len, cobs[index].expiry, 
				nowt, cobs[index].node);
		
		/* Write to memory 							*/
		work_pos_index = cobs[index].chnk_num % FscC_Page_Cob_Num;
		memcpy (file_area[work_pos_index].msg, cobs[index].msg, cobs[index].msg_len);
		file_area[work_pos_index].msg_len 	= cobs[index].msg_len;
		file_area[work_pos_index].chnk_num 	= cobs[index].chnk_num;
		file_area[work_pos_index].pay_len 	= cobs[index].pay_len;
		
		if (hdl->algo_apis.insert) {
			(*(hdl->algo_apis.insert))(&cobs[index]);
		} else {
			hdl->cache_cobs++;
		}
		
		if (hdl->cache_cobs >= hdl->cache_cob_max) {
			break;
		}
NextCob:
		index++;
	}
	
	if (fp) {
#ifdef CefC_Debug
		csmgrd_dbg_write (CefC_Dbg_Finer, 
			"cob put thread writes the page: %s\n", cont_path);
#endif // CefC_Debug
		fwrite (file_area, FscC_File_Area, 1, fp);
		fclose (fp);
	}
	
	return (0);
}
/*--------------------------------------------------------------------------------------
	Store API
----------------------------------------------------------------------------------------*/
static int
fsc_cs_store (
	CsmgrdT_Content_Entry* entry
) {
	if (hdl->cache_cobs < hdl->cache_cob_max) {
		hdl->cache_cobs++;
		return (1);
	}
	
	return (-1);
}
/*--------------------------------------------------------------------------------------
	Remove API
----------------------------------------------------------------------------------------*/
static void
fsc_cs_remove (
	unsigned char* key,
	int key_len
) {
	struct tlv_hdr* tlv_hdp;
	struct value32_tlv* tlv32_hdp;
	int index = 0;
	int find_chunk_f = 0;
	uint16_t type;
	uint16_t length;
	uint32_t chunk_num;
	
	while (index < key_len) {
		tlv_hdp = (struct tlv_hdr*) &key[index];
		type 	= ntohs (tlv_hdp->type);
		length 	= ntohs (tlv_hdp->length);
		
		if (length < 1) {
			return;
		}
		if (type == CefC_T_CHUNK) {
			find_chunk_f = 1;
			break;
		}
		index += sizeof (struct tlv_hdr) + length;
	}
	
	if (find_chunk_f) {
		tlv32_hdp = (struct value32_tlv*) &key[index];
		chunk_num = ntohl (tlv32_hdp->value);
		csmgrd_stat_cob_remove (
			csmgr_stat_hdl, &key[0], key_len - index, chunk_num, 0);
		
		hdl->cache_cobs--;
	}
	
	return;
}
/*--------------------------------------------------------------------------------------
	Check FileSystem Cache Directory
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_root_dir_check (
	char* root_path								/* csmgr root path						*/
) {
	DIR* main_dir;
	
	main_dir = opendir (root_path);
	if(main_dir == NULL) {
		/* Root dir is not exist	*/
		return (-1);
 	}
	closedir (main_dir);
	return (0);
}
/*--------------------------------------------------------------------------------------
	Initialize FileSystemCache
----------------------------------------------------------------------------------------*/
static uint32_t						/* The return value is FSCID						*/
fsc_cache_id_create (
	FscT_Cache_Handle* hdl
) {
	DIR* cache_dir;
	int cache_id;
	char cache_path[CefC_Csmgr_File_Path_Length] = {0};
	uint32_t fsc_id = 0xFFFFFFFF;
	
	srand ((unsigned int) time (NULL));
	
	cache_id = rand () % FscC_Max_Node_Inf_Num;
	sprintf (cache_path, "%s/%d", hdl->fsc_root_path, cache_id);
	cache_dir = opendir (cache_path);
	
	if (cache_dir) {
		closedir (cache_dir);
		
		if (fsc_recursive_dir_clear (cache_path) != 0) {
			csmgrd_log_write (CefC_Log_Error, "Failed to remove the cache directory\n");
			return (fsc_id);
		}
	}
	
	if (mkdir (cache_path, 0766) != 0) {
		csmgrd_log_write (CefC_Log_Error, 
			"Failed to create the cache directory in %s\n", hdl->fsc_root_path);
		
		if (errno == EACCES) {
			csmgrd_log_write (CefC_Log_Error, 
				"Please make sure that you have write permission for %s.\n", 
				hdl->fsc_root_path);
		}
		if (errno == ENOENT) {
			csmgrd_log_write (CefC_Log_Error, 
				"Please make sure that %s exists.\n", hdl->fsc_root_path);
		}
		
		return (fsc_id);
	}
	strcpy (hdl->fsc_cache_path, cache_path);
	fsc_id = (uint32_t) cache_id;
	
	return (fsc_id);
}
/*--------------------------------------------------------------------------------------
	Read config file
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_config_read (
	FscT_Config_Param* conf_param				/* Fsc config parameter					*/
) {
	FILE*	fp = NULL;								/* file pointer						*/
	char	file_name[PATH_MAX];					/* file name						*/

	char	param[4096] = {0};						/* parameter						*/
	char	param_buff[4096] = {0};					/* param buff						*/
	int		len;									/* read length						*/

	char*	option;									/* deny option						*/
	char*	value;									/* parameter						*/

	int		i, n;
	int64_t	res;

	memset (conf_param, 0, sizeof (FscT_Config_Param));

	/* Obtains the directory path where the cefnetd's config file is located. */
	sprintf (file_name, "%s/csmgrd.conf", csmgr_conf_dir);
	
	/* Opens the csmgr's config file. */
	fp = fopen (file_name, "r");
	if (fp == NULL) {
		csmgrd_log_write (CefC_Log_Error, "[%s] open %s\n", __func__, file_name);
		return (-1);
	}

	/* Set default value */
	strcpy (conf_param->fsc_root_path, csmgr_conf_dir);
	conf_param->cache_cob_max 	= 65535;
	sprintf (conf_param->algo_name, "libcsmgrd_lru");
	
	/* Get parameter */
	while (fgets (param_buff, sizeof (param_buff), fp) != NULL) {
		len = strlen (param_buff);
		if ((param_buff[0] == '#') || (param_buff[0] == '\n') || (len == 0)) {
			continue;
		}
		if (param_buff[len - 1] == '\n') {
			param_buff[len - 1] = '\0';
		}

		for (i = 0, n = 0; i < len; i++) {
			if (param_buff[i] != ' ') {
				param[n] = param_buff[i];
				n++;
			}
		}
		/* Get option */
		value = param;
		option = strsep (&value, "=");
		if (value == NULL) {
			continue;
		}

		if (strcmp (option, "CACHE_PATH") == 0) {
			res = strlen (value);
			if (res > CefC_Csmgr_File_Path_Length) {
				csmgrd_log_write (
					CefC_Log_Error, "Invalid value %s=%s\n", __func__, option, value);
				return (-1);
			}
			strcpy (conf_param->fsc_root_path, value);
		} else if (strcmp (option, "CACHE_ALGORITHM") == 0) {
			strcpy (conf_param->algo_name, value);
		} else if (strcmp (option, "CACHE_CAPACITY") == 0) {
			res = cef_csmgr_config_get_value (option, value);
			if ((res < 1) || (res > 819200)) {
				csmgrd_log_write (CefC_Log_Error,
					"CACHE_CAPACITY must be higher than 0 and lower than 819,200.\n");
				return (-1);
			}
			conf_param->cache_cob_max = res;
		} else {
			continue;
		}
	}
	fclose (fp);

	return (0);
}
/*--------------------------------------------------------------------------------------
	Check content expire
----------------------------------------------------------------------------------------*/
static void
fsc_cs_expire_check (
	void
) {
	int 			index = 0;
	CsmgrT_Stat* 	rcd = NULL;
	char			file_path[PATH_MAX];
	uint32_t 		i, n;
	uint64_t 		mask;
//	int 			cob_cnt=0;
	uint32_t 		chnk_num, net_chnk_num;
	unsigned char 	trg_key[65535];
	int 			trg_key_len=0;
	int 			name_len;
	
	do {
		rcd = csmgrd_stat_expired_content_info_get (csmgr_stat_hdl, &index);
		
		if (!rcd) {
			break;
		}
		
		sprintf (file_path, "%s/%d", hdl->fsc_cache_path, (int) rcd->index);
		fsc_recursive_dir_clear (file_path);


		if (hdl->algo_apis.erase) {
			for (i = 0 ; i < CsmgrT_Map_Max ; i++) {
				if (rcd->cob_map[i]) {
					mask = 0x0000000000000001;
					for (n = 0 ; n < 64 ; n++) {
						if (!rcd->cob_num) {
							goto LOOP_END;
						}
						if (rcd->cob_map[i] & mask) {
							name_len = rcd->name_len;
							memcpy (&trg_key[0], rcd->name, name_len);
							trg_key[name_len] 		= 0x00;
							trg_key[name_len + 1] 	= 0x10;
							trg_key[name_len + 2] 	= 0x00;
							trg_key[name_len + 3] 	= 0x04;
							chnk_num = (i * 64 + n);
							net_chnk_num = htonl (chnk_num);
							memcpy (&trg_key[name_len + 4], &net_chnk_num, sizeof (uint32_t));
							trg_key_len = name_len + 4 + sizeof (uint32_t);

							(*(hdl->algo_apis.erase))(trg_key, trg_key_len);

							csmgrd_stat_cob_remove (
								csmgr_stat_hdl, rcd->name, name_len, chnk_num, 0);
							
							hdl->cache_cobs--;
							
						}
						mask <<= 1;
					}
				}
			}
		}
LOOP_END:;

		csmgrd_stat_content_info_delete (csmgr_stat_hdl, rcd->name, rcd->name_len);
		
	} while (rcd);
	
	return;
}
/*--------------------------------------------------------------------------------------
	delete file in this directory
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_is_file_delete (
	char* filepath								/* file path							*/
) {
	int rc = 0;
	struct stat sb = {0};

	rc = stat (filepath, &sb);
	if (rc < 0) {
		csmgrd_log_write (CefC_Log_Critical,
			"stat error(%s): file path is %s\n", filepath, strerror (errno));
		return (-1);
	}
	if (S_ISDIR (sb.st_mode)) {
		return (0);
	}

	rc = unlink (filepath);
	if (rc < 0) {
		csmgrd_log_write (CefC_Log_Critical,
			"unlink error(%s): file path is %s\n", filepath, strerror (errno));
		return(-1);
	}
	return(1);
}
/*--------------------------------------------------------------------------------------
	delete directory path
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_dir_clear (
	char* filepath								/* file path							*/
) {
	int rc = 0;
	DIR *dp = NULL;
	struct dirent *ent = NULL;
	char buf[CefC_Csmgr_File_Path_Length];

	dp = opendir (filepath);
	if (dp == NULL) {
		csmgrd_log_write (CefC_Log_Error, "fsc_dir_clear(opendir(%s))", filepath);
		return (-1);
	}

	while ((ent = readdir (dp)) != NULL ) {
		if ((strcmp (".", ent->d_name) == 0 ) || (strcmp ("..", ent->d_name) == 0)) {
			continue;
		}

		snprintf (buf, sizeof (buf), "%s/%s", filepath, ent->d_name);
		rc = fsc_recursive_dir_clear (buf);
		if (rc != 0) {
			break;
		}
	}

	closedir (dp);
	return (rc);
}
/*--------------------------------------------------------------------------------------
	delete in this directory(recursive)
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_recursive_dir_clear (
	char* filepath								/* file path							*/
) {
	int rc = 0;

	rc = fsc_is_file_delete (filepath);
	if (rc == 1) {
		return (0);
	}
	if (rc != 0) {
		return (-1);
	}

	rc = fsc_dir_clear (filepath);
	if (rc != 0) {
		return (-1);
	}

	rc = rmdir (filepath);
	if (rc < 0) {
		csmgrd_log_write (
			CefC_Log_Error, "fsc_recursive_dir_clear(rmdir(%s))", filepath );
		return (-1);
	}

	return (0);
}
/*--------------------------------------------------------------------------------------
	Destroy content store
----------------------------------------------------------------------------------------*/
static void
fsc_cs_destroy (
	void
) {
	int i = 0;
	void* status;
	
	/* Destory the threads 		*/
	if (fsc_rcv_thread_f) {
		fsc_rcv_thread_f = 0;
		pthread_join (fsc_rcv_thread, &status);
	}

	/* Destroy the common work buffer 		*/
	for (i = 0 ; i < FscC_Max_Buff ; i++) {
		if (fsc_proc_cob_buff[i]) {
			free (fsc_proc_cob_buff[i]);
		}
		pthread_mutex_destroy (&fsc_comn_buff_mutex[i]);
	}
	for (i = 0 ; i < CsmgrT_Stat_Max ; i++) {
		if (fsc_tx_cob_map[i]) {
			free (fsc_tx_cob_map[i]);
		}
	}
	if (fsc_tx_buffer) {
		free (fsc_tx_buffer);
	}
	
	/* Destroy FscT_File_Element */
	if (file_area != NULL) {
		free (file_area);
		file_area = NULL;
	}
	
	/* Check handle */
	if (hdl == NULL) {
		return;
	}
	
	if (hdl->fsc_cache_path[0] != 0x00) {
		fsc_recursive_dir_clear (hdl->fsc_cache_path);
	}
	
	/* Close the loaded cache algorithm library */
	if (hdl->algo_lib) {
		if (hdl->algo_apis.destroy) {
			(*(hdl->algo_apis.destroy))();
		}
		dlclose (hdl->algo_lib);
	}
	
	/* Destroy handle */
	free (hdl);
	hdl = NULL;
	
	return;
}
/*--------------------------------------------------------------------------------------
	Function to read a ContentObject from FileSystemCache
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_item_get (
	unsigned char* key,							/* content name							*/
	uint16_t key_size,							/* content name Length					*/
	uint32_t seqno,								/* chunk num							*/
	int sock									/* received socket						*/
) {
	CsmgrT_Stat* rcd = NULL;
	uint64_t 	mask;
	uint16_t 	x;
	
	char		file_path[PATH_MAX];
	
	int 		page_index;
	int 		pos_index;
	FILE* 		fp = NULL;
	
	int 		i;
	int 		tx_cnt = 0;
	size_t 		ret_bytes;
	int			resend_1cob_f = 0;
	
	unsigned char 	trg_key[CsmgrdC_Key_Max];
	int 			trg_key_len;
	
	uint64_t nowt;
	struct timeval tv;
	
#ifdef CefC_Debug
	csmgrd_dbg_write (CefC_Dbg_Finest, "Incoming Interest : seqno = %u\n", seqno);
#endif // CefC_Debug
	/* Obtain the information of the specified content 		*/
	rcd = csmgrd_stat_content_info_access (csmgr_stat_hdl, key, key_size);
	
	if (!rcd) {
		return (CefC_Csmgr_Cob_NotExist);
	}
	if (rcd->expire_f) {
		sprintf (file_path, "%s/%d", hdl->fsc_cache_path, (int) rcd->index);
#ifdef CefC_Debug
		csmgrd_dbg_write (CefC_Dbg_Fine, "Delete the expired content = %s\n", file_path);
#endif // CefC_Debug
		fsc_recursive_dir_clear (file_path);
		csmgrd_stat_content_info_delete (csmgr_stat_hdl, key, key_size);
		return (CefC_Csmgr_Cob_NotExist);
	}
	
	trg_key_len = csmgrd_name_chunknum_concatenate (key, key_size, seqno, trg_key);
	
	/* Check the work cob is cached or not 		*/
	mask = 1;
	x = seqno / 64;
	mask <<= (seqno % 64);
	
	if (!(rcd->cob_map[x] & mask)) {
#ifdef CefC_Debug
		csmgrd_dbg_write (CefC_Dbg_Finest, "seqno = %u is not cached\n", seqno);
#endif // CefC_Debug
		if (hdl->algo_apis.miss) {
			(*(hdl->algo_apis.miss))(trg_key, trg_key_len);
		}
		return (CefC_Csmgr_Cob_NotExist);
	}
	if (hdl->algo_apis.hit) {
		(*(hdl->algo_apis.hit))(trg_key, trg_key_len);
	}
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000 + tv.tv_usec;
	
	if (nowt > fsc_tx_cob_time[rcd->index][x]) {
		fsc_tx_cob_map[rcd->index][x] = 0;
	}
	
	if (fsc_tx_cob_map[rcd->index][x] & mask) {
//		fsc_tx_cob_map[rcd->index][x] &= ~mask;
#ifdef CefC_Debug
		csmgrd_dbg_write (CefC_Dbg_Finest, "seqno = %u is already fowarded\n", seqno);
#endif // CefC_Debug
		resend_1cob_f = 1;
	}
	
	/* Open the file that specified cob is cached 		*/
	page_index = (int)(seqno / FscC_Page_Cob_Num);
	sprintf (file_path, "%s/%d/%d", hdl->fsc_cache_path, (int) rcd->index, page_index);
	
	fp = fopen (file_path, "rb");
	if (!fp) {
		csmgrd_log_write (CefC_Log_Error, 
			"Failed to open the cache file (%s)\n", file_path);
		goto ItemGetPost;
	}
	ret_bytes = fread (file_area, FscC_File_Area, 1, fp);
	if (ret_bytes < 1) {
		goto ItemGetPost;
	}
	
	/* Send the cobs 		*/
	pos_index = (int)(seqno % FscC_Page_Cob_Num);
#ifdef CefC_Debug
	csmgrd_dbg_write (CefC_Dbg_Finest, 
		"send seqno = %u (%d bytes)\n", seqno, file_area[pos_index].msg_len);
#endif // CefC_Debug
	csmgrd_plugin_cob_msg_send (
		sock, file_area[pos_index].msg, file_area[pos_index].msg_len);
	if(resend_1cob_f == 1){
		if (fp) {
			fclose (fp);
		}
		return (CefC_Csmgr_Cob_Exist);
	}
	tx_cnt++;
	seqno++;
	fsc_tx_cob_time[rcd->index][x] = nowt + FscC_Map_Reset_Time;
	
	for (i = pos_index + 1 ; i < FscC_Page_Cob_Num ; i++) {
		if (tx_cnt < FscC_Tx_Cob_Num) {
			mask = 1;
			x = seqno / 64;
			mask <<= (seqno % 64);
			
			if (!(rcd->cob_map[x] & mask)) {
				seqno++;
				continue;
			}
			
			if (nowt > fsc_tx_cob_time[rcd->index][x]) {
				fsc_tx_cob_time[rcd->index][x] = nowt + FscC_Map_Reset_Time;
				fsc_tx_cob_map[rcd->index][x] = 0;
			}
			
			if (fsc_tx_cob_map[rcd->index][x] & mask) {
//				fsc_tx_cob_map[rcd->index][x] &= ~mask;
				seqno++;
				continue;
			}
			fsc_tx_cob_map[rcd->index][x] |= mask;
#ifdef CefC_Debug
			csmgrd_dbg_write (CefC_Dbg_Finest, 
				"send seqno = %u (%d bytes)\n", seqno, file_area[i].msg_len);
#endif // CefC_Debug
			csmgrd_plugin_cob_msg_send (
				sock, file_area[i].msg, file_area[i].msg_len);
			tx_cnt++;
			seqno++;
		} else {
			break;
		}
	}
	
ItemGetPost:
	if (fp) {
		fclose (fp);
	}
	
	return (CefC_Csmgr_Cob_Exist);
}
/*--------------------------------------------------------------------------------------
	Upload content byte steream
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_item_puts (
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
	
	for (i = 0 ; i < FscC_Max_Buff ; i++) {
		
		if (pthread_mutex_trylock(&fsc_comn_buff_mutex[i]) != 0) {
			continue;
		}
		
		if (fsc_proc_cob_buff_idx[i] == 0) {
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
					&fsc_proc_cob_buff[i][fsc_proc_cob_buff_idx[i]], 
					&entry, 
					sizeof (CsmgrdT_Content_Entry));
				
				fsc_proc_cob_buff_idx[i] += 1;
				index += res;
				
				if (fsc_proc_cob_buff_idx[i] + 1 == CsmgrC_Buff_Num) {
					break;
				}
			}
		}
		pthread_mutex_unlock (&fsc_comn_buff_mutex[i]);
		
		if (index >= msg_len) {
			break;
		}
	}
	
#ifdef CefC_Debug
	if (i == FscC_Max_Buff) {
		csmgrd_dbg_write (CefC_Dbg_Fine, 
			"cob rcv thread lost %d bytes\n", msg_len - index);
	}
#endif // CefC_Debug
	
	return (0);
}

/*--------------------------------------------------------------------------------------
	Function to increment access count
----------------------------------------------------------------------------------------*/
static void
fsc_cs_ac_cnt_inc (
	unsigned char* key,							/* content name							*/
	uint16_t key_size,							/* content name Length					*/
	uint32_t seq_num							/* sequence number						*/
) {
	struct tlv_hdr* tlv_hdp;
	struct value32_tlv* tlv32_hdp;
	int index = 0;
	int find_chunk_f = 0;
	uint16_t type;
	uint16_t length;
	uint32_t chunk_num;
	
	if (hdl->algo_apis.hit) {
		(*(hdl->algo_apis.hit))(key, key_size);
	}
	
	if (seq_num) {
		return;
	}
	
	while (index < key_size) {
		tlv_hdp = (struct tlv_hdr*) &key[index];
		type 	= ntohs (tlv_hdp->type);
		length 	= ntohs (tlv_hdp->length);
		
		if (length < 1) {
			return;
		}
		if (type == CefC_T_CHUNK) {
			find_chunk_f = 1;
			break;
		}
		index += sizeof (struct tlv_hdr) + length;
	}
	
	if (find_chunk_f) {
		tlv32_hdp = (struct value32_tlv*) &key[index];
		chunk_num = ntohl (tlv32_hdp->value);
		
		if (chunk_num == 0) {
			csmgrd_stat_access_count_update (
				csmgr_stat_hdl, &key[0], key_size - index);
		}
	}
	
	return;
}

#ifdef CefC_Ccore
/*--------------------------------------------------------------------------------------
	Change cache capacity
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_change_cap (
	uint64_t cap								/* New capacity to set					*/
) {
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
			(*(hdl->algo_apis.init))(cap, fsc_cs_store, fsc_cs_remove);
		}
	}
	csmgrd_stat_cache_capacity_update (csmgr_stat_hdl, (uint32_t) cap);
	hdl->cache_cob_max = (int) cap;
	
	fsc_recursive_dir_clear (hdl->fsc_cache_path);
	hdl->fsc_id = fsc_cache_id_create (hdl);
	if (hdl->fsc_id == 0xFFFFFFFF) {
		csmgrd_log_write (CefC_Log_Error, "FileSystemCache init error\n");
		return (-1);
	}
	
	return (0);
}
/*--------------------------------------------------------------------------------------
	Set content lifetime
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_content_lifetime_set (
	unsigned char* name,						/* Content name							*/
	uint16_t name_len,							/* Content name length					*/
	uint64_t lifetime							/* Content Lifetime						*/
) {
	uint64_t nowt;
	struct timeval tv;
	uint64_t new_life;
	
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000 + tv.tv_usec;
	new_life = nowt + lifetime * 1000000;
	
	/* Updtes the content information */
	csmgrd_stat_content_lifetime_update (csmgr_stat_hdl, name, name_len, new_life);
	
	return (0);
}
#endif // CefC_Ccore


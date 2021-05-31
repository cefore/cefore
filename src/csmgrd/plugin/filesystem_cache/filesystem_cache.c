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
 * filesystem_cache.c
 */
#define __CSMGRD_FILE_SYSTEM_CACHE_SOURCE__

/*
	fsc_cache.c is a primitive filesystem cache implementation.
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
#include <sys/ipc.h> 
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/mman.h>
#include <pthread.h>
#include <semaphore.h>
#include <sched.h>

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

#define FscC_Max_Buff 			16
#define FscC_Min_Buff			16

#define FscC_Tx_Cob_Num 		256
#define FscC_Sent_Reset_Time	50000			/* Reset sent info (50msec)			*/

#define FscC_File_Head_Area			(sizeof (FscT_File_Head_Element) * FscC_Page_Cob_Num)

#define FcsC_SEMNAME			"/ceffscsem"

#define FscC_Page_File_Num_in_Dir	1000


#define FscC_Page_Cob_Num		4096
#define FscC_File_Page_Num		1000

#define FSC_RECORD_CORRECT_SIZE		CefC_Max_Header_Size

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

/****************************************************************************************
 State Variables
 ****************************************************************************************/
static FscT_Cache_Handle* hdl = NULL;						/* FileSystemCache Handle	*/
static CsmgrdT_Content_Entry* cobs_arr = NULL;
int fsc_compare_name (const void *a, const void *b);

static char csmgr_conf_dir[PATH_MAX] = {"/usr/local/cefore"};

static pthread_mutex_t 			fsc_comn_buff_mutex[FscC_Max_Buff];
static sem_t*					fsc_comn_buff_sem;
static pthread_t				fsc_rcv_thread;
static int 						fsc_thread_f = 0;
static CsmgrdT_Content_Entry* 	fsc_proc_cob_buff[FscC_Max_Buff]		= {0};
static int 						fsc_proc_cob_buff_idx[FscC_Max_Buff] 	= {0};
static CsmgrT_Stat_Handle 		csmgr_stat_hdl;
static pthread_mutex_t 			fsc_cs_mutex = PTHREAD_MUTEX_INITIALIZER;

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
	Destroy content store
----------------------------------------------------------------------------------------*/
static void
fsc_cs_destroy (
	void
);
/*--------------------------------------------------------------------------------------
	Check content expire
----------------------------------------------------------------------------------------*/
static void
fsc_cs_expire_check (
	void
);
/*--------------------------------------------------------------------------------------
	Function to read a ContentObject from Filesystem Cache
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_item_get (
	unsigned char* key,							/* content name							*/
	uint16_t key_size,							/* content name Length					*/
	uint32_t seqno,								/* chunk num							*/
	int sock									/* received socket						*/
);
/*--------------------------------------------------------------------------------------
	Upload content byte steream
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_item_puts (
	unsigned char* msg, 
	int msg_len
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
/*--------------------------------------------------------------------------------------
	function for processing the received message
----------------------------------------------------------------------------------------*/
static void* 
fsc_cob_process_thread (
	void* arg
);
/*--------------------------------------------------------------------------------------
	writes the cobs to filesystem cache
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_cob_write (
	CsmgrdT_Content_Entry* cobs, 
	int cob_num
);
/*--------------------------------------------------------------------------------------
	Read config file
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_config_read (
	FscT_Config_Param* conf_param				/* Fsc config parameter					*/
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
#ifdef CefC_Ccore
/*--------------------------------------------------------------------------------------
	Change cache capacity
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_change_cap (
	uint64_t cap								/* New capacity to set					*/
);
/*--------------------------------------------------------------------------------------
	Set content lifetime
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_set_lifetime (
	unsigned char* name,						/* Content name							*/
	uint16_t name_len,							/* Content name length					*/
	uint64_t lifetime							/* Content Lifetime						*/
);
/*--------------------------------------------------------------------------------------
	Delete content entry
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_del (
	unsigned char* name,						/* Content name							*/
	uint16_t name_len,							/* Content name length					*/
	uint32_t chunk_num							/* ChunkNumber							*/
);
#endif // CefC_Ccore

/*--------------------------------------------------------------------------------------
	get lifetime for ccninfo
----------------------------------------------------------------------------------------*/
static int										/* This value MAY be -1 if the router does not know or cannot report. */
fsc_cache_lifetime_get (
	unsigned char* name,						/* content name							*/
	uint16_t name_len,							/* content name Length					*/
	uint32_t* cache_time,						/* The elapsed time (seconds) after the oldest	*/
												/* content object of the content is cached.		*/
	uint32_t* lifetime,							/* The lifetime (seconds) of a content object, 	*/
												/* which is removed first among the cached content objects.*/
	uint8_t partial_f							/* when flag is 0, exact match			*/
												/* when flag is 1, partial match		*/
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

/****************************************************************************************
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Road the cache plugin
----------------------------------------------------------------------------------------*/
int
csmgrd_filesystem_plugin_load (
	CsmgrdT_Plugin_Interface* cs_in, 
	const char* config_dir
) {
	CSMGRD_SET_CALLBACKS (
		fsc_cs_create, fsc_cs_destroy, fsc_cs_expire_check, fsc_cache_item_get,
		fsc_cache_item_puts, fsc_cs_ac_cnt_inc, fsc_cache_lifetime_get);
	
#ifdef CefC_Ccore
	cs_in->cache_cap_set 		= fsc_change_cap;
	cs_in->content_lifetime_set = fsc_cache_set_lifetime;
	cs_in->content_cache_del	= fsc_cache_del;
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
	csmgrd_log_init ("filesystem", 1);
	csmgrd_log_init2 (csmgr_conf_dir);
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
	hdl->cache_capacity = conf_param.cache_capacity;
	strcpy (hdl->algo_name, conf_param.algo_name);
	hdl->algo_name_size = conf_param.algo_name_size;
	hdl->algo_cob_size = conf_param.algo_cob_size;
	hdl->cache_cobs = 0;
	strcpy (hdl->fsc_root_path, conf_param.fsc_root_path);
	
	/* Check for excessive or insufficient memory resources for cache algorithm library */
	if (strcmp (hdl->algo_name, "None") != 0) {
		if (csmgrd_cache_algo_availability_check (
				hdl->cache_capacity, hdl->algo_name, hdl->algo_name_size, hdl->algo_cob_size, "filesystem")
			< 0) {
			return (-1);
		}
	}
	
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
	
	/* Loads the library for cache algorithm 		*/
	if (strcmp (conf_param.algo_name, "None")) {
		int rc = snprintf (hdl->algo_name, sizeof (hdl->algo_name), "%s%s", conf_param.algo_name, CsmgrdC_Library_Name);
		if ( rc < 0 ) {
			csmgrd_log_write (CefC_Log_Error, "create library for cache algorithm name\n");
			return (-1);
		}
		res = csmgrd_lib_api_get (hdl->algo_name, &hdl->algo_lib, &hdl->algo_apis);
		if (res < 0) {
			csmgrd_log_write (CefC_Log_Error, "Load the lib (%s)\n", hdl->algo_name);
			return (-1);
		}
		csmgrd_log_write (CefC_Log_Info, "Library : %s ... OK\n", hdl->algo_name);
		if (hdl->algo_apis.init) {
			(*(hdl->algo_apis.init))(hdl->cache_capacity, fsc_cs_store, fsc_cs_remove);
		}
	} else {
		csmgrd_log_write (CefC_Log_Info, "Library : Not Specified\n");
	}
	
	/* Creates the process buffer 		*/
	for (i = 0 ; i < FscC_Max_Buff ; i++) {
		if (i < FscC_Min_Buff) {
			fsc_proc_cob_buff[i] = (CsmgrdT_Content_Entry*) 
				malloc (sizeof (CsmgrdT_Content_Entry) * CsmgrC_Buff_Num);
			if (fsc_proc_cob_buff[i] == NULL) {
				csmgrd_log_write (CefC_Log_Error, 
					"Failed to allocation process cob buffer\n");
				return (-1);
			}
			memset (fsc_proc_cob_buff[i], 0,  sizeof (CsmgrdT_Content_Entry) * CsmgrC_Buff_Num);
		} else {
			fsc_proc_cob_buff[i] = NULL;
		}
		fsc_proc_cob_buff_idx[i] = 0;
		pthread_mutex_init (&fsc_comn_buff_mutex[i], NULL);
	}
	fsc_comn_buff_sem = sem_open (FcsC_SEMNAME, O_CREAT | O_EXCL, 0777, 0);
	if (fsc_comn_buff_sem == SEM_FAILED && errno == EEXIST) {
		sem_unlink (FcsC_SEMNAME);
		fsc_comn_buff_sem = sem_open (FcsC_SEMNAME, O_CREAT | O_EXCL, 0777, 0);
	}
	if (fsc_comn_buff_sem == SEM_FAILED) {
		csmgrd_log_write (CefC_Log_Error, "Failed to create the new semaphore\n");
		return (-1);
	}
	csmgrd_log_write (CefC_Log_Info, "Inits rx buffer ... OK\n");
	
	/* Creates the threads 		*/
	if (pthread_create (&fsc_rcv_thread, NULL, fsc_cob_process_thread, hdl) == -1) {
		csmgrd_log_write (CefC_Log_Error, "Failed to create the new thread\n");
		return (-1);
	}

	fsc_thread_f = 1;
	csmgrd_log_write (CefC_Log_Info, "Inits rx thread ... OK\n");
	
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
fsc_cob_process_thread (
	void* arg
) {
	int i;
	
	while (fsc_thread_f) {
		sem_wait (fsc_comn_buff_sem);
		if (!fsc_thread_f)
			break;
		for (i = 0 ; i < FscC_Max_Buff ; i++) {
			if (pthread_mutex_trylock (&fsc_comn_buff_mutex[i]) != 0) {
				continue;
			}
			if (fsc_proc_cob_buff_idx[i] > 0) {
#ifdef CefC_Debug
				csmgrd_dbg_write (CefC_Dbg_Fine, 
					"cob put thread starts to write %d cobs\n", fsc_proc_cob_buff_idx[i]);
#endif // CefC_Debug
				fsc_cache_cob_write (&fsc_proc_cob_buff[i][0], fsc_proc_cob_buff_idx[i]);
				fsc_proc_cob_buff_idx[i] = 0;
				if (i >= FscC_Min_Buff) {
					free (fsc_proc_cob_buff[i]);
					fsc_proc_cob_buff[i] = NULL;
				}
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
	function for sort cobs
----------------------------------------------------------------------------------------*/
int
fsc_compare_name (const void *a, const void *b) {
	int len;
	int ret;
	if (cobs_arr[*(int *)a].name_len > cobs_arr[*(int *)b].name_len) {
		len = cobs_arr[*(int *)a].name_len;
	} else {
		len = cobs_arr[*(int *)b].name_len;
	}
	ret = memcmp (cobs_arr[*(int *)a].name, cobs_arr[*(int *)b].name, len);
	if (ret == 0) {
		if (cobs_arr[*(int *)a].chnk_num > cobs_arr[*(int *)b].chnk_num)
			ret = 1;
		else if (cobs_arr[*(int *)a].chnk_num < cobs_arr[*(int *)b].chnk_num)
			ret = -1;
		else
			ret = 0;
	}
	return (ret);
}

/*--------------------------------------------------------------------------------------
	Store API
----------------------------------------------------------------------------------------*/
static int 
fsc_cs_store (
	CsmgrdT_Content_Entry* new_entry
) {
	
	; /* NOP */

	return (0);
}

/*--------------------------------------------------------------------------------------
	Remove API
----------------------------------------------------------------------------------------*/
static void
fsc_cs_remove (
	unsigned char* key, 
	int key_len
) {
	struct tlv_hdr* 	tlv_hdp;
	struct value32_tlv* tlv32_hdp;
	int 				find_chunk_f = 0;
	uint16_t 			type;
	uint32_t 			chunk_num;
	CsmgrT_Stat*		rcd = NULL;
	uint32_t			x, n;
	uint64_t 			mask;

	
	tlv_hdp = (struct tlv_hdr*) &key[key_len-8];
	type 	= ntohs (tlv_hdp->type);
		
	if (type == CefC_T_CHUNK) {
		find_chunk_f = 1;
	}
	if (find_chunk_f) {
		tlv32_hdp = (struct value32_tlv*) &key[key_len-8];
		chunk_num = ntohl (tlv32_hdp->value);
		rcd = csmgrd_stat_content_info_get (csmgr_stat_hdl, &key[0], key_len - 8);
		if (!rcd) {
			return;
		}
		/* Removes the cache  		*/
		mask = 1;
		x = chunk_num / 64;
		n = chunk_num % 64;
		if ((rcd->map_max-1) < x) {
			return;
		}
//		if (hdl->algo_apis.erase) {
			if (rcd->cob_map[x]) {
				mask <<= n;
				if (rcd->cob_map[x] & mask) {
					if (rcd->cob_num == 1) {
						char file_path[PATH_MAX];
						sprintf (file_path, "%s/%d", hdl->fsc_cache_path, (int) rcd->index);
						fsc_recursive_dir_clear (file_path);
					}
					csmgrd_stat_cob_remove (
						csmgr_stat_hdl, &key[0], key_len - 8, chunk_num, 0);
			
					hdl->cache_cobs--;
				}
			}
//		}
	}
	return;
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
	
	pthread_mutex_destroy (&fsc_cs_mutex);
	
	/* Destory the threads 		*/
	if (fsc_thread_f) {
		fsc_thread_f = 0;
		sem_post (fsc_comn_buff_sem);	/* To avoid deadlock */
		pthread_join (fsc_rcv_thread, &status);
	}
	sem_close (fsc_comn_buff_sem);
	sem_unlink (FcsC_SEMNAME);

	/* Destroy the common work buffer 		*/
	for (i = 0 ; i < FscC_Max_Buff ; i++) {
		if (fsc_proc_cob_buff[i]) {
			free (fsc_proc_cob_buff[i]);
		}
		pthread_mutex_destroy (&fsc_comn_buff_mutex[i]);
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
	uint32_t 		chnk_num, net_chnk_num;
	unsigned char 	trg_key[65535];
	int 			trg_key_len = 0;
	int 			name_len;
	uint64_t		cob_cnt;
	
	if (pthread_mutex_trylock (&fsc_cs_mutex) != 0) {
		return;
	}
	while (1) {
		rcd = csmgrd_stat_expired_content_info_get (csmgr_stat_hdl, &index);
		
		if (!rcd) {
			break;
		}
		
		sprintf (file_path, "%s/%d", hdl->fsc_cache_path, (int) rcd->index);
		fsc_recursive_dir_clear (file_path);

		cob_cnt = rcd->cob_num;
		if (hdl->algo_apis.erase) {
			for (i = 0 ; i < rcd->map_max ; i++) {
				if (cob_cnt == 0) {
					goto LOOP_END;
				}
				if (rcd->cob_map[i]) {
					mask = 0x0000000000000001;
					for (n = 0 ; n < 64 ; n++) {
						if (cob_cnt == 0) {
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
							cob_cnt--;
						}
						mask <<= 1;
					}
				}
			}
		} else {
			csmgrd_stat_content_info_delete (csmgr_stat_hdl, rcd->name, rcd->name_len);
			hdl->cache_cobs -= cob_cnt;
		}
LOOP_END:;
		
	}
	pthread_mutex_unlock (&fsc_cs_mutex);
	
	return;
	
}

/*--------------------------------------------------------------------------------------
	Function to read a ContentObject from filesystem cache
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_item_get (
	unsigned char* key,							/* content name							*/
	uint16_t key_size,							/* content name Length					*/
	uint32_t seqno,								/* chunk num							*/
	int sock									/* received socket						*/
) {
	CsmgrT_Stat* rcd = NULL;
	uint32_t	file_msglen;
	uint64_t 	mask;
	uint32_t 	x;
	char		file_path[PATH_MAX];
	static char	red_file_path[PATH_MAX] = {0};
	int 		cob_block_index;
	static int  red_cob_block_index = -1;
	int			rtc;
	int 		page_index;
	int 		pos_index;
	FILE*		fp = NULL;
	int 		i;
	int 		tx_cnt = 0;
	int			resend_1cob_f = 0;
	int			send_cob_f = 0;
	unsigned char 	trg_key[CsmgrdC_Key_Max];
	int 			trg_key_len;
	uint64_t nowt;
	struct timeval tv;
	static unsigned char*	page_cob_buf = NULL;
	int				rcdsize;
	
#ifdef CefC_Debug
	csmgrd_dbg_write (CefC_Dbg_Finest, "Incoming Interest : seqno = %u\n", seqno);
#endif // CefC_Debug
	pthread_mutex_lock (&fsc_cs_mutex);
	/* Obtain the information of the specified content 		*/
	rcd = csmgrd_stat_content_info_access (csmgr_stat_hdl, key, key_size);
	if (!rcd) {
		pthread_mutex_unlock (&fsc_cs_mutex);
		return (CefC_Csmgr_Cob_NotExist);
	}
	if (rcd->expire_f) {
		sprintf (file_path, "%s/%d", hdl->fsc_cache_path, (int) rcd->index);
#ifdef CefC_Debug
		csmgrd_dbg_write (CefC_Dbg_Fine, "Delete the expired content = %s\n", file_path);
#endif // CefC_Debug
		fsc_recursive_dir_clear (file_path);
		csmgrd_stat_content_info_delete (csmgr_stat_hdl, key, key_size);
		hdl->cache_cobs -= rcd->cob_num;
		pthread_mutex_unlock (&fsc_cs_mutex);
		return (CefC_Csmgr_Cob_NotExist);
	}
	
	trg_key_len = csmgrd_name_chunknum_concatenate (key, key_size, seqno, trg_key);
	
	/* Check the work cob is cached or not 		*/
	mask = 1;
	x = seqno / 64;
	mask <<= (seqno % 64);
	
	file_msglen = rcd->file_msglen;
	rcdsize = sizeof (uint16_t) + file_msglen;
	
	if ((rcd->map_max-1) < x || !(rcd->cob_map[x] & mask)) {
#ifdef CefC_Debug
		csmgrd_dbg_write (CefC_Dbg_Finest, "seqno = %u is not cached\n", seqno);
#endif // CefC_Debug
		if (hdl->algo_apis.miss) {
			(*(hdl->algo_apis.miss))(trg_key, trg_key_len);
		}
		pthread_mutex_unlock (&fsc_cs_mutex);
		return (CefC_Csmgr_Cob_NotExist);
	}
	if (hdl->algo_apis.hit) {
		(*(hdl->algo_apis.hit))(trg_key, trg_key_len);
	}
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;
		
	if (nowt > rcd->tx_time) {
		rcd->tx_seq = 0;
		rcd->tx_num = -1;
	}
	if (rcd->tx_num ==-1) {
		send_cob_f = 1;
	} else {
		if (seqno >= rcd->tx_seq && seqno < (rcd->tx_seq + rcd->tx_num)) {
			resend_1cob_f = 1;
		} else {
			send_cob_f = 1;
		}
	}
	if (send_cob_f == 0 && resend_1cob_f == 0) {
		pthread_mutex_unlock (&fsc_cs_mutex);
		return (CefC_Csmgr_Cob_NotExist);
	}
	if (send_cob_f == 1) {
		rcd->tx_seq = seqno;
		rcd->tx_num = FscC_Tx_Cob_Num;
		rcd->tx_time = nowt + FscC_Sent_Reset_Time;
	}
	
	/* Open the file that specified cob is cached 		*/
	cob_block_index = (int)(seqno / FscC_Page_Cob_Num) % FscC_File_Page_Num;
	page_index = (int)(seqno / FscC_Page_Cob_Num/FscC_File_Page_Num);
	sprintf (file_path, "%s/%d/%d", hdl->fsc_cache_path, (int) rcd->index, page_index);
	
	if (strcmp (red_file_path, file_path) != 0 || cob_block_index != red_cob_block_index) {
		if (page_cob_buf != NULL) {
			free (page_cob_buf);
			page_cob_buf = NULL;
		}

		fp = fopen (file_path, "rb");
		if (fp == NULL) {
			csmgrd_log_write (CefC_Log_Error, "Failed to open the cache file (%s)\n", file_path);
			goto ItemGetPost;
		}
		strcpy (red_file_path, file_path);
		red_cob_block_index = cob_block_index;
		page_cob_buf = calloc (FscC_Page_Cob_Num, rcdsize);
		fseek (fp, (int64_t)cob_block_index * (int64_t)rcdsize * FscC_Page_Cob_Num, SEEK_SET);
		for (int i=0; i<FscC_Page_Cob_Num; i++) {
			rtc = fread (&page_cob_buf[i*rcdsize], rcdsize, 1, fp);
			if (rtc != 1) {
				break;
			}
		}
	} else {
		fp = NULL;
	}
	
	/* Send the cobs 		*/
	pos_index = (int)(seqno % FscC_Page_Cob_Num);
#ifdef CefC_Debug
	{
		uint16_t mlen;
		memcpy (&mlen, &page_cob_buf[pos_index*rcdsize], sizeof (uint16_t));
		csmgrd_dbg_write (CefC_Dbg_Finest, "send seqno = %u (%u bytes)\n", seqno, mlen);
	}
#endif // CefC_Debug
	csmgrd_stat_access_count_update (
			csmgr_stat_hdl, key, key_size);
	
	/* Send Cob to cefnetd */
	uint16_t mlen;
	memcpy (&mlen, &page_cob_buf[pos_index*rcdsize], sizeof (uint16_t));
	csmgrd_plugin_cob_msg_send (
						sock, &page_cob_buf[pos_index*rcdsize+sizeof (uint16_t)], mlen);
	if (resend_1cob_f == 1) {
		if (fp != NULL) {
			fclose (fp);
		}
		pthread_mutex_unlock (&fsc_cs_mutex);
		return (CefC_Csmgr_Cob_Exist);
	}
	tx_cnt++;
	seqno++;
	
	for (i = pos_index + 1 ; i < FscC_Page_Cob_Num ; i++) {
		if (tx_cnt < FscC_Tx_Cob_Num) {
			mask = 1;
			x = seqno / 64;
			mask <<= (seqno % 64);
			
			if ((rcd->map_max-1) < x || !(rcd->cob_map[x] & mask)) {
				seqno++;
				continue;
			}
#ifdef CefC_Debug
			{
				uint16_t mlen;
				memcpy (&mlen, &page_cob_buf[i*rcdsize], sizeof (uint16_t));
				csmgrd_dbg_write (CefC_Dbg_Finest, "send seqno = %u (%u bytes)\n", seqno, mlen);
			}
#endif // CefC_Debug
			uint16_t mlen;
			memcpy (&mlen, &page_cob_buf[i*rcdsize], sizeof (uint16_t));
			if (mlen != 0) {
				csmgrd_plugin_cob_msg_send (
					sock, &page_cob_buf[i*rcdsize+sizeof (uint16_t)], mlen);
			}
			tx_cnt++;
			seqno++;
		} else {
			break;
		}
	}
	
ItemGetPost:
	if (fp != NULL) {
		fclose (fp);
	}
	pthread_mutex_unlock (&fsc_cs_mutex);
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
	int write_f = 0;
	
#ifdef CefC_Debug
	csmgrd_dbg_write (CefC_Dbg_Fine, "cob rcv thread receives %d bytes\n", msg_len);
#endif // CefC_Debug
	for (i = 0 ; i < FscC_Max_Buff ; i++) {
		
		if (pthread_mutex_trylock (&fsc_comn_buff_mutex[i]) != 0) {
			continue;
		}
		
		if (fsc_proc_cob_buff_idx[i] == 0) {
			if (i >= FscC_Min_Buff &&
				fsc_proc_cob_buff[i] == NULL) {
				
				fsc_proc_cob_buff[i] = (CsmgrdT_Content_Entry*) 
					malloc (sizeof (CsmgrdT_Content_Entry) * CsmgrC_Buff_Num);
				if (fsc_proc_cob_buff[i] == NULL) {
					csmgrd_log_write (CefC_Log_Info, 
						"Failed to allocation process cob buffer(temporary)\n");
					pthread_mutex_unlock (&fsc_comn_buff_mutex[i]);
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
		if (fsc_proc_cob_buff_idx[i] > 0) {
			write_f++;
		}
		pthread_mutex_unlock (&fsc_comn_buff_mutex[i]);
		
		if (index >= msg_len) {
			break;
		}
	}
	if (write_f > 0) {
		sem_post (fsc_comn_buff_sem);
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
	writes the cobs to filesystem cache
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
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
	char			file_path[PATH_MAX];
	int  			cob_block_index;
	int 			rcdsize;
	char			cont_path[PATH_MAX];
	FILE*			fp = NULL;
	uint64_t 		mask;
	uint32_t 		x;
	int*			indxs = NULL;
	int				cnt = 0;
	int				rbpflag = 0;
	int				swindx[FscC_Page_Cob_Num];
	uint32_t		file_msglen;
	unsigned char 	del_name[CsmgrT_Name_Max];
	uint16_t 		del_name_len = 0;
	uint32_t 		del_chunk_num = 0;
	
#define COBS_SORT

	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;

#ifdef COBS_SORT
	indxs = (int*)malloc (sizeof (int) * cob_num);
	cobs_arr = cobs;
	while (index < cob_num) {
		indxs[index] = index;
		index++;
	}
	qsort (indxs, cob_num, sizeof (int), fsc_compare_name);
#else 
	index = 0;
#endif
#ifdef COBS_SORT
	while (cnt < cob_num) {
#else 
	while (index < cob_num) {
#endif
		
#ifdef COBS_SORT
		index = indxs[cnt];
#endif
		pthread_mutex_lock (&fsc_cs_mutex);
		if (!fsc_thread_f) {
			goto NEXTCOB;
		}
		uint32_t chunk_num = cobs[index].chnk_num;
		if (cobs[index].expiry < nowt) {
			goto NEXTCOB;
		}
		if (!(hdl->algo_apis.insert)) {
			if (hdl->cache_cobs >= hdl->cache_capacity) {
				goto NEXTCOB;
			}
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
					goto NEXTCOB;
				}
			}
			work_con_index = (int) rcd->index;
			prev_page_index = -1;
			sprintf (cont_path, "%s/%d", hdl->fsc_cache_path, work_con_index);
			memcpy (name, cobs[index].name, cobs[index].name_len);
			name_len = cobs[index].name_len;
			
			if (mkdir (cont_path, 0766) != 0) {
				if (errno == ENOENT) {
					csmgrd_log_write (CefC_Log_Error, 
						"Failed to create the cache directory for the each content\n");
					goto NEXTCOB;
				}
				if (errno == EACCES) {
					csmgrd_log_write (CefC_Log_Error, 
						"Please make sure that you have write permission for %s.\n", 
						hdl->fsc_cache_path);
					goto NEXTCOB;
		}
			}
		}

		/* Cotrol record size */
		if (rcd->file_msglen == 0) {
			rcd->file_msglen 
					= ((cobs[index].msg_len + FSC_RECORD_CORRECT_SIZE) < CefC_Max_Msg_Size ? 
						(cobs[index].msg_len + FSC_RECORD_CORRECT_SIZE) : CefC_Max_Msg_Size);
			rcd->detect_chnkno = chunk_num;
		} else {
			if (rcd->cob_num == 1) {
				if (rcd->detect_chnkno > chunk_num) {
					int new_file_msglen
								= ((cobs[index].msg_len + FSC_RECORD_CORRECT_SIZE) < CefC_Max_Msg_Size ? 
									(cobs[index].msg_len + FSC_RECORD_CORRECT_SIZE) : CefC_Max_Msg_Size);
					if (rcd->file_msglen < new_file_msglen) {
						rcd->file_msglen = new_file_msglen;
						memcpy (del_name, cobs[index].name, cobs[index].name_len);
						del_name_len = cobs[index].name_len;
						del_chunk_num = rcd->detect_chnkno;
						rcd->detect_chnkno = chunk_num;
					}
				}
			}
		}
		file_msglen = rcd->file_msglen;
		rcdsize = sizeof (uint16_t) + file_msglen;

		if ( file_msglen < cobs[index].msg_len ) {
			goto NEXTCOB;
		}
		/* Check the work cob is cached or not 		*/
		mask = 1;
		x = chunk_num / 64;
		mask <<= (chunk_num % 64);
		if ((rcd->map_max-1) >= x && rcd->cob_map[x] & mask) {
			goto NEXTCOB;
		}
		/* Update the page to write the received cob 		*/
		work_page_index = chunk_num / FscC_Page_Cob_Num / FscC_File_Page_Num;
		cob_block_index = (chunk_num / FscC_Page_Cob_Num) % FscC_File_Page_Num;
		if (work_page_index != prev_page_index) {
			if (fp != NULL) {
#ifdef CefC_Debug
				csmgrd_dbg_write (CefC_Dbg_Finer, 
					"cob put thread writes the page: %s\n", cont_path);
#endif // CefC_Debug
				if (rbpflag == 1) {
					fflush (fp);
					fclose (fp);
					fp = NULL;
					rbpflag = 0;
				} else {
					fflush (fp);
					fclose (fp);
					fp = NULL;	
				}
			}
			
			prev_page_index = work_page_index;
			struct stat st;
			sprintf (file_path, 
				"%s/%d/%d", hdl->fsc_cache_path, work_con_index, work_page_index);
            if (stat (file_path, &st) != 0) {
				fp = fopen (file_path, "w");
            	fclose (fp);
            	fp = fopen (file_path, "rb+");
			}
			else {
				fp = fopen (file_path, "rb+");
				if (!fp) {
					csmgrd_log_write (CefC_Log_Error, 
						"Failed to open the cache file (%s)\n", file_path);
					goto NEXTCOB;
				}
				memset (swindx, 0 , sizeof (swindx));
				rbpflag = 1;
			}
		}
		
		/* Updates the content information 			*/
		if (hdl->algo_apis.insert) {
			(*(hdl->algo_apis.insert))(&cobs[index]);
		}
		csmgrd_stat_cob_update (csmgr_stat_hdl, cobs[index].name, cobs[index].name_len, 
				chunk_num, cobs[index].pay_len, cobs[index].expiry, 
				nowt, cobs[index].node);
		/* Delete invalid starage Cob info */
		if (del_chunk_num != 0) {
			if (del_name_len == cobs[index].name_len
				&& memcmp (del_name, cobs[index].name, del_name_len) == 0) {
				if (hdl->algo_apis.erase) {
					unsigned char 	trg_key[CsmgrdC_Key_Max];
					int 			trg_key_len;
					trg_key_len = csmgrd_name_chunknum_concatenate (
									del_name, del_name_len, del_chunk_num, trg_key);
					(*(hdl->algo_apis.erase))(trg_key, trg_key_len);
				}
				csmgrd_stat_cob_remove (csmgr_stat_hdl, del_name, del_name_len, del_chunk_num, 0);
				hdl->cache_cobs--;
				del_chunk_num = 0;
			}
		}

		/* Set to write buffer 							*/
		unsigned char wbuff[sizeof (uint16_t) + UINT16_MAX];
		int write_index = chunk_num % FscC_Page_Cob_Num;
		fseek (fp, (int64_t)cob_block_index * FscC_Page_Cob_Num * (int64_t)rcdsize
					+ (int64_t)write_index * (int64_t)rcdsize, SEEK_SET);
		memcpy (wbuff, &cobs[index].msg_len, sizeof (uint16_t));
		memcpy (&wbuff[sizeof (uint16_t)], cobs[index].msg, cobs[index].msg_len);
		fwrite (wbuff, sizeof (uint16_t) + file_msglen, 1, fp);
		fflush (fp);

		if (!(hdl->algo_apis.insert)) {
			hdl->cache_cobs++;
		}
		
NEXTCOB:
		free (cobs[index].msg);
		free (cobs[index].name);
#ifdef COBS_SORT
		cnt++;
#else
		index++;
#endif
		pthread_mutex_unlock (&fsc_cs_mutex);
	}
	
	if (fp) {
		fflush (fp);
		fclose (fp);
	}
#ifdef COBS_SORT
	free (indxs);
#endif
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
	int index = 0;
	int find_chunk_f = 0;
	uint16_t type;
	uint16_t length;
	
	pthread_mutex_lock (&fsc_cs_mutex);
	if (hdl->algo_apis.hit) {
		(*(hdl->algo_apis.hit))(key, key_size);
	}
	pthread_mutex_unlock (&fsc_cs_mutex);
	
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
		csmgrd_stat_access_count_update (
				csmgr_stat_hdl, &key[0], index);
	}
	
	return;
}

/*--------------------------------------------------------------------------------------
	Read config file
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_config_read (
	FscT_Config_Param* params						/* record parameters				*/
) {
	FILE*	fp = NULL;								/* file pointer						*/
	char	file_name[PATH_MAX];					/* file name						*/
	
	char	param[4096] = {0};						/* parameter						*/
	char	param_buff[4096] = {0};					/* param buff						*/
	int		len;									/* read length						*/
	
	char*	option;									/* deny option						*/
	char*	value;									/* parameter						*/
	
	int 	res;
	int		i, n;
	
	/* Inits parameters		*/
	memset (params, 0, sizeof (FscT_Config_Param));
	strcpy (params->fsc_root_path, csmgr_conf_dir);
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
		if (strcmp (option, "CACHE_PATH") == 0) {
			res = strlen (value);
			if (res > CefC_Csmgr_File_Path_Length) {
				csmgrd_log_write (
					CefC_Log_Error, "[%s] Invalid value %s=%s\n", __func__, option, value);
				fclose (fp);
				return (-1);
			}
			if (!(    access (value, F_OK) == 0
				   && access (value, R_OK) == 0
		   		   && access (value, W_OK) == 0
		   		   && access (value, X_OK) == 0)) {
				cef_log_write (CefC_Log_Error,
					"EXCACHE_PLUGIN (Invalid value %s=%s) - %s\n", option, value, strerror (errno));
				fclose (fp);
				return (-1);
			}
			strcpy (params->fsc_root_path, value);
		} else if (strcmp (option, "CACHE_ALGORITHM") == 0) {
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
	if (!(    access (params->fsc_root_path, F_OK) == 0
		   && access (params->fsc_root_path, R_OK) == 0
   		   && access (params->fsc_root_path, W_OK) == 0
   		   && access (params->fsc_root_path, X_OK) == 0)) {
		cef_log_write (CefC_Log_Error,
			"Invalid default fsc root path(%s) - %s\n", params->fsc_root_path, strerror (errno));
			fclose (fp);
			return (-1);
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
				"Cache capacity value must be less than or equal to 819200 when using algorithms lfu.\n");
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
fsc_change_cap (
	uint64_t cap								/* New capacity to set					*/
) {
	
	if ((cap < 1) || (cap > 0xFFFFFFFFF)) {
		csmgrd_log_write (CefC_Log_Error, "Invalid capacity\n");
		return (-1);
	}
	/* Check for excessive or insufficient memory resources for cache algorithm library */
	if (strcmp (hdl->algo_name, "None") != 0) {
		if (csmgrd_cache_algo_availability_check (
				cap, hdl->algo_name, hdl->algo_name_size, hdl->algo_cob_size, "filesystem")
			< 0) {
			return (-1);
		}
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
	csmgrd_stat_cache_capacity_update (csmgr_stat_hdl, cap);
	hdl->cache_capacity = cap;
	hdl->cache_cobs = 0;
	
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
fsc_cache_set_lifetime (
	unsigned char* name,						/* Content name							*/
	uint16_t name_len,							/* Content name length					*/
	uint64_t lifetime							/* Content Lifetime						*/
) {
	uint64_t nowt;
	struct timeval tv;
	uint64_t new_life;
	
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;
	new_life = nowt + lifetime * 1000000llu;
	
	/* Updtes the content information */
	csmgrd_stat_content_lifetime_update (csmgr_stat_hdl, name, name_len, new_life);
	
	return (0);
}
/*--------------------------------------------------------------------------------------
	Delete content entry
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_del (
	unsigned char* name,						/* Content name							*/
	uint16_t name_len,							/* Content name length					*/
	uint32_t chunk_num							/* ChunkNumber							*/
) {
	CsmgrT_Stat*	rcd = NULL;
	unsigned char 	trg_key[CsmgrdC_Key_Max];
	int 			trg_key_len;
	uint32_t		x, n;
	uint64_t 		mask = 0x0000000000000001;
	
	pthread_mutex_lock (&fsc_cs_mutex);
	
	trg_key_len = csmgrd_name_chunknum_concatenate (
						name, name_len, chunk_num, trg_key);
	/* Obtain the information of the specified content 		*/
	rcd = csmgrd_stat_content_info_get (csmgr_stat_hdl, name, name_len);
	
	if (!rcd) {
		pthread_mutex_unlock (&fsc_cs_mutex);
		return (-1);
	}
	
	/* Removes the cache  		*/
	x = chunk_num / 64;
	n = chunk_num % 64;

	if ((rcd->map_max-1) < x) {
		pthread_mutex_unlock (&fsc_cs_mutex);
		return (-1);
	}

	if (rcd->cob_map[x]) {
		mask <<= n;
		if (rcd->cob_map[x] & mask) {
			if (hdl->algo_apis.erase) {
				(*(hdl->algo_apis.erase))(trg_key, trg_key_len);
			}
			if (rcd->cob_num == 1) {
				char file_path[PATH_MAX];
				sprintf (file_path, "%s/%d", hdl->fsc_cache_path, (int) rcd->index);
				fsc_recursive_dir_clear (file_path);
			}
			csmgrd_stat_cob_remove (csmgr_stat_hdl, rcd->name, name_len, chunk_num, 0);
			hdl->cache_cobs--;
		}
	}

	pthread_mutex_unlock (&fsc_cs_mutex);

	return (0);
}
#endif // CefC_Ccore
/*--------------------------------------------------------------------------------------
	get lifetime for ccninfo
----------------------------------------------------------------------------------------*/
static int										/* This value MAY be -1 if the router does not know or cannot report. */
fsc_cache_lifetime_get (
	unsigned char* name,						/* content name							*/
	uint16_t name_len,							/* content name Length					*/
	uint32_t* cache_time,						/* The elapsed time (seconds) after the oldest	*/
												/* content object of the content is cached.		*/
	uint32_t* lifetime,							/* The lifetime (seconds) of a content object, 	*/
												/* which is removed first among the cached content objects.*/
	uint8_t partial_f							/* when flag is 0, exact match			*/
												/* when flag is 1, partial match		*/
) {
	*lifetime = 0;
	*cache_time = 0;
	
	CsmgrT_Stat* rcd = NULL;
	uint64_t nowt;
	struct timeval tv;
	uint16_t name_len_wo_chunk;
	
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;
	
	pthread_mutex_lock (&fsc_cs_mutex);
	if (partial_f != 0) {
		rcd = csmgr_stat_content_info_get (csmgr_stat_hdl, name, name_len);
	} else {
		uint32_t seqno = 0;
		name_len_wo_chunk = cef_frame_get_name_without_chunkno (name, name_len, &seqno);
		if (name_len_wo_chunk == 0) {
			return (-1);
		}
		rcd = csmgr_stat_content_info_access (csmgr_stat_hdl, name, name_len_wo_chunk);
	}
	if (!rcd || rcd->expire_f) {
		pthread_mutex_unlock (&fsc_cs_mutex);
		return (-1);
	}
	
	*cache_time = (uint32_t)((nowt - rcd->cached_time) / 1000000);
	if (rcd->expiry < nowt) {
		*lifetime = 0;
	} else {
		*lifetime = (uint32_t)((rcd->expiry - nowt) / 1000000);
	}
	
	pthread_mutex_unlock (&fsc_cs_mutex);

	return (1);
}

/****************************************************************************************
 ****************************************************************************************/
/*--------------------------------------------------------------------------------------
	Check FileSystem Cache Directory
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_root_dir_check (
	char* root_path								/* csmgr root path						*/
) {
	DIR* main_dir;
	
	main_dir = opendir (root_path);
	if (main_dir == NULL) {
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
//	sprintf (cache_path, "%s/%d", hdl->fsc_root_path, cache_id);
	int rc = snprintf (cache_path, sizeof (cache_path),"%s/csmgr_fsc_%d", hdl->fsc_root_path, cache_id);
	if ( rc < 0 ) {
		csmgrd_log_write (CefC_Log_Error, "Failed to cache_path name create\n");
		return (0xFFFFFFFF);
	}
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
		return (-1);
	}
	return (1);
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

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
 * filesystem_cache.c
 */
#define __CONPUBD_FILESYSTEM_CACHE_SOURCE__

/*
	filesystem_cache.c is a primitive filesystem cache implementation.
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

#include "filesystem_cache.h"
#include <cefore/cef_client.h>
#include <cefore/cef_conpub.h>
#include <cefore/cef_frame.h>
#include <conpubd/conpubd_plugin.h>


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
typedef struct {

	/********** Content Object in filesystem cache		***********/
	unsigned char	*msg;						/* Message								*/
	uint16_t		msg_len;					/* Message length						*/
	unsigned char	*name;						/* Content name							*/
	uint16_t		name_len;					/* Content name length					*/
	uint16_t		pay_len;					/* Payload length						*/
	uint32_t		chunk_num;					/* Chunk num							*/
	uint64_t		rct;						/* RCT									*/
	uint64_t		expiry;						/* Expiry								*/
	uint64_t		cachetime;					/* cachetime							*/
	struct in_addr	node;						/* Node address							*/

} ConpubdT_Content_Fsc_Entry;

/****************************************************************************************
 State Variables
 ****************************************************************************************/

static FscT_Cache_Handle* 		cobpub_hdl = NULL;
static char 					conpub_conf_dir[PATH_MAX] = {"/usr/local/cefore"};
static CsmgrT_Stat_Handle 		conpub_stat_hdl;

static pthread_mutex_t 			conpub_fsc_cs_mutex = PTHREAD_MUTEX_INITIALIZER;

static ConpubdT_Content_Entry* 	fsc_proc_cob_buff = NULL;

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
	int sock,									/* received socket						*/
	unsigned char* version,						/* version								*/
	uint16_t ver_len							/* length of version					*/
);
/*--------------------------------------------------------------------------------------
	Upload content byte steream
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_item_puts (
//JK	ConpubdT_Content_Entry* entry, 
	void* entry, 
	int size,
	void* conpubd_hdl
);
/*--------------------------------------------------------------------------------------
	writes the cobs to filesystem cache
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_cob_write (
	ConpubdT_Content_Entry* cobs, 
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
/*--------------------------------------------------------------------------------------
	Delete content entry
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_content_del (
	unsigned char* name,						/* Content name							*/
	uint16_t name_len,							/* Content name length					*/
	uint64_t cob_num							/* Total number of Cob					*/
);
/*--------------------------------------------------------------------------------------
	Retuern cached cob num
----------------------------------------------------------------------------------------*/
static uint64_t
fsc_cached_cobs (
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
conpubd_filesystem_plugin_load (
	ConpubdT_Plugin_Interface* cs_in, 
	const char* config_dir
) {
	CONPUBD_SET_CALLBACKS (
		fsc_cs_create, fsc_cs_destroy, fsc_cs_expire_check, fsc_cache_item_get,
		fsc_cache_item_puts, fsc_cs_ac_cnt_inc, fsc_content_del, fsc_cached_cobs);

	if (config_dir) {
		strcpy (conpub_conf_dir, config_dir);
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
	
	/* create handle 		*/
	if (cobpub_hdl != NULL) {
		free (cobpub_hdl);
		cobpub_hdl = NULL;
	}

	/* Init logging 	*/
	conpubd_log_init ("conpubd_fscache", 1);
	conpubd_log_init2 (conpub_conf_dir);
#ifdef CefC_Debug
	conpubd_dbg_init ("conpubd_fscache", conpub_conf_dir);
#endif // CefC_Debug

	cobpub_hdl = (FscT_Cache_Handle*) malloc (sizeof (FscT_Cache_Handle));
	if (cobpub_hdl == NULL) {
		conpubd_log_write (CefC_Log_Error, "malloc error\n");
		return (-1);
	}
	memset (cobpub_hdl, 0, sizeof (FscT_Cache_Handle));
	
	/* Reads config 		*/
	if (fsc_config_read (&conf_param) < 0) {
		conpubd_log_write (CefC_Log_Error, "[%s] read config\n", __func__);
		return (-1);
	}
	cobpub_hdl->cache_capacity = conf_param.cache_capacity;
	cobpub_hdl->cache_cobs = 0;
	strcpy (cobpub_hdl->fsc_root_path, conf_param.cache_path);
	cobpub_hdl->cache_default_rct = conf_param.cache_default_rct;
	
	/* Check and create root directory	*/
	if (fsc_root_dir_check (cobpub_hdl->fsc_root_path) < 0) {
		conpubd_log_write (CefC_Log_Error,
			"[%s] Root dir is not exist (%s)\n" , __func__, cobpub_hdl->fsc_root_path);
		cobpub_hdl->fsc_root_path[0] = 0;
		return (-1);
	}
	
	/* Creates the directory to store cache files		*/
	cobpub_hdl->fsc_id = fsc_cache_id_create (cobpub_hdl);
	if (cobpub_hdl->fsc_id == 0xFFFFFFFF) {
		conpubd_log_write (CefC_Log_Error, "FileSystemCache init error\n");
		return (-1);
	}
	conpubd_log_write (CefC_Log_Info, 
		"Creation the cache directory (%s) ... OK\n", cobpub_hdl->fsc_cache_path);
	
	conpubd_log_write (CefC_Log_Info, "Start\n");
	conpubd_log_write (CefC_Log_Info, "Capacity : "FMTU64"\n", cobpub_hdl->cache_capacity);
	conpubd_log_write (CefC_Log_Info, "cache_default_rct : %u\n", cobpub_hdl->cache_default_rct);
	conpub_stat_hdl = stat_hdl;
	conpubd_stat_cache_capacity_update (conpub_stat_hdl, cobpub_hdl->cache_capacity);
	
	/* Create cob buffer */
	fsc_proc_cob_buff 
		= (ConpubdT_Content_Entry*) malloc (sizeof (ConpubdT_Content_Entry) * ConpubC_Buff_Num);
	if (fsc_proc_cob_buff == NULL) {
		conpubd_log_write (CefC_Log_Info, "Failed to allocation process cob buffer\n");
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

	pthread_mutex_destroy (&conpub_fsc_cs_mutex);
	
	if (cobpub_hdl == NULL) {
		return;
	}
	if (cobpub_hdl->fsc_cache_path[0] != 0x00) {
		fsc_recursive_dir_clear (cobpub_hdl->fsc_cache_path);
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
fsc_cs_expire_check (
	void
) {
	int 			index = 0;
	CsmgrT_Stat* 	rcd = NULL;
	char			file_path[PATH_MAX];
	
	if (pthread_mutex_trylock (&conpub_fsc_cs_mutex) != 0) {
		return;
	}
	while (1) {
		rcd = conpubd_stat_expired_content_info_get (conpub_stat_hdl, &index);
		if (!rcd) {
			break;
		}

		sprintf (file_path, "%s/%d", cobpub_hdl->fsc_cache_path, (int) rcd->index);
		fsc_recursive_dir_clear (file_path);

		conpubd_stat_content_info_delete (conpub_stat_hdl, rcd->name, rcd->name_len);
		cobpub_hdl->cache_cobs -= rcd->cob_num;
	}
	pthread_mutex_unlock (&conpub_fsc_cs_mutex);
	
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
	int sock,									/* received socket						*/
	unsigned char* version,						/* version								*/
	uint16_t ver_len							/* length of version					*/
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
	uint64_t	nowt;
	struct timeval tv;
	static unsigned char*	page_cob_buf = NULL;
	int			rcdsize;
	int			update_ver = 1;
	static uint16_t red_ver_len = 0;
	static unsigned char red_version[PATH_MAX] = {0};
	
#ifdef CefC_Debug
	conpubd_dbg_write (CefC_Dbg_Finest, "Incoming Interest : seqno = %u\n", seqno);
#endif // CefC_Debug
	pthread_mutex_lock (&conpub_fsc_cs_mutex);
	/* Obtain the information of the specified content 		*/
	rcd = conpubd_stat_content_info_access (conpub_stat_hdl, key, key_size);
	if (!rcd) {
		pthread_mutex_unlock (&conpub_fsc_cs_mutex);
		return (-1);
	}
	if (rcd->expire_f) {
		sprintf (file_path, "%s/%d", cobpub_hdl->fsc_cache_path, (int) rcd->index);
#ifdef CefC_Debug
		conpubd_dbg_write (CefC_Dbg_Fine, "Delete the expired content = %s\n", file_path);
#endif // CefC_Debug
		fsc_recursive_dir_clear (file_path);
		conpubd_stat_content_info_delete (conpub_stat_hdl, key, key_size);
		cobpub_hdl->cache_cobs -= rcd->cob_num;
		pthread_mutex_unlock (&conpub_fsc_cs_mutex);
		return (-1);
	}
	
	file_msglen = rcd->file_msglen;
	rcdsize = sizeof (uint16_t) + file_msglen;
	
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
		pthread_mutex_unlock (&conpub_fsc_cs_mutex);
		return (-1);
	}
	if (send_cob_f == 1) {
		rcd->tx_seq = seqno;
		rcd->tx_num = FscC_Tx_Cob_Num;
		rcd->tx_time = nowt + FscC_Sent_Reset_Time;
	}
	
	/* Open the file that specified cob is cached 		*/
	cob_block_index = (int)(seqno / FscC_Page_Cob_Num) % FscC_File_Page_Num;
	page_index = (int)(seqno / FscC_Page_Cob_Num/FscC_File_Page_Num);
	sprintf (file_path, "%s/%d/%d", cobpub_hdl->fsc_cache_path, (int) rcd->index, page_index);
	
	if (ver_len) {
		if (red_ver_len == ver_len &&
			memcmp (version, red_version, red_ver_len) == 0) {
			update_ver = 0;
		}
	} else {
		update_ver = 0;
	}
	
	if (strcmp (red_file_path, file_path) != 0 || cob_block_index != red_cob_block_index ||
		(strcmp (red_file_path, file_path) == 0 && update_ver != 0)) {
		if (page_cob_buf != NULL) {
			free (page_cob_buf);
			page_cob_buf = NULL;
		}

		fp = fopen (file_path, "rb");
		if (fp == NULL) {
			conpubd_log_write (CefC_Log_Error, "Failed to open the cache file (%s)\n", file_path);
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
		if (red_ver_len) {
			memset (red_version, 0, PATH_MAX);
		}
		red_ver_len = ver_len;
		if (ver_len) {
			memcpy (red_version, version, ver_len);
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
		conpubd_dbg_write (CefC_Dbg_Finest, "send seqno = %u (%u bytes)\n", seqno, mlen);
	}
#endif // CefC_Debug
	conpubd_stat_access_count_update (
			conpub_stat_hdl, key, key_size);
	
	/* Set cache time */
	{
	uint64_t cachetime;
	time_t timer = time (NULL);
	struct tm* local = localtime (&timer);
	time_t now_time = mktime (local);
	cachetime = (uint64_t)(now_time + cobpub_hdl->cache_default_rct) * 1000;
	cef_frame_opheader_cachetime_update (&page_cob_buf[pos_index*rcdsize+sizeof (uint16_t)], cachetime);
	}
	/* Send Cob to cefnetd */
	uint16_t mlen;
	memcpy (&mlen, &page_cob_buf[pos_index*rcdsize], sizeof (uint16_t));
	conpubd_plugin_cob_msg_send (
						sock, &page_cob_buf[pos_index*rcdsize+sizeof (uint16_t)], mlen);
	if (resend_1cob_f == 1) {
		if (fp != NULL) {
			fclose (fp);
		}
		pthread_mutex_unlock (&conpub_fsc_cs_mutex);
		return (0);
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
				conpubd_dbg_write (CefC_Dbg_Finest, "send seqno = %u (%u bytes)\n", seqno, mlen);
			}
#endif // CefC_Debug
	/* Set cache time */
			{
			uint64_t cachetime;
			time_t timer = time (NULL);
			struct tm* local = localtime (&timer);
			time_t now_time = mktime (local);
			cachetime = (uint64_t)(now_time + cobpub_hdl->cache_default_rct) * 1000;
			cef_frame_opheader_cachetime_update (&page_cob_buf[i*rcdsize+sizeof (uint16_t)], cachetime);
			}
			uint16_t mlen;
			memcpy (&mlen, &page_cob_buf[i*rcdsize], sizeof (uint16_t));
			if (mlen != 0) {
				conpubd_plugin_cob_msg_send (
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
	pthread_mutex_unlock (&conpub_fsc_cs_mutex);
	return (0);
}
/*--------------------------------------------------------------------------------------
	Upload content byte steream
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_item_puts (
//	ConpubdT_Content_Entry* entry, 
	void* in_entry, 
	int size,
	void* conpubd_hdl
) {
	static int cob_num = 0;
	int rtc = 0;
	ConpubdT_Content_Entry* entry = (ConpubdT_Content_Entry*)in_entry;
	
	if (entry == NULL) {
		if (cob_num != 0) {
			pthread_mutex_lock (&conpub_fsc_cs_mutex);
			rtc = fsc_cache_cob_write (fsc_proc_cob_buff, cob_num);
			pthread_mutex_unlock (&conpub_fsc_cs_mutex);
			cob_num = 0;
		}
	} else {
		memcpy (&fsc_proc_cob_buff[cob_num], entry, sizeof (ConpubdT_Content_Entry));
		cob_num ++;
		if (cob_num == ConpubC_Buff_Num) {
			pthread_mutex_lock (&conpub_fsc_cs_mutex);
			rtc = fsc_cache_cob_write (fsc_proc_cob_buff, cob_num);
			pthread_mutex_unlock (&conpub_fsc_cs_mutex);
			cob_num = 0;
		}
	}
	return (rtc);
}
/*--------------------------------------------------------------------------------------
	writes the cobs to filesystem cache
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_cob_write (
	ConpubdT_Content_Entry* cobs, 
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
	int				rbpflag = 0;
	int				swindx[FscC_Page_Cob_Num];
	uint32_t		file_msglen;
	CsmgrT_DB_COB_MAP**	cob_map = NULL;		//0.8.3c
	
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;

	index = 0;
	while (index < cob_num) {
		
		uint32_t chunk_num = cobs[index].chunk_num;
		if (cobs[index].expiry < nowt) {
			goto NEXTCOB;
		}
		if (cobpub_hdl->cache_cobs >= cobpub_hdl->cache_capacity) {
			goto NEXTCOB;
		}
		/* Update the directory to write the received cob 		*/
		if ((cobs[index].name_len != name_len) ||
			(memcmp (cobs[index].name, name, cobs[index].name_len))) {
			rcd = conpubd_stat_content_info_access (
					conpub_stat_hdl, cobs[index].name, cobs[index].name_len);
			
			if (!rcd) {
				rcd = conpubd_stat_content_info_init (
						conpub_stat_hdl, cobs[index].name, cobs[index].name_len, cob_map);
				if (!rcd) {
					goto NEXTCOB;
				}
			}
			work_con_index = (int) rcd->index;
			prev_page_index = -1;
			sprintf (cont_path, "%s/%d", cobpub_hdl->fsc_cache_path, work_con_index);
			memcpy (name, cobs[index].name, cobs[index].name_len);
			name_len = cobs[index].name_len;
			
			if (mkdir (cont_path, 0766) != 0) {
				if (errno == ENOENT) {
					conpubd_log_write (CefC_Log_Error, 
						"Failed to create the cache directory for the each content\n");
					goto NEXTCOB;
				}
				if (errno == EACCES) {
					conpubd_log_write (CefC_Log_Error, 
						"Please make sure that you have write permission for %s.\n", 
						cobpub_hdl->fsc_cache_path);
					goto NEXTCOB;
				}
			}
		}

		/* Cotrol record size */
		if (rcd->file_msglen == 0) {
			rcd->file_msglen = cobs[index].msg_len + 3;
			rcd->detect_chnkno = chunk_num;
		} else {
			;
		}
		file_msglen = rcd->file_msglen;
		rcdsize = sizeof (uint16_t) + file_msglen;

		if ( file_msglen < cobs[index].msg_len ) {
			goto NEXTCOB;
		}
		/* Update the page to write the received cob 		*/
		work_page_index = chunk_num / FscC_Page_Cob_Num / FscC_File_Page_Num;
		cob_block_index = (chunk_num / FscC_Page_Cob_Num) % FscC_File_Page_Num;
		if (work_page_index != prev_page_index) {
			if (fp != NULL) {
#ifdef CefC_Debug
				conpubd_dbg_write (CefC_Dbg_Finer, 
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
				"%s/%d/%d", cobpub_hdl->fsc_cache_path, work_con_index, work_page_index);
            if (stat (file_path, &st) != 0) {
				fp = fopen (file_path, "w");
            	fclose (fp);
            	fp = fopen (file_path, "rb+");
			}
			else {
				fp = fopen (file_path, "rb+");
				if (!fp) {
					conpubd_log_write (CefC_Log_Error, 
						"Failed to open the cache file (%s)\n", file_path);
					goto NEXTCOB;
				}
				memset (swindx, 0 , sizeof (swindx));
				rbpflag = 1;
			}
		}
		
		/* Updates the content information 			*/
		conpubd_stat_cob_update (conpub_stat_hdl, cobs[index].name, cobs[index].name_len, 
				chunk_num, cobs[index].pay_len, cobs[index].expiry, 
				nowt, cobs[index].node);

		/* Set to write buffer 							*/
		unsigned char wbuff[sizeof (uint16_t) + UINT16_MAX];
		int write_index = chunk_num % FscC_Page_Cob_Num;
		fseek (fp, (int64_t)cob_block_index * FscC_Page_Cob_Num * (int64_t)rcdsize
					+ (int64_t)write_index * (int64_t)rcdsize, SEEK_SET);
		memcpy (wbuff, &cobs[index].msg_len, sizeof (uint16_t));
		memcpy (&wbuff[sizeof (uint16_t)], cobs[index].msg, cobs[index].msg_len);
		fwrite (wbuff, sizeof (uint16_t) + file_msglen, 1, fp);
		fflush (fp);

			cobpub_hdl->cache_cobs++;
		
NEXTCOB:
		free (cobs[index].msg);
		free (cobs[index].name);
		index++;
	}
	
	if (fp) {
		fflush (fp);
		fclose (fp);
	}
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
		conpubd_stat_access_count_update (
				conpub_stat_hdl, &key[0], index);
	}
	
	return;
}
/*--------------------------------------------------------------------------------------
	Delete content entry
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_content_del (
	unsigned char* name,						/* Content name							*/
	uint16_t name_len,							/* Content name length					*/
	uint64_t cob_num							/* Total number of Cob					*/
) {
	CsmgrT_Stat*	rcd = NULL;
	char			file_path[PATH_MAX];
	
	pthread_mutex_lock (&conpub_fsc_cs_mutex);
	
	rcd = conpubd_stat_content_info_access (conpub_stat_hdl, name, name_len);
	if (!rcd) {
		pthread_mutex_unlock (&conpub_fsc_cs_mutex);
		return (-1);
	}
	
	sprintf (file_path, "%s/%d", cobpub_hdl->fsc_cache_path, (int) rcd->index);
	fsc_recursive_dir_clear (file_path);

	conpubd_stat_content_info_delete (conpub_stat_hdl, rcd->name, rcd->name_len);
	cobpub_hdl->cache_cobs -= cob_num;

	pthread_mutex_unlock (&conpub_fsc_cs_mutex);

	return (0);
}
/*--------------------------------------------------------------------------------------
	Retuern cached cob num
----------------------------------------------------------------------------------------*/
static uint64_t
fsc_cached_cobs (
) {
	return (cobpub_hdl->cache_cobs);
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
	char	param[128] = {0};						/* parameter						*/
	char	param_buff[128] = {0};					/* param buff						*/
	int		len;									/* read length						*/
	char*	option;									/* deny option						*/
	char*	value;									/* parameter						*/
	int		res;
	int			i, n;
	
	/* Inits parameters		*/
	memset (params, 0, sizeof (FscT_Config_Param));
	params->cache_capacity 			= CefC_CnpbDefault_Contents_Capacity;
	strcpy(params->cache_path, 		  conpub_conf_dir);
	params->cache_default_rct = CefC_CnpbDefault_Cache_Default_Rct;

	/* Obtains the directory path where the conpubd's config file is located. */
#if 0 //+++++ GCC v9 +++++
	sprintf (file_name, "%s/conpubd.conf", conpub_conf_dir);
#else 
	int		rc;
	rc = snprintf (file_name, sizeof(file_name), "%s/conpubd.conf", conpub_conf_dir);
	if (rc < 0) {
		conpubd_log_write (CefC_Log_Error, "Config file dir path too long(%s)\n", conpub_conf_dir);
		return (-1);
	}
#endif //----- GCC v9 -----
	
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
		} else
		if (strcmp (option, "CACHE_PATH") == 0) {
			res = strlen (value);
			if (res > CefC_Conpubd_File_Path_Length) {
				conpubd_log_write (
					CefC_Log_Error, "[%s] Invalid value %s=%s\n", __func__, option, value);
				fclose (fp);
				return (-1);
			}
			if (!(    access (value, F_OK) == 0
				   && access (value, R_OK) == 0
		   		   && access (value, W_OK) == 0
		   		   && access (value, X_OK) == 0)) {
				conpubd_log_write (CefC_Log_Error,
					"EXCACHE_PLUGIN (Invalid value %s=%s) - %s\n", option, value, strerror (errno));
				fclose (fp);
				return (-1);
		    }
			strcpy (params->cache_path, value);
		} else
		if (strcmp (option, "CACHE_DEFAULT_RCT") == 0) {
			char *endp = "";
			params->cache_default_rct = strtoul (value, &endp, 0);
			if (!(1 < params->cache_default_rct && params->cache_default_rct < 3600)) {
				cef_log_write (CefC_Log_Error,
					"CACHE_DEFAULT_RCT value must be higher than 1 and lower than 3600 (secs).\n");
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
	char cache_path[CefC_Conpubd_File_Path_Length] = {0};
	uint32_t fsc_id = 0xFFFFFFFF;
	
	srand ((unsigned int) time (NULL));
	
	cache_id = rand () % FscC_Max_Node_Inf_Num;
	int rc = snprintf (cache_path, sizeof (cache_path),"%s/conpub_fsc_%d", cobpub_hdl->fsc_root_path, cache_id);
	if ( rc < 0 ) {
		conpubd_log_write (CefC_Log_Error, "Failed to cache_path name create\n");
		return (0xFFFFFFFF);
	}
	cache_dir = opendir (cache_path);
	
	if (cache_dir) {
		closedir (cache_dir);
		
		if (fsc_recursive_dir_clear (cache_path) != 0) {
			conpubd_log_write (CefC_Log_Error, "Failed to remove the cache directory\n");
			return (fsc_id);
		}
	}
	
	if (mkdir (cache_path, 0766) != 0) {
		conpubd_log_write (CefC_Log_Error, 
			"Failed to create the cache directory in %s\n", cobpub_hdl->fsc_root_path);
		
		if (errno == EACCES) {
			conpubd_log_write (CefC_Log_Error, 
				"Please make sure that you have write permission for %s.\n", 
				cobpub_hdl->fsc_root_path);
		}
		if (errno == ENOENT) {
			conpubd_log_write (CefC_Log_Error, 
				"Please make sure that %s exists.\n", cobpub_hdl->fsc_root_path);
		}
		
		return (fsc_id);
	}
	strcpy (cobpub_hdl->fsc_cache_path, cache_path);
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
		conpubd_log_write (CefC_Log_Critical,
			"stat error(%s): file path is %s\n", filepath, strerror (errno));
		return (-1);
	}
	if (S_ISDIR (sb.st_mode)) {
		return (0);
	}

	rc = unlink (filepath);
	if (rc < 0) {
		conpubd_log_write (CefC_Log_Critical,
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
	char buf[CefC_Conpubd_File_Path_Length];

	dp = opendir (filepath);
	if (dp == NULL) {
		conpubd_log_write (CefC_Log_Error, "fsc_dir_clear(opendir(%s))", filepath);
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
		conpubd_log_write (
			CefC_Log_Error, "fsc_recursive_dir_clear(rmdir(%s))", filepath );
		return (-1);
	}

	return (0);
}


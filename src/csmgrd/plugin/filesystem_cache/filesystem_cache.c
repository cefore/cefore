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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>

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

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

typedef struct _FscT_Rm_Key {

	unsigned char			key[CsmgrdC_Key_Max];
	int 					key_len;
	struct _FscT_Rm_Key* 	next;

} FscT_Rm_Key;



/****************************************************************************************
 State Variables
 ****************************************************************************************/
static FscT_Cache_Handle* hdl = NULL;						/* FileSystemCache Handle	*/
static FscT_Contentmng* contmng = NULL;						/* Content Manager			*/
static FscT_File_Element* file_area = NULL;					/* File Element				*/

static FscT_Rm_Key 		rm_key_list;
static FscT_Ch_Pid_List child_pid_list[FscC_Max_Child_Num];

static char csmgr_conf_dir[PATH_MAX] = {"/usr/local/cefore"};

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Init content store
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cs_create (
	void
);
/*--------------------------------------------------------------------------------------
	Check FileSystem Cache Directory
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_root_dir_check (
	char* root_path								/* csmgr root path						*/
);
/*--------------------------------------------------------------------------------------
	Create CSMng file
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_csmng_create (
	char* root_path								/* csmgr root path						*/
);
/*--------------------------------------------------------------------------------------
	Function to read the management information file individual or common
	If there is no file ,create new
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_csmng_get_mk (
	FscT_Csmng* cmng,							/* FilesystemCache content manager		*/
	char* path									/* csmng file path						*/
);
/*--------------------------------------------------------------------------------------
	Initialize FileSystemCache
----------------------------------------------------------------------------------------*/
static uint32_t						/* The return value is FSCID						*/
fsc_cache_init (
	FscT_Cache_Handle* hdl,						/* FileSystemCache daemon handle		*/
	int* erst						/* The return value is negative if an error occurs	*/
);
/*--------------------------------------------------------------------------------------
	Function to file lock.   If the file is locked, the return value is 0.
	If you can lock the file, the return value is lock number.
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_lock (
	char* path,									/* path of lock file					*/
	int* lock									/* return lock number					*/
);
/*--------------------------------------------------------------------------------------
	Function to file unlock.   Argument of the function lock number.
----------------------------------------------------------------------------------------*/
static void
fsc_cache_unlock (
	char* path,									/* path of lock file					*/
	int lockno									/* lock number							*/
);
/*--------------------------------------------------------------------------------------
	Function to read the management information file individual or common
	If there is no file, an error results
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_csmng_get (
	FscT_Csmng* cmng,							/* FilesystemCache content manager		*/
	char* path									/* csmng file path						*/
);
/*--------------------------------------------------------------------------------------
	Function to write out the information management file an individual or common
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_csmng_put (
	FscT_Csmng* cmng,							/* FilesystemCache content manager		*/
	char* path									/* csmng file path						*/
);
/*--------------------------------------------------------------------------------------
	Function to get FileSystemCache use path name
----------------------------------------------------------------------------------------*/
static void
fsc_my_dir_get (
	uint32_t ex_id,								/* FilesystemCache ID					*/
	FscT_Csmng* cmng,							/* FilesystemCache content manager		*/
	char* idir,									/* in directory path					*/
	char* odir									/* out directory path					*/
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
	Function to read the content management file
	If there is no file ,no read
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_contentmng_get (
	char* dir,									/* content manager directory			*/
	FscT_Contentmng* contmng					/* content manager						*/
);
/*--------------------------------------------------------------------------------------
	Function to read the cob management file
	If there is no file ,no read
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cobmng_get (
	char* dir,									/* cob manager directory				*/
	FscT_Cobmng* comng							/* cob manager							*/
);
/*--------------------------------------------------------------------------------------
	delete directory path
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_dir_remove (
	char* filepath,								/* file path							*/
	int mode									/* Remove Mode							*/
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
	Function to write out the content management file
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_contentmng_put (
	char* dir,									/* content manager directory			*/
	FscT_Contentmng* contmng					/* content manager						*/
);
/*--------------------------------------------------------------------------------------
	Destroy content store
----------------------------------------------------------------------------------------*/
static void
fsc_cs_destroy (
	void
);
/*--------------------------------------------------------------------------------------
	Function to read the content management file
	If there is no file ,create new
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_mk_contentmng_get (
	char* dir,									/* content manager directory			*/
	FscT_Contentmng* contmng					/* content manager						*/
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
	Function to get content entry no
----------------------------------------------------------------------------------------*/
static int							/* The return value is content entry num			*/
fsc_content_no_get (
	FscT_Contentmng* contmng,					/* content manager						*/
	unsigned char* key,							/* content name							*/
	int key_size								/* content name length					*/
);
/*--------------------------------------------------------------------------------------
	Function to get content path name
----------------------------------------------------------------------------------------*/
static void
fsc_cont_dir_get (
	char* dir,									/* content manager directory			*/
	int contno,									/* content chunk number					*/
	char* contdir								/* content directory					*/
);
/*--------------------------------------------------------------------------------------
	Function to check receive status on cob management file
----------------------------------------------------------------------------------------*/
static int							/* The return value is result						*/
fsc_cob_bit_check (
	FscT_Cobmng* comng,							/* cob manager							*/
	int seqno									/* chunk num							*/
);
/*--------------------------------------------------------------------------------------
	Function to read elements group file
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_element_g_read (
	char* dir,									/* element group file directory			*/
	int file_no,								/* file number							*/
	char* cent									/* file Element							*/
);
/*--------------------------------------------------------------------------------------
	Function to get content_entry info
----------------------------------------------------------------------------------------*/
static CefT_Csmgrd_Content_Info* 	/* The return value is NULL if an error occurs		*/
fsc_content_entry_get (
	FscT_File_Element* cent,					/* file element							*/
	CefT_Csmgrd_Content_Info* centry			/* content information					*/
);
/*--------------------------------------------------------------------------------------
	Upload content entry
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_item_put (
	CsmgrdT_Content_Entry* entry				/* content entry						*/
);
/*--------------------------------------------------------------------------------------
	fork process , and reset ring queue.
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_item_put_into_cache (
	FscT_Cache_Handle* hdl						/* FileSystemCache daemon handle		*/
);
/*--------------------------------------------------------------------------------------
	Write Cob entry
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_item_write (
	int item_que_num,							/* queue num							*/
	CefT_Rngque* item_put_que,					/* item queue							*/
	CefT_Mp_Handle item_put_que_mp				/* item queue memory pool				*/
);
/*--------------------------------------------------------------------------------------
	Function to set content manage info
----------------------------------------------------------------------------------------*/
static int							/* The return value is content information index	*/
fsc_content_inf_set (
	FscT_Contentmng* contmng,					/* content manager						*/
	CsmgrdT_Content_Entry* entry				/* content Information					*/
);
/*--------------------------------------------------------------------------------------
	Function to read the cob management file
	If there is no file ,create new
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_mk_cobmng_get (
	char* dir,									/* cob manager directory				*/
	FscT_Cobmng* comng							/* cob manager							*/
);
/*--------------------------------------------------------------------------------------
	Function to set receive status on cob management file
----------------------------------------------------------------------------------------*/
static void
fsc_cob_bit_set (
	FscT_Cobmng* comng,							/* cob manager							*/
	int seqno									/* chunk num							*/
);
/*--------------------------------------------------------------------------------------
	Function to unset receive status on cob management file
----------------------------------------------------------------------------------------*/
static int
fsc_cob_bit_unset (
	FscT_Cobmng* comng,							/* cob manager							*/
	int seqno									/* chunk num							*/
);
/*--------------------------------------------------------------------------------------
	Function to write out the cob management file
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cobmng_put (
	char* dir,									/* cob manager directory				*/
	FscT_Cobmng* comng							/* cob manager							*/
);
/*--------------------------------------------------------------------------------------
	Function to read elements group file
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_element_g_get (
	char* dir,									/* element group file directory			*/
	int file_no,								/* file number							*/
	char* cent									/* file Element							*/
);
/*--------------------------------------------------------------------------------------
	Function to write elements group file
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_element_g_put (
	char* dir,									/* element group file directory			*/
	int file_no,								/* file number							*/
	char* cent									/* file Element							*/
);
/*--------------------------------------------------------------------------------------
	Function to set content_entry info
----------------------------------------------------------------------------------------*/
static void
fsc_content_entry_put (
	FscT_File_Element* f_elem,					/* file element							*/
	CsmgrdT_Content_Entry* centry				/* content entry						*/
);
/*--------------------------------------------------------------------------------------
	Get Csmgrd status
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_stat_get (
	char* stat,									/* String of FS Cache status			*/
	uint16_t* stat_len,							/* String length						*/
	uint8_t cache_f,							/* Cache request flag					*/
	char uris[CefC_Csmgr_Stat_MaxUri][265],		/* Content URI							*/
	CefT_Csmgrd_Stat_Cache* cache,				/* Content information					*/
	uint16_t* cache_len							/* Length of content information		*/
);
#ifdef CefC_Contrace
/*--------------------------------------------------------------------------------------
	Create the cache information
----------------------------------------------------------------------------------------*/
static int							/* number of returned caches						*/
fsc_cache_info_get (
	int* total_len,										/* length of returned status	*/
	char uris[CefstatC_MaxUri][265],					/* record created cache name	*/
	CefstatT_Cache stat[CefstatC_MaxUri]				/* record created cache status	*/
);
#endif // CefC_Contrace
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
	Create new content entry
----------------------------------------------------------------------------------------*/
static FscT_Mem_Cache_Content_Entry*	/* The return value is null if an error occurs	*/
fsc_memcache_content_entry_create (
	CefT_Csmgrd_Content_Info* centry			/* content information					*/
);
/*--------------------------------------------------------------------------------------
	Create new cob entry
----------------------------------------------------------------------------------------*/
static CefT_Csmgrd_Content_Info*	/* The return value is null if an error occurs		*/
fsc_memcache_cob_entry_create (
	CefT_Csmgrd_Content_Info* centry			/* content information					*/
);
/*--------------------------------------------------------------------------------------
	Search cob in memory cache
----------------------------------------------------------------------------------------*/
static int							/* If found cache , return 0						*/
fsc_memcache_lookup (
	unsigned char* key,							/* content name							*/
	uint16_t key_size,							/* content name Length					*/
	uint32_t seqno,								/* chunk num							*/
	int sock									/* received socket						*/
);
/*--------------------------------------------------------------------------------------
	Remove expired content
----------------------------------------------------------------------------------------*/
static void
fsc_memcache_expire_check (
	void
);
/*--------------------------------------------------------------------------------------
	Remove old cob block
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_memcache_old_cob_block_remove (
	void
);
#if defined (CefC_Conping) || defined (CefC_Contrace)
/*--------------------------------------------------------------------------------------
	Check presence of cache
----------------------------------------------------------------------------------------*/
static int					/* It returns the negative value or NotExist if not found.	*/
fsc_content_exist_check (
	unsigned char* name,						/* content name							*/
	uint16_t name_len							/* content name length					*/
);
/*--------------------------------------------------------------------------------------
	Function to get content entry no
----------------------------------------------------------------------------------------*/
static int							/* The return value is content entry num			*/
fsc_content_no_prefix_search (
	FscT_Contentmng* contmng,					/* content manager						*/
	unsigned char* key,							/* content name							*/
	int key_size								/* content name length					*/
);
#endif // (CefC_Conping || CefC_Contrace)
/*--------------------------------------------------------------------------------------
	Function to read a all ContentObject in content from FileSystemCache
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_content_get (
	unsigned char* key,							/* content name							*/
	uint16_t key_size,							/* content name Length					*/
	uint32_t seqno,								/* chunk num							*/
	int sock									/* received socket						*/
);
/*--------------------------------------------------------------------------------------
	Function to read a all ContentObject in content from FileSystemCache
----------------------------------------------------------------------------------------*/
static void
fsc_cache_content_send (
	unsigned char* key,							/* content name							*/
	uint16_t key_size,							/* content name Length					*/
	uint32_t seqno,								/* chunk num							*/
	int sock									/* received socket						*/
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
	Send cob to cefnetd
----------------------------------------------------------------------------------------*/
static void
fsc_cache_cob_send (
	CefT_Csmgrd_Content_Info* cob_que[],
	int que_num,
	int sock
);
/*--------------------------------------------------------------------------------------
	Search free element
----------------------------------------------------------------------------------------*/
static int
fsc_free_pid_index_search (
	void
);
/*--------------------------------------------------------------------------------------
	Check child pid list
----------------------------------------------------------------------------------------*/
static int
fsc_child_pid_list_check (
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
/*--------------------------------------------------------------------------------------
	Removes specified cobs from thc cache
----------------------------------------------------------------------------------------*/
static void
fsc_cache_cob_remove (
	void
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
		fsc_cache_item_put, fsc_stat_get, fsc_cs_ac_cnt_inc);
#ifdef CefC_Contrace
	cs_in->cache_info_get = fsc_cache_info_get;
#endif // CefC_Contrace
#if defined (CefC_Conping) || defined (CefC_Contrace)
	cs_in->content_exist_check = fsc_content_exist_check;
#endif // (CefC_Conping || CefC_Contrace)
	cs_in->cache_content_get = fsc_cache_content_get;
	
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
	void
) {
	FscT_Config_Param conf_param;
	int i;
	int rst = -1;
	int res;

	/* Check handle */
	if (hdl != NULL) {
		free (hdl);
		hdl = NULL;
	}

	/* Init logging 	*/
	csmgrd_log_init ("filesystem");
#ifdef CefC_Debug
	csmgrd_dbg_init ("filesystem", csmgr_conf_dir);
#endif // CefC_Debug

	/* Create handle */
	hdl = (FscT_Cache_Handle*)malloc (sizeof (FscT_Cache_Handle));
	if (hdl == NULL) {
		csmgrd_log_write (CefC_Log_Error, "Failed to get memory required for startup.\n");
		return (-1);
	}
	memset (hdl, 0, sizeof (FscT_Cache_Handle));
	memset (&rm_key_list, 0, sizeof (FscT_Rm_Key));

	/* Read config */
	if (fsc_config_read (&conf_param) < 0) {
		csmgrd_log_write (CefC_Log_Error, "[%s] Read config error\n", __func__);
		return (-1);
	}
	hdl->cache_cob_max = conf_param.cache_cob_max;

	/* Check config */
	memcpy (
			hdl->fsc_root_path,
			conf_param.fsc_root_path,
			CefC_Csmgr_File_Path_Length);
	hdl->fsc_node_type = conf_param.fsc_node_type;

	/* Check and create root directory	*/
	if (fsc_root_dir_check (hdl->fsc_root_path) < 0) {
		csmgrd_log_write (CefC_Log_Error,
			"[%s] Root dir is not exist (%s)\n" , __func__, hdl->fsc_root_path);
		hdl->fsc_root_path[0] = 0;
		return (-1);
	}
	/* Create file(CSMng)	*/
	if (fsc_csmng_create (hdl->fsc_root_path) < 0) {
		csmgrd_log_write (CefC_Log_Error, "fsc_csmng_create error\n");
		return (-1);
	}
	sprintf (
		hdl->fsc_csmng_file_name,
		"%s/%s",
		hdl->fsc_root_path, FscC_Csmng_File_Name);
	/* Init FileSystemCache		*/
	for (i = 0; i < 5; i++) {
		hdl->fsc_id = fsc_cache_init (hdl, &rst);
		if(rst == 0) {
			break;
		}
	}
	if (hdl->fsc_id == 0xFFFFFFFF) {
		csmgrd_log_write (CefC_Log_Error, "FileSystemCache init error\n");
		return (-1);
	}

	/* Init ring queue	*/
	hdl->item_que_num = 0;
	hdl->item_put_que = cef_rngque_create (FscC_ItemPut_Que_Size);

	/* Initialize FscT_Contentmng */
	if (contmng != NULL) {
		free (contmng);
		contmng = NULL;
	}
	contmng = (FscT_Contentmng*)malloc (sizeof (FscT_Contentmng));
	if (contmng == NULL) {
		/* Malloc error */
		csmgrd_log_write (CefC_Log_Error, "Failed to get memory required for startup.\n");
		return (-1);
	}

	/* Initialize FscT_File_Element */
	if (file_area != NULL) {
		free (file_area);
		file_area = NULL;
	}
	file_area = (FscT_File_Element*)malloc (
										sizeof (FscT_File_Element) * FscC_Element_Num);
	if (file_area == NULL) {
		/* Malloc error */
		csmgrd_log_write (CefC_Log_Error, "Failed to get memory required for startup.\n");
		return (-1);
	}

	/* Initialize Memory Cache */
	/* Memory cache queue */
	hdl->mem_cache_num = 0;
	hdl->mem_cache_que = cef_rngque_create (FscC_MemCache_Max_Cob_Num);
	
	/* Memory cache table */
	hdl->mem_cache_table_num = 0;
	hdl->mem_cache_table = cef_hash_tbl_create ((uint16_t) FscC_MemCache_Max_Content_Num);
	if (hdl->mem_cache_table == (CefT_Hash_Handle)NULL) {
		csmgrd_log_write (CefC_Log_Error, "Create hash table error\n");
		return (-1);
	}

	/* Loads the library for cache algorithm 		*/
	if (conf_param.algo_name[0]) {
		sprintf (hdl->algo_name, "%s%s", conf_param.algo_name, CsmgrdC_Library_Name);
		csmgrd_log_write (CefC_Log_Info, "Library : %s\n", hdl->algo_name);
		res = csmgrd_lib_api_get (hdl->algo_name, &hdl->algo_lib, &hdl->algo_apis);
		if (res < 0) {
			csmgrd_log_write (CefC_Log_Error, "Load the lib (%s)\n", hdl->algo_name);
			return (-1);
		}

		if (hdl->algo_apis.init) {
			(*(hdl->algo_apis.init))(hdl->cache_cob_max, fsc_cs_store, fsc_cs_remove);
		}
	} else {
		csmgrd_log_write (CefC_Log_Info, "Library : Not Specified\n");
	}

	/* Set SIGCHLD	*/
	setup_SIGCHLD ();

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
	FscT_Rm_Key* work_key = rm_key_list.next;
	FscT_Rm_Key* tail_key = &rm_key_list;
	FscT_Rm_Key* new_key;

	while (work_key) {
		if ((work_key->key_len == key_len) &&
			(memcmp (work_key->key, key, key_len) == 0)) {
			return;
		}
		tail_key = work_key;
		work_key = work_key->next;
	}

	new_key = (FscT_Rm_Key*) malloc (sizeof (FscT_Rm_Key));
	new_key->next 		= NULL;
	new_key->key_len 	= key_len;
	memcpy (new_key->key, key, key_len);

	tail_key->next = new_key;
	hdl->cache_cobs--;
}
/*--------------------------------------------------------------------------------------
	Removes specified cobs from thc cache
----------------------------------------------------------------------------------------*/
static void
fsc_cache_cob_remove (
	void
) {
	unsigned char dir[CefC_Csmgr_File_Path_Length] = {0};
	unsigned char cdir[CefC_Csmgr_File_Path_Length] = {0};
	char CSLok[CefC_Csmgr_File_Path_Length] = {0};
	int lockno = 0; 			/* 0=Failure 0!=success */
	FscT_Csmng csmng = {0};
	FscT_Csmng* cmng = &csmng;
	int rst = 0;
	FscT_Cobmng cob_mng = {0};
	FscT_Cobmng* comng = &cob_mng;

	int 	tbl_no;
	FscT_Rm_Key* work_key ;
	FscT_Rm_Key* dele_key;
	uint32_t 	seqno;

	if (rm_key_list.next == NULL) {
		return;
	}

	/* Creates the lock file name */
	sprintf (CSLok, "%s/%s", hdl->fsc_root_path, FscC_Csmng_Lock_Name);

	/* Locks the FileSystemCache */
	rst = fsc_cache_lock (CSLok, &lockno);
	if (rst != 0) {
		return;
	}

	/* Obtains csmgr management information	*/
	rst = fsc_csmng_get (cmng, hdl->fsc_csmng_file_name);
	if(rst == -1) {
		goto RemoveExit;
	}

	/* Obtains my directory */
	fsc_my_dir_get (hdl->fsc_id, cmng, hdl->fsc_root_path, (char*) dir);
	if (dir[0] == 0) {
		goto RemoveExit;
	}

	/* Obtains the content manager */
	rst = fsc_mk_contentmng_get ((char*) dir, contmng);
	if (rst < 0) {
		rst = fsc_mk_contentmng_get ((char*) dir, contmng);
		if (rst == -1) {
			goto RemoveExit;
		}
	}

	work_key = rm_key_list.next;

	while (work_key) {

		/* Obtains the content number */
		tbl_no = fsc_content_no_get (
			contmng, work_key->key, work_key->key_len - (4 + sizeof (uint32_t)));

		if (tbl_no > FscC_Max_Content_Num) {
			goto GotoNext;
		}

		/* Obtains content directory */
		fsc_cont_dir_get ((char*) dir, tbl_no, (char*) cdir);

		/* Obtains cob manager */
		rst = fsc_cobmng_get ((char*) cdir, comng);
		if (rst == -1) {
			goto GotoNext;
		}

		/* Unset the bit for the removed cob */
		memcpy (&seqno, &(work_key->key[work_key->key_len - 4]), sizeof (uint32_t));
		seqno = ntohl (seqno);
		rst = fsc_cob_bit_unset (comng, seqno);

		if (rst > 0) {
			fsc_cobmng_put ((char*) cdir, comng);
		}
GotoNext:
		dele_key = work_key;
		work_key = work_key->next;
		free (dele_key);
	}
	rm_key_list.next = NULL;

RemoveExit:
	/* Unlock FileSystemCache */
	fsc_cache_unlock (CSLok , lockno);

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
	Create CSMng file
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_csmng_create (
	char* root_path								/* csmgr root path						*/
) {
	char file_path[CefC_Csmgr_File_Path_Length] = {0};
	FscT_Csmng cmng;

	/* Make CSMng file */
	sprintf (file_path, "%s/%s", root_path, FscC_Csmng_File_Name);
	if (fsc_csmng_get_mk (&cmng, file_path) < 0) {
		csmgrd_log_write (CefC_Log_Error, "CSMng create error\n");
		return (-1);
	}
	csmgrd_log_write (CefC_Log_Info, "Create CSMng [%s] ... OK\n", file_path);

	return (0);
}
/*--------------------------------------------------------------------------------------
	Function to read the management information file individual or common
	If there is no file ,create new
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_csmng_get_mk (
	FscT_Csmng* cmng,							/* FilesystemCache content manager		*/
	char* path									/* csmng file path						*/
) {
	FILE* fp;
	int fd;
	struct stat stbuf;
	int i = 0;

	memset (cmng, 0, sizeof (FscT_Csmng));

	/* Open file */
	while (i < FscC_Max_Wait_Count) {
		fd = open (path, O_RDONLY);
		if (fd != -1) {
			fp = fdopen (fd, "rb");
			if (fp != NULL) {
				break;
			}
			close (fd);
		}
		usleep (FscC_Sleep_Time);
		i++;
	}
	/* Create new file */
	if (i == FscC_Max_Wait_Count) {
		fp = fopen (path, "wb");
		if (fp != NULL) {
			fwrite (cmng, sizeof (FscT_Csmng), 1, fp);
			fclose (fp);
		} else {
			return (-1);
		}
		fd = open (path, O_RDONLY);
		if (fd == -1) {
			fclose (fp);
			return (-1);
		}
		fp = fdopen (fd, "rb");
	}
	/* fstat */
	if (fstat (fd, &stbuf) == -1) {
		close (fd);
		fclose (fp);
		return (-1);
	}
	/* Check file size */
	if (stbuf.st_size != sizeof (FscT_Csmng)) {
		csmgrd_log_write (CefC_Log_Error, "csmng file size is invalid [%d]\n", __LINE__);
		close (fd);
		fclose (fp);
		return (-1);
	}
	/* Read file */
	if (fread (cmng, stbuf.st_size, 1, fp) < 1) {
		csmgrd_log_write (CefC_Log_Error, "Read file error [%d]\n", __LINE__);
	}
	close (fd);
	fclose (fp);

	return (0);
}
/*--------------------------------------------------------------------------------------
	Initialize FileSystemCache
----------------------------------------------------------------------------------------*/
static uint32_t						/* The return value is FSCID						*/
fsc_cache_init (
	FscT_Cache_Handle* hdl,						/* FileSystemCache daemon handle		*/
	int* erst						/* The return value is negative if an error occurs	*/
) {
	char dir[CefC_Csmgr_File_Path_Length] = {0};
	char CSLok[CefC_Csmgr_File_Path_Length] = {0};
	FscT_Csmng csmng = {0};
	FscT_Csmng* cmng = &csmng;
	int mydir = 0;
	int i = 0;
	int newchk = 0;
	uint32_t fsc_id = 0xFFFFFFFF;
	int rst = 0;
	int lockno = 0; 			/* 0=Failure 0!=success */
	mode_t dmode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IXOTH | S_IXOTH;

	/* Create lock file name */
	sprintf (CSLok, "%s/%s", hdl->fsc_root_path, FscC_Csmng_Lock_Name);

	/* Lock FileSystemCache */
	rst = fsc_cache_lock (CSLok, &lockno);

	/* Initialize FileSystemCache */
	if (rst == 0) {
		/* Get csmgr management information */
		rst = fsc_csmng_get (cmng, hdl->fsc_csmng_file_name);
		if (rst == 0) {
			if (hdl->fsc_node_type == 0) {
				/* Local cache */
				while (1) {
					srand ((unsigned int)time (NULL));
					mydir = rand () % FscC_Max_Node_Inf_Num;
					if (csmng.node_inf[mydir].use_flag == 0) {
						csmng.all_init_number++;
						csmng.node_inf[mydir].use_flag = 1;
						newchk = 1;
						fsc_id = (uint32_t)mydir;
						break;
					}
				}
			} else {
				/* Common cache */
				for (i = 0; i < FscC_Max_Common_Cs_Num ; i++) {
					if (csmng.common_cs[i].node_type == hdl->fsc_node_type) {
						csmng.common_cs[i].ccs_number++;
						csmng.all_init_number++;
						fsc_id = (uint32_t)csmng.common_cs[i].nodeid;
						break;
					}
				}
				if (i >= FscC_Max_Common_Cs_Num) {
					while (1) {
						srand ((unsigned int)time (NULL));
						mydir = rand() % FscC_Max_Node_Inf_Num;
						if (csmng.node_inf[mydir].use_flag == 0) {
							csmng.all_init_number++;
							csmng.node_inf[mydir].use_flag = 1;
							newchk = 1;
							fsc_id = (uint32_t)mydir;
							for (i = 0; i  < FscC_Max_Common_Cs_Num ; i++) {
								if(csmng.common_cs[i].ccs_number == 0){
									csmng.common_cs[i].ccs_number = 1;
									csmng.common_cs[i].node_type = hdl->fsc_node_type;
									csmng.common_cs[i].nodeid = mydir;
									break;
								}
							}
						   break;
						}
					}
				}
			}
			fsc_csmng_put (cmng, hdl->fsc_csmng_file_name);
		}
		if (newchk == 1) {
			fsc_my_dir_get (fsc_id, cmng, hdl->fsc_root_path, (char*)dir);
			mkdir (dir, dmode);
		}
		*erst = 0;
		fsc_cache_unlock (CSLok , lockno);
	} else {
		*erst = -1;
	}
	return (fsc_id);
}
/*--------------------------------------------------------------------------------------
	Function to file lock.   If the file is locked, the return value is 0.
	If you can lock the file, the return value is lock number.
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_lock (
	char* path,									/* path of lock file					*/
	int* lock									/* return lock number					*/
) {
	unsigned char rdno[FscC_No_Area] = {0};
	FILE* fp;
	int lockno = 0;
	int readno = 0;
	int count = 0;
	int rst = 0;
	int cls = 0;

	while (lockno == 0) {
		fp = fopen (path, "rb");
		if(fp == NULL){
			usleep (FscC_Sleep_Time);
			fp = fopen (path, "rb");
		}
		if (fp != NULL) {
			usleep (FscC_Sleep_Time);
			if (++count > FscC_Sleep_Count) {
				if (fread (rdno, sizeof (rdno), 1, fp) < 1) {
					if (fclose (fp) != 0) {
						csmgrd_log_write (CefC_Log_Error,
							"fsc_lock[%d](%s)\n", __LINE__, strerror (errno));
					}
					return (-1);
				}
				lockno = atoi ((char*)rdno);
				rst = -1;
			}
			if((cls = fclose (fp)) != 0) {
				csmgrd_log_write (CefC_Log_Error,
					"fsc_lock[%d](%s)\n", __LINE__, strerror (errno));
			}
		} else {
			fp = fopen (path, "wb");
			if (fp != NULL) {
				srand ((unsigned int) time (NULL));
				lockno = rand ();
				sprintf ((char*)rdno, "%d", lockno);
				fwrite (rdno, sizeof (rdno), 1, fp);
				
			} else {
				csmgrd_log_write (CefC_Log_Error,
					"fsc_lock[%d](%s)\n", __LINE__, strerror (errno));
				return (-1);
			}
			
			if((cls = fclose (fp)) != 0){
				csmgrd_log_write (CefC_Log_Error,
					"fsc_lock[%d](%s)\n", __LINE__, strerror (errno));
			}
			
			fp = fopen (path, "rb");
			if (fp == NULL) {
				usleep (FscC_Sleep_Time);
				fp = fopen (path, "rb");
			}
			if (fp != NULL) {
				if (fread (rdno, sizeof (rdno), 1, fp) < 1) {
					if (fclose (fp) != 0) {
						csmgrd_log_write (CefC_Log_Error,
							"fsc_lock[%d](%s)\n", __LINE__, strerror (errno));
					}
					return (-1);
				}

				if ((cls = fclose (fp)) != 0){
					csmgrd_log_write (CefC_Log_Error,
						"fsc_lock[%d](%s)\n", __LINE__, strerror (errno));
				}
				readno = atoi ((char*)rdno);

				if (lockno != readno) {
					lockno = 0;
				}
			} else {
				lockno = 0;
				usleep (FscC_Sleep_Time);
			}
		}
	}
	*lock = lockno;
	return (rst);
}
/*--------------------------------------------------------------------------------------
	Function to file unlock.   Argument of the function lock number.
----------------------------------------------------------------------------------------*/
static void
fsc_cache_unlock (
	char* path,									/* path of lock file					*/
	int lockno									/* lock number							*/
) {
	unsigned char rdno[FscC_No_Area] = {0};
	char rmdir[CefC_Csmgr_File_Path_Length] = {0};
	FILE* fp;
	int readno;
	int cls = 0;

	/* Open file	*/
	fp = fopen (path, "rb");
	if (fp == NULL) {
		usleep (FscC_Sleep_Time);
		fp = fopen (path, "rb");
	}
	/* Unlock file	*/
	if (fp != NULL) {
		if (fread (rdno, sizeof (rdno), 1, fp) < 1) {
			csmgrd_log_write (CefC_Log_Error,
				"fsc_unlock[%d](%s)\n", __LINE__, strerror (errno));
			return;
		}
		readno = atoi ((char*)rdno);

		if (readno != lockno) {
			csmgrd_log_write (CefC_Log_Warn, ">>>>> %d (%d)\n", lockno, readno);
		} else {
			sprintf (rmdir, "rm %s", path);
			if (system (rmdir) != 0) {
				csmgrd_log_write (CefC_Log_Error, "fsc_unlock[%d]\n\r", __LINE__);
			}
 		}
 		if ((cls = fclose (fp)) != 0) {
			csmgrd_log_write (CefC_Log_Error,
				"fsc_unlock[%d](%s)\n", __LINE__, strerror (errno));
		}
	}
}
/*--------------------------------------------------------------------------------------
	Function to read the management information file individual or common
	If there is no file, an error results
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_csmng_get (
	FscT_Csmng* cmng,							/* FilesystemCache content manager		*/
	char* path									/* csmng file path						*/
) {
	FILE* fp = NULL;
	int i = 0;
	int rst = 0;

	/* Open file	*/
	while (i < FscC_Max_Wait_Count) {
		fp = fopen (path, "rb");
		if (fp != NULL) {
			break;
		}
		usleep (FscC_Sleep_Time);
		i++;
	}

	/* Read file	*/
	if (fp != NULL) {
		if (fread (cmng, sizeof (FscT_Csmng), 1, fp) < 1) {
			rst = -1;
		}
		fclose (fp);
	} else {
		memset (cmng, 0, sizeof (FscT_Csmng));
		rst = -1;
	}

	return (rst);
}
/*--------------------------------------------------------------------------------------
	Function to write out the information management file an individual or common
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_csmng_put (
	FscT_Csmng* cmng,							/* FilesystemCache content manager		*/
	char* path									/* csmng file path						*/
) {
	FILE* fp = NULL;
	int i = 0;
	int rst = 0;

	/* Open file	*/
	while (i < FscC_Max_Wait_Count) {
		fp = fopen (path, "wb");
		if (fp != NULL) {
			break;
		}
		usleep (FscC_Sleep_Time);
		i++;
	}

	/* Write file	*/
	if (fp != NULL) {
		fwrite (cmng, sizeof (FscT_Csmng), 1, fp);
		fclose (fp);
	} else {
		rst = -1;
	}

	return (rst);
}
/*--------------------------------------------------------------------------------------
	Function to get FileSystemCache use path name
----------------------------------------------------------------------------------------*/
static void
fsc_my_dir_get (
	uint32_t ex_id,								/* FilesystemCache ID					*/
	FscT_Csmng* cmng,							/* FilesystemCache content manager		*/
	char* idir,									/* in directory path					*/
	char* odir									/* out directory path					*/
) {
	if (cmng->node_inf[ex_id].use_flag != 0) {
		sprintf (odir, "%s/%u", idir, ex_id);
	}
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
	conf_param->fsc_node_type	= 0;
	conf_param->cache_cob_max 	= 65535;

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
			memcpy (conf_param->fsc_root_path, value, res);
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
	FscT_Csmng		cmng;
	FscT_Cobmng		cob_mng;
	char	cntmng_f_path[CefC_Csmgr_File_Path_Length] = {0};
	char	cobmng_f_path[CefC_Csmgr_File_Path_Length] = {0};
	char	lock_f_path[CefC_Csmgr_File_Path_Length] = {0};

	int		dir_idx, cnt_idx;
	int		rc = 0;
	int		del_cnt = 0;
	int		all_del_cnt = 0;
	static int		lockno = -1;
	static int		lock_time = 0;
	int				prev_lockno = -1;
	uint64_t nowt = cef_client_present_timeus_calc ();
	int 	rst, x;
	unsigned char 	trg_key[CsmgrdC_Key_Max];
	int 			trg_key_len;

	/* Check expire memory cache */
	fsc_memcache_expire_check ();

	if (hdl->algo_lib) {
		fsc_cache_cob_remove ();
	}

	/* Create file name */
	sprintf (lock_f_path, "%s/%s", hdl->fsc_root_path, FscC_Csmng_Lock_Name);

	/* Keep previous lock no. */
	prev_lockno = lockno;

	/* Lock FilesystemCache	*/
	rc = fsc_cache_lock (lock_f_path, &lockno);
	if (rc != -1) {
		lock_time = 0;
	} else {
		if ((lockno != -1) && (prev_lockno == lockno)) {
			lock_time++;
			if (lock_time >= FscC_Lock_Retry) {
				/* Force delete lockfile */
				rc = fsc_is_file_delete (lock_f_path);
				if (rc < 1) {
					csmgrd_log_write (
						CefC_Log_Critical, "The lock file could not be deleted.\n");
					exit (-1);
				}
				/* Retry */
				prev_lockno = lockno;
				rc = fsc_cache_lock (lock_f_path, &lockno);
				if (rc == -1) {
					csmgrd_log_write (
						CefC_Log_Critical, "Lock could not be obtained.\n");
					exit (-1);
				}
				lock_time = 0;
			} else {
				return;
			}
		} else {
			lock_time = 0;
			return;
		}
	}

	/* Read CSMng file */
	rc = fsc_csmng_get (&cmng, hdl->fsc_csmng_file_name);
	if (rc == -1) {
		/* File unlock */
		fsc_cache_unlock (lock_f_path, lockno);
		lockno = -1;
		return;
	}

	if (cmng.all_init_number <= 0) {
		/* File unlock */
		fsc_cache_unlock (lock_f_path, lockno);
		lockno = -1;
		return;
	}

	/* Loop all contents */
	for (dir_idx = 0 ; dir_idx < FscC_Max_Node_Inf_Num ; dir_idx++) {
		/* It doesn't make sense to distinguish between shared and individual           */
		/* for the management process, It only perform maintenance without distinction. */
		if (cmng.node_inf[dir_idx].use_flag < 1) {
			continue;
		}

		/* This directory is in use */
		/* Read ContentMng file */
		sprintf (cntmng_f_path, "%s/%d", hdl->fsc_root_path, dir_idx);
		rc = fsc_contentmng_get (cntmng_f_path, contmng);
		if (rc == -1) {
			continue;
		}

		/* Skip if content number is 0 */
		if (contmng->content_number <= 0) {
			continue;
		}

#ifdef CefC_Debug
		csmgrd_dbg_write (CefC_Dbg_Finest, "check content life time\n");
		csmgrd_dbg_write (CefC_Dbg_Finest, "content num is %d\n", contmng->content_number);
#endif // CefC_Debug
		for (cnt_idx = 0; cnt_idx < FscC_Max_Content_Num; cnt_idx++) {
			/* Skip if there is no time registration */
			if (timerisset (&contmng->cont_inf[cnt_idx].settime) == 0) {
				continue;
			}

			/* Read CobMng file */
			sprintf (cobmng_f_path, "%s/%d/%d", hdl->fsc_root_path, dir_idx, cnt_idx + 1);
			rc = fsc_cobmng_get (cobmng_f_path, &cob_mng);

#ifdef CefC_Debug
			if (contmng->cont_inf[cnt_idx].expiry) {
				csmgrd_dbg_write (CefC_Dbg_Finest,
					"Remaining time = "FMTU64"\n",
					contmng->cont_inf[cnt_idx].expiry - nowt);
			}
#endif // CefC_Debug

			/* Check cache expiry	*/
			if ((contmng->cont_inf[cnt_idx].expiry > 0) &&
				(nowt > contmng->cont_inf[cnt_idx].expiry)) {
				/* content expire	*/
#ifdef CefC_Debug
				csmgrd_dbg_write (CefC_Dbg_Finest,
					""FMTU64" cob expire\n", contmng->cont_inf[cnt_idx].cob_num);
#endif // CefC_Debug
				char del_contnt_name[CefC_Csmgr_File_Path_Length] = {0};
				sprintf (del_contnt_name,
					 			"%s/%d/%d", hdl->fsc_root_path, dir_idx, cnt_idx + 1);

				/* Delete this content(directory and all files) */
				rc = fsc_dir_remove (del_contnt_name, FscC_Not_Del_Rootdir);
				if (rc < 0) {
					/* Clean root directory */
					fsc_dir_remove (hdl->fsc_root_path, FscC_Not_Del_Rootdir);
					csmgrd_log_write (
						CefC_Log_Critical, "Failed to remove content directory.\n");
					exit (-1);
				}

				/* Calls erase API */
				if (hdl->algo_lib) {
					for (x = contmng->cont_inf[cnt_idx].chunk_min ;
						x <= contmng->cont_inf[cnt_idx].chunk_max ; x++) {

						rst = fsc_cob_bit_unset (&cob_mng, x);

						if (rst > 0) {
							hdl->cache_cobs--;

							/* Creates the key */
							trg_key_len = csmgrd_name_chunknum_concatenate (
								(unsigned char*) contmng->cont_inf[cnt_idx].name,
								contmng->cont_inf[cnt_idx].name_len,
								(uint32_t) x, trg_key);
							if (hdl->algo_apis.erase) {
								(*(hdl->algo_apis.erase))(trg_key, trg_key_len);
							}
						}
					}
				}

				/* Count delete content */
				del_cnt++;
				memset (&contmng->cont_inf[cnt_idx].name,
					 0, sizeof(char) * CefC_Max_Msg_Size);
				timerclear (&contmng->cont_inf[cnt_idx].settime);
				contmng->cont_inf[cnt_idx].expiry = 0;
				contmng->cont_inf[cnt_idx].access_cnt = 0;
				contmng->cont_inf[cnt_idx].size = 0;
				contmng->cont_inf[cnt_idx].cob_num = 0;
				contmng->cont_inf[cnt_idx].chunk_max = 0;
				contmng->cont_inf[cnt_idx].chunk_min = 0;
			}
		}
		/* Reflect results */
		if (del_cnt > 0) {
			contmng->content_number = contmng->content_number - del_cnt;
			fsc_contentmng_put (cntmng_f_path, contmng);
			all_del_cnt += del_cnt;
			del_cnt = 0;
		}
	}

	if (all_del_cnt) {
		/* Update all content num */
		cmng.all_content_number -= all_del_cnt;
		fsc_csmng_put (&cmng, hdl->fsc_csmng_file_name);
	}

	/* File unlock */
	fsc_cache_unlock (lock_f_path, lockno);
	lockno = -1;

	/* Check put queue	*/
	if (hdl->item_que_num != 0) {
		if ((hdl->item_put_time != 0) && hdl->item_put_time < nowt) {
			fsc_item_put_into_cache (hdl);
		}
	}

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
	Function to read the content management file
	If there is no file ,no read
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_contentmng_get (
	char* dir,									/* content manager directory			*/
	FscT_Contentmng* contmng					/* content manager						*/
) {
	char cmsg[CefC_Csmgr_File_Path_Length] = {0};
	FILE* fp = NULL;
	int i = 0;
	int rst = 0;

	/* Create file name	*/
	sprintf (cmsg, "%s/ContentMng", dir);

	/* Try open file	*/
	while (i < FscC_Max_Wait_Count) {
		fp = fopen (cmsg, "rb");
		if (fp != NULL) {
			break;
		}
		usleep (FscC_Sleep_Time);
		i++;
	}

	if (fp != NULL) {
		if (fread (contmng, sizeof (FscT_Contentmng), 1, fp) < 1) {
			csmgrd_log_write (CefC_Log_Error, "Content manager read error\n");
		}
		fclose (fp);
	} else {
		memset (contmng, 0, sizeof (FscT_Contentmng));
		rst = -1;
	}

	return (rst);
}
/*--------------------------------------------------------------------------------------
	Function to read the cob management file
	If there is no file ,no read
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cobmng_get (
	char* dir,									/* cob manager directory				*/
	FscT_Cobmng* comng							/* cob manager							*/
) {
	char omsg[CefC_Csmgr_File_Path_Length] = {0};
	FILE* fp = NULL;
	int i = 0;
	int rst = 0;

	/* Create file name	*/
	sprintf (omsg, "%s/CobMng", dir);

	/* Open file	*/
	while (i < FscC_Max_Wait_Count) {
		fp = fopen (omsg, "rb");
		if (fp != NULL) {
			break;
		}
		usleep (FscC_Sleep_Time);
		i++;
	}

	if (fp != NULL) {
		if (fread (comng, sizeof (FscT_Cobmng), 1, fp) < 1) {
			csmgrd_log_write (CefC_Log_Error, "Cob manager read error\n");
		}
		fclose (fp);
	} else {
		memset (comng, 0, sizeof (FscT_Cobmng));
		rst = -1;
	}

	return (rst);
}
/*--------------------------------------------------------------------------------------
	delete directory path
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_dir_remove (
	char* filepath,								/* file path							*/
	int mode									/* Remove Mode							*/
) {
	int rc = 0;

	/* Delete internal file */
	rc = fsc_dir_clear (filepath);
	if( rc != 0 ) {
		csmgrd_log_write (CefC_Log_Error, "Dir clear\n");
		return (-1);
	}

	if (mode == FscC_Not_Del_Rootdir) {
		/* Delete directory */
		rc = rmdir (filepath);
		if (rc < 0) {
			csmgrd_log_write (CefC_Log_Error, "rmdir error\n");
			return (-1);
		}
	}

	return (0);
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
	Function to write out the content management file
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_contentmng_put (
	char* dir,									/* content manager directory			*/
	FscT_Contentmng* contmng					/* content manager						*/
) {
	char cmsg[CefC_Csmgr_File_Path_Length] = {0};
	FILE* fp = NULL;
	int i = 0;
	int rst = 0;

	/* Create filename */
	sprintf (cmsg, "%s/ContentMng", dir);

	/* Open file */
	while (i < FscC_Max_Wait_Count) {
		fp = fopen (cmsg, "wb");
		if (fp != NULL) {
			break;
		}
		usleep (FscC_Sleep_Time);
		i++;
	}

	if (fp != NULL) {
		fwrite (contmng, sizeof (FscT_Contentmng), 1, fp);
		fclose (fp);
	} else {
		/* Open failed */
		rst = -1;
	}

	return (rst);
}
/*--------------------------------------------------------------------------------------
	Destroy content store
----------------------------------------------------------------------------------------*/
static void
fsc_cs_destroy (
	void
) {
	unsigned char dir[CefC_Csmgr_File_Path_Length] = {0};
	char CSLok[CefC_Csmgr_File_Path_Length] = {0};
	char rmdir[CefC_Csmgr_File_Path_Length] = {0};
	FscT_Csmng csmng = {0};
	FscT_Csmng* cmng = &csmng;
	int nodeid = 0;
	int delid = 0;
	int common = 0;
	int i = 0;
	int rst;
	int lockno = 0; 			/* 0=Failure 0!=success */

	/* Check handle */
	if (hdl == NULL) {
		return;
	}

	/* Close the looded cache algorithm library */
	if (hdl->algo_lib) {
		if (hdl->algo_apis.destroy) {
			(*(hdl->algo_apis.destroy))();
		}
		dlclose (hdl->algo_lib);
	}

	/* Create lock file name */
	sprintf (CSLok, "%s/%s", hdl->fsc_root_path, FscC_Csmng_Lock_Name);

	/* Lock FileSystemCache */
	rst = fsc_cache_lock (CSLok, &lockno);

	/* Clean FileSystemCache	*/
	if (rst == 0) {
		/* Get csmgr management information	*/
		rst = fsc_csmng_get (cmng, hdl->fsc_csmng_file_name);
		if (rst == 0) {
			fsc_my_dir_get (hdl->fsc_id, cmng, hdl->fsc_root_path, (char*)dir);
			nodeid = hdl->fsc_id;
			for (i = 0; i < FscC_Max_Common_Cs_Num; i++) {
				if (csmng.common_cs[i].nodeid == nodeid) {
					csmng.common_cs[i].ccs_number--;
					csmng.all_init_number--;
					if (csmng.common_cs[i].ccs_number == 0) {
						csmng.common_cs[i].node_type = 0;
						csmng.common_cs[i].nodeid = 0;
						csmng.node_inf[nodeid].use_flag = 0;
						delid = nodeid;
					}
					common = 1;
				}
			}
			if (common == 0) {
				if (csmng.node_inf[nodeid].use_flag != 0) {
					csmng.node_inf[nodeid].use_flag = 0;
					csmng.all_init_number--;
					delid = nodeid;
				}
			}
			/* Get content manager	*/
			rst = fsc_mk_contentmng_get ((char*)dir, contmng);
			if (contmng->content_number > 0) {
				if (csmng.all_content_number >= contmng->content_number) {
					csmng.all_content_number -= contmng->content_number;
				}
			}
			fsc_csmng_put (cmng, hdl->fsc_csmng_file_name);
			if (delid > 0) {
				sprintf (rmdir, "rm -r ");
				strcat (rmdir, (char*)dir);
				if (system (rmdir) != 0) {
					csmgrd_log_write (CefC_Log_Error, "fsc_unlock[%d]\n", __LINE__);
				}
			}
		}
		fsc_cache_unlock (CSLok, lockno);
	}

	/* Clean cache queue */
	if (hdl->item_put_que != NULL) {
		cef_rngque_destroy (hdl->item_put_que);
		hdl->item_put_que = NULL;
	}
	if (hdl->mem_cache_que != NULL) {
		cef_rngque_destroy (hdl->mem_cache_que);
		hdl->mem_cache_que = NULL;
	}

	/* Destroy handle */
	free (hdl);
	hdl = NULL;

	/* Destroy FscT_Contentmng */
	if (contmng != NULL) {
		free (contmng);
		contmng = NULL;
	}

	/* Destroy FscT_File_Element */
	if (file_area != NULL) {
		free (file_area);
		file_area = NULL;
	}

	return;
}
/*--------------------------------------------------------------------------------------
	Function to read the content management file
	If there is no file ,create new
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_mk_contentmng_get (
	char* dir,									/* content manager directory			*/
	FscT_Contentmng* contmng					/* content manager						*/
) {
	char cmsg[CefC_Csmgr_File_Path_Length] = {0};
	FILE* fp;
	int fd;
	struct stat stbuf;
	int i = 0;

	/* Create file name */
	sprintf (cmsg, "%s/ContentMng", dir);

	memset (contmng, 0, sizeof (FscT_Contentmng));
	/* Try open file */
	while (i < FscC_Max_Wait_Count) {
		fd = open (cmsg, O_RDONLY);
		if (fd != -1) {
			fp = fdopen (fd, "rb");
			if (fp != NULL) {
				break;
			}
			close (fd);
		}
		usleep (FscC_Sleep_Time);
		i++;
	}

	if (i == FscC_Max_Wait_Count) {
		/* Create file	*/
		fp = fopen (cmsg, "wb");
		if (fp != NULL) {
			fwrite (contmng, sizeof (FscT_Contentmng), 1, fp);
			fclose (fp);
		} else {
			/* Open file error	*/
			return (-1);
		}
		fd = open (cmsg, O_RDONLY);
		fp = fdopen (fd, "rb");
	}
	/* Get file status	*/
	if (fstat (fd, &stbuf) == -1) {
		return (-1);
	}
	/* Check size	*/
	if (stbuf.st_size != sizeof (FscT_Contentmng)) {
		csmgrd_log_write (CefC_Log_Error, "Content manager file size is invalid\n");
		return (-1);
	}
	/* Read content manager	*/
	if (fread (contmng, stbuf.st_size, 1, fp) < 1) {
		csmgrd_log_write (CefC_Log_Error, "Content manager read error)\n");
	}
	close (fd);
	fclose (fp);

	return (1);
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
	unsigned char dir[CefC_Csmgr_File_Path_Length] = {0};
	unsigned char cdir[CefC_Csmgr_File_Path_Length] = {0};
	char CSLok[CefC_Csmgr_File_Path_Length] = {0};
	FscT_Csmng csmng = {0};
	FscT_Csmng* cmng = &csmng;
	FscT_Cobmng cob_mng = {0};
	FscT_Cobmng* comng = &cob_mng;
	int no;
	int rst = 0;
	int result = CefC_Csmgr_Cob_Exist;
	int ele_no = -1;
	int lockno = 0; 			/* 0=Failure 0!=success */
	int i;
	FscT_Mem_Cache_Content_Entry* content_entry = NULL;
	CefT_Csmgrd_Content_Info* cob_entry;
	FscT_Mem_Cache_Cob_Queue* cob_que;
	FscT_Mem_Cache_Cob_Queue* cob_que_top = NULL;
	CefT_Csmgrd_Content_Info* send_cob_que[FscC_MemCache_Max_Block_Num];
	unsigned char 	trg_key[CsmgrdC_Key_Max];
	int 			trg_key_len;
	CefT_Csmgrd_Content_Info c_entry;
	CefT_Csmgrd_Content_Info* centry = &c_entry;
	int read_num = 0;

	/* Search memory cache */
	if (fsc_memcache_lookup (key, key_size, seqno, sock) == CefC_Csmgr_Cob_Exist) {
		/* Success */
		return (CefC_Csmgr_Cob_Exist);
	}

	/* Create file name */
	sprintf (CSLok, "%s/%s", hdl->fsc_root_path, FscC_Csmng_Lock_Name);

	/* Lock FileSystemCache */
	rst = fsc_cache_lock (CSLok, &lockno);
	if (rst != 0) {
		/* Lock error */
		csmgrd_log_write (CefC_Log_Error, "Lock error\n");
		return (-1);
	}

	/* Get csmng status */
	rst = fsc_csmng_get (cmng, hdl->fsc_csmng_file_name);
	if (rst == -1) {
		/* Get status error */
		result = -1;
		goto GetExit;
	}
	/* Get directory */
	fsc_my_dir_get (hdl->fsc_id, cmng, (char*)hdl->fsc_root_path, (char*)dir);
	if (dir[0] == 0) {
		/* Get directory error */
		result = -1;
		goto GetExit;
	}
	/* Get content manager */
	rst = fsc_contentmng_get ((char*)dir, contmng);
	if (rst < 0) {
		/* Get content manager error */
		result = -1;
		goto GetExit;
	}
	/* Search content name */
	no = fsc_content_no_get (contmng, key, key_size);
	if (no > FscC_Max_Content_Num) {
		result = -1;
		goto GetExit;
	}

	/* Check expire */
	if ((contmng->cont_inf[no - 1].expiry != 0) &&
		(contmng->cont_inf[no - 1].expiry < cef_client_present_timeus_calc ())) {
		/* Content expire */
		result = -1;
		goto GetExit;
	}

	/* Check chunk num */
	if (seqno == 0) {
		/* Access count increment */
		contmng->cont_inf[no - 1].access_cnt += 1;
		fsc_contentmng_put ((char*)dir, contmng);
	}
	/* Get content directory */
	fsc_cont_dir_get ((char*)dir, no, (char*)cdir);
	/* Get cob manager */
	rst = fsc_cobmng_get ((char*)cdir, comng);
	if (rst == -1) {
		/* Error */
		result = -1;
		goto GetExit;
	}

	/* Get content */
	for (i = 0; i < FscC_MemCache_Max_Block_Num; i++) {
		rst = fsc_cob_bit_check (comng, seqno + i);
		if (rst == 0) {
			if (i) {
				if (comng->last_cob_number < (seqno + i)) {
					/* File end */
					goto GetExit;
				}
				continue;
			} else {
				/* no cob */
				result = -1;
				goto GetExit;
			}
		}
		if (ele_no != (seqno + i) / FscC_Element_Num) {
			ele_no = (seqno + i) / FscC_Element_Num;
			rst = fsc_element_g_read ((char*)cdir, ele_no, (char *)&file_area[0]);
			if (rst == -1) {
				result = -1;
				goto GetExit;
			}
		}
		/* Get entry */
		fsc_content_entry_get (
				(FscT_File_Element*)&file_area[(seqno + i) % FscC_Element_Num], centry);
		memcpy (
			centry->name,
			contmng->cont_inf[no - 1].name,
			contmng->cont_inf[no - 1].name_len);
		centry->name_len = contmng->cont_inf[no - 1].name_len;
		centry->cache_time = contmng->cont_inf[no - 1].cache_time;
		centry->expiry = contmng->cont_inf[no - 1].expiry;
		/* Check content entry */
		if (content_entry == NULL) {
			/* Search content */
			content_entry = (FscT_Mem_Cache_Content_Entry*)cef_hash_tbl_item_get (
									hdl->mem_cache_table, centry->name, centry->name_len);
			/* Check result */
			if (content_entry == NULL) {
				/* Content entry is not exist. create new content entry */
				content_entry = fsc_memcache_content_entry_create (centry);
				if (content_entry == NULL) {
					goto GetExit;
				}
				/* Set content entry */
				rst = cef_hash_tbl_item_set (
											hdl->mem_cache_table,
											(const unsigned char*)(content_entry->name),
											content_entry->name_len,
											content_entry);
				/* Check result */
				if (rst == CefC_Hash_Faile) {
					free (content_entry);
					goto GetExit;
				}
				content_entry->index = rst;
				/* Increment content num */
				hdl->mem_cache_table_num++;
			}
		}
		/* Check cob */
		if (content_entry->entry[(seqno + i) % FscC_MemCache_Max_Cob_Num] != NULL) {
			free (content_entry->entry[(seqno + i) % FscC_MemCache_Max_Cob_Num]);
			content_entry->entry[(seqno + i) % FscC_MemCache_Max_Cob_Num] = NULL;
		}
		/* Create new cob entry */
		cob_entry = fsc_memcache_cob_entry_create (centry);
		if (cob_entry == NULL) {
			goto GetExit;
		}

		if (cob_que_top == NULL) {
			/* Create cob queue */
			cob_que_top = (FscT_Mem_Cache_Cob_Queue*) malloc (sizeof (FscT_Mem_Cache_Cob_Queue));
			cob_que_top->index = content_entry->index;
			cob_que_top->block_num = 0;
			cob_que_top->seq_num = cob_entry->chnk_num;
			cob_que_top->expiry = cef_client_present_timeus_get ()
			 						+ (FscC_MemCache_Check_Expire * 1000000);
			/* Push cob queue */
			rst = cef_rngque_push (hdl->mem_cache_que, cob_que_top);
			if (rst < 1) {
				/* Push failed */
				free (cob_entry);
				free (cob_que_top);
				goto GetExit;
			}
		} else {
			/* Create cob queue */
			cob_que = (FscT_Mem_Cache_Cob_Queue*) malloc (sizeof (FscT_Mem_Cache_Cob_Queue));
			cob_que->seq_num = cob_entry->chnk_num;
			/* Push cob queue */
			rst = cef_rngque_push (hdl->mem_cache_que, cob_que);
			if (rst < 1) {
				/* Push failed */
				free (cob_entry);
				free (cob_que);
				goto GetExit;
			}
		}
		/* Set cob entry */
		content_entry->entry[(seqno + i) % FscC_MemCache_Max_Cob_Num] = cob_entry;
		send_cob_que[read_num] = cob_entry;
		/* Increment num */
		content_entry->cache_num++;
		hdl->mem_cache_num++;
		cob_que_top->block_num++;
		read_num++;
	}

GetExit:
	/* Unlock FileSystemCache */
	fsc_cache_unlock (CSLok, lockno);

	if (result != CefC_Csmgr_Cob_Exist) {
		if (hdl->algo_apis.miss) {
			trg_key_len =
				 csmgrd_name_chunknum_concatenate (key, key_size, seqno, trg_key);
			(*(hdl->algo_apis.miss))(trg_key, trg_key_len);
		}
	} else {
		if (hdl->algo_apis.hit) {
			trg_key_len =
				 csmgrd_name_chunknum_concatenate (key, key_size, seqno, trg_key);
			(*(hdl->algo_apis.hit))(trg_key, trg_key_len);
		}
	}

	if (read_num != 0) {
		/* Search free element */
		if ((rst = fsc_free_pid_index_search ()) < 0) {
			return (-1);
		}
		/* Send cob */
		pid_t child_pid = fork ();
		/* Check pid */
		if (child_pid == -1) {
			csmgrd_log_write (CefC_Log_Error, "fork (%d : %s)\n", errno, strerror (errno));
			return (-1);
		}
		/* Check child pid 	*/
		if (child_pid == 0) {
#ifdef CefC_Debug
			csmgrd_dbg_write (CefC_Dbg_Fine, "**CEF-CHILD** Enter\n");
			csmgrd_dbg_write (CefC_Dbg_Fine, "get some cob = %d\n", read_num);
#endif // CefC_Debug
			/* Send ContentObject to cefnetd */
			fsc_cache_cob_send (send_cob_que, read_num, sock);
#ifdef CefC_Debug
			csmgrd_dbg_write (CefC_Dbg_Fine, "**CEF-CHILD** Exit\n");
#endif // CefC_Debug
			exit (0);
		}
		/* Set pid element */
		child_pid_list[rst].child_pid = child_pid;
		memcpy (child_pid_list[rst].key, key, key_size);
		child_pid_list[rst].key_len = key_size;
		child_pid_list[rst].seq_num = seqno;
		child_pid_list[rst].sock = sock;
	}

	return (result);
}
/*--------------------------------------------------------------------------------------
	Function to get content entry no
----------------------------------------------------------------------------------------*/
static int							/* The return value is content entry num			*/
fsc_content_no_get (
	FscT_Contentmng* contmng,					/* content manager						*/
	unsigned char* key,							/* content name							*/
	int key_size								/* content name length					*/
) {
	int i;
	for (i = 0; i < FscC_Max_Content_Num; i++) {
		if (contmng->cont_inf[i].name_len == key_size) {
			if (memcmp (contmng->cont_inf[i].name, key, key_size) == 0) {
				break;
			}
		}
	}
	return(i + 1);
}
/*--------------------------------------------------------------------------------------
	Function to get content path name
----------------------------------------------------------------------------------------*/
static void
fsc_cont_dir_get (
	char* dir,									/* content manager directory			*/
	int contno,									/* content chunk number					*/
	char* contdir								/* content directory					*/
) {
	sprintf (contdir, "%s/%d", dir, contno);
	return;
}
/*--------------------------------------------------------------------------------------
	Function to check receive status on cob management file
----------------------------------------------------------------------------------------*/
static int							/* The return value is result						*/
fsc_cob_bit_check (
	FscT_Cobmng* comng,							/* cob manager							*/
	int seqno									/* chunk num							*/
) {
	int off;
	int bit;
	int line_size;
	unsigned bit_p = 1;
	int result = 0;

	line_size = sizeof (unsigned) * 8;
	if (seqno <= (FscC_Rcvcheck_Size * line_size)) {
		off = seqno / line_size;
		bit = seqno % line_size;

		bit_p = (bit_p << bit);
		result = (int)(comng->rcvcheck[off] & bit_p);
	}
	return(result);
}
/*--------------------------------------------------------------------------------------
	Function to read elements group file
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_element_g_read (
	char* dir,									/* element group file directory			*/
	int file_no,								/* file number							*/
	char* cent									/* file Element							*/
) {
	char file_name[CefC_Max_Msg_Size] = {0};

	FILE* fp;
	struct stat stbuf;
	int fd;

	/* Create file name	*/
	sprintf (file_name, "%s/%d", dir, file_no);

	/* Open file	*/
	fd = open (file_name, O_RDONLY);
	if (fd == -1) {
		return (-1);
	}

	fp = fdopen (fd, "rb");
	if (fp == NULL) {
		return (-1);
	}

	/* Get file status	*/
	if (fstat (fd, &stbuf) == -1) {
		return (-1);
	}
	/* Read file	*/
	if (fread (cent, stbuf.st_size, 1, fp) < 1) {
		csmgrd_log_write (CefC_Log_Error, "elements group file read error\n");
	}

	close (fd);
	fclose (fp);

	return (0);
}
/*--------------------------------------------------------------------------------------
	Function to get content_entry info
----------------------------------------------------------------------------------------*/
static CefT_Csmgrd_Content_Info* 	/* The return value is NULL if an error occurs		*/
fsc_content_entry_get (
	FscT_File_Element* cent,					/* file element							*/
	CefT_Csmgrd_Content_Info* centry			/* content information					*/
) {
	/* Get content information	*/
	memcpy (centry->msg, &cent->msg, CefC_Max_Msg_Size);
	centry->msg_len = cent->msg_len;
	centry->chnk_num = cent->chnk_num;
	centry->pay_len = cent->pay_len;

	return (centry);
}
/*--------------------------------------------------------------------------------------
	Upload content entry
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_item_put (
	CsmgrdT_Content_Entry* entry
) {
	CsmgrdT_Content_Entry* content_entry;
	int res;
	
	/* Check item num */
	if ((hdl->item_que_num + 1) == FscC_ItemPut_Que_Size) {
		/* To write item to file	*/
		fsc_item_put_into_cache (hdl);
	}
	
	/* Alloc memory */
	content_entry = (CsmgrdT_Content_Entry*)malloc (sizeof (CsmgrdT_Content_Entry));
	if (content_entry == NULL) {
		csmgrd_log_write (CefC_Log_Error, "mpool alloc error\n");
		return (-1);
	}
	memcpy (content_entry, entry, sizeof (CsmgrdT_Content_Entry));

	/* Queue item */
	res = cef_rngque_push (hdl->item_put_que, content_entry);
	if (res < 1) {
		/* Push failed */
		csmgrd_log_write (CefC_Log_Error,
			"Push failed chunk num = %d\n", content_entry->chnk_num);
		free (content_entry);
	} else {
		/* Set time */
		hdl->item_que_num++;
		hdl->item_put_time = cef_client_present_timeus_calc () + FscC_ItemPut_Time;
	}

	return (0);
}
/*--------------------------------------------------------------------------------------
	fork process , and reset ring queue.
----------------------------------------------------------------------------------------*/
static int
fsc_item_put_into_cache (
	FscT_Cache_Handle* hdl
) {
	CsmgrdT_Content_Entry* content_entry;

	/* FORK */
	pid_t child_pid = fork ();

	/* Check pid	*/
	if (child_pid == -1) {
		csmgrd_log_write (
			CefC_Log_Error, "fork (%d : %s)\n", errno, strerror (errno));
		return (-1);
	}

	/* Check child pid */
	if (child_pid == 0) {
#ifdef CefC_Debug
		csmgrd_dbg_write (CefC_Dbg_Fine, "**CEF-CHILD** Enter\n");
		csmgrd_dbg_write (CefC_Dbg_Fine, "put item num = %d\n", hdl->item_que_num);
#endif // CefC_Debug
		/* Put ContentObject into Content Store */
		fsc_cache_item_write (hdl->item_que_num, hdl->item_put_que, hdl->item_put_que_mp);
#ifdef CefC_Debug
		csmgrd_dbg_write (CefC_Dbg_Fine, "**CEF-CHILD** Exit\n");
#endif // CefC_Debug
		exit (0);
	}

	/* Free all ring queue */
	while (1) {
		content_entry = (CsmgrdT_Content_Entry*)cef_rngque_pop (hdl->item_put_que);
		if (content_entry == NULL) {
			/* Empty */
			break;
		}
		if (hdl->algo_apis.insert) {
			(*(hdl->algo_apis.insert))(content_entry);
		}
		hdl->item_que_num--;
		/* Free the pooled block */
		free (content_entry);
	}
	
	hdl->item_que_num = 0;
	hdl->item_put_time = 0;
	return (0);
}
/*--------------------------------------------------------------------------------------
	Write Cob entry
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_item_write (
	int item_que_num,							/* queue num							*/
	CefT_Rngque* item_put_que,					/* item queue							*/
	CefT_Mp_Handle item_put_que_mp				/* item queue memory pool				*/
) {
	unsigned char dir[CefC_Csmgr_File_Path_Length] = {0};
	unsigned char cdir[CefC_Csmgr_File_Path_Length] = {0};
	char CSLok[CefC_Csmgr_File_Path_Length] = {0};
	int result = 0; 			/* 0=success 0!=Failure*/
	int lockno = 0; 			/* 0=Failure 0!=success */
	FscT_Csmng csmng = {0};
	FscT_Csmng* cmng = &csmng;
	FscT_Cobmng cob_mng = {0};
	FscT_Cobmng *comng = &cob_mng;
	int i;
	int j;
	int set_cnt = 0;
	int set_ele = 0;
	mode_t dmode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IXOTH | S_IXOTH;
	int rst = 0;

	int notbl[FscC_ItemPut_Que_Size];
	int eletbl[FscC_ItemPut_Que_Size][2];
	int ex_ele;
	int ele_gno;

	CsmgrdT_Content_Entry* ptble[FscC_ItemPut_Que_Size];
	CsmgrdT_Content_Entry* entry;
	int prev_content_num;

	/* Create lock file name */
	sprintf (CSLok, "%s/%s", hdl->fsc_root_path, FscC_Csmng_Lock_Name);

	/* Lock FileSystemCache */
	rst = fsc_cache_lock (CSLok, &lockno);
	if (rst != 0) {
		csmgrd_log_write (CefC_Log_Error, "Lock error\n");
		return (-1);
	}

	/* Get csmgr management information */
	rst = fsc_csmng_get (cmng, hdl->fsc_csmng_file_name);
	if(rst == -1) {
		result = -3;
		goto PutExit;
	}

	/* Get my directory */
	fsc_my_dir_get (hdl->fsc_id, cmng, hdl->fsc_root_path, (char*)dir);
	if (dir[0] == 0) {
		result = -3;
		goto PutExit;
	}

	/* Get content manager */
	rst = fsc_mk_contentmng_get ((char*)dir, contmng);
	if (rst < 0) {
		rst = fsc_mk_contentmng_get ((char*)dir, contmng);
		if (rst == -1) {
			result = -3;
			goto PutExit;
		}
	}

	prev_content_num = contmng->content_number;
	/* Get item from ring queue */
	for (i = 0; i < item_que_num; i++) {
		/* Pop item */
		entry = (CsmgrdT_Content_Entry*)cef_rngque_pop (item_put_que);
		/* Get content info */
		notbl[i] = fsc_content_no_get (contmng, entry->name, entry->name_len);
		if (notbl[i] > FscC_Max_Content_Num) {
			/* Set new content info */
			notbl[i] = fsc_content_inf_set (contmng, entry);
			if (notbl[i] > FscC_Max_Content_Num) {
				result = -3;
				free (entry);
				goto PutExit;
			}
		}
		ptble[i] = entry;
	}

	ex_ele = 0;

	/* Put content object */
	for (i = 0; i < FscC_Max_Content_Num; i++) {
		set_cnt = 1;
		for (j = 0; j < item_que_num; j++) {
			if (notbl[j] != i) {
				eletbl[j][0] = -1;
				continue;
			}
			if (set_cnt) {
				/* Get content directory */
				memset (cdir, 0, sizeof (cdir));
				fsc_cont_dir_get ((char*)dir, notbl[j], (char*)cdir);
				/* Get or make cob manager */
				rst = fsc_mk_cobmng_get ((char*)cdir, comng);
				if (rst == -1) {
					mkdir ((char*)cdir, dmode);
					rst = fsc_mk_cobmng_get ((char*)cdir, comng);
					if (rst == -1) {
						result = -3;
						csmgrd_log_write (
							CefC_Log_Error, "ERROR(1) result[%d]\n", result);
						break;
					}
				}
				set_cnt = 0;
			}
			/* Check cob bit */
			rst = fsc_cob_bit_check (comng, ptble[j]->chnk_num);
			if (rst != 0) {
				result = -3;
				free (ptble[j]);
				continue;
			}
			/* Set cob bit */
			fsc_cob_bit_set (comng, ptble[j]->chnk_num);
			cob_mng.cob_number++;
			if (cob_mng.last_cob_number < ptble[j]->chnk_num) {
				cob_mng.last_cob_number = ptble[j]->chnk_num;
			}
			eletbl[j][0] = ptble[j]->chnk_num / FscC_Element_Num;
			eletbl[j][1] = ptble[j]->chnk_num % FscC_Element_Num;

			contmng->cont_inf[notbl[j] - 1].cob_num += 1;
			contmng->cont_inf[notbl[j] - 1].size += (uint64_t)(ptble[j]->pay_len);
			if (contmng->cont_inf[notbl[j] - 1].chunk_max < ptble[j]->chnk_num) {
				contmng->cont_inf[notbl[j] - 1].chunk_max = ptble[j]->chnk_num;
			}
			if (contmng->cont_inf[notbl[j] - 1].chunk_min > ptble[j]->chnk_num) {
				contmng->cont_inf[notbl[j] - 1].chunk_min = ptble[j]->chnk_num;
			}
			ex_ele++;
		}

		/* Check set count */
		if (set_cnt != 0) {
			continue;
		}
		/* Put cob manager */
		ele_gno = 0;
		/* Put content object */
		while (ex_ele > 0) {
			set_ele = 1;
			for (j = 0 ; j < item_que_num; j++){
				if (eletbl[j][0] != ele_gno) {
					continue;
				}
				if (set_ele) {
					rst = fsc_element_g_get ((char*)cdir, ele_gno, (char *)&file_area[0]);
					if (rst < 0) {
						free (ptble[j]);
						ex_ele--;
						continue;
					}
					set_ele = 0;
				}
				fsc_content_entry_put (&file_area[eletbl[j][1]], ptble[j]);
				/* Free item */
				free (ptble[j]);
				ex_ele--;
			}
			if (set_ele != 1) {
				fsc_element_g_put ((char*)cdir, ele_gno, (char *)&file_area[0]);
			}
			ele_gno++;
		}
		fsc_cobmng_put ((char*)cdir, comng);
	}
	/* Update content manager */
	fsc_contentmng_put ((char*)dir, contmng);
	/* Update all content num */
	if (contmng->content_number > prev_content_num) {
		cmng->all_content_number += contmng->content_number - prev_content_num;
		fsc_csmng_put (cmng, hdl->fsc_csmng_file_name);
	}
PutExit:
	/* Unlock FileSystemCache*/
	fsc_cache_unlock (CSLok , lockno);

	return (result);
}
/*--------------------------------------------------------------------------------------
	Function to set content manage info
----------------------------------------------------------------------------------------*/
static int							/* The return value is content information index	*/
fsc_content_inf_set (
	FscT_Contentmng* contmng,					/* content manager						*/
	CsmgrdT_Content_Entry* entry				/* content Information					*/
) {
	int i;

	/* Search free info */
	for (i = 0; i < FscC_Max_Content_Num; i++) {
		if (contmng->cont_inf[i].name_len == 0) {
			/* Set new content info */
			contmng->content_number++;
			memcpy (contmng->cont_inf[i].name, entry->name, entry->name_len);
			contmng->cont_inf[i].name_len = entry->name_len;
			timerclear (&contmng->cont_inf[i].settime);
			contmng->cont_inf[i].cache_time = entry->cache_time;
			contmng->cont_inf[i].expiry = entry->expiry;
			contmng->cont_inf[i].access_cnt = 0;
			contmng->cont_inf[i].cob_num = 0;
			contmng->cont_inf[i].size = 0;
			contmng->cont_inf[i].node = entry->node;
			contmng->cont_inf[i].chunk_max = entry->chnk_num;
			contmng->cont_inf[i].chunk_min = entry->chnk_num;

			/* Gettimeofday */
			if (gettimeofday (&contmng->cont_inf[i].settime, NULL)) {
				/* Failed */
				i = FscC_Max_Content_Num;
			}
			break;
		}
	}
	return(i + 1);
}
/*--------------------------------------------------------------------------------------
	Function to read the cob management file
	If there is no file ,create new
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_mk_cobmng_get (
	char* dir,									/* cob manager directory				*/
	FscT_Cobmng* comng							/* cob manager							*/
) {
	char omsg[CefC_Csmgr_File_Path_Length] = {0};
	FILE* fp;
	int fd;
	struct stat stbuf;
	int i = 0;

	/* Create file name */
	sprintf (omsg, "%s/CobMng", dir);
	memset (comng, 0, sizeof (FscT_Cobmng));

	/* Open file */
	while (i < FscC_Max_Wait_Count) {
		fd = open (omsg, O_RDONLY);
		if (fd != -1) {
			fp = fdopen (fd, "rb");
			if (fp != NULL) {
				break;
			}
			close (fd);
		}
		usleep (FscC_Sleep_Time);
		i++;
	}

	/* Create new file */
	if (i == FscC_Max_Wait_Count) {
		fp = fopen (omsg, "wb");
		if (fp != NULL) {
			fwrite (comng, sizeof (FscT_Cobmng), 1, fp);
			fclose (fp);
		} else {
			return (-1);
		}
		fd = open (omsg, O_RDONLY);
		fp = fdopen (fd, "rb");
	}

	/* Get status */
	if (fstat (fd, &stbuf) == -1) {
		return (-1);
	}

	/* Check status */
	if (stbuf.st_size != sizeof (FscT_Cobmng)) {
		csmgrd_log_write (CefC_Log_Error, "cob manager filesize is invalid\n");
		return (-1);
	}

	/* Read file */
	if (fread (comng, stbuf.st_size, 1, fp) < 1) {
		csmgrd_log_write (CefC_Log_Error, "cob manager read error\n");
	}
	close (fd);
	fclose (fp);

	return (1);
}
/*--------------------------------------------------------------------------------------
	Function to set receive status on cob management file
----------------------------------------------------------------------------------------*/
static void
fsc_cob_bit_set (
	FscT_Cobmng* comng,							/* cob manager							*/
	int seqno									/* chunk num							*/
) {
	int off;
	int bit;
	int line_size;
	unsigned bit_p = 1;

	line_size = sizeof(unsigned) * 8;
	off = seqno / line_size;
	bit = seqno % line_size;

	bit_p = (bit_p << bit);
	comng->rcvcheck[off] = comng->rcvcheck[off] | bit_p;
	return;
}
/*--------------------------------------------------------------------------------------
	Function to unset receive status on cob management file
----------------------------------------------------------------------------------------*/
static int
fsc_cob_bit_unset (
	FscT_Cobmng* comng,							/* cob manager							*/
	int seqno									/* chunk num							*/
) {
	int off;
	int bit;
	int line_size;
	unsigned bit_p = 1;

	line_size = sizeof(unsigned) * 8;
	off = seqno / line_size;
	bit = seqno % line_size;

	bit_p = (bit_p << bit);

	if (comng->rcvcheck[off] & bit_p) {
		comng->rcvcheck[off] = comng->rcvcheck[off] & ~bit_p;
		return (1);
	}

	return (0);
}
/*--------------------------------------------------------------------------------------
	Function to write out the cob management file
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cobmng_put (
	char* dir,									/* cob manager directory				*/
	FscT_Cobmng* comng							/* cob manager							*/
) {
	char omsg[CefC_Csmgr_File_Path_Length] = {0};
	FILE* fp = NULL;
	int i = 0;
	int rst = 0;

	/* Create file name */
	sprintf (omsg, "%s/CobMng", dir);

	/* Open file */
	while (i < FscC_Max_Wait_Count) {
		fp = fopen (omsg, "wb");
		if (fp != NULL) {
			break;
		}
		usleep (FscC_Sleep_Time);
		i++;
	}

	if (fp != NULL) {
		fwrite (comng, sizeof (FscT_Cobmng), 1, fp);
		fclose (fp);
	} else {
		rst = -1;
	}

	return (rst);
}
/*--------------------------------------------------------------------------------------
	Function to read elements group file
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_element_g_get (
	char* dir,									/* element group file directory			*/
	int file_no,								/* file number							*/
	char* cent									/* file Element							*/
) {
	char file_name[CefC_Max_Msg_Size] = {0};
	FILE* fp = NULL;
	int i = 0;
	int rst = 0;

	/* Create file name */
	sprintf (file_name, "%s/%d", dir, file_no);

	/* Open file */
	while (i < FscC_Max_Wait_Count) {
		fp = fopen (file_name, "rb");
		if (fp != NULL) {
			break;
		}
		usleep (FscC_Sleep_Time);
		i++;
	}

	if (fp != NULL) {
		if (fread (cent, sizeof (FscT_File_Element) * FscC_Element_Num, 1, fp) < 1) {
			csmgrd_log_write (CefC_Log_Error, "element group file read error\n");
			rst = -1;
		}
		fclose (fp);
	} else {
		if ((errno != ENOENT) && (errno != ETIMEDOUT)) {
			rst = -1;
			csmgrd_log_write (CefC_Log_Error, "File open erro : %s\n", strerror (errno));
		}
		memset (cent, 0, sizeof (FscT_File_Element) * FscC_Element_Num);
	}

	return (rst);
}
/*--------------------------------------------------------------------------------------
	Function to write elements group file
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_element_g_put (
	char* dir,									/* element group file directory			*/
	int file_no,								/* file number							*/
	char* cent									/* file Element							*/
) {
	char file_name[CefC_Max_Msg_Size] = {0};
	FILE* fp = NULL;
	int i = 0;
	int rst = 0;

	/* Create file name	*/
	sprintf (file_name, "%s/%d", dir, file_no);

	/* Open file	*/
	while (i < FscC_Max_Wait_Count) {
		fp = fopen (file_name, "wb");
		if (fp != NULL) {
			break;
		}
		usleep (FscC_Sleep_Time);
		i++;
	}

	/* Write file	*/
	if (fp != NULL) {
		fwrite (cent, sizeof (FscT_File_Element) * FscC_Element_Num, 1, fp);
		fclose (fp);
	} else {
		rst = -1;
	}

	return (rst);
}
/*--------------------------------------------------------------------------------------
	Function to set content_entry info
----------------------------------------------------------------------------------------*/
static void
fsc_content_entry_put (
	FscT_File_Element* f_elem,					/* file element							*/
	CsmgrdT_Content_Entry* centry				/* content entry						*/
) {
	/* Copy cob info */
	memcpy (&f_elem->msg, centry->msg, CefC_Max_Msg_Size);
	f_elem->msg_len = centry->msg_len;
	f_elem->chnk_num = centry->chnk_num;
	f_elem->pay_len = centry->pay_len;
	return;
}
/*--------------------------------------------------------------------------------------
	Get Csmgrd status
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_stat_get (
	char* stat,									/* String of FS Cache status			*/
	uint16_t* stat_len,							/* String length						*/
	uint8_t cache_f,							/* Cache request flag					*/
	char uris[CefC_Csmgr_Stat_MaxUri][265],		/* Content URI							*/
	CefT_Csmgrd_Stat_Cache* cache,				/* Content information					*/
	uint16_t* cache_len							/* Length of content information		*/
) {
	char CSLok[CefC_Csmgr_File_Path_Length] = {0};
	unsigned char dir[CefC_Csmgr_File_Path_Length] = {0};
	int result = 0; 			/* 0=success 0!=Failure*/
	int lockno = 0; 			/* 0=Failure 0!=success */
	FscT_Csmng csmng = {0};
	FscT_Csmng* cmng = &csmng;
	int rst = 0;
	int i;
	uint64_t nowt;
	char name[CefC_Max_Length];
	uint16_t name_len;
	int idx = 0;

	/* Create lock file name */
	sprintf (CSLok, "%s/%s", hdl->fsc_root_path, FscC_Csmng_Lock_Name);

	/* Lock FileSystemCache */
	rst = fsc_cache_lock (CSLok, &lockno);
	if (rst != 0) {
		csmgrd_log_write (CefC_Log_Error, "Lock error\n");
		return (-1);
	}

	/* Get csmgr management information */
	rst = fsc_csmng_get (cmng, hdl->fsc_csmng_file_name);
	if(rst == -1) {
		result = -1;
		goto StatExit;
	}

	/* Set fsc status */
	*stat_len  = sprintf (stat, "Fscache ID              : %u\n", hdl->fsc_id);
	*stat_len += sprintf (
			stat + *stat_len, "All content num         : %d\n", cmng->all_content_number);

	/* Check cache flag */
	if (cache_f == 0) {
		goto StatExit;
	}

	/* Get my directory */
	fsc_my_dir_get (hdl->fsc_id, cmng, hdl->fsc_root_path, (char*)dir);
	if (dir[0] == 0) {
		csmgrd_log_write (CefC_Log_Error, "fsc_my_dir_get error\n");
		result = -1;
		goto StatExit;
	}

	/* Get content manager */
	rst = fsc_mk_contentmng_get ((char*)dir, contmng);
	if (rst == -1) {
		result = -1;
		csmgrd_log_write (CefC_Log_Error, "fsc_mk_contentmng_get error\n");
		goto StatExit;
	}
	if (contmng->content_number <= 0) {
		result = 0;
		goto StatExit;
	}

	memset (cache, 0, sizeof (CefT_Csmgrd_Stat_Cache) * CefC_Csmgr_Stat_MaxUri);
	*cache_len = 0;
	nowt = cef_client_present_timeus_calc ();

	/* Get content information */
	for (i = 0; i < FscC_Max_Content_Num; i++) {
		/* Check content num */
		if (idx > CefC_Csmgr_Stat_MaxUri) {
			break;
		}
		if (idx == contmng->content_number) {
			break;
		}

		if (contmng->cont_inf[i].cob_num == 0) {
			continue;
		}

		/* Create a URI string from content entry */
		name_len = cef_frame_conversion_name_to_uri (
											(unsigned char*)contmng->cont_inf[i].name,
											contmng->cont_inf[i].name_len,
											name);
		if (name_len > 255) {
			continue;
		}
		name[name_len] = 0;

		/* Set cache status */
		*cache_len += name_len;
		/* Set content name */
		memcpy (uris[idx], name, name_len);
		/* Set content size */
		cache[idx].size = contmng->cont_inf[i].size;
		/* Set access count */
		cache[idx].access_cnt = contmng->cont_inf[i].access_cnt;
		/* Set content freshness */
		if ((contmng->cont_inf[i].expiry != 0) &&
			(nowt > contmng->cont_inf[i].expiry)) {
			/* Content expire */
			cache[idx].freshness_sec = 1;
		} else if (contmng->cont_inf[i].expiry == 0) {
			cache[idx].freshness_sec = 0;
		} else {
			/* Content not expire */
			/* Set expiry */
			cache[idx].freshness_sec = (contmng->cont_inf[i].expiry - nowt) / 1000000;
		}
		/* Set content elapsed time */
		cache[idx].elapsed_time =
		 			(nowt - (contmng->cont_inf[i].settime.tv_sec * 1000000 +
								contmng->cont_inf[i].settime.tv_usec)) / 1000000;
		idx++;
	}
	result = idx;

StatExit:
	/* Unlock FileSystemCache */
	fsc_cache_unlock (CSLok , lockno);

	return (result);
}
#ifdef CefC_Contrace
/*--------------------------------------------------------------------------------------
	Create the cache information
----------------------------------------------------------------------------------------*/
static int							/* number of returned caches						*/
fsc_cache_info_get (
	int* total_len, 									/* length of returned status	*/
	char uris[CefstatC_MaxUri][265],					/* record created cache name	*/
	CefstatT_Cache stat[CefstatC_MaxUri]				/* record created cache status	*/
) {
	char name[CefC_Max_Length];
	uint16_t name_len;
	int i = 0;
	int idx = 0;
	uint64_t nowt;

	FscT_Csmng csmng = {0};
	FscT_Csmng* cmng = &csmng;
	char CSLok[CefC_Csmgr_File_Path_Length] = {0};
	unsigned char dir[CefC_Csmgr_File_Path_Length] = {0};
	int rst = 0;
	int lockno = 0; 			/* 0=Failure 0!=success */

#ifdef CefC_Debug
	csmgrd_dbg_write (CefC_Dbg_Fine, "FIN: fsc_cache_info_get\n");
#endif // CefC_Debug

	sprintf (CSLok, "%s/%s", hdl->fsc_root_path, FscC_Csmng_Lock_Name);
	/* Lock FileSystemCache */
	rst = fsc_cache_lock (CSLok, &lockno);
	if (rst != 0) {
		csmgrd_log_write (CefC_Log_Error, "Lock error\n");
		return (0);
	}

	/* Get csmgr management information */
	rst = fsc_csmng_get (cmng, hdl->fsc_csmng_file_name);
	if(rst == -1) {
		goto CacheInfoExit;
	}

	/* Get my directory */
	fsc_my_dir_get (hdl->fsc_id, cmng, hdl->fsc_root_path, (char*)dir);
	if (dir[0] == 0) {
		goto CacheInfoExit;
	}

	/* Get content manager */
	rst = fsc_mk_contentmng_get ((char*)dir, contmng);
	if ((rst == -1) || (contmng->content_number <= 0)) {
		goto CacheInfoExit;
	}

	memset (stat, 0, sizeof (CefstatT_Cache) * CefstatC_MaxUri);
	*total_len = 0;
	nowt = cef_client_present_timeus_calc ();

	/* Get content information */
	for (i = 0; i < FscC_Max_Content_Num; i++) {
		/* Check content num */
		if (idx > CefstatC_MaxUri) {
			break;
		}
		if (idx == contmng->content_number) {
			break;
		}

		if (contmng->cont_inf[i].cob_num == 0) {
			continue;
		}

		/* Create a URI string from content entry */
		name_len = cef_frame_conversion_name_to_uri (
											(unsigned char*)contmng->cont_inf[i].name,
											contmng->cont_inf[i].name_len,
											name);
		if (name_len > 255) {
			continue;
		}
		name[name_len] = 0;

		/* Set cache status */
		*total_len += name_len;
		/* Set content name */
		memcpy (uris[idx], name, name_len);
		/* Set content size */
		stat[idx].size = contmng->cont_inf[i].size;
		/* Set content num */
		stat[idx].cob_num = contmng->cont_inf[i].cob_num;
		/* Set access count */
		stat[idx].access_cnt = contmng->cont_inf[i].access_cnt;
		/* Set content freshness */
		if ((contmng->cont_inf[i].expiry != 0) &&
			(nowt > contmng->cont_inf[i].expiry)) {
			/* Content expire */
			stat[idx].freshness_sec = 1;
		} else if (contmng->cont_inf[i].expiry == 0) {
			stat[idx].freshness_sec = 0;
		} else {
			/* Content not expire */
			/* Set expiry */
			stat[idx].freshness_sec = (contmng->cont_inf[i].expiry - nowt) / 1000000;
		}
		/* Set content elapsed time */
		stat[idx].elapsed_time =
		 			(nowt - (contmng->cont_inf[i].settime.tv_sec * 1000000 +
								contmng->cont_inf[i].settime.tv_usec)) / 1000000;
		/* Set upstream address */
		stat[idx].upaddr = contmng->cont_inf[i].node;

		/* Set sequence num */
		stat[idx].min_seq_num = contmng->cont_inf[i].chunk_min;
		stat[idx].max_seq_num = contmng->cont_inf[i].chunk_max;

		idx++;
	}
CacheInfoExit:
	/* Unlock FileSystemCache */
	fsc_cache_unlock (CSLok , lockno);

	return (idx);
}
#endif // CefC_Contrace
/*--------------------------------------------------------------------------------------
	Function to increment access count
----------------------------------------------------------------------------------------*/
static void
fsc_cs_ac_cnt_inc (
	unsigned char* key,							/* content name							*/
	uint16_t key_size,							/* content name Length					*/
	uint32_t seq_num							/* sequence number						*/
) {
	unsigned char dir[CefC_Csmgr_File_Path_Length] = {0};
	char CSLok[CefC_Csmgr_File_Path_Length] = {0};
	FscT_Csmng csmng = {0};
	FscT_Csmng* cmng = &csmng;
	int no;
	int rst = 0;
	int lockno = 0; 			/* 0=Failure 0!=success */

	if (hdl->algo_apis.hit) {
		(*(hdl->algo_apis.hit))(key, key_size);
	}

	if (seq_num != 0) {
		return;
	}
	/* Recreate key size (sequence num is not included) */
	key_size = key_size - (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);

	/* Create file name */
	sprintf (CSLok, "%s/%s", hdl->fsc_root_path, FscC_Csmng_Lock_Name);
	/* Lock FileSystemCache */
	rst = fsc_cache_lock (CSLok, &lockno);
	if (rst != 0) {
		/* Lock error */
		csmgrd_log_write (CefC_Log_Error, "Lock error\n");
		return;
	}

	/* Get csmng status */
	rst = fsc_csmng_get (cmng, hdl->fsc_csmng_file_name);
	if (rst == -1) {
		/* Get status error */
		goto IncExit;
	}

	/* Get directory */
	fsc_my_dir_get (hdl->fsc_id, cmng, (char*)hdl->fsc_root_path, (char*)dir);
	if (dir[0] == 0) {
		/* Get directory error */
		goto IncExit;
	}
	/* Get content manager */
	rst = fsc_contentmng_get ((char*)dir, contmng);
	if (rst < 0) {
		/* Get content manager error */
		goto IncExit;
	}
	/* Search content name */
	no = fsc_content_no_get (contmng, key, key_size);
	if (no > FscC_Max_Content_Num) {
		goto IncExit;
	}

	/* Check expire */
	if ((contmng->cont_inf[no - 1].expiry != 0) &&
		(contmng->cont_inf[no - 1].expiry < cef_client_present_timeus_get())) {
		/* Content expire */
		goto IncExit;
	}

	/* Access count increment */
	contmng->cont_inf[no - 1].access_cnt += 1;
	fsc_contentmng_put ((char*)dir, contmng);

IncExit:
	/* Unlock FileSystemCache */
	fsc_cache_unlock (CSLok, lockno);

	return;
}
/*--------------------------------------------------------------------------------------
	Create new content entry
----------------------------------------------------------------------------------------*/
static FscT_Mem_Cache_Content_Entry*	/* The return value is null if an error occurs	*/
fsc_memcache_content_entry_create (
	CefT_Csmgrd_Content_Info* centry			/* content information					*/
) {
	int i;
	FscT_Mem_Cache_Content_Entry* content_entry = NULL;

	/* Check content num */
	if ((hdl->mem_cache_table_num + 1) == FscC_MemCache_Max_Content_Num) {
		/* Content num is too many */
		return (NULL);
	}
	content_entry = (FscT_Mem_Cache_Content_Entry*) malloc (sizeof (FscT_Mem_Cache_Content_Entry));
	/* Check result */
	if (content_entry == NULL) {
		/* Get cob, but calloc error */
		return (NULL);
	}
	/* Initialize content entry information */
	memcpy (content_entry->name, centry->name, centry->name_len);
	content_entry->name_len = centry->name_len;
	content_entry->cache_num = 0;
	for (i = 0; i < FscC_MemCache_Max_Cob_Num; i++) {
		content_entry->entry[i] = NULL;
	}
	return (content_entry);
}
/*--------------------------------------------------------------------------------------
	Create new cob entry
----------------------------------------------------------------------------------------*/
static CefT_Csmgrd_Content_Info*	/* The return value is null if an error occurs		*/
fsc_memcache_cob_entry_create (
	CefT_Csmgrd_Content_Info* centry			/* content information					*/
) {
	CefT_Csmgrd_Content_Info* cob_entry = NULL;

	/* Create new cob entry */
	if ((hdl->mem_cache_num + 1) == FscC_MemCache_Max_Cob_Num) {
		/* Remove old entry */
		if (fsc_memcache_old_cob_block_remove () < 0) {
#ifdef CefC_Debug
			csmgrd_dbg_write (
				CefC_Dbg_Fine, "%s(%d) : Remove old block error\n", __func__, __LINE__);
#endif // CefC_Debug
			return (NULL);
		}
	}
	cob_entry = (CefT_Csmgrd_Content_Info*)malloc (sizeof (CefT_Csmgrd_Content_Info));
	/* Check result */
	if (cob_entry == NULL) {
		return (NULL);
	}
	memcpy (cob_entry, centry, sizeof (CefT_Csmgrd_Content_Info));
	return (cob_entry);
}
/*--------------------------------------------------------------------------------------
	Search cob in memory cache
----------------------------------------------------------------------------------------*/
static int							/* If found cache , return 0						*/
fsc_memcache_lookup (
	unsigned char* key,							/* content name							*/
	uint16_t key_size,							/* content name Length					*/
	uint32_t seqno,								/* chunk num							*/
	int sock									/* received socket						*/
) {
	FscT_Mem_Cache_Content_Entry* content_entry;
	uint32_t index;
	CefT_Csmgrd_Content_Info* send_cob_que[FscC_MemCache_Max_Block_Num];
	unsigned char trg_key[CsmgrdC_Key_Max];
	int trg_key_len;
	int read_num = 0;
	int i;

	/* Search content entry */
	content_entry = (FscT_Mem_Cache_Content_Entry*)cef_hash_tbl_item_get (
													hdl->mem_cache_table, key, key_size);
	if (content_entry == NULL) {
		return (-1);
	}

	index = seqno % FscC_MemCache_Max_Cob_Num;
	/* Check cob entry */
	if (content_entry->entry[index] == NULL) {
		return (-1);
	}

	/* Check sequence num*/
	if (content_entry->entry[index]->chnk_num != seqno) {
		return (-1);
	}

	if (hdl->algo_apis.hit) {
		trg_key_len =
			csmgrd_name_chunknum_concatenate (key, key_size, seqno, trg_key);
		(*(hdl->algo_apis.hit))(trg_key, trg_key_len);
	}
	csmgrd_plugin_cob_msg_send (
		sock, content_entry->entry[index]->msg, content_entry->entry[index]->msg_len);
	
	/* Check child_pid_list */
	if (fsc_child_pid_list_check (key, key_size, seqno, sock) < 0) {
		return (CefC_Csmgr_Cob_Exist);
	}

	/* Send cob */
	pid_t child_pid = fork ();
	/* Check pid */
	if (child_pid == -1) {
		csmgrd_log_write (
			CefC_Log_Error, "fork (%d : %s)\n", errno, strerror (errno));
	}
	/* Check child pid */
	if (child_pid == 0) {
#ifdef CefC_Debug
		csmgrd_dbg_write (CefC_Dbg_Fine, "**CEF-CHILD** Enter\n");
#endif // CefC_Debug.
		if (seqno == 0) {
			/* Increment access_cnt */
			fsc_cs_ac_cnt_inc (key, key_size, seqno);
		}
		/* Create send que */
		for (i = 1; i < FscC_MemCache_Max_Block_Num; i++) {
			index = (seqno + i) % FscC_MemCache_Max_Cob_Num;
			/* Check cob entry */
			if (content_entry->entry[index] == NULL) {
				break;
			}
			/* Check sequence num */
			if (content_entry->entry[index]->chnk_num != (seqno + i)) {
				break;
			}
			send_cob_que[read_num] = content_entry->entry[index];
			read_num++;
		}
		/* Send ContentObject to cefnetd */
		fsc_cache_cob_send (send_cob_que, read_num, sock);
#ifdef CefC_Debug
		csmgrd_dbg_write (CefC_Dbg_Fine, "**CEF-CHILD** Exit\n");
#endif // CefC_Debug
		exit (0);
	}

	return (CefC_Csmgr_Cob_Exist);
}
/*--------------------------------------------------------------------------------------
	Remove expired content
----------------------------------------------------------------------------------------*/
static void
fsc_memcache_expire_check (
	void
) {
	FscT_Mem_Cache_Cob_Queue* cob_que;
	FscT_Mem_Cache_Content_Entry* content_entry;
	uint64_t nowt;
	int i;
	uint32_t block_num;
	uint32_t array_index;

	/* Check mem cache num */
	if (hdl->mem_cache_num == 0) {
		/* Memcache is empty */
		return;
	}

	/* Get now */
	nowt = cef_client_present_timeus_get ();

	while (hdl->mem_cache_num != 0) {
		/* Check top queue */
		cob_que = (FscT_Mem_Cache_Cob_Queue*)cef_rngque_read (hdl->mem_cache_que);
		if (cob_que == NULL) {
			/* Read queue error */
#ifdef CefC_Debug
			csmgrd_dbg_write (
				CefC_Dbg_Fine, "%s(%d) : cef_rngque_read error\n", __func__, __LINE__);
#endif // CefC_Debug
			break;
		}
		/* Check expire */
		if (cob_que->expiry > nowt) {
			/* Not expired yet */
			break;
		}
		/* Get content entry */
		content_entry = (FscT_Mem_Cache_Content_Entry*)cef_hash_tbl_item_get_from_index (
																	hdl->mem_cache_table,
																	cob_que->index);
		if (content_entry == NULL) {
			/* Search content entry error */
#ifdef CefC_Debug
			csmgrd_dbg_write (CefC_Dbg_Fine,
				"%s(%d) : search content entry error\n", __func__, __LINE__);
#endif // CefC_Debug
			break;
		}

		/* Remove cob_que and cob_entry */
		block_num = cob_que->block_num;
		for (i = 0; i < block_num; i++) {
			/* Pop queue */
			cob_que = (FscT_Mem_Cache_Cob_Queue*)cef_rngque_pop (hdl->mem_cache_que);
			if (cob_que == NULL) {
				/* Read queue error */
#ifdef CefC_Debug
				csmgrd_dbg_write (
					CefC_Dbg_Fine, "%s(%d) : cef_rngque_pop error\n", __func__, __LINE__);
#endif // CefC_Debug
				break;
			}

			/* Remove entry */
			array_index = cob_que->seq_num % FscC_MemCache_Max_Cob_Num;
			if ((content_entry->entry[array_index] != NULL) &&
				(content_entry->entry[array_index]->chnk_num == cob_que->seq_num)) {
				free (content_entry->entry[array_index]);
				content_entry->entry[array_index] = NULL;
				content_entry->cache_num--;
				if (content_entry->cache_num == 0) {
					/* Remove content entry */
					cef_hash_tbl_item_remove_from_index (
											hdl->mem_cache_table, content_entry->index);
					free (content_entry);
#ifdef CefC_Debug
					csmgrd_dbg_write (CefC_Dbg_Fine,
						"%s(%d) : delete content entry\n", __func__, __LINE__);
#endif // CefC_Debug
					hdl->mem_cache_table_num--;
				}
			}
			free (cob_que);
			hdl->mem_cache_num--;
		}
	}

	return;
}
/*--------------------------------------------------------------------------------------
	Remove old cob block
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_memcache_old_cob_block_remove (
	void
) {
	FscT_Mem_Cache_Cob_Queue* cob_que;
	FscT_Mem_Cache_Content_Entry* content_entry;
	int i;
	uint32_t block_num;
	uint32_t array_index;

	/* Check top queue */
	cob_que = (FscT_Mem_Cache_Cob_Queue*)cef_rngque_read (hdl->mem_cache_que);
	if (cob_que == NULL) {
		/* Read queue error */
		csmgrd_log_write (CefC_Log_Error,
			"%s(%d) : cef_rngque_read error\n", __func__, __LINE__);
		return (-1);
	}

	/* Get content entry */
	content_entry = (FscT_Mem_Cache_Content_Entry*)cef_hash_tbl_item_get_from_index (
																	hdl->mem_cache_table,
																	cob_que->index);
	if (content_entry == NULL) {
		/* Search content entry error */
		csmgrd_log_write (
			CefC_Log_Error, "%s(%d) : search content entry error\n", __func__, __LINE__);
		return (-1);
	}

	/* Remove cob_que and cob_entry */
	block_num = cob_que->block_num;
	for (i = 0; i < block_num; i++) {
		/* Pop queue */
		cob_que = (FscT_Mem_Cache_Cob_Queue*)cef_rngque_pop (hdl->mem_cache_que);
		if (cob_que == NULL) {
			/* Read queue error */
			csmgrd_log_write (
				CefC_Log_Error, "%s(%d) : cef_rngque_pop error\n", __func__, __LINE__);
			return (-1);
		}

		/* Remove entry */
		array_index = cob_que->seq_num % FscC_MemCache_Max_Cob_Num;
		if (content_entry->entry[array_index] != NULL) {
			free (content_entry->entry[array_index]);
			content_entry->entry[array_index] = NULL;
			content_entry->cache_num--;
			if (content_entry->cache_num == 0) {
				/* Remove content entry */
				cef_hash_tbl_item_remove_from_index (
										hdl->mem_cache_table, content_entry->index);
				free (content_entry);
#ifdef CefC_Debug
				csmgrd_dbg_write (CefC_Dbg_Finest,
					"%s(%d) : delete content entry\n", __func__, __LINE__);
#endif // CefC_Debug
				hdl->mem_cache_table_num--;
			}
		}
		free (cob_que);
		hdl->mem_cache_num--;
	}

	return (0);
}
#if defined (CefC_Conping) || defined (CefC_Contrace)
/*--------------------------------------------------------------------------------------
	Check presence of cache
----------------------------------------------------------------------------------------*/
static int					/* It returns the negative value or NotExist if not found.	*/
fsc_content_exist_check (
	unsigned char* name,						/* content name							*/
	uint16_t name_len							/* content name length					*/
) {
	FscT_Csmng csmng = {0};
	FscT_Csmng* cmng = &csmng;
	char CSLok[CefC_Csmgr_File_Path_Length] = {0};
	unsigned char dir[CefC_Csmgr_File_Path_Length] = {0};
	int lockno = 0; 			/* 0=Failure 0!=success */
	int rst;
	int result = 0;
	int no;

	sprintf (CSLok, "%s/%s", hdl->fsc_root_path, FscC_Csmng_Lock_Name);
	/* Lock FileSystemCache */
	rst = fsc_cache_lock (CSLok, &lockno);
	if (rst != 0) {
		csmgrd_log_write (CefC_Log_Error, "lock error\n");
		return (-1);
	}

	/* Get csmgr management information */
	rst = fsc_csmng_get (cmng, hdl->fsc_csmng_file_name);
	if(rst == -1) {
		result = -1;
		goto CheckExistExit;
	}
	/* Get my directory */
	fsc_my_dir_get (hdl->fsc_id, cmng, hdl->fsc_root_path, (char*)dir);
	if (dir[0] == 0) {
		result = -1;
		goto CheckExistExit;
	}
	/* Get content manager */
	rst = fsc_contentmng_get ((char*)dir, contmng);
	if (rst < 0) {
		/* Get content manager error */
		result = -1;
		goto CheckExistExit;
	}
	/* Search content name */
	no = fsc_content_no_prefix_search (contmng, name, name_len);
	if (no > FscC_Max_Content_Num) {
		result = CefC_Csmgr_Cob_NotExist;
		goto CheckExistExit;
	}

	/* Check expire */
	if ((contmng->cont_inf[no - 1].expiry != 0) &&
		(contmng->cont_inf[no - 1].expiry < cef_client_present_timeus_calc ())) {
		/* Content expire */
		result = CefC_Csmgr_Cob_NotExist;
	} else {
		result = CefC_Csmgr_Cob_Exist;
	}

CheckExistExit:
	/* Unlock FileSystemCache */
	fsc_cache_unlock (CSLok , lockno);

	return (result);
}
/*--------------------------------------------------------------------------------------
	Function to get content entry no
----------------------------------------------------------------------------------------*/
static int							/* The return value is content entry num			*/
fsc_content_no_prefix_search (
	FscT_Contentmng* contmng,					/* content manager						*/
	unsigned char* key,							/* content name							*/
	int key_size								/* content name length					*/
) {
	int i;
	/* Search content entry */
	for (i = 0; i < FscC_Max_Content_Num; i++) {
		/* Check content name length */
		if (contmng->cont_inf[i].name_len >= key_size) {
			if (memcmp (contmng->cont_inf[i].name, key, key_size) == 0) {
				/* Found */
				break;
			}
		}
	}
	return(i + 1);
}
#endif // (CefC_Conping || CefC_Contrace)
/*--------------------------------------------------------------------------------------
	Function to read a all ContentObject in content from FileSystemCache
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
fsc_cache_content_get (
	unsigned char* key,							/* content name							*/
	uint16_t key_size,							/* content name Length					*/
	uint32_t seqno,								/* chunk num							*/
	int sock									/* received socket						*/
) {
	unsigned char dir[CefC_Csmgr_File_Path_Length] = {0};
	char CSLok[CefC_Csmgr_File_Path_Length] = {0};
	FscT_Csmng csmng = {0};
	FscT_Csmng* cmng = &csmng;
	int no;
	int rst = 0;
	int result = 0;
	int lockno = 0; 			/* 0=Failure 0!=success */

	/* Create file name */
	sprintf (CSLok, "%s/%s", hdl->fsc_root_path, FscC_Csmng_Lock_Name);

	/* Lock FileSystemCache */
	rst = fsc_cache_lock (CSLok, &lockno);
	if (rst != 0) {
		/* Lock error */
		csmgrd_log_write (CefC_Log_Error, "Lock error\n");
		return (-1);
	}

	/* Get csmng status */
	rst = fsc_csmng_get (cmng, hdl->fsc_csmng_file_name);
	if (rst == -1) {
		/* Get status error */
		result = -1;
		goto ConGetExit;
	}
	/* Get directory */
	fsc_my_dir_get (hdl->fsc_id, cmng, (char*)hdl->fsc_root_path, (char*)dir);
	if (dir[0] == 0) {
		/* Get directory error */
		result = -1;
		goto ConGetExit;
	}
	/* Get content manager */
	rst = fsc_contentmng_get ((char*)dir, contmng);
	if (rst < 0) {
		/* Get content manager error */
		result = -1;
		goto ConGetExit;
	}
	/* Search content name */
	no = fsc_content_no_get (contmng, key, key_size);
	if (no > FscC_Max_Content_Num) {
		result = -1;
		goto ConGetExit;
	}

	/* Check expire */
	if ((contmng->cont_inf[no - 1].expiry != 0) &&
		(contmng->cont_inf[no - 1].expiry < cef_client_present_timeus_calc ())) {
		/* Content expire */
		result = -1;
		goto ConGetExit;
	}

	/* Check chunk num */
	if (seqno == 0) {
		/* Access count increment */
		contmng->cont_inf[no - 1].access_cnt += 1;
		fsc_contentmng_put ((char*)dir, contmng);
	}

	/* Set result */
	result = CefC_Csmgr_Cob_Exist;

ConGetExit:
	/* Unlock FileSystemCache */
	fsc_cache_unlock (CSLok, lockno);

	if (result < 0) {
		return (result);
	}

	/* FORK */
	pid_t child_pid = fork ();
	/* Check pid */
	if (child_pid == -1) {
		csmgrd_log_write (
			CefC_Log_Error, "fork (%d : %s)\n", errno, strerror (errno));
		return (-1);
	}
	/* Check child pid */
	if (child_pid == 0) {
#ifdef CefC_Debug
		csmgrd_dbg_write (CefC_Dbg_Fine, "**CEF-CHILD** Enter\n");
		csmgrd_dbg_write (CefC_Dbg_Fine, "get all cob in content\n");
#endif // CefC_Debug
		/* Send ContentObject to csmgrd */
		fsc_cache_content_send (key, key_size, seqno, sock);
#ifdef CefC_Debug
		csmgrd_dbg_write (CefC_Dbg_Fine, "**CEF-CHILD** Exit\n");
#endif // CefC_Debug
		exit (0);
	}

	return (result);
}
/*--------------------------------------------------------------------------------------
	Function to read a all ContentObject in content from FileSystemCache
----------------------------------------------------------------------------------------*/
static void
fsc_cache_content_send (
	unsigned char* key,							/* content name							*/
	uint16_t key_size,							/* content name Length					*/
	uint32_t seqno,								/* chunk num							*/
	int sock									/* received socket						*/
) {
	int i;
	int ele_no = -1;
	unsigned char dir[CefC_Csmgr_File_Path_Length] = {0};
	unsigned char cdir[CefC_Csmgr_File_Path_Length] = {0};
	char CSLok[CefC_Csmgr_File_Path_Length] = {0};
	FscT_Csmng csmng = {0};
	FscT_Csmng* cmng = &csmng;
	FscT_Cobmng cob_mng = {0};
	FscT_Cobmng *comng = &cob_mng;
	int no;
	int rst = 0;
	int result = CefC_Csmgr_Cob_Exist;
	int lockno = 0; 			/* 0=Failure 0!=success */
	int read_num = 0;
	CefT_Csmgrd_Content_Info cob_entry[FscC_Bulk_Get_Same_Time];
	uint32_t sum_len = 0;
	uint64_t next;

	/* Create file name */
	sprintf (CSLok, "%s/%s", hdl->fsc_root_path, FscC_Csmng_Lock_Name);

	while (1) {
		/* Lock FileSystemCache */
		rst = fsc_cache_lock (CSLok, &lockno);
		if (rst != 0) {
			/* Lock error */
			csmgrd_log_write (CefC_Log_Error, "lock error\n");
			return;
		}

		/* Get csmng status */
		rst = fsc_csmng_get (cmng, hdl->fsc_csmng_file_name);
		if (rst == -1) {
			/* Get status error */
			result = -1;
			goto ConSendExit;
		}
		/* Get directory */
		fsc_my_dir_get (hdl->fsc_id, cmng, (char*)hdl->fsc_root_path, (char*)dir);
		if (dir[0] == 0) {
			/* Get directory error */
			result = -1;
			goto ConSendExit;
		}
		/* Get content manager */
		rst = fsc_contentmng_get ((char*)dir, contmng);
		if (rst < 0) {
			/* Get content manager error */
			result = -1;
			goto ConSendExit;
		}
		/* Search content name */
		no = fsc_content_no_get (contmng, key, key_size);
		if (no > FscC_Max_Content_Num) {
			result = -1;
			goto ConSendExit;
		}

		/* Check expire */
		if ((contmng->cont_inf[no - 1].expiry != 0) &&
			(contmng->cont_inf[no - 1].expiry < cef_client_present_timeus_get ())) {
			/* Content expire */
			result = -1;
			goto ConSendExit;
		}

		/* Get content directory */
		fsc_cont_dir_get ((char*)dir, no, (char*)cdir);
		/* Get cob manager */
		rst = fsc_cobmng_get ((char*)cdir, comng);
		if (rst == -1) {
			/* Error */
			result = -1;
			goto ConSendExit;
		}

		/* Get cob */
		for (i = 0; i < FscC_Bulk_Get_Same_Time; i++) {
			/* Check exist */
			rst = fsc_cob_bit_check (comng, seqno + i);
			if (rst == 0) {
				/* Not exist */
				if (comng->last_cob_number < (seqno + i)) {
					/* File end */
					result = 1;
					goto ConSendExit;
				}
				continue;
			}
			if (ele_no != (seqno + i) / FscC_Element_Num) {
				ele_no = (seqno + i) / FscC_Element_Num;
				rst = fsc_element_g_read ((char*)cdir, ele_no, (char *)&file_area[0]);
				if (rst == -1) {
					result = -1;
					goto ConSendExit;
				}
			}
			/* Get entry */
			fsc_content_entry_get (
					(FscT_File_Element*)&file_area[(seqno + i) % FscC_Element_Num],
					&cob_entry[read_num]);
			read_num++;
		}

ConSendExit:
		/* Unlock FileSystemCache */
		fsc_cache_unlock (CSLok, lockno);
		/* Check result */
		if (result < 0) {
			break;
		}

		/* Send content */
		for (i = 0; i < read_num; i++) {
			if (csmgrd_plugin_cob_msg_send (
					sock, cob_entry[i].msg, cob_entry[i].msg_len) < 0) {
				/* Send error */
#ifdef CefC_Debug
				csmgrd_dbg_write (CefC_Dbg_Fine, "content send error\n");
#endif // CefC_Debug
				break;
			}
			sum_len += cob_entry[i].msg_len;
			/* Rate control */
			if (i % 3 == 0) {
				next = sum_len * 8 / FscC_Bulk_Get_Send_Rate;
				usleep (next);
				sum_len = 0;
			}
		}

		/* Check result */
		if ((result > 0) || (i != read_num)) {
			/* Content send end */
			break;
		}
		/* Reset variable */
		ele_no   = -1;
		read_num = 0;
		lockno   = 0;
		seqno   += FscC_Bulk_Get_Same_Time;
	}

	return;
}
/*--------------------------------------------------------------------------------------
	Send cob to cefnetd
----------------------------------------------------------------------------------------*/
static void
fsc_cache_cob_send (
	CefT_Csmgrd_Content_Info* cob_que[],
	int que_num,
	int sock
) {
	int i;
	uint64_t sum_len = 0;
	uint64_t next;
	for (i = 0; i < que_num; i++) {
		if (csmgrd_plugin_cob_msg_send (sock, cob_que[i]->msg, cob_que[i]->msg_len) < 0) {
			/* Send error */
#ifdef CefC_Debug
			csmgrd_dbg_write (CefC_Dbg_Fine, "Cob send error\n");
#endif // CefC_Debug
			break;
		}
		sum_len += cob_que[i]->msg_len;
		/* Check interval */
		if (i % 3 == 0) {
			next = sum_len * 8 / FscC_Bulk_Get_Send_Rate;
			usleep (next);
			sum_len = 0;
		}
	}
	return;
}
/*--------------------------------------------------------------------------------------
	Search free element
----------------------------------------------------------------------------------------*/
static int
fsc_free_pid_index_search (
	void
) {
	int i;
	for (i = 0; i < FscC_Max_Child_Num; i++) {
		if (child_pid_list[i].child_pid == 0) {
			break;
		}
	}
	if (i == FscC_Max_Child_Num) {
		/* Full of list */
		return (-1);
	}
	return (i);
}
/*--------------------------------------------------------------------------------------
	Check child pid list
----------------------------------------------------------------------------------------*/
static int
fsc_child_pid_list_check (
	unsigned char* key,							/* content name							*/
	uint16_t key_len,							/* content name Length					*/
	uint32_t seqno,								/* chunk num							*/
	int sock									/* received socket						*/
) {
	int i;
	for (i = 0; i < FscC_Max_Child_Num; i++) {
		if ((child_pid_list[i].child_pid != 0) &&
			(child_pid_list[i].sock == sock) &&
			(child_pid_list[i].key_len == key_len) &&
			(memcmp (key, child_pid_list[i].key, key_len) == 0)) {
			/* Check sequence num */
			if ((seqno >= child_pid_list[i].seq_num) &&
				(seqno < child_pid_list[i].seq_num + FscC_MemCache_Max_Block_Num)) {
				/* Send cob process is already running */
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
	for (i = 0; i < FscC_Max_Child_Num; i++) {
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
			for (i = 0; i < FscC_Max_Child_Num; i++) {
				if (child_pid == child_pid_list[i].child_pid) {
					child_pid_list[i].child_pid = 0;
				}
			}
		}
	} while (child_pid > 0);
}

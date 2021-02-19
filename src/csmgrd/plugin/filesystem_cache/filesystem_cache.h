/*
 * Copyright (c) 2016-2020, National Institute of Information and Communications
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
 * filesystem_cache.h
 */
#ifndef __CSMGRD_FILESYSTEM_CACHE_HEADER__
#define __CSMGRD_FILESYSTEM_CACHE_HEADER__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <netinet/in.h>
#include <stdint.h>

#include <cefore/cef_define.h>
#include <cefore/cef_csmgr.h>
#include <cefore/cef_rngque.h>
#include <csmgrd/csmgrd_plugin.h>



/****************************************************************************************
 Macros
 ****************************************************************************************/

#define FscC_Page_Cob_Num				4096

/*------------------------------------------------------------------*/
/* Macros for file													*/
/*------------------------------------------------------------------*/
#define FscC_Sleep_Time					1000			/* Sleep time					*/
#define FscC_Sleep_Count				2000			/* Sleep count					*/
#define FscC_Max_Wait_Count				2				/* Max wait count				*/
#define FscC_Csmng_File_Name			"CSMng"			/* Csmng File Name				*/
#define FscC_Csmng_Lock_Name			"lock"			/* Csmng Lock File Name			*/
#define FscC_Rcvcheck_Size				25600			/* Receive Check Bit size		*/
#define FscC_Lock_Retry					1				/* Lock Retry Num				*/
#define FscC_No_Area					30				/* No area						*/
#define FscC_Del_Rootdir				0				/* Delete root directory		*/
#define FscC_Not_Del_Rootdir			1				/* Not delete root directory	*/

/*------------------------------------------------------------------*/
/* Macros for FileSystemCache status								*/
/*------------------------------------------------------------------*/
#define FscC_Max_Common_Cs_Num			24				/* Max Cs num					*/
#define FscC_Max_Node_Inf_Num			1024			/* Max NodeInformation Num		*/
#define FscC_Max_Content_Num			1024			/* Max Content Num				*/
#define FscC_Element_Num				1024			/* Element Num					*/
#define FscC_Excache_Node_Type_Max		24				/* Mode Individual				*/

/*------------------------------------------------------------------*/
/* Macros for cache queue status									*/
/*------------------------------------------------------------------*/
#define FscC_ItemPut_Que_Size			3072			/* PutQue Size					*/
#define FscC_ItemPut_Time				1000000			/* Time that put item from que	*/

/*------------------------------------------------------------------*/
/* Macros for memory cache											*/
/*------------------------------------------------------------------*/
#define FscC_MemCache_Max_Cob_Num		10000			/* Max Cob Num					*/
#define FscC_MemCache_Max_Block_Num		100				/* Block num max				*/
#define FscC_MemCache_Check_Expire		5				/* Time of check expire			*/
#define FscC_MemCache_Max_Content_Num	100				/* Content num					*/

/*------------------------------------------------------------------*/
/* Macros for Symbolic Interest										*/
/*------------------------------------------------------------------*/
#define FscC_Bulk_Get_Same_Time			255			/* Num of get content at same time.	*/
#define FscC_Bulk_Get_Send_Rate			16			/* Rate of send						*/

#define FscC_Max_Child_Num				32			/* Num of child (fork process)		*/
#define FscC_Map_Reset_Time				50000		/* Reset Bitmap (50msec)			*/


/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/

typedef struct {

	/********** FileSystem Cache Information ***********/
	char			fsc_root_path[CefC_Csmgr_File_Path_Length];
												/* FileSystemCache root dir				*/
	
	/********** cache algorithm library **********/
	char 			algo_name[1024];			/* algorithm to replece cache entries	*/
	int 			cache_cob_max;

} FscT_Config_Param;

typedef struct {

	/********** Common content store ***********/
	int				ccs_number;					/* Common cs num						*/
	int				node_type;					/* Node type							*/
	int				nodeid;						/* Node ID								*/

} FscT_Ccs;

typedef struct {

	/********** use check flag ***********/
	int				use_flag;					/* Use flag								*/

} FscT_Use_Check;

typedef struct {

	/********** Content Store Manage ***********/
	int				all_init_number;			/* All init num							*/
	int				all_content_number;			/* All content num						*/
	FscT_Ccs		common_cs[FscC_Max_Common_Cs_Num];
												/* Common content store information		*/
	FscT_Use_Check	node_inf[FscC_Max_Node_Inf_Num];
												/* Use flag 							*/

} FscT_Csmng;

typedef struct {

	/********** Content Entry Separate Area ***********/
	char				name[CefC_Max_Msg_Size];	/* Content name						*/
	uint16_t			name_len;				/* Length of name 						*/
	struct timeval		settime;				/* Time that received message			*/
	uint64_t			cache_time;				/* Cache time							*/
	uint64_t			expiry;					/* Expiry								*/
	uint64_t			access_cnt;				/* Access count							*/
	uint64_t			cob_num;				/* Content Object num					*/
	uint64_t			size;					/* Content size							*/
	struct in_addr		node;					/* Node address							*/
	uint32_t			chunk_max;				/* Max Chunk Number						*/
	uint32_t			chunk_min;				/* Min Chunk Number						*/

} FscT_Separate_Area;

typedef struct {

	/********** Content Manager ***********/
	int						content_number;			/* Content num						*/
	FscT_Separate_Area		cont_inf[FscC_Max_Content_Num];
													/* Content Entry Separate Area		*/

} FscT_Contentmng;

typedef struct {

	/********** Cob Manager ***********/
	int cob_number;								/* Cob num								*/
	int last_cob_number;						/* Last cob chunk num					*/
	unsigned rcvcheck[FscC_Rcvcheck_Size];		/* Check cob area						*/

} FscT_Cobmng;

typedef struct {

	/********** File Element ***********/
	unsigned char	msg[CefC_Max_Msg_Size];		/* Message								*/
	uint16_t		msg_len;					/* Message length						*/
	uint32_t		chnk_num;					/* Chunk num							*/
	uint16_t		pay_len;					/* Payload length						*/

} FscT_File_Element;

typedef struct {

	/********** Memory Cache ***********/
	int			index;							/* content entry index					*/
	uint32_t	block_num;						/* num of this block					*/
	uint32_t	seq_num;						/* cob sequence num						*/
	uint64_t	expiry;							/* expiration date						*/

} FscT_Mem_Cache_Cob_Queue;

typedef struct {

	/********** Memory Cache ***********/
	char		name[CefC_Max_Msg_Size];		/* Content name							*/
	uint16_t	name_len;						/* Content name length					*/
	int			index;							/* content entry index					*/
	uint32_t	cache_num;						/* Num of cache							*/
	CefT_Csmgrd_Content_Info* entry[FscC_MemCache_Max_Cob_Num];
												/* Content Information					*/

} FscT_Mem_Cache_Content_Entry;

typedef struct {

	/********** Child pid list ***********/
	pid_t			child_pid;
	unsigned char	key[CsmgrdC_Key_Max];
	int 			key_len;
	uint32_t		seq_num;
	int				sock;

} FscT_Ch_Pid_List;

typedef struct {

	/********** FileSystemCache Status ***********/
	char			fsc_root_path[CefC_Csmgr_File_Path_Length];
	char			fsc_cache_path[CefC_Csmgr_File_Path_Length];
												/* FileSystemCache root dir				*/
	char			fsc_csmng_file_name[CefC_Csmgr_File_Path_Length];
												/* Csmng dir path						*/
	uint32_t		interval;					/* Interval that to check cache			*/
	uint32_t		fsc_id;						/* FileSystemCache ID					*/
	
	FscT_Contentmng* contmng;					/* Content manager						*/
	int contmng_id;								/* Content manager memory id			*/

	/********** ring queue ***********/
	int				item_que_num;				/* Num of queue item					*/
	CefT_Mp_Handle	item_put_que_mp;			/* for item_put_que 					*/
	CefT_Rngque*	item_put_que;				/* TX ring buffer 						*/
	uint64_t		item_put_time;

	/********** memory cache ***********/
	int				mem_cache_num;				/* Num of memory cache					*/
	CefT_Mp_Handle	mem_cache_cob_mp;			/* for cob entry						*/
	CefT_Mp_Handle	mem_cache_que_mp;			/* for mem_cache_que 					*/
	CefT_Rngque*	mem_cache_que;				/* TX ring buffer 						*/
	uint64_t		mem_expire_check;
	int				mem_cache_table_num;		/* Num of memory cache table			*/
	CefT_Hash_Handle mem_cache_table;			/* Memory Cache Table					*/
	CefT_Mp_Handle	mem_cache_table_mp;			/* for Memory Cache Table				*/

	/********** cache algorithm library **********/
	void* 			algo_lib;					/* records to the loaded library 		*/
	CsmgrdT_Lib_Interface algo_apis;
	char 			algo_name[1024];			/* algorithm to replece cache entries	*/
	uint32_t 		cache_cobs;
	int 			cache_cob_max;
	CefT_Mp_Handle	mem_rm_key;

} FscT_Cache_Handle;


#endif // __CSMGRD_FILESYSTEM_CACHE_HEADER__

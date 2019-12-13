/*
 * Copyright (c) 2016-2019, National Institute of Information and Communications
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
 * csmgrd_plugin.h
 */
#ifndef __CSMGRD_PLUGIN_HEADER__
#define __CSMGRD_PLUGIN_HEADER__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdint.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <netinet/in.h>


#include <cefore/cef_csmgr.h>
#include <cefore/cef_csmgr_stat.h>

#ifdef CefC_Ccninfo
#include <cefore/cef_ccninfo.h>
#endif // CefC_Ccninfo
#include <cefore/cef_log.h>



/****************************************************************************************
 Macros
 ****************************************************************************************/

#define CsmgrdC_Max_Plugin_Name_Len 	64
#define CsmgrdC_Key_Max 				1024

#define CsmgrC_Buff_Size 				10000000
#define CsmgrC_Buff_Max 				100000000
#define CsmgrC_Buff_Num 				65536

/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/

typedef struct {

	/********** Receive Content Object		***********/
	unsigned char	msg[CefC_Max_Msg_Size];		/* Message								*/
	uint16_t		msg_len;					/* Message length						*/
	unsigned char	name[CefC_Max_Msg_Size];	/* Content name							*/
	uint16_t		name_len;					/* Content name length					*/
	uint16_t		pay_len;					/* Payload length						*/
	uint32_t		chnk_num;					/* Chunk num							*/
	uint64_t		cache_time;					/* Cache time							*/
	uint64_t		expiry;						/* Expiry								*/
	struct in_addr	node;						/* Node address							*/
	
	uint64_t		ins_time;					/* Insert time(use mem cache only)		*/

} CsmgrdT_Content_Entry;


typedef struct CsmgrdT_Plugin_Interface {
	/* Initialize process */
	int (*init)(CsmgrT_Stat_Handle);
	
	/* Destroy process */
	void (*destroy)(void);
	
	/* Check expiry */
	void (*expire_check)(void);
	
	/* Get Cob Entry */
	int (*cache_item_get)(unsigned char*, uint16_t, uint32_t, int);
	
	/* Put contents */
	int (*cache_item_puts)(unsigned char*, int);
	
	/* Increment access count */
	void (*ac_cnt_inc)(unsigned char*, uint16_t, uint32_t);
	
#ifdef CefC_Ccore
	/* Set cache capacity */
	int (*cache_cap_set) (uint64_t);
	
	/* Set cache lifetime 	*/
	int (*content_lifetime_set) (unsigned char*, uint16_t, uint64_t);
	
	/* Delete cache entry */
	int (*content_cache_del) (unsigned char*, uint16_t, uint32_t);
#endif // CefC_Ccore
	
	int (*content_lifetime_get) (unsigned char*, uint16_t, uint32_t*, uint32_t*, uint8_t);

} CsmgrdT_Plugin_Interface;

typedef struct CsmgrdT_Lib_Interface {

	/* Init API 		*/
	int
	(*init) (
		int ,
		int (*store)(CsmgrdT_Content_Entry*),
		void (*remove)(unsigned char*, int)
	);

	/* Destroy API 		*/
	void
	(*destroy) (
		void
	);

	/* Insert API		*/
	void
	(*insert) (
		CsmgrdT_Content_Entry*
	);

	/* Erase API		*/
	void
	(*erase) (
		unsigned char*,
		int
	);

	/* Hit API		*/
	void
	(*hit) (
		unsigned char*,
		int
	);

	/* Remove API		*/
	void
	(*miss) (
		unsigned char*,
		int
	);

	/* Status API 		*/
	void
	(*status) (
		void*
	);

} CsmgrdT_Lib_Interface;

/****************************************************************************************
 Global Variables
 ****************************************************************************************/



/****************************************************************************************
 Function Declarations
 ****************************************************************************************/
#define CSMGRD_SET_CALLBACKS( fc_init, fc_destroy, fc_expire_check, fc_cache_item_get, fc_cache_item_puts, fc_ac_cnt_inc, fc_lifetime_get ) \
	do { \
		cs_in->init = (fc_init); \
		cs_in->destroy = (fc_destroy); \
		cs_in->expire_check = (fc_expire_check); \
		cs_in->cache_item_get = (fc_cache_item_get); \
		cs_in->cache_item_puts = (fc_cache_item_puts); \
		cs_in->ac_cnt_inc = (fc_ac_cnt_inc); \
		cs_in->content_lifetime_get = (fc_lifetime_get); \
	} while(0)

/*--------------------------------------------------------------------------------------
	Function to Create Cob message
----------------------------------------------------------------------------------------*/
void
csmgrd_plugin_cob_msg_create (
	unsigned char* buff,						/* created message						*/
	uint16_t* buff_len,							/* Length of message					*/
	unsigned char* msg,							/* Content Object						*/
	uint16_t msg_len,							/* Length of Content Object				*/
	uint32_t chnk_num,							/* Chunk number							*/
	int faceid									/* faceid								*/
);
/*--------------------------------------------------------------------------------------
	Function to Send Cob message
----------------------------------------------------------------------------------------*/
int
csmgrd_plugin_cob_msg_send (
	int fd,									/* socket fd								*/
	unsigned char* msg,						/* send message								*/
	uint16_t msg_len						/* message length							*/
);
/*--------------------------------------------------------------------------------------
	Sets APIs for cache algorithm library
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
csmgrd_lib_api_get (
	const char* algo_lib_name,
	void** 	algo_lib,
	CsmgrdT_Lib_Interface* algo_apis
);
/*--------------------------------------------------------------------------------------
	Creates tye key from name and chunk number
----------------------------------------------------------------------------------------*/
int												/* length of the created key 			*/
csmgrd_key_create (
	CsmgrdT_Content_Entry* entry,
	unsigned char* key
);
/*--------------------------------------------------------------------------------------
	Concatenates name and chunk number
----------------------------------------------------------------------------------------*/
int												/* length of the created key 			*/
csmgrd_name_chunknum_concatenate (
	const unsigned char* name,
	uint16_t name_len,
	uint32_t chunknum,
	unsigned char* key
);

/*--------------------------------------------------------------------------------------
	Creates the content entry
----------------------------------------------------------------------------------------*/
int 
cef_csmgr_con_entry_create (
	unsigned char* buff,						/* receive message						*/
	int buff_len,								/* message length						*/
	CsmgrdT_Content_Entry* entry
);

void
csmgrd_log_init (
	const char* proc_name,
	int			level
);

void
csmgrd_log_init2 (
	const char* config_file_dir 
);

void
csmgrd_log_write (
	int level, 										/* logging level 					*/
	const char* fmt, 								/* output format					*/
	...												/* parameters						*/
);

#ifdef CefC_Debug
void
csmgrd_dbg_init (
	const char* proc_name,
	const char* config_file_dir
);

void
csmgrd_dbg_write (
	int level, 										/* debug level 						*/
	const char* fmt, 								/* output format					*/
	...												/* parameters						*/
);

void
csmgrd_dbg_buff_write (
	int level, 										/* debug level 						*/
	const unsigned char* buff,
	int len
);
#endif // CefC_Debug
#endif // __CSMGRD_PLUGIN_HEADER__

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
 * cef_mem_cache.h
 */

#ifndef __CEF_MEM_CACHE_HEADER__
#define __CEF_MEM_CACHE_HEADER__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <limits.h>

#include <ifaddrs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <cefore/cef_define.h>
#include <cefore/cef_fib.h>
#include <cefore/cef_pit.h>
#include <cefore/cef_face.h>
#include <cefore/cef_frame.h>
#include <cefore/cef_hash.h>
#include <cefore/cef_client.h>
#include <cefore/cef_print.h>
#include <cefore/cef_csmgr.h>
#include <cefore/cef_valid.h>
#include <cefore/cef_log.h>
#include <cefore/cef_csmgr_stat.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

#define CefMemCacheC_Key_Max 				1024
#define Cef_InconsistentVersion				-1000
#define Cef_SameVersion						0
#define Cef_NewestVersion_1stArg			1
#define Cef_NewestVersion_2ndArg			-1

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
	uint32_t		chunk_num;					/* Chunk num							*/
	uint64_t		cache_time;					/* Cache time							*/
	uint64_t		expiry;						/* Expiry								*/
	struct in_addr	node;						/* Node address							*/
	unsigned char*	version;					/* 0.8.3c */
	uint16_t		ver_len;					/* 0.8.3c */

} CefMemCacheT_Content_Entry;

typedef struct {

	/********** Content Object in mem cache		***********/
	unsigned char	*msg;						/* Message								*/
	uint16_t		msg_len;					/* Message length						*/
	unsigned char	*name;						/* Content name							*/
	uint16_t		name_len;					/* Content name length					*/
	uint16_t		pay_len;					/* Payload length						*/
	unsigned char*	version;					/* 0.8.3c */
	uint16_t		ver_len;					/* 0.8.3c */
	uint32_t		chunk_num;					/* Chunk num							*/
	uint64_t		cache_time;					/* Cache time							*/
	uint64_t		expiry;						/* Expiry								*/
	struct in_addr	node;						/* Node address							*/

} CefMemCacheT_Content_Mem_Entry;

typedef struct {
	uint32_t		con_size;
	uint32_t		con_num;
	uint32_t		ac_cnt;
	uint32_t		min_seq;
	uint32_t		max_seq;
} CefMemCacheT_Ccninfo;

/****************************************************************************************
 Global Variables
 ****************************************************************************************/

/****************************************************************************************
 Function Declarations
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Intialize local cache environment
----------------------------------------------------------------------------------------*/
int
cef_mem_cache_init(
		uint32_t		capacity
);
/*--------------------------------------------------------------------------------------
	A thread that puts a content object in the local cache
----------------------------------------------------------------------------------------*/
void *
cef_mem_cache_put_thread (
	void *p
);
/*--------------------------------------------------------------------------------------
	Thread to clear expirly content object of local cache
----------------------------------------------------------------------------------------*/
void *
cef_mem_cache_clear_thread (
	void *p
);
/*--------------------------------------------------------------------------------------
	A thread that delete a content object in the local cache
----------------------------------------------------------------------------------------*/
void *
cef_mem_cache_delete_thread (
	void *p
);
/*--------------------------------------------------------------------------------------
	set the cob to memry cache
----------------------------------------------------------------------------------------*/
int
cef_mem_cache_item_set (
	CefMemCacheT_Content_Entry* entry
);
/*--------------------------------------------------------------------------------------
	Function to read a ContentObject from Local Cache
----------------------------------------------------------------------------------------*/
CefMemCacheT_Content_Mem_Entry*
cef_mem_cache_item_get (
	unsigned char* trg_key,						/* content name							*/
	uint16_t trg_key_len						/* content name Length					*/
);
/*--------------------------------------------------------------------------------------
	Destroy local cache resources
----------------------------------------------------------------------------------------*/
void
cef_mem_cache_destroy (
	void
);
/*--------------------------------------------------------------------------------------
	Function to increment access count
----------------------------------------------------------------------------------------*/
void
cef_mem_cache_cs_ac_cnt_inc (
	unsigned char* key,							/* content name							*/
	uint16_t key_size,							/* content name Length					*/
	uint32_t seq_num							/* sequence number						*/
);
/*--------------------------------------------------------------------------------------
	Get stat
----------------------------------------------------------------------------------------*/
int
cef_mem_cache_mstat_get (
	unsigned char* key,
	uint32_t klen,
	CefMemCacheT_Ccninfo* info_p
);
#if ((defined CefC_CefnetdCache) && (defined CefC_Develop))
/*--------------------------------------------------------------------------------------
	Get mstat info in buffer
----------------------------------------------------------------------------------------*/
int
cef_mem_cache_mstat_get_buff (
	char* buff,
	int buff_size
);
#endif //((defined CefC_CefnetdCache) && (defined CefC_Develop))
#endif // __CEF_MEM_CACHE_HEADER__

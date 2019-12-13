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
 * cef_csmgr_stat.h
 */

#ifndef __CEF_CSMGR_STAT_HEADER__
#define __CEF_CSMGR_STAT_HEADER__

/****************************************************************************************
 Include Files
 ****************************************************************************************/

#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <cefore/cef_define.h>
#include <cefore/cef_cefinfo.h>
#include <cefore/cef_log.h>


/****************************************************************************************
 Macros
 ****************************************************************************************/

#define CsmgrT_Stat_Seq_Max 			262143

#define CsmgrT_Name_Max					65536
#define CsmgrT_Stat_Max					8192
#define CsmgrT_Map_Max					4096
#define CsmgrC_Invalid	 				0


/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/

typedef size_t CsmgrT_Stat_Handle;

typedef struct {
	
	uint32_t 			hash;
	uint16_t 			index;
	unsigned char 		name[CsmgrT_Name_Max];
	uint16_t 			name_len;
	uint64_t 			con_size;
	uint64_t 			cob_num;
	uint64_t 			access;
	uint64_t 			cob_map[CsmgrT_Map_Max];
	uint64_t 			expiry;
	uint64_t 			cached_time;
	uint32_t 			min_seq;
	uint32_t 			max_seq;
	struct in_addr 		node;
	int 				expire_f;
	
} CsmgrT_Stat;

/****************************************************************************************
 Function Declarations
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Creates the Csmgrd Stat Handle
----------------------------------------------------------------------------------------*/
CsmgrT_Stat_Handle 
csmgrd_stat_handle_create (
	void 
);
/*--------------------------------------------------------------------------------------
	Destroy the Csmgrd Stat Handle
----------------------------------------------------------------------------------------*/
void 
csmgrd_stat_handle_destroy (
	CsmgrT_Stat_Handle hdl
);
/*--------------------------------------------------------------------------------------
	Access the content information
----------------------------------------------------------------------------------------*/
CsmgrT_Stat* 
csmgrd_stat_content_info_access (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len
);
/*--------------------------------------------------------------------------------------
	Obtain the content information
----------------------------------------------------------------------------------------*/
CsmgrT_Stat* 
csmgrd_stat_content_info_get (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len
);
/*--------------------------------------------------------------------------------------
	Obtain the content information
----------------------------------------------------------------------------------------*/
int 
csmgrd_stat_content_info_gets (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len, 
	int partial_match_f, 
	CsmgrT_Stat* ret[CefstatC_MaxUri]
);
/*--------------------------------------------------------------------------------------
	Obtain the expred lifetime content information
----------------------------------------------------------------------------------------*/
CsmgrT_Stat* 
csmgrd_stat_expired_content_info_get (
	CsmgrT_Stat_Handle hdl, 
	int* index
);
/*--------------------------------------------------------------------------------------
	Update cached Cob status
----------------------------------------------------------------------------------------*/
void 
csmgrd_stat_cob_update (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len, 
	uint32_t seq, 
	uint32_t cob_size, 
	uint64_t expiry, 
	uint64_t cached_time, 
	struct in_addr node
);
/*--------------------------------------------------------------------------------------
	Remove the specified cached Cob status
----------------------------------------------------------------------------------------*/
int 
csmgrd_stat_cob_remove (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len, 
	uint32_t seq, 
	uint32_t cob_size
);
/*--------------------------------------------------------------------------------------
	Update access count
----------------------------------------------------------------------------------------*/
void 
csmgrd_stat_access_count_update (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len
);
/*--------------------------------------------------------------------------------------
	Init the valiables of the specified content
----------------------------------------------------------------------------------------*/
CsmgrT_Stat* 
csmgrd_stat_content_info_init (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len
);
/*--------------------------------------------------------------------------------------
	Deletes the content information
----------------------------------------------------------------------------------------*/
void 
csmgrd_stat_content_info_delete (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len
);
/*--------------------------------------------------------------------------------------
	Update cache capacity
----------------------------------------------------------------------------------------*/
void 
csmgrd_stat_cache_capacity_update (
	CsmgrT_Stat_Handle hdl, 
	uint32_t capacity
);
/*--------------------------------------------------------------------------------------
	Update content expire time
----------------------------------------------------------------------------------------*/
void 
csmgrd_stat_content_lifetime_update (
	CsmgrT_Stat_Handle hdl, 
	const unsigned char* name, 
	uint16_t name_len, 
	uint64_t expiry
);
/*--------------------------------------------------------------------------------------
	Obtains the number of cached content
----------------------------------------------------------------------------------------*/
uint16_t 
csmgrd_stat_cached_con_num_get (
	CsmgrT_Stat_Handle hdl
);
/*--------------------------------------------------------------------------------------
	Obtains the Cache capacity
----------------------------------------------------------------------------------------*/
uint32_t 
csmgrd_stat_cache_capacity_get (
	CsmgrT_Stat_Handle hdl
);

#endif // __CEF_CSMGR_STAT_HEADER__

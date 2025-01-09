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
#include <cefore/cef_ccninfo.h>
#include <cefore/cef_log.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

#define CsmgrT_Name_Max					65536
#define CsmgrT_Stat_Max					1000000
#define CsmgrC_Invalid	 				0

#define CsmgrT_Add_Maps					1000

#define	CsmgrT_MAP_BASE					(64 * CsmgrT_Add_Maps)
#define CsmgrT_NODE_MAX					100

#define	CsmgrT_IM_CSMGRD				1
#define	CsmgrT_IM_CONPUBD 				2

#define	CsmgrT_UCINC_STAT_NONE			0
#define	CsmgrT_UCINC_STAT_KEY_WAIT		1
#define	CsmgrT_UCINC_STAT_ACK_WAIT		2
#define	CsmgrT_UCINC_STAT_ACK_RECEIVED	3
#define	CsmgrT_UCINC_STAT_VALIDATION_OK	4
#define	is_check_pending_timer_status(s) \
	((CsmgrT_UCINC_STAT_NONE < (s) && (s) < CsmgrT_UCINC_STAT_VALIDATION_OK) ? 1 : 0)
/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/

typedef size_t CsmgrT_Stat_Handle;

typedef struct CsmgrT_NODE_INFO {
	unsigned char 		nodeid[16];
	uint16_t 			nodeid_len;
}	CsmgrT_NODE_INFO;

typedef struct CsmgrT_Stat {

	uint32_t 			index;
	unsigned char 		*name;
	uint16_t 			name_len;
	uint64_t 			con_size;
	/* FILE/DB Cob size information */
	uint32_t			cob_size;
	uint32_t			last_cob_size;
	uint32_t			last_chunk_num;

	uint64_t 			cob_num;
	uint64_t 			access;
	uint64_t 			req_count;		//0.8.3c

	uint64_t 			*cob_map;
	uint32_t			map_max;

	uint32_t			map_num;		//0.8.3c

	uint64_t 			expiry;
	uint64_t 			publisher_expiry;
	uint64_t 			cached_time;
	uint32_t 			min_seq;
	uint32_t 			max_seq;
	struct in_addr 		node;
	struct CsmgrT_NODE_INFO Owner_csmgrd;	//0.8.3c
	int 				expire_f;

	/* FILE cache record size information */
	uint32_t			file_msglen;
	uint32_t			detect_chunkno;
	uint64_t			fsc_write_time;

	/* Bulk sent information */
	uint32_t 			tx_seq;
	uint32_t 			tx_num;
	uint64_t			tx_time;

	unsigned char*		version;
	uint16_t			ver_len;

	/* UCINC information */
	uint16_t			ucinc_stat;
	uint64_t			pending_timer;
	unsigned char*		ssl_public_key_val;
	uint16_t			ssl_public_key_len;
	uint16_t			validation_result;

	struct CsmgrT_Stat*	next;
} CsmgrT_Stat;
//0.8.3c S
typedef struct {

	uint64_t 			capacity;
	uint32_t			cached_con_num;
	uint64_t			cached_cob_num;
	CsmgrT_Stat** 		rcds;
	pthread_mutex_t 	stat_mutex;

} CsmgrT_Stat_Table;
//0.8.3c E

//0.8.3c S
typedef struct CsmgrT_DB_COB_MAP {
	uint64_t	cob_map[CsmgrT_Add_Maps];
	struct		CsmgrT_DB_COB_MAP* next;
}	CsmgrT_DB_COB_MAP;

typedef struct CsmgrT_CSMGRD_TBL {
	int							csmgrd_num;
	struct	CsmgrT_NODE_INFO	csmgrd_addr[CsmgrT_NODE_MAX];
}	CsmgrT_CSMGRD_TBL;

typedef struct CsmgrT_KEY_INFO	{
	int				key_len;
	char			key_str[CefC_Max_Length];
	int				name_len;
	unsigned char	name[CefC_Max_Length];
	int				expiry;
}	CsmgrT_KEY_INFO;

//0.8.3c E

/****************************************************************************************
 Function Declarations
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Creates the Csmgr Stat Handle
----------------------------------------------------------------------------------------*/
CsmgrT_Stat_Handle
csmgr_stat_handle_create (
	void
);
/*--------------------------------------------------------------------------------------
	Destroy the Csmgr Stat Handle
----------------------------------------------------------------------------------------*/
void
csmgr_stat_handle_destroy (
	CsmgrT_Stat_Handle hdl
);
/*--------------------------------------------------------------------------------------
	Check if content information exists
----------------------------------------------------------------------------------------*/
CsmgrT_Stat*
csmgr_stat_content_info_is_exist (
	CsmgrT_Stat_Handle hdl,
	const unsigned char* name,
	uint16_t name_len,
	CsmgrT_DB_COB_MAP**	cob_map
);
/*--------------------------------------------------------------------------------------
	Access the content information
----------------------------------------------------------------------------------------*/
CsmgrT_Stat*
csmgr_stat_content_info_access (
	CsmgrT_Stat_Handle hdl,
	const unsigned char* name,
	uint16_t name_len,
	uint16_t module_name
);
/*--------------------------------------------------------------------------------------
	Confirm existence of the content information
----------------------------------------------------------------------------------------*/
CsmgrT_Stat*
csmgr_stat_content_is_exist (
	CsmgrT_Stat_Handle hdl,
	const unsigned char* name,
	uint16_t name_len
);

/*--------------------------------------------------------------------------------------
	Obtain the content information
----------------------------------------------------------------------------------------*/
CsmgrT_Stat*
csmgr_stat_content_info_get (
	CsmgrT_Stat_Handle hdl,
	const unsigned char* name,
	uint16_t name_len
);
/*--------------------------------------------------------------------------------------
	Obtain the content information
----------------------------------------------------------------------------------------*/
int
csmgr_stat_content_info_gets (
	CsmgrT_Stat_Handle hdl,
	const unsigned char* name,
	uint16_t name_len,
	int partial_match_f,
	CsmgrT_Stat* ret[]
);
/*--------------------------------------------------------------------------------------
	Obtain the content information
----------------------------------------------------------------------------------------*/
int
csmgr_stat_content_info_gets_for_RM (
	CsmgrT_Stat_Handle hdl,
	const unsigned char* name,
	uint16_t name_len,
	uint64_t* cob_info
);
/*--------------------------------------------------------------------------------------
	Obtain the expred lifetime content information
----------------------------------------------------------------------------------------*/
CsmgrT_Stat*
csmgr_stat_expired_content_info_get (
	CsmgrT_Stat_Handle hdl,
	int* index,
	uint16_t module_name
);
/*--------------------------------------------------------------------------------------
	Update cached Cob status
----------------------------------------------------------------------------------------*/
void
csmgr_stat_cob_update (
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
csmgr_stat_cob_remove (
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
csmgr_stat_access_count_update (
	CsmgrT_Stat_Handle hdl,
	const unsigned char* name,
	uint16_t name_len
);
/*--------------------------------------------------------------------------------------
	Update request count
----------------------------------------------------------------------------------------*/
void
csmgr_stat_request_count_update (
	CsmgrT_Stat_Handle hdl,
	const unsigned char* name,
	uint16_t name_len
);
/*--------------------------------------------------------------------------------------
	Init the valiables of the specified content
----------------------------------------------------------------------------------------*/
CsmgrT_Stat*
csmgr_stat_content_info_init (
	CsmgrT_Stat_Handle hdl,
	const unsigned char* name,
	uint16_t name_len,
	CsmgrT_DB_COB_MAP**	cob_map
);
/*--------------------------------------------------------------------------------------
	Init the valiables of the specified content (for version)
----------------------------------------------------------------------------------------*/
int
csmgr_stat_content_info_version_init (
	CsmgrT_Stat_Handle hdl,
	CsmgrT_Stat* rcd,
	unsigned char* version,
	uint16_t ver_len
);
/*--------------------------------------------------------------------------------------
	Deletes the content information
----------------------------------------------------------------------------------------*/
void
csmgr_stat_content_info_delete (
	CsmgrT_Stat_Handle hdl,
	const unsigned char* name,
	uint16_t name_len
);
/*--------------------------------------------------------------------------------------
	Update cache capacity
----------------------------------------------------------------------------------------*/
void
csmgr_stat_cache_capacity_update (
	CsmgrT_Stat_Handle hdl,
	uint64_t capacity
);
/*--------------------------------------------------------------------------------------
	Update content expire time
----------------------------------------------------------------------------------------*/
void
csmgr_stat_content_lifetime_update (
	CsmgrT_Stat_Handle hdl,
	const unsigned char* name,
	uint16_t name_len,
	uint64_t expiry
);
/*--------------------------------------------------------------------------------------
	Obtains the number of cached content
----------------------------------------------------------------------------------------*/
uint32_t
csmgr_stat_cached_con_num_get (
	CsmgrT_Stat_Handle hdl
);
/*--------------------------------------------------------------------------------------
	Obtains the number of cached cob
----------------------------------------------------------------------------------------*/
uint64_t
csmgr_stat_cached_cob_num_get (
	CsmgrT_Stat_Handle hdl
);
/*--------------------------------------------------------------------------------------
	Obtains the Cache capacity
----------------------------------------------------------------------------------------*/
uint64_t
csmgr_stat_cache_capacity_get (
	CsmgrT_Stat_Handle hdl
);
/*--------------------------------------------------------------------------------------
	Verification for UCINC
----------------------------------------------------------------------------------------*/
int
csmgr_stat_cob_verify_ucinc (
	CsmgrT_Stat_Handle hdl,
	const unsigned char* name,
	uint16_t name_len,
	unsigned char* signature_val,
	uint16_t signature_len,
	unsigned char* plain_val,
	uint16_t plain_len
);
/*--------------------------------------------------------------------------------------
	Update content UCINC Stat
----------------------------------------------------------------------------------------*/
void
csmgr_stat_content_ucinc_stat_update (
	CsmgrT_Stat_Handle hdl,
	const unsigned char* name,
	uint16_t name_len,
	uint16_t ucinc_stat
);
/*--------------------------------------------------------------------------------------
	Update content Pending timer
----------------------------------------------------------------------------------------*/
void
csmgr_stat_content_pending_timer_update (
	CsmgrT_Stat_Handle hdl,
	const unsigned char* name,
	uint16_t name_len,
	uint64_t pending_timer
);
/*--------------------------------------------------------------------------------------
	Update content SSL public key
----------------------------------------------------------------------------------------*/
void
csmgr_stat_content_ssl_public_key_update (
	CsmgrT_Stat_Handle hdl,
	const unsigned char* name,
	uint16_t name_len,
	unsigned char* ssl_public_key_val,
	uint16_t ssl_public_key_len
);
/*--------------------------------------------------------------------------------------
	Update content signature
----------------------------------------------------------------------------------------*/
void
csmgr_stat_content_signature_update (
	CsmgrT_Stat_Handle hdl,
	const unsigned char* name,
	uint16_t name_len,
	unsigned char* signature_val,
	uint16_t signature_len
);
/*--------------------------------------------------------------------------------------
	Update content plain
----------------------------------------------------------------------------------------*/
void
csmgr_stat_content_plain_update (
	CsmgrT_Stat_Handle hdl,
	const unsigned char* name,
	uint16_t name_len,
	unsigned char* plain_val,
	uint16_t plain_len
);
/*--------------------------------------------------------------------------------------
	Update content publisher expiry
----------------------------------------------------------------------------------------*/
void
csmgr_stat_content_publisher_expiry_update (
	CsmgrT_Stat_Handle hdl,
	const unsigned char* name,
	uint16_t name_len,
	uint64_t publisher_expiry
);
/*--------------------------------------------------------------------------------------
	Obtain the content information for publisher
----------------------------------------------------------------------------------------*/
CsmgrT_Stat*
csmgr_stat_content_info_get_for_pub (
	CsmgrT_Stat_Handle hdl,
	const unsigned char* name,
	uint16_t name_len
);
/*--------------------------------------------------------------------------------------
	Obtain the content information for publisher
----------------------------------------------------------------------------------------*/
int
csmgr_stat_content_info_gets_for_pub (
	CsmgrT_Stat_Handle hdl,
	const unsigned char* name,
	uint16_t name_len,
	int partial_match_f,
	CsmgrT_Stat* ret[]
);
/*--------------------------------------------------------------------------------------
	Update cached Cob status for publisher
----------------------------------------------------------------------------------------*/
void
csmgr_stat_cob_update_for_pub (
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
	Remove the specified cached Cob status for publisher
----------------------------------------------------------------------------------------*/
int
csmgr_stat_cob_remove_for_pub (
	CsmgrT_Stat_Handle hdl,
	const unsigned char* name,
	uint16_t name_len,
	uint32_t seq,
	uint32_t cob_size
);

/****************************************************************************************
 Function Alias Declarations
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	for csmgrd
----------------------------------------------------------------------------------------*/
#define csmgrd_stat_handle_create() \
		 csmgr_stat_handle_create()
#define csmgrd_stat_handle_destroy(hdl) \
		 csmgr_stat_handle_destroy(hdl)
#define csmgrd_stat_content_info_access(hdl, name, name_len) \
		 csmgr_stat_content_info_access(hdl, name, name_len, CsmgrT_IM_CSMGRD)
#define csmgrd_stat_content_info_is_exist(hdl, name, name_len, cob_map) \
		 csmgr_stat_content_info_is_exist(hdl, name, name_len, cob_map)
#define csmgrd_stat_content_info_get(hdl, name, name_len) \
		 csmgr_stat_content_info_get(hdl, name, name_len)
#define csmgrd_stat_content_info_gets(hdl, name, name_len, partial_match_f, retARY) \
		 csmgr_stat_content_info_gets(hdl, name, name_len, partial_match_f, retARY)
#define csmgrd_stat_expired_content_info_get(hdl, index) \
		 csmgr_stat_expired_content_info_get(hdl, index, CsmgrT_IM_CSMGRD)
#define csmgrd_stat_cob_update(hdl, name, name_len, seq, cob_size, expiry, cached_time, node) \
		 csmgr_stat_cob_update(hdl, name, name_len, seq, cob_size, expiry, cached_time, node)
#define csmgrd_stat_cob_remove(hdl, name, name_len, seq, cob_size) \
		 csmgr_stat_cob_remove(hdl, name, name_len, seq, cob_size)
#define csmgrd_stat_access_count_update(hdl, name, name_len) \
		 csmgr_stat_access_count_update(hdl, name, name_len)
#define csmgrd_stat_request_count_update(hdl, name, name_len) \
		 csmgr_stat_request_count_update(hdl, name, name_len)
#define csmgrd_stat_content_info_init(hdl, name, name_len, cob_map) \
		 csmgr_stat_content_info_init(hdl, name, name_len, cob_map)
#define csmgrd_stat_content_info_version_init(hdl, rcd, version, ver_len) \
		 csmgr_stat_content_info_version_init(hdl, rcd, version, ver_len)
#define csmgrd_stat_content_info_delete(hdl, name, name_len) \
		 csmgr_stat_content_info_delete(hdl, name, name_len)
#define csmgrd_stat_cache_capacity_update(hdl, capacity) \
		 csmgr_stat_cache_capacity_update(hdl, capacity)
#define csmgrd_stat_content_lifetime_update(hdl, name, name_len, expiry) \
		 csmgr_stat_content_lifetime_update(hdl, name, name_len, expiry)
#define csmgrd_stat_cached_con_num_get(hdl) \
		 csmgr_stat_cached_con_num_get(hdl)
#define csmgrd_stat_cached_cob_num_get(hdl) \
		 csmgr_stat_cached_cob_num_get(hdl)
#define csmgrd_stat_cache_capacity_get(hdl) \
		 csmgr_stat_cache_capacity_get(hdl)
//0.8.3c
#define	 csmgrd_stat_content_info_gets_for_RM(hdl, name, name_len, ret) \
		 csmgr_stat_content_info_gets_for_RM(hdl, name, name_len, ret)
//0.10.x
#define	 csmgrd_stat_cob_verify_ucinc(hdl, name, name_len, signature_val, signature_len, plain_val, plain_len) \
		 csmgr_stat_cob_verify_ucinc(hdl, name, name_len, signature_val, signature_len, plain_val, plain_len)
#define	 csmgrd_stat_content_ucinc_stat_update(hdl, name, name_len, ucinc_stat) \
		 csmgr_stat_content_ucinc_stat_update(hdl, name, name_len, ucinc_stat)
#define	 csmgrd_stat_content_pending_timer_update(hdl, name, name_len, pending_timer) \
		 csmgr_stat_content_pending_timer_update(hdl, name, name_len, pending_timer)
#define	 csmgrd_stat_content_ssl_public_key_update(hdl, name, name_len, ssl_public_key_val, ssl_public_key_len) \
		 csmgr_stat_content_ssl_public_key_update(hdl, name, name_len, ssl_public_key_val, ssl_public_key_len)
#define	 csmgrd_stat_content_publisher_expiry_update(hdl, name, name_len, publisher_expiry) \
		 csmgr_stat_content_publisher_expiry_update(hdl, name, name_len, publisher_expiry)
/*--------------------------------------------------------------------------------------
	for conpubd
----------------------------------------------------------------------------------------*/
#define conpubd_stat_handle_create() \
		  csmgr_stat_handle_create()
#define conpubd_stat_handle_destroy(hdl) \
		  csmgr_stat_handle_destroy(hdl)
#define conpubd_stat_content_info_access(hdl, name, name_len) \
		  csmgr_stat_content_info_access(hdl, name, name_len, CsmgrT_IM_CONPUBD)
#define conpubd_stat_content_info_is_exist(hdl, name, name_len, cob_map) \
		 csmgr_stat_content_info_is_exist(hdl, name, name_len, cob_map)
#define conpubd_stat_content_info_get(hdl, name, name_len) \
		  csmgr_stat_content_info_get(hdl, name, name_len)
//		  csmgr_stat_content_info_get_for_pub(hdl, name, name_len)
#define conpubd_stat_content_info_gets(hdl, name, name_len, partial_match_f, retARY) \
		  csmgr_stat_content_info_gets_for_pub(hdl, name, name_len, partial_match_f, retARY)
//		  csmgr_stat_content_info_gets(hdl, name, name_len, partial_match_f, retARY)
#define conpubd_stat_expired_content_info_get(hdl, index) \
		  csmgr_stat_expired_content_info_get(hdl, index, CsmgrT_IM_CONPUBD)
#define conpubd_stat_cob_update(hdl, name, name_len, seq, cob_size, expiry, cached_time, node) \
		  csmgr_stat_cob_update(hdl, name, name_len, seq, cob_size, expiry, cached_time, node)
//		  csmgr_stat_cob_update_for_pub(hdl, name, name_len, seq, cob_size, expiry, cached_time, node)
#define conpubd_stat_cob_remove(hdl, name, name_len, seq, cob_size) \
		  csmgr_stat_cob_remove(hdl, name, name_len, seq, cob_size)
//		  csmgr_stat_cob_remove_for_pub(hdl, name, name_len, seq, cob_size)
#define conpubd_stat_access_count_update(hdl, name, name_len) \
		  csmgr_stat_access_count_update(hdl, name, name_len)
#define conpubd_stat_content_info_init(hdl, name, name_len, cob_map) \
		  csmgr_stat_content_info_init(hdl, name, name_len, cob_map)
#define conpubd_stat_content_info_version_init(hdl, rcd, version, ver_len) \
		  csmgr_stat_content_info_version_init(hdl, rcd, version, ver_len)
#define conpubd_stat_content_info_delete(hdl, name, name_len) \
		  csmgr_stat_content_info_delete(hdl, name, name_len)
#define conpubd_stat_cache_capacity_update(hdl, capacity) \
		  csmgr_stat_cache_capacity_update(hdl, capacity)
#define conpubd_stat_content_lifetime_update(hdl, name, name_len, expiry) \
		  csmgr_stat_content_lifetime_update(hdl, name, name_len, expiry)
#define conpubd_stat_cached_con_num_get(hdl) \
		  csmgr_stat_cached_con_num_get(hdl)
#define conpubd_stat_cached_cob_num_get(hdl) \
		  csmgr_stat_cached_cob_num_get(hdl)
#define conpubd_stat_cache_capacity_get(hdl) \
		  csmgr_stat_cache_capacity_get(hdl)

#endif // __CEF_CSMGR_STAT_HEADER__

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
 * conpubd_plugin.h
 */
#ifndef __CONPUBD_PLUGIN_HEADER__
#define __CONPUBD_PLUGIN_HEADER__

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

#include <cefore/cef_ccninfo.h>
#include <cefore/cef_log.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/
#define ConpubdC_Max_Sock_Num		32					/* Max number of TCP peer		*/

#define CefC_Name_Max_Length	2048

#define ConpubdC_Max_Plugin_Name_Len 	64
#define ConpubdC_Key_Max 				1024

#define ConpubC_Buff_Num 				65535

#define ConpubC_Add_Maps				1000

/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/

typedef struct ConpubdT_Plugin_Interface {
	/* Initialize process */
	int (*init)(CsmgrT_Stat_Handle);

	/* Destroy process */
	void (*destroy)(void);

	/* Check expiry */
	void (*expire_check)(void);

	/* Get Cob Entry */
	int (*cache_item_get)(unsigned char*, uint16_t, uint32_t, int, unsigned char*, uint16_t);

	/* Put contents */
//JK	int (*cache_item_puts)(	ConpubdT_Content_Entry*, int);
	int (*cache_item_puts)(void*, int, void*);

	/* Increment access count */
	void (*ac_cnt_inc)(unsigned char*, uint16_t, uint32_t);

	/* Delete content */
	int (*content_del) (unsigned char*, uint16_t, uint64_t);

	/* Get chahed cob num */
	uint64_t (*cached_cobs) ();

} ConpubdT_Plugin_Interface;

typedef struct {
	char 				launched_user_name[CefC_Csmgr_User_Len];

	/********** TCP Listen Sockets		***********/
	uint16_t 			port_num;
	int 				tcp_listen_fd;
	struct sockaddr* 	ai_addr;
	socklen_t 			ai_addrlen;
	int 				tcp_fds[ConpubdC_Max_Sock_Num];
	int 				tcp_index[ConpubdC_Max_Sock_Num];
	unsigned char* 		tcp_buff[ConpubdC_Max_Sock_Num];
	char				peer_id_str[ConpubdC_Max_Sock_Num][NI_MAXHOST];
	char				peer_sv_str[ConpubdC_Max_Sock_Num][NI_MAXSERV];
	int 				peer_num;
	
	/********** Local listen socket 	***********/
	int 				local_listen_fd;
	char 				local_sock_name[1024];
	int					local_peer_sock;
	
	/********** load functions			***********/
	ConpubdT_Plugin_Interface* cs_mod_int;		/* plugin interface						*/
	char			cache_type[ConpubdC_Max_Plugin_Name_Len];
												/* plugin library name					*/
	void*			mod_lib;					/* plugin library						*/
	
	/********** CS parameters info. ***********/
	uint32_t		purge_interval;				/* Interval that to purge cache			*/
	char			cache_path[PATH_MAX];
	int				contents_num;
	uint64_t		contents_capacity;

	/********** Cob parameters info. ***********/
	int				block_size;
	uint32_t		cache_default_rct;
	uint16_t 		valid_type;

	/********** APP FIB registration info. ***********/
	char 		cefnetd_id[128];
	char 		cefnetd_port_str[128];
	int 		cefnetd_port_num;
	int			cefnetd_sock;
	uint64_t 	cefnetd_reconnect_time;
	
	/********** Published info.  ***********/
	int				published_contents_num;
	
} CefT_Conpubd_Handle;

typedef struct {

	/********** Receive Content Object		***********/
	unsigned char*	msg;						/* Message								*/
	uint16_t		msg_len;					/* Message length						*/
	unsigned char*	name;						/* Content name							*/
	uint16_t		name_len;					/* Content name length					*/
	uint16_t		pay_len;					/* Payload length						*/
	uint32_t		chunk_num;					/* Chunk num							*/
	uint64_t		rct;						/* RCT									*/
	uint64_t		expiry;						/* Expiry								*/
	struct in_addr	node;						/* Node address							*/

} ConpubdT_Content_Entry;

/* Content management entry */
typedef struct _CefT_Cpubcnt_Hdl {

	unsigned char 		name[CefC_Name_Max_Length];
	int 				name_len;
	unsigned char 		version[CefC_Name_Max_Length];
	int 				version_len;
	char 				file_path[PATH_MAX];
	time_t 				date;					/* date of upload */
	time_t 				expiry;
	uint64_t 			interests;
	uint64_t			cob_num;
	int					line_no;
	struct _CefT_Cpubcnt_Hdl* next;

} CefT_Cpubcnt_Hdl;

#if 0		//JK
typedef struct ConpubdT_Plugin_Interface {
	/* Initialize process */
	int (*init)(CsmgrT_Stat_Handle);

	/* Destroy process */
	void (*destroy)(void);

	/* Check expiry */
	void (*expire_check)(void);

	/* Get Cob Entry */
	int (*cache_item_get)(unsigned char*, uint16_t, uint32_t, int, unsigned char*, uint16_t);

	/* Put contents */
//JK	int (*cache_item_puts)(	ConpubdT_Content_Entry*, int);
	int (*cache_item_puts)(void*, int, void*);

	/* Increment access count */
	void (*ac_cnt_inc)(unsigned char*, uint16_t, uint32_t);

	/* Delete content */
	int (*content_del) (unsigned char*, uint16_t, uint64_t);

	/* Get chahed cob num */
	uint64_t (*cached_cobs) ();

} ConpubdT_Plugin_Interface;
#endif		//JK

/****************************************************************************************
 Global Variables
 ****************************************************************************************/

/****************************************************************************************
 Function Declarations
 ****************************************************************************************/
#define CONPUBD_SET_CALLBACKS( fc_init, fc_destroy, fc_expire_check, fc_cache_item_get, fc_cache_item_puts, fc_ac_cnt_inc, fc_content_del, fc_cached_cobs ) \
	do { \
		cs_in->init = (fc_init); \
		cs_in->destroy = (fc_destroy); \
		cs_in->expire_check = (fc_expire_check); \
		cs_in->cache_item_get = (fc_cache_item_get); \
		cs_in->cache_item_puts = (fc_cache_item_puts); \
		cs_in->ac_cnt_inc = (fc_ac_cnt_inc); \
		cs_in->content_del = (fc_content_del); \
		cs_in->cached_cobs = (fc_cached_cobs); \
	} while (0)

/*--------------------------------------------------------------------------------------
	Function to Send Cob message
----------------------------------------------------------------------------------------*/
int
conpubd_plugin_cob_msg_send (
	int fd,									/* socket fd								*/
	unsigned char* msg,						/* send message								*/
	uint16_t msg_len						/* message length							*/
);

/*--------------------------------------------------------------------------------------
	Creates tye key from name and chunk number
----------------------------------------------------------------------------------------*/
int												/* length of the created key 			*/
conpubd_key_create (
	ConpubdT_Content_Entry* entry,
	unsigned char* key
);
/*--------------------------------------------------------------------------------------
	Concatenates name and chunk number
----------------------------------------------------------------------------------------*/
int												/* length of the created key 			*/
conpubd_name_chunknum_concatenate (
	const unsigned char* name,
	uint16_t name_len,
	uint32_t chunknum,
	unsigned char* key
);

void
conpubd_log_init (
	const char*	proc_name,
	int			level
);

void
conpubd_log_init2 (
	const char* config_file_dir
);

void
conpubd_log_write (
	int level, 										/* logging level 					*/
	const char* fmt, 								/* output format					*/
	...												/* parameters						*/
);

#ifdef CefC_Debug
void
conpubd_dbg_init (
	const char* proc_name,
	const char* config_file_dir
);

void
conpubd_dbg_write (
	int level, 										/* debug level 						*/
	const char* fmt, 								/* output format					*/
	...												/* parameters						*/
);

void
conpubd_dbg_buff_write (
	int level, 										/* debug level 						*/
	const unsigned char* buff,
	int len
);
#endif // CefC_Debug
#endif // __CONPUBD_PLUGIN_HEADER__

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
 * conpubd.h
 */

#ifndef __CONPUBD_HEADER__
#define __CONPUBD_HEADER__
/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>

#include <cefore/cef_define.h>
#include <cefore/cef_conpub.h>
#include <cefore/cef_rngque.h>
#include <conpubd/conpubd_plugin.h>


/****************************************************************************************
 Macros
 ****************************************************************************************/
/*------------------------------------------------------------------*/
/* Macros for conpubd status										*/
/*------------------------------------------------------------------*/
//JK	#define ConpubdC_Max_Sock_Num		32					/* Max number of TCP peer		*/

/* Library name				*/
#ifdef __APPLE__
#define ConpubdC_Plugin_Library_Name	"libconpubd_plugin.dylib"
#else // __APPLE__
#define ConpubdC_Plugin_Library_Name	"libconpubd_plugin.so"
#endif // __APPLE__


/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/
typedef struct {
	uint16_t 		port_num;
	char 			local_sock_id[64+1];
	char			cache_type[ConpubdC_Max_Plugin_Name_Len];
	char			cache_path[PATH_MAX];
	uint32_t		purge_interval;
	uint32_t		cache_default_rct;
	char			Valid_Alg[128];
	int				contents_num;
	uint64_t		contents_capacity;
	int				block_size;
	char			cefnetd_node[128]; 
	int				cefnetd_port;
	char			restore_path[PATH_MAX];
	char			restore_fname[PATH_MAX];
} ConpubT_Config_Param;

#if 0	//JK
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
#endif		//JK

/****************************************************************************************
 Function Declarations
 ****************************************************************************************/
#endif // __CONPUBD_HEADER__

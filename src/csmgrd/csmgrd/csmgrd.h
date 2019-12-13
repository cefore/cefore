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
 * csmgrd.h
 */

#ifndef __CSMGRD_HEADER__
#define __CSMGRD_HEADER__
/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>

#include <cefore/cef_define.h>
#include <cefore/cef_csmgr.h>
#include <cefore/cef_rngque.h>
#include <csmgrd/csmgrd_plugin.h>


/****************************************************************************************
 Macros
 ****************************************************************************************/
/*------------------------------------------------------------------*/
/* Macros for csmgrd status										*/
/*------------------------------------------------------------------*/
#define CsmgrdC_Max_Sock_Num		32					/* Max number of TCP peer		*/

/* Library name				*/
#ifdef __APPLE__
#define CsmgrdC_Plugin_Library_Name	"libcsmgrd_plugin.dylib"
#else // __APPLE__
#define CsmgrdC_Plugin_Library_Name	"libcsmgrd_plugin.so"
#endif // __APPLE__


/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/

typedef struct {

	/********** Content Store Parameters	***********/
	uint32_t		interval;					/* Interval that to check cache			*/
	char			cs_mod_name[CsmgrdC_Max_Plugin_Name_Len]; /* CS plugin name			*/
	uint16_t 		port_num;					/* PORT_NUM in csmgrd.conf 				*/
	char 			local_sock_id[1024];
	
} CsmgrT_Config_Param;

typedef struct CsmgrT_White_List {

	/********** White list	***********/
	unsigned char   host_addr[16];
	int 			host_addr_len;
	struct CsmgrT_White_List*	next;
	
} CsmgrT_White_List;


typedef struct {
	
	char 				launched_user_name[CefC_Csmgr_User_Len];
	
	/********** Access Control 			***********/
	CsmgrT_White_List*	white_list;				/* White List							*/
	int 				allow_all_f;
	
	/********** TCP Listen Sockets		***********/
	uint16_t 			port_num;
	int 				tcp_listen_fd;
	struct sockaddr* 	ai_addr;
	socklen_t 			ai_addrlen;
	int 				tcp_fds[CsmgrdC_Max_Sock_Num];
	int 				tcp_index[CsmgrdC_Max_Sock_Num];
	unsigned char* 		tcp_buff[CsmgrdC_Max_Sock_Num];
	char				peer_id_str[CsmgrdC_Max_Sock_Num][NI_MAXHOST];
	char				peer_sv_str[CsmgrdC_Max_Sock_Num][NI_MAXSERV];
	int 				peer_num;
	
	/********** Local listen socket 	***********/
	int 				local_listen_fd;
	char 				local_sock_name[1024];
	int					local_peer_sock;
	
	/********** load functions			***********/
	CsmgrdT_Plugin_Interface* cs_mod_int;		/* plugin interface						*/
	char			cs_mod_name[CsmgrdC_Max_Plugin_Name_Len];
												/* plugin library name					*/
	void*			mod_lib;					/* plugin library						*/
	
	/********** excache Status			***********/
	uint32_t		interval;					/* Interval that to check cache			*/
	
} CefT_Csmgrd_Handle;



/****************************************************************************************
 Function Declarations
 ****************************************************************************************/
#endif // __CSMGRD_HEADER__

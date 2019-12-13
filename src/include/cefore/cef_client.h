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
 * cef_client.h
 */

#ifndef __CEF_CLIENT_HEADER__
#define __CEF_CLIENT_HEADER__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#ifndef CefC_Android
#include <sys/fcntl.h>
#else // CefC_Android
#include <fcntl.h>
#endif // CefC_Android
#include <unistd.h>
#include <sys/un.h>

#include <cefore/cef_define.h>
#include <cefore/cef_frame.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

#define CefC_App_Reg				0x01
#define CefC_App_DeReg				0x02
#define CefC_App_RegPrefix			0x03		/* for prefix match 					*/
#define CefC_App_RegPit				0x04
#define CefC_App_DeRegPit			0x05

#define CefC_Unset_Port 			0
#define CefC_Unset_Id 				NULL

#ifndef CefC_Android
#define CefC_AppBuff_Size			10000000
#else // CefC_Android
#define CefC_AppBuff_Size			200000
#endif // CefC_Android

#define CefC_App_Magic_No		0xbe736ffa


/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/

/***** Client Handle 					*****/
typedef size_t CefT_Client_Handle;

/***** Connection to an application 	*****/
typedef struct {
	int 	sock;							/* File descriptor 							*/
	struct addrinfo* ai;					/* addrinfo of this connection 				*/
	uint32_t seqnum;
} CefT_Connect;

/****************************************************************************************
 Global Variables
 ****************************************************************************************/



/****************************************************************************************
 Function Declarations
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Sets the local socket name 
----------------------------------------------------------------------------------------*/
int 
cef_client_init (
	int port_num, 
	const char* config_file_dir
);
/*--------------------------------------------------------------------------------------
	Gets the local socket name 
----------------------------------------------------------------------------------------*/
int 
cef_client_local_sock_name_get (
	char* local_sock_name
);
/*--------------------------------------------------------------------------------------
	Gets the local socket name for cefbabeld
----------------------------------------------------------------------------------------*/
int 
cef_client_babel_sock_name_get (
	char* local_sock_name
);
/*--------------------------------------------------------------------------------------
	Gets the config file directory
----------------------------------------------------------------------------------------*/
int 
cef_client_config_dir_get (
	char* config_dir
);
/*--------------------------------------------------------------------------------------
	Gets the listen port number
----------------------------------------------------------------------------------------*/
int 
cef_client_listen_port_get (
	void 
);
/*--------------------------------------------------------------------------------------
	Creats the client handle
----------------------------------------------------------------------------------------*/
CefT_Client_Handle 								/* created client handle 				*/
cef_client_connect (
	void
);
/*--------------------------------------------------------------------------------------
	Creats the client handle with the SOCK_DGRAM socket
----------------------------------------------------------------------------------------*/
CefT_Client_Handle 								/* created client handle 				*/
cef_client_connect_srv (
	void
);
/*--------------------------------------------------------------------------------------
	Creats the client handle with the SOCK_STREAM socket
----------------------------------------------------------------------------------------*/
CefT_Client_Handle 								/* created client handle 				*/
cef_client_connect_cli (
	void
);
/*--------------------------------------------------------------------------------------
	Creats the client handle with the specified type of socket
----------------------------------------------------------------------------------------*/
CefT_Client_Handle 								/* created client handle 				*/
cef_client_connect_cli_core (
	int sk_type									/* type of socket 						*/
);
/*--------------------------------------------------------------------------------------
	Destroys the specified client handle
----------------------------------------------------------------------------------------*/
void 
cef_client_close (
	CefT_Client_Handle fhdl 					/* client handle to be destroyed 		*/
);
/*--------------------------------------------------------------------------------------
	Inputs the unformatted message into socket
----------------------------------------------------------------------------------------*/
int
cef_client_message_input (
	CefT_Client_Handle fhdl,					/* client handle 						*/
	unsigned char* msg,							/* message 								*/
	size_t len									/* length of message 					*/
);
/*--------------------------------------------------------------------------------------
	Inputs the interest to the cefnetd
----------------------------------------------------------------------------------------*/
int												/* length of the created interest 		*/
cef_client_interest_input (
	CefT_Client_Handle fhdl,					/* client handle 						*/
	CefT_Interest_TLVs* tlvs					/* parameters to create the interest 	*/
);
/*--------------------------------------------------------------------------------------
	Reads the message from the specified connection (socket)
----------------------------------------------------------------------------------------*/
int 											/* length of read buffer 				*/
cef_client_read (
	CefT_Client_Handle fhdl, 					/* client handle 						*/
	unsigned char* buff, 						/* buffer to write the message 			*/
	int len 									/* length of buffer 					*/
);
/*--------------------------------------------------------------------------------------
	Obtains one message from the buffer
----------------------------------------------------------------------------------------*/
int 											/* remaining length of buffer 			*/
cef_client_payload_get (
	unsigned char* buff, 						/* buffer 								*/
	int buff_len, 								/* length of buffer 					*/
	unsigned char* msg, 						/* variable to write one message 		*/
	int* frame_size 							/* length of one message 				*/
);
/*--------------------------------------------------------------------------------------
	Obtains one message from the buffer
----------------------------------------------------------------------------------------*/
int 											/* remaining length of buffer 			*/
cef_client_payload_get_with_info (
	unsigned char* buff, 
	int buff_len, 
	struct cef_app_frame* app_frame
);
/*--------------------------------------------------------------------------------------
	Obtains one Interest message from the buffer
----------------------------------------------------------------------------------------*/
int 											/* remaining length of buffer 			*/
cef_client_request_get_with_info (
	unsigned char* buff, 
	int buff_len, 
	struct cef_app_request* app_request
);
/*--------------------------------------------------------------------------------------
	Obtains one Raw data from the buffer
----------------------------------------------------------------------------------------*/
int 											/* remaining length of buffer 			*/
cef_client_rawdata_get (
	unsigned char* buff, 						/* buffer 								*/
	int buff_len,								/* length of buffer 					*/
	unsigned char* frame,						/* get frame							*/
	int* frame_len,								/* length of frame						*/
	int* frame_type								/* type of frame						*/
);
/*--------------------------------------------------------------------------------------
	Inputs the object to the cefnetd
----------------------------------------------------------------------------------------*/
int												/* length of the created object 		*/
cef_client_object_input (
	CefT_Client_Handle fhdl,					/* client handle 						*/
	CefT_Object_TLVs* tlvs						/* parameters to create the object 		*/
);
/*--------------------------------------------------------------------------------------
	Inputs the cefping to the cefnetd
----------------------------------------------------------------------------------------*/
int												/* length of the created cefping 		*/
cef_client_cefping_input (
	CefT_Client_Handle fhdl,					/* client handle 						*/
	CefT_Ping_TLVs* tlvs						/* parameters to create the cefping		*/
);
/*--------------------------------------------------------------------------------------
	Inputs the cefinfo request to the cefnetd
----------------------------------------------------------------------------------------*/
int												/* length of the created cefinfo 		*/
cef_client_cefinfo_input (
	CefT_Client_Handle fhdl,					/* client handle 						*/
	CefT_Trace_TLVs* tlvs						/* parameters to create the cefinfo	*/
);
/*--------------------------------------------------------------------------------------
	Register/Deregister the specified Name of the Application
----------------------------------------------------------------------------------------*/
void
cef_client_name_reg (
	CefT_Client_Handle fhdl, 					/* client handle						*/
	uint16_t func, 								/* CefC_App_Reg/CefC_App_DeReg 			*/
	const unsigned char* name,					/* Name (not URI)						*/
	uint16_t name_len							/* length of the Name					*/
);
/*--------------------------------------------------------------------------------------
	Register/Deregister the specified Name of the Application (accept prefix match of Name)
----------------------------------------------------------------------------------------*/
void
cef_client_prefix_reg (
	CefT_Client_Handle fhdl, 					/* client handle						*/
	uint16_t func, 								/* CefC_App_Reg/CefC_App_DeReg 			*/
	const unsigned char* name,					/* Name (not URI)						*/
	uint16_t name_len							/* length of the Name					*/
);
/*--------------------------------------------------------------------------------------
	Register/Deregister the specified Name of the Application in PIT
----------------------------------------------------------------------------------------*/
void
cef_client_prefix_reg_for_pit (
	CefT_Client_Handle fhdl, 					/* client handle						*/
	uint16_t func, 								/* CefC_App_Reg/CefC_App_DeReg 			*/
	const unsigned char* name,					/* Name (not URI)						*/
	uint16_t name_len							/* length of the Name					*/
);

uint64_t
cef_client_covert_timeval_to_us (
	struct timeval t
);
uint64_t
cef_client_present_timeus_calc (
	void
);
uint64_t
cef_client_present_timeus_get (
	void
);
uint64_t
cef_client_htonb (
	uint64_t x
);

uint64_t
cef_client_ntohb (
	uint64_t x
);

#endif // __CEF_CLIENT_HEADER__

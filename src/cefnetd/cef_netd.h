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
 * cef_netd.h
 */

#ifndef __CEF_NETD_HEADER__
#define __CEF_NETD_HEADER__

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

#ifndef CefC_Android
#include <ifaddrs.h>
#else // CefC_Android
#include <cefore/cef_android.h>
#endif // CefC_Android
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
#include <cefore/cef_plugin.h>
#include <cefore/cef_valid.h>
#include <cefore/cef_log.h>

#ifdef CefC_Ccore
#include <ccore/ccore_common.h>
#include <ccore/ccore_define.h>
#include <ccore/ccore_frame.h>
#include <ccore/ccore_valid.h>
#endif // CefC_Ccore

#ifdef CefC_Ccninfo
#include <cefore/cef_ccninfo.h>
#endif // CefC_Ccninfo
#ifdef CefC_Ser_Log
#include <cefore/cef_ser_log.h>
#endif // CefC_Ser_Log

/****************************************************************************************
 Macros
 ****************************************************************************************/

/*------------------------------------------------------------------*/
/* Commands to control cefnetd										*/
/*------------------------------------------------------------------*/

#define CefC_Ctrl					"/CTRL"
#define CefC_Ctrl_Len				strlen(CefC_Ctrl)
#define CefC_Ctrl_Kill				"STOP"
#define CefC_Ctrl_Kill_Len			strlen(CefC_Ctrl_Kill)
#define CefC_Ctrl_Status			"STATUS"
#define CefC_Ctrl_Status_Len		strlen(CefC_Ctrl_Status)
#define CefC_Ctrl_StatusPit			"STATUSPIT"
#define CefC_Ctrl_StatusPit_Len		strlen(CefC_Ctrl_StatusPit)
#define CefC_Ctrl_Route				"ROUTE"
#define CefC_Ctrl_Route_Len			strlen(CefC_Ctrl_Route)
#define CefC_Ctrl_Babel				"BABEL"
#define CefC_Ctrl_Babel_Len			strlen(CefC_Ctrl_Babel)
#define CefC_Ctrl_User_Len			256
#ifdef CefC_Ser_Log
#define CefC_Ctrl_Ser_Log			"SERLOG"
#define CefC_Ctrl_Ser_Log_Len		strlen(CefC_Ctrl_Route)
#endif // CefC_Ser_Log
#define CefC_App_Conn_Num			64
#define CefC_Cmd_Num_Max			256
#define CefC_Cmd_Len_Max			1024
#define CefC_Name_Len_Max			512
#define CefC_Nbr_Len_Max			64
#define CefC_Protocol_Name			8

#ifdef CefC_Android
#define CefC_Listen_Face_Max		8
#else // CefC_Android
#define CefC_Listen_Face_Max		32
#endif // CefC_Android

/*------------------------------------------------------------------*/
/* Neighbor Management												*/
/*------------------------------------------------------------------*/

#define CefC_Max_Uri 				32			/* Maximum URI Count 					*/
#define CefC_Max_Nbr 				32			/* Maximum Neighbor Count 				*/
#define CefC_Fail_Thred				3			/* Threadshold to estimate link failure	*/


/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/

/********** Neighbor Management 	***********/
typedef struct {
	
	char 				uri[CefC_Name_Len_Max];
	unsigned char 		name[CefC_Max_Length];
	int 				name_len;
	int* 				nbr_idx;
	int* 				nbr_shnum;
	int 				nbr_num;
	
	int 				con_max;
	int* 				con_nbr;
	int 				con_num;
	
} CefT_Uris;

typedef struct {
	
	char 				nbr[CefC_Nbr_Len_Max];
	char 				protocol[8];
	uint16_t 			faceid;
	int 				fd;
	uint64_t 			rtt;
	uint8_t 			active_f;
	uint8_t 			fd_tcp_f;
	int 				fail_num;
	
} CefT_Nbrs;

/********** cefned main handle  	***********/
typedef struct {
	
	char 				launched_user_name[CefC_Ctrl_User_Len];
	
	/********** Key Information 	***********/
	uint8_t				node_type;				/* CefC_Node_Type_xxx					*/
	uint64_t 			nowtus;
	
	/********** NodeID (IP Address) ***********/
	unsigned char 		top_nodeid[16];
	uint16_t 			top_nodeid_len;
	unsigned char** 	nodeid4;
	unsigned char** 	nodeid16;
	int 				nodeid4_num;
	int 				nodeid16_num;
	unsigned int** 		nodeid4_mtu;	/* For ccninfo reply size check */
	unsigned int** 		nodeid16_mtu;	/* For ccninfo reply size check */
	unsigned int		lo_mtu;			/* For ccninfo reply size check */
	unsigned int		top_nodeid_mtu;	/* For ccninfo reply size check */
	
	/********** Listen Port 		***********/
	struct pollfd 		inudpfds[CefC_Listen_Face_Max];
	uint16_t 			inudpfaces[CefC_Listen_Face_Max];
	uint8_t				inudpfdc;

	struct pollfd 		intcpfds[CefC_Listen_Face_Max];
	uint16_t 			intcpfaces[CefC_Listen_Face_Max];
	uint8_t				intcpfdc;
	
	struct pollfd 		inndnfds[CefC_Listen_Face_Max];
	uint16_t 			inndnfaces[CefC_Listen_Face_Max];
	uint8_t				inndnfdc;
	
	/********** Parameters 			***********/
	uint16_t 			port_num;				/* Port Number							*/
	uint16_t 			fib_max_size;			/* Maximum FIB entry 					*/
	uint32_t 			pit_max_size;			/* Maximum PIT entry 					*/
	int		 			sk_type;				/* Type of socket 						*/
	uint16_t 			nbr_max_size;
	uint64_t 			nbr_mng_intv;
	uint16_t 			nbr_mng_thread;
	uint16_t 			fwd_rate;
	uint8_t 			cs_mode;
	uint32_t 			forwarding_info_strategy;
												/* FIB entry selection strategy.		*/
												/*   0: Forward using 					*/
												/*      any 1 match FIB entry			*/
												/*   1: Forward using 					*/
												/*      all match FIB entries			*/
#ifdef CefC_Ccninfo
	uint32_t 			ccninfo_access_policy;	/* CCNinfo access policy				*/
												/*   0: No limit						*/
												/*   1: Permit transfer only			*/
												/*   2: Do not allow access				*/
	uint32_t 			ccninfo_full_discovery;	/* "Full discovery request" 			*/
												/* permission setting					*/
												/*   0: Allow							*/
												/*   1: Not Allow						*/
												/*   2: Authentication and Authorization*/
	char				ccninfo_valid_alg[256];	/* Specify the Validation Algorithm 	*/
												/* to be added to Cefnifo Reply.		*/
												/* Validation is not added when NONE is */
												/* specified.							*/
												/* Either sha256 or crc32 can be 		*/
												/* specified.							*/
	uint16_t			ccninfo_valid_type;		/* Specify the Validation Algorithm 	*/
												/* to be added to Cefnifo Reply.		*/
	char				ccninfo_sha256_key_prfx[256];
												/* Private key, public key prefix		*/
												/*   Private key name: 					*/
												/*     Specified string + "-private-key"*/
												/*   Public key name: 					*/
												/*     Specified string + "-public-key" */
	uint32_t 			ccninfo_reply_timeout;	/* PIT lifetime(seconds) at 			*/
												/* "full discovery request"				*/
												/*  This value must be 					*/
												/*  higher than or equal to 2 			*/
												/*  and lower than or equal to 5.		*/
#endif // CefC_Ccninfo
	/********** Tables				***********/
	CefT_Hash_Handle	fib;					/* FIB 									*/
	CefT_Hash_Handle	pit;					/* PIT 									*/
	uint8_t 			cefrt_seed;
	uint16_t			cmd_filter[CefC_Cmd_Num_Max];
	uint16_t			cmd_len[CefC_Cmd_Num_Max];
	unsigned char		cmd[CefC_Cmd_Num_Max][CefC_Cmd_Len_Max];

	/********** Local Sockets		***********/
	int 				app_fds[CefC_App_Conn_Num];
	int 				app_faces[CefC_App_Conn_Num];
	int 				app_steps[CefC_App_Conn_Num];
	uint8_t				app_fds_num;

	/********** Timers				***********/
	uint64_t			pit_clean_t;
	uint32_t 			pit_clean_i;
	uint64_t			fib_clean_t;
	uint32_t 			fib_clean_i;
	
	/********** Statistics 			***********/
	uint64_t 			stat_recv_frames;
	uint64_t 			stat_send_frames;

	/********** Content Store		***********/
	CefT_Cs_Stat*		cs_stat;				/* Status of Content Store				*/
#if (defined CefC_ContentStore) || (defined CefC_Dtc) \
	|| (defined CefC_Conpub) || (defined CefC_CefnetdCache)
	double				send_rate;				/* send content rate					*/
	uint64_t			send_next;				/* Send content next					*/
#endif // CefC_ContentStore || CefC_Conpub
	
	/********** Neighbor Management ***********/
	CefT_Uris* 			uris;				/* URIs are specified in neighbor list 		*/
	uint8_t 			uri_num;			/* URI count in neighbor list 				*/
	CefT_Nbrs* 			nbrs;				/* Neighbors are specified in neighbor list */
	CefT_Rtts* 			rtts;
	uint8_t 			nbr_num;			/* Neighbor count in neighbor list 			*/
	uint64_t 			nbr_next_t;			/* time which cefnetd will send the link 	*/
											/* request message to measure RTT between 	*/
											/* two cefnetds [unit:us]					*/
	uint64_t 			nbr_base_t;
	uint64_t 			nbr_wait_t;
	
	/********** App Resister 		***********/
	CefT_Hash_Handle	app_reg;				/* App Resister table					*/
	CefT_Hash_Handle	app_pit;				/* App Resister PIT						*/
	
	/********** Plugin 				***********/
	CefT_Plugin_Handle 	plugin_hdl;
	
#ifdef CefC_Ccore
	/********** Controller 			***********/
	CcoreT_Rt_Handle* 	rt_hdl;
#endif
	
	/********** Babel 				***********/
	int 				babel_use_f;
	int 				babel_sock;
	int 				babel_face;
	int 				babel_route;

#ifdef CefC_Dtc
	/********** Cefore-DTC 			***********/
	uint64_t			dtc_resnd_t;
#endif // CefC_Dtc
	
#ifdef CefC_Ccninfo
	/********** Ccninfo				***********/
	uint16_t 			ccninfousr_id_len;
	unsigned char   	ccninfousr_node_id[CefC_Max_Node_Id];
	int 				ccninfo_rcvdpub_key_bi_len;
	unsigned char* 		ccninfo_rcvdpub_key_bi;
#endif //CefC_Ccninfo
	
} CefT_Netd_Handle;

/****************************************************************************************
 Global Variables
 ****************************************************************************************/



/****************************************************************************************
 Function Declarations
 ****************************************************************************************/
int
cef_node_run (
	void
);
/*--------------------------------------------------------------------------------------
	Creates and initialize the cefnetd handle
----------------------------------------------------------------------------------------*/
CefT_Netd_Handle* 								/* the created cefnetd handle			*/
cefnetd_handle_create (
	uint8_t 	node_type						/* Node Type (Router/Receiver....)		*/
);
/*--------------------------------------------------------------------------------------
	Destroys the cefnetd handle
----------------------------------------------------------------------------------------*/
void
cefnetd_handle_destroy (
	CefT_Netd_Handle* hdl						/* cefnetd handle to destroy			*/
);
/*--------------------------------------------------------------------------------------
	Main Loop Function
----------------------------------------------------------------------------------------*/
void
cefnetd_event_dispatch (
	CefT_Netd_Handle* hdl 						/* cefnetd handle						*/
);
/*--------------------------------------------------------------------------------------
	Forwards the specified Interest
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cefnetd_interest_forward (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	uint16_t faceids[], 					/* Face-IDs to forward						*/
	uint16_t faceid_num, 					/* Number of Face-IDs to forward			*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	CefT_Parsed_Message* pm, 				/* Parsed message 							*/
	CefT_Parsed_Opheader* poh, 				/* Parsed Option Header						*/
	CefT_Pit_Entry* pe, 					/* PIT entry matching this Interest 		*/
	CefT_Fib_Entry* fe						/* FIB entry matching this Interest 		*/
);
/*--------------------------------------------------------------------------------------
	Forwards the specified ccninfo request
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cefnetd_ccninforeq_forward (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	uint16_t faceids[], 					/* Face-IDs to forward						*/
	uint16_t faceid_num, 					/* Number of Face-IDs to forward			*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	CefT_Parsed_Message* pm, 				/* Parsed message 							*/
	CefT_Parsed_Opheader* poh, 				/* Parsed Option Header						*/
	CefT_Pit_Entry* pe, 					/* PIT entry matching this Interest 		*/
	CefT_Fib_Entry* fe						/* FIB entry matching this Interest 		*/
);
/*--------------------------------------------------------------------------------------
	Forwards the specified cefping request
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cefnetd_cefpingreq_forward (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	uint16_t faceids[], 					/* Face-IDs to forward						*/
	uint16_t faceid_num, 					/* Number of Face-IDs to forward			*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	CefT_Parsed_Message* pm, 				/* Parsed message 							*/
	CefT_Parsed_Opheader* poh, 				/* Parsed Option Header						*/
	CefT_Pit_Entry* pe, 					/* PIT entry matching this Interest 		*/
	CefT_Fib_Entry* fe						/* FIB entry matching this Interest 		*/
);
/*--------------------------------------------------------------------------------------
	Forwards the specified Content Object
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cefnetd_object_forward (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	uint16_t faceids[], 					/* Face-IDs to forward						*/
	uint16_t faceid_num, 					/* Number of Face-IDs to forward			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	CefT_Parsed_Message* pm, 				/* Parsed message 							*/
	CefT_Parsed_Opheader* poh, 				/* Parsed Option Header						*/
	CefT_Pit_Entry* pe	 					/* PIT entry matching this Interest 		*/
);

/*--------------------------------------------------------------------------------------
	Inits neighbor management
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cefnetd_nbr_init (
	CefT_Netd_Handle* hdl					/* cefnetd handle							*/
);

/*--------------------------------------------------------------------------------------
	Manages the neighbor cefnetd status
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cefnetd_nbr_management (
	CefT_Netd_Handle* hdl, 					/* cefnetd handle							*/
	uint64_t nowt							/* current time (usec) 						*/
);

/*--------------------------------------------------------------------------------------
	Records RTT
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cefnetd_nbr_rtt_record (
	CefT_Netd_Handle* hdl, 					/* cefnetd handle							*/
	uint64_t nowt,							/* current time (usec) 						*/
	int faceid
);
/*--------------------------------------------------------------------------------------
	Close neighbor management
----------------------------------------------------------------------------------------*/
void 
cefnetd_nbr_destroy (
	CefT_Netd_Handle* hdl					/* cefnetd handle							*/
);

/*--------------------------------------------------------------------------------------
	Ccninfo Full discobery authentication & authorization
----------------------------------------------------------------------------------------*/
int											/* Returns 0 if authentication 				*/
											/* and authorization are OK 				*/
cefnetd_ccninfo_fulldiscovery_authNZ(
	uint16_t 		usr_id_len,
	unsigned char*  usr_node_id,
	int 			rcvdpub_key_bi_len,
	unsigned char* 	rcvdpub_key_bi
);
/*--------------------------------------------------------------------------------------
	Check Ccninfo Relpy size
	  NOTE: When oversize, create a reply message of NO_SPECE
----------------------------------------------------------------------------------------*/
uint16_t
cefnetd_ccninfo_check_relpy_size(
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	unsigned char* msg, 					/* Reply message							*/
	uint16_t msg_len 						/* Length of this message			*/
);

#endif // __CEF_NETD_HEADER__

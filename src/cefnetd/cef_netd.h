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
#define __USE_GNU		// for pthread_sigqueue
#include <signal.h>
#include <poll.h>
#include <limits.h>
#include <openssl/md5.h>
#include <dlfcn.h>

#include <ifaddrs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <openssl/sha.h>	//0.8.3

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
#include <cefore/cef_pthread.h>

#include <cefore/cef_ccninfo.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

/* Library name libcefnetd_fwd_plugin		*/
#ifdef __APPLE__
#define CefnetdC_FwdPlugin_Library_Name		"libcefnetd_fwd_plugin.dylib"
#else // __APPLE__
#define CefnetdC_FwdPlugin_Library_Name		"libcefnetd_fwd_plugin.so"
#endif // __APPLE__

#define	FALSE	0
#if	((defined CefC_Csmgr) || (defined CefC_Conpub) || (defined CefC_CefnetdCache))
#define	CefC_IsEnable_ContentStore	(~FALSE)
#else
#define	CefC_IsEnable_ContentStore	FALSE
#endif

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
#define CefC_Ctrl_StatusStat		"STATUSSTAT"
#define CefC_Ctrl_StatusStat_Len	strlen(CefC_Ctrl_StatusStat)
#define CefC_Ctrl_Route				"ROUTE"
#define CefC_Ctrl_Route_Len			strlen(CefC_Ctrl_Route)
#define CefC_Ctrl_Babel				"BABEL"
#define CefC_Ctrl_Babel_Len			strlen(CefC_Ctrl_Babel)
#define CefC_Ctrl_User_Len			256
#define CefC_App_Conn_Num			64
#define CefC_Cmd_Num_Max			256
#define CefC_Cmd_Len_Max			1024
#define CefC_Cefstatus_MsgSize		128

#define CefC_Listen_Face_Max		CefC_Face_Router_Max
#define	CefC_TxWorkerMax			32
#define	CefC_TxWorkerDefault		(CefC_TxWorkerMax/4)
#define	CefC_TxQueueDefault			(CefC_Tx_Que_Size*CefC_TxWorkerMax)

/* cefstatus output option */
#define CefC_Ctrl_StatusOpt_Stat	0x0001
#define CefC_Ctrl_StatusOpt_Metric	0x0002
#if ((defined CefC_CefnetdCache) && (defined CefC_Develop))
#define CefC_Ctrl_StatusOpt_LCache	0x0004
#endif //((defined CefC_CefnetdCache) && (defined CefC_Develop))
#define CefC_Ctrl_StatusOpt_Numofpit	0x0008

/* cefstatus output option */
#if ((defined CefC_Develop))
#define CefC_Ctrl_StatusOpt_FibOnly	0x0100
#define CefC_Ctrl_StatusOpt_FibInetOnly		0x0200
#define CefC_Ctrl_StatusOpt_FibV4UdpOnly	0x0400
#endif //((defined CefC_Develop))


/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/

/********** cefnetd main handle  	***********/
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
	char**				nodeid4_c;		/* char */
	char**				nodeid16_c;		/* char */
	unsigned int** 		nodeid4_mtu;	/* For ccninfo reply size check */
	unsigned int** 		nodeid16_mtu;	/* For ccninfo reply size check */
	unsigned int		lo_mtu;			/* For ccninfo reply size check */
	unsigned int		top_nodeid_mtu;	/* For ccninfo reply size check */

	/********** Listen Port 		***********/
	struct pollfd 		inudpfds[CefC_Listen_Face_Max];
	uint16_t 			inudpfaces[CefC_Listen_Face_Max];
	uint16_t			inudpfdc;

	struct pollfd 		intcpfds[CefC_Listen_Face_Max];
	uint16_t 			intcpfaces[CefC_Listen_Face_Max];
	uint16_t			intcpfdc;

	char 				udp_listen_addr[CefC_NAME_BUFSIZ];

	/********** Parameters 			***********/
	uint16_t 			port_num;				/* Port Number							*/
	uint32_t 			fib_max_size;			/* Maximum FIB entry 					*/
	uint32_t 			pit_max_size;			/* Maximum PIT entry 					*/
	int		 			sk_type;				/* Type of socket 						*/
	uint64_t 			nbr_mng_intv;
	uint16_t 			fwd_rate;
	uint8_t 			cs_mode;
	char*				forwarding_strategy;	/* FIB entry selection strategy.		*/
												/*  default:							*/
												/*      Forward using					*/
												/*      any 1 match FIB entry			*/
												/*  flooding:							*/
												/*      Forward using					*/
												/*      all match FIB entries			*/
												/*  shortest_path:						*/
												/*      Forward using					*/
												/*      the Lowest Routing Cost			*/
												/*      in match FIB entries			*/
												/*  and any more...						*/
	uint32_t			app_fib_max_size;		/* Maximum FIB(APP) entry 				*/
	uint32_t			app_pit_max_size;		/* Maximum PIT(APP) entry 				*/
	char*				My_Node_Name;			/* Node Name							*/
	unsigned char*		My_Node_Name_TLV;		/* Node Name TLV						*/
	int					My_Node_Name_TLV_len;	/* Node Name TLV Length					*/
	//0.8.3
	int					InterestRetrans;		/* 0:RFC8599 1:NO_SUPPRESSION			*/
	int					Selective_fwd;			/* 0:Not FWD 1:FWD */
	int					SymbolicBack;			/* */
	double				IR_Congestion;			/* */
	int					BW_Stat_interval;
	int					Symbolic_max_lifetime;
	int					Regular_max_lifetime;
	int					Ex_Cache_Access;		/* 0:Read/Write   1:ReadOnly			*/
	uint32_t			Buffer_Cache_Time;		/* Buffer cahce timt					*/
												/* for KeyIdRestriction					*/
												/* Private key, public key prefix		*/
												/*   Private key name: 					*/
												/*     Specified string + "-private-key"*/
												/*   Public key name: 					*/
												/*     Specified string + "-public-key" */
	/*202108*/
	int					IR_Option;				/* Interest Return Option 0:Not Create & Forward */
												/* 						  1:Create & Forward */
	int					IR_enable[10];			/* ENABLED_RETURN_CODE 0:Disabled 1:Enabled */
	//20220311
	uint32_t			Selective_max_range;

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
												/* Either rsa-sha256 or crc32c can be 	*/
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
	uint32_t 			app_pit_clean_i;
	uint64_t			face_clean_t;
	int16_t				face_lifetime;

	/********** Statistics 			***********/
	uint64_t 			stat_recv_frames;				/* Count of Received ContentObject */
	uint64_t 			stat_send_frames;				/* Count of Send ContentObject	*/
	uint64_t			stat_recv_interest;				/* Count of Received Interest	*/
	uint64_t			stat_recv_interest_types[3];	/* Count of Received Interest by type */
														/* 0:Regular, 1:Symbolic, 2:Selective */
	uint64_t			stat_send_interest;				/* Count of Send Interest		*/
	uint64_t			stat_send_interest_types[3];	/* Count of Send Interest by type */
														/* 0:Regular, 1:Symbolic, 2:Selective */

	/********** Content Store		***********/
	CefT_Cs_Stat*		cs_stat;				/* Status of Content Store				*/
#if CefC_IsEnable_ContentStore
	double				send_rate;				/* send content rate					*/
	uint64_t			send_next;				/* Send content next					*/
#endif // CefC_IsEnable_ContentStore

	/********** App Resister 		***********/
	CefT_Hash_Handle	app_reg;				/* App Resister table					*/
	CefT_Hash_Handle	app_pit;				/* App Resister PIT						*/

	/********** Plugin 				***********/
	CefT_Plugin_Handle 	plugin_hdl;

	/********** Babel 				***********/
	int 				babel_use_f;
	int 				babel_sock;
	int 				babel_face;
	int 				babel_route;

	/********** Ccninfo				***********/
	uint16_t 			ccninfousr_id_len;
	unsigned char   	ccninfousr_node_id[CefC_Max_Node_Id];
	int 				ccninfo_rcvdpub_key_bi_len;
	unsigned char* 		ccninfo_rcvdpub_key_bi;

	/********** cefstatus pipe **********/
	int		cefstatus_pipe_fd[2];
	unsigned char *app_rsp_msg;

	/********** Forwarding Strategy Plugin **********/
	CefT_Plugin_Fwd_Strtgy*		fwd_strtgy_hdl;
	void*						fwd_strtgy_lib;

	/*** cefore tx queue 						***/
//#define CefC_TxMultiThread
	CefT_Rngque		*tx_que, *tx_que_high, *tx_que_low;

#ifdef CefC_TxMultiThread
	uint16_t 			tx_worker_num;
	CefT_Rngque* 		tx_worker_que[CefC_TxWorkerMax];
	pthread_cond_t		tx_worker_cond[CefC_TxWorkerMax];
	pthread_mutex_t		tx_worker_mutex[CefC_TxWorkerMax];
#endif // CefC_TxMultiThread

	uint	 			tx_que_size;
	CefT_Mp_Handle 		tx_que_mp;

} CefT_Netd_Handle;

typedef struct {
	unsigned char	msg[CefC_Cefstatus_MsgSize];
	int				resp_fd;
}	CefT_Cefstatus_Msg;

typedef struct {
	uint16_t 		faceid;
	unsigned char 	name[CefC_NAME_MAXLEN];
	uint16_t 		name_len;
	uint8_t 		match_type;				/* Exact or Prefix */
} CefT_App_Reg;

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
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed message 							*/
	CefT_CcnMsg_OptHdr* poh, 				/* Parsed Option Header						*/
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
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed message 							*/
	CefT_CcnMsg_OptHdr* poh, 				/* Parsed Option Header						*/
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
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed message 							*/
	CefT_CcnMsg_OptHdr* poh 				/* Parsed Option Header						*/
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
	uint16_t msg_len, 						/* Length of this message			*/
	uint16_t ccninfo_flag					/* ccninfo_flag ccninfo-05 */
);


/*--------------------------------------------------------------------------------------
	Handles the elements of TX queue
----------------------------------------------------------------------------------------*/
void *
cefnetd_cefstatus_thread (
	void *p									/* cefnetd handle							*/
);

void
cefnetd_frame_send_core (
	void*			hdl,					/* cefnetd handle							*/
	uint16_t 		faceid_num, 			/* number of Face-ID				 		*/
	uint16_t 		faceid[], 				/* Face-ID indicating the destination 		*/
	unsigned char* 	msg, 					/* a message to send						*/
	size_t			msg_len,				/* length of the message to send 			*/
	CefT_TxQueClass	tx_prio,				/* priority									*/
	int				tx_copies				/* copies 									*/
);

void
cefnetd_frame_send_normal (
	void*			hdl,					/* cefnetd handle							*/
	uint16_t 		faceid, 				/* Face-ID indicating the destination 		*/
	unsigned char* 	msg, 					/* a message to send						*/
	size_t			msg_len					/* length of the message to send 			*/
);

/*--------------------------------------------------------------------------------------
	Reads the FIB configuration file
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cefnetd_config_fib_read (
	CefT_Netd_Handle* hdl					/* cefnetd handle							*/
);
/*--------------------------------------------------------------------------------------
	Add route in FIB
----------------------------------------------------------------------------------------*/
int
cefnetd_fib_route_add (
	CefT_Hash_Handle fib,					/* FIB										*/
	int faceid,								/* face id									*/
	uint8_t fe_type,						/* CefC_Fib_Entry_XXX				0.8.3c	*/
	CefT_Fib_Metric	*fib_metric,			//0.8.3c
	int name_len,
	unsigned char *name,
	int keyid_len,							/* extantion for full-source forwarding		*/
	unsigned char *keyid					/* extantion for full-source forwarding		*/
);
/*--------------------------------------------------------------------------------------
	Delete route in FIB
----------------------------------------------------------------------------------------*/
int
cefnetd_fib_route_del (
	CefT_Hash_Handle fib,					/* FIB										*/
	int faceid,								/* face id									*/
	uint8_t fe_type,						/* CefC_Fib_Entry_XXX				0.8.3c	*/
	int name_len,
	unsigned char *name,
	int keyid_len,
	unsigned char *keyid
);
/*--------------------------------------------------------------------------------------
	Check Input Cefroute msg
----------------------------------------------------------------------------------------*/
int
cefnetd_route_msg_check (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	unsigned char* msg,						/* received message to handle				*/
	int msg_size							/* size of received message(s)				*/
);

/*--------------------------------------------------------------------------------------
	Obtain the Name from the received route message
----------------------------------------------------------------------------------------*/
int
cefnetd_fib_name_get_from_route_msg (
	unsigned char* msg, 					/* the received message(s)					*/
	int msg_size,
	unsigned char* name
);
/*--------------------------------------------------------------------------------------
	Process the FIB route message
----------------------------------------------------------------------------------------*/
int
cefnetd_fib_route_msg_process (
	CefT_Hash_Handle fib,					/* FIB										*/
	unsigned char* msg, 					/* the received message(s)					*/
	int msg_size,							/* size of received message(s)				*/
	uint8_t type,							/* CefC_Fib_Entry_XXX						*/
	int* rc, 								/* 0x01=New Entry, 0x02=Free Entry 0.8.3c	*/
	CefT_Fib_Metric*	fib_metric
);
/*--------------------------------------------------------------------------------------
	Handles the request forwarding infomation for CefBabel
----------------------------------------------------------------------------------------*/
int
cefnetd_request_forwarding_info (
	CefT_Netd_Handle* hdl,
	unsigned char** rsp_msgpp
);
/*--------------------------------------------------------------------------------------
	Handles the retrieve forwarding infomation for Ccore
----------------------------------------------------------------------------------------*/
int
cefnetd_retrieve_forwarding_info (
	CefT_Hash_Handle* fib,
	char* info_buff,
	int info_buff_size,
	const unsigned char* name,
	int name_len,
	int partial_match_f
);
#endif // __CEF_NETD_HEADER__

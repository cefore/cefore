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
 * cef_netd.c
 */

#define __CEF_NETD_SOURECE__

// #define	DEB_CCNINFO
/****************************************************************************************
 Include Files
 ****************************************************************************************/
#ifdef __APPLE__
#define __APPLE_USE_RFC_3542
#endif //__APPLE
#include "cef_netd.h"
#include "cef_status.h"
#ifdef __APPLE__
#include <sys/socket.h>
#include <netinet/in.h>
#endif //__APPLE

#include <sys/ioctl.h>

#ifdef DEB_CCNINFO
#include <ctype.h>
#endif //DEB_CCNINFO

#define	CefC_BufSiz_1KB			1024
#define	CefC_BufSiz_2KB			2048
#define	CefC_KeyIdSiz			CefC_KeyId_SIZ

//#define	_DEBUG_BABEL_

/****************************************************************************************
 Macros
 ****************************************************************************************/

/* The number of processing function of message (invalid/Interest/Object) 	*/
#define CefC_Msg_Process_Num		7

#define CEFRTHASH8(_p, _seed, _limit)				\
	do {											\
		int _i0;									\
		unsigned char* _wp = (unsigned char*) _p;	\
		for (_i0 = 0 ; _i0 < _limit ; _i0++) {		\
			_seed = _seed * 33 + _wp[_i0];			\
		}											\
	} while (0)

typedef	enum	{
	CefC_Connection_Type_Udp = 0,
	CefC_Connection_Type_Tcp,
	CefC_Connection_Type_Csm,
	CefC_Connection_Type_Num,
	CefC_Connection_Type_Local = 99,
}	CefC_Connection_Type;


#define CefC_App_MatchType_Exact		0
#define CefC_App_MatchType_Prefix		1

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

struct cef_hdr {
	uint8_t 	version;
	uint8_t 	type;
	uint16_t 	pkt_len;
	uint8_t		hoplimit;
	uint8_t		reserve1;
	uint8_t		reserve2;
	uint8_t 	hdr_len;
} __attribute__((__packed__));

#ifdef CefC_TxMultiThread
typedef struct {
	int					worker_id;		/* worker id */
	CefT_Netd_Handle	*hdl_cefnetd;	/* cefnetd handle */
	CefT_Rngque* 		tx_que;
	CefT_Mp_Handle 		tx_que_mp;
	uint64_t			tx_packets, tx_bytes;
	uint64_t			drop_packets, drop_bytes;
	struct timeval		tx_packet_interval;
	pthread_mutex_t		tx_worker_mutex;
	pthread_cond_t		tx_worker_cond;
}	CefT_Netd_TxWorker;
#endif // CefC_TxMultiThread

/****************************************************************************************
 State Variables
 ****************************************************************************************/

/* The flag which shows cefnetd is running. 	*/
static uint8_t cefnetd_running_f = 0;
static uint64_t stat_nopit_frames = 0;
static uint64_t stat_rcv_size_cnt = 0;
static uint64_t stat_rcv_size_sum = 0;
static uint64_t stat_rcv_size_min = 65536;
static uint64_t stat_rcv_size_max = 0;

static char root_user_name[CefC_Ctrl_User_Len] = {"root"};

static char strNone[] = "None";

#if CefC_IsEnable_ContentStore
static uint64_t ccninfo_push_time = 0;
#endif // CefC_IsEnable_ContentStore

#ifdef CefC_Debug
static char cnd_dbg_msg[CefC_BufSiz_2KB];
static int cef_dbg_loglv_finest = 0;
#endif // CefC_Debug

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/
#ifdef CefC_TxMultiThread
static	pthread_t cefnetd_transmit_worker_th;
static CefT_Netd_TxWorker transmit_worker_hdl[CefC_TxWorkerMax];
#endif // CefC_TxMultiThread
static	pthread_t cefnetd_transmit_main_th;
static	pthread_t cefnetd_cefstatus_th;

static	pthread_mutex_t cefnetd_txqueue_mutex;
static	pthread_cond_t  cefnetd_txqueue_cond;

/*--------------------------------------------------------------------------------------
	Reads the config file
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_config_read (
	CefT_Netd_Handle* hdl					/* cefnetd handle							*/
);

/*--------------------------------------------------------------------------------------
	Reads the FIB configuration file
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_config_fib_read (
	CefT_Netd_Handle* hdl					/* cefnetd handle							*/
);

/*--------------------------------------------------------------------------------------
	Handles the control message
----------------------------------------------------------------------------------------*/
static int
cefnetd_input_control_message (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	unsigned char* msg, 						/* the received message(s)				*/
	int msg_size,								/* size of received message(s)			*/
	unsigned char** rspp,
	int fd
);
/*--------------------------------------------------------------------------------------
	Handles the message to reg/dereg application name
----------------------------------------------------------------------------------------*/
static int
cefnetd_input_app_reg_command (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh,				/* Parsed Option Header						*/
	uint16_t faceid
);
/*--------------------------------------------------------------------------------------
	Report xroute is changed to cefbabeld
----------------------------------------------------------------------------------------*/
static void
cefnetd_xroute_change_report (
	CefT_Netd_Handle* hdl,
	unsigned char* name,
	uint16_t name_len,
	int reg_f
);
/*--------------------------------------------------------------------------------------
	Handles the FIB request message
----------------------------------------------------------------------------------------*/
static int
cefnetd_fib_info_get (
	CefT_Netd_Handle* hdl,
	unsigned char** buff
);
/*--------------------------------------------------------------------------------------
	Handles the command from babeld
----------------------------------------------------------------------------------------*/
static int
cefnetd_babel_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	unsigned char* msg,
	int msg_len,
	unsigned char* buff
);
/*--------------------------------------------------------------------------------------
	Creates listening socket(s)
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_faces_init (
	CefT_Netd_Handle* hdl					/* cefnetd handle							*/
);
static int
cefnetd_trim_line_string (
	const char* p1, 						/* target string for trimming 				*/
	char* p2,								/* name string after trimming				*/
	char* p3								/* value string after trimming				*/
);
/*--------------------------------------------------------------------------------------
	Closes faces
----------------------------------------------------------------------------------------*/
static int
cefnetd_faces_destroy (
	CefT_Netd_Handle* hdl					/* cefnetd handle							*/
);
/*--------------------------------------------------------------------------------------
	Handles the input message
----------------------------------------------------------------------------------------*/
static int
cefnetd_udp_input_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int fd, 								/* FD which is polled POLLIN				*/
	int faceid								/* Face-ID that message arrived 			*/
);
/*--------------------------------------------------------------------------------------
	Handles the input message from the TCP listen socket
----------------------------------------------------------------------------------------*/
static int
cefnetd_tcp_input_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	int faceid									/* Face-ID that message arrived 		*/
);
/*--------------------------------------------------------------------------------------
	Handles the input message from Csmgr
----------------------------------------------------------------------------------------*/
static int
cefnetd_csm_input_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	int faceid									/* Face-ID that message arrived 		*/
);
static int									/* No care now								*/
(*cefnetd_input_process[CefC_Connection_Type_Num]) (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	int faceid									/* Face-ID that message arrived 		*/
) = {
	cefnetd_udp_input_process,					/* CefC_Connection_Type_Udp */
	cefnetd_tcp_input_process,					/* CefC_Connection_Type_Tcp */
	cefnetd_csm_input_process					/* CefC_Connection_Type_Csm */
};

/*--------------------------------------------------------------------------------------
	Check Input Cefroute msg
----------------------------------------------------------------------------------------*/
static int
cefnetd_route_msg_check (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	unsigned char* msg,						/* received message to handle				*/
	int msg_size							/* size of received message(s)				*/
);

/*--------------------------------------------------------------------------------------
	Handles the received message(s)
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cefnetd_input_message_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* the received message(s)					*/
	int msg_size,							/* size of received message(s)				*/
	char*	user_id
);
/*--------------------------------------------------------------------------------------
	Handles the received Interest message
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_interest_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	char*	user_id
);
/*--------------------------------------------------------------------------------------
	Handles the received Content Object message
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_object_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	char*	user_id
);
/*--------------------------------------------------------------------------------------
	Handles the received InterestReturn
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_intreturn_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	char*	user_id
);
/*--------------------------------------------------------------------------------------
	Handles the received Ccninfo Request
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_ccninforeq_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	char*	user_id
);
/*--------------------------------------------------------------------------------------
	Handles the received Ccninfo Replay
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_ccninforep_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	char*	user_id
);
#if CefC_IsEnable_ContentStore
/*--------------------------------------------------------------------------------------
	cefnetd cached Object process
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_cefcache_object_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	unsigned char* msg 						/* received message to handle				*/
);
#endif //CefC_IsEnable_ContentStore

static int									/* Returns a negative value if it fails 	*/
(*cefnetd_incoming_msg_process[CefC_Msg_Process_Num]) (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	char*	user_id
) = {
	cefnetd_incoming_interest_process,
	cefnetd_incoming_object_process,
	cefnetd_incoming_intreturn_process,
	cefnetd_incoming_ccninforeq_process,
	cefnetd_incoming_ccninforep_process
};
/*--------------------------------------------------------------------------------------
	Handles the received Piggyback message
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_piggyback_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* pkt, 					/* received packet to handle				*/
	uint16_t msg_len, 						/* length of ccn message 					*/
	uint16_t header_len						/* length of fixed and option header 		*/
);
#if CefC_IsEnable_ContentStore
/*--------------------------------------------------------------------------------------
	Handles the received message(s) from csmgr
----------------------------------------------------------------------------------------*/
static int										/* No care now							*/
cefnetd_input_message_from_csmgr_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	unsigned char* msg, 						/* the received message(s)				*/
	int msg_size								/* size of received message(s)			*/
);
/*--------------------------------------------------------------------------------------
	Handles the received Interest message
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_csmgr_interest_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	char*	user_id
);
/*--------------------------------------------------------------------------------------
	Handles the received Content Object message
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_csmgr_object_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	char*	user_id
);
/*--------------------------------------------------------------------------------------
	Handles the received Ccninfo Request
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_csmgr_ccninforeq_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	char*	user_id
);

static int									/* Returns a negative value if it fails 	*/
(*cefnetd_incoming_csmgr_msg_process[CefC_Msg_Process_Num]) (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	char*	user_id
) = {
	cefnetd_incoming_csmgr_interest_process,
	cefnetd_incoming_csmgr_object_process,
	cefnetd_incoming_intreturn_process,
	cefnetd_incoming_csmgr_ccninforeq_process,
	cefnetd_incoming_ccninforep_process
};

/*--------------------------------------------------------------------------------------
	Seeks the csmgr and creates the ccninfo response
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_external_cache_seek (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	CefT_CcnMsg_MsgBdy* pm,				/* Structure to set parsed CEFORE message	*/
	CefT_CcnMsg_OptHdr* poh
);

#endif // CefC_IsEnable_ContentStore
/*--------------------------------------------------------------------------------------
	Create and Send the FHR's ccninfo response
----------------------------------------------------------------------------------------*/
static void
cefnetd_FHR_Reply_process(
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	const unsigned char* name,				/* Report name								*/
	uint32_t name_len,						/* Report name length						*/
	CefT_CcnMsg_OptHdr* poh
);

/*--------------------------------------------------------------------------------------
	ccninfo loop check ccninfo-03
----------------------------------------------------------------------------------------*/
static	int
cefnetd_ccninfo_loop_check(
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	CefT_Parsed_Ccninfo* pci
);

/*--------------------------------------------------------------------------------------
	Create for ccninfo_name ccninfo-03
----------------------------------------------------------------------------------------*/
#define		CCNINFO_REQ		0
#define		CCNINFO_REP		1
static int
cefnetd_ccninfo_name_create(
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	CefT_Parsed_Ccninfo* pci,
	unsigned char* ccninfo_name,
	int		req_or_rep,
	int		skip_option
);

/*--------------------------------------------------------------------------------------
	Clean PIT entries
----------------------------------------------------------------------------------------*/
static void
cefnetd_pit_cleanup (
	CefT_Netd_Handle* hdl, 						/* cefnetd handle						*/
	uint64_t nowt								/* current time (usec) 					*/
);
/*--------------------------------------------------------------------------------------
	Clean Face entries
----------------------------------------------------------------------------------------*/
static void
cefnetd_faces_cleanup (
	CefT_Netd_Handle* hdl, 						/* cefnetd handle						*/
	uint64_t nowt								/* current time (usec) 					*/
);
/*--------------------------------------------------------------------------------------
	Handles the invalid command
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_invalid_command_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	CefT_CcnMsg_MsgBdy* pm					/* Structure to set parsed CEFORE message	*/
);
/*--------------------------------------------------------------------------------------
	Handles the Link Request command
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_link_req_command_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	CefT_CcnMsg_MsgBdy* pm					/* Structure to set parsed CEFORE message	*/
);
/*--------------------------------------------------------------------------------------
	Handles the Link Response command
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_link_res_command_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	CefT_CcnMsg_MsgBdy* pm					/* Structure to set parsed CEFORE message	*/
);

static int									/* Returns a negative value if it fails 	*/
(*cefnetd_command_process[CefC_Cmd_Num]) (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	CefT_CcnMsg_MsgBdy* pm					/* Structure to set parsed CEFORE message	*/
) = {
	cefnetd_invalid_command_process,
	cefnetd_link_req_command_process,
	cefnetd_link_res_command_process
};

/*--------------------------------------------------------------------------------------
	Creates the Command Filter(s)
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_command_filter_init (
	CefT_Netd_Handle* hdl					/* cefnetd handle							*/
);
/*--------------------------------------------------------------------------------------
	Handles a command message
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_command_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	CefT_CcnMsg_MsgBdy* pm					/* Structure to set parsed CEFORE message	*/
);
/*--------------------------------------------------------------------------------------
	Accepts and receives the frame(s) from local face
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cefnetd_input_from_local_process (
	CefT_Netd_Handle* hdl					/* cefnetd handle							*/
);

/*--------------------------------------------------------------------------------------
	Handles the elements of cs_stat TX queue
----------------------------------------------------------------------------------------*/
static int										/* No care now							*/
cefnetd_input_from_csque_process (
	CefT_Netd_Handle* hdl						/* cefnetd handle						*/
);
/*--------------------------------------------------------------------------------------
	check state of port use
----------------------------------------------------------------------------------------*/
static int										/* No care now							*/
	cefnetd_check_state_of_port_use (
	CefT_Netd_Handle* hdl						/* cefnetd handle						*/
);
/*--------------------------------------------------------------------------------------
	Prepares the UDP and TCP sockets to be polled
----------------------------------------------------------------------------------------*/
static int										/* number of the poll which has events	*/
cefnetd_poll_socket_prepare (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	struct pollfd fds[],
	CefC_Connection_Type fd_type[],
	int faceids[]
);
/*--------------------------------------------------------------------------------------
	Obtains my NodeID (IP Address)
----------------------------------------------------------------------------------------*/
static void
cefnetd_node_id_get (
	CefT_Netd_Handle* hdl						/* cefnetd handle						*/
);

/*--------------------------------------------------------------------------------------
	Obtains my NodeID (IP Address)
----------------------------------------------------------------------------------------*/
static int
cefnetd_matched_node_id_get (
	CefT_Netd_Handle* hdl,
	unsigned char* peer_node_id,
	int peer_node_id_len,
	unsigned char* node_id,
	unsigned int* responder_mtu

);

//0.8.3
/*--------------------------------------------------------------------------------------
	Handles the received Interest message has T_SELECTIVE
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_selective_interest_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh				/* Parsed Option Header						*/
);

/* NodeName Check */
static int									/*  */
cefnetd_nodename_check (
	const char* in_name,					/* input NodeName							*/
	unsigned char* ot_name					/* buffer to set After Check NodeName		*/
);


#ifdef DEB_CCNINFO
/*--------------------------------------------------------------------------------------
	for debug
----------------------------------------------------------------------------------------*/
static void
cefnetd_dbg_cpi_print (
	CefT_Parsed_Ccninfo* pci
);
#endif

//0.8.3
static int
cefnetd_keyid_get (
	const unsigned char* msg,
	int msg_len,
	unsigned char *keyid_buff
);

static int
cefnetd_fwd_plugin_load (
	CefT_Netd_Handle* hdl					/* cefnetd handle							*/
);

static int
cefnetd_continfo_process (
	CefT_Netd_Handle*		hdl,			/* cefnetd handle							*/
	int						faceid,			/* Face-ID where messages arrived at		*/
	int						peer_faceid,	/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char*			msg,			/* received message to handle				*/
	uint16_t				payload_len,	/* Payload Length of this message			*/
	uint16_t				header_len,		/* Header Length of this message			*/
	CefT_CcnMsg_MsgBdy*	pm,				/* Structure to set parsed CEFORE message	*/
	CefT_Parsed_Ccninfo*	pci				/* Structure to set parsed Ccninfo message	*/
);

static void
cefnetd_adv_route_process (
	CefT_Netd_Handle*		hdl,			/* cefnetd handle							*/
	CefT_CcnMsg_MsgBdy*	pm				/* Structure to set parsed CEFORE message	*/
);

#ifdef CefC_TxMultiThread
static void *
cefnetd_transmit_worker_thread (
	void* hdl							/* cefnetd handle						*/
);
#endif	// CefC_TxMultiThread

static void *
cefnetd_transmit_main_thread (
	void* hdl							/* cefnetd handle						*/
);

/****************************************************************************************
 ****************************************************************************************/
/*--------------------------------------------------------------------------------------
	Creates and initialize the cefnetd handle
----------------------------------------------------------------------------------------*/
CefT_Netd_Handle* 								/* the created cefnetd handle			*/
cefnetd_handle_create (
	uint8_t 	node_type						/* Node Type (Router/Receiver....)		*/
) {
	CefT_Netd_Handle* hdl;
	int res;
	void* 	vret = NULL;
	char*	wp;
	char 	conf_path[CefC_BufSiz_1KB];
	char 	sock_path[CefC_BufSiz_1KB];

	/* Allocates a block of memory for cefnetd handle 	*/
	hdl = (CefT_Netd_Handle*) malloc (sizeof (CefT_Netd_Handle));
	if (hdl == NULL) {
		cef_log_write (CefC_Log_Error, "%s CefT_Netd_Handle memory allocation failed (%s)\n"
						, __func__, strerror(errno));
		return (NULL);
	}
	memset (hdl, 0, sizeof (CefT_Netd_Handle));
	hdl->nowtus = cef_client_present_timeus_calc ();

	/* Assigns the Node Type							*/
	hdl->node_type = node_type;

	/* Assigns default values to the cefnetd handle 	*/
	hdl->port_num 		= CefC_Default_PortNum;
	hdl->fib_max_size 	= CefC_Default_FibSize;
	hdl->pit_max_size 	= CefC_Default_PitSize;
	hdl->sk_type 		= CefC_Default_Sktype;
	hdl->nbr_max_size 	= CefC_Default_NbrSize;
	hdl->nbr_mng_intv 	= CefC_Default_NbrInterval;
	hdl->nbr_mng_thread = CefC_Default_NbrThread;
	hdl->fwd_rate 		= CefC_Default_Cache_Send_Rate;
	hdl->babel_route 	= 0x03;		/* both 	*/
	hdl->cs_mode 		= 0;
	hdl->forwarding_strategy = strNone;
	hdl->app_fib_max_size		= CefC_Default_FibAppSize;
	hdl->app_pit_max_size		= CefC_Default_PitAppSize;
	hdl->My_Node_Name			= NULL;
	hdl->My_Node_Name_TLV		= NULL;
	hdl->My_Node_Name_TLV_len	= 0;

#ifdef	CefC_TxMultiThread
	hdl->tx_worker_num = CefC_TxWorkerDefault;
#endif  // CefC_TxMultiThread
	hdl->tx_que_size = CefC_TxQueueDefault;
	hdl->face_lifetime = -1;

	hdl->ccninfo_access_policy = CefC_Default_CcninfoAccessPolicy;
	hdl->ccninfo_full_discovery = CefC_Default_CcninfoFullDiscovery;
	strcpy(hdl->ccninfo_valid_alg ,CefC_Default_CcninfoValidAlg);
	hdl->ccninfo_valid_type = CefC_T_CRC32C;	/* ccninfo-05 */
	strcpy(hdl->ccninfo_sha256_key_prfx ,CefC_Default_CcninfoSha256KeyPrfx);
	hdl->ccninfo_reply_timeout = CefC_Default_CcninfoReplyTimeout;

	//0.8.3
	hdl->InterestRetrans		= CefC_IntRetrans_Type_RFC;
	hdl->Selective_fwd			= CefC_Default_SelectiveForward;
	hdl->SymbolicBack			= CefC_Default_SymbolicBackBuff;
	hdl->IR_Congestion			= CefC_Default_IR_Congestion;
	hdl->BW_Stat_interval		= CefC_Default_BANDWIDTH_STAT_INTERVAL;
	hdl->Symbolic_max_lifetime	= CefC_Default_SYMBOLIC_LIFETIME;
	hdl->Regular_max_lifetime	= CefC_Default_REGULAR_LIFETIME;
	hdl->Ex_Cache_Access		= CefC_Default_CSMGR_ACCESS_RW;
	hdl->Buffer_Cache_Time		= CefC_Default_BUFFER_CACHE_TIME * 1000;
	hdl->cefstatus_pipe_fd[0]	= -1;
	hdl->cefstatus_pipe_fd[1]	= -1;
	//202108
	hdl->IR_Option				= 0;	//Not
	memset (hdl->IR_enable, 0, sizeof (hdl->IR_enable));

	hdl->stat_recv_frames							 = 0;
	hdl->stat_send_frames							 = 0;
	hdl->stat_recv_interest							 = 0;
	hdl->stat_recv_interest_types[CefC_PIT_TYPE_Rgl] = 0;
	hdl->stat_recv_interest_types[CefC_PIT_TYPE_Sym] = 0;
	hdl->stat_recv_interest_types[CefC_PIT_TYPE_Sel] = 0;
	hdl->stat_send_interest							 = 0;
	hdl->stat_send_interest_types[CefC_PIT_TYPE_Rgl] = 0;
	hdl->stat_send_interest_types[CefC_PIT_TYPE_Sym] = 0;
	hdl->stat_send_interest_types[CefC_PIT_TYPE_Sel] = 0;

	//20220311
	hdl->Selective_max_range = CefC_Default_SELECTIVE_MAX;

	/* Initialize the frame module 						*/
	cef_client_config_dir_get (conf_path);
	cef_frame_init ();
	res = cef_valid_init (conf_path);
	if (res < 0) {
		cef_log_write (CefC_Log_Error, "Failed to read the Encryption key file.\n");
		return (NULL);
	}
	cef_log_write (CefC_Log_Info, "Loading Encryption key file ... OK\n");

	/* Reads the config file 				*/
	hdl->port_num = cef_client_listen_port_get ();
	res = cefnetd_config_read (hdl);
	if (res < 0) {
		cef_log_write (CefC_Log_Error, "Failed to read the cefnetd.conf\n");
		return (NULL);
	}
	cef_log_write (CefC_Log_Info, "Loading cefnetd.conf ... OK\n");

	/* Initialize sha256 validation environment for ccninfo */
	if (hdl->ccninfo_valid_type == CefC_T_RSA_SHA256) {
		res = cef_valid_init_ccninfoRT (conf_path);
		if (res < 0) {
			return (NULL);
		}
	}
	/* Clear information used in authentication & authorization */
	hdl->ccninfousr_id_len = 0;
	memset (hdl->ccninfousr_node_id, 0, sizeof(hdl->ccninfousr_node_id));
	if (hdl->ccninfo_rcvdpub_key_bi != NULL) {
		free (hdl->ccninfo_rcvdpub_key_bi);
		hdl->ccninfo_rcvdpub_key_bi = NULL;
	}
	hdl->ccninfo_rcvdpub_key_bi_len = 0;

	/* check state of port use */
	res = cefnetd_check_state_of_port_use (hdl);
	if (res < 0) {
		char	tmp_sock_path[CefC_BufSiz_1KB];
		char	tmp_msg[CefC_BufSiz_2KB];
		cef_client_local_sock_name_get (tmp_sock_path);
		sprintf( tmp_msg, "Another cefnetd may be running with the same port. If not, remove the old socket file (%s) and restart cefnetd.\n", tmp_sock_path );
		cef_log_write (CefC_Log_Error, tmp_msg);
		return (NULL);
	}

	/* Creates listening socket(s)			*/
	res = cefnetd_faces_init (hdl);
	if (res < 0) {
		/* Delete UNIX domain socket file */
		cef_client_local_sock_name_get (sock_path);
		unlink (sock_path);
		if (hdl->babel_use_f) {
			cef_client_babel_sock_name_get (sock_path);
			unlink (sock_path);
		}
		return (NULL);
	}
	srand ((unsigned) time (NULL));
	hdl->cefrt_seed = (uint8_t)(rand () + 1);
	cef_log_write (CefC_Log_Info, "Creation the listen faces ... OK\n");

	/* Obtains my NodeID (IP Address) 	*/
	cefnetd_node_id_get (hdl);

	/* Creates and initialize FIB			*/
	hdl->fib = cef_hash_tbl_create_ext ((uint16_t) hdl->fib_max_size, CefC_Hash_Coef_FIB);
	cefnetd_config_fib_read (hdl);
	cef_fib_faceid_cleanup (hdl->fib);

	cef_face_update_listen_faces (
		hdl->inudpfds, hdl->inudpfaces, &hdl->inudpfdc,
		hdl->intcpfds, hdl->intcpfaces, &hdl->intcpfdc);
	hdl->face_clean_t = cef_client_present_timeus_calc () + 1000000;
	cef_log_write (CefC_Log_Info, "Creation FIB ... OK\n");

	/* Creates the Command Filter(s) 		*/
	cefnetd_command_filter_init (hdl);

	/* Creates PIT 							*/
	cef_pit_init (hdl->ccninfo_reply_timeout, hdl->Symbolic_max_lifetime, hdl->Regular_max_lifetime); //0.8.3
	hdl->pit = cef_lhash_tbl_create_ext (hdl->pit_max_size, CefC_Hash_Coef_PIT);
	hdl->pit_clean_t = cef_client_present_timeus_calc () + CefC_Pit_CleaningTime;
	cef_log_write (CefC_Log_Info, "Creation PIT ... OK\n");

	/* Prepares sockets for applications 	*/
	for (res = 0 ; res < CefC_App_Conn_Num ; res++) {
		hdl->app_fds[res] = -1;
		hdl->app_faces[res] = -1;
	}
	hdl->app_fds_num = 0;

#if CefC_IsEnable_ContentStore
	/* Reads the config file 				*/
	hdl->cs_stat = cef_csmgr_stat_create (hdl->cs_mode);

	if (hdl->cs_stat == NULL) {
		cef_log_write (CefC_Log_Error, "Failed to init Content Store\n");
		/* Delete UNIX domain socket file */
		cef_client_local_sock_name_get (sock_path);
		unlink (sock_path);
		if (hdl->babel_use_f) {
			cef_client_babel_sock_name_get (sock_path);
			unlink (sock_path);
		}
		return (NULL);
	}
	if (hdl->cs_stat->cache_type != CefC_Default_Cache_Type) {
		cef_log_write (CefC_Log_Info, "Initialization Content Store ... OK\n");
	} else {
		cef_log_write (CefC_Log_Info, "Not use Content Store\n");
	}
	/* RW or RO */
	hdl->cs_stat->csmgr_access = hdl->Ex_Cache_Access;
	/* BUFFER_CACHE_TIME */
	hdl->cs_stat->buffer_cache_time = hdl->Buffer_Cache_Time;

	/* set send content rate 	*/
	hdl->send_rate = (double)(8.0 / (double) hdl->fwd_rate);
	hdl->send_next = 0;
#else // CefC_IsEnable_ContentStore
	hdl->cs_stat = NULL;
#endif // CefC_IsEnable_ContentStore

	/* Creates App Reg table 		*/
	hdl->app_reg = cef_hash_tbl_create_ext (hdl->app_fib_max_size, CefC_Hash_Coef_FIB);
	if ( !hdl->app_reg ){
		cef_log_write (CefC_Log_Error,
			"Failed to cef_hash_tbl_create_ext(app_fib_max_size=%d)\n", hdl->app_fib_max_size);
		/* NG */
		cefnetd_handle_destroy (hdl);
		return (NULL);
	}

	/* Creates App Reg PIT 			*/
	hdl->app_pit = cef_lhash_tbl_create_ext (hdl->app_pit_max_size, CefC_Hash_Coef_PIT);
	if ( !hdl->app_pit ){
		cef_log_write (CefC_Log_Error,
			"Failed to cef_hash_tbl_create_ext(app_pit_max_size=%d)\n", hdl->app_pit_max_size);
		/* NG */
		cefnetd_handle_destroy (hdl);
		return (NULL);
	}

	/* Creates the tx buffer (main)								*/
	hdl->tx_que = cef_rngque_create (hdl->tx_que_size);	// 100%
	if ( !hdl->tx_que ){
		cef_log_write (CefC_Log_Error,
			"Failed to cef_rngque_create(tx_que)\n");
		/* NG */
		cefnetd_handle_destroy (hdl);
		return (NULL);
	}
	/* Creates the tx buffer (priolity:high)					*/
	hdl->tx_que_high = cef_rngque_create (hdl->tx_que_size);	// 100%
	if ( !hdl->tx_que_high ){
		cef_log_write (CefC_Log_Error,
			"Failed to cef_rngque_create(tx_que_high)\n");
		/* NG */
		cefnetd_handle_destroy (hdl);
		return (NULL);
	}
	/* Creates the tx buffer (priolity:low)						*/
	hdl->tx_que_low = cef_rngque_create ((hdl->tx_que_size * 25) / 100);	// 25%
	if ( !hdl->tx_que_low ){
		cef_log_write (CefC_Log_Error,
			"Failed to cef_rngque_create(tx_que_low)\n");
		/* NG */
		cefnetd_handle_destroy (hdl);
		return (NULL);
	}
#ifdef CefC_TxMultiThread
	for (int i = 0; i < hdl->tx_worker_num; i++ ){
		int		worker_que_size = hdl->tx_que_size / hdl->tx_worker_num;
		hdl->tx_worker_que[i] = cef_rngque_create (worker_que_size);
		if ( !hdl->tx_worker_que[i] ){
			cef_log_write (CefC_Log_Error,
				"Failed to cef_rngque_create [%d/%d]\n", i, hdl->tx_worker_num);
			/* NG */
			cefnetd_handle_destroy (hdl);
			return (NULL);
		}
		pthread_mutex_init(&hdl->tx_worker_mutex[i], NULL);
		pthread_cond_init(&hdl->tx_worker_cond[i], NULL);
	}
#endif // CefC_TxMultiThread
	hdl->tx_que_mp
		= cef_mpool_init ("CefTxMSF", sizeof (CefT_Tx_Elem), hdl->tx_que_size);
	if ( !hdl->tx_que_mp ){
		cef_log_write (CefC_Log_Error,
			"Failed to cef_mpool_init(CefTxMSF)\n");
		/* NG */
		cefnetd_handle_destroy (hdl);
		return (NULL);
	}

	/* Inits the plugin 			*/
	cef_plugin_init (&(hdl->plugin_hdl));

	cef_tp_plugin_init (
		&hdl->plugin_hdl.tp, hdl->tx_que, hdl->tx_que_high, hdl->tx_que_low, hdl->tx_que_mp, vret);

	/* Forwarding Strategy Plugin(libcefnetd_fwd_plugin) */
	hdl->fwd_strtgy_hdl = (CefT_Plugin_Fwd_Strtgy*) malloc (sizeof (CefT_Plugin_Fwd_Strtgy));
	if (hdl->fwd_strtgy_hdl == NULL){
		cefnetd_handle_destroy (hdl);
		cef_log_write (CefC_Log_Error, "%s fwd_strtgy_hdl memory allocation failed (%s)\n"
						, __func__, strerror(errno));
		return (NULL);
	}
	memset( hdl->fwd_strtgy_hdl, 0, sizeof (CefT_Plugin_Fwd_Strtgy));
 	hdl->fwd_strtgy_hdl->fwd_int = cef_forward_interest;
 	hdl->fwd_strtgy_hdl->fwd_cob = cef_forward_object;

	if ( strcasecmp( hdl->forwarding_strategy, strNone ) != 0 ) {
		res = cefnetd_fwd_plugin_load(hdl);
		if (res < 0) {
			cefnetd_handle_destroy (hdl);
			return (NULL);
		}
		if (hdl->fwd_strtgy_hdl->init) {
			res = hdl->fwd_strtgy_hdl->init();
			if (res < 0) {
				cefnetd_handle_destroy (hdl);
				return (NULL);
			}
		}
	}

	/* Records the user which launched cefnetd 		*/
	wp = getenv ("USER");

	if (wp == NULL) {
		cefnetd_handle_destroy (hdl);
		cef_log_write (CefC_Log_Error,
			"Failed to obtain $USER launched cefnetd\n");
		return (NULL);
	}
	memset (hdl->launched_user_name, 0, CefC_Ctrl_User_Len);
	strcpy (hdl->launched_user_name, wp);

	//NodeName Check
	if ( hdl->My_Node_Name == NULL ) {
		// If NODE_NAME is specified in the cefnetd.conf, skip the this block.
		char		addrstr[256];
		if ( hdl->top_nodeid_len == 4 ) {
			inet_ntop (AF_INET, hdl->top_nodeid, addrstr, sizeof (addrstr));
		} else if ( hdl->top_nodeid_len == 16 ) {
			inet_ntop (AF_INET6, hdl->top_nodeid, addrstr, sizeof (addrstr));
		}
		unsigned char	out_name[CefC_Max_Length];
		unsigned char	out_name_tlv[CefC_Max_Length];

		hdl->My_Node_Name = malloc( sizeof(char) * strlen(addrstr) + 1 );
		if (hdl->My_Node_Name == NULL){
			cefnetd_handle_destroy (hdl);
			cef_log_write (CefC_Log_Error, "%s My_Node_Name memory allocation failed (%s)\n"
							, __func__, strerror(errno));
			return (NULL);
		}
		strcpy( hdl->My_Node_Name, addrstr );
		/* Convert Name TLV */
		strcpy( (char*)out_name, "ccnx:/" );
		strcat( (char*)out_name, hdl->My_Node_Name );
		res = cef_frame_conversion_uri_to_name ((char*)out_name, out_name_tlv);
		if ( res < 0 ) {
			/* Error */
			cef_log_write (CefC_Log_Error, "NODE_NAME contains characters that cannot be used.\n");
			return( NULL );
		} else if ( CefC_NAME_MAXLEN < res ){
			cef_log_write (CefC_Log_Error,
				"NODE_NAME is too long (%d bytes), cefore does not support T_NAMEs longer than %u bytes.\n",
					res, CefC_NAME_MAXLEN);
			return( NULL );
		} else {
			struct tlv_hdr name_tlv_hdr;
			name_tlv_hdr.type = htons (CefC_T_NAME);
			name_tlv_hdr.length = htons (res);
			hdl->My_Node_Name_TLV = (unsigned char*)malloc( res+CefC_S_TLF );
			if (hdl->My_Node_Name_TLV == NULL){
				cefnetd_handle_destroy (hdl);
				cef_log_write (CefC_Log_Error, "%s My_Node_Name_TLV memory allocation failed (%s)\n"
								, __func__, strerror(errno));
				return (NULL);
			}
			hdl->My_Node_Name_TLV_len = res + CefC_S_TLF;
			memcpy( &hdl->My_Node_Name_TLV[0], &name_tlv_hdr, sizeof(struct tlv_hdr) );
			memcpy( &hdl->My_Node_Name_TLV[CefC_S_TLF], out_name_tlv, res );
		}
		cef_log_write (CefC_Log_Warn, "No NODE_NAME defined in cefnetd.conf; IP address is temporarily used as the node name.\n");
	}

	hdl->app_rsp_msg = calloc(10, CefC_Max_Length);
	if (hdl->app_rsp_msg == NULL){
		cefnetd_handle_destroy (hdl);
		cef_log_write (CefC_Log_Error, "%s app_rsp_msg memory allocation failed (%s)\n"
						, __func__, strerror(errno));
		return (NULL);
	}

#ifdef CefC_TxMultiThread
	/*#####*/
		/* cefnetd_transmit_worker_thread */
	for (int i = 0; i < hdl->tx_worker_num; i++ ){
		memset(&transmit_worker_hdl[i], 0x00, sizeof(CefT_Netd_TxWorker));
		transmit_worker_hdl[i].worker_id = i;
		transmit_worker_hdl[i].hdl_cefnetd = hdl;
		transmit_worker_hdl[i].tx_que = hdl->tx_worker_que[i];
		transmit_worker_hdl[i].tx_que_mp = hdl->tx_que_mp;
		transmit_worker_hdl[i].tx_worker_cond = hdl->tx_worker_cond[i];
		transmit_worker_hdl[i].tx_worker_mutex = hdl->tx_worker_mutex[i];
		if (cef_pthread_create(&cefnetd_transmit_worker_th, NULL
				, &cefnetd_transmit_worker_thread, &transmit_worker_hdl[i]) == -1) {
				cefnetd_handle_destroy (hdl);
				cef_log_write (CefC_Log_Error
							, "%s Failed to create the new thread(cefnetd_transmit_worker_thread)\n"
							, __func__);
			return (NULL);
		}
	}
#endif // CefC_TxMultiThread

	/*#####*/
	{	/* cefnetd_transmit_main_thread */
		if (cef_pthread_create(&cefnetd_transmit_main_th, NULL
				, &cefnetd_transmit_main_thread, (hdl)) == -1) {
				cefnetd_handle_destroy (hdl);
				cef_log_write (CefC_Log_Error
							, "%s Failed to create the new thread(cefnetd_transmit_main_thread)\n"
							, __func__);
			return (NULL);
		}
	}
	pthread_mutex_init(&cefnetd_txqueue_mutex, NULL);
	pthread_cond_init(&cefnetd_txqueue_cond, NULL);

	/*#####*/
	{	/* cefstatus_thread */
		int flags;
		/* Create socket for communication between cednetd and memory cache */
		if ( socketpair(AF_UNIX,SOCK_DGRAM, 0, hdl->cefstatus_pipe_fd) == -1 ) {
			cefnetd_handle_destroy (hdl);
			cef_log_write (CefC_Log_Error, "%s cefstatus pair socket creation error (%s)\n"
							, __func__, strerror(errno));
			return (NULL);
	  	}
		/* Set cefnetd side socket as non-blocking I/O */
		if ( (flags = fcntl(hdl->cefstatus_pipe_fd[0], F_GETFL, 0) ) < 0) {
			cefnetd_handle_destroy (hdl);
			cef_log_write (CefC_Log_Error, "%s fcntl error (%s)\n"
							, __func__, strerror(errno));
			return (NULL);
		}
		flags |= O_NONBLOCK;
		if (fcntl(hdl->cefstatus_pipe_fd[0], F_SETFL, flags) < 0) {
			cefnetd_handle_destroy (hdl);
			cef_log_write (CefC_Log_Error, "%s fcntl error (%s)\n"
							, __func__, strerror(errno));
			return (NULL);
		}

		if (cef_pthread_create(&cefnetd_cefstatus_th, NULL
				, &cefnetd_cefstatus_thread, (hdl)) == -1) {
				cefnetd_handle_destroy (hdl);
				cef_log_write (CefC_Log_Error
							, "%s Failed to create the new thread(cefnetd_cefstatus_thread)\n"
							, __func__);
			return (NULL);
		}
	}


	return (hdl);
}
/*--------------------------------------------------------------------------------------
	Destroys the cefnetd handle
----------------------------------------------------------------------------------------*/
void
cefnetd_handle_destroy (
	CefT_Netd_Handle* hdl						/* cefnetd handle to destroy			*/
) {
	char sock_path[CefC_BufSiz_1KB];

	/* destroy plugins 		*/
	cef_tp_plugin_destroy (hdl->plugin_hdl.tp);
	cef_plugin_destroy (&(hdl->plugin_hdl));

#ifdef CefC_TxMultiThread
	for (int i = 0; i < hdl->tx_worker_num; i++ ){
		if ( hdl->tx_worker_que[i] ){
			cef_rngque_destroy (hdl->tx_worker_que[i]);
		}
		if ( &hdl->tx_worker_mutex[i] ){
			pthread_mutex_destroy(&hdl->tx_worker_mutex[i]);
		}
		if ( &hdl->tx_worker_cond[i] ){
			pthread_cond_destroy(&hdl->tx_worker_cond[i]);
		}
	}
#endif // CefC_TxMultiThread
	cef_rngque_destroy (hdl->tx_que_low);
	cef_rngque_destroy (hdl->tx_que_high);
	cef_rngque_destroy (hdl->tx_que);
	cef_mpool_destroy (hdl->tx_que_mp);

	pthread_mutex_destroy(&cefnetd_txqueue_mutex);
	pthread_cond_destroy(&cefnetd_txqueue_cond);

	if (hdl->fwd_strtgy_hdl && hdl->fwd_strtgy_hdl->destroy) {
		hdl->fwd_strtgy_hdl->destroy();
	}
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine,
		"<STAT> Rx ContentObject = "FMTU64"\n", hdl->stat_recv_frames);
	cef_dbg_write (CefC_Dbg_Fine,
		"<STAT> Tx ContentObject = "FMTU64"\n", hdl->stat_send_frames);
	cef_dbg_write (CefC_Dbg_Fine,
		"<STAT> Rx Interest      = "FMTU64"\n", hdl->stat_recv_interest);
	cef_dbg_write (CefC_Dbg_Fine,
		"                        = RGL("FMTU64"), SYM("FMTU64"), SEL("FMTU64")\n",
									hdl->stat_recv_interest_types[0],
									hdl->stat_recv_interest_types[1],
									hdl->stat_recv_interest_types[2]);
	cef_dbg_write (CefC_Dbg_Fine,
		"<STAT> Tx Interest      = "FMTU64"\n", hdl->stat_send_interest);
	cef_dbg_write (CefC_Dbg_Fine,
		"                        = RGL("FMTU64"), SYM("FMTU64"), SEL("FMTU64")\n",
									hdl->stat_send_interest_types[0],
									hdl->stat_send_interest_types[1],
									hdl->stat_send_interest_types[2]);
#ifdef CefC_TxMultiThread
	for (int i = 0; i < hdl->tx_worker_num; i++ ){
		cef_dbg_write (CefC_Dbg_Fine,
			"<STAT> Tx Thread:%02d     = packets "FMTU64" bytes "FMTU64" drops "FMTU64" \n",
										transmit_worker_hdl[i].worker_id,
										transmit_worker_hdl[i].tx_packets,
										transmit_worker_hdl[i].tx_bytes,
										transmit_worker_hdl[i].drop_packets);
	}
#endif // CefC_TxMultiThread
	cef_dbg_write (CefC_Dbg_Fine,
		"<STAT> No PIT Frames    = "FMTU64"\n", stat_nopit_frames);
	cef_dbg_write (CefC_Dbg_Fine,
		"<STAT> Frame Size Cnt   = "FMTU64"\n", stat_rcv_size_cnt);
	cef_dbg_write (CefC_Dbg_Fine,
		"<STAT> Frame Size Sum   = "FMTU64"\n", stat_rcv_size_sum);
	if (stat_rcv_size_min > 65535) {
		stat_rcv_size_min = 0;
	}
	cef_dbg_write (CefC_Dbg_Fine,
		"<STAT> Frame Size Min   = "FMTU64"\n", stat_rcv_size_min);
	cef_dbg_write (CefC_Dbg_Fine,
		"<STAT> Frame Size Max   = "FMTU64"\n", stat_rcv_size_max);
#endif // CefC_Debug

	cefnetd_faces_destroy (hdl);
	if (hdl->babel_use_f) {
		cef_client_babel_sock_name_get (sock_path);
		unlink (sock_path);
	}

	if ( hdl->app_rsp_msg )
		free(hdl->app_rsp_msg);
	if ( hdl->My_Node_Name_TLV )
		free(hdl->My_Node_Name_TLV);
	if ( hdl->My_Node_Name )
		free(hdl->My_Node_Name);
	if ( hdl->fwd_strtgy_hdl )
		free(hdl->fwd_strtgy_hdl);

#if CefC_IsEnable_ContentStore
	cef_csmgr_stat_destroy (&hdl->cs_stat);
#endif // CefC_IsEnable_ContentStore

	free (hdl);

	cef_client_local_sock_name_get (sock_path);
	unlink (sock_path);

	cef_log_write (CefC_Log_Info, "Stop\n");
}
/*--------------------------------------------------------------------------------------
	Main Loop Function
----------------------------------------------------------------------------------------*/
void
cefnetd_event_dispatch (
	CefT_Netd_Handle* hdl 						/* cefnetd handle						*/
) {
	int i;
	int res;

	uint64_t nowt = cef_client_present_timeus_calc ();

	cef_log_write (CefC_Log_Info, "Running\n");
	cefnetd_running_f = 1;

	struct pollfd fds[CefC_Listen_Face_Max * 2];
	CefC_Connection_Type fd_type[CefC_Listen_Face_Max * 2];
	int faceids[CefC_Listen_Face_Max * 2];
	int fdnum;

	while (cefnetd_running_f) {

		/* Calculates the present time 						*/
		nowt = cef_client_present_timeus_calc ();
		hdl->nowtus = nowt;

		/* Cleans PIT entries 		*/
		cefnetd_pit_cleanup (hdl, nowt);

		/* Cleans Face entries 		*/
		if ( 0 < hdl->face_lifetime ){
			cefnetd_faces_cleanup (hdl, nowt);
		}

		/* Accepts the TCP socket 	*/
		res = cef_face_accept_connect ();

		if ((res > 0) && (hdl->intcpfdc < CefC_Listen_Face_Max)) {
			hdl->intcpfaces[hdl->intcpfdc] = (uint16_t) res;
			hdl->intcpfds[hdl->intcpfdc].fd
				= cef_face_get_fd_from_faceid ((uint16_t) res);
			hdl->intcpfds[hdl->intcpfdc].events = POLLIN | POLLERR;
			hdl->intcpfdc++;
		}

		/* Receives the frame(s) from local process 		*/
		cefnetd_input_from_local_process (hdl);
		cef_face_update_listen_faces (
				hdl->inudpfds, hdl->inudpfaces, &hdl->inudpfdc,
				hdl->intcpfds, hdl->intcpfaces, &hdl->intcpfdc);
		/* Receives the frame(s) from the listen port 		*/
		fdnum = cefnetd_poll_socket_prepare (hdl, fds, fd_type, faceids);
		res = poll (fds, fdnum, 1);

		for (i = 0 ; res > 0 && i < fdnum ; i++) {

			if (fds[i].revents != 0) {
				res--;
				if (fds[i].revents & POLLIN) {
					if (fd_type[i] == CefC_Connection_Type_Local) {
						continue;
					}
					(*cefnetd_input_process[fd_type[i]]) (
										hdl, fds[i].fd, faceids[i]);
				}
#ifdef __APPLE__
				if (fds[i].revents & (POLLERR | POLLNVAL)) {
#else // __APPLE__
				if (fds[i].revents & (POLLERR | POLLNVAL | POLLHUP)) {
#endif // __APPLE__
					if (fd_type[i] < CefC_Connection_Type_Csm) {
						cef_face_close (faceids[i]);
						cef_fib_faceid_cleanup (hdl->fib);
					}
				}

			}
		}

		cefnetd_input_from_csque_process (hdl);

#if CefC_IsEnable_ContentStore
		if ((hdl->cs_stat->cache_type != CefC_Cache_Type_None) &&
			(nowt > ccninfo_push_time)) {
			if (hdl->cs_stat->cache_type == CefC_Cache_Type_Excache) {
				cef_csmgr_excache_item_push (hdl->cs_stat);
				ccninfo_push_time = nowt + 500000;
			}
#ifdef	CefC_CefnetdCache
			else
			if (hdl->cs_stat->cache_type == CefC_Cache_Type_Localcache) {
				; /* NOP */
			}
#endif	//CefC_CefnetdCache
		}
#endif // CefC_IsEnable_ContentStore


	}
}
/*--------------------------------------------------------------------------------------
	Ccninfo Full discobery authentication & authorization
	NOTE: Stub function for future expansion
----------------------------------------------------------------------------------------*/
int											/* Returns 0 if authentication 				*/
											/* and authorization are OK 				*/
cefnetd_ccninfo_fulldiscovery_authNZ(
	uint16_t 		usr_id_len,
	unsigned char*  usr_node_id,
	int 			rcvdpub_key_bi_len,
	unsigned char* 	rcvdpub_key_bi
) {
	if (rcvdpub_key_bi_len == 0){
		return (-1);
	} else {
		return (0);
	}
}
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
){

	struct fixed_hdr* 	fixed_hp;
	struct tlv_hdr* 	tlv_ptr;
	uint16_t 			hdr_len;
	uint16_t 			pkt_len;
	uint16_t 			new_pkt_len;
	uint16_t 			dsc_len;
	uint16_t 			new_dsc_len;
	uint16_t 			name_len;
	uint16_t 			vald_len;

#define CCNINFO_MAX_REPLY_SIZE 1280

	if (msg_len > CCNINFO_MAX_REPLY_SIZE){
		/* Remove the Valation-related TLV from the message */
		msg_len = cef_valid_remove_valdsegs_fr_msg_forccninfo (msg, msg_len);
		if (msg_len <= CCNINFO_MAX_REPLY_SIZE){
			return (msg_len);
		}

		/***
                          1               2               3
	      0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
	     +---------------+---------------+---------------+---------------+
	     |    Version    |  PacketType   |         PacketLength          |
	     +---------------+---------------+-------------+-+---------------+
	     |    HopLimit   |   ReturnCode  |Reserved(MBZ)  | HeaderLength  |
	     +===============+===============+=============+=+===============+
	     |                                                               |
	     +                       Request block TLV                       +
	     |                                                               |
	     +---------------+---------------+---------------+---------------+
	     /                               .                               /
	     /                      n Report block TLVs                      /
	     /                               .                               /
	     +===============+===============+===============+===============+
	     |          T_DISCOVERY          |         MessageLength         |
	     +---------------+---------------+---------------+---------------+
	     |            T_NAME             |             Length            |
	     +---------------+---------------+---------------+---------------+
	     / Name segment TLVs (name prefix specified by ccninfo command) /
	     +---------------+---------------+---------------+---------------+
	     /                        Reply block TLV                        /
	     +---------------+---------------+---------------+---------------+
	     /                     Reply sub-block TLV 1                     /
	     /                               .                               /
		***/

		/* Obtains header length */
		fixed_hp 	= (struct fixed_hdr*) msg;
		hdr_len		= fixed_hp->hdr_len;
		pkt_len		= ntohs (fixed_hp->pkt_len);
		/* Obtains T_DISCOVERY Length 	*/
		tlv_ptr = (struct tlv_hdr*) &msg[hdr_len];
		dsc_len = ntohs (tlv_ptr->length);
		/* Obtains Validation Length 	*/
		vald_len = pkt_len - (dsc_len + CefC_S_TLF);
		/* Obtains T_NAME Length 	*/
		tlv_ptr = (struct tlv_hdr*)
					&msg[hdr_len+CefC_S_TLF /* T_DISCOVERY+MessageLength */];
		name_len = ntohs (tlv_ptr->length);

		/* Create NO_SPACE message */
		new_pkt_len = hdr_len
						+ CefC_S_TLF /* T_DISCOVERY+MessageLength	*/
						+ CefC_S_TLF /* T_NAME+Length				*/
						+ name_len;
		fixed_hp->pkt_len = htons (new_pkt_len);
		new_dsc_len = CefC_S_TLF /* T_NAME+Length				*/
						+ name_len;
		tlv_ptr = (struct tlv_hdr*) &msg[hdr_len];
		tlv_ptr->length = htons (new_dsc_len);
		msg[CefC_O_Fix_Type] 			= CefC_PT_REPLY;
		msg[CefC_O_Fix_Ccninfo_RetCode] 	= CefC_CtRc_NO_SPACE;

		if ( ccninfo_flag & CefC_CtOp_ReqValidation )	/* ccninfo-05 */
		{
		/* Validation */
		if ((new_pkt_len + vald_len) <= CCNINFO_MAX_REPLY_SIZE
			&& (hdl->ccninfo_valid_type != CefC_T_ALG_INVALID)) {
			CefT_Ccninfo_TLVs tlvs;
			tlvs.alg.valid_type = hdl->ccninfo_valid_type;
			new_pkt_len = cef_frame_ccninfo_vald_create_for_reply (msg, &tlvs);
		}
		}
		return (new_pkt_len);
	}
	return (msg_len);
}

/*--------------------------------------------------------------------------------------
	check state of port use
----------------------------------------------------------------------------------------*/
static int										/* No care now							*/
	cefnetd_check_state_of_port_use (
	CefT_Netd_Handle* hdl						/* cefnetd handle						*/
){
	char sock_path[CefC_BufSiz_1KB];
	int rc = 0;
	struct stat sb = {0};

	cef_client_local_sock_name_get (sock_path);
	rc = stat (sock_path, &sb);
	if (rc == 0) {
		cef_log_write (CefC_Log_Warn, "%s (%s)\n", __func__, strerror (errno));
		return (-1);
	}
	return (0);
}

/*--------------------------------------------------------------------------------------
	Prepares the UDP and TCP sockets to be polled
----------------------------------------------------------------------------------------*/
static int										/* number of the poll which has events	*/
cefnetd_poll_socket_prepare (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	struct pollfd fds[],
	CefC_Connection_Type fd_type[],
	int faceids[]
) {
	int res = 0;
	int i;
	int n;

	for (i = 0 ; i < hdl->inudpfdc ; i++) {
		if (cef_face_check_active (hdl->inudpfaces[i]) > 0) {
			fds[res].events = POLLIN | POLLERR;
			fds[res].fd = hdl->inudpfds[i].fd;
			fd_type[res] = CefC_Connection_Type_Udp;
			faceids[res] = hdl->inudpfaces[i];
			res++;
#if 0   // 2024/7/22
		} else {
			for (n = i ; n < hdl->inudpfdc - 1 ; n++) {
				hdl->inudpfds[n].fd = hdl->inudpfds[n + 1].fd;
				hdl->inudpfaces[n] 	= hdl->inudpfaces[n + 1];
			}
			hdl->inudpfdc--;
			i--;
#endif // 2024/7/22
		}
	}

	for (i = 0 ; i < hdl->intcpfdc ; i++) {
		if (cef_face_check_active (hdl->intcpfaces[i]) > 0) {
			fds[res].events = POLLIN | POLLERR;
			fds[res].fd = hdl->intcpfds[i].fd;
			fd_type[res] = CefC_Connection_Type_Tcp;
			faceids[res] = hdl->intcpfaces[i];
			res++;
		} else {
			for (n = i ; n < hdl->intcpfdc - 1 ; n++) {
				hdl->intcpfds[n].fd = hdl->intcpfds[n + 1].fd;
				hdl->intcpfaces[n] 	= hdl->intcpfaces[n + 1];
			}
			hdl->intcpfdc--;
			i--;
		}
	}

#if CefC_IsEnable_ContentStore
	if (hdl->cs_stat->local_sock != -1) {
		fds[res].events = POLLIN | POLLERR;
		fds[res].fd = hdl->cs_stat->local_sock;
		fd_type[res] = CefC_Connection_Type_Csm;
		faceids[res] = 0;
		res++;
	}

	if (hdl->cs_stat->tcp_sock != -1) {
		fds[res].events = POLLIN | POLLERR;
		fds[res].fd = hdl->cs_stat->tcp_sock;
		fd_type[res] = CefC_Connection_Type_Csm;
		faceids[res] = 0;
		res++;
	}
#endif // CefC_IsEnable_ContentStore

	for (i = 0 ; i < hdl->app_fds_num ; i++) {
		if (hdl->app_fds[i] != -1) {
			fds[res].events = POLLIN | POLLERR;
			fds[res].fd = hdl->app_fds[i] ;
			fd_type[res] = CefC_Connection_Type_Local;
			faceids[res] = 0;
			res++;
		}
	}

	return (res);
}
/*--------------------------------------------------------------------------------------
	Handles the elements of cs_stat TX queue
----------------------------------------------------------------------------------------*/
#if CefC_IsEnable_ContentStore
static int
cefnetd_csmgr_cob_forward (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int faceid,									/* Face-ID to reply to the origin of 	*/
	unsigned char* msg,							/* Receive message						*/
	uint16_t msg_len,							/* Length of message					*/
	uint32_t chunk_num							/* Chunk Number of content				*/
) {
	uint16_t name_len;
	uint16_t name_off;
	uint16_t pay_len;
	uint16_t pay_off;

	/* send content object */
	if (cef_face_check_active (faceid) > 0) {

		if (cef_face_is_local_face (faceid)) {
			cef_frame_payload_parse (
				msg, msg_len, &name_off, &name_len, &pay_off, &pay_len);
			if (pay_len != 0) {
				cef_face_frame_send_iflocal (faceid, msg, msg_len);
			}
		} else {
			/* face is not local */
			cefnetd_frame_send_txque (hdl, faceid, msg, msg_len);
		}
	} else {
		return (-1);
	}
	return (0);
}
#endif // CefC_IsEnable_ContentStore

static int										/* No care now							*/
cefnetd_input_from_csque_process (
	CefT_Netd_Handle* hdl						/* cefnetd handle						*/
) {

#if CefC_IsEnable_ContentStore
{	CefT_Cs_Stat* cs_stat = hdl->cs_stat;
	uint64_t nowt = cef_client_present_timeus_calc ();

	if ((hdl->cs_stat->cache_type != CefC_Default_Cache_Type)
		 && (nowt > hdl->send_next)) {
		int send_cnt = 0;
		uint64_t data_sum = 0;

		while (1) {
			/* Pop one element from the TX Ring Queue 		*/
			CefT_Cs_Tx_Elem* cs_tx_elem
				= (CefT_Cs_Tx_Elem*) cef_rngque_read (cs_stat->tx_que);

			if (cs_tx_elem == NULL) {
				break;
			}
			if (cs_tx_elem->type == CefC_Cs_Tx_Elem_Type_Cob) {
				CefT_Cs_Tx_Elem_Cob* cob_temp;

				cs_tx_elem = (CefT_Cs_Tx_Elem*) cef_rngque_pop (cs_stat->tx_que);

				/* send cob	*/
				cob_temp = (CefT_Cs_Tx_Elem_Cob*) cs_tx_elem->data;
				cefnetd_csmgr_cob_forward (hdl,
							cob_temp->faceid, cob_temp->cob.msg,
							cob_temp->cob.msg_len, cob_temp->cob.chunk_num);
				/* Free the pooled block 	*/
				data_sum += cob_temp->cob.msg_len;
				cef_mpool_free (cs_stat->tx_cob_mp, cob_temp);
				cef_mpool_free (cs_stat->tx_que_mp, cs_tx_elem);
				send_cnt++;
				hdl->stat_send_frames++;
			} else {
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine,
					"Memcache queue read the unknown type message\n");
#endif // CefC_Debug
				cef_rngque_pop (cs_stat->tx_que);
				cef_mpool_free (cs_stat->tx_que_mp, cs_tx_elem);
			}
			if (send_cnt > CefC_Csmgr_Max_Send_Num) {
				/* Temporarily suspend	*/
				break;
			}
		}
		/* set next	*/
		hdl->send_next = nowt + (hdl->send_rate * data_sum);
	}
}
#endif // CefC_IsEnable_ContentStore

	return (1);
}

/*--------------------------------------------------------------------------------------
	Accepts and receives the frame(s) from local face
----------------------------------------------------------------------------------------*/
static int										/* No care now							*/
cefnetd_input_from_local_process (
	CefT_Netd_Handle* hdl						/* cefnetd handle						*/
) {
	int sock;
	int work_peer_sock;
	struct sockaddr_un peeraddr;
	socklen_t addrlen = (socklen_t) sizeof (peeraddr);
	int len;
	int flag;
	int i;
	int peer_faceid;
	unsigned char buff[CefC_Max_Length];
	unsigned char* rsp_msg = hdl->app_rsp_msg;
	struct pollfd send_fds[1];
	char	user_id[512];

	/* Obtains the FD for local face 	*/
	sock = cef_face_get_fd_from_faceid (CefC_Faceid_Local);

	/* Accepts the interrupt from local process */
	if ((work_peer_sock = accept (sock, (struct sockaddr*)&peeraddr, &addrlen)) < 0) {
		/* NOP */;
	} else {
		if (hdl->app_fds_num < CefC_App_Conn_Num) {
			hdl->app_fds[hdl->app_fds_num] = work_peer_sock;

			flag = fcntl (hdl->app_fds[hdl->app_fds_num], F_GETFL, 0);
			if (flag < 0) {
				cef_log_write (CefC_Log_Info,
					"<Fail> cefnetd_input_from_local_process (fcntl)\n");
				work_peer_sock = -1;
			} else {
				if (fcntl (hdl->app_fds[hdl->app_fds_num]
									, F_SETFL, flag | O_NONBLOCK) < 0) {
					cef_log_write (CefC_Log_Info,
						"<Fail> cefnetd_input_from_local_process (fcntl)\n");
					work_peer_sock = -1;
				}
			}
			if (work_peer_sock != -1) {
				peer_faceid = cef_face_lookup_local_faceid (work_peer_sock);

				if (peer_faceid < 0) {
					char errmsg[BUFSIZ];
					sprintf(errmsg,"ERROR:cefnetd is resource busy, #%d.\n", work_peer_sock);
					write(work_peer_sock, errmsg, strlen(errmsg));
					close (hdl->app_steps[hdl->app_fds_num]);
					hdl->app_fds[hdl->app_fds_num] = -1;
				} else {
					hdl->app_faces[hdl->app_fds_num] = peer_faceid;
					hdl->app_steps[hdl->app_fds_num] = 0;
					hdl->app_fds_num++;
				}
			} else {
				close (hdl->app_steps[hdl->app_fds_num]);
				hdl->app_fds[hdl->app_fds_num] = -1;
			}
		} else {
			close (work_peer_sock);
		}
	}

	/* Checks whether frame(s) arrivals from the active local faces */
	for (i = 0 ; i < hdl->app_fds_num ; i++) {
		len = recv (hdl->app_fds[i], buff, CefC_Max_Length, 0);

		if (len > 0) {
			hdl->app_steps[i] = 0;

			if (memcmp (buff, CefC_Ctrl, CefC_Ctrl_Len) == 0) {
				flag = cefnetd_input_control_message (
						hdl, buff, len, &rsp_msg, hdl->app_fds[i]);
				if (flag > 0) {
					send_fds[0].fd = hdl->app_fds[i];
					send_fds[0].events = POLLOUT | POLLERR;
					if (poll (send_fds, 1, 0) > 0) {
						if (send_fds[0].revents & (POLLERR | POLLNVAL | POLLHUP)) {
							cef_log_write (CefC_Log_Warn,
								"Failed to send to Local peer (%d)\n", send_fds[0].fd);
						} else {
							{
								int	fblocks;
								int rem_size;
								int counter;
								int fcntlfl;
								fcntlfl = fcntl (hdl->app_fds[i], F_GETFL, 0);
								fcntl (hdl->app_fds[i], F_SETFL, fcntlfl & ~O_NONBLOCK);
								fblocks = flag / 65535;
								rem_size = flag % 65535;
								for (counter=0; counter<fblocks; counter++){
									send (hdl->app_fds[i], &rsp_msg[counter*65535], 65535, 0);
								}
								if (rem_size != 0){
									send (hdl->app_fds[i], &rsp_msg[fblocks*65535], rem_size, 0);
								}
								fcntl (hdl->app_fds[i], F_SETFL, fcntlfl | O_NONBLOCK);
							}
						}
					}
				}
			} else if (memcmp (buff, CefC_Face_Close, len) == 0) {

				cef_face_close (hdl->app_faces[i]);
				hdl->app_fds[i] = -1;
				hdl->app_fds_num--;

				for (flag = i ; flag < hdl->app_fds_num ; flag++) {
					hdl->app_fds[flag] = hdl->app_fds[flag + 1];
					hdl->app_faces[flag] = hdl->app_faces[flag + 1];
					hdl->app_steps[flag] = hdl->app_steps[flag + 1];
				}
				i--;
			} else {
				cefnetd_input_message_process (
						hdl, CefC_Faceid_Local, hdl->app_faces[i], buff, len, user_id);
			}
		}
		else {
			struct pollfd fds[1];
			fds[0].fd = hdl->app_fds[i];
			fds[0].events = POLLIN | POLLERR;
			poll (fds, 1, 0);
			if ((fds[0].revents & POLLIN) && (fds[0].revents & POLLHUP)) {
				cef_face_close (hdl->app_faces[i]);
				hdl->app_fds[i] = -1;
				hdl->app_fds_num--;

				for (flag = i ; flag < hdl->app_fds_num ; flag++) {
					hdl->app_fds[flag] = hdl->app_fds[flag + 1];
					hdl->app_faces[flag] = hdl->app_faces[flag + 1];
					hdl->app_steps[flag] = hdl->app_steps[flag + 1];
				}
				i--;
			}
		}
	}

	if (!hdl->babel_use_f) {
		return (1);
	}

	/* Obtains the FD for local face 	*/
	sock = cef_face_get_fd_from_faceid (CefC_Faceid_ListenBabel);

	/* Accepts the interrupt from local process */
	if ((work_peer_sock = accept (sock, (struct sockaddr*)&peeraddr, &addrlen)) < 0) {
		/* NOP */;
	} else {
		if (hdl->babel_sock > 0) {
			cef_face_close (hdl->babel_face);
			hdl->babel_sock = -1;
			hdl->babel_face = -1;
		}
		flag = fcntl (work_peer_sock, F_GETFL, 0);
		if (flag < 0) {
			cef_log_write (CefC_Log_Info,
				"<Fail> cefnetd_input_from_local_process (fcntl)\n");
			work_peer_sock = -1;
		} else {
			if (fcntl (work_peer_sock, F_SETFL, flag | O_NONBLOCK) < 0) {
				cef_log_write (CefC_Log_Info,
					"<Fail> cefnetd_input_from_local_process (fcntl)\n");
				work_peer_sock = -1;
			}
		}
		if (work_peer_sock != -1) {
			peer_faceid = cef_face_lookup_local_faceid (work_peer_sock);

			if (peer_faceid < 0) {
				close (work_peer_sock);
			} else {
				hdl->babel_sock = work_peer_sock;
				hdl->babel_face = peer_faceid;
			}
		} else {
			close (work_peer_sock);
		}
	}

	if (hdl->babel_sock < 0) {
		return (1);
	}

	/* Checks whether frame(s) arrivals from the active local faces */
	len = recv (hdl->babel_sock, buff, CefC_Max_Length, 0);

	if (len > 0) {

		if (memcmp (buff, CefC_Ctrl, CefC_Ctrl_Len) == 0) {
			memset (rsp_msg, 0, CefC_Max_Length);
			flag = cefnetd_input_control_message (
					hdl, buff, len, &rsp_msg, hdl->babel_sock);
			if (flag > 0) {
				{
					int	fblocks;
					int rem_size;
					int counter;
					int fcntlfl;
					fcntlfl = fcntl (hdl->babel_sock, F_GETFL, 0);
					fcntl (hdl->babel_sock, F_SETFL, fcntlfl & ~O_NONBLOCK);
					fblocks = flag / 65535;
					rem_size = flag % 65535;
					for (counter=0; counter<fblocks; counter++){
						send (hdl->babel_sock, &rsp_msg[counter*65535], 65535, 0);
					}
					if (rem_size != 0){
						send (hdl->babel_sock, &rsp_msg[fblocks*65535], rem_size, 0);
					}
					fcntl (hdl->babel_sock, F_SETFL, fcntlfl | O_NONBLOCK);
				}
			}
		} else if (memcmp (buff, CefC_Face_Close, len) == 0) {
			cef_face_close (hdl->babel_face);
			hdl->babel_sock = -1;
			hdl->babel_face = -1;
		} else {
			/* NOP */;
		}
	}
	else {
		struct pollfd fds[1];
		int kerrno;
		kerrno = errno;
		fds[0].fd = hdl->babel_sock;
		fds[0].events = POLLIN | POLLERR;
		poll (fds, 1, 0);
		if (fds[0].revents & (POLLIN | POLLHUP)) {
			if((fds[0].revents == POLLIN) && (kerrno == EAGAIN || kerrno == EWOULDBLOCK)) {
				; // NOP
			} else {
				cef_face_close (hdl->babel_face);
				hdl->babel_sock = -1;
				hdl->babel_face = -1;
			}
		}
	}

	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the message to reg/dereg application name
----------------------------------------------------------------------------------------*/
static
char *
cefnetd_name_to_uri(
	CefT_CcnMsg_MsgBdy*	pm,				/* Structure to set parsed CEFORE message	*/
	char	*buff_uri,
	size_t	buff_siz
){
	if ( pm->name_len < CefC_NAME_MAXLEN ){
		cef_frame_conversion_name_to_uri (pm->name, pm->name_len, buff_uri);
	} else {
		snprintf (buff_uri, buff_siz, "ccnx:/name_len=%d", pm->name_len);
	}
	return buff_uri;
}

static int
cefnetd_input_app_reg_command (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh,				/* Parsed Option Header						*/
	uint16_t faceid
) {
	CefT_App_Reg* wp;
	CefT_Pit_Entry* pe = NULL;

#ifdef CefC_Debug
	memset (cnd_dbg_msg, 0, sizeof (cnd_dbg_msg));
	if (poh->app_reg_f == CefC_T_OPT_APP_DEREG) {
		sprintf (cnd_dbg_msg, "Unreg the application name filter [");
	} else if (poh->app_reg_f == CefC_T_OPT_APP_REG){
		sprintf (cnd_dbg_msg, "Reg the application name filter [");
	} else if (poh->app_reg_f == CefC_T_OPT_APP_REG_P) {
		sprintf (cnd_dbg_msg, "Reg(prefix) the application name filter [");
	} else if (poh->app_reg_f == CefC_T_OPT_APP_PIT_REG) {
		sprintf (cnd_dbg_msg, "Reg(PIT) the application name filter [");
	} else if (poh->app_reg_f == CefC_T_OPT_APP_PIT_DEREG) {
		sprintf (cnd_dbg_msg, "Unreg(PIT) the application name filter [");
	} else if (poh->app_reg_f == CefC_T_OPT_DEV_REG_PIT){
		sprintf (cnd_dbg_msg, "Reg(PIT) the develop name filter [");
	} else {
		sprintf (cnd_dbg_msg, "Unknown the application name filter [");
	}
	cef_dbg_buff_write_name (CefC_Dbg_Finer,
								(unsigned char*)cnd_dbg_msg, strlen(cnd_dbg_msg),
								pm->name, pm->name_len,
								(unsigned char*)" ]\n", strlen(" ]\n"));
#endif // CefC_Debug

	/* Max Check */
	if ( (poh->app_reg_f == CefC_T_OPT_APP_REG ) || (poh->app_reg_f == CefC_T_OPT_APP_REG_P) ) {
		if( cef_hash_tbl_item_num_get(hdl->app_reg) == cef_hash_tbl_def_max_get(hdl->app_reg)) {
		cef_log_write (CefC_Log_Warn,
			"FIB(APP) table is full(FIB_SIZE_APP = %d)\n", cef_hash_tbl_def_max_get(hdl->app_reg));
		return (0);
		}
	} else if (poh->app_reg_f == CefC_T_OPT_APP_PIT_REG) {
		if( cef_lhash_tbl_item_num_get(hdl->app_pit) == cef_lhash_tbl_def_max_get(hdl->app_pit)) {
		cef_log_write (CefC_Log_Warn,
			"PIT(APP) table is full(PIT_SIZE_APP = %d)\n", cef_lhash_tbl_def_max_get(hdl->app_pit));
		return (0);
		}
	}
	if (poh->app_reg_f == CefC_T_OPT_DEV_REG_PIT) {
		if (cef_lhash_tbl_item_num_get(hdl->pit) == cef_lhash_tbl_def_max_get(hdl->pit)) {
			cef_log_write (CefC_Log_Warn,
				"PIT table is full(PIT_SIZE = %d)\n", cef_lhash_tbl_def_max_get(hdl->pit));
			return (0);
		}
	}

	if (poh->app_reg_f == CefC_T_OPT_APP_REG || poh->app_reg_f == CefC_T_OPT_APP_REG_P) {
		wp = (CefT_App_Reg*) malloc (sizeof (CefT_App_Reg));
		if (wp == NULL){
			cef_log_write (CefC_Log_Warn, "%s CefT_App_Reg memory allocation failed. (%s)\n"
							, __func__, strerror(errno));
			return (0);
		}
		wp->faceid = faceid;
		wp->name_len = pm->name_len;
		memcpy (wp->name, pm->name, pm->name_len);
		if (poh->app_reg_f == CefC_T_OPT_APP_REG) {
			wp->match_type = CefC_App_MatchType_Exact;
		} else {
			wp->match_type = CefC_App_MatchType_Prefix;
		}
		if (CefC_Hash_Faile !=
				cef_hash_tbl_item_set_for_app (hdl->app_reg, pm->name,
											   pm->name_len, wp->match_type, wp)) {
			cefnetd_xroute_change_report (hdl, pm->name, pm->name_len, 1);
		}
		else{
			char uri[CefC_NAME_BUFSIZ];
			cefnetd_name_to_uri (pm, uri, sizeof(uri));
			cef_log_write (CefC_Log_Warn, "This Name[%s] has already been registered or can't register any more, so SKIP register\n", uri);
			if (wp) {
				free(wp);
			}
		}
	} else if (poh->app_reg_f == CefC_T_OPT_APP_DEREG) {
		wp = (CefT_App_Reg*)
				cef_hash_tbl_item_remove (hdl->app_reg, pm->name, pm->name_len);

		if (wp) {
			cefnetd_xroute_change_report (hdl, pm->name, pm->name_len, 0);
			free(wp);
		}
	} else if (poh->app_reg_f == CefC_T_OPT_APP_PIT_REG) {
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "OPT_APP_PIT_REG:lifetime_f=%d, lifetime=%u.\n", poh->lifetime_f, poh->lifetime);
#endif // CefC_Debug
		/* Searches a PIT entry matching this Command 	*/
		pe = cef_pit_entry_lookup_with_lock (hdl->app_pit, pm, poh, pm->name, pm->name_len, CefC_Pit_WithLOCK);
		if (pe == NULL) {
			char uri[CefC_NAME_BUFSIZ];
			cefnetd_name_to_uri (pm, uri, sizeof(uri));
			cef_log_write (CefC_Log_Warn, "This Name[%s] can't registered in PIT, so SKIP register\n", uri);
			return (1);
		}
		/* Updates the information of down face that this Command arrived 	*/
		cef_pit_entry_down_face_update (pe, faceid, pm, poh, NULL, CefC_IntRetrans_Type_NOSUP);	//0.8.3
		cef_pit_entry_unlock (pe);
	} else if (poh->app_reg_f == CefC_T_OPT_APP_PIT_DEREG) {
		/* Searches a PIT entry matching this Command 	*/
		pe = cef_pit_entry_search (hdl->app_pit, pm, poh, NULL, 0);
		if (pe != NULL && cef_pit_entry_lock(pe)){
			cef_pit_entry_free (hdl->app_pit, pe);
		}
	} else if (poh->app_reg_f == CefC_T_OPT_DEV_REG_PIT) {
		int cnt;
		int pit_max, pit_num;

		pit_num = cef_lhash_tbl_item_num_get(hdl->pit);
		pit_max = cef_lhash_tbl_def_max_get(hdl->pit);

		if ( pm->InterestType == CefC_PIT_TYPE_Sym ) {
			pe = cef_pit_entry_lookup_and_down_face_update (hdl->pit, pm, poh, NULL, 0,
						faceid, NULL, CefC_IntRetrans_Type_NOSUP, NULL);
			if (pe) {
				/* Restore the length of the name */
				pm->name_len -= (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
			}
		} else {
			for (cnt = 0; cnt < poh->dev_reg_pit_num;cnt++) {
				if (pit_num < pit_max) {
					uint32_t chunk_num_wk;
					uint16_t chunk_len_wk;
					uint16_t ftvn_chunk;
					int idx = 0;

					chunk_num_wk = htonl(cnt);
					chunk_len_wk = htons(CefC_S_ChunkNum);
					ftvn_chunk = htons (CefC_T_CHUNK);

					memcpy (&(pm->name[pm->name_len+idx]), &ftvn_chunk, CefC_S_Type);
					idx += CefC_S_Type;
					memcpy (&(pm->name[pm->name_len+idx]), &chunk_len_wk, CefC_S_Length);
					idx += CefC_S_Length;
					memcpy (&(pm->name[pm->name_len+idx]), &chunk_num_wk, CefC_S_ChunkNum);
					pm->name_len += (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);

					pe = cef_pit_entry_lookup_and_down_face_update (hdl->pit, pm, poh, NULL, 0,
								faceid, NULL, CefC_IntRetrans_Type_NOSUP, NULL);
					if (pe) {
						/* Restore the length of the name */
						pm->name_len -= (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
					} else {
						break;
					}
					pit_num++;
				} else {
					cef_log_write (CefC_Log_Warn, "PIT table is full(PIT_SIZE = %d)\n", pit_max);
					break;
				}
			}
		}
	}

	return (1);
}
/*--------------------------------------------------------------------------------------
	Report xroute is changed to cefbabeld
----------------------------------------------------------------------------------------*/
static void
cefnetd_xroute_change_report (
	CefT_Netd_Handle* hdl,
	unsigned char* name,
	uint16_t name_len,
	int reg_f
) {
	unsigned char buff[CefC_Max_Length];
	int rc;
	uint16_t length;

	if ((!hdl->babel_use_f) || (hdl->babel_sock < 0)) {
		return;
	}

	buff[0] = 0x03;
	length = sizeof (uint16_t) + name_len + 1;
	memcpy (&buff[1], &length, sizeof (uint16_t));

	buff[3] = (reg_f) ? 0x01 : 0x00;

	memcpy (&buff[4], &name_len, sizeof (uint16_t));
	memcpy (&buff[4 + sizeof (uint16_t)], name, name_len);

	rc = send (hdl->babel_sock, buff, length + 3, 0);
	if (rc < 0) {
		cef_face_close (hdl->babel_face);
		hdl->babel_sock = -1;
		hdl->babel_face = -1;
	}

	return;
}

/*--------------------------------------------------------------------------------------
	Handles the FIB request message
----------------------------------------------------------------------------------------*/
static int
cefnetd_fib_info_get (
	CefT_Netd_Handle* hdl,
	unsigned char** rsp_msgpp
) {
	uint32_t msg_len = 5; /* code(1byte)+length(4byte) */
	uint32_t length;
	CefT_App_Reg* aentry;
	uint32_t index = 0;
	CefT_Fib_Entry* fentry = NULL;
	int table_num;
	int i;
	char* buff;
	int buff_size;

	buff = (char*)*rsp_msgpp;
	buff_size = CefC_Max_Length;

	if (!hdl->babel_use_f) {
		buff[0] = 0x01;
		length = 0;
		memcpy (&buff[1], &length, sizeof (uint32_t));
		return (5);
	}

	do {
		aentry = (CefT_App_Reg*)
					cef_hash_tbl_item_check_from_index (hdl->app_reg, &index);

		if (aentry) {
			if ((msg_len + sizeof (uint16_t) + aentry->name_len) > buff_size){
				void *new = realloc(buff, buff_size+CefC_Max_Length);
				if (new == NULL) {
					buff[0] = 0x01;
					length = 0;
					memcpy (&buff[1], &length, sizeof (uint32_t));
					return (5);
				}
				buff = new;
				*rsp_msgpp = (unsigned char*)new;
				buff_size += CefC_Max_Length;
			}
			memcpy (&buff[msg_len], &aentry->name_len, sizeof (uint16_t));
			memcpy (&buff[msg_len + sizeof (uint16_t)], aentry->name, aentry->name_len);
			msg_len += sizeof (uint16_t) + aentry->name_len;
		}
		index++;
	} while (aentry);

	table_num = cef_hash_tbl_item_num_get (hdl->fib);
	index = 0;

	for (i = 0; i < table_num; i++) {
		fentry = (CefT_Fib_Entry*) cef_hash_tbl_elem_get (hdl->fib, &index);
		if (fentry == NULL) {
			break;
		}

		/* Face Check */
		{
			CefT_Fib_Face* faces = NULL;
			int			type_c = 0;
			int			type_s = 0;
			int			type_d = 0;

			faces = fentry->faces.next;
			while (faces != NULL) {

				if ( (faces->type >> 2) & 0x01 ) {
					type_c = 1;
				}
				if ( (faces->type >> 1) & 0x01 ) {
					type_s = 1;
				}
				if ( (faces->type) & 0x01 ) {
					type_d = 1;
				}
				faces = faces->next;
			}
			if ( (type_c == 0) && (type_s == 0) && (type_d == 1) ) {
				index++;
				continue;
			}
		}

		if ((msg_len + sizeof (uint16_t) + fentry->klen) > buff_size){
			void *new = realloc(buff, buff_size+CefC_Max_Length);
			if (new == NULL) {
				buff[0] = 0x01;
				length = 0;
				memcpy (&buff[1], &length, sizeof (uint32_t));
				return (5);
			}
			buff = new;
			*rsp_msgpp = (unsigned char*)new;
			buff_size += CefC_Max_Length;
		}
		memcpy (&buff[msg_len], &fentry->klen, sizeof (uint16_t));
		memcpy (&buff[msg_len + sizeof (uint16_t)], fentry->key, fentry->klen);
		msg_len += sizeof (uint16_t) + fentry->klen;
		index++;
	}

	buff[0] = 0x01;
	length = msg_len - 5;
	memcpy (&buff[1], &length, sizeof (uint32_t));

	return ((int) msg_len);
}
/*--------------------------------------------------------------------------------------
	Handles the command from babeld
----------------------------------------------------------------------------------------*/
static int
cefnetd_babel_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	unsigned char* msg,
	int msg_len,
	unsigned char* buff
) {
	uint8_t opetype;
	uint16_t index;
	struct tlv_hdr* tlv_hdr;
	uint16_t prefix_len, prefix_index;
	uint16_t node_len, node_index;
	uint16_t length;
	int rcu, rct;
	char uri[CefC_NAME_BUFSIZ];
//	int change_f;
	int change_f = 0;

	CefT_Fib_Metric		fib_metric;	//0.8.3c

	if (!hdl->babel_use_f) {
		return (0);
	}

#ifdef	_DEBUG_BABEL_
	{
		int dbg_x;
		fprintf (stderr, "[%s] Input msg_len:%d\n", __func__, msg_len );
		fprintf (stderr, "Msg [ ");
		for (dbg_x = 0 ; dbg_x < msg_len ; dbg_x++) {
			fprintf (stderr, "%02x ", msg[dbg_x]);
		}
		fprintf (stderr, "](%d)\n", msg_len);
	}
#endif

	memset( &fib_metric, 0x00, sizeof(CefT_Fib_Metric) );

	/*-----------------------------------------------------------
		Parses the command from babeld
	-------------------------------------------------------------*/
	switch (msg[0]) {
	case 'A': {
		opetype = 0x01;
		break;
	}
	case 'D': {
		opetype = 0x02;
		break;
	}
	default: {
		opetype = 0x00;
		break;
	}
	if (opetype == 0) {
		return (0);
	}
	}
	index = 1;

	memcpy (&length, &msg[index], sizeof (uint16_t));
	index += sizeof (uint16_t);

	/* Obtains the prefix			*/
	tlv_hdr = (struct tlv_hdr*) &msg[index];
	if (tlv_hdr->type != 0x0000) {
		return (0);
	}
	prefix_len   = tlv_hdr->length;
	prefix_index = index + sizeof (struct tlv_hdr);
	index += sizeof (struct tlv_hdr) + prefix_len;

	/* Obtains the nexthop			*/
	tlv_hdr = (struct tlv_hdr*) &msg[index];
#ifdef	_DEBUG_BABEL_
	fprintf (stderr, "tlv_hdr->type %d \n", tlv_hdr->type );
	fprintf (stderr, "tlv_hdr->length %d \n", tlv_hdr->length );
#endif
	if (tlv_hdr->type != 0x0001) {
		return (0);
	}
	node_len   = tlv_hdr->length;
	node_index = index + sizeof (struct tlv_hdr);
	index += sizeof (struct tlv_hdr) + node_len;

	//0.8.3 S
	if ( opetype == 0x01 ) {
		struct value16_tlv*	v16_tlv;
		//Metric
		index += sizeof (unsigned short);
		v16_tlv = (struct value16_tlv*) &msg[index];
#ifdef	_DEBUG_BABEL_
	fprintf (stderr, "index %d \n", index );
	fprintf (stderr, "v16_tlv->type %d \n", v16_tlv->type );
	fprintf (stderr, "v16_tlv->length %d \n", v16_tlv->length );
	fprintf (stderr, "v16_tlv->value %d \n", v16_tlv->value );
#endif
		fib_metric.cost = v16_tlv->value;

		index += sizeof (struct value16_tlv);
		v16_tlv = (struct value16_tlv*) &msg[index];
#ifdef	_DEBUG_BABEL_
	fprintf (stderr, "index %d \n", index );
	fprintf (stderr, "v16_tlv->type %d \n", v16_tlv->type );
	fprintf (stderr, "v16_tlv->length %d \n", v16_tlv->length );
	fprintf (stderr, "v16_tlv->value %d \n", v16_tlv->value );
#endif
		fib_metric.dummy_metric = v16_tlv->value;
	}
	//0.8.3 E

	/*-----------------------------------------------------------
		Creates the FIB route message
	-------------------------------------------------------------*/

	/* Set operation 		*/
	buff[0] = opetype;
	index = 2;

	/* Set URI		 		*/
	cef_frame_conversion_name_to_uri (&msg[prefix_index], prefix_len, uri);
	prefix_len = (uint16_t) strlen (uri);
	memcpy (&buff[index], &prefix_len, sizeof (uint16_t));
	index += sizeof (uint16_t);
	memcpy (&buff[index], uri, prefix_len);
	index += prefix_len;

	/* Set host		 		*/
	buff[index] = (uint8_t) node_len;
	index++;
	memcpy (&buff[index], &msg[node_index], node_len);
	index += node_len;
	rcu = rct = 0;

	/* Update FIB with TCP			*/
	if (hdl->babel_route & 0x01) {
		buff[1] = 0x01;
		rcu = cef_fib_route_msg_read (
				hdl->fib, buff, index, CefC_Fib_Entry_Dynamic, &change_f, &fib_metric);		//0.8.3c
	}

	/* Update FIB with UDP			*/
	if (hdl->babel_route & 0x02) {
		buff[1] = 0x02;
		rct = cef_fib_route_msg_read (
				hdl->fib, buff, index, CefC_Fib_Entry_Dynamic, &change_f, &fib_metric);		//0.8.3c
	}

	if (rcu + rct) {
		cef_face_update_listen_faces (
			hdl->inudpfds, hdl->inudpfaces, &hdl->inudpfdc,
			hdl->intcpfds, hdl->intcpfaces, &hdl->intcpfdc);
	}

	buff[0] = 0x02;
	buff[1] = 0x01;
	buff[2] = 0x01;

	return (3);
}
/*--------------------------------------------------------------------------------------
	Handles the control message
----------------------------------------------------------------------------------------*/
static int
cefnetd_input_control_message (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	unsigned char* msg, 						/* the received message(s)				*/
	int msg_size,								/* size of received message(s)			*/
	unsigned char** rspp,
	int fd
) {
	int index;
	int res = 0;
	int rc, change_f;
	unsigned char name[CefC_NAME_MAXLEN];
	int name_len;
	CefT_Cefstatus_Msg	cefstaus_msg;
	uint16_t	out_opt;

	if (memcmp (&msg[CefC_Ctrl_Len], CefC_Ctrl_Kill, CefC_Ctrl_Kill_Len) == 0) {

		index = CefC_Ctrl_Len + CefC_Ctrl_Kill_Len;
		if ((memcmp (&msg[index], root_user_name, CefC_Ctrl_User_Len) == 0) ||
			(memcmp (&msg[index], hdl->launched_user_name, CefC_Ctrl_User_Len) == 0)) {
			cefnetd_running_f = 0;
			return (-1);
		} else {
			cef_log_write (CefC_Log_Warn, "Permission denied (cefnetdstop)\n");
		}
	} else if (
			memcmp (&msg[CefC_Ctrl_Len], CefC_Ctrl_StatusPit, CefC_Ctrl_StatusPit_Len) == 0) {
		res = cef_status_stats_output_pit (hdl);
		return (-1);
	} else if (
			memcmp (&msg[CefC_Ctrl_Len], CefC_Ctrl_StatusStat, CefC_Ctrl_StatusStat_Len) == 0) {
		memset (&cefstaus_msg, 0, sizeof(CefT_Cefstatus_Msg));
		memcpy (cefstaus_msg.msg, CefC_Ctrl_StatusStat, CefC_Ctrl_StatusStat_Len);
		index = CefC_Ctrl_Len + CefC_Ctrl_StatusStat_Len;
		/* output option */
		memcpy (&cefstaus_msg.msg[CefC_Ctrl_StatusStat_Len], &msg[index], sizeof (uint16_t));
		memcpy (&out_opt, &msg[index], sizeof (uint16_t));
		if ( out_opt & CefC_Ctrl_StatusOpt_Numofpit ) {
			index += sizeof (uint16_t);
			uint16_t	numofpit;
			memcpy( &numofpit, &msg[index], sizeof (uint16_t));
			memcpy (&cefstaus_msg.msg[CefC_Ctrl_StatusStat_Len + sizeof (uint16_t)], &numofpit, sizeof (uint16_t));
		}
		cefstaus_msg.resp_fd = fd;
		res = write(hdl->cefstatus_pipe_fd[0], &cefstaus_msg, sizeof(CefT_Cefstatus_Msg));
		if ( res != sizeof(CefT_Cefstatus_Msg) ){
			char buf_errmsg[BUFSIZ];
#ifdef	CefC_Debug
cef_dbg_write (CefC_Dbg_Fine, "write(cefstatus_pipe)=%d, %s\n", res, strerror(errno));
#endif	// CefC_Debug
			cef_log_write (CefC_Log_Info, "write(cefstatus_pipe)=%d, %s\n", res, strerror(errno));
			sprintf(buf_errmsg, "ERROR:write(cefstatus_pipe)=%d, %s\n", res, strerror(errno));
			write(fd, buf_errmsg, strlen(buf_errmsg));
		}
		return (-1);
	} else if (
			memcmp (&msg[CefC_Ctrl_Len], CefC_Ctrl_Status, CefC_Ctrl_Status_Len) == 0) {
		memset( &cefstaus_msg, 0, sizeof(CefT_Cefstatus_Msg) );
		memcpy( cefstaus_msg.msg, CefC_Ctrl_Status, CefC_Ctrl_Status_Len );
		cefstaus_msg.resp_fd = fd;
		res = write(hdl->cefstatus_pipe_fd[0], &cefstaus_msg, sizeof(CefT_Cefstatus_Msg));
		if ( res != sizeof(CefT_Cefstatus_Msg) ){
			char buf_errmsg[BUFSIZ];
#ifdef	CefC_Debug
cef_dbg_write (CefC_Dbg_Fine, "write(cefstatus_pipe)=%d, %s\n", res, strerror(errno));
#endif	// CefC_Debug
			cef_log_write (CefC_Log_Info, "write(cefstatus_pipe)=%d, %s\n", res, strerror(errno));
			sprintf(buf_errmsg, "ERROR:write(cefstatus_pipe)=%d, %s\n", res, strerror(errno));
			write(fd, buf_errmsg, strlen(buf_errmsg));
		}
		return (-1);
	} else if (memcmp (&msg[CefC_Ctrl_Len], CefC_Ctrl_Route, CefC_Ctrl_Route_Len) == 0) {
		index = CefC_Ctrl_Len + CefC_Ctrl_Route_Len;
		if ((memcmp (&msg[index], root_user_name, CefC_Ctrl_User_Len) == 0) ||
			(memcmp (&msg[index], hdl->launched_user_name, CefC_Ctrl_User_Len) == 0)) {
			/* Own IP_addr check */
			unsigned char chk_msg[CefC_Max_Length] = {0};
			memcpy( chk_msg, &msg[index + CefC_Ctrl_User_Len],
						msg_size - (CefC_Ctrl_Len + CefC_Ctrl_Route_Len + CefC_Ctrl_User_Len) );
			res = cefnetd_route_msg_check( hdl, chk_msg, msg_size - (CefC_Ctrl_Len + CefC_Ctrl_Route_Len + CefC_Ctrl_User_Len) );
			if ( res < 0 ) {
				/* Error */
				return(0);
			}

			rc = cef_fib_route_msg_read (
				hdl->fib,
				&msg[index + CefC_Ctrl_User_Len],
				msg_size - (CefC_Ctrl_Len + CefC_Ctrl_Route_Len + CefC_Ctrl_User_Len),
				CefC_Fib_Entry_Static, &change_f, NULL);		//0.8.3c
#ifdef	CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "cef_fib_route_msg_read, rc=%d\n", rc);
			if ( rc < 0 ) {
cef_dbg_write (CefC_Dbg_Fine, "ERROR:cef_fib_route_msg_read, rc=%d\n", rc);
			}
#endif	// CefC_Debug
			cef_fib_faceid_cleanup (hdl->fib);
			if (rc > 0) {
				cef_face_update_listen_faces (
					hdl->inudpfds, hdl->inudpfaces, &hdl->inudpfdc,
					hdl->intcpfds, hdl->intcpfaces, &hdl->intcpfdc);
			}
			if (hdl->babel_use_f && change_f) {
				name_len = cef_fib_name_get_from_route_msg (
					&msg[index + CefC_Ctrl_User_Len],
					msg_size - (CefC_Ctrl_Len + CefC_Ctrl_Route_Len + CefC_Ctrl_User_Len),
					name);
				cefnetd_xroute_change_report (
					hdl, name, name_len, (change_f == 0x02) ? 0 : 1);
			}
		} else {
#ifdef	CefC_Debug
cef_dbg_write (CefC_Dbg_Fine, "Permission denied (cefroute)\n");
#endif	// CefC_Debug
			cef_log_write (CefC_Log_Error, "Permission denied (cefroute)\n");
		}
	} else if (memcmp (&msg[CefC_Ctrl_Len], CefC_Ctrl_Babel, CefC_Ctrl_Babel_Len) == 0) {
		index = CefC_Ctrl_Len + CefC_Ctrl_Babel_Len;

		switch (msg[index]) {
		case 'R': {
			res = cefnetd_fib_info_get (hdl, rspp);
			break;
		}
		case 'A': {
			res = cefnetd_babel_process (hdl, &msg[index],
				msg_size - (CefC_Ctrl_Len + CefC_Ctrl_Babel_Len), *rspp);
			break;
		}
		case 'D': {
			res = cefnetd_babel_process (hdl, &msg[index],
				msg_size - (CefC_Ctrl_Len + CefC_Ctrl_Babel_Len), *rspp);
			break;
		}
		default: {
#ifdef	CefC_Debug
cef_dbg_write (CefC_Dbg_Fine, "Illegal message (cefbabel)\n");
#endif	// CefC_Debug
			break;
		}
		}
	}

	return (res);
}
/*--------------------------------------------------------------------------------------
	Handles the input message
----------------------------------------------------------------------------------------*/
#define	NS_INADDRSZ		4
#define	NS_IN6ADDRSZ	16
static int
cefnetd_broadcast_filter(
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	struct sockaddr_in *sa,
	socklen_t sa_len
) {
static char in6_broadcast[NS_IN6ADDRSZ] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff
	};
	int result = 0;
#ifdef CefC_Debug
	char src_addr[NI_MAXHOST];
	char buff[NI_MAXHOST];

	memset(src_addr, 0x00, sizeof(src_addr));
	switch ( sa->sin_family ){
	case AF_INET:
		inet_ntop(AF_INET, &sa->sin_addr, src_addr,  NI_MAXHOST);
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, &sa->sin_addr, src_addr,  NI_MAXHOST);
		break;
	default:
		sprintf(src_addr, "[unknown sin_family=0x%x]", sa->sin_family);
		break;
	}
#endif // CefC_Debug

	switch ( sa->sin_family ){
	case AF_INET:
		for (int i = 0 ; !result && i < hdl->nodeid4_num ; i++) {
#ifdef CefC_Debug
inet_ntop(AF_INET, (struct sockaddr_in *)hdl->nodeid4[i], buff,  NI_MAXHOST);
cef_dbg_write (CefC_Dbg_Finest, "nodeid4[%d]: %s.\n", i, buff);
#endif // CefC_Debug
			if ( !memcmp(hdl->nodeid4[i], &(sa->sin_addr), NS_INADDRSZ) ) {
				result = -1;
			}
		}
		break;
	case AF_INET6:
		// IPv6 broadcast address
		if ( !memcmp(in6_broadcast, &(sa->sin_addr), NS_IN6ADDRSZ) ) {
			result = -1;
			break;
		}
		for (int i = 0; !result && i < hdl->nodeid16_num; i++ ) {
#ifdef CefC_Debug
inet_ntop(AF_INET6, (struct sockaddr_in *)hdl->nodeid16[i], buff,  NI_MAXHOST);
cef_dbg_write (CefC_Dbg_Finest, "nodeid16[%d]: %s.\n", i, buff);
#endif // CefC_Debug
			if ( !memcmp(hdl->nodeid16[i], &(sa->sin_addr), NS_IN6ADDRSZ) ) {
				result = -1;
			}
		}
		break;
	}
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "src_addr=%s, result=%d.\n", src_addr, result);
#endif // CefC_Debug
	return result;
}

static int
cefnetd_udp_input_process_core (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	int faceid									/* Face-ID that message arrived 		*/
) {
	int protocol;
	size_t recv_len;
	int peer_faceid;
	struct sockaddr_storage sas;
	struct addrinfo *sas_p = (struct addrinfo *)&sas;
	socklen_t sas_len = (socklen_t) sizeof (struct addrinfo);
	unsigned char buff[CefC_Max_Length];
	char user_id[512];	//0.8.3

	/* Receives the message(s) from the specified FD */
	recv_len
		= recvfrom (fd, buff, CefC_Max_Length, 0, (struct sockaddr*) &sas, &sas_len);

	if ( cefnetd_broadcast_filter(hdl, (struct sockaddr_in *)&sas, sas_len) ){
		return (-1);
	}

	// TBD: process for the special message

	/* Looks up the peer Face-ID 		*/
	protocol = cef_face_get_protocol_from_fd (fd);
	peer_faceid = cef_face_lookup_peer_faceid (sas_p/*&sas*/, sas_len, protocol, user_id);	//0.8.3
	if (peer_faceid < 0) {
		cef_log_write (CefC_Log_Error, "cef_face_lookup_peer_faceid() missing the fd=%d, sas_len=%d.\n", fd, sas_len);
		return (-1);
	}

#ifdef __APPLE__
	{
		CefT_Face*	face;
		int			ifindex;
		int			rc;

		struct sockaddr_storage ss;
		socklen_t sslen = sizeof(ss);

		if ((rc = getsockname(fd, (struct sockaddr *)&ss, &sslen)) < 0){
			return (-1);
		}
		if (((struct sockaddr *)&ss)->sa_family == AF_INET6) {
			face = cef_face_get_face_from_faceid (peer_faceid);
			if (face->ifindex == -1) {
				CefT_Hash_Handle* sock_tbl;
				CefT_Sock* sock;
				struct in6_pktinfo pinfo;
				char dst_addr[256];
				sock_tbl = cef_face_return_sock_table ();
				sock = (CefT_Sock*) cef_hash_tbl_item_get_from_index (*sock_tbl, face->index);

				{/* get ifindex */
					char	*ifname_p;
					char	hostname[NI_MAXHOST];
					int		result;
					result = getnameinfo ((struct sockaddr*) sas_p, sas_len,
											hostname, sizeof (hostname), 0, 0, NI_NUMERICHOST);
					if (result != 0) {
						cef_log_write (CefC_Log_Error, "%s (getnameinfo:%s)\n", __func__, gai_strerror(result));
						return (-1);
					}
					ifname_p = strchr(hostname, '%');
					if(ifname_p == NULL){
						cef_log_write (CefC_Log_Error, "%s IPv6 UDP recive error\n", __func__);
						return (-1);
					}
					ifindex = if_nametoindex(ifname_p+1);
					if (ifindex == 0) {
						cef_log_write (CefC_Log_Error, "%s if_nametoindex(%s) error: %s\n",
										__func__, ifname_p, strerror(errno));
						return (-1);
					 }
				}
				face->ifindex = ifindex;
				if(face->ifindex != -1){
					getnameinfo (sock->ai_addr, sock->ai_addrlen, dst_addr, sizeof(dst_addr),
									NULL, 0, NI_NUMERICHOST);
					if(strncmp(dst_addr, "fe80::", 6) == 0) { /* IPv6 linklocal address */
						pinfo.ipi6_addr = in6addr_any;
						pinfo.ipi6_ifindex = face->ifindex;
						if(setsockopt(sock->skfd, IPPROTO_IPV6, IPV6_PKTINFO, &pinfo, sizeof(struct in6_pktinfo)) == -1){
							return(-1);
						}
					}
				}
			}
		}
	}
#endif

	/* Handles the received CEFORE message 	*/
	cefnetd_input_message_process (hdl, faceid, peer_faceid, buff, (int) recv_len, user_id);

	return (1);
}

#define	CefC_Max_UdpInputSegs	32
static int
cefnetd_udp_input_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	int faceid									/* Face-ID that message arrived 		*/
) {
	int i, ret = 1;

	for ( i = 0; 0 < ret && i < CefC_Max_UdpInputSegs; i++ ){
		struct pollfd pollfd;

		pollfd.fd = fd;
		pollfd.events = POLLIN;
		pollfd.revents = 0;
		ret = cefnetd_udp_input_process_core (hdl, fd, faceid);
		poll (&pollfd, 1, 0);
		if (!(pollfd.revents & POLLIN))
			break;
	}

	return (ret);
}

/*--------------------------------------------------------------------------------------
	Handles the input message from the TCP listen socket
----------------------------------------------------------------------------------------*/
static int
cefnetd_tcp_input_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	int faceid									/* Face-ID that message arrived 		*/
) {
	int recv_len;
	unsigned char buff[CefC_Max_Length];
	char	user_id[512];

	/* Receives the message(s) from the specified FD */
	recv_len = read (fd, buff, CefC_Max_Length);

	if (recv_len <= 0) {
		cef_log_write (CefC_Log_Warn, "Detected Face#%d (TCP) is down\n", faceid);
//		cef_fib_faceid_cleanup (hdl->fib, faceid);
//		cef_face_close (faceid);
		cef_face_close_for_down (faceid);
		cef_face_down (faceid);
		return (1);
	}
	// TBD: process for the special message

	unsigned char peer_node_id[16];
	char		addrstr[256];
	int id_len;
	id_len = cef_face_node_id_get (faceid, peer_node_id);
	if ( id_len == 4 ) {
		inet_ntop (AF_INET, peer_node_id, addrstr, sizeof (addrstr));
	} else if ( id_len == 16 ) {
		inet_ntop (AF_INET6, peer_node_id, addrstr, sizeof (addrstr));
	} else {
		addrstr[0] = 0x00;
	}

	strcpy( user_id, addrstr );
	/* Handles the received CEFORE message 	*/
	cefnetd_input_message_process (hdl, faceid, faceid, buff, recv_len, user_id);

	return (1);
}

/*--------------------------------------------------------------------------------------
	Handles the input message from csmgr
----------------------------------------------------------------------------------------*/
static int
cefnetd_csm_input_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	int faceid									/* Face-ID that message arrived 		*/
) {
#if CefC_IsEnable_ContentStore
	int recv_len;
	unsigned char buff[CefC_Max_Length];

	recv_len = recv (fd, buff, CefC_Max_Length, 0);

	if (recv_len > 0) {
		cefnetd_input_message_from_csmgr_process (hdl, buff, recv_len);
	} else {
		cef_log_write (CefC_Log_Warn,
			"csmgr is down or connection refused, so mode moves to no cache\n");
		csmgr_sock_close (hdl->cs_stat);
//		hdl->cs_stat->cache_type = CefC_Cache_Type_None;
	}
#else
	cef_log_write (CefC_Log_Error, "Invalid input from csmgr\n");
	cefnetd_running_f = 0;
#endif // CefC_IsEnable_ContentStore

	return (1);
}

/*--------------------------------------------------------------------------------------
	Seeks the top of the frame from the receive buffer
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_messege_head_seek (
	int		faceid,
	CefT_RcvBuf* rcvbuf,					/* the rcvbuf structure						*/
	uint16_t* payload_len,
	uint16_t* header_len
) {
	uint16_t index = 0;

	if ( rcvbuf->rcv_len <= sizeof(struct cef_hdr) ){
		return (-1);
	}

	for ( index = 0; index < rcvbuf->rcv_len; index++ ) {
		struct cef_hdr* chp = (struct cef_hdr*) &(rcvbuf->rcv_buff[index]);
		uint16_t move_len;
		uint16_t pkt_len;
		uint16_t hdr_len;

		pkt_len = ntohs (chp->pkt_len);
		hdr_len = chp->hdr_len;

		if (chp->version != CefC_Version) {
			unsigned char* wp = &rcvbuf->rcv_buff[index];
			unsigned char* ep = &rcvbuf->rcv_buff[rcvbuf->rcv_len];

			for (move_len = 0; wp < ep; wp++) {
				unsigned char buff[CefC_Max_Length];
				chp = (struct cef_hdr*)wp;

				if (chp->version != CefC_Version)
					continue;
				if (chp->type > CefC_PT_MAX)
					continue;
				pkt_len = ntohs (chp->pkt_len);
				hdr_len = chp->hdr_len;
				if (   (pkt_len < sizeof(struct cef_hdr))
					|| (hdr_len < sizeof(struct cef_hdr))
					|| (pkt_len < hdr_len) ){
					continue;
				}

				move_len = ep - wp;
				memcpy (buff, wp, move_len);
				memcpy (rcvbuf->rcv_buff, buff, move_len);
				chp = (struct cef_hdr*) &(rcvbuf->rcv_buff);
				rcvbuf->rcv_len -= (wp - rcvbuf->rcv_buff);
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "index=%d, rcv_len=%d, move_len=%d\n", index, rcvbuf->rcv_len, move_len);
#endif // CefC_Debug

				index = 0;

				if ((pkt_len == 0) || (hdr_len == 0)) {
					move_len = 0;
				}

				break;
			}
			if (move_len == 0) {
#ifdef CefC_Debug
#define minimum(a,b)	((a)<(b)?(a):(b))
cef_dbg_write (CefC_Dbg_Finer, "Removed invalid data in rcv_buff:index=%d, rcv_len=%d\n", index, rcvbuf->rcv_len);
cef_dbg_buff_write (CefC_Dbg_Finest, (void *)&rcvbuf->rcv_buff[index], minimum(rcvbuf->rcv_len,CefC_BufSiz_2KB));
#endif // CefC_Debug
				rcvbuf->rcv_len = index;
				return (-1);
			}
		}

		if ((chp->type > CefC_PT_MAX)
			|| (pkt_len < sizeof(struct cef_hdr))
				|| (hdr_len < sizeof(struct cef_hdr))
					|| (pkt_len < hdr_len)
			){
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "index=%d, type=%d, pkt_len=%d, hdr_len=%d\n", index, chp->type, pkt_len, hdr_len);
#endif // CefC_Debug
			continue;
		}

		if (rcvbuf->rcv_len < (hdr_len + CefC_S_TLF)) {
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "index=%d, rcv_len=%d, hdr_len=%d\n", index, rcvbuf->rcv_len, hdr_len);
#endif // CefC_Debug
			return (-1);
		}

		/* Obtains values of Header Length from Fix header */
		*header_len 	= hdr_len;
		*payload_len	= 0;
		int invalid_type	= 0;

		/* Compare pkt_len with the total length of the header and all Top-Level TLVs */
		for ( uint16_t ix = (index + hdr_len); ix < rcvbuf->rcv_len; ){
			uint16_t *msg_tlv;
			uint16_t tlv_typ, tlv_len;

			msg_tlv = (uint16_t *)&rcvbuf->rcv_buff[ix];
			tlv_typ =  ntohs(msg_tlv[0]);
			tlv_len = (ntohs(msg_tlv[1]) + CefC_S_TLF);
			if ( CefC_T_INTEREST <= tlv_typ && tlv_typ < CefC_T_TOP_TLV_NUM ){
				/* Obtains values of payload length from Top-Level TLVs length */
				*payload_len += tlv_len;
				ix += tlv_len;		/* next Top-Level TLV */
			} else {
				cef_log_write (CefC_Log_Warn,
					"Invalid Message type detected:face=%d, index=%u, ix=%u, pkt_len=%d, header_len=%u, tlv_typ=0x%04x, tlv_len=%u\n",
						 faceid, index, ix, pkt_len, *header_len, tlv_typ, tlv_len);
				invalid_type = 1;

#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Fine,
	"Invalid Message type detected:face=%d, index=%u, ix=%u, pkt_len=%d, header_len=%u, tlv_typ=0x%04x, tlv_len=%u\n",
		 faceid, index, ix, pkt_len, *header_len, tlv_typ, tlv_len);
cef_dbg_buff_write (CefC_Dbg_Fine, (void *)&rcvbuf->rcv_buff, ((ix+63)/64)*64);
#endif // CefC_Debug
				break;
			}
			/* Compare pkt_len with the total length of the header and all Top-Level TLVs */
			if ( (hdr_len + *payload_len) == pkt_len ){
				break;
			}
		}

		if (invalid_type) {
			continue;
		}

		if (rcvbuf->rcv_len < pkt_len) {
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "Fragment data detected:index=%d, rcv_len=%d, pkt_len=%d\n", index, rcvbuf->rcv_len, pkt_len);
#endif // CefC_Debug
			return (-1);
		}

		if ( (hdr_len + *payload_len) != pkt_len ){
			cef_log_write (CefC_Log_Warn,
				"Packet length mismatch detected:index=%d, pkt_len=%d, header_len=%u\n",
					 index, pkt_len, *header_len, *payload_len);
			continue;
		}

#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "index=%u, rcv_len=%u, pkt_len=%d, header_len=%u, payload_len=%u\n",
					 index, rcvbuf->rcv_len, pkt_len, *header_len, *payload_len);
#endif // CefC_Debug

		if (index > 0) {
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "index=%d, rcv_len=%d\n", index, rcvbuf->rcv_len);
#endif // CefC_Debug
			rcvbuf->rcv_len -= index;
			memmove (rcvbuf->rcv_buff, rcvbuf->rcv_buff + index, rcvbuf->rcv_len);
		}
		return (1);
	}

	return (-1);
}
/*--------------------------------------------------------------------------------------
	Handles the received message(s)
----------------------------------------------------------------------------------------*/
static int										/* No care now							*/
cefnetd_input_message_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int faceid, 								/* Face-ID where messages arrived at	*/
	int peer_faceid, 							/* Face-ID to reply to the origin of 	*/
												/* transmission of the message(s)		*/
	unsigned char* msg, 						/* the received message(s)				*/
	int msg_size,								/* size of received message(s)			*/
	char* user_id
) {
	CefT_Face* face;
	unsigned char* wp;
	uint16_t move_len;
	uint16_t fdv_payload_len;
	uint16_t fdv_header_len;
	int res;

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finer,
		"Inputs CEFORE message(s) from Face#%d\n", peer_faceid);
	cef_dbg_buff_write (CefC_Dbg_Finest, msg, msg_size);
#endif // CefC_Debug

	/* Obtains the face structure corresponding to the peer Face-ID 	*/
	face = cef_face_get_face_from_faceid (peer_faceid);

	/* Handles the received message(s) 		*/
	while (msg_size > 0) {
		/* Calculates the size of the message which have not been yet handled 	*/
		if (msg_size > CefC_Max_Length - face->rcvbuf.rcv_len) {
			move_len = CefC_Max_Length - face->rcvbuf.rcv_len;
		} else {
			move_len = (uint16_t) msg_size;
		}
		msg_size -= move_len;

		/* Updates the receive buffer 		*/
		memcpy (face->rcvbuf.rcv_buff + face->rcvbuf.rcv_len, msg, move_len);
		face->rcvbuf.rcv_len += move_len;
		msg += move_len;

		while (face->rcvbuf.rcv_len > 0) {
			/* Seeks the top of the message */
			res = cefnetd_messege_head_seek (peer_faceid, &(face->rcvbuf), &fdv_payload_len, &fdv_header_len);
			if (res < 0) {
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "invalid message:res=%d, rcv_len=%u, fdv_payload_len=%u, fdv_header_len=%u\n", res, face->rcvbuf.rcv_len, fdv_payload_len, fdv_header_len);
#endif // CefC_Debug
				break;
			}

			unsigned char *packet = face->rcvbuf.rcv_buff;

			/* Calls the function corresponding to the type of the message 	*/
			if (packet[1] > CefC_PT_MAX) {
				cef_log_write (CefC_Log_Warn,
					"Detects the unknown PT_XXX=%d\n", packet[1]);
				face->rcvbuf.rcv_len = 0;
				break;
			} else {
				(*cefnetd_incoming_msg_process[packet[1]])
					(hdl, faceid, peer_faceid,
							packet, fdv_payload_len, fdv_header_len, user_id);
			}

			/* Updates the receive buffer 		*/
			move_len = fdv_payload_len + fdv_header_len;

			wp = face->rcvbuf.rcv_buff + move_len;
			memmove (face->rcvbuf.rcv_buff, wp, face->rcvbuf.rcv_len - move_len);
			face->rcvbuf.rcv_len -= move_len;
		}
	}

	return (1);
}
#if CefC_IsEnable_ContentStore
/*--------------------------------------------------------------------------------------
	Handles the received message(s) from csmgr
----------------------------------------------------------------------------------------*/
static int										/* No care now							*/
cefnetd_input_message_from_csmgr_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	unsigned char* msg, 						/* the received message(s)				*/
	int msg_size								/* size of received message(s)			*/
) {
	unsigned char* wp;
	uint16_t move_len;
	uint16_t fdv_payload_len;
	uint16_t fdv_header_len;
	int res;
	char	user_id[512];

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finer, "Inputs CEFORE message(s) from csmgrd, msg_size=%u, rcv_len=%u\n", msg_size, hdl->cs_stat->rcvbuf.rcv_len);
	cef_dbg_buff_write (CefC_Dbg_Finest, msg, msg_size);
#endif // CefC_Debug

	/* Handles the received message(s) 		*/
	while (msg_size > 0) {
		/* Calculates the size of the message which have not been yet handled 	*/
		if (msg_size > CefC_Max_Length - hdl->cs_stat->rcvbuf.rcv_len) {
			move_len = CefC_Max_Length - hdl->cs_stat->rcvbuf.rcv_len;
		} else {
			move_len = (uint16_t) msg_size;
		}
		msg_size -= move_len;
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "rcv_len=%u, move_len=%u, msg_size=%u\n", hdl->cs_stat->rcvbuf.rcv_len, move_len, msg_size);
#endif // CefC_Debug

		/* Updates the receive buffer 		*/
		memcpy (hdl->cs_stat->rcvbuf.rcv_buff + hdl->cs_stat->rcvbuf.rcv_len, msg, move_len);
		hdl->cs_stat->rcvbuf.rcv_len += move_len;
		msg += move_len;

		while (hdl->cs_stat->rcvbuf.rcv_len > 0) {
			/* Seeks the top of the message */
			res = cefnetd_messege_head_seek (-1,
						&(hdl->cs_stat->rcvbuf), &fdv_payload_len, &fdv_header_len);
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "res=%d, rcv_len=%u, fdv_payload_len=%u, fdv_header_len=%u\n", res, hdl->cs_stat->rcvbuf.rcv_len, fdv_payload_len, fdv_header_len);
#endif // CefC_Debug
			if (res < 0) {
				break;
			}

			/* Calls the function corresponding to the type of the message 	*/
			if (hdl->cs_stat->rcvbuf.rcv_buff[1] > CefC_PT_MAX) {
				cef_log_write (CefC_Log_Warn,
					"Detects the unknown PT_XXX=%d from csmgr\n",
					hdl->cs_stat->rcvbuf.rcv_buff[1]);
				hdl->cs_stat->rcvbuf.rcv_len = 0;
				break;
			} else {
				(*cefnetd_incoming_csmgr_msg_process[hdl->cs_stat->rcvbuf.rcv_buff[1]])
					(hdl, 0, 0, hdl->cs_stat->rcvbuf.rcv_buff, fdv_payload_len, fdv_header_len, user_id);
			}

			/* Updates the receive buffer 		*/
			move_len = fdv_payload_len + fdv_header_len;
			wp = hdl->cs_stat->rcvbuf.rcv_buff + move_len;
			memmove( hdl->cs_stat->rcvbuf.rcv_buff, wp, hdl->cs_stat->rcvbuf.rcv_len - move_len);
			hdl->cs_stat->rcvbuf.rcv_len -= move_len;
		}
	}

	return (1);
}
#endif // CefC_IsEnable_ContentStore

/*--------------------------------------------------------------------------------------
	Handles the received Interest message
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_interest_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	char*	user_id
) {
	CefT_CcnMsg_MsgBdy pm = { 0 };
	CefT_CcnMsg_OptHdr poh = { 0 };

	int res;
	int pit_res = 0;
	CefT_Pit_Entry* pe = NULL;
	CefT_Fib_Entry* fe = NULL;
	uint16_t name_len;
#if CefC_IsEnable_ContentStore
	unsigned int prev_dnfacenum = 0;
	int cs_res = -1;
#endif // CefC_IsEnable_ContentStore
	CefT_Rx_Elem elem;
	uint16_t faceids[CefC_Fib_UpFace_Max];
	uint16_t face_num = 0;
	int forward_interest_f = 0;
	int i;
	int tp_plugin_res = CefC_Pi_All_Permission;
	uint16_t* fip;
	double	bw_utilization = 0.0;

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finer,
		"Process the Interest (%d bytes)\n", payload_len + header_len);
#endif // CefC_Debug

#ifdef	__INTEREST__
	fprintf (stderr, "[%s] IN   faceid:%d Local:%d  peer_faceid:%d Local:%d\n\n", __func__, faceid, cef_face_is_local_face(faceid),
							peer_faceid,  cef_face_is_local_face(peer_faceid) );
#endif

	if (payload_len + header_len > CefC_Max_Msg_Size) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Interest is too large\n");
#endif // CefC_Debug
		return (-1);
	}

	/* Checks the Validation 			*/
	res = cef_valid_msg_verify (msg, payload_len + header_len);
	if (res != 0) {
		/***********************************************************************
			[rfc8569] 2.4.4. Interest Pipeline
			If the forwarder drops an Interest due to failed validation,
			it MAY send an Interest Return (Section 10.3.9).
		 ***********************************************************************/
		cef_log_write (CefC_Log_Info, "Drops a malformed Interest.\n");
		return (-1);
	}

	/* Parses the received Interest 	*/
	res = cef_frame_message_parse (
					msg, payload_len, header_len, &poh, &pm, CefC_PT_INTEREST);
	if (res < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Detects the invalid Interest\n");
#endif // CefC_Debug
		return (-1);
	}

	//0.8.3 HopLimit=0 IR 0x02
	if (pm.hoplimit < 1) {
		//Interest Return 0x02:HopLimit Exceeded
#ifdef	CefC_INTEREST_RETURN
#ifdef	__INTEREST__
	fprintf (stderr, "\t Interest Return 0x02:HopLimit Exceeded SendForce\n" );
#endif
		if ( (hdl->IR_Option != 0) && (hdl->IR_enable[2] == 1) ) {	//202108
			unsigned char buff[CefC_Max_Length];	//0.8.3
			res = cef_frame_interest_return_create( msg, payload_len + header_len, buff, CefC_IR_HOPLIMIT_EXCEEDED );
			if ( res < 0 ) {
				return(-1);
			}
			cefnetd_frame_send_txque (hdl, peer_faceid, buff, res);
		}	//202108
#endif	// CefC_INTEREST_RETURN
		return(-1);
	}

#ifdef CefC_Debug
{static const char header[] = "Interest's Name [";
	cef_dbg_buff_write_name (CefC_Dbg_Finer,
								(unsigned char *)header, strlen(header),
								pm.name, pm.name_len,
								(unsigned char *)" ]\n", 3);
}
#endif // CefC_Debug

	/* Checks whether this interest is the command or not */
	res = cefnetd_incoming_command_process (hdl, faceid, peer_faceid, &pm);
	if (res > 0) {
		return (1);
	}

	if (poh.app_reg_f > 0) {
		cefnetd_input_app_reg_command (hdl, &pm, &poh, (uint16_t) peer_faceid);
		return (1);
	}

	//0.8.3	Symbolic/Osymbilic Check PIT
	if ( pm.InterestType == CefC_PIT_TYPE_Sym ) {
		res = cef_pit_symbolic_pit_check( hdl->pit, &pm, &poh );
		if ( res < 0 ) {
			return (-1);
		}
	}
	//0.8.3 Selective
	if ( pm.InterestType == CefC_PIT_TYPE_Sel ) {
		res = cefnetd_incoming_selective_interest_process (
			hdl, faceid, peer_faceid, msg, payload_len, header_len, &pm, &poh);
		if ( res < 0 ) {
			return(-1);
		}
		return (1);
	}

	if (pm.org.putverify_f) {
		if (pm.org.putverify_msgtype != CefC_CpvOp_FibRegMsg) {
			return (-1);
		}
		cefnetd_adv_route_process (hdl, &pm);
		return (1);
	}

	/**********************************************************************/
	/* Create a PIT entry for the proxy application's INTEREST in app_pit */
	/**********************************************************************/
	if ( cef_face_is_local_face(peer_faceid) ) {
		CefT_Pit_Entry* app_pe = NULL;

		/********************************************************/
		/*	The Proxy application that terminates the flow		*/
		/*	must be registered in advance with OPT_APP_PIT_REG.	*/
		/********************************************************/

		/* Search the PIT of the registered application with OPT_APP_PIT_REG */
		app_pe = cef_pit_entry_search_symbolic (hdl->app_pit, &pm, &poh);
		if ( app_pe != NULL ){
			CefT_Down_Faces* face = NULL;

			/* If it is the same face as OPT_APP_PIT_REG ? */
			for ( face = &(app_pe->dnfaces); face->next; ) {
				face = face->next;

				if ( face->faceid == peer_faceid ){
					/* create a App PIT entry matching this Interest */
					pe = cef_pit_entry_lookup_with_lock (hdl->app_pit,
						&pm, &poh, pm.name, pm.name_len, CefC_Pit_WithLOCK);
					break;
				}
			}
		}
	}

	if ( pe == NULL ){
		/* create a Normal PIT entry matching this Interest with lock	*/
		pe = cef_pit_entry_lookup_with_lock (hdl->pit, &pm, &poh, pm.name, pm.name_len, CefC_Pit_WithLOCK);
	}

	if (pe == NULL) {
		return (-1);
	}

#if CefC_IsEnable_ContentStore
	// TODO change process
	prev_dnfacenum = pe->dnfacenum;
#endif // CefC_IsEnable_ContentStore

	/* Updates the information of down face that this Interest arrived 	*/
	pit_res = cef_pit_entry_down_face_update (pe, peer_faceid, &pm, &poh, msg, hdl->InterestRetrans);	//0.8.3
	cef_pit_entry_unlock (pe);

#ifdef	CefC_INTEREST_RETURN
	//0.8.3 HopLimit==1
	if (pm.hoplimit == 1 && !cef_face_is_local_face (peer_faceid)) {
		//Interest Return 0x02:HopLimit Exceeded
#ifdef	__INTEREST__
	fprintf (stderr, "\t Interest Return 0x02:HopLimit Exceeded HoldPIT\n" );
#endif
		if ( (hdl->IR_Option != 0) && (hdl->IR_enable[2] == 1) ) {	//202108
			unsigned char buff[CefC_Max_Length];	//0.8.3
			res = cef_frame_interest_return_create( msg, payload_len + header_len, buff, CefC_IR_HOPLIMIT_EXCEEDED );
			if ( res < 0 ) {
				return(-1);
			}
			//Hold pe peer_faceid
			res = cef_pit_interest_return_set( pe, &pm, &poh, peer_faceid, CefC_IR_HOPLIMIT_EXCEEDED, res, buff );
			if ( res < 0 ) {
				/* */
			}
		}	//202108
	}
#endif	// CefC_INTEREST_RETURN

	/* Searches a FIB entry matching this Interest 		*/
	if (pm.chunk_num_f) {
		name_len = pm.name_len - (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
	} else {
		/* Symbolic Interest	*/
		name_len = pm.name_len;
	}

	if (pit_res != 0) {
		/* Searches a FIB entry matching this Interest 		*/
		fe = cef_fib_entry_search (hdl->fib, pm.name, name_len);

		/* Count of Received Interest */
		hdl->stat_recv_interest++;
		/* Count of Received Interest by type */
		hdl->stat_recv_interest_types[pm.InterestType]++;

		/* Obtains Face-ID(s) to forward the Interest */
		if (fe) {
			/* Count of Received Interest at FIB */
			fe->rx_int++;
			/* Count of Received Interest by type at FIB */
			fe->rx_int_types[pm.InterestType]++;
			face_num = cef_fib_forward_faceid_select (fe, peer_faceid, faceids);
		}

		if ( pm.payload_f ) {
			struct cef_hdr* msghdr;
			uint16_t pkt_len;
			uint16_t hdr_len;

			msghdr = (struct cef_hdr*) pm.payload;
			pkt_len = ntohs (msghdr->pkt_len);
			hdr_len = msghdr->hdr_len;

			cefnetd_incoming_piggyback_process (
				hdl, faceid, peer_faceid, pm.payload, pkt_len - hdr_len, hdr_len);

			tp_plugin_res = CefC_Pi_Interest_Send;
		}
	}

	/*--------------------------------------------------------------------
		Transport Plugin
	----------------------------------------------------------------------*/
	if (poh.org.tp_variant > CefC_T_OPT_TP_NONE) {
		CefT_Pit_Entry* tmpe = cef_pit_entry_search_symbolic (hdl->pit, &pm, &poh);
		uint32_t contents_hashv = 0;	/* Hash value of this contents (without chunk number) */
		if ( tmpe ){
			contents_hashv = tmpe->hashv;	/* Hash value of this contents */
		} else {
			contents_hashv = 0;				/* Hash value of this contents */
		}

		if ((hdl->plugin_hdl.tp)[poh.org.tp_variant].interest) {
			/* Creates CefT_Rx_Elem 		*/
			memset (&elem, 0, sizeof (CefT_Rx_Elem));
			elem.plugin_variant 	= poh.org.tp_variant;
			elem.type 				= CefC_Elem_Type_Interest;
			elem.hashv 				= contents_hashv;
			elem.in_faceid 			= (uint16_t) peer_faceid;
			elem.bw_utilization 	= bw_utilization;
			elem.parsed_msg 		= &pm;
			memcpy (&(elem.msg[0]), msg, payload_len + header_len);
			elem.msg_len 			= payload_len + header_len;
			elem.out_faceid_num 	= face_num;

			for (i = 0 ; i < face_num ; i++) {
				elem.out_faceids[i] = faceids[i];
			}

			elem.parsed_oph 		= &poh;
			memcpy (elem.ophdr, poh.org.tp_val, poh.org.tp_len);
			elem.ophdr_len = poh.org.tp_len;

			/* Callback 		*/
			tp_plugin_res = (*(hdl->plugin_hdl.tp)[poh.org.tp_variant].interest)(
				&(hdl->plugin_hdl.tp[poh.org.tp_variant]), &elem
			);
		}
	}

#if CefC_IsEnable_ContentStore
	/*--------------------------------------------------------------------
		Content Store
	----------------------------------------------------------------------*/
	if (tp_plugin_res & CefC_Pi_Object_Match) {

		if (pm.org.from_pub_f) {
			if (pm.chunk_num_f) {
				name_len = pm.name_len - (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
			} else {
				name_len = pm.name_len;
			}
			if (cef_hash_tbl_item_check_exact (hdl->app_reg, pm.name, name_len) < 0) {
				forward_interest_f = 1;
				goto FORWARD_INTEREST;
			}
		}

		/* Checks Reply 	*/
		if (!pm.org.longlife_f && !pm.org.csact.signature_len)
		{
			if (pit_res != 0) {
				pit_res = cef_csmgr_rep_f_check (pe, peer_faceid);
			}
			if ((pit_res == 0) || (prev_dnfacenum == pe->dnfacenum)) {
				forward_interest_f = 1;			//#909
				goto FORWARD_INTEREST;
			}
		}

		/* Checks Content Store */
		if (hdl->cs_stat->cache_type != CefC_Default_Cache_Type) {	//#938

			if (pm.org.version_f == 1 && pm.org.version_len == 0) {
				/* This interest is VerReq, so don't have to search the cache */
				forward_interest_f = 1;
				goto FORWARD_INTEREST;
			}
			/* Checks the temporary/local cache in cefnetd 		*/
			unsigned char* cob = NULL;
			cs_res = cef_csmgr_cache_lookup (hdl->cs_stat, peer_faceid, &pm, &poh, pe, &cob);

			if (cs_res < 0) {
#ifdef	CefC_Conpub
				if (hdl->cs_stat->cache_type != CefC_Cache_Type_ExConpub){
#endif	//CefC_Conpub
					/* Cache does not exist in the temporary cache in cefnetd, 		*/
					/* so inquiries to the csmgr 									*/
					cef_csmgr_excache_lookup (hdl->cs_stat, peer_faceid, &pm, &poh, pe);
					cef_dbg_write (CefC_Dbg_Finer, "Forward the Interest to csmgr\n");
#ifdef	CefC_Conpub
				}
#endif	//CefC_Conpub
			} else {
				cef_dbg_write (CefC_Dbg_Finer,
					"Return the Content Object from the buffer/local cache\n");

				cefnetd_cefcache_object_process (hdl, cob);
				return (-1);
			}
		}

		/* Checks Reply 	*/
		if (!pm.org.longlife_f && !pm.org.csact.signature_len)
		{
			if (pit_res != 0) {
				pit_res = cef_csmgr_rep_f_check (pe, peer_faceid);
			}
			if ((pit_res == 0) || (prev_dnfacenum == pe->dnfacenum)) {
				forward_interest_f = 1;			//#909
				goto FORWARD_INTEREST;
			}
		}
	}

	if ((pit_res != 0) && (cs_res != 0)) {
		forward_interest_f = 1;
	}
FORWARD_INTEREST:
#else // CefC_IsEnable_ContentStore
	if (pit_res != 0) {
		forward_interest_f = 1;
	}
#endif // CefC_IsEnable_ContentStore

	/*--------------------------------------------------------------------
		Forwards the received Interest
	----------------------------------------------------------------------*/
	if (tp_plugin_res & CefC_Pi_Interest_Send) {
		if (pm.chunk_num_f) {
			name_len = pm.name_len - (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
		} else {
			name_len = pm.name_len;
		}
		fip = (uint16_t*) cef_hash_tbl_item_get_for_app (hdl->app_reg, pm.name, name_len);

		if (fip && (*fip != peer_faceid)) {
			if (cef_face_check_active (*fip) > 0) {
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Finer,
					"Forward the Interest to the local application(s)\n");
#endif // CefC_Debug
				cefnetd_frame_send_txque (hdl,
					*fip, msg, (size_t) (payload_len + header_len));

				cef_pit_entry_up_face_update (pe, *fip, &pm, &poh);
			}
			return (1);
		}

		if ((forward_interest_f) && (face_num > 0)) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finer, "Forward the Interest to the next cefnetd(s)\n");
#endif // CefC_Debug
			cefnetd_interest_forward (
				hdl, faceids, face_num, peer_faceid, msg,
				payload_len, header_len, &pm, &poh, pe, fe
			);
			return (1);
		}

		//0.8.3
		else {
			if ((forward_interest_f) && (pit_res)) {
#ifdef	__PIT_CLEAN__
	fprintf( stderr, "[%s] IR:NO_ROUTE\n", __func__ );
#endif
				//Interest Return 0x01:NO Route
#ifdef	__INTEREST__
	fprintf (stderr, "\t Interest Return 0x01:NO Route HoldPIT\n" );
#endif
#ifdef	CefC_INTEREST_RETURN
				if ( (hdl->IR_Option != 0) && (hdl->IR_enable[1] == 1) ) {	//202108
					unsigned char buff[CefC_Max_Length];	//0.8.3
					res = cef_frame_interest_return_create( msg, payload_len + header_len, buff, CefC_IR_NO_ROUTE);
					if ( (hdl->cs_mode == 2) || (hdl->cs_mode == 3) ) {
						//Hold pe peer_faceid
						res = cef_pit_interest_return_set( pe, &pm, &poh, peer_faceid, CefC_IR_NO_ROUTE, res, buff );
						if ( res < 0 ) {
							/* */
						}
					} else {
						/* IR Send */
						cefnetd_frame_send_txque (hdl, peer_faceid, buff, res);
					}
				}	//202108
#endif	// CefC_INTEREST_RETURN
				return(-1);
			}
			else {	//20210628
				//Interest Return 0x01:NO Route
#ifdef	__INTEREST__
	fprintf (stderr, "\t Interest Return 0x01:NO Route HoldPIT\n" );
#endif
#ifdef	CefC_INTEREST_RETURN
				if ( (hdl->IR_Option != 0) && (hdl->IR_enable[1] == 1) ) {	//202108
					unsigned char buff[CefC_Max_Length];	//0.8.3
					res = cef_frame_interest_return_create( msg, payload_len + header_len, buff, CefC_IR_NO_ROUTE);
					if ( (hdl->cs_mode == 2) || (hdl->cs_mode == 3) ) {
						//Hold pe peer_faceid
						res = cef_pit_interest_return_set( pe, &pm, &poh, peer_faceid, CefC_IR_NO_ROUTE, res, buff );
						if ( res < 0 ) {
							/* */
						}
					} else {
						/* IR Send */
						cefnetd_frame_send_txque (hdl, peer_faceid, buff, res);
					}
				}	//202108
#endif	// CefC_INTEREST_RETURN
				return(-1);
			}	//20210628
		}
	}

	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the faceid map
----------------------------------------------------------------------------------------*/
static void
cefnetd_faceidmap_init (
	uint8_t	maptbl[],
	int		mapsiz
){
	memset(maptbl, 0x00, mapsiz);
}

static void
cefnetd_faceidmap_set (
	uint8_t	maptbl[],
	int		index
){
	int		ix = index / 8;
	uint8_t	bits = 0x01 << (index % 8);

	maptbl[ix] |= bits;
}
/*
static void
cefnetd_faceidmap_reset (
	uint8_t	maptbl[],
	int		index
){
	int		ix = index / 8;
	uint8_t	bits = 0x01 << (index % 8);

	maptbl[ix] &= ~bits;
}	*/

static int									/* Returns a true value if it set		*/
cefnetd_faceidmap_is_set (
	uint8_t	maptbl[],
	int		index
){
	int		ix = index / 8;
	uint8_t	bits = 0x01 << (index % 8);

	return ((maptbl[ix] & bits) != 0);
}

/*--------------------------------------------------------------------------------------
	Handles the received Content Object message
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_object_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	char*	user_id
) {
	CefT_CcnMsg_MsgBdy pm = { 0 };
	CefT_CcnMsg_OptHdr poh = { 0 };
	CefT_Pit_Entry* pe = NULL;
	int res;
	uint8_t faceid_bitmap[CefC_Face_Router_Max];
	uint16_t faceids[CefC_Fib_UpFace_Max];
	uint16_t face_num = 0;
	CefT_Down_Faces* face;
	CefT_Rx_Elem elem;
	int i;
	int tp_plugin_res = CefC_Pi_All_Permission;
	uint16_t pkt_len = 0;	//0.8.3
	CefT_Hash_Handle pit_handle = hdl->pit;

	cefnetd_faceidmap_init(faceid_bitmap, sizeof(faceid_bitmap));

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finer,
		"Process the Content Object (%d bytes)\n", payload_len + header_len);
#endif // CefC_Debug

#ifdef	__SYMBOLIC__
	fprintf( stderr, "[%s] IN msg (%d bytes) \n", __func__, payload_len + header_len );
#endif

	if (payload_len + header_len > CefC_Max_Msg_Size) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Content Object is too large\n");
#endif // CefC_Debug

		return (-1);
	}

	pkt_len = payload_len + header_len;	//0.8.3

	/* Checks the Validation 			*/
	res = cef_valid_msg_verify (msg, payload_len + header_len);
	if (res != 0) {
		cef_log_write (CefC_Log_Info, "Drops a malformed Object.\n");
		return (-1);
	}

	res = cef_frame_message_parse (
					msg, payload_len, header_len, &poh, &pm, CefC_PT_OBJECT);
	if (res < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Detects the invalid Content Object\n");
#endif // CefC_Debug
		return (-1);
	}

#ifdef CefC_Debug
	cef_dbg_buff_write_name (CefC_Dbg_Finer,
								(unsigned char*)"Object's Name [", strlen("Object's Name ["),
								pm.name, pm.name_len,
								(unsigned char*)" ]\n", strlen(" ]\n"));
#endif // CefC_Debug

	/* Checks whether this Object is the command or not */
	res = cefnetd_incoming_command_process (hdl, faceid, peer_faceid, &pm);
	if (res > 0) {
		return (1);
	}
	hdl->stat_recv_frames++;

	stat_rcv_size_cnt++;
	stat_rcv_size_sum += (payload_len + header_len);
	if ((payload_len + header_len) < stat_rcv_size_min) {
		stat_rcv_size_min = payload_len + header_len;
	}
	if ((payload_len + header_len) > stat_rcv_size_max) {
		stat_rcv_size_max = payload_len + header_len;
	}

	if (hdl->fwd_strtgy_hdl->fwd_telemetry) {
		CefT_FwdStrtgy_Param	fwdstr = { 0 };

		/* Set parameters */
		fwdstr.msg             = msg;
		fwdstr.payload_len     = payload_len;
		fwdstr.header_len      = header_len;
		fwdstr.pm              = &pm;
		fwdstr.poh             = &poh;
		fwdstr.peer_faceid     = peer_faceid;

		fwdstr.fe = cef_fib_entry_search (hdl->fib, pm.name, pm.name_len);

		/* Update In-Band Network Telemetry according to Forwarding Strategy. */
		hdl->fwd_strtgy_hdl->fwd_telemetry(&fwdstr);
	}

	/* Searches a PIT entry matching this Object 	*/

	/**** 1st. app_pit ****/

	/* Search the PIT of the registered application with OPT_APP_PIT_REG */
	pit_handle = hdl->app_pit;
	pe = cef_pit_entry_search_with_chunk (pit_handle, &pm, &poh);
	if ( pe ){
		CefT_Down_Faces* face = NULL;

		/* If it is the same face as OPT_APP_PIT_REG ? */
		for ( face = &(pe->dnfaces); face->next; ) {
			face = face->next;

			if ( face->faceid == peer_faceid ){
				/* Objects sent by the proxy application itself */
				/* Continue normal PIT search */
				pe = NULL;
				break;
			}
		}
	}

	if ( pe == NULL ){
		CefT_Pit_Entry* pe_smi = NULL;

#if CefC_IsEnable_ContentStore
		/*--------------------------------------------------------------------
			Content Store
		----------------------------------------------------------------------*/
		/* Stores Content Object to Content Store 		*/
		if ((pm.expiry > 0) && (hdl->cs_stat->cache_type != CefC_Default_Cache_Type)) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finer, "Forward the Content Object to cache\n");
#endif // CefC_Debug
			cef_csmgr_excache_item_put (
				hdl->cs_stat, msg, payload_len + header_len, peer_faceid, &pm, &poh);
		}
#endif // CefC_IsEnable_ContentStore

		pit_handle = hdl->pit;
		pe_smi = cef_pit_entry_search_symbolic (pit_handle, &pm, &poh);
		/**** 2nd. symbolic pit ****/
		if ( pe_smi && pe_smi->PitType != CefC_PIT_TYPE_Rgl ){
			if ( pm.chunk_num < (pe_smi->Last_chunk_num - hdl->SymbolicBack) ) {
				cef_dbg_write (CefC_Dbg_Fine, "SymbolicBack drop, chunk_num=%u\n", pm.chunk_num);
				pe_smi = NULL;		// stat_nopit_frames++
			} else if ( pe_smi->Last_chunk_num < pm.chunk_num ) {
				pe_smi->Last_chunk_num = pm.chunk_num;
			}
			if ( pe_smi ){
				for ( face = &(pe_smi->dnfaces); face->next; ) {
					face = face->next;
					if ( !cefnetd_faceidmap_is_set(faceid_bitmap, face->faceid) ){
						cefnetd_faceidmap_set(faceid_bitmap, face->faceid);
						faceids[face_num++] = face->faceid;
					}
				}
			}
		}
		/**** 3rd. reguler pit ****/
		pe = cef_pit_entry_search_with_chunk (pit_handle, &pm, &poh);
		if ( pe == NULL ){
			pe = pe_smi;
		}
	}

	/* COB without chunk number matches only Reg-PIT */
	if ( pm.chunk_num_f == 0 && pe && pe->PitType != CefC_PIT_TYPE_Rgl ) {
		cef_dbg_write (CefC_Dbg_Fine, "PitType Unmatch\n");
		pe = NULL;		// stat_nopit_frames++
	}

	if ( pe ) {
		//0.8.3
		if ( pe->COBHR_len > 0 ) {
			/* CobHash */
			uint16_t		CobHash_index;
			uint16_t		CobHash_len;
			unsigned char 	hash[SHA256_DIGEST_LENGTH];

			CobHash_index = header_len;
			CobHash_len   = payload_len;
			cef_valid_sha256( &msg[CobHash_index], CobHash_len, hash );	/* for OpenSSL 3.x */
#ifdef	__RESTRICT__
{
	int		hidx;
	char	hash_dbg[CefC_BufSiz_1KB];

	printf ( "%s\n", __func__ );
	sprintf (hash_dbg, "PIT CobHash [");
	for (hidx = 0 ; hidx < pe->COBHR_len ; hidx++) {
		sprintf (hash_dbg, "%s %02X", hash_dbg, pe->COBHR_selector[hidx]);
	}
	sprintf (hash_dbg, "%s ]\n", hash_dbg);
	printf( "%s", hash_dbg );

	sprintf (hash_dbg, "OBJ CobHash [");
	for (hidx = 0 ; hidx < pe->COBHR_len ; hidx++) {
		sprintf (hash_dbg, "%s %02X", hash_dbg, pe->COBHR_selector[hidx]);
	}
	sprintf (hash_dbg, "%s ]\n", hash_dbg);
	printf( "%s", hash_dbg );
}
#endif // __RESTRICT__

			if ( memcmp(pe->COBHR_selector, hash, pe->COBHR_len) == 0 ) {
				/* OK */
			} else {
				/* NG */
				cef_log_write (CefC_Log_Info, "Dropped due to ObjectHash restrictions.\n");
				return (-1);
			}
		}
		if ( pe->KIDR_len > 0 ) {
			/* KeyIdRest */
			int keyid_len;
			unsigned char keyid_buff[CefC_KeyIdSiz];
			keyid_len = cefnetd_keyid_get( msg, pkt_len, keyid_buff );
			if ( (keyid_len == CefC_KeyIdSiz) && (memcmp(pe->KIDR_selector, keyid_buff, CefC_KeyIdSiz) == 0) ) {
				/* OK */
			} else {
				/* NG */
				cef_log_write (CefC_Log_Info, "Dropped due to KeyId restrictions.\n");
				return (-1);
			}
		}

		for (face = &(pe->dnfaces); face->next;) {
			face = face->next;
			if ( !cefnetd_faceidmap_is_set(faceid_bitmap, face->faceid) ){
				cefnetd_faceidmap_set(faceid_bitmap, face->faceid);
				faceids[face_num++] = face->faceid;
			}
		}
	} else {
		stat_nopit_frames++;
#ifdef CefC_Debug
{		char uri[CefC_NAME_BUFSIZ];
		cefnetd_name_to_uri (&pm, uri, sizeof(uri));
		cef_dbg_write (CefC_Dbg_Finer, "NOPIT:stat_nopit_frames=%u, %s\n", stat_nopit_frames, uri);
}
#endif // CefC_Debug
	}

	/*--------------------------------------------------------------------
		Transport Plugin
	----------------------------------------------------------------------*/
	if ((poh.org.tp_variant > CefC_T_OPT_TP_NONE)
	&&	(hdl->plugin_hdl.tp[poh.org.tp_variant].cob)
	) {
		CefT_Pit_Entry* tmpe = cef_pit_entry_search_symbolic (hdl->pit, &pm, &poh);
		uint32_t contents_hashv = 0;	/* Hash value of this contents (without chunk number) */
		if ( tmpe ){
			contents_hashv = tmpe->hashv;	/* Hash value of this contents */
		} else {
			contents_hashv = 0;				/* Hash value of this contents */
		}

		/* Creates CefT_Rx_Elem 		*/
		memset (&elem, 0, sizeof (CefT_Rx_Elem));
		elem.plugin_variant 	= poh.org.tp_variant;
		elem.type 				= CefC_Elem_Type_Object;
		elem.hashv 				= contents_hashv;
		elem.in_faceid 			= (uint16_t) peer_faceid;
		elem.parsed_msg 		= &pm;
		memcpy (&(elem.msg[0]), msg, payload_len + header_len);
		elem.msg_len 			= payload_len + header_len;
		elem.out_faceid_num 	= face_num;

		for (i = 0 ; i < face_num ; i++) {
			elem.out_faceids[i] = faceids[i];
		}

		elem.parsed_oph 		= &poh;
		memcpy (elem.ophdr, poh.org.tp_val, poh.org.tp_len);
		elem.ophdr_len = poh.org.tp_len;

		/* Callback 		*/
		tp_plugin_res = (*(hdl->plugin_hdl.tp)[poh.org.tp_variant].cob)(
			&(hdl->plugin_hdl.tp[poh.org.tp_variant]), &elem
		);
	}

	/*--------------------------------------------------------------------
		Forwards the Content Object
	----------------------------------------------------------------------*/
	if (tp_plugin_res & CefC_Pi_Object_Send) {
		if (face_num > 0) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finer, "Forward the Content Object to cefnetd(s)\n");
#endif // CefC_Debug
			cefnetd_object_forward (hdl, faceids, face_num, msg,
				payload_len, header_len, &pm, &poh, pe);

			if (pe->stole_f) {
				if (cef_pit_entry_lock(pe))					// 2023/04/19 by iD
					cef_pit_entry_free (pit_handle, pe);
			}
		}
	}

	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the received InterestReturn
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_intreturn_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	char*	user_id
) {
	//0.8.3
	CefT_CcnMsg_MsgBdy pm = { 0 };
	CefT_CcnMsg_OptHdr poh = { 0 };
	CefT_Pit_Entry* pe = NULL;
	int loop_max = 2;						/* For App(0), Trans(1)						*/
	int pit_idx = 0;
	int res;
	uint16_t faceids[CefC_Fib_UpFace_Max];
	uint16_t face_num = 0;
	CefT_Down_Faces* face;
	int i;
	int tp_plugin_res = CefC_Pi_All_Permission;

	//202108
	if ( hdl->IR_Option == 0 ) {
		return( -1 );
	}

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finer,
		"Process the Interest Return (%d bytes)\n", payload_len + header_len);
#endif // CefC_Debug

	if (payload_len + header_len > CefC_Max_Msg_Size) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Interest Return is too large\n");
#endif // CefC_Debug

		return (-1);
	}

	/* Checks the Validation 			*/
	res = cef_valid_msg_verify (msg, payload_len + header_len);
	if (res != 0) {
		cef_log_write (CefC_Log_Info, "Drops a malformed Interest Return.\n");
		return (-1);
	}

	res = cef_frame_message_parse (
					msg, payload_len, header_len, &poh, &pm, CefC_PT_INTRETURN);
	if (res < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Detects the invalid Interest Return\n");
#endif // CefC_Debug
		return (-1);
	}

#ifdef CefC_Debug
	cef_dbg_buff_write_name (CefC_Dbg_Finer,
								(unsigned char*)"Interest Return's Name [", strlen("Interest Return's Name ["),
								pm.name, pm.name_len,
								(unsigned char*)" ]\n", strlen(" ]\n"));
#endif // CefC_Debug

	/* Searches a PIT entry matching this InterestReturn 	*/
	/* Initialize the loop counter */
	pit_idx = 0;

	for (; pit_idx < loop_max; pit_idx++) {
		if (pit_idx == 0) {
			pe = cef_pit_entry_search (hdl->app_pit, &pm, &poh, NULL, 0);
		} else {
			if (pit_idx == 1) {
				pe = cef_pit_entry_search (hdl->pit, &pm, &poh, NULL, 0);
			}
		}
		if (pe == NULL) {
			continue;
		}

		if (pe) {
			face = &(pe->dnfaces);

			while (face->next) {
				face = face->next;
				faceids[face_num] = face->faceid;
				face_num++;
			}
		} else {
			return (-1);
		}

		/*--------------------------------------------------------------------
			Forwards the Interest Return
		----------------------------------------------------------------------*/
		if (tp_plugin_res & CefC_Pi_Object_Send) {

			if (face_num > 0) {
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Finer, "Forward the Interest Return cefnetd(s)\n");
#endif // CefC_Debug
				cefnetd_object_forward (hdl, faceids, face_num, msg,
					payload_len, header_len, &pm, &poh, pe);

				if (pe->stole_f && cef_pit_entry_lock(pe)){					// 2023/05/08 by iD
					cef_pit_entry_free (hdl->pit, pe);
				}

				if(pit_idx == 0) {
					return (1);
				}

			}
		}

		for (i = 0; i < face_num; i++)
			faceids[i] = 0;
		face_num = 0;
		pe = NULL;
	}

	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the received Piggyback message
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_piggyback_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* pkt, 					/* received packet to handle				*/
	uint16_t msg_len, 						/* length of ccn message 					*/
	uint16_t header_len						/* length of fixed and option header 		*/
) {
	CefT_CcnMsg_MsgBdy pm = { 0 };
	CefT_CcnMsg_OptHdr poh = { 0 };
	CefT_Pit_Entry* pe;
	int res;
	uint16_t faceids[CefC_Fib_UpFace_Max];
	uint16_t face_num = 0;
	CefT_Down_Faces* face;

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finer,
		"Process the Piggyback (%d bytes)\n", msg_len + header_len);
#endif // CefC_Debug

	if (msg_len + header_len > CefC_Max_Msg_Size) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finer, "Piggyback is too large\n");
#endif // CefC_Debug
		return (-1);
	}

	res = cef_frame_message_parse (
					pkt, msg_len, header_len, &poh, &pm, CefC_PT_OBJECT);
	if (res < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finer, "Detects the invalid Piggyback\n");
#endif // CefC_Debug
		return (-1);
	}
#ifdef CefC_Debug
	cef_dbg_buff_write_name (CefC_Dbg_Finer,
								(unsigned char*)"Piggyback Interest's Name [", strlen("Piggyback Interest's Name ["),
								pm.name, pm.name_len,
								(unsigned char*)" ]\n", strlen(" ]\n"));
#endif // CefC_Debug

#if CefC_IsEnable_ContentStore
	/*--------------------------------------------------------------------
		Content Store
	----------------------------------------------------------------------*/
	/* Stores Content Object to Content Store 		*/
	if ((pm.expiry > 0) && (hdl->cs_stat->cache_type != CefC_Default_Cache_Type)) {
			cef_csmgr_excache_item_put (
				hdl->cs_stat, pkt, (msg_len + header_len), peer_faceid, &pm, &poh);
	}
#endif // CefC_IsEnable_ContentStore

	/* Searches a PIT entry matching this Object 	*/
	if (pm.chunk_num_f) {
		pm.name_len -= (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
	}

	pe = cef_pit_entry_search (hdl->pit, &pm, &poh, NULL, 0);

	if (pe) {
		face = &(pe->dnfaces);

		while (face->next) {
			face = face->next;

			if ((peer_faceid != face->faceid) &&
				(cef_face_is_local_face (face->faceid))) {
				faceids[face_num] = face->faceid;
				face_num++;
			}
		}
	}

	if (face_num > 0) {
		cefnetd_object_forward (
			hdl, faceids, face_num, pkt, msg_len, header_len, &pm, &poh, pe);
	}

	return (1);
}

/*--------------------------------------------------------------------------------------
	Handles the received Ccninfo Request
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_ccninforeq_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	char*	user_id
) {
	CefT_CcnMsg_MsgBdy pm = { 0 };
	CefT_CcnMsg_OptHdr poh = { 0 };
	int res;
	int forward_req_f = 0;
	uint16_t new_header_len;
	uint16_t return_code = CefC_CtRc_NO_ERROR;
	CefT_Pit_Entry* pe;
	CefT_Fib_Entry* fe = NULL;
	uint16_t name_len;
	uint16_t pkt_len;
	uint16_t faceids[CefC_Fib_UpFace_Max];
	uint16_t face_num = 0;
	struct timeval t;
	uint16_t* fip;
	unsigned int responder_mtu;
	// ccninfo-03
	CefT_Parsed_Ccninfo	*pci;
	CEF_FRAME_SKIPHOP_T	w_skiphop;
#define	CefC_Ccninfo_NameSize	CefC_BufSiz_1KB
	unsigned char ccninfo_name[CefC_Ccninfo_NameSize];
	int			  ccninfo_namelen;
	int			  detect_loop = 0;

	unsigned char peer_node_id[16];
	unsigned char node_id[16];

	unsigned char stamp_node_id[16] = {0};	/* Not Use */
	int id_len = -1;

	pkt_len = header_len + payload_len;

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finer,
		"Process the Ccninfo Request (%d bytes) from Face#%u\n", payload_len + header_len, peer_faceid);
#endif // CefC_Debug

#ifdef	DEB_CCNINFO
	printf( "[%s] Ccninfo Request (%d bytes)\n",
			"cefnetd_incoming_ccninforeq_process", payload_len + header_len );
#endif

	/* Check the message size 		*/
	if (payload_len + header_len > CefC_Max_Msg_Size) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Ccninfo Request is too large\n");
#endif // CefC_Debug

#ifdef	DEB_CCNINFO
		fprintf( stderr, "[%s] return(-1) Ccninfo Request is too large\n",
				"cefnetd_incoming_ccninforeq_process" );
#endif

		return (-1);
	}

	/* Clear information used in authentication & authorization */
	hdl->ccninfousr_id_len = 0;
	memset (hdl->ccninfousr_node_id, 0, sizeof(hdl->ccninfousr_node_id));
	if (hdl->ccninfo_rcvdpub_key_bi != NULL) {
		free (hdl->ccninfo_rcvdpub_key_bi);
		hdl->ccninfo_rcvdpub_key_bi = NULL;
	}
	hdl->ccninfo_rcvdpub_key_bi_len = 0;
	/* Parses the received  Ccninfo Request 	*/
	res = cef_frame_message_parse (
					msg, payload_len, header_len, &poh, &pm, CefC_PT_REQUEST);
	if (res < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Detects the invalid Ccninfo Request\n");
#endif // CefC_Debug
		return (-1);
	}


	/* Parses the received Ccninfo ccninfo-03	*/
	if ( (pci = cef_frame_ccninfo_parse (msg)) == NULL ){
		return(-1);
	}
#ifdef DEB_CCNINFO
	cefnetd_dbg_cpi_print ( pci );
#endif

	/* ccninfo-03 Loop check */
	res = cefnetd_ccninfo_loop_check( hdl, pci );
	if ( res < 0 ) {
		/* Detect Loop */
		detect_loop = 1;
	} else {
		detect_loop = 0;
	}

	if (pci->putverify_f) {
		if (pci->putverify_msgtype != CefC_CpvOp_ContInfoMsg) {
			cef_frame_ccninfo_parsed_free (pci);
			return (-1);
		}
		res = cefnetd_continfo_process (
			hdl, faceid, peer_faceid, msg, payload_len, header_len, &pm, pci);
		cef_frame_ccninfo_parsed_free (pci);
		if (res < 0) {
			return (-1);
		}
		return (1);
	}

	/* Check HopLimit */
	if (pm.hoplimit < 1 || pm.hoplimit <= poh.skip_hop) {
		cef_frame_ccninfo_parsed_free (pci);
		return (-1);
	}

	/* Set information used in authentication & authorization */
	memcpy (hdl->ccninfousr_node_id, pci->node_id, pci->id_len);
	hdl->ccninfousr_id_len = pci->id_len;

#ifdef CefC_Debug
	cef_dbg_buff_write_name (CefC_Dbg_Finer,
								(unsigned char*)"Ccninfo Request's Name [", strlen("Ccninfo Request's Name ["),
								pm.name, pm.name_len,
								(unsigned char*)" ]\n", strlen(" ]\n"));
#endif // CefC_Debug

#ifdef DEB_CCNINFO
{
	int dbg_x;
	fprintf (stderr, "DEB_CCNINFO: Rcvd Ccnifno Request's Msg [ ");
	for (dbg_x = 0 ; dbg_x < payload_len+header_len ; dbg_x++) {
		fprintf (stderr, "%02x ", msg[dbg_x]);
	}
	fprintf (stderr, "](%d)\n", payload_len+header_len);
	fprintf(stderr, "poh.req_id=%d\n", poh.req_id);
	fprintf(stderr, "poh.skip_hop=%d\n", poh.skip_hop);
	fprintf(stderr, "poh.skip_hop_offset=%d\n", poh.skip_hop_offset);
	fprintf(stderr, "poh.ccninfo_flag=%d\n", poh.ccninfo_flag);
	fprintf(stderr, "poh.req_arrival_time=%u\n", poh.req_arrival_time);
	fprintf(stderr, "poh.node_id=");
	for(dbg_x = 0 ; dbg_x < poh.nodeid_len ; dbg_x++)
		fprintf(stderr, "%x", poh.nodeid_val[dbg_x]);
	fprintf(stderr, " (%d)\n", poh.nodeid_len);

}
#endif  //DEB_CCNINFO

	/* Adds the time stamp on this request 		*/
	id_len = cef_face_node_id_get (peer_faceid, peer_node_id);
	id_len = cefnetd_matched_node_id_get (hdl, peer_node_id, id_len, node_id, &responder_mtu);
	memcpy (stamp_node_id, node_id, id_len);
	new_header_len
		= header_len + CefC_S_TLF + hdl->My_Node_Name_TLV_len + CefC_S_ReqArrivalTime;

	if (poh.skip_hop == 0) {
		if (new_header_len <= CefC_Max_Header_Size) {
			/* NOP */
		} else {
			return_code = CefC_CtRc_NO_SPACE;
#ifdef DEB_CCNINFO
{
	fprintf(stderr, "[%s] NO_SPACE\n",
			"cefnetd_incoming_ccninforeq_process" );
}
#endif //DEB_CCNINFO
			goto SEND_REPLY;
		}
	}
	/* Checks the Validation 			*/
	res = cef_valid_msg_verify_forccninfo
						(msg, payload_len + header_len
					 	 , &(hdl->ccninfo_rcvdpub_key_bi_len)
						 , &(hdl->ccninfo_rcvdpub_key_bi));
	if (res != 0) {
		if (poh.skip_hop != 0) {
			cef_frame_ccninfo_parsed_free (pci);
			return (-1);
		} else {
			return_code = CefC_CtRc_INVALID_REQUEST;
			goto SEND_REPLY;
		}
	}
	/* Check Access Policy */
	if (hdl->ccninfo_access_policy == 2 /* Do not allow access */) {
		return_code = CefC_CtRc_ADMIN_PROHIB;
		goto SEND_REPLY;
	}
	if (hdl->ccninfo_full_discovery == 0 /* Not Allow ccninfo-03 */
		&& poh.ccninfo_flag & CefC_CtOp_FullDisCover) {
		return_code = CefC_CtRc_ADMIN_PROHIB;
		goto SEND_REPLY;
	}

	/* Check whether this cefnetd will be the responder 	*/
	if (poh.skip_hop > 0) {
		forward_req_f = 1;
	} else {
		if (hdl->ccninfo_access_policy == 0 /* No limit */) {
			/* Searches a App Reg Table entry matching this request 		*/
			if (pm.chunk_num_f) {
				name_len = pm.name_len - (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
			} else {
				name_len = pm.name_len;
			}
			fip = (uint16_t*) cef_hash_tbl_item_get_for_app (hdl->app_reg, pm.name, name_len);
#ifdef DEB_CCNINFO
{
	int ii;
	char outstr[4096];
	char xstr[32];

	fprintf(stderr, "DEB_CCNINFO: [%s] CALLed cef_hash_tbl_item_get(%d) fip=%p\n", __FUNCTION__, __LINE__, fip);
	fprintf(stderr, "========== name_len=%d / pm.name ==========\n", name_len);
	memset(outstr, 0, sizeof(outstr));
	for(ii=0; ii < name_len; ii++){
		if(isprint(pm.name[ii])){
			sprintf(xstr, ".%c", pm.name[ii]);
		} else {
			sprintf(xstr, "%02X", (unsigned char)pm.name[ii]);
		}
		strcat(outstr, xstr);
	}
	fprintf(stderr, "%s\n", outstr);
	fprintf(stderr, "===============================\n");
}
#endif //DEB_CCNINFO

			if (fip) {
				/* Check Validations ccninfo-05 */
				if ( poh.ccninfo_flag & CefC_CtOp_ReqValidation ) {
					if ( hdl->ccninfo_valid_type == CefC_T_ALG_INVALID ) {
						/* Invalid */
						return_code = CefC_CtRc_INVALID_REQUEST;
						goto SEND_REPLY;
					}
				}
				/* ccninfo-05 */
				cefnetd_FHR_Reply_process(hdl, peer_faceid, msg, payload_len, header_len
											, ((CefT_App_Reg*)fip)->name, ((CefT_App_Reg*)fip)->name_len, &poh);
				cef_frame_ccninfo_parsed_free (pci);
				return (0);
			} else {
				forward_req_f = 1;
			}
		}

#if CefC_IsEnable_ContentStore
		if (hdl->cs_stat != NULL
			&& hdl->ccninfo_access_policy == 0 /* No limit */
			&& !(poh.ccninfo_flag & CefC_CtOp_Publisher)
			&& hdl->cs_stat->cache_type != CefC_Cache_Type_ExConpub
		   ) {
			/* Checks whether the specified contents is cached 	*/
			if (hdl->cs_stat->cache_type != CefC_Default_Cache_Type) {
				/* Query by Name without chunk number to check if content exists */
				if (pm.chunk_num_f) {
					name_len = pm.name_len - (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
				} else {
					name_len = pm.name_len;
				}
				/* Check content exists */
				res = cef_csmgr_excache_item_check_for_ccninfo (hdl->cs_stat, pm.name, name_len);
				if (res < 0) {
					forward_req_f = 1;
				} else {
					forward_req_f = 0;
				}
				if (forward_req_f != 1) {
					/* Query by Name to check if content(or chunk) exists */
					res = cefnetd_external_cache_seek (
						hdl, peer_faceid, msg, payload_len, header_len, &pm, &poh);

					if (res > 0) {
						cef_frame_ccninfo_parsed_free (pci);
						return (1);
					}
					forward_req_f = 1;
				}
			}
		} else {
			forward_req_f = 1;
		}
#endif // CefC_IsEnable_ContentStore
	}

	if ((forward_req_f == 1) && (pm.hoplimit == 1)) {
		forward_req_f = 0;
		return_code = CefC_CtRc_NO_INFO;
	}

	/* Detect Loop? */
	if ( detect_loop == 1 ) {
		goto SEND_REPLY;
	}

	if (forward_req_f) {
		/* Searches a FIB entry matching this request 		*/
		if (pm.chunk_num_f) {
			name_len = pm.name_len - (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
		} else {
			/* Symbolic Interest	*/
			name_len = pm.name_len;
		}

		/* Searches a FIB entry matching this request 	*/
		fe = cef_fib_entry_search (hdl->fib, pm.name, name_len);

		/* Obtains Face-ID(s) to forward the request 	*/
		if (fe) {
			int pit_res = 0;

			/* Obtains the FaceID(s) to forward the request 	*/
			face_num = cef_fib_forward_faceid_select (fe, peer_faceid, faceids);

			/* Searches a PIT entry matching this request 	*/
			/* Create PIT for ccninfo ccninfo-03 */
			memset( ccninfo_name, 0x00, sizeof(ccninfo_name) );
			ccninfo_namelen = cefnetd_ccninfo_name_create( hdl, pci, ccninfo_name, CCNINFO_REQ, 0 );
			pe = cef_pit_entry_search (hdl->pit, &pm, &poh, ccninfo_name, ccninfo_namelen);
			if ( pe != NULL ) {
				/* Alredy passed request */
				cef_frame_ccninfo_parsed_free (pci);
				return(-1);
			}

			/* Updates the information of down face that this request arrived 	*/
			pe = cef_pit_entry_lookup_and_down_face_update (hdl->pit, &pm, &poh, ccninfo_name, ccninfo_namelen,
						peer_faceid, msg, CefC_IntRetrans_Type_NOSUP, &pit_res);

			if (pe == NULL) {
				cef_frame_ccninfo_parsed_free (pci);
				return (-1);
			}

			/* Forwards the received Ccninfo Request */
			if (pit_res != 0) {
				/* ccninfo-05 */
				if (poh.skip_hop > 0) {
					/* NOP */
				} else {
					gettimeofday (&t, NULL);
					pkt_len = cef_frame_ccninfo_req_add_stamp (
									msg, payload_len + header_len, hdl->My_Node_Name_TLV, hdl->My_Node_Name_TLV_len, t);
					header_len 	= msg[CefC_O_Fix_HeaderLength];
					payload_len = pkt_len - header_len;
				}
				/* ccninfo-05 */
				/* Updates the skip hop 					*/
				if (poh.skip_hop > 0) {
					poh.skip_hop--;
//					msg[poh.skip_hop_offset] = poh.skip_hop;
					w_skiphop.sh_4bit = poh.skip_hop;
					w_skiphop.fl_4bit = 0;
					memcpy(&msg[poh.skip_hop_offset], &w_skiphop, 1);
				}
				pm.hoplimit--;
				msg[CefC_O_Fix_HopLimit] = pm.hoplimit;
#ifdef DEB_CCNINFO
{
	int dbg_x;
	fprintf (stderr, "DEB_CCNINFO: Forward Ccninfo Request's Msg [ ");
	for (dbg_x = 0 ; dbg_x < payload_len+header_len ; dbg_x++) {
		fprintf (stderr, "%02x ", msg[dbg_x]);
	}
	fprintf (stderr, "](%d)\n", payload_len+header_len);
}
#endif //DEB_CCNINFO
				/* Forwards 		*/
				cefnetd_ccninforeq_forward (
					hdl, faceids, face_num, peer_faceid, msg,
					payload_len, header_len, &pm, &poh, pe, fe);
			}
			cef_frame_ccninfo_parsed_free (pci);
			return (1);
		} else {
			if (poh.skip_hop > 0) {
				cef_frame_ccninfo_parsed_free (pci);
				return (1);
			}
			return_code = CefC_CtRc_NO_ROUTE;
		}
	}

SEND_REPLY:;
#ifdef	DEB_CCNINFO
	printf( "[%s] SEND_REPLY\n",
			"cefnetd_incoming_ccninforeq_process" );
#endif
	/* ccninfo-05 */
	switch ( return_code ) {
		case	CefC_CtRc_NO_ERROR:
			if ( detect_loop == 1 ) {
				gettimeofday (&t, NULL);
				pkt_len = cef_frame_ccninfo_req_add_stamp (
								msg, payload_len + header_len, hdl->My_Node_Name_TLV, hdl->My_Node_Name_TLV_len, t);
				header_len 	= msg[CefC_O_Fix_HeaderLength];
				payload_len = pkt_len - header_len;
			}
			break;
		case	CefC_CtRc_NO_SPACE:
			break;
		default:
			gettimeofday (&t, NULL);
			pkt_len = cef_frame_ccninfo_req_add_stamp (
							msg, payload_len + header_len, hdl->My_Node_Name_TLV, hdl->My_Node_Name_TLV_len, t);
			header_len 	= msg[CefC_O_Fix_HeaderLength];
			payload_len = pkt_len - header_len;
			break;
	}

	if ( return_code != CefC_CtRc_NO_SPACE ) {
		if ( poh.ccninfo_flag & CefC_CtOp_ReqValidation ) {
			if ( hdl->ccninfo_valid_type == CefC_T_ALG_INVALID ) {
				return_code = CefC_CtRc_INVALID_REQUEST;
			} else {
				/* NOP */
			}
		} else {
			/* NOP */
		}
	}
	/* ccninfo-05 */
	/* ccninfo-03 */
	/* Loop? */
	if ( detect_loop == 1 ) {
		return_code |= CefC_CtRc_FATAL_ERROR;
	}
	/* ccninfo-03 */

	/* Remove the Valation-related TLV from the message */
	pkt_len = cef_valid_remove_valdsegs_fr_msg_forccninfo (msg, pkt_len);
	/* Set PacketType and Return Code 		*/
	msg[CefC_O_Fix_Type] 			= CefC_PT_REPLY;
	msg[CefC_O_Fix_Ccninfo_RetCode] 	= return_code;


	/*----------------------------------------------------------*/
	/* Validations	 											*/
	/*----------------------------------------------------------*/
	if ( poh.ccninfo_flag & CefC_CtOp_ReqValidation )
	{
		CefT_Ccninfo_TLVs tlvs;

		if (hdl->ccninfo_valid_type != CefC_T_ALG_INVALID) {
			tlvs.alg.valid_type = hdl->ccninfo_valid_type;
			pkt_len = cef_frame_ccninfo_vald_create_for_reply (msg, &tlvs);
		}
	}
	/* Check Ccninfo Relpy size										*/
	/*   NOTE: When oversize, create a reply message of NO_SPECE	*/
	pkt_len = cefnetd_ccninfo_check_relpy_size(hdl, msg, pkt_len, poh.ccninfo_flag);

	/* Returns a Ccninfo Reply with error return code 		*/
	cefnetd_frame_send_txque (hdl, peer_faceid, msg, pkt_len);

	cef_frame_ccninfo_parsed_free (pci);

	return (1);
}
#if CefC_IsEnable_ContentStore
/*--------------------------------------------------------------------------------------
	Seeks the csmgr and creates the ccninfo response
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_external_cache_seek (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	CefT_CcnMsg_MsgBdy* pm,				/* Structure to set parsed CEFORE message	*/
	CefT_CcnMsg_OptHdr* poh
) {
	unsigned char buff[CefC_Max_Length] = {0};
	int res=-1;
	uint16_t pld_len;
	uint16_t index;
	uint16_t name_len;
	uint16_t msg_len;
	uint16_t pkt_len;
	uint16_t pld_len_new;
	struct tlv_hdr pyld_tlv_hdr;
	struct fixed_hdr* fix_hdr;
	struct tlv_hdr* tlv_hp;
	struct tlv_hdr* name_tlv_hdr;
//	struct value32_tlv value32_tlv;	/* for T_DISC_REPLY */
	uint8_t rtn_cd;
	struct ccninfo_req_block req_blk;	/* for T_DISC_REPLY ccninfo-05 */

#ifdef	DEB_CCNINFO
	printf( "[%s] IN payload_len(%d) + header_len(%d) = %d\n",
			"cefnetd_external_cache_seek", payload_len, header_len, payload_len + header_len );
#endif

	/* Remove the Valation-related TLV from the message */
	payload_len = cef_valid_remove_valdsegs_fr_msg_forccninfo (msg, payload_len+header_len)
				  - header_len;
	if (hdl->cs_stat->cache_type != CefC_Cache_Type_Localcache) {
		if (pm->chunk_num_f) {
			res = cef_csmgr_excache_info_get (
				hdl->cs_stat, pm->name, pm->name_len, buff, 0/*ExactMatch*/);
		} else {
			res = cef_csmgr_excache_info_get (
				hdl->cs_stat, pm->name, pm->name_len, buff, 1/*PartialMatch*/);
		}
	}
#ifdef CefC_CefnetdCache
	else {
		res = cef_csmgr_locache_info_get (
			hdl->cs_stat, pm->name, pm->name_len, buff, 0/*ExactMatch*/);
	}
#endif //CefC_CefnetdCache
	if (res < 1) {
		return (0);
	}

#ifdef DEB_CCNINFO
{
	int dbg_x;
	fprintf (stderr, "res = %d [ ", res);
	for (dbg_x = 0 ; dbg_x < res ; dbg_x++) {
		fprintf (stderr, "%02x ", buff[dbg_x]);
	}
	fprintf (stderr, "]\n");
}
#endif //DEB_CCNINFO

	/* Check Validations */
	if ( poh->ccninfo_flag & CefC_CtOp_ReqValidation ) {
		if ( hdl->ccninfo_valid_type == CefC_T_ALG_INVALID ) {
			/* Invalid */
			rtn_cd = CefC_CtRc_INVALID_REQUEST;
			res = 0;
#ifdef DEB_CCNINFO
	printf( "\t000 rtn_cd = CefC_CtRc_INVALID_REQUEST\n");
#endif //DEB_CCNINFO
		} else {
			rtn_cd = CefC_CtRc_NO_ERROR;
#ifdef DEB_CCNINFO
	printf( "\t001 rtn_cd = CefC_CtRc_NO_ERROR\n");
#endif //DEB_CCNINFO
		}
	} else {
		rtn_cd = CefC_CtRc_NO_ERROR;
#ifdef DEB_CCNINFO
	printf( "\t002 rtn_cd = CefC_CtRc_NO_ERROR\n");
#endif //DEB_CCNINFO
	}


	/* Returns a Ccninfo Reply 			*/
	if (res) {
		if (poh->ccninfo_flag & CefC_CtOp_Cache) {
			pld_len = (uint16_t) res;
			index   = 0;

			while (index < pld_len) {
				index += CefC_S_TLF + sizeof (struct ccninfo_rep_block);

				name_tlv_hdr = (struct tlv_hdr*) &buff[index];
				name_len = ntohs (name_tlv_hdr->length);
				index += CefC_S_TLF;

				/* Sets the header of Reply Block 		*/
				index += name_len;
			}

			/* Sets type and length of T_DISC_REPLY 		*/
			pyld_tlv_hdr.type 	 = htons (CefC_T_DISC_REPLY);
			/* pld_len + R_ArrTime + NodeID */
//JK			pld_len_new = CefC_S_TLF + CefC_S_ReqArrivalTime + hdl->My_Node_Name_TLV_len + pld_len;
			pld_len_new = CefC_S_ReqArrivalTime + hdl->My_Node_Name_TLV_len + pld_len;
#ifdef DEB_CCNINFO
		printf( "\t010 pld_len_new = %d(%x)\n", pld_len_new, pld_len_new);
#endif //DEB_CCNINFO
			pyld_tlv_hdr.length  = htons (pld_len_new);
			memcpy (&msg[payload_len + header_len], &pyld_tlv_hdr, sizeof (struct tlv_hdr));
			index = payload_len + header_len;
#ifdef DEB_CCNINFO
		printf( "\t011 index = %d(%x)\n", index, index);
#endif //DEB_CCNINFO
			index += CefC_S_TLF;
#ifdef DEB_CCNINFO
		printf( "\t011-1 index = %d(%x)\n", index, index);
#endif //DEB_CCNINFO
			{	/* set 32bit-NTP time */
		    	struct timespec tv;
				uint32_t ntp32b;
				clock_gettime(CLOCK_REALTIME, &tv);
				ntp32b = ((tv.tv_sec + 32384) << 16) + ((tv.tv_nsec << 7) / 1953125);
				req_blk.req_arrival_time 	= htonl (ntp32b);
				memcpy (&msg[index], &req_blk, sizeof (struct ccninfo_req_block));
//JK				index += CefC_S_TLF + CefC_S_ReqArrivalTime;
				index += CefC_S_ReqArrivalTime;
#ifdef DEB_CCNINFO
		printf( "\t012 index = %d(%x)\n", index, index);
#endif //DEB_CCNINFO
			}
			/* NODE ID */
			memcpy ( &msg[index], hdl->My_Node_Name_TLV, hdl->My_Node_Name_TLV_len );
			index += hdl->My_Node_Name_TLV_len;
#ifdef DEB_CCNINFO
		printf( "\t013 index = %d(%x)\n", index, index);
#endif //DEB_CCNINFO
			payload_len += CefC_S_TLF + CefC_S_ReqArrivalTime + hdl->My_Node_Name_TLV_len;
#ifdef DEB_CCNINFO
		printf( "\t014 payload_len = %d(%x)\n", payload_len, payload_len);
#endif //DEB_CCNINFO
			memcpy (&msg[index], buff, pld_len);

			/* Sets ICN message length 	*/
			pkt_len = payload_len + header_len + pld_len;
//JK			pkt_len = payload_len + header_len + CefC_S_TLF + pld_len;
#ifdef DEB_CCNINFO
		printf( "\t015 pkt_len = %d(%x)\n", pkt_len, pkt_len);
#endif //DEB_CCNINFO
			msg_len = pkt_len - (header_len + CefC_S_TLF);
#ifdef DEB_CCNINFO
		printf( "\t016 msg_len = %d(%x)\n", msg_len, msg_len);
#endif //DEB_CCNINFO

			tlv_hp = (struct tlv_hdr*) &msg[header_len];
			tlv_hp->length = htons (msg_len);

			/* Updates PacketLength and HeaderLength 		*/
			fix_hdr = (struct fixed_hdr*) msg;
			fix_hdr->type 	  = CefC_PT_REPLY;
			fix_hdr->reserve1 = rtn_cd;
			fix_hdr->pkt_len  = htons (pkt_len);
		} else {
			pld_len = (uint16_t) 0;
			index   = 0;
			/* Sets type and length of T_DISC_REPLY 		*/
			pyld_tlv_hdr.type 	 = htons (CefC_T_DISC_REPLY);
			/* R_ArrTime + NodeID */
			pld_len_new = CefC_S_ReqArrivalTime + hdl->My_Node_Name_TLV_len;
			pyld_tlv_hdr.length  = htons (pld_len_new);
			memcpy (&msg[payload_len + header_len], &pyld_tlv_hdr, sizeof (struct tlv_hdr));
			index = payload_len + header_len;
			index += CefC_S_TLF;
			{	/* set 32bit-NTP time */
		    	struct timespec tv;
				uint32_t ntp32b;
				clock_gettime(CLOCK_REALTIME, &tv);
				ntp32b = ((tv.tv_sec + 32384) << 16) + ((tv.tv_nsec << 7) / 1953125);
				req_blk.req_arrival_time 	= htonl (ntp32b);
				memcpy (&msg[index], &req_blk, sizeof (struct ccninfo_req_block));
//JK				index += CefC_S_TLF + CefC_S_ReqArrivalTime;
				index += CefC_S_ReqArrivalTime;
			}
			/* NODE ID */
			memcpy ( &msg[index], hdl->My_Node_Name_TLV, hdl->My_Node_Name_TLV_len );
			index += hdl->My_Node_Name_TLV_len;
			payload_len += CefC_S_TLF + CefC_S_ReqArrivalTime + hdl->My_Node_Name_TLV_len;

			/* Sets ICN message length 	*/
//JK			pkt_len = payload_len + header_len + CefC_S_TLF;
			pkt_len = payload_len + header_len + pld_len;
//JK			pkt_len = payload_len + header_len + CefC_S_TLF + pld_len;
			msg_len = pkt_len - (header_len + CefC_S_TLF);

			tlv_hp = (struct tlv_hdr*) &msg[header_len];
			tlv_hp->length = htons (msg_len);
			/* ccninfo-05 */
			fix_hdr = (struct fixed_hdr*) msg;
			fix_hdr->type 	  = CefC_PT_REPLY;
			fix_hdr->reserve1 = rtn_cd;
			pkt_len  		  = fix_hdr->pkt_len;
		}


		/*----------------------------------------------------------*/
		/* Validations	 											*/
		/*----------------------------------------------------------*/
		if ( poh->ccninfo_flag & CefC_CtOp_ReqValidation )
		{
			CefT_Ccninfo_TLVs tlvs;

			if (hdl->ccninfo_valid_type != CefC_T_ALG_INVALID) {
				tlvs.alg.valid_type = hdl->ccninfo_valid_type;
				pkt_len = cef_frame_ccninfo_vald_create_for_reply (msg, &tlvs);
			}
		}

		/* Check Ccninfo Relpy size										*/
		/*   NOTE: When oversize, create a reply message of NO_SPECE	*/
		pkt_len = cefnetd_ccninfo_check_relpy_size(hdl, msg, pkt_len, poh->ccninfo_flag);
#ifdef DEB_CCNINFO
		printf( "\t020 pkt_len = %d(%x)\n", pkt_len, pkt_len);
#endif //DEB_CCNINFO

#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Ccninfo response is follow:\n");
		cef_dbg_buff_write (CefC_Dbg_Finest, msg, pkt_len);
#endif // CefC_Debug
		cefnetd_frame_send_txque (hdl, peer_faceid, msg, pkt_len);
#ifdef	DEB_CCNINFO
	printf( "[%s] Return(1)\n",
			"cefnetd_external_cache_seek" );
#endif

		return (1);
	}

#ifdef	DEB_CCNINFO
	printf( "[%s] Return(0)\n",
			"cefnetd_external_cache_seek" );
#endif
	return (0);
}
#endif // CefC_IsEnable_ContentStore
/*--------------------------------------------------------------------------------------
	Create and Send the FHR's ccninfo response
----------------------------------------------------------------------------------------*/
static void
cefnetd_FHR_Reply_process(
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	const unsigned char* name,				/* Report name								*/
	uint32_t name_len,						/* Report name length						*/
	CefT_CcnMsg_OptHdr* poh
){
	unsigned char rply_sub_block[CefC_Max_Length] = {0};
	uint16_t index = 0;
	uint16_t rec_index;
	struct ccninfo_rep_block rep_blk;
	struct tlv_hdr rply_tlv_hdr;
	struct tlv_hdr name_tlv_hdr;
	struct tlv_hdr pyld_tlv_hdr;
	struct tlv_hdr* tlv_hp;
	uint16_t msg_len;
	uint16_t pkt_len;
	struct fixed_hdr* fix_hdr;
	uint16_t pld_len_new;
	uint16_t pld_len;
	struct ccninfo_req_block req_blk;	/* for T_DISC_REPLY ccninfo-05 */

#ifdef	DEB_CCNINFO
	printf( "[%s] IN payload_len(%d) + header_len(%d) = %d\n",
			"cefnetd_FHR_Reply_process", payload_len, header_len, payload_len + header_len );
#endif

	/* Remove the Valation-related TLV from the message */
	payload_len = cef_valid_remove_valdsegs_fr_msg_forccninfo (msg, payload_len+header_len)
				  - header_len;

	if (!(poh->ccninfo_flag & CefC_CtOp_Cache)) {
		pld_len = 0;
		goto SKIP_REP_BLK;
	}
	name_tlv_hdr.type = htons (CefC_T_NAME);

	rec_index = index;
	index += CefC_S_TLF;
	//ccninfo-05
	rep_blk.cont_size 	= htonl (UINT32_MAX);
	rep_blk.cont_cnt 	= htonl (UINT32_MAX);
	rep_blk.rcv_int 	= htonl (UINT32_MAX);
	rep_blk.first_seq 	= htonl (UINT32_MAX);
	rep_blk.last_seq 	= htonl (UINT32_MAX);
	rep_blk.cache_time 	= htonl (UINT32_MAX);
	rep_blk.remain_time	= htonl (UINT32_MAX);

	memcpy (&rply_sub_block[index], &rep_blk, sizeof (struct ccninfo_rep_block));
	index += sizeof (struct ccninfo_rep_block);

	/* Name 				*/
	name_tlv_hdr.length = htons (name_len);
	memcpy (&rply_sub_block[index], &name_tlv_hdr, sizeof (struct tlv_hdr));
	memcpy (&rply_sub_block[index + CefC_S_TLF], name, name_len);
	index += CefC_S_TLF + name_len;

	/* Sets the header of Reply Block 		*/
	rply_tlv_hdr.type = htons (CefC_T_DISC_CONTENT_OWNER);
	rply_tlv_hdr.length = htons (index - (rec_index + CefC_S_TLF));
	memcpy (&rply_sub_block[rec_index], &rply_tlv_hdr, sizeof (struct tlv_hdr));
	pld_len = index;

SKIP_REP_BLK:;

	/* Sets type and length of T_DISC_REPLY 		*/
	pyld_tlv_hdr.type 	 = htons (CefC_T_DISC_REPLY);
	/* ccninfo-05 */
	/* pld_len + R_ArrTime + NodeID */
	pld_len_new = CefC_S_ReqArrivalTime + hdl->My_Node_Name_TLV_len + pld_len;
	pyld_tlv_hdr.length  = htons (pld_len_new);
	memcpy (&msg[payload_len + header_len], &pyld_tlv_hdr, sizeof (struct tlv_hdr));
	index = payload_len + header_len;
	index += CefC_S_TLF;
	{	/* set 32bit-NTP time */
    	struct timespec tv;
		uint32_t ntp32b;
		clock_gettime(CLOCK_REALTIME, &tv);
		ntp32b = ((tv.tv_sec + 32384) << 16) + ((tv.tv_nsec << 7) / 1953125);
		req_blk.req_arrival_time 	= htonl (ntp32b);
		memcpy (&msg[index], &req_blk, sizeof (struct ccninfo_req_block));
		index += CefC_S_ReqArrivalTime;
	}
	/* NODE ID */
	memcpy ( &msg[index], hdl->My_Node_Name_TLV, hdl->My_Node_Name_TLV_len );
	index += hdl->My_Node_Name_TLV_len;
	payload_len += CefC_S_TLF + CefC_S_ReqArrivalTime + hdl->My_Node_Name_TLV_len;

	if ( pld_len > 0 ) {
		memcpy (&msg[index], rply_sub_block, pld_len);
	}

	/* Sets ICN message length 	*/
	pkt_len = payload_len + header_len + pld_len;
	msg_len = pkt_len - (header_len + CefC_S_TLF);

	tlv_hp = (struct tlv_hdr*) &msg[header_len];
	tlv_hp->length = htons (msg_len);

	/* Updates PacketLength and HeaderLength 		*/
	fix_hdr = (struct fixed_hdr*) msg;
	fix_hdr->type 	  = CefC_PT_REPLY;
	fix_hdr->reserve1 = CefC_CtRc_NO_ERROR;
	fix_hdr->pkt_len  = htons (pkt_len);
#ifdef DEB_CCNINFO
{
	int dbg_x;
	fprintf (stderr, "DEB_CCNINFO: Sent Ccninfo Relpy's Msg [ ");
	for (dbg_x = 0 ; dbg_x < pkt_len ; dbg_x++) {
		fprintf (stderr, "%02x ", msg[dbg_x]);
	}
	fprintf (stderr, "](%d)\n", pkt_len);
}
#endif //DEB_CCNINFO

	/*----------------------------------------------------------*/
	/* Validations	 											*/
	/*----------------------------------------------------------*/
	if ( poh->ccninfo_flag & CefC_CtOp_ReqValidation )
	{
		CefT_Ccninfo_TLVs tlvs;

		if (hdl->ccninfo_valid_type != CefC_T_ALG_INVALID) {
			tlvs.alg.valid_type = hdl->ccninfo_valid_type;
			pkt_len = cef_frame_ccninfo_vald_create_for_reply (msg, &tlvs);
		}
	}

	/* Check Ccninfo Relpy size										*/
	/*   NOTE: When oversize, create a reply message of NO_SPECE	*/
	pkt_len = cefnetd_ccninfo_check_relpy_size(hdl, msg, pkt_len, poh->ccninfo_flag);

#ifdef DEB_CCNINFO
{
	int dbg_x;
	fprintf (stderr, "DEB_CCNINFO: Sent Ccninfo Relpy's Msg(2) [ ");
	for (dbg_x = 0 ; dbg_x < pkt_len ; dbg_x++) {
		fprintf (stderr, "%02x ", msg[dbg_x]);
	}
	fprintf (stderr, "](%d)\n", pkt_len);
}
#endif //DEB_CCNINFO
	cefnetd_frame_send_txque (hdl, peer_faceid, msg, pkt_len);
}


/*--------------------------------------------------------------------------------------
	Handles the received Ccninfo Replay
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_ccninforep_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	char*	user_id
) {

	CefT_CcnMsg_MsgBdy pm = { 0 };
	CefT_CcnMsg_OptHdr poh = { 0 };
	CefT_Pit_Entry* pe;
	int res, i;
	uint16_t faceids[CefC_Fib_UpFace_Max];
	uint16_t face_num = 0;
	CefT_Down_Faces* face;
	// ccninfo-03
	CefT_Parsed_Ccninfo	*pci;
	unsigned char ccninfo_name[CefC_Ccninfo_NameSize];
	int			  ccninfo_namelen;
#ifdef DEB_CCNINFO
{
	int dbg_x;
	fprintf (stderr, "DEB_CCNINFO: Rcvd Ccninfo Relpy's Msg (cefnetd_incoming_ccninforep_process())[ ");
	for (dbg_x = 0 ; dbg_x < payload_len+header_len ; dbg_x++) {
		fprintf (stderr, "%02x ", msg[dbg_x]);
	}
	fprintf (stderr, "](%d)\n", payload_len+header_len);
}
#endif //DEB_CCNINFO
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finer,
		"Process the Ccninfo Response (%d bytes)\n", payload_len + header_len);
#endif // CefC_Debug

#ifdef	DEB_CCNINFO
	fprintf( stderr, "[%s] Ccninfo Response (%d bytes)\n",
			"cefnetd_incoming_ccninforep_process", payload_len + header_len );
#endif

	/* Check the message size 		*/
	if (payload_len + header_len > CefC_Max_Msg_Size) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Ccninfo Response is too large\n");
#endif // CefC_Debug
		return (-1);
	}
	/* Check Access Policy */
	if (hdl->ccninfo_access_policy == 2 /* Do not allow access */) {
#ifdef	DEB_CCNINFO
		fprintf( stderr, "\t(hdl->ccninfo_access_policy == 2 /* Do not allow access */) return(0)\n" );
#endif
		return (0);
	}

	/* Parses the received Ccninfo Replay 	*/
	res = cef_frame_message_parse (
					msg, payload_len, header_len, &poh, &pm, CefC_PT_REPLY);
	if (res < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Detects the invalid Ccninfo Response\n");
#endif // CefC_Debug
#ifdef	DEB_CCNINFO
		fprintf( stderr, "\tDetects the invalid Ccninfo Response return(-1)\n" );
#endif
		return (-1);
	}

	/* Parses the received Ccninfo ccninfo-03	*/
	if ( (pci = cef_frame_ccninfo_parse (msg)) == NULL ){
#ifdef	DEB_CCNINFO
		fprintf( stderr, "\t(res < 0)cef_frame_ccninfo_parse() return(-1)\n" );
#endif
		return(-1);
	}
#ifdef DEB_CCNINFO
	cefnetd_dbg_cpi_print ( pci );
#endif

#ifdef CefC_Debug
{ static char title[] = "Ccninfo Response's Name [";
	cef_dbg_buff_write_name (CefC_Dbg_Finer,
								(void *)title, strlen(title),
								pm.name, pm.name_len,
								(unsigned char*)" ]\n", strlen(" ]\n"));
}
#endif // CefC_Debug

	/* Create PIT Name for ccninfo ccninfo-03 */
	memset( ccninfo_name, 0x00, sizeof(ccninfo_name) );
	ccninfo_namelen = cefnetd_ccninfo_name_create( hdl, pci, ccninfo_name, CCNINFO_REP, 1 );

	/* Searches a PIT entry matching this replay 	*/
	pe = cef_pit_entry_search (hdl->pit, &pm, &poh, ccninfo_name, ccninfo_namelen);
	if ( pe == NULL ) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finer, "PIT entry not found.\n");
#endif // CefC_Debug
		memset( ccninfo_name, 0x00, sizeof(ccninfo_name) );
		ccninfo_namelen = cefnetd_ccninfo_name_create( hdl, pci, ccninfo_name, CCNINFO_REP, 0 );
		pe = cef_pit_entry_search (hdl->pit, &pm, &poh, ccninfo_name, ccninfo_namelen);
	}

	if (pe) {
		face = &(pe->dnfaces);
		while (face->next) {
			face = face->next;
			faceids[face_num] = face->faceid;
			face_num++;
			cef_pit_entry_down_face_remove (pe, face, &pm);
		}
	} else {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finer, "PIT entry not found.\n");
#endif // CefC_Debug
		cef_frame_ccninfo_parsed_free (pci);
		return (-1);
	}

	/* Forwards the ccninfo Replay 					*/
	for (i = 0 ; i < face_num ; i++) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finer, "Forward the CcninfoReply to Face#%u.\n", faceids[i]);
#endif // CefC_Debug

		if (cef_face_check_active (faceids[i]) > 0) {
			cefnetd_frame_send_txque (hdl, faceids[i], msg, payload_len + header_len);
		} else {
			cef_pit_down_faceid_remove (pe, faceids[i]);
		}
	}
	/* Not full discovery */
	if (pe->stole_f && cef_pit_entry_lock(pe)){					// 2023/05/08 by iD
		cef_pit_entry_free (hdl->pit, pe);
	}
	cef_frame_ccninfo_parsed_free (pci);

	return (1);
}
#if CefC_IsEnable_ContentStore
/*--------------------------------------------------------------------------------------
	Handles the received Interest from csmgr
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_csmgr_interest_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	char*	user_id
) {
	/* NOP */;
	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the received Object from csmgr
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_csmgr_object_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	char*	user_id
) {
	CefT_CcnMsg_MsgBdy pm = { 0 };
	CefT_CcnMsg_OptHdr poh = { 0 };
	CefT_Pit_Entry* pe;
	int i;
	int res;
	uint8_t faceid_bitmap[CefC_Face_Router_Max];
	uint16_t faceids[CefC_Fib_UpFace_Max];
	uint16_t face_num = 0;
	CefT_Down_Faces* face;
	uint16_t pkt_len = 0;	//0.8.3
	CefT_Rx_Elem elem;
	int tp_plugin_res = CefC_Pi_All_Permission;
	CefT_Hash_Handle pit_handle = hdl->pit;

	cefnetd_faceidmap_init(faceid_bitmap, sizeof(faceid_bitmap));

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finer,
		"Process the Content Object (%d bytes) from csmgr\n", payload_len + header_len);
	cef_dbg_buff_write (CefC_Dbg_Finest, msg, payload_len + header_len);
#endif // CefC_Debug

#ifdef	__SYMBOLIC__
	fprintf( stderr, "[%s] IN Object (%d bytes) from csmgr\n", __func__, payload_len + header_len );
#endif

	/*--------------------------------------------------------------------
		Parses the Object message
	----------------------------------------------------------------------*/
	if (payload_len + header_len > CefC_Max_Msg_Size) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finer, "Content Object is too large\n");
#endif // CefC_Debug

		return (-1);
	}

	pkt_len = payload_len + header_len;	//0.8.3

	/* Checks the Validation 			*/
	res = cef_valid_msg_verify (msg, payload_len + header_len);
	if (res != 0) {
		cef_log_write (CefC_Log_Info, "Drops a malformed Cached Object.\n");
		return (-1);
	}

	res = cef_frame_message_parse (
					msg, payload_len, header_len, &poh, &pm, CefC_PT_OBJECT);
	if (res < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finer,
			"Detects the invalid Content Object from csmgr\n");
#endif // CefC_Debug

		return (-1);
	}
#ifdef	__SYMBOLIC__
	fprintf( stderr, "\t IN Object Chunk:%u \n", pm.chunk_num );
#endif
#ifdef CefC_Debug
	cef_dbg_buff_write_name (CefC_Dbg_Finer,
								(unsigned char*)"Object's Name [", strlen("Object's Name ["),
								pm.name, pm.name_len,
								(unsigned char*)" ]\n", strlen(" ]\n"));
#endif // CefC_Debug

	/*--------------------------------------------------------------------
		Inserts the Cob into temporary cache
	----------------------------------------------------------------------*/
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finer, "Insert the received Content Object to the buffer\n");
#endif // CefC_Debug
	cef_csmgr_cache_insert (hdl->cs_stat, msg, payload_len + header_len, &pm, &poh);

	/*--------------------------------------------------------------------
		Updates the statistics
	----------------------------------------------------------------------*/
	hdl->stat_recv_frames++;

	stat_rcv_size_cnt++;
	stat_rcv_size_sum += (payload_len + header_len);
	if ((payload_len + header_len) < stat_rcv_size_min) {
		stat_rcv_size_min = payload_len + header_len;
	}
	if ((payload_len + header_len) > stat_rcv_size_max) {
		stat_rcv_size_max = payload_len + header_len;
	}

	/*--------------------------------------------------------------------
		Searches a PIT entry matching this Object
	----------------------------------------------------------------------*/

	/**** 1st. app_pit ****/

	/* Search the PIT of the registered application with OPT_APP_PIT_REG */
	pit_handle = hdl->app_pit;
	pe = NULL;

	if ( pe == NULL ){
		CefT_Pit_Entry* pe_smi = NULL;

		pit_handle = hdl->pit;
		pe_smi = cef_pit_entry_search_symbolic (pit_handle, &pm, &poh);
		/**** 2nd. symbolic pit ****/
		if ( pe_smi && pe_smi->PitType != CefC_PIT_TYPE_Rgl ){
			if ( pm.chunk_num < (pe_smi->Last_chunk_num - hdl->SymbolicBack) ) {
				cef_dbg_write (CefC_Dbg_Fine, "SymbolicBack drop, chunk_num=%u\n", pm.chunk_num);
				pe_smi = NULL;		// stat_nopit_frames++
			} else if ( pe_smi->Last_chunk_num < pm.chunk_num ) {
				pe_smi->Last_chunk_num = pm.chunk_num;
			}
			if ( pe_smi ){
				for ( face = &(pe_smi->dnfaces); face->next; ) {
					face = face->next;
					if ( !cefnetd_faceidmap_is_set(faceid_bitmap, face->faceid) ){
						cefnetd_faceidmap_set(faceid_bitmap, face->faceid);
						faceids[face_num++] = face->faceid;
					}
				}
			}
		}
		/**** 3rd. reguler pit ****/
		pe = cef_pit_entry_search_with_chunk (pit_handle, &pm, &poh);
		if ( pe == NULL ){
			pe = pe_smi;
		}
	}

	/* COB without chunk number matches only Reg-PIT */
	if ( pm.chunk_num_f == 0 && pe && pe->PitType != CefC_PIT_TYPE_Rgl ) {
		cef_dbg_write (CefC_Dbg_Fine, "PitType Unmatch\n");
		pe = NULL;		// stat_nopit_frames++
	}

	if ( pe ) {
		//0.8.3
		if ( pe->COBHR_len > 0 ) {
			/* CobHash */
			uint16_t		CobHash_index;
			uint16_t		CobHash_len;
			unsigned char 	hash[SHA256_DIGEST_LENGTH];

			CobHash_index = header_len;
			CobHash_len   = payload_len;
			cef_valid_sha256( &msg[CobHash_index], CobHash_len, hash );	/* for OpenSSL 3.x */

			if ( memcmp(pe->COBHR_selector, hash, pe->COBHR_len) == 0 ) {
				/* OK */
			} else {
				/* NG */
				cef_log_write (CefC_Log_Info, "Dropped due to ObjectHash restrictions.\n");
				return (-1);
			}
		}
		if ( pe->KIDR_len > 0 ) {
			/* KeyIdRest */
			int keyid_len;
			unsigned char keyid_buff[CefC_KeyIdSiz];
			keyid_len = cefnetd_keyid_get( msg, pkt_len, keyid_buff );
			if ( (keyid_len == CefC_KeyIdSiz) && (memcmp(pe->KIDR_selector, keyid_buff, CefC_KeyIdSiz) == 0) ) {
				/* OK */
			} else {
				/* NG */
				cef_log_write (CefC_Log_Info, "Dropped due to KeyId restrictions.\n");
				return (-1);
			}
		}

		for (face = &(pe->dnfaces); face->next;) {
			face = face->next;
			if ( !cefnetd_faceidmap_is_set(faceid_bitmap, face->faceid) ){
				cefnetd_faceidmap_set(faceid_bitmap, face->faceid);
				faceids[face_num++] = face->faceid;
			}
		}
	} else {
		stat_nopit_frames++;
#ifdef CefC_Debug
{		char uri[CefC_NAME_BUFSIZ];
		cefnetd_name_to_uri (&pm, uri, sizeof(uri));
		cef_dbg_write (CefC_Dbg_Finer, "NOPIT:stat_nopit_frames=%u, %s\n", stat_nopit_frames, uri);
}
#endif // CefC_Debug
	}

	/*--------------------------------------------------------------------
		Transport Plugin
	----------------------------------------------------------------------*/
	if ((poh.org.tp_variant > CefC_T_OPT_TP_NONE)
	&&	(hdl->plugin_hdl.tp[poh.org.tp_variant].cob_from_cs)
	) {
		CefT_Pit_Entry* tmpe = cef_pit_entry_search_symbolic (hdl->pit, &pm, &poh);
		uint32_t contents_hashv = 0;	/* Hash value of this contents (without chunk number) */
		if ( tmpe ){
			contents_hashv = tmpe->hashv;	/* Hash value of this contents */
		} else {
			contents_hashv = 0;				/* Hash value of this contents */
		}

		/* Creates CefT_Rx_Elem 		*/
		memset (&elem, 0, sizeof (CefT_Rx_Elem));
		elem.plugin_variant 	= poh.org.tp_variant;
		elem.type 				= CefC_Elem_Type_Object;
		elem.hashv 				= contents_hashv;
		elem.in_faceid 			= (uint16_t) peer_faceid;
		elem.parsed_msg 		= &pm;
		memcpy (&(elem.msg[0]), msg, payload_len + header_len);
		elem.msg_len 			= payload_len + header_len;
		elem.out_faceid_num 	= face_num;

		for (i = 0 ; i < face_num ; i++) {
			elem.out_faceids[i] = faceids[i];
		}

		elem.parsed_oph 		= &poh;
		memcpy (elem.ophdr, poh.org.tp_val, poh.org.tp_len);
		elem.ophdr_len = poh.org.tp_len;

		/* Callback 		*/
		tp_plugin_res = (*(hdl->plugin_hdl.tp)[poh.org.tp_variant].cob_from_cs)(
			&(hdl->plugin_hdl.tp[poh.org.tp_variant]), &elem
		);
	}

	/*--------------------------------------------------------------------
		Forwards the Content Object
	----------------------------------------------------------------------*/
	if (tp_plugin_res & CefC_Pi_Object_Send) {
		if (face_num > 0) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finer, "Forward the Content Object to cefnetd(s)\n");
#endif // CefC_Debug
			cefnetd_object_forward (hdl, faceids, face_num, msg,
				payload_len, header_len, &pm, &poh, pe);

			if (pe->stole_f) {
				if (cef_pit_entry_lock(pe))					// 2023/04/19 by iD
					cef_pit_entry_free (pit_handle, pe);
			}
		}
	}

	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the received Ccninfo Request from csmgr
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_csmgr_ccninforeq_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	char*	user_id
) {
	/* NOP */;
	return (1);
}
#endif // CefC_IsEnable_ContentStore
/*--------------------------------------------------------------------------------------
	Reads the config file
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_config_read (
	CefT_Netd_Handle* hdl					/* cefnetd handle							*/
) {
//	char 	ws[CefC_BufSiz_1KB];
	char 	ws[CefC_BufSiz_2KB];
	char 	ws_w[CefC_BufSiz_1KB];
	FILE*	fp = NULL;
	char 	buff[CefC_BufSiz_1KB];
	char 	pname[64];
	int 	res;
	double 	res_dbl;
	int		IR_enabled = 0;

	/* Obtains the directory path where the cefnetd's config file is located. */
	cef_client_config_dir_get (ws_w);

	if (mkdir (ws_w, 0777) != 0) {
		if (errno == ENOENT) {
			cef_log_write (CefC_Log_Error, "<Fail> cefnetd_config_read (mkdir)\n");
			return (-1);
		}
	}
	sprintf (ws, "%s/cefnetd.conf", ws_w);

	/* Opens the cefnetd's config file. */
	fp = fopen (ws, "r");
	if (fp == NULL) {
		cef_log_write (CefC_Log_Error, "<Fail> cefnetd_config_read (fopen)\n");
		return (-1);
	}

	/* Reads and records written values in the cefnetd's config file. */
	while (fgets (buff, sizeof(buff)-1, fp) != NULL) {
		buff[sizeof(buff)-1] = 0;

		if (buff[0] == 0x23/* '#' */) {
			continue;
		}

		res = cefnetd_trim_line_string (buff, pname, ws);
		if (res < 0) {
			continue;
		}

		if (strcmp (pname, CefC_ParamName_PitSize) == 0) {
			res = atoi (ws);
			if (res < 1) {
				cef_log_write (CefC_Log_Error, "PIT_SIZE must be higher than 0.\n");
				return (-1);
			}
			if (res > 16777215) {	/* 16777216=2^24 */
				cef_log_write (CefC_Log_Error, "PIT_SIZE must be lower than 16777216.\n");
				return (-1);
			}
			hdl->pit_max_size = res;
		} else if (strcmp (pname, CefC_ParamName_FibSize) == 0) {
			res = atoi (ws);
			if (res < 1) {
				cef_log_write (CefC_Log_Error, "FIB_SIZE must be higher than 0.\n");
				return (-1);
			}
			if (res > 65535) {
				cef_log_write (CefC_Log_Error, "FIB_SIZE must be lower than 65536.\n");
				return (-1);
			}
			hdl->fib_max_size = (uint16_t) res;
		} else if (strcmp (pname, CefC_ParamName_Babel) == 0) {
			res = atoi (ws);
			if ((res != 0) && (res != 1)) {
				cef_log_write (CefC_Log_Error, "USE_CEFBABEL must be 0 or 1.\n");
				return (-1);
			}
			hdl->babel_use_f = res;
		} else if (strcmp (pname, CefC_ParamName_Babel_Route) == 0) {
			if (strcmp (ws, "udp") == 0) {
				hdl->babel_route = 0x02;
			} else if (strcmp (ws, "tcp") == 0) {
				hdl->babel_route = 0x01;
			} else if (strcmp (ws, "both") == 0) {
				hdl->babel_route = 0x03;
			} else {
				cef_log_write (CefC_Log_Error,
					"CEFBABEL_ROUTE must be tcp, udp or both\n");
				return (-1);
			}
		} else if (strcasecmp (pname, CefC_ParamName_Cs_Mode) == 0) {
			res = atoi (ws);
#ifndef CefC_CefnetdCache
			if (res == CefC_Cache_Type_Localcache){
				cef_log_write (CefC_Log_Error, "CS_MODE 1 is not supported.\n");
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine, "CS_MODE 1 is not supported.\n");
#endif // CefC_Debug
				return (-1);
			}
#endif  // CefC_CefnetdCache
#ifndef CefC_Csmgr
			if (res == CefC_Cache_Type_Excache){
				cef_log_write (CefC_Log_Error, "CS_MODE 2 is not supported.\n");
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine, "CS_MODE 2 is not supported.\n");
#endif // CefC_Debug
				return (-1);
			}
#endif  // CefC_Csmgr
#ifndef CefC_Conpub
			if (res == CefC_Cache_Type_ExConpub){
				cef_log_write (CefC_Log_Error, "CS_MODE 3 is not supported.\n");
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine, "CS_MODE 3 is not supported.\n");
#endif // CefC_Debug
				return (-1);
			}
#endif  // CefC_Conpub
			if (!(CefC_Cache_Type_None <= res && res <= CefC_Cache_Type_ExConpub)){
				cef_log_write (CefC_Log_Error, "CS_MODE must be 0/1/2/3\n");
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine, "CS_MODE must be 0/1/2/3\n");
#endif // CefC_Debug
				return (-1);
			}
			hdl->cs_mode = res;
		}
		else if (strcasecmp (pname, CefC_ParamName_Forwarding_Strategy) == 0) {
			int		in_len;

			in_len = strlen(ws);
			if (in_len >= CefC_FwdStrPlg_Max_NameLen) {
				cef_log_write (CefC_Log_Error,
								"FORWARDING_STRATEGY must be less than %d characters.\n", CefC_FwdStrPlg_Max_NameLen);
				return (-1);
			}
			hdl->forwarding_strategy = calloc(in_len + 1, sizeof(char));
			strcpy(hdl->forwarding_strategy ,ws);
		}

		else if (strcasecmp (pname, CefC_ParamName_CcninfoAccessPolicy) == 0) {
			res = atoi (ws);
			if (!(res == 0 || res == 1 || res == 2)) {
				cef_log_write (CefC_Log_Error, "CCNINFO_ACCESS_POLICY must be 0, 1 or 2.\n");
				return (-1);
			}
			hdl->ccninfo_access_policy = res;
		}
		else if (strcasecmp (pname, CefC_ParamName_CcninfoFullDiscovery) == 0) {
			res = atoi (ws);
			if (!(res == 0 || res == 1 || res == 2)) {
				cef_log_write (CefC_Log_Error, "CCNINFO_FULL_DISCOVERY must be 0, 1 or 2.\n");
				return (-1);
			}
			hdl->ccninfo_full_discovery =  res;
		}
		else if (strcasecmp (pname, CefC_ParamName_CcninfoValidAlg) == 0) {
			if (!(strcasecmp(ws, strNone) == 0
                || strcasecmp(ws, CefC_ValidTypeStr_CRC32C) == 0
                || strcasecmp(ws, CefC_ValidTypeStr_RSA256) == 0)) {
				cef_log_write (CefC_Log_Error, "CCNINFO_VALID_ALG must be None, %s or %s.\n",
                    CefC_ValidTypeStr_CRC32C, CefC_ValidTypeStr_RSA256);
				return (-1);
			}
			strcpy(hdl->ccninfo_valid_alg ,ws);
			hdl->ccninfo_valid_type = (uint16_t) cef_valid_type_get (hdl->ccninfo_valid_alg);
		}
		else if (strcasecmp (pname, CefC_ParamName_CcninfoSha256KeyPrfx) == 0) {
			strcpy(hdl->ccninfo_sha256_key_prfx ,ws);
		}
		else if (strcasecmp (pname, CefC_ParamName_CcninfoReplyTimeout) == 0) {
			res = atoi (ws);
			if (!(2 <= res && res <= 5)) {
				cef_log_write (CefC_Log_Error
				               , "CCNINFO_REPLY_TIMEOUT must be higher than or equal to 2 and lower than or equal to 5.\n");
				return (-1);
			}
			hdl->ccninfo_reply_timeout =  res;
		}

		else if (strcasecmp (pname, CefC_ParamName_Node_Name) == 0) {
			unsigned char	out_name[CefC_NAME_BUFSIZ];
			unsigned char	out_name_tlv[CefC_NAME_BUFSIZ];

			if ( CefC_NAME_MAXLEN < strlen(ws) ){
				cef_log_write (CefC_Log_Error,
					"NODE_NAME is too long (%d bytes), cefore does not support longer than %u bytes.\n",
						strlen(ws), CefC_NAME_MAXLEN);
				return( -1 );
			}

			/* CHeck NodeName */
			res = cefnetd_nodename_check( ws, out_name );
			if ( res <= 0 ) {
				/* Error */
				cef_log_write (CefC_Log_Error, "NODE_NAME contains characters that cannot be used.\n");
				return( -1 );
			} else {
				hdl->My_Node_Name = malloc( sizeof(char) * res + 1 );
				if (hdl->My_Node_Name == NULL){
					cefnetd_handle_destroy (hdl);
					cef_log_write (CefC_Log_Error, "%s My_Node_Name memory allocation failed (%s)\n"
									, __func__, strerror(errno));
					return( -1 );
				}
				strcpy( hdl->My_Node_Name, (char*)out_name );
				/* Convert Name TLV */
				strcpy( (char*)out_name, "ccnx:/" );
				strcat( (char*)out_name, hdl->My_Node_Name );
				res = cef_frame_conversion_uri_to_name ((char*)out_name, out_name_tlv);
				if ( res < 0 ) {
					/* Error */
					cef_log_write (CefC_Log_Error, "NODE_NAME contains characters that cannot be used.\n");
					return( -1 );
				} else if ( CefC_NAME_MAXLEN < res ){
					cef_log_write (CefC_Log_Error,
						"NODE_NAME is too long (%d bytes), cefore does not support T_NAMEs longer than %u bytes.\n",
							res, CefC_NAME_MAXLEN);
					return( -1 );
				} else {
					struct tlv_hdr name_tlv_hdr;
					name_tlv_hdr.type = htons (CefC_T_NAME);
					name_tlv_hdr.length = htons (res);
					hdl->My_Node_Name_TLV = (unsigned char*)malloc( res+CefC_S_TLF );
					if (hdl->My_Node_Name_TLV == NULL){
						cefnetd_handle_destroy (hdl);
						cef_log_write (CefC_Log_Error, "%s My_Node_Name_TLV memory allocation failed (%s)\n"
										, __func__, strerror(errno));
						return( -1 );
					}
					hdl->My_Node_Name_TLV_len = res + CefC_S_TLF;
					memcpy( &hdl->My_Node_Name_TLV[0], &name_tlv_hdr, sizeof(struct tlv_hdr) );
					memcpy( &hdl->My_Node_Name_TLV[CefC_S_TLF], out_name_tlv, res );
				}
			}
		}
		else if (strcasecmp (pname, CefC_ParamName_PitSize_App) == 0) {
			res = atoi(ws);
			if ( res < 1 ) {
				cef_log_write (CefC_Log_Error, "PIT_SIZE_APP must be higher than 0.\n");
				return (-1);
			}
			if (res > CefC_PitAppSize_MAX) {
				cef_log_write (CefC_Log_Error, "PIT_SIZE_APP must be lower than %d.\n", CefC_PitAppSize_MAX+1);
				return (-1);
			}
			hdl->app_pit_max_size = res;
		}
		else if (strcasecmp (pname, CefC_ParamName_FibSize_App) == 0) {
			res = atoi(ws);
			if ( res < 1 ) {
				cef_log_write (CefC_Log_Error, "FIB_SIZE_APP must be higher than 0.\n");
				return (-1);
			}
			if (res >= CefC_FibAppSize_MAX) {
				cef_log_write (CefC_Log_Error, "FIB_SIZE_APP must be lower than 1024000.\n");
				return (-1);
			}
			hdl->app_fib_max_size = res;
		}
		else if (strcasecmp (pname, CefC_ParamName_SELECTIVE_MAX) == 0) {
			res = atoi(ws);
			if ( res < CefC_SELECTIVE_MIN ) {
				cef_log_write (CefC_Log_Error, "SELECTIVE_INTEREST_MAX_RANGE must be higher than 0.\n");
				return (-1);
			}
			if (res > CefC_SELECTIVE_MAX) {
				cef_log_write (CefC_Log_Error, "SELECTIVE_INTEREST_MAX_RANGE must be lower than 2049.\n");
				return (-1);
			}
			hdl->Selective_max_range = res;
		}

		else if ( strcasecmp (pname, CefC_ParamName_InterestRetrans) == 0 ) {
			if ( strcasecmp( ws, CefC_Default_InterestRetrans ) == 0 ) {
				hdl->InterestRetrans = CefC_IntRetrans_Type_RFC;
			}
			else if ( strcasecmp( ws, "NO_SUPPRESSION" ) == 0 ) {
				hdl->InterestRetrans = CefC_IntRetrans_Type_NOSUP;
			}
			else {
				cef_log_write (CefC_Log_Error, "INTEREST_RETRANSMISSION must be RFC8569 or NO_SUPPRESSION.\n");
				return (-1);
			}
		}
		else if ( strcasecmp (pname, CefC_ParamName_SelectiveForward) == 0 ) {
			res = atoi(ws);
			if ( (res != 0) && (res != 1) ) {
				cef_log_write (CefC_Log_Error, "SELECTIVE_FORWARDING must be 0 or 1.\n");
				return (-1);
			}
			hdl->Selective_fwd = res;
		}
		else if ( strcasecmp (pname, CefC_ParamName_SymbolicBackBuff) == 0 ) {
			res = atoi(ws);
			if ( res < 0 ) {
				cef_log_write (CefC_Log_Error, "SYMBOLIC_BACKBUFFER must be higher than 0.\n");
				return (-1);
			}
			hdl->SymbolicBack = res;
		}
		else if ( strcasecmp (pname, CefC_ParamName_BANDWIDTH_INTVAL) == 0 ) {
			res = atoi(ws);
			if ( res < 0 ) {
				cef_log_write (CefC_Log_Error, "BANDWIDTH_STAT_INTERVAL must be higher than 0.\n");
				return (-1);
			}
			hdl->BW_Stat_interval = res;
		}
		else if ( strcasecmp (pname, CefC_ParamName_SYMBOLIC_LIFETIME) == 0 ) {
			res = atoi(ws);
			if ( res < 0 ) {
				cef_log_write (CefC_Log_Error, "SYMBOLIC_INTEREST_MAX_LIFETIME must be higher than 0.\n");
				return (-1);
			}
			hdl->Symbolic_max_lifetime = res * 1000;
		}
		else if ( strcasecmp (pname, CefC_ParamName_REGULAR_LIFETIME) == 0 ) {
			res = atoi(ws);
			if ( res < 0 ) {
				cef_log_write (CefC_Log_Error, "REGULAR_INTEREST_MAX_LIFETIME must be higher than 0.\n");
				return (-1);
			}
			hdl->Regular_max_lifetime = res * 1000;
		}
		else if ( strcasecmp (pname, CefC_ParamName_IR_Congestion) == 0 ) {
			res_dbl = atof( ws );
			if ( res_dbl <= 0.0 ) {
				cef_log_write (CefC_Log_Error
				               , "INTEREST_RETURN_CONGESTION_THRESHOLD must be higher than or equal to 0.\n");
				return (-1);
			}
			hdl->IR_Congestion = res_dbl;
		}
		else if ( strcasecmp (pname, CefC_ParamName_CSMGR_ACCESS) == 0 ) {
			if ( strcasecmp( ws, "RW" ) == 0 ) {
				hdl->Ex_Cache_Access = CefC_Default_CSMGR_ACCESS_RW;
			}
			else if ( strcasecmp( ws, "RO" ) == 0 ) {
				hdl->Ex_Cache_Access = CefC_Default_CSMGR_ACCESS_RO;
			}
			else {
				cef_log_write (CefC_Log_Error, "CSMGR_ACCESS must RW or RO.\n");
				return (-1);
			}
		}
		else if ( strcasecmp (pname, CefC_ParamName_BUFFER_CACHE_TIME) == 0 ) {
			res = atoi(ws);
			if ( res < 0 ) {
				cef_log_write (CefC_Log_Error, "BUFFER_CACHE_TIME be higher than or equal to 0.\n");
				return (-1);
			}
			hdl->Buffer_Cache_Time = res * 1000;
		}
		//202108
#ifdef	CefC_INTEREST_RETURN
		else if ( strcasecmp (pname, CefC_ParamName_IR_Option) == 0 ) {
			res = atoi(ws);
			if ( (res == 0 ) || (res == 1) ){

			} else {
				cef_log_write (CefC_Log_Error, "ENABLE_INTEREST_RETURN must 0 or 1.\n");
				return (-1);
			}
			hdl->IR_Option = res;
		}
		else if ( strcasecmp (pname, CefC_ParamName_IR_Enabled) == 0 ) {
			IR_enabled = 1;
			{
				char*	wk_p;
				int		wk_i;
				int		wk_len;
				int		ll;
				wk_p = strtok( ws, "," );
				wk_len = strlen(wk_p);
				for ( ll = 0; ll < wk_len; ll++ ) {
					if ( isdigit(wk_p[ll]) != 0 ) {
						/* digit */
					} else {
						cef_log_write (CefC_Log_Error, "ENABLED_RETURN_CODE is not a number.\n");
						return (-1);
					}
				}
				wk_i = strtol(wk_p, NULL, 10);
				if ((wk_i < 1) || (wk_i > 9)) {
					cef_log_write (CefC_Log_Error, "ENABLED_RETURN_CODE must 1 to 9.\n");
					return (-1);
				}
				hdl->IR_enable[wk_i] = 1;
				while( wk_p != NULL ) {
					wk_p = strtok( NULL, "," );
					if ( wk_p != NULL ) {
						wk_len = strlen(wk_p);
						for ( ll = 0; ll < wk_len; ll++ ) {
							if ( isdigit(wk_p[ll]) != 0 ) {
								/* digit */
							} else {
								cef_log_write (CefC_Log_Error, "ENABLED_RETURN_CODE is not a number.\n");
								return (-1);
							}
						}
						wk_i = strtol(wk_p, NULL, 10);
						if ((wk_i < 1) || (wk_i > 9)) {
							cef_log_write (CefC_Log_Error, "ENABLED_RETURN_CODE must 1 to 9.\n");
							return (-1);
						}
						hdl->IR_enable[wk_i] = 1;
					}
				}
			}
		}
#endif	//CefC_INTEREST_RETURN
#ifdef CefC_TxMultiThread
		else if (strcmp (pname, "TX_WORKER_NUM") == 0) {
			long num = strtol (ws, NULL, 10);
			if ( num < 1 || CefC_TxWorkerMax < num ){
				cef_log_write (CefC_Log_Error, "TX_WORKER_NUM must be lower than %d.\n", CefC_TxWorkerMax+1);
			}
			hdl->tx_worker_num = num;
		}
#endif // CefC_TxMultiThread
		else if (strcmp (pname, "TX_QUEUE_SIZE") == 0) {
			long num = strtol (ws, NULL, 10);
			if ( num < CefC_Tx_Que_Size ){
				cef_log_write (CefC_Log_Error, "TX_QUEUE_SIZE must be grater than %d.\n", CefC_Tx_Que_Size);
			}
			hdl->tx_que_size = num;
		}
		else if (strcmp (pname, "UDP_LISTEN_ADDR") == 0) {
			strncpy (hdl->udp_listen_addr, ws, sizeof(hdl->udp_listen_addr)-1);
		}
		else if (strcmp (pname, "FACE_LIFETIME") == 0) {
			hdl->face_lifetime = strtol (ws, NULL, 10) * 60;	/* minutes -> seconds */
		}
#ifdef CefC_Debug
		else if (strcmp (pname, "CEF_DEBUG_LEVEL") == 0) {
			int log_lv = 0;
			log_lv = atoi (ws);
			if (log_lv == CefC_Dbg_Finest) {
				cef_dbg_loglv_finest = 1;
			}
		}
#endif // CefC_Debug
		else {
			/* NOP */;
		}
	}
	fclose (fp);

	//202108
	if ( hdl->IR_Option ) {
		if ( IR_enabled == 0 ) {
			//Set default
			hdl->IR_enable[1] = 1;
			hdl->IR_enable[2] = 1;
			hdl->IR_enable[6] = 1;
		}
	}

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "PORT_NUM = %d\n", hdl->port_num);
	cef_dbg_write (CefC_Dbg_Fine, "PIT_SIZE = %d\n", hdl->pit_max_size);
	cef_dbg_write (CefC_Dbg_Fine, "FIB_SIZE = %d\n", hdl->fib_max_size);
	cef_dbg_write (CefC_Dbg_Fine, "PIT_SIZE_APP = %d\n", hdl->app_pit_max_size);
	cef_dbg_write (CefC_Dbg_Fine, "FIB_SIZE_APP = %d\n", hdl->app_fib_max_size);
	cef_dbg_write (CefC_Dbg_Fine, "FORWARDING_STRATEGY = %s\n", hdl->forwarding_strategy);
	cef_dbg_write (CefC_Dbg_Fine, "INTEREST_RETRANSMISSION = %s\n",
					(hdl->InterestRetrans == CefC_IntRetrans_Type_RFC) ? "RFC8569" : "NO_SUPPRESSION" );
	cef_dbg_write (CefC_Dbg_Fine, "SELECTIVE_FORWARDING    = %d\n", hdl->Selective_fwd);
	cef_dbg_write (CefC_Dbg_Fine, "SYMBOLIC_BACKBUFFER     = %d\n", hdl->SymbolicBack);
	cef_dbg_write (CefC_Dbg_Fine, "INTEREST_RETURN_CONGESTION_THRESHOLD = %f\n", hdl->IR_Congestion);
	cef_dbg_write (CefC_Dbg_Fine, "BANDWIDTH_STAT_INTERVAL = %d\n", hdl->BW_Stat_interval);
	cef_dbg_write (CefC_Dbg_Fine, "SYMBOLIC_INTEREST_MAX_LIFETIME = %d\n", hdl->Symbolic_max_lifetime);
	cef_dbg_write (CefC_Dbg_Fine, "REGULAR_INTEREST_MAX_LIFETIME = %d\n", hdl->Regular_max_lifetime);
	cef_dbg_write (CefC_Dbg_Fine, "CSMGR_ACCESS = %s\n",
					(hdl->Ex_Cache_Access == CefC_Default_CSMGR_ACCESS_RW) ? "RW" : "RO" );
	cef_dbg_write (CefC_Dbg_Fine, "BUFFER_CACHE_TIME    = %d\n", hdl->Buffer_Cache_Time);
	cef_dbg_write (CefC_Dbg_Fine, "ENABLE_INTEREST_RETURN = %d\n", hdl->IR_Option);
	cef_dbg_write (CefC_Dbg_Fine, "ENABLED_RETURN_CODE = %d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n", hdl->IR_enable[0],
																						   hdl->IR_enable[1],
																						   hdl->IR_enable[2],
																						   hdl->IR_enable[3],
																						   hdl->IR_enable[4],
																						   hdl->IR_enable[5],
																						   hdl->IR_enable[6],
																						   hdl->IR_enable[7],
																						   hdl->IR_enable[8],
																						   hdl->IR_enable[9] );
	cef_dbg_write (CefC_Dbg_Fine, "SELECTIVE_INTEREST_MAX_RANGE = %d\n", hdl->Selective_max_range);	//20220311

	cef_dbg_write (CefC_Dbg_Fine, "CCNINFO_ACCESS_POLICY = %d\n"
								, hdl->ccninfo_access_policy);
	cef_dbg_write (CefC_Dbg_Fine, "CCNINFO_FULL_DISCOVERY = %d\n"
								, hdl->ccninfo_full_discovery);
	cef_dbg_write (CefC_Dbg_Fine, "CCNINFO_VALID_ALG = %s (type=%u)\n"
								, hdl->ccninfo_valid_alg, hdl->ccninfo_valid_type);
	cef_dbg_write (CefC_Dbg_Fine, "CCNINFO_SHA256_KEY_PRFX = %s\n"
								, hdl->ccninfo_sha256_key_prfx);
	cef_dbg_write (CefC_Dbg_Fine, "CCNINFO_REPLY_TIMEOUT = %d\n"
								, hdl->ccninfo_reply_timeout);
#ifdef CefC_TxMultiThread
	cef_dbg_write (CefC_Dbg_Fine, "TX_WORKER_NUM = %d\n", hdl->tx_worker_num);
#endif // CefC_TxMultiThread
	cef_dbg_write (CefC_Dbg_Fine, "TX_QUEUE_SIZE = %d\n", hdl->tx_que_size);
	cef_dbg_write (CefC_Dbg_Fine, "UDP_LISTEN_ADDR = %s\n", hdl->udp_listen_addr);

	if ( hdl->My_Node_Name != NULL ) {
		cef_dbg_write (CefC_Dbg_Fine, "NODE_NAME = %s\n", hdl->My_Node_Name );
	}

#endif // CefC_Debug
	return (1);
}

static int
cefnetd_trim_line_string (
	const char* p1, 							/* target string for trimming 			*/
	char* p2,									/* name string after trimming			*/
	char* p3									/* value string after trimming			*/
) {
	char ws[CefC_BufSiz_1KB];
	char* wp = ws;
	char* rp = p2;
	int equal_f = -1;

	while (*p1) {
		if ((*p1 == 0x0D) || (*p1 == 0x0A)) {
			break;
		}

		if ((*p1 == 0x20) || (*p1 == 0x09)) {
			p1++;
			continue;
		} else {
			*wp = *p1;
		}

		p1++;
		wp++;
	}
	*wp = 0x00;
	wp = ws;

	while (*wp) {
		if (*wp == 0x3d /* '=' */) {
			if (equal_f > 0) {
				return (-1);
			}
			equal_f = 1;
			*rp = 0x00;
			rp = p3;
		} else {
			*rp = *wp;
			rp++;
		}
		wp++;
	}
	*rp = 0x00;

	return (equal_f);
}
/*--------------------------------------------------------------------------------------
	Creates the Command Filter(s)
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_command_filter_init (
	CefT_Netd_Handle* hdl					/* cefnetd handle							*/
) {

	unsigned char buff[256];
	int len;
	uint8_t hash;

	/* Sets filter for the Link Request Command 		*/
	len = cef_frame_link_req_cmd_get (buff);
	if ((len > 0) && (len < CefC_Cmd_Len_Max)) {
		hash = hdl->cefrt_seed;
		CEFRTHASH8(buff, hash, len);
		hdl->cmd_filter[hash] = CefC_Cmd_Link_Req;
		hdl->cmd_len[hash] = len;
		memcpy (&hdl->cmd[hash][0], buff, len);
	}

	/* Sets filter for the Link Response Command 		*/
	len = cef_frame_link_res_cmd_get (buff);
	if ((len > 0) && (len < CefC_Cmd_Len_Max)) {
		hash = hdl->cefrt_seed;
		CEFRTHASH8(buff, hash, len);
		hdl->cmd_filter[hash] = CefC_Cmd_Link_Res;
		hdl->cmd_len[hash] = len;
		memcpy (&hdl->cmd[hash][0], buff, len);
	}

	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles a command message
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_command_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	CefT_CcnMsg_MsgBdy* pm					/* Structure to set parsed CEFORE message	*/
) {

	uint8_t hash = hdl->cefrt_seed;

	CEFRTHASH8(pm->name, hash, pm->name_len);

	if ((hdl->cmd_filter[hash] < CefC_Cmd_Link_Req) ||
		(hdl->cmd_filter[hash] > CefC_Cmd_Link_Res)) {
		return (0);
	}

	if (hdl->cmd_len[hash] != pm->name_len) {
		return (0);
	} else {
		if (memcmp (&hdl->cmd[hash][0], pm->name, pm->name_len)) {
			return (0);
		}
	}

	/* Calls the function corresponding to the type of the command 	*/
	(*cefnetd_command_process[hdl->cmd_filter[hash]])(hdl, faceid, peer_faceid, pm);

	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the Invalid command
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_invalid_command_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	CefT_CcnMsg_MsgBdy* pm					/* Structure to set parsed CEFORE message	*/
) {
	/* Ignores the invalid command */
	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the Link Request command
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_link_req_command_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	CefT_CcnMsg_MsgBdy* pm					/* Structure to set parsed CEFORE message	*/
) {
	int msg_len;
	unsigned char buff[CefC_Max_Length];

	/* Creates and sends a Link Response message */
	memset (buff, 0, CefC_Max_Length);
	msg_len = cef_frame_object_link_msg_create (buff);

	if (msg_len > 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finer,
			"Send a Object Link message to Face#%d\n", peer_faceid);
#endif // CefC_Debug
		cefnetd_frame_send_txque (hdl, peer_faceid, buff, (size_t) msg_len);
	}

	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the Link Response command
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_link_res_command_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	CefT_CcnMsg_MsgBdy* pm					/* Structure to set parsed CEFORE message	*/
) {

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finer,
		"Receive a Object Link message from Face#%d\n", peer_faceid);
#endif // CefC_Debug

	return (1);
}
/*--------------------------------------------------------------------------------------
	Creates listening socket(s)
----------------------------------------------------------------------------------------*/
static void
cefnetd_create_udp_listener_from_ifaddrs(
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int	faceid
){
	char ip_str[INET6_ADDRSTRLEN] = {0,0,0,0};
	struct sockaddr_storage myaddr;
	struct ifaddrs *p, *ifaddrs = NULL;
	int listen_port_num = hdl->port_num;
	int ret = getifaddrs(&ifaddrs);

	if ( ret < 0 ){
		cef_log_write (CefC_Log_Warn, "[%s]getifaddrs()=%d, errno=%d:%s\n", __func__, ret, errno, strerror(errno));
		return;
	}

	for (p = ifaddrs; p != NULL; p = p->ifa_next){
		int   fd;
		int   optval = 1;
		size_t	sz_myaddr = 0;

		if ( !p->ifa_addr )
			continue;

		int   af_type = p->ifa_addr->sa_family;

		memset(&myaddr, 0x00, sizeof(myaddr));
		switch ( af_type ){
		case AF_INET:	// IPv4
			inet_ntop(af_type, &((struct sockaddr_in *)p->ifa_addr)->sin_addr,
				ip_str, INET_ADDRSTRLEN);
			memcpy(&myaddr, p->ifa_addr, sizeof(struct sockaddr_in));
			((struct sockaddr_in *)&myaddr)->sin_port = htons(listen_port_num);
			sz_myaddr = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:	// IPv6
			inet_ntop(af_type, &((struct sockaddr_in6 *)p->ifa_addr)->sin6_addr,
				ip_str, INET6_ADDRSTRLEN);
			memcpy(&myaddr, p->ifa_addr, sizeof(struct sockaddr_in6));
			((struct sockaddr_in6 *)&myaddr)->sin6_port = htons(listen_port_num);
			sz_myaddr = sizeof(struct sockaddr_in6);
			break;
		default:
			continue;
		}

		if ( CefC_Face_Reserved <= ++faceid ){
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "faceid=%d, exceeds CefC_Face_Reserved(%d).\n", faceid, CefC_Face_Reserved);
#endif // CefC_Debug
			break;
		}

		fd = socket (af_type, SOCK_DGRAM, IPPROTO_UDP);
		if ( fd < 0 ){
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Fine, "af=%d, socket error=%d:%s\n", af_type, errno, strerror(errno));
#endif // CefC_Debug
			continue;
		}

		if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const char *)&optval, sizeof(optval)) < 0){
			cef_dbg_write (CefC_Dbg_Fine, "setsockopt(SO_REUSEPORT) error=%d:%s\n", errno, strerror(errno));
			continue;
		}
		if (bind(fd, (struct sockaddr *)&myaddr, sz_myaddr) < 0){
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Fine, "%s, bind error=%d:%s\n", ip_str, errno, strerror(errno));
#endif // CefC_Debug
			close(fd);
			continue;
		}

		if ( cef_face_create_listener_from_ipaddrs(faceid,
				fd, af_type, &myaddr, ip_str, listen_port_num, CefC_Face_Type_Udp) != faceid ){
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Fine, "cef_face_create_listener_from_ipaddrs error=%d:%s\n", errno, strerror(errno));
#endif // CefC_Debug
			close(fd);
			continue;
		}

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finer, "faceid=%d, fd=%d, IP=%s, sin6_scope_id=%d\n", faceid, fd, ip_str, ((struct sockaddr_in6 *)&myaddr)->sin6_scope_id);
#endif // CefC_Debug

		hdl->inudpfaces[hdl->inudpfdc] = faceid;
		hdl->inudpfds[hdl->inudpfdc].fd = fd;
		hdl->inudpfds[hdl->inudpfdc].events = POLLIN | POLLERR;
		hdl->inudpfdc++;
	}
	freeifaddrs(ifaddrs);
}

static void
cefnetd_create_udp_listener_from_ipaddrs(
	CefT_Netd_Handle* hdl						/* cefnetd handle						*/
){
	int listen_port_num = hdl->port_num;
	int faceid = CefC_Faceid_ListenBabel + 1;

	if ( !strcasecmp(hdl->udp_listen_addr, "all") ){
		// Bind to the IP address obtained with getifaddrs
		cefnetd_create_udp_listener_from_ifaddrs(hdl, faceid);
	} else {
		static char delim[] = ", ;[]";
		char	*savptr, *token;
		char port_str[INET6_ADDRSTRLEN];

		sprintf(port_str, "%d", listen_port_num);

		for ( token = strtok_r(hdl->udp_listen_addr, delim, &savptr);
				token != NULL;
					token = strtok_r(NULL, delim, &savptr) ){
			struct addrinfo hints;
			struct addrinfo* res;
			struct addrinfo* cres;
			struct sockaddr_storage myaddr;
			size_t	sz_myaddr = 0;
			char ip_str[INET6_ADDRSTRLEN];
			int fd, ret;
			int optval = 1;
			int	af_type = AF_INET;

			strcpy(ip_str, token);
			memset(&myaddr, 0x00, sizeof(myaddr));
			memset (&hints, 0, sizeof (hints));
			hints.ai_family = AF_UNSPEC;
			hints.ai_flags = (AI_NUMERICHOST | AI_NUMERICSERV);
			hints.ai_socktype = SOCK_DGRAM;

			/* Use getaddrinfo to get the sin6_scope_id required to bind to an IPv6 link-local address. */
			if ((ret = getaddrinfo (ip_str, port_str, &hints, &res)) != 0) {
				cef_dbg_write (CefC_Dbg_Fine,
					"getaddrinfo(%s)=%s\n", ip_str, gai_strerror(ret));
				continue;
			}
			for (cres = res ; cres != NULL ; cres = cres->ai_next) {
				struct sockaddr_in *ai = (struct sockaddr_in *)(cres->ai_addr);
				struct sockaddr_in6 *ai6 = (struct sockaddr_in6 *)(cres->ai_addr);

				af_type = ai->sin_family;
				switch ( af_type ){
				case AF_INET:
					*((struct sockaddr_in *)&myaddr) = *ai;
					((struct sockaddr_in *)&myaddr)->sin_port = htons(listen_port_num);
					sz_myaddr = sizeof(struct sockaddr_in);
					break;
				case AF_INET6:
					*((struct sockaddr_in6 *)&myaddr) = *ai6;
					((struct sockaddr_in6 *)&myaddr)->sin6_port = htons(listen_port_num);
					sz_myaddr = sizeof(struct sockaddr_in6);
					break;
				default:
					continue;
				}
				break;
			}
			freeaddrinfo (res);
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "ip_str=%s, scope_id=%d\n",
	ip_str, ((struct sockaddr_in6 *)&myaddr)->sin6_scope_id);
#endif // CefC_Debug


			if ( CefC_Face_Reserved <= ++faceid ){
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Fine, "faceid=%d, exceeds CefC_Face_Reserved(%d).\n", faceid, CefC_Face_Reserved);
#endif // CefC_Debug
				break;
			}

			fd = socket (af_type, SOCK_DGRAM, IPPROTO_UDP);
			if ( fd < 0 ){
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Fine, "af=%d, socket error=%d:%s\n", af_type, errno, strerror(errno));
#endif // CefC_Debug
				continue;
			}

			if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const char *)&optval, sizeof(optval)) < 0){
				cef_dbg_write (CefC_Dbg_Fine, "setsockopt(SO_REUSEPORT) error=%d:%s\n", errno, strerror(errno));
				continue;
			}
			if (bind(fd, (struct sockaddr *)&myaddr, sz_myaddr) < 0){
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Fine, "af=%d, bind error=%d:%s\n", af_type, errno, strerror(errno));
#endif // CefC_Debug
				close(fd);
				continue;
			}

			if ( cef_face_create_listener_from_ipaddrs(faceid,
					fd, af_type, &myaddr, ip_str, listen_port_num, CefC_Face_Type_Udp) != faceid ){
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Fine, "cef_face_create_listener_from_ipaddrs error=%d:%s\n", errno, strerror(errno));
#endif // CefC_Debug
				close(fd);
				continue;
			}

#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "faceid=%d, fd=%d, IP=%s\n", faceid, fd, ip_str);
#endif // CefC_Debug

			hdl->inudpfaces[hdl->inudpfdc] = faceid;
			hdl->inudpfds[hdl->inudpfdc].fd = fd;
			hdl->inudpfds[hdl->inudpfdc].events = POLLIN | POLLERR;
			hdl->inudpfdc++;
		}
	}
}

static int									/* Returns a negative value if it fails 	*/
cefnetd_faces_init (
	CefT_Netd_Handle* hdl					/* cefnetd handle							*/
) {
	int res;
	int res_v4 = -1;
	int res_v6 = -1;

	/* Initialize the face module 		*/
	res = cef_face_init (hdl->node_type);
	if (res < 0) {
		cef_log_write (CefC_Log_Error, "Failed to init Face package.\n");
		return (-1);
	}

	/* Creates listening face 			*/
	res = cef_face_udp_listen_face_create (hdl->port_num, &res_v4, &res_v6);
	if (res < 0) {
		cef_log_write (CefC_Log_Error, "Failed to create the UDP listen socket.\n");
		return (-1);
	}
	/* Prepares file descriptors to listen 		*/
	if (res_v4 > 0) {
		hdl->inudpfaces[hdl->inudpfdc] = (uint16_t) res_v4;
		hdl->inudpfds[hdl->inudpfdc].fd = cef_face_get_fd_from_faceid ((uint16_t) res_v4);
		hdl->inudpfds[hdl->inudpfdc].events = POLLIN | POLLERR;
		hdl->inudpfdc++;
	}
	if (res_v6 > 0) {
		hdl->inudpfaces[hdl->inudpfdc] = (uint16_t) res_v6;
		hdl->inudpfds[hdl->inudpfdc].fd = cef_face_get_fd_from_faceid ((uint16_t) res_v6);
		hdl->inudpfds[hdl->inudpfdc].events = POLLIN | POLLERR;
		hdl->inudpfdc++;
	}

	res = cef_face_tcp_listen_face_create (hdl->port_num, &res_v4, &res_v6);
	if (res < 0) {
		cef_log_write (CefC_Log_Error, "Failed to create the TCP listen socket.\n");
		return (-1);
	}

	/* Creates the local face 			*/
	res = cef_face_local_face_create (hdl->sk_type);
	if (res < 0) {
		cef_log_write (CefC_Log_Error, "Failed to create the local listen socket.\n");
		return (-1);
	}

	/* Creates the local face for cefbabeld 	*/
	hdl->babel_sock = -1;
	hdl->babel_face = -1;

	if (hdl->babel_use_f) {
		res = cef_face_babel_face_create (hdl->sk_type);
		if (res < 0) {
			cef_log_write (CefC_Log_Error,
				"Failed to create the local listen socket for cefbabeld.\n");
			return (-1);
		}
		cef_log_write (CefC_Log_Info, "Initialization for cefbabeld ... OK\n");
	} else {
		cef_log_write (CefC_Log_Info, "Not use cefbabeld\n");
	}

	cefnetd_create_udp_listener_from_ipaddrs(hdl);

	return (1);
}
/*--------------------------------------------------------------------------------------
	Clean Face entries
----------------------------------------------------------------------------------------*/
static int
cefnetd_is_faceid_refer_in_fib (
	CefT_Netd_Handle* hdl, 						/* cefnetd handle						*/
	int faceid
) {
	CefT_App_Reg *entry;
	uint32_t index = 0;
	int		ret;

#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "faceid=%d\n", faceid);
#endif // CefC_Debug

	ret = cef_fib_faceid_search(hdl->fib, faceid);
	if ( CefC_Face_Reserved <= ret ){
		return ( -1 );		// refer in FIB
	}

	do {
		entry = (CefT_App_Reg *)cef_hash_tbl_item_check_from_index (hdl->app_reg, &index);
		if (entry){
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finest, "app_reg:index=%d, faceid=%d\n", index, entry->faceid);
#endif // CefC_Debug
			if (faceid == entry->faceid) {
				return ( -1 );		// refer in FIB(App)
			}
		}
		index++;
	} while (entry != NULL);

	return 0;	// faceid is not refer
}

static void
cefnetd_faces_cleanup (
	CefT_Netd_Handle* hdl, 						/* cefnetd handle						*/
	uint64_t nowt								/* current time (usec) 					*/
) {
	int faceid;

	if ( hdl->face_clean_t < nowt ){
		long	tv_thresh = (nowt / 1000000llu) - hdl->face_lifetime;

		for ( faceid = CefC_Face_Reserved; faceid < CefC_Face_Router_Max; faceid++ ){
			/* Gets the time when the face was latest referenced. */
			long	tv_sec = cef_face_get_reftime(faceid);

			if ( tv_sec <= 0 )
				continue;

			switch ( cef_face_type_get(faceid) ){
			case CefC_Face_Type_Local:			/* UnixDomain */
				continue;
			case CefC_Face_Type_Udp:			/* UDP */
				break;
			case CefC_Face_Type_Tcp:			/* TCP */
			default:
				if ( cef_face_check_active (faceid) )
					continue;
				break;
			}

			/* Close if not used for face_lifetime seconds */
			if ( tv_thresh <= tv_sec )
				continue;

			/* Do not close if referenced by FIB */
			if ( cefnetd_is_faceid_refer_in_fib(hdl, faceid) )
				continue;

#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finest, "cef_face_close(%d), tv_sec=%ld\n", faceid, tv_sec);
#endif // CefC_Debug
			cef_log_write (CefC_Log_Info, "[%s]cef_face_close(%d)\n", __func__, faceid);

			cef_face_close(faceid);
		}

		hdl->face_clean_t = nowt + 1000000 * 60;		/* Repeat every 60 seconds */
	}

	return;
}
/*--------------------------------------------------------------------------------------
	Closes faces
----------------------------------------------------------------------------------------*/
static int
cefnetd_faces_destroy (
	CefT_Netd_Handle* hdl						/* cefnetd handle						*/
) {
	/* Closes all faces 	*/
	cef_face_all_face_close ();
	return (1);
}
/*--------------------------------------------------------------------------------------
	Cleanups PIT entry which expires the lifetime
----------------------------------------------------------------------------------------*/
static void
cefnetd_pit_entry_clean (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_Pit_Entry* entry 					/* PIT entry 								*/
) {
	CefT_Down_Faces* dnface;
	CefT_Down_Faces* dnface_prv;
	CefT_Down_Faces* clean_dnface;
	uint64_t now;

	now = cef_client_present_timeus_get ();

#ifdef	__PIT_CLEAN__
cef_dbg_write (CefC_Dbg_Finer, "\t entry=%p, now="FMTU64", adv_lifetime_us="FMTU64", clean_us="FMTU64"\n",
 (void*)entry, now/1000, entry->adv_lifetime_us/1000, entry->clean_us/1000);
#endif
	if (now > entry->adv_lifetime_us) {
		clean_dnface = &(entry->clean_dnfaces);
		while (clean_dnface->next) {
			clean_dnface = clean_dnface->next;
		}

		dnface = &(entry->dnfaces);

		while (dnface->next) {
			dnface = dnface->next;
			clean_dnface->next = dnface;
			clean_dnface = dnface;
//			clean_dnface->next = NULL;	// 2023/04/04 by iD

			if (cef_face_check_active (dnface->faceid) > 0 && dnface->IR_msg) {
				cefnetd_frame_send_txque (hdl, dnface->faceid, dnface->IR_msg, dnface->IR_len);
			}
		}
		entry->dnfaces.next = NULL;
		entry->dnfacenum = 0;

		return;
	}

	if (now < entry->clean_us) {
#ifdef	__PIT_CLEAN__
cef_dbg_write (CefC_Dbg_Finer, "\t(now < entry->clean_us) RETURN\n" );
#endif
		return;
	}
	entry->clean_us = now + CefC_Pit_CleaningTime;

	dnface = &(entry->dnfaces);
	dnface_prv = dnface;

	while (dnface->next) {
		dnface = dnface->next;

		if (now > dnface->lifetime_us) {
			dnface_prv->next = dnface->next;
			clean_dnface = &(entry->clean_dnfaces);
			while (clean_dnface->next) {
				clean_dnface = clean_dnface->next;
			}
			clean_dnface->next = dnface;
			clean_dnface->next->next = NULL;
			dnface = dnface_prv;
			entry->dnfacenum--;

			if (cef_face_check_active (dnface->faceid) > 0 && dnface->IR_msg) {
#ifdef	__PIT_CLEAN__
cef_dbg_write (CefC_Dbg_Finer, "\t Send IR\n" );
#endif
				cefnetd_frame_send_txque (hdl, dnface->faceid, dnface->IR_msg, dnface->IR_len);
			}
		} else {
			dnface_prv = dnface;
		}
	}
#ifdef	__PIT_CLEAN__
cef_dbg_write (CefC_Dbg_Finer, "\t After while RETURN entry->dnfacenum:%d\n", entry->dnfacenum );
#endif

	return;
}
/*--------------------------------------------------------------------------------------
	Clean PIT entries
----------------------------------------------------------------------------------------*/
static void
cefnetd_pit_cleanup (
	CefT_Netd_Handle* hdl, 						/* cefnetd handle						*/
	uint64_t nowt								/* current time (usec) 					*/
) {
	CefT_Pit_Entry* pe;
	CefT_Down_Faces* face;
	int idx;
	int clean_num = 0;
	int rec_index = 0;
	int end_index;
	int end_flag = 0;

	if ( nowt < hdl->pit_clean_t )
		return;

	int pit_num = cef_lhash_tbl_item_num_get(hdl->pit);
	end_index = hdl->pit_clean_i;

#ifdef	__PIT_CLEAN__
	if (pit_num > 0) {
		fprintf(stderr, "[%s] pit_num=%d, end_index=%d\n", __func__, pit_num, end_index);
	}
#endif

	for (end_flag = clean_num = 0; clean_num < pit_num; ) {
		uint32_t elem_num, elem_index, eidx;

		pe = (CefT_Pit_Entry*) cef_lhash_tbl_elem_get (hdl->pit, &(hdl->pit_clean_i), &elem_num);

		if (hdl->pit_clean_i == end_index) {
			end_flag++;
			if (end_flag > 1) {
				break;
			}
		}
		rec_index = hdl->pit_clean_i;
		hdl->pit_clean_i++;

		if (pe == NULL) {
			break;
		}
#ifdef	__PIT_CLEAN__
fprintf( stderr, "[%s] elem_get rec_index=%d, elm_num=%d\n", __func__, rec_index, elem_num);
#endif

		for (eidx = 0, elem_index = 0; elem_index < elem_num; elem_index++) {
			pe = (CefT_Pit_Entry*)
					cef_lhash_tbl_item_get_from_index (hdl->pit, rec_index, eidx);

			if (!pe || !cef_pit_entry_lock(pe) ){
				eidx++;
				continue;
			}

			clean_num++;
			cefnetd_pit_entry_clean (hdl, hdl->pit, pe);

			/* Indicates that a PIT entry was deleted to Transport  	*/
			if (hdl->plugin_hdl.tp[pe->tp_variant].pit) {
				CefT_Rx_Elem_Sig_DelPit sig_delpit;

				memset(&sig_delpit, 0x00, sizeof(sig_delpit));

				/* Records PIT entries ware deleted  	*/
				face = &(pe->clean_dnfaces);
				idx = 0;

				while (face->next) {
					face = face->next;
					sig_delpit.faceids[idx] = face->faceid;
					idx++;
				}

				if (idx > 0) {

					sig_delpit.faceid_num = idx;
					sig_delpit.hashv = pe->hashv;

					(*(hdl->plugin_hdl.tp)[pe->tp_variant].pit)(
						&(hdl->plugin_hdl.tp[pe->tp_variant]), &sig_delpit);
				}
			}

			if (pe->drp_lifetime_us < nowt) {	// 2023/04/05 by iD
#ifdef	__PIT_CLEAN__
fprintf( stderr, "[%s] cef_pit_entry_free()\n", __func__ );
#endif
#ifdef	CefC_Debug
cef_dbg_write (CefC_Dbg_Finest, "now_t="FMTU64" , pe->drp_lifetime_us= "FMTU64"\n", nowt, pe->drp_lifetime_us );
#endif // CefC_Debug

				cef_pit_entry_free (hdl->pit, pe);

			} else {
				cef_pit_entry_unlock(pe);
				eidx++;
			}
		}
	}

	pit_num = cef_lhash_tbl_item_num_get(hdl->app_pit);
	end_index = hdl->app_pit_clean_i;

#ifdef	CefC_Debug
	if (pit_num > 0) {
		cef_dbg_write (CefC_Dbg_Finest, "app_pit_num=%d, end_index=%d\n", pit_num, end_index);
	}
#endif

	for (end_flag = clean_num = 0; clean_num < pit_num; ) {
		uint32_t elem_num, elem_index, eidx;

		pe = (CefT_Pit_Entry*) cef_lhash_tbl_elem_get (hdl->app_pit, &(hdl->app_pit_clean_i), &elem_num);

		if (hdl->app_pit_clean_i == end_index) {
			end_flag++;
			if (end_flag > 1) {
				break;
			}
		}
		rec_index = hdl->app_pit_clean_i;
		hdl->app_pit_clean_i++;

		if (pe == NULL) {
			break;
		}
#ifdef	__PIT_CLEAN__
fprintf( stderr, "[%s:%d] elem_get end_index=%d, rec_index=%d, elem_num=%d\n", __func__, __LINE__,
	end_index, rec_index, elem_num);
#endif

		for (eidx = 0, elem_index = 0; elem_index < elem_num; elem_index++) {
			pe = (CefT_Pit_Entry*)
					cef_lhash_tbl_item_get_from_index (hdl->app_pit, rec_index, eidx);

			if (!pe || !cef_pit_entry_lock(pe) ){
#ifdef	CefC_Debug
cef_dbg_write (CefC_Dbg_Fine, "pe=%p, lock failure.\n", pe);
#endif // CefC_Debug
				eidx++;
				continue;
			}

			clean_num++;
			cefnetd_pit_entry_clean (hdl, hdl->app_pit, pe);

			if (pe->drp_lifetime_us < nowt) {	// 2023/04/05 by iD
#ifdef	CefC_Debug
cef_dbg_write (CefC_Dbg_Finest, "now_t="FMTU64" , pe->drp_lifetime_us= "FMTU64"\n", nowt, pe->drp_lifetime_us );
#endif // CefC_Debug

				cef_pit_entry_free (hdl->app_pit, pe);

			} else {
				cef_pit_entry_unlock(pe);
				eidx++;
			}
		}
	}

	hdl->pit_clean_t = nowt + CefC_Pit_CleaningTime;

	cef_log_flush ();

	return;
}
/*--------------------------------------------------------------------------------------
	Obtains my NodeID (IP Address)
----------------------------------------------------------------------------------------*/
static void
cefnetd_node_id_get (
	CefT_Netd_Handle* hdl						/* cefnetd handle						*/
) {
	struct ifaddrs *ifa_list;
	struct ifaddrs *ifa;
	int n;
	int mtu;


	n = getifaddrs (&ifa_list);
	if (n < 0) {
		cef_log_write (CefC_Log_Warn, "[%s]getifaddrs()=%d, errno=%d:%s\n", __func__, n, errno, strerror(errno));
		return;
	}

	hdl->nodeid4_num 	= 0;
	hdl->nodeid16_num 	= 0;
	hdl->lo_mtu 		= 65536;

	for(ifa = ifa_list ; ifa != NULL ; ifa=ifa->ifa_next) {

		if (ifa->ifa_addr == NULL) {
			continue;
		}

		if (ifa->ifa_addr->sa_family == AF_INET) {
			if (ifa->ifa_flags & IFF_LOOPBACK) {
				continue;
			}
			hdl->nodeid4_num++;
		} else if (ifa->ifa_addr->sa_family == AF_INET6) {
			if (ifa->ifa_flags & IFF_LOOPBACK) {
				continue;
			}
			hdl->nodeid16_num++;
		} else {
			/* NOP */;
		}
	}
	hdl->nodeid4 =
		(unsigned char**) calloc (hdl->nodeid4_num, sizeof (unsigned char*));
	hdl->nodeid4_mtu =
		(unsigned int**) calloc (hdl->nodeid4_num, sizeof (unsigned int*));
	hdl->nodeid4_c =
		(char**) calloc (hdl->nodeid4_num, sizeof (char*));

	for (n = 0 ; n < hdl->nodeid4_num ; n++) {
		hdl->nodeid4[n] = (unsigned char*) calloc (4, 1);
		hdl->nodeid4_mtu[n] = (unsigned int*) calloc (sizeof (unsigned int), 1);
		hdl->nodeid4_c[n] = (char*) calloc (NI_MAXHOST, 1);
	}

	hdl->nodeid16 =
		(unsigned char**) calloc (hdl->nodeid16_num, sizeof (unsigned char*));
	hdl->nodeid16_mtu =
		(unsigned int**) calloc (hdl->nodeid16_num, sizeof (unsigned int*));
	hdl->nodeid16_c =
		(char**) calloc (hdl->nodeid16_num, sizeof (char*));
	for (n = 0 ; n < hdl->nodeid16_num ; n++) {
		hdl->nodeid16[n] = (unsigned char*) calloc (16, 1);
		hdl->nodeid16_mtu[n] = (unsigned int*) calloc (sizeof (unsigned int), 1);
		hdl->nodeid16_c[n] = (char*) calloc (NI_MAXHOST, 1);
	}

	hdl->nodeid4_num 	= 0;
	hdl->nodeid16_num 	= 0;

	for (ifa = ifa_list ; ifa != NULL ; ifa=ifa->ifa_next) {

		if (ifa->ifa_addr == NULL) {
			continue;
		}
		{ /* Get MTU */
			int fd;
			struct ifreq ifr;

			fd = socket(AF_INET, SOCK_DGRAM, 0);
			if(fd == -1) {
				return;
			}
			strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ-1);
			if (ioctl(fd, SIOCGIFMTU, &ifr) != 0) {
				return;
			}
			close(fd);
			mtu = ifr.ifr_mtu;
		}

		if (ifa->ifa_addr->sa_family == AF_INET) {
			if (ifa->ifa_flags & IFF_LOOPBACK) {
				if (hdl->lo_mtu > mtu){
					hdl->lo_mtu = mtu;
				}
				continue;
			}
			memcpy (&hdl->nodeid4[hdl->nodeid4_num][0],
				&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, 4);
			*(hdl->nodeid4_mtu[hdl->nodeid4_num]) = mtu;
			inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, hdl->nodeid4_c[hdl->nodeid4_num], NI_MAXHOST);
			hdl->nodeid4_num++;
		} else if (ifa->ifa_addr->sa_family == AF_INET6) {
			if (ifa->ifa_flags & IFF_LOOPBACK) {
				if (hdl->lo_mtu > mtu){
					hdl->lo_mtu = mtu;
				}
				continue;
			}
			memcpy (&hdl->nodeid16[hdl->nodeid16_num][0],
				&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, 16);
			*(hdl->nodeid16_mtu[hdl->nodeid16_num]) = mtu;
			inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, hdl->nodeid16_c[hdl->nodeid16_num], NI_MAXHOST);
			hdl->nodeid16_num++;
		} else {
			/* NOP */;
		}
	}
	freeifaddrs (ifa_list);

	if (hdl->nodeid4_num > 0) {
		memcpy (hdl->top_nodeid, hdl->nodeid4[0], 4);
		hdl->top_nodeid_len = 4;
		hdl->top_nodeid_mtu = *(hdl->nodeid4_mtu[0]);
	} else if (hdl->nodeid16_num > 0) {
		memcpy (hdl->top_nodeid, hdl->nodeid16[0], 16);
		hdl->top_nodeid_len = 16;
		hdl->top_nodeid_mtu = *(hdl->nodeid16_mtu[0]);
	} else {
		hdl->top_nodeid[0] = 0x7F;
		hdl->top_nodeid[1] = 0x00;
		hdl->top_nodeid[2] = 0x00;
		hdl->top_nodeid[3] = 0x01;
		hdl->top_nodeid_len = 4;
		hdl->top_nodeid_mtu = hdl->lo_mtu;
	}


	return;
}

/*--------------------------------------------------------------------------------------
	Obtains my NodeID (IP Address)
----------------------------------------------------------------------------------------*/
static int
cefnetd_matched_node_id_get (
	CefT_Netd_Handle* hdl,
	unsigned char* peer_node_id,
	int peer_node_id_len,
	unsigned char* node_id,
	unsigned int* responder_mtu
) {
	int i, n;
	int find_f = 0;

	if (peer_node_id_len == 16) {
		for (n = 15 ; n > 0 ; n--) {
			for (i = 0 ; i < hdl->nodeid16_num ; i++) {
				if (memcmp (&hdl->nodeid16[i][0], peer_node_id, n) == 0) {
					find_f = 1;
					break;
				}
			}
			if (find_f) {
				memcpy (node_id, &hdl->nodeid16[i][0], 16);
				*responder_mtu = *(hdl->nodeid16_mtu[i]);
				return (16);
			}
		}
	} else if (peer_node_id_len == 4) {
		for (n = 4 ; n > 0 ; n--) {
			for (i = 0 ; i < hdl->nodeid4_num ; i++) {
				if (memcmp (&hdl->nodeid4[i][0], peer_node_id, n) == 0) {
					find_f = 1;
					break;
				}
			}
			if (find_f) {
				memcpy (node_id, &hdl->nodeid4[i][0], 4);
				*responder_mtu = *(hdl->nodeid4_mtu[i]);
				return (4);
			}
		}
	}
	node_id[0] = 0x7F;
	node_id[1] = 0x00;
	node_id[2] = 0x00;
	node_id[3] = 0x01;

	return (4);
}

#if CefC_IsEnable_ContentStore
/*--------------------------------------------------------------------------------------
	cefnetd cached Object process
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_cefcache_object_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	unsigned char* msg 						/* received message to handle				*/
){
	struct fixed_hdr* chp;
	uint16_t pkt_len = 0;
	uint16_t hdr_len = 0;
	uint16_t payload_len = 0;
	uint16_t header_len = 0;
	CefT_CcnMsg_MsgBdy pm = { 0 };
	CefT_CcnMsg_OptHdr poh = { 0 };
	CefT_Pit_Entry* pe = NULL;
	int i, res;
	uint8_t faceid_bitmap[CefC_Face_Router_Max];
	uint16_t faceids[CefC_Fib_UpFace_Max];
	uint16_t face_num = 0;
	CefT_Down_Faces* face = NULL;
	CefT_Rx_Elem elem;
	int tp_plugin_res = CefC_Pi_All_Permission;
	CefT_Hash_Handle pit_handle = hdl->pit;

	cefnetd_faceidmap_init(faceid_bitmap, sizeof(faceid_bitmap));

	chp = (struct fixed_hdr*) msg;
	pkt_len = ntohs (chp->pkt_len);
	hdr_len = chp->hdr_len;
	payload_len = pkt_len - hdr_len;
	header_len 	= hdr_len;

#ifdef	__SYMBOLIC__
	fprintf( stderr, "[%s] IN Msg (%d bytes) \n", __func__, payload_len + header_len );
#endif

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finer,
		"Process the Content Object (%d bytes) from cefnetd cache\n", payload_len + header_len);
	cef_dbg_buff_write (CefC_Dbg_Finest, msg, payload_len + header_len);
#endif // CefC_Debug
	/*--------------------------------------------------------------------
		Parses the Object message
	----------------------------------------------------------------------*/
	if (payload_len + header_len > CefC_Max_Msg_Size) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finer, "Content Object is too large\n");
#endif // CefC_Debug
		return (-1);
	}
	res = cef_frame_message_parse (
					msg, payload_len, header_len, &poh, &pm, CefC_PT_OBJECT);
	if (res < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finer,
			"Detects the invalid Content Object from localcache.\n");
#endif // CefC_Debug
		return (-1);
	}
	/*--------------------------------------------------------------------
		Searches a PIT entry matching this Object
	----------------------------------------------------------------------*/

	/**** 1st. app_pit ****/

	/* Search the PIT of the registered application with OPT_APP_PIT_REG */
	pit_handle = hdl->app_pit;
	pe = NULL;

	if ( pe == NULL ){
		CefT_Pit_Entry* pe_smi = NULL;

		pit_handle = hdl->pit;
		pe_smi = cef_pit_entry_search_symbolic (pit_handle, &pm, &poh);
		/**** 2nd. symbolic pit ****/
		if ( pe_smi && pe_smi->PitType != CefC_PIT_TYPE_Rgl ){
			if ( pm.chunk_num < (pe_smi->Last_chunk_num - hdl->SymbolicBack) ) {
				cef_dbg_write (CefC_Dbg_Fine, "SymbolicBack drop, chunk_num=%u\n", pm.chunk_num);
				pe_smi = NULL;		// stat_nopit_frames++
			} else if ( pe_smi->Last_chunk_num < pm.chunk_num ) {
				pe_smi->Last_chunk_num = pm.chunk_num;
			}
			if ( pe_smi ){
				for ( face = &(pe_smi->dnfaces); face->next; ) {
					face = face->next;
					if ( !cefnetd_faceidmap_is_set(faceid_bitmap, face->faceid) ){
						cefnetd_faceidmap_set(faceid_bitmap, face->faceid);
						faceids[face_num++] = face->faceid;
					}
				}
			}
		}
		/**** 3rd. reguler pit ****/
		pe = cef_pit_entry_search_with_chunk (pit_handle, &pm, &poh);
		if ( pe == NULL ){
			pe = pe_smi;
		}
	}

	/* COB without chunk number matches only Reg-PIT */
	if ( pm.chunk_num_f == 0 && pe && pe->PitType != CefC_PIT_TYPE_Rgl ) {
		cef_dbg_write (CefC_Dbg_Fine, "PitType Unmatch\n");
		pe = NULL;		// stat_nopit_frames++
	}

	if ( pe ) {
		//0.8.3
		if ( pe->COBHR_len > 0 ) {
			/* CobHash */
			uint16_t		CobHash_index;
			uint16_t		CobHash_len;
			unsigned char 	hash[SHA256_DIGEST_LENGTH];

			CobHash_index = header_len;
			CobHash_len   = payload_len;
			cef_valid_sha256( &msg[CobHash_index], CobHash_len, hash );	/* for OpenSSL 3.x */

			if ( memcmp(pe->COBHR_selector, hash, pe->COBHR_len) == 0 ) {
				/* OK */
			} else {
				/* NG */
				cef_log_write (CefC_Log_Info, "Dropped due to ObjectHash restrictions.\n");
				return (-1);
			}
		}
		if ( pe->KIDR_len > 0 ) {
			/* KeyIdRest */
			int keyid_len;
			unsigned char keyid_buff[CefC_KeyIdSiz];
			keyid_len = cefnetd_keyid_get( msg, pkt_len, keyid_buff );
			if ( (keyid_len == CefC_KeyIdSiz) && (memcmp(pe->KIDR_selector, keyid_buff, CefC_KeyIdSiz) == 0) ) {
				/* OK */
			} else {
				/* NG */
				cef_log_write (CefC_Log_Info, "Dropped due to KeyId restrictions.\n");
				return (-1);
			}
		}

		for (face = &(pe->dnfaces); face->next;) {
			face = face->next;
			if ( !cefnetd_faceidmap_is_set(faceid_bitmap, face->faceid) ){
				cefnetd_faceidmap_set(faceid_bitmap, face->faceid);
				faceids[face_num++] = face->faceid;
			}
		}
	} else {
		stat_nopit_frames++;
#ifdef CefC_Debug
{		char uri[CefC_NAME_BUFSIZ];
		cefnetd_name_to_uri (&pm, uri, sizeof(uri));
		cef_dbg_write (CefC_Dbg_Finer, "NOPIT:stat_nopit_frames=%u, %s\n", stat_nopit_frames, uri);
}
#endif // CefC_Debug
	}

	/*--------------------------------------------------------------------
		Transport Plugin
	----------------------------------------------------------------------*/
	if ((poh.org.tp_variant > CefC_T_OPT_TP_NONE)
	&&	(hdl->plugin_hdl.tp[poh.org.tp_variant].cob_from_cs)
	) {
		CefT_Pit_Entry* tmpe = cef_pit_entry_search_symbolic (hdl->pit, &pm, &poh);
		uint32_t contents_hashv = 0;	/* Hash value of this contents (without chunk number) */
		if ( tmpe ){
			contents_hashv = tmpe->hashv;	/* Hash value of this contents */
		} else {
			contents_hashv = 0;				/* Hash value of this contents */
		}

		/* Creates CefT_Rx_Elem 		*/
		memset (&elem, 0, sizeof (CefT_Rx_Elem));
		elem.plugin_variant 	= poh.org.tp_variant;
		elem.type 				= CefC_Elem_Type_Object;
		elem.hashv 				= contents_hashv;
		elem.in_faceid 			= 0;		/* local cache */
		elem.parsed_msg 		= &pm;
		memcpy (&(elem.msg[0]), msg, payload_len + header_len);
		elem.msg_len 			= payload_len + header_len;
		elem.out_faceid_num 	= face_num;

		for (i = 0 ; i < face_num ; i++) {
			elem.out_faceids[i] = faceids[i];
		}

		elem.parsed_oph 		= &poh;
		memcpy (elem.ophdr, poh.org.tp_val, poh.org.tp_len);
		elem.ophdr_len = poh.org.tp_len;

		/* Callback 		*/
		tp_plugin_res = (*(hdl->plugin_hdl.tp)[poh.org.tp_variant].cob_from_cs)(
			&(hdl->plugin_hdl.tp[poh.org.tp_variant]), &elem
		);
	}

	/*--------------------------------------------------------------------
		Forwards the Content Object
	----------------------------------------------------------------------*/
	if (tp_plugin_res & CefC_Pi_Object_Send) {
		if (face_num > 0) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finer, "Forward the Content Object to cefnetd(s)\n");
#endif // CefC_Debug
			cefnetd_object_forward (hdl, faceids, face_num, msg,
				payload_len, header_len, &pm, &poh, pe);

			if (pe->stole_f) {
				if (cef_pit_entry_lock(pe))					// 2023/04/19 by iD
					cef_pit_entry_free (pit_handle, pe);
			}
		}
	}

	return (1);
}
#endif //CefC_IsEnable_ContentStore


/* NodeName Check */
static int									/* 0:OK -1:Error */
cefnetd_nodename_check (
	const char* in_name,					/* input NodeName							*/
	unsigned char* ot_name					/* buffer to set After Check NodeName		*/
) {
	unsigned char chk_name[CefC_NAME_BUFSIZ];
	int		in_len;
	int		i;
	char*	ot_p;
	char*	chk_p;

	in_len = strlen(in_name);
	if ( CefC_NAME_MAXLEN < in_len ){
		cef_log_write (CefC_Log_Error,
			"NODE_NAME is too long (%d bytes), cefore does not support T_NAMEs longer than %u bytes.\n",
				in_len, CefC_NAME_MAXLEN);
		return( -1 );
	}
	memset( chk_name, 0x00, CefC_NAME_BUFSIZ );
	memcpy( chk_name, in_name, in_len );

	ot_p = (char*)ot_name;
	chk_p = (char*)chk_name;

	if ( strncmp( (char*)chk_name, "http://", 7 ) == 0 ) {
		chk_p += 7;
		strcpy( ot_p, chk_p );
		return( strlen(ot_p) );
	}

	for ( i = 0; i < in_len; i++ ) {
		if ( *chk_p == '/' ) {
			chk_p++;
		} else {
			break;
		}
	}

	strcpy( ot_p, chk_p );

	return( strlen(ot_p) );
}

static	int
cefnetd_ccninfo_loop_check(
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	CefT_Parsed_Ccninfo* pci
) {

	CefT_Request_RptBlk*	rpt_p;		/* Report block */
	int					rpt_idx;
	unsigned char		chk_node_name[CefC_BufSiz_1KB];

#ifdef	DEB_CCNINFO
	fprintf( stderr, "%s Entry\n", "cefnetd_ccninfo_loop_check()" );
	fprintf( stderr, "\t pci->rpt_blk_num=%d \n", pci->rpt_blk_num );
#endif

	if ( pci->rpt_blk_num == 0 ) {
		return( 0 );
	}

	rpt_p = pci->rpt_blk;
	for ( rpt_idx = 0; rpt_idx < pci->rpt_blk_num; rpt_idx++ ) {
		memset( chk_node_name, 0x00, sizeof(chk_node_name) );
		memcpy( chk_node_name, &rpt_p->node_id[0], rpt_p->id_len);
		if ( memcmp( chk_node_name, hdl->My_Node_Name_TLV, hdl->My_Node_Name_TLV_len ) == 0 ) {
			/* Detect Loop */
#ifdef	DEB_CCNINFO
			fprintf( stderr, "\t Detect Loop pci->rpt_blk_num=%d \n", pci->rpt_blk_num );
#endif
			return( -1 );
		}
		rpt_p = rpt_p->next;
	}

	return( 0 );
}

static int
cefnetd_ccninfo_name_create(
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	CefT_Parsed_Ccninfo* pci,
	unsigned char* ccninfo_name,
	int		req_or_rep,
	int		skip_option
) {


	int	wp = 0;
	unsigned char	tmp_buff[CefC_Ccninfo_NameSize*2];
	CefT_Request_RptBlk*	rpt_p;		/* Report block */
	int					rpt_idx;
	int					find_my_node = 0;
	int					top_node = 0;
	int					is_skip = 0;

	memset( tmp_buff, 0x00, sizeof(tmp_buff) );


#ifdef	DEB_CCNINFO
	fprintf( stderr, "%s Entry\n", "cefnetd_ccninfo_name_create()" );
#endif
	rpt_p = pci->rpt_blk;

	if ( pci->rpt_blk_num == 0 ) {
#ifdef	DEB_CCNINFO
		fprintf( stderr, "\t pci->rpt_blk_num=%d SKIP_CONCAT\n", pci->rpt_blk_num );
#endif
		goto SKIP_CONCAT;
	}

	if ( pci->id_len == rpt_p->id_len ) {
		if ( memcmp(&pci->node_id[0], &rpt_p->node_id[0], pci->id_len) == 0 ) {
			/* Req eq Top. NoSkip */
		} else {
			is_skip = 1;
		}
	} else {
		is_skip = 1;
	}

	find_my_node = 0;
	for ( rpt_idx = 0; rpt_idx < pci->rpt_blk_num; rpt_idx++ ) {
		if ( memcmp( &rpt_p->node_id[0], hdl->My_Node_Name_TLV, hdl->My_Node_Name_TLV_len ) == 0 ) {
			find_my_node = 1;
			if ( rpt_idx == 0 ) {
				top_node = 1;
			}
		}
		rpt_p = rpt_p->next;
	}

	if ( (req_or_rep == CCNINFO_REP) && (find_my_node != 1) ) {
#ifdef	DEB_CCNINFO
		fprintf( stderr, "\t Reply NotFound MyNode SKIP_CONCAT\n" );
#endif
		goto SKIP_CONCAT;
	}

	if ( req_or_rep == CCNINFO_REP ) {
		if ( pci->ret_code == 0x00 ) {
			/* Normal */
		} else if ( pci->ret_code >= 0x80 ) {
			if ( is_skip == 0 ) {
				/* Normal */
			} else {
				if ( top_node == 1 ) {
					/* Normal */
				} else {
					if ( skip_option == 1 ) {
						/* Special */
#ifdef	DEB_CCNINFO
						fprintf( stderr, "\t 0x80 Special-1 SKIP_CONCAT\n" );
#endif
						goto SKIP_CONCAT;
					}
				}
			}
		}
	}

	rpt_p = pci->rpt_blk;

#ifdef	DEB_CCNINFO
	fprintf( stderr, "\t 000 pci->rpt_blk_num=%d\n", pci->rpt_blk_num );
#endif
	for ( rpt_idx = 0; rpt_idx < pci->rpt_blk_num; rpt_idx++ ) {
#ifdef	DEB_CCNINFO
		fprintf( stderr, "\t 000-1 rpt_idx=%d\n", rpt_idx );
#endif
		if ( req_or_rep == CCNINFO_REP ) {
			/* Reply */
			if ( memcmp( &rpt_p->node_id[0], hdl->My_Node_Name_TLV, hdl->My_Node_Name_TLV_len ) == 0 ) {
#ifdef	DEB_CCNINFO
				fprintf( stderr, "\t 000-2 Break\n" );
#endif
				break;
			}
		}

		memcpy( &tmp_buff[wp], &rpt_p->node_id[0], rpt_p->id_len );
		if ( sizeof(tmp_buff) <= (wp + rpt_p->id_len) ){
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finer, "tmp_buff[wp] overrun, rpt_p->id_len=%d.\n", rpt_p->id_len);
#endif // CefC_Debug
			goto SKIP_CONCAT;
		}
		wp += rpt_p->id_len;
		rpt_p = rpt_p->next;
	}

SKIP_CONCAT:;

#ifdef	DEB_CCNINFO
	fprintf( stderr, "\t 001 wp=%d\n", wp );
#endif
	/* Content Name */
	memcpy( &tmp_buff[wp], pci->disc_name, pci->disc_name_len );
	if ( sizeof(tmp_buff) <= (wp + pci->disc_name_len) ){
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finer, "tmp_buff[wp] overrun, pci->disc_name_len=%d.\n", pci->disc_name_len);
#endif // CefC_Debug
		goto SKIP_CONCAT;
	}
	wp += pci->disc_name_len;
#ifdef	DEB_CCNINFO
	fprintf( stderr,"\t 002 wp=%d\n", wp );
#endif
#ifdef	DEB_CCNINFO
	{
		int	jj;
		int	tmp_len;
		tmp_len = wp;
		fprintf( stderr, "cefnetd_ccninfo_name_create() wp=%d\n", wp );
		for (jj = 0 ; jj < tmp_len ; jj++) {
			if ( jj != 0 ) {
				if ( jj%32 == 0 ) {
				fprintf( stderr, "\n" );
				}
			}
			fprintf( stderr, "%02x ", tmp_buff[jj] );
		}
		fprintf( stderr, "\n" );
	}
#endif

	/* hash */
	// MD5 ( (unsigned char*)tmp_buff, wp, ccninfo_name );
	cef_valid_md5( tmp_buff, wp, ccninfo_name );	/* for Openssl 3.x */
#ifdef	DEB_CCNINFO
	fprintf( stderr, "\t 003\n" );
#endif
	/* RequestID */
	memcpy( &ccninfo_name[MD5_DIGEST_LENGTH], &pci->req_id, sizeof(uint16_t) );
#ifdef	DEB_CCNINFO
	fprintf( stderr, "\t 004\n" );
#endif

#ifdef	DEB_CCNINFO
	{
		int	ii;
		int	tmp_len;
		tmp_len = MD5_DIGEST_LENGTH + sizeof(uint16_t);
		fprintf( stderr, "cefnetd_ccninfo_name_create() pit_len=%d\n", tmp_len );
		for (ii = 0 ; ii < tmp_len ; ii++) {
			if ( ii != 0 ) {
				if ( ii%32 == 0 ) {
				fprintf( stderr, "\n" );
				}
			}
			fprintf( stderr, "%02x ", ccninfo_name[ii] );
		}
		fprintf( stderr, "\n" );
	}
#endif

	return( MD5_DIGEST_LENGTH + sizeof(uint16_t) );
}


#ifdef DEB_CCNINFO
/*--------------------------------------------------------------------------------------
	for debug
----------------------------------------------------------------------------------------*/
static void
cefnetd_dbg_cpi_print (
	CefT_Parsed_Ccninfo* pci
) {
	int aaa, bbb;
	CefT_Request_RptBlk* rpt_p;
	CefT_Reply_SubBlk* rep_p;

	fprintf(stderr, "----- cef_frame_ccninfo_parse -----\n");
	fprintf(stderr, "PacketType                : 0x%02x\n", pci->pkt_type);
	fprintf(stderr, "ReturnCode                : 0x%02x\n", pci->ret_code);
	if (pci->putverify_f) {
		fprintf(stderr, "  --- option header ---\n");
		fprintf(stderr, "  MsgType                 : 0x%02x\n", pci->putverify_msgtype);
		fprintf(stderr, "  start seq               : %d\n", pci->putverify_sseq);
		fprintf(stderr, "  end seq                 : %d\n", pci->putverify_eseq);
	}
	fprintf(stderr, "  --- Request Block ---\n");
	fprintf(stderr, "  Request ID              : %u\n", pci->req_id);
	fprintf(stderr, "  SkipHopCount            : %u\n", pci->skip_hop);
	fprintf(stderr, "  Flags                   : 0x%02x V(%c) F(%c), O(%c), C(%c)\n", pci->ccninfo_flag,
						(pci->ccninfo_flag & CefC_CtOp_ReqValidation) ? 'o': 'x',
						(pci->ccninfo_flag & CefC_CtOp_FullDisCover) ? 'o': 'x',
						(pci->ccninfo_flag & CefC_CtOp_Publisher)    ? 'o': 'x',
						(pci->ccninfo_flag & CefC_CtOp_Cache)        ? 'o': 'x');
	fprintf(stderr, "  Request Arrival Time    : %u\n", pci->req_arrival_time);
	fprintf(stderr, "  Node Identifier         : ");
	for (aaa=0; aaa<pci->id_len; aaa++)
		fprintf(stderr, "%02x ", pci->node_id[aaa]);
	fprintf(stderr, "\n");
	fprintf(stderr, "  --- Report Block ---(%d)\n", pci->rpt_blk_num);
	rpt_p = pci->rpt_blk;
	for (bbb=0; bbb<pci->rpt_blk_num; bbb++) {
		fprintf(stderr, "  [%d]\n", bbb);
		fprintf(stderr, "    Request Arrival Time  : %u\n", rpt_p->req_arrival_time);
		fprintf(stderr, "    Node Identifier       : ");
		for (aaa=0; aaa<rpt_p->id_len; aaa++)
			fprintf(stderr, "%02x ", rpt_p->node_id[aaa]);
		fprintf(stderr, "\n");
		rpt_p = rpt_p->next;
	}
	fprintf(stderr, "  --- Discovery ---\n");
	fprintf(stderr, "  Name                    : ");
	for (aaa=0; aaa<pci->disc_name_len; aaa++)
		fprintf(stderr, "%02x ", pci->disc_name[aaa]);
	fprintf(stderr, "(%d)\n", pci->disc_name_len);

	if ( pci->reply_node_len > 0 ) {
	fprintf(stderr, "  --- Reply Node ---\n");
	fprintf(stderr, "    Request Arrival Time  : %u\n", pci->reply_req_arrival_time);
	fprintf(stderr, "    Node Identifier       : ");
	for (aaa=0; aaa<pci->reply_node_len; aaa++)
		fprintf(stderr, "%02x ", pci->reply_reply_node[aaa]);
	fprintf(stderr, "\n");
	}

	fprintf(stderr, "  --- Reply Block ---(%d)\n", pci->rep_blk_num);
	rep_p = pci->rep_blk;
	for (bbb=0; bbb<pci->rep_blk_num; bbb++) {
		fprintf(stderr, "  [%d]\n", bbb);
		fprintf(stderr, "    Content Type          : %s\n",
			(rep_p->rep_type == CefC_T_DISC_CONTENT) ? "T_DISC_CONTENT" : "T_DISC_CONTENT_OWNER");
		fprintf(stderr, "    Object Size           : %u\n", rep_p->obj_size);
		fprintf(stderr, "    Object Count          : %u\n", rep_p->obj_cnt);
		fprintf(stderr, "    # Received Interest   : %u\n", rep_p->rcv_interest_cnt);
		fprintf(stderr, "    First Seqnum          : %u\n", rep_p->first_seq);
		fprintf(stderr, "    Last Seqnum           : %u\n", rep_p->last_seq);
		fprintf(stderr, "    Elapsed Cache Time    : %u\n", rep_p->cache_time);
		fprintf(stderr, "    Remain Cache Lifetime : %u\n", rep_p->lifetime);
		fprintf(stderr, "    Name                  : ");
		for (aaa=0; aaa<rep_p->rep_name_len; aaa++)
			fprintf(stderr, "%02x ", rep_p->rep_name[aaa]);
		fprintf(stderr, "(%d)\n", rep_p->rep_name_len);
		if (rep_p->rep_range_len) {
			fprintf(stderr, "    Cache Chunk           : %s\n", rep_p->rep_range);
		}
		rep_p = rep_p->next;
	}
}
#endif

//0.8.3
/*--------------------------------------------------------------------------------------
	Handles the received Interest message has T_SELECTIVE
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_selective_interest_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh				/* Parsed Option Header						*/
) {
	CefT_Pit_Entry* pe = NULL;
	CefT_Fib_Entry* fe = NULL;
	uint16_t faceids[CefC_Fib_UpFace_Max];
	uint16_t face_num = 0;
	unsigned char trg_name[CefC_Max_Length];
	struct value32_tlv value32_fld;
	uint16_t org_name_len;
	uint16_t trg_name_len;
	unsigned char 	org_name[CefC_Max_Length];
	int pit_res = 0;
	int pit_res_first;

#if defined(CSMFILE)
	int	interest_to_csm	= 0;
#endif

	uint64_t		first_chunk;
	uint64_t		l;
	uint64_t		select_cob_num;

#ifdef	__SELECTIVE__
	fprintf( stderr, "[%s] IN\n", __func__ );
#endif

	//First Chunk Number to CefC_Select_Cob_Num : RegPIT & CS_MODE=2 Interest to Csmgrd
	if ( pm->org.req_chunk == 0 ) {
		/* Error 4 5 12 13 */
		return (-1);
	}

	//20220311
	if ( pm->org.req_chunk > hdl->Selective_max_range ) {
		return(-1);
	}


	first_chunk = (uint64_t)pm->org.first_chunk;
	if ( pm->org.last_chunk_f > 0 ) {
		/* ptn A  */
		if ( pm->org.first_chunk > pm->org.last_chunk ) {
			/* Error 3 */
			return (-1);
		}
		if ( (pm->org.last_chunk - pm->org.first_chunk) < pm->org.req_chunk ) {
			/* Error 7 */
			return (-1);
		}
		if ( pm->org.req_chunk > 0 ) {
			/* 1 2 */
			select_cob_num = (uint64_t)pm->org.req_chunk;
			goto SELECT_OK;
		}
		/* 6 8 */
		select_cob_num = (uint64_t)pm->org.req_chunk;
	} else {
		/* ptn B */
		/* 9 10 11 */
		select_cob_num = (uint64_t)pm->org.req_chunk;
	}
SELECT_OK:;

	org_name_len = pm->name_len;
	memcpy (org_name, pm->name, pm->name_len);
	memcpy (trg_name, pm->name, pm->name_len);

#ifdef	__SELECTIVE__
	fprintf( stderr, "[%s] CKP-010\n", __func__ );
#endif
	/* InterestType */
	pm->InterestType = CefC_PIT_TYPE_Rgl;
	for ( l = 0; l < select_cob_num; l++ ) {
		/* Max check */
		if ( first_chunk == UINT32_MAX ) {
			/* Warning */
#ifdef	__SELECTIVE__
			fprintf( stderr, "[%s] return(-1)\n", __func__ );
#endif
			return(-1);
		}

		/* set Chunk Number */
		trg_name_len = org_name_len;
		value32_fld.type   = htons (CefC_T_CHUNK);
		value32_fld.length = htons (CefC_S_ChunkNum);
		value32_fld.value  = htonl ((uint32_t)first_chunk);
		memcpy (&trg_name[trg_name_len], &value32_fld, sizeof (struct value32_tlv));
		trg_name_len += sizeof (struct value32_tlv);
		pm->name_len = trg_name_len;
		memcpy (pm->name, trg_name, trg_name_len);
		pm->chunk_num_f 	= 1;
		pm->chunk_num 	= (uint32_t)first_chunk;

		/* Searches a PIT entry matching this Interest 	*/
		/* Updates the information of down face that this Interest arrived 	*/
		pe = cef_pit_entry_lookup_and_down_face_update (hdl->pit, pm, poh,  NULL, 0,
					faceid, msg, hdl->InterestRetrans, &pit_res);
		if (pe == NULL) {
#ifdef	__SELECTIVE__
	fprintf( stderr, "[%s] CKP-020\n", __func__ );
#endif
			return (-1);
		}

#ifdef	__SELECTIVE__
	fprintf( stderr, "[%s] CKP-011\n", __func__ );
#endif
#ifdef	__SELECTIVE__
	fprintf( stderr, "[%s] CKP-012\n", __func__ );
#endif
		if ( l == 0 ) {
			pit_res_first = pit_res;
		}

#if defined(CSMFILE)
		if ( interest_to_csm != 0 ) {
			goto SKIP_INTEREST;
		}
#endif

#ifdef	__SELECTIVE__
	fprintf( stderr, "[%s] CKP-013\n", __func__ );
#endif

		if ( hdl->Selective_fwd == CefC_Selet_FWD_ON ) {
			goto SKIP_INTEREST;
		}

#if CefC_IsEnable_ContentStore
		/*--------------------------------------------------------------------
			Content Store
		----------------------------------------------------------------------*/
		/* Checks Content Store */
		if (hdl->cs_stat->cache_type != CefC_Default_Cache_Type) {
			/* Checks the temporary/local cache in cefnetd 		*/
#ifdef	__SELECTIVE__
	fprintf( stderr, "[%s] CKP-014\n", __func__ );
#endif
			unsigned char* cob = NULL;
			int cs_res = -1;
			cs_res = cef_csmgr_cache_lookup (hdl->cs_stat, peer_faceid, pm, poh, pe, &cob);
			if (cs_res < 0) {
#ifdef	__SELECTIVE__
	fprintf( stderr, "[%s] CKP-015\n", __func__ );
#endif
#ifdef	CefC_Conpub
				if (hdl->cs_stat->cache_type != CefC_Cache_Type_ExConpub){
#endif	//CefC_Conpub
					/* Cache does not exist in the temporary cache in cefnetd, 		*/
					/* so inquiries to the csmgr 									*/
					cef_csmgr_excache_lookup (hdl->cs_stat, peer_faceid, pm, poh, pe);
#if defined(CSMFILE)
					interest_to_csm	= 1;
#endif

#ifdef	CefC_Conpub
				}
#endif	//CefC_Conpub
			} else {
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Finer,
					"Return the Content Object from the buffer/local cache\n");
#endif // CefC_Debug
#ifdef	__SELECTIVE__
	fprintf( stderr, "[%s] CKP-016\n", __func__ );
#endif
				cefnetd_cefcache_object_process (hdl, cob);
			}
		}
#endif

		/* Update first_chunk */
#ifdef	__SELECTIVE__
	fprintf( stderr, "[%s] CKP-018\n", __func__ );
#endif

SKIP_INTEREST:;
		first_chunk++;
	}
#ifdef	__SELECTIVE__
	fprintf( stderr, "[%s] CKP-090\n", __func__ );
#endif

	pm->name_len = org_name_len;
	memcpy (pm->name, org_name, pm->name_len);

	/* Reset InterestType to the original type */
	pm->InterestType = CefC_PIT_TYPE_Sel;
	/* Count of Received Interest */
	hdl->stat_recv_interest++;
	/* Count of Received Interest by type */
	hdl->stat_recv_interest_types[pm->InterestType]++;
	fe = cef_fib_entry_search (hdl->fib, pm->name, pm->name_len);
	if (fe) {
		/* Count of Received Interest at FIB */
		fe->rx_int++;
		/* Count of Received Interest by type at FIB */
		fe->rx_int_types[pm->InterestType]++;
		fe = NULL;
	}

	//hdl->Selective_fwd==CefC_Selet_FWD_ON : NextHop
	if ( pit_res_first != 0 ) {
		if ( hdl->Selective_fwd == CefC_Selet_FWD_ON ) {
			/* Searches a FIB entry matching this Interest 		*/
			fe = cef_fib_entry_search (hdl->fib, pm->name, pm->name_len);
			/* Obtains Face-ID(s) to forward the Interest */
			if (fe) {
				face_num = cef_fib_forward_faceid_select (fe, peer_faceid, faceids);
			}
			if (face_num > 0) {
				cefnetd_interest_forward (
					hdl, faceids, face_num, peer_faceid, msg,
					payload_len, header_len, pm, poh, pe, fe
				);
			}
		}
	}
#ifdef	__SELECTIVE__
	fprintf( stderr, "[%s] OUT\n", __func__ );
#endif

	return (1);
}

static int
cefnetd_keyid_get (
	const unsigned char* msg,
	int msg_len,
	unsigned char *keyid_buff
) {
	struct fixed_hdr* 	fixed_hp;
	struct tlv_hdr* 	tlv_ptr;

	uint16_t 	index;
	uint16_t 	pkt_len;
	uint16_t 	hdr_len;
	uint16_t 	val_len;
	uint16_t 	type, alg_type;
	uint16_t 	alg_offset = 0;
	uint16_t 	t_keyid_offset = 0;
	uint16_t 	t_keyid_len = 0;
	uint16_t 	t_keyid_type = 0;
#ifdef	__RESTRICT__
		printf( "\n\n%s IN\n", __func__ );
#endif

	/* Obtains header length and packet length 		*/
	fixed_hp = (struct fixed_hdr*) msg;
	pkt_len  = ntohs (fixed_hp->pkt_len);
	if (pkt_len != msg_len) {
#ifdef	__RESTRICT__
		printf( "\t (pkt_len:%d != msg_len:%d)\n", pkt_len, msg_len );
#endif
		return (-1);
	}
	hdr_len = fixed_hp->hdr_len;

	/* Obtains CCN message size 		*/
	tlv_ptr = (struct tlv_hdr*) &msg[hdr_len];
	val_len = ntohs (tlv_ptr->length);
	if (hdr_len + CefC_S_TLF + val_len == pkt_len) {
#ifdef	__RESTRICT__
		printf( "\t (hdr_len:%d + CefC_S_TLF:%d + val_len:%d == pkt_len:%d)\n", hdr_len, CefC_S_TLF, val_len, pkt_len);
#endif
		return (0);
	}
	index = hdr_len + CefC_S_TLF + val_len;

	/* Checks Validation Algorithm TLVs 	*/
	alg_offset = index;
#ifdef	__RESTRICT__
		printf( "\t alg_offset:%d index:%d\n", alg_offset, index );
#endif
	tlv_ptr = (struct tlv_hdr*) &msg[alg_offset];
	type = ntohs (tlv_ptr->type);
	if (type != CefC_T_VALIDATION_ALG) {
#ifdef	__RESTRICT__
		printf( "\t (type != CefC_T_VALIDATION_ALG)\n" );
#endif
		return (-1);
	}

	val_len = ntohs (tlv_ptr->length);
#ifdef	__RESTRICT__
		printf( "\t val_len:%d\n", val_len );
#endif
	if (index + CefC_S_TLF + val_len >= pkt_len) {
#ifdef	__RESTRICT__
		printf( "\t (index + CefC_S_TLF + val_len >= pkt_len)\n" );
#endif
		return (-1);
	}
	index += CefC_S_TLF;
#ifdef	__RESTRICT__
		printf( "\t alg_offset:%d index:%d\n", alg_offset, index );
#endif

	/* Checks Algorithm Type 		*/
	tlv_ptr = (struct tlv_hdr*) &msg[index];
	alg_type = ntohs (tlv_ptr->type);

	if ( alg_type != CefC_T_RSA_SHA256 ) {
		return (-1);
	}

	/* T_KEYID */
	t_keyid_offset = index + 4;
	tlv_ptr = (struct tlv_hdr*) &msg[t_keyid_offset];
	t_keyid_type = ntohs (tlv_ptr->type);
	t_keyid_len  = ntohs (tlv_ptr->length);
#ifdef	__RESTRICT__
		printf( "\t t_keyid_offset:%d t_keyid_type:%d t_keyid_len:%d\n", t_keyid_offset, t_keyid_type,t_keyid_len );
#endif

	if ( t_keyid_type != CefC_T_KEYID ) {
		return (-1);
	}
	if ( t_keyid_len != 32 ) {
		return (-1);
	}
	t_keyid_offset += CefC_S_TLF;
	memcpy( keyid_buff, &msg[t_keyid_offset], 32 );

	return ( t_keyid_len );

}


void *
cefnetd_cefstatus_thread (
	void *p
) {
	CefT_Netd_Handle*	cefned_hdl;
	int 				read_fd = -1;
	struct pollfd 		poll_fds[1];
	CefT_Cefstatus_Msg	in_msg;
	int					in_msg_len;
	char				msg[CefC_Max_Length];
	int					resp_fd = -1;
	int					res;
	unsigned char*		rsp_msg = NULL;
	struct pollfd		send_fds[1];
	uint16_t			output_opt = 0x0000;
	uint16_t			numofpit = 0;

	cefned_hdl = (CefT_Netd_Handle*)p;

	read_fd = cefned_hdl->cefstatus_pipe_fd[1];

	pthread_t self_thread = pthread_self();
	pthread_detach(self_thread);

	memset(&poll_fds, 0, sizeof(poll_fds));
	poll_fds[0].fd = read_fd;
	poll_fds[0].events = POLLIN | POLLERR;

#if 0
	uint64_t	dev_cnt = 0;
#endif
	while (1){
#if 0
	dev_cnt++;
	if ( (dev_cnt % 100000) == 0 ) {
		printf( "[%s]   dev_cnt:"FMTU64" \n", __func__, dev_cnt );
	}
#endif

	    poll(poll_fds, 1, 1000);
	    if (poll_fds[0].revents & POLLIN) {
			if((in_msg_len = read(read_fd, &in_msg, sizeof(CefT_Cefstatus_Msg))) < 1){
				continue;
			}

			memcpy( msg, (unsigned char*)in_msg.msg, CefC_Cefstatus_MsgSize );
			resp_fd = in_msg.resp_fd;

			if ( strncmp( msg, CefC_Ctrl_Status, CefC_Ctrl_Status_Len) == 0) {
				rsp_msg = calloc(1, CefC_Max_Length*10);
				output_opt = 0x0000;
				if (strncmp (msg, CefC_Ctrl_StatusStat, CefC_Ctrl_StatusStat_Len) == 0) {
					/* output option */
					memcpy (&output_opt, &msg[CefC_Ctrl_StatusStat_Len], sizeof (uint16_t));
					if ( output_opt & CefC_Ctrl_StatusOpt_Numofpit ) {
						memcpy( &numofpit, &msg[CefC_Ctrl_StatusStat_Len + sizeof (uint16_t)], sizeof (uint16_t) );
					}
				}
				res = cef_status_stats_output (cefned_hdl, &rsp_msg, output_opt, numofpit);

				if (res > 0) {
					send_fds[0].fd = resp_fd;
					send_fds[0].events = POLLOUT | POLLERR;
					if (poll (send_fds, 1, 0) > 0) {
						if (send_fds[0].revents & (POLLERR | POLLNVAL | POLLHUP)) {
							cef_log_write (CefC_Log_Warn,
								"Failed to send to Local peer (%d)\n", send_fds[0].fd);
						} else {
							{
								int	fblocks;
								int rem_size;
								int counter;
								int fcntlfl;
								fcntlfl = fcntl (resp_fd, F_GETFL, 0);
								fcntl (resp_fd, F_SETFL, fcntlfl & ~O_NONBLOCK);
								fblocks = res / 65535;
								rem_size = res % 65535;
								for (counter=0; counter<fblocks; counter++){
									send (resp_fd, &rsp_msg[counter*65535], 65535, 0);
								}
								if (rem_size != 0){
									send (resp_fd, &rsp_msg[fblocks*65535], rem_size, 0);
								}
								fcntl (resp_fd, F_SETFL, fcntlfl | O_NONBLOCK);
							}
						}
					}
				}
				if ( rsp_msg != NULL ) {
					free( rsp_msg );
					rsp_msg = NULL;
				}
			} else {
				/* Erroe */
			}

			if ( rsp_msg != NULL ) {
				free( rsp_msg );
				rsp_msg = NULL;
			}
			memset( msg, 0, CefC_Max_Length );
			resp_fd = -1;
		}

	}

	pthread_exit (NULL);
	return 0;

}

static int
cefnetd_fwd_plugin_load (
	CefT_Netd_Handle* hdl					/* cefnetd handle							*/
) {
	int (*func)(CefT_Plugin_Fwd_Strtgy*);
	char func_name[CefC_FwdStrPlg_Max_NameLen+32] = {0};

	/* Open library */
	hdl->fwd_strtgy_lib = dlopen (CefnetdC_FwdPlugin_Library_Name, RTLD_LAZY);
	if (hdl->fwd_strtgy_lib == NULL) {
		cef_log_write (CefC_Log_Error, "%s\n", dlerror ());
		return (-1);
	}

	/* Load plugin */
	sprintf (func_name, "cefnetd_fwd_%s_plugin_load", hdl->forwarding_strategy);
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Fwd Plugin name = %s.\n", func_name);
#endif // CefC_Debug
	func = dlsym (hdl->fwd_strtgy_lib, (const char*)func_name);
	if (func == NULL) {
		cef_log_write (CefC_Log_Error, "%s\n", dlerror ());
		/* close library */
		dlclose (hdl->fwd_strtgy_lib);
		return (-1);
	}

	/* Load functions */
	if ((func) (hdl->fwd_strtgy_hdl) != 0) {
		cef_log_write (CefC_Log_Warn, "Forwarding Strategy Plugin function is not set.\n");
		return (0);
	}

	if (hdl->fwd_strtgy_hdl->init == NULL) {
		cef_log_write (CefC_Log_Warn, "Initialize Forwarding Strategy Plugin function is not set.\n");
	}

	return( 0 );
}

static int
cefnetd_continfo_process (
	CefT_Netd_Handle*		hdl,			/* cefnetd handle							*/
	int						faceid,			/* Face-ID where messages arrived at		*/
	int						peer_faceid,	/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char*			msg,			/* received message to handle				*/
	uint16_t				payload_len,	/* Payload Length of this message			*/
	uint16_t				header_len,		/* Header Length of this message			*/
	CefT_CcnMsg_MsgBdy*	pm,				/* Structure to set parsed CEFORE message	*/
	CefT_Parsed_Ccninfo*	pci				/* Structure to set parsed Ccninfo message	*/
) {
#if CefC_IsEnable_ContentStore
	int						res;
	char*					info_buff;
	char					range[CefC_Max_Length];
	int						range_len;
#endif // CefC_IsEnable_ContentStore

	if ((hdl->cs_stat == NULL) ||
		(hdl->cs_stat->cache_type != CefC_Cache_Type_Excache)) {
		cef_log_write (CefC_Log_Warn, "Incoming continfo message, but CS is not Excache.\n");
		return (-1);
	}

#if CefC_IsEnable_ContentStore
	/*-------------------------------------------------------------
		Creates and send the Contents Information Request/Response
	---------------------------------------------------------------*/

	/* Obtains the Contents Information of the specified Prefix */
	memset (range, 0, CefC_Max_Length);
	range_len = sprintf (range, "%u:%u", pci->putverify_sseq, pci->putverify_eseq);
	res = cef_csmgr_content_info_get (
				hdl->cs_stat, (char*)pm->name, pm->name_len,
				range, range_len, &info_buff);

	/* Returns a Ccninfo Reply 			*/
	if (res >= 0) {
		uint16_t					index = 0;
		struct tlv_hdr				tlv_hdr;
		uint16_t					pld_len_new;
		struct ccninfo_req_block	req_blk;
		struct tlv_hdr*				tlv_hp;
		struct fixed_hdr*			fix_hdr;
		char*						last_comma;
		uint16_t					pkt_len;
		uint16_t					msg_len;
		uint16_t					range_len_ns;
		uint16_t					total_rep_sub_length;
		struct ccninfo_rep_block	rep_blk;

		/* Sets the header size		*/
		index = payload_len + header_len;

		/* Sets type and length of T_DISC_REPLY 		*/
/*
		+---------------+---------------+---------------+---------------+
		|      Type (=T_DISC_REPLY)     |             Length            |
		+---------------+---------------+---------------+---------------+
		|                     Request Arrival Time                      |
		+---------------+---------------+---------------+---------------+
		/                        Node Identifier                        /
		+---------------+---------------+---------------+---------------+
*/
		/* Reply block TLV */
		tlv_hdr.type = htons (CefC_T_DISC_REPLY);
		/* R_ArrTime + NodeID */
		pld_len_new = CefC_S_ReqArrivalTime + hdl->My_Node_Name_TLV_len;
		/* the total length of Reply sub-block(s) */
		total_rep_sub_length = CefC_S_TLF + sizeof (struct ccninfo_rep_block)	/* T_DISC_CONTENT */
								+ CefC_S_TLF + pm->name_len						/* T_NAME */
								+ CefC_S_Length + res;							/* RespRange */
		tlv_hdr.length = htons (pld_len_new + total_rep_sub_length);
		memcpy (&msg[index], &tlv_hdr, sizeof (struct tlv_hdr));
		index += CefC_S_TLF;
		{	/* set 32bit-NTP time */
	    	struct timespec tv;
			uint32_t ntp32b;
			clock_gettime(CLOCK_REALTIME, &tv);
			ntp32b = ((tv.tv_sec + 32384) << 16) + ((tv.tv_nsec << 7) / 1953125);
			req_blk.req_arrival_time 	= htonl (ntp32b);
			memcpy (&msg[index], &req_blk, sizeof (struct ccninfo_req_block));
			index += CefC_S_ReqArrivalTime;
		}
		/* Node Identifier (is Name TLV format) */
		memcpy (&msg[index], hdl->My_Node_Name_TLV, hdl->My_Node_Name_TLV_len);
		index += hdl->My_Node_Name_TLV_len;
		payload_len += CefC_S_TLF + CefC_S_ReqArrivalTime + hdl->My_Node_Name_TLV_len;

		/* Cache Information (just adjust index) */
/*
		+---------------+---------------+---------------+---------------+
		|     Type (=T_DISC_CONTENT)    |             Length            |
		+---------------+---------------+---------------+---------------+
		|                          Object Size                          |
		+---------------+---------------+---------------+---------------+
		|                         Object Count                          |
		+---------------+---------------+---------------+---------------+
		|                      # Received Interest                      |
		+---------------+---------------+---------------+---------------+
		|                         First Seqnum                          |
		+---------------+---------------+---------------+---------------+
		|                          Last Seqnum                          |
		+---------------+---------------+---------------+---------------+
		|                       Elapsed Cache Time                      |
		+---------------+---------------+---------------+---------------+
		|                      Remain Cache Lifetime                    |
		+---------------+---------------+---------------+---------------+
		|            T_NAME             |             Length            |
		+---------------+---------------+---------------+---------------+
		/                       Name Segment TLVs                       /
		+---------------+---------------+---------------+---------------+
		|       RespRange Length        |                               /
		+---------------+---------------+---------------+---------------+
		|                        RespRange(string)                      /
		+---------------+---------------+---------------+---------------+
*/
		tlv_hdr.type = htons (CefC_T_DISC_CONTENT);
		/* exclude Type and Length */
		total_rep_sub_length = sizeof (struct ccninfo_rep_block);
		tlv_hdr.length = htons (total_rep_sub_length);
		memcpy (&msg[index], &tlv_hdr, sizeof (struct tlv_hdr));
		index += CefC_S_TLF;
		memset (&rep_blk, 0x00, sizeof (struct ccninfo_rep_block));
		memcpy (&msg[index], &rep_blk, sizeof (struct ccninfo_rep_block));
		index += sizeof (struct ccninfo_rep_block);

		/* Name */
		tlv_hdr.type = htons (CefC_T_NAME);
		tlv_hdr.length = htons (pm->name_len);
		memcpy (&msg[index], &tlv_hdr, sizeof (struct tlv_hdr));
		memcpy (&msg[index + CefC_S_TLF], pm->name, pm->name_len);
		index += CefC_S_TLF + pm->name_len;

		if (res > 0) {
			/* Trim response data (end of data is a comma(',')) */
			info_buff[res] = '\0';
			last_comma = strrchr((const char*) info_buff, (int) ',');
			if (last_comma != NULL){
				*(last_comma+1) = '\0';
				res = strlen((const char*) info_buff);
			}

			/* RespRange */
			range_len_ns = htons (res);
			memcpy (&msg[index], &range_len_ns, CefC_S_Length);
			index += CefC_S_Length;
			memcpy (&msg[index], info_buff, res);
			free (info_buff);
			index += res;
		} else {
			range_len_ns = 0x00;
			memcpy (&msg[index], &range_len_ns, CefC_S_Length);
			index += CefC_S_Length;
		}

		/* Sets ICN message length 	*/
		pkt_len = index;
		msg_len = pkt_len - (header_len + CefC_S_TLF);

		tlv_hp = (struct tlv_hdr*) &msg[header_len];
		tlv_hp->length = htons (msg_len);

		/* Updates PacketLength and HeaderLength 		*/
		fix_hdr = (struct fixed_hdr*) msg;
		fix_hdr->type 	  = CefC_PT_REPLY;
		fix_hdr->reserve1 = CefC_CtRc_NO_ERROR;
		fix_hdr->pkt_len  = htons (pkt_len);

#ifdef DEB_CCNINFO
{	CefT_Parsed_Ccninfo *snd_pci;
		if ( (snd_pci = cef_frame_ccninfo_parse (msg)) != NULL ){
			cefnetd_dbg_cpi_print (snd_pci);
			cef_frame_ccninfo_parsed_free (snd_pci);
		}
}
#endif
		cefnetd_frame_send_txque (hdl, peer_faceid, msg, pkt_len);

		return (1);
	}
#endif // CefC_IsEnable_ContentStore

	return (1);
};

static void
cefnetd_adv_route_process (
	CefT_Netd_Handle*		hdl,		/* cefnetd handle							*/
	CefT_CcnMsg_MsgBdy*	pm				/* Structure to set parsed CEFORE message	*/
) {

	if (hdl->babel_use_f) {
		cefnetd_xroute_change_report (
			hdl, pm->name, pm->name_len, 1);
	}

	return;
}

static int
cefnetd_route_msg_check (
	CefT_Netd_Handle* hdl,				/* cefnetd handle							*/
	unsigned char* msg,					/* received message to handle				*/
	int msg_size						/* size of received message(s)				*/
) {
	uint8_t op;
	uint8_t prot;
	int index = 0;
	int entries = 0;
	char uri[CefC_NAME_BUFSIZ];
	uint16_t uri_len;
	int		err;

	/* get operation */
	if ((msg_size - index) < sizeof (op)) {
		return (0);
	}
	op = msg[index];
	index += sizeof (op);

	/* get protocol */
	if ((msg_size - index) < sizeof (prot)) {
		/* message is too short */
		return (-1);
	}
	prot = msg[index];
	index += sizeof (prot);

	/* get uri */
	memcpy (&uri_len, &msg[index], sizeof (uint16_t));
	index += sizeof (uint16_t);
	if (uri_len <= 0) {
		/* message is too short */
		return (0);
	}
	if ((msg_size - index) < uri_len) {
		/* message is too short */
		return (0);
	}
	memcpy (uri, &msg[index], uri_len);
	uri[uri_len] = 0x00;
	index += uri_len;

	while (index < msg_size) {
		struct addrinfo hints;
		struct addrinfo* res;
		struct addrinfo* cres;
		uint8_t host_len;
		char host[CefC_NAME_BUFSIZ] = {0};
		char *port_str = NULL;
		char *IPv6_endmark = NULL;
		int	 port_num = hdl->port_num;

		/* get host */
		if ((msg_size - index) < sizeof (host_len)) {
			/* message is too short */
			return (-1);
		}
		host_len = msg[index];
		index += sizeof (host_len);
		if ((msg_size - index) < host_len) {
			/* message is too short */
			return (-1);
		}
		/* host must be an IP address string */
		memcpy (host, &msg[index], host_len);
		host[host_len] = 0x00;
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "host = %s\n", host);
#endif // CefC_Debug

		IPv6_endmark = strchr(host, ']');	/* Rules for enclosing IPv6 strings in [] */

		if ( host[0] != '[' ){			/* not IPv6 */
			if ( (port_str = strchr(host, ':')) != NULL ){
				*port_str++ = '\0';
				port_num = strtol(port_str, NULL, 0);
			}
		} else if ( IPv6_endmark ) {	/* IPv6 */
			*IPv6_endmark++ = '\0';
			if ( (port_str = strchr(IPv6_endmark, ':')) != NULL ){
				*port_str++ = '\0';
				port_num = strtol(port_str, NULL, 0);
			}
			// strcpy(host, &host[1]);  /* An exception occurred on a Mac. */
			for ( int i = 0; i < host_len; i++ ){
				host[i] = host[i+1];
			}
		}
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "port = %s\n", port_str);
#endif // CefC_Debug
		if ( port_num < 1 || UINT16_MAX < port_num ){
			/* value is out of range */
			cef_log_write (CefC_Log_Error, "Failed cefroute command, The specified port number is out of range. (%s)\n", host);
			return (-1);
		}

		memset (&hints, 0, sizeof (hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_flags = (AI_NUMERICHOST | AI_NUMERICSERV);
		if (prot != CefC_Face_Type_Tcp) {
			hints.ai_socktype = SOCK_DGRAM;
		} else {
			hints.ai_socktype = SOCK_STREAM;
		}

		/* This getaddrinfo uses only format conversion */
		/* (avoids time-consuming DNS requests) */
		if ((err = getaddrinfo (host, port_str, &hints, &res)) != 0) {
			cef_log_write (CefC_Log_Error,
				"getaddrinfo(%s)=%s\n", host, gai_strerror(err));
			return (-1);
		}
		for (cres = res ; cres != NULL ; cres = cres->ai_next) {
			struct sockaddr_in *ai = (struct sockaddr_in *)(cres->ai_addr);
			struct sockaddr_in6 *ai6 = (struct sockaddr_in6 *)(cres->ai_addr);
			char buf[INET6_ADDRSTRLEN];

			switch ( ai->sin_family ){
			case AF_INET:
				inet_ntop(ai->sin_family, &(ai->sin_addr), buf, sizeof(buf));
				if ( port_num == hdl->port_num ){
					if ( ((char *)&ai->sin_addr)[0] == 127 ){
						/* Error */
						cef_log_write (CefC_Log_Error, "Failed cefroute command.(loopback address %s) !!\n", host);
						return(-1);
					}
					for ( int i = 0; i < hdl->nodeid4_num; i++ ) {
#ifdef CefC_Debug
char  buff[NI_MAXHOST];
inet_ntop(AF_INET, (struct sockaddr_in *)hdl->nodeid4[i], buff,  NI_MAXHOST);
cef_dbg_write (CefC_Dbg_Finer, "nodeid4[%d]: %s.\n", i, buff);
#endif // CefC_Debug
						if ( !memcmp(hdl->nodeid4[i], &(ai->sin_addr), NS_INADDRSZ) ){
							/* Error */
							cef_log_write (CefC_Log_Error, "Failed cefroute command.(Own address %s)\n", host);
							return(-1);
						}
					}
				}
				break;
			case AF_INET6:
				inet_ntop(ai6->sin6_family, &(ai6->sin6_addr), buf, sizeof(buf));
				if ( port_num == hdl->port_num ){
					if ( !strcmp(buf, "::1") ){
						/* Error */
						cef_log_write (CefC_Log_Error, "Failed cefroute command.(loopback address %s) !!\n", host);
						return(-1);
					}
					for ( int i = 0; i < hdl->nodeid16_num; i++ ) {
#ifdef CefC_Debug
char  buff[NI_MAXHOST];
inet_ntop(AF_INET6, (struct sockaddr_in *)hdl->nodeid16[i], buff,  NI_MAXHOST);
cef_dbg_write (CefC_Dbg_Finer, "nodeid6[%d]: %s.\n", i, buff);
#endif // CefC_Debug
						if ( !memcmp(hdl->nodeid16[i], &(ai6->sin6_addr), NS_IN6ADDRSZ) ){
							/* Error */
							cef_log_write (CefC_Log_Error, "Failed cefroute command.(Own address %s)\n", host);
							return(-1);
						}
					}
				}
				break;
			default:
				continue;
			}
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finer, "IP address [%d] = %s\n", entries, buf);
#endif // CefC_Debug
			entries++;
		}

		freeaddrinfo (res);
		index += host_len;
	}

	if ( !entries ){
		cef_log_write (CefC_Log_Error, "Failed cefroute command. (%s)\n", &msg[index]);
		return -1;
	}

	return (entries);

}

/*--------------------------------------------------------------------------------------
	Handles the elements of TX queue
----------------------------------------------------------------------------------------*/

#define	CefC_Sleep_Max			1000
#define	Cef_TxThreadSleep(t)	((long)(t)*(t))

static struct timespec *
cefnetd_get_waittime(
	struct timespec *ts,
	long			wait_us		// micro-seconds
){
	const long	nano = 1000*1000*1000;
	struct timespec ts_now;
	long		t_ns;		// nano-seconds

	clock_gettime(CLOCK_REALTIME, &ts_now);
	t_ns = (ts_now.tv_nsec + (wait_us * 1000L));
	ts->tv_sec = ts_now.tv_sec + (t_ns / nano);
	ts->tv_nsec = t_ns % nano;

// cef_dbg_write (CefC_Dbg_Fine, "wait_us=%ld, timespec=%ld.%06ld.\n", wait_us, ts->tv_sec, ts->tv_nsec);

	return ts;
}

#ifdef CefC_TxMultiThread
static void *
cefnetd_transmit_worker_thread (
	void *p
) {
	CefT_Netd_TxWorker* hdl_wkr = p;
	int		   worker_id = hdl_wkr->worker_id;	/* worker id */
	long	   t_sleep = 0;
	struct timeval tv_prev = { 0, 0 };

	while (!cefnetd_running_f) {
		const struct timespec ts = { 0, 100*1000*1000 };
		nanosleep(&ts, NULL);
	}

#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "worker#%d thread(%p) start..\n", worker_id, pthread_self());
cef_dbg_write (CefC_Dbg_Finer, "tv_interval=%ld.%06ld.\n", hdl_wkr->tx_packet_interval.tv_sec, hdl_wkr->tx_packet_interval.tv_usec);
#endif // CefC_Debug

	while (cefnetd_running_f) {
		CefT_Tx_Elem* tx_elem;
		int		faceid = 0;

		/* Pop one element from the TX Ring Queue 		*/
		tx_elem = (CefT_Tx_Elem*) cef_rngque_pop (hdl_wkr->tx_que);

		if (!tx_elem){
			struct timespec ts = { 0, 0 };

			if ( CefC_Sleep_Max < ++t_sleep )
				t_sleep = CefC_Sleep_Max;

			cefnetd_get_waittime(&ts, Cef_TxThreadSleep(t_sleep));
			pthread_mutex_lock(&hdl_wkr->tx_worker_mutex);
			pthread_cond_timedwait(&hdl_wkr->tx_worker_cond,
							&hdl_wkr->tx_worker_mutex, &ts);
			pthread_mutex_unlock(&hdl_wkr->tx_worker_mutex);
			continue;
		}
		t_sleep = 0;

		if ( 0 < (hdl_wkr->tx_packet_interval.tv_usec) ){
			struct timeval tv_now, tv_target;

			timeradd(&tv_prev, &(hdl_wkr->tx_packet_interval), &tv_target);
			gettimeofday(&tv_now, NULL);
			if ( timercmp(&tv_now, &tv_target, < ) ){
				struct timeval  tv_sleep;
				struct timespec ts_sleep;

				timersub(&tv_target, &tv_now, &tv_sleep);
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "tv_sleep=%ld.%06ld.\n", tv_sleep.tv_sec, tv_sleep.tv_usec);
#endif // CefC_Debug
				ts_sleep.tv_sec = 0;
				ts_sleep.tv_nsec = (long)tv_sleep.tv_usec * 1000UL;
				nanosleep(&ts_sleep, NULL);
			}
		}
		gettimeofday(&tv_prev, NULL);

		faceid = tx_elem->faceids[0];
//		assert (CefC_Face_Reserved <= faceid && faceid < CefC_Face_Router_Max);
		if ( !(CefC_Face_Reserved <= faceid && faceid < CefC_Face_Router_Max) ){
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Fine, "ASSERT tx_elem=%p, faceid=%d, msg_type=0x%02x, msg_len=%d\n", tx_elem, faceid, tx_elem->msg[CefC_O_Fix_Type], tx_elem->msg_len);
#endif // CefC_Debug
			/* Free the pooled block 	*/
			cef_mpool_free (hdl_wkr->tx_que_mp, tx_elem);
			continue;
		}

#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "tx_elem=%p, faceid=%d, msg_type=0x%02x, msg_len=%d\n", tx_elem, faceid, tx_elem->msg[CefC_O_Fix_Type], tx_elem->msg_len);
#endif // CefC_Debug

		if (cef_face_check_active (faceid)){
			unsigned char new_buff[CefC_Max_Length];
			unsigned char *ptr_msg = tx_elem->msg;
			size_t   msg_len = tx_elem->msg_len;
			int		ret;

			if (cef_frame_get_opt_seqnum_f() && tx_elem->msg[CefC_O_Fix_Type] == CefC_PT_OBJECT) {
				uint32_t	seqnum;
				seqnum = cef_face_get_seqnum_from_faceid (faceid);
				msg_len =
					cef_frame_seqence_update (new_buff, tx_elem->msg, seqnum);
				ptr_msg = new_buff;
			}
			ret = cef_face_frame_send (faceid, ptr_msg, msg_len);
			if ( ret != msg_len ){
#ifdef CefC_Debug
				CefT_CcnMsg_MsgBdy pm = { 0 };
				CefT_CcnMsg_OptHdr poh = { 0 };
				char uri[CefC_NAME_BUFSIZ];
				struct fixed_hdr* chp = (struct fixed_hdr*) ptr_msg;
				uint16_t pkt_len = ntohs (chp->pkt_len);
				uint16_t hdr_len = chp->hdr_len;
				uint16_t payload_len = pkt_len - hdr_len;

				cef_frame_message_parse (
								ptr_msg, payload_len, hdr_len, &poh, &pm, CefC_PT_INTEREST);
				cefnetd_name_to_uri (&pm, uri, sizeof(uri));
				cef_dbg_write (CefC_Dbg_Fine, "Worker#%d Face#%d send(%s, %d)=%d\n", worker_id, faceid,
					uri, msg_len, ret);
#endif // CefC_Debug
				/* Warning */
				if ( 0 < ret ){
					cef_log_write (CefC_Log_Warn, "Worker#%d Face#%d lost the last %d bytes.\n",
						worker_id, faceid, (msg_len - ret));
				} else {
					cef_log_write (CefC_Log_Warn, "Worker#%d Face#%d send err=%d:%s\n",
						worker_id, faceid, errno, strerror(errno));
				}
				hdl_wkr->drop_packets++;
				hdl_wkr->drop_bytes += (msg_len - ret);
				continue;
			}
			hdl_wkr->tx_packets++;
			hdl_wkr->tx_bytes += msg_len;
		}

		/* Free the pooled block 	*/
		cef_mpool_free (hdl_wkr->tx_que_mp, tx_elem);
	}
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, " worker#%d thread exit..\n", worker_id);
#endif // CefC_Debug

	pthread_exit (NULL);

	return NULL;
}

static int
cefnetd_transmit_worker_assign(
	CefT_Netd_Handle* hdl,				/* cefnetd handle */
	CefT_Tx_Elem *worker_elem
){
	int id = (worker_elem->faceids[0] % hdl->tx_worker_num);

	return id;
}

/* for plugin API */
CefT_Netd_Handle * cefnetd_get_myhdl (void);

long
cefnetd_transmit_packet_interval (
	uint16_t 		faceid, 		/* Face-ID indicating the destination 		*/
	long			tv_usec
) {
	CefT_Netd_Handle *hdl = cefnetd_get_myhdl ();
	int id = (faceid % hdl->tx_worker_num);

	transmit_worker_hdl[id].tx_packet_interval.tv_sec = 0;
	transmit_worker_hdl[id].tx_packet_interval.tv_usec = tv_usec;
	return tv_usec;
}
#else  // CefC_TxMultiThread
long
cefnetd_transmit_packet_interval (
	uint16_t 		faceid, 		/* Face-ID indicating the destination 		*/
	long			tv_usec
) {
	return tv_usec;
}
#endif // CefC_TxMultiThread

#define	CefC_QueuingRetryLimit	50		/* Queuing retry limit */

static void *
cefnetd_transmit_main_thread (
	void *p
) {
	CefT_Netd_Handle* hdl = p;		/* cefnetd handle */
	int	t_sleep = 0;

#ifdef	CefC_TxMultiThread
	CefT_Rngque		*tx_class[CefC_Num_TxQueClass];	/* 0:high, 1:normal, 2:low */
	int				idx_class;

	tx_class[0] = hdl->tx_que_high;
	tx_class[1] = hdl->tx_que;
	tx_class[2] = hdl->tx_que_low;
#endif  // CefC_TxMultiThread

	while (!cefnetd_running_f) {
		const struct timespec ts = { 0, 100*1000*1000 };
		nanosleep(&ts, NULL);
	}

#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "thread start..\n");
#endif // CefC_Debug

	while (cefnetd_running_f) {
		CefT_Tx_Elem* tx_elem;

		/* Pop one element from the TX Ring Queue 		*/
#ifdef	CefC_TxMultiThread
		tx_elem = (CefT_Tx_Elem*) cef_rngque_pop (tx_class[idx_class]);
#else   // CefC_TxMultiThread
		tx_elem = (CefT_Tx_Elem*) cef_rngque_pop (hdl->tx_que);
#endif  // CefC_TxMultiThread

		if (!tx_elem){

#ifdef	CefC_TxMultiThread
			if ( ++idx_class < CefC_Num_TxQueClass )
				continue;
			idx_class = 0;
#endif  // CefC_TxMultiThread

			struct timespec ts = { 0, 0 };

			if ( CefC_Sleep_Max < ++t_sleep )
				t_sleep = CefC_Sleep_Max;

			cefnetd_get_waittime(&ts, Cef_TxThreadSleep(t_sleep));
			pthread_mutex_lock(&cefnetd_txqueue_mutex);
			pthread_cond_timedwait(&cefnetd_txqueue_cond,
							&cefnetd_txqueue_mutex, &ts);
			pthread_mutex_unlock(&cefnetd_txqueue_mutex);
			continue;
		}
		t_sleep = 0;

#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "tx_elem=%p, msg_type=0x%02x, msg_len=%d\n", tx_elem, tx_elem->msg[CefC_O_Fix_Type], tx_elem->msg_len);
#endif // CefC_Debug

		if (tx_elem->type > CefC_Elem_Type_Object) {
			/* Free the pooled block 	*/
			cef_mpool_free (hdl->tx_que_mp, tx_elem);
			continue;
		}

#ifdef CefC_TxMultiThread
		/*==============================================================*
			Multi thread
		 *==============================================================*/
{		int i = 0, worker = 0;

		for ( i = 0; i < tx_elem->faceid_num; i++ ) {
			CefT_Tx_Elem *worker_elem;
			int		j = 0;

			/* Creates the forward packet buffer 				*/
			worker_elem = (CefT_Tx_Elem*) cef_mpool_alloc (hdl->tx_que_mp);
			worker_elem->type = tx_elem->type;
			memcpy(worker_elem->msg, tx_elem->msg, tx_elem->msg_len);
			worker_elem->msg_len = tx_elem->msg_len;
			worker_elem->faceids[0] = tx_elem->faceids[i];
			worker_elem->faceid_num = 1;

			worker = cefnetd_transmit_worker_assign(hdl, worker_elem);

			/* Pushes the forward message to worker queue */
			for ( j = 0; j < CefC_QueuingRetryLimit; usleep(100) ){
				if (cef_rngque_push (hdl->tx_worker_que[worker], worker_elem)){
					pthread_mutex_lock(&hdl->tx_worker_mutex[worker]);
					pthread_cond_signal(&hdl->tx_worker_cond[worker]);
					pthread_mutex_unlock(&hdl->tx_worker_mutex[worker]);
					break;		// Success.
				}

				if ( ++j == CefC_QueuingRetryLimit ){
					/* error:packet discard. */
					cef_log_write (CefC_Log_Info, "Failed to dispatch to Worker#%d, discarded packet.\n", worker);
					cef_mpool_free (hdl->tx_que_mp, worker_elem);
					break;
				}
			}
		}
}
#else // CefC_TxMultiThread
		/*==============================================================*
			Single thread
		 *==============================================================*/
		for (int i = 0 ; i < tx_elem->faceid_num ; i++) {
			unsigned char new_buff[CefC_Max_Length];
			unsigned char *ptr_msg = tx_elem->msg;
			size_t   msg_len = tx_elem->msg_len;

			if (!cef_face_check_active (tx_elem->faceids[i]))
				continue;

			if (cef_frame_get_opt_seqnum_f() && tx_elem->msg[CefC_O_Fix_Type] == CefC_PT_OBJECT) {
				uint32_t	seqnum;
				seqnum = cef_face_get_seqnum_from_faceid (tx_elem->faceids[i]);
				msg_len =
					cef_frame_seqence_update (new_buff, tx_elem->msg, seqnum);
				ptr_msg = new_buff;
			}
			cef_face_frame_send (tx_elem->faceids[i], ptr_msg, msg_len);
		}
#endif // CefC_TxMultiThread
		/* Free the pooled block 	*/
		cef_mpool_free (hdl->tx_que_mp, tx_elem);
	}
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, " exit..\n");
#endif // CefC_Debug

	pthread_exit (NULL);

	return NULL;
}

void
cefnetd_frame_send_txque_faces (
	void*			cefnetd_hdl,			/* cefnetd handle							*/
	uint16_t 		faceid_num, 			/* number of Face-ID				 		*/
	uint16_t 		faceid[], 				/* Face-ID indicating the destination 		*/
	unsigned char* 	msg, 					/* a message to send						*/
	size_t			msg_len					/* length of the message to send 			*/
) {
	CefT_Netd_Handle*	hdl = cefnetd_hdl;	/* cefnetd handle */
	CefT_Tx_Elem*	tx_elem;
	int		j;

	if ( faceid_num < 1 )
		return;

	/* Creates the forward object 				*/
	tx_elem = (CefT_Tx_Elem*) cef_mpool_alloc (hdl->tx_que_mp);
	if ( !tx_elem ){
		/* Error */
		cef_log_write (CefC_Log_Error, "%s cef_mpool_alloc(%s)\n", __func__, strerror(errno));
		return;
	}
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "tx_elem=%p, msg_type=0x%02x, msg_len=%d\n", tx_elem, msg[CefC_O_Fix_Type], msg_len);
#endif // CefC_Debug
	memset(tx_elem, 0x00, sizeof(CefT_Tx_Elem));
	switch (msg[CefC_O_Fix_Type] ){
	case CefC_PT_INTEREST:
	case CefC_PT_INTRETURN:
	case CefC_PT_REQUEST:
	case CefC_PT_REPLY:
		tx_elem->type = CefC_Elem_Type_Interest;	// hop-limit support
		break;
	default:
		tx_elem->type = CefC_Elem_Type_Object;
		break;
	}

	memcpy(tx_elem->faceids, faceid, sizeof(faceid[0])*faceid_num);
	tx_elem->faceid_num = faceid_num;

	tx_elem->msg_len = msg_len;
	memcpy (tx_elem->msg, msg, msg_len);

	/* Pushes the forward message to tx buffer */
	for ( j = 0; j < CefC_QueuingRetryLimit; j++ ){
		struct timespec ts = { 0, 0 };
		if (cef_rngque_push (hdl->tx_que, tx_elem)){
			pthread_mutex_lock(&cefnetd_txqueue_mutex);
			pthread_cond_signal(&cefnetd_txqueue_cond);
			pthread_mutex_unlock(&cefnetd_txqueue_mutex);
			break;
		}
		ts.tv_nsec = (j + 1) * 100;
		nanosleep(&ts, NULL);
	}

	if ( j == CefC_QueuingRetryLimit ){
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Fine, "cef_rngque_push failed, discarded packet.\n");
#endif // CefC_Debug
		cef_mpool_free (hdl->tx_que_mp, tx_elem);
	} else if ( j ){
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "cef_rngque_push retry, %d times.\n", j);
#endif // CefC_Debug
	}
}

void
cefnetd_frame_send_txque (
	void*			cefnetd_hdl,			/* cefnetd handle							*/
	uint16_t 		faceid, 				/* Face-ID indicating the destination 		*/
	unsigned char* 	msg, 					/* a message to send						*/
	size_t			msg_len					/* length of the message to send 			*/
) {
	CefT_Netd_Handle*	hdl = cefnetd_hdl;	/* cefnetd handle */
	uint16_t 		faceids[CefC_Elem_Face_Num];	/* outgoing FaceIDs that were 		*/

	memset(faceids, 0x00, sizeof(faceids));
	faceids[0] = faceid;

	cefnetd_frame_send_txque_faces(hdl, 1, faceids, msg, msg_len);
}

#define CefC_Fib_DefaultRoute_Len	4
#define CefC_Fib_Addr_Max		32
#define CefC_Fib_Addr_Siz		INET6_ADDRSTRLEN

/*--------------------------------------------------------------------------------------
	Reads the FIB configuration file
----------------------------------------------------------------------------------------*/
static int
cefnetd_fib_parse_line (
	char* p, 									/* target string for trimming 			*/
	char* name,									/* name string after trimming			*/
	char* prot,									/* protocol string after trimming		*/
	char addr[CefC_Fib_Addr_Max][CefC_Fib_Addr_Siz]
) {
	int addr_num = 0;
	char* wp;


	if ((*p == 0x23) || (*p == 0x0D) || (*p == 0x0A)|| (*p == 0x00)) {
		return (0);
	}

	wp = p;
	while (*wp) {
		if ((*wp == 0x0D) || (*wp == 0x0A)) {
			*wp = 0x00;
		}
		wp++;
	}

	/* URI 				*/
	wp = strtok (p," \t");
	if (wp) {
		strcpy (name, wp);
	} else {
		return (0);
	}

	/* protocol			*/
	wp = strtok (NULL, " \t");
	if (wp) {
		strcpy (prot, wp);
		if (strcmp(prot, "tcp") != 0 && strcmp(prot, "udp") != 0) {
			return (0);
		}
	} else {
		return (0);
	}

	/* addresses		*/
	while (wp != NULL) {

		wp = strtok (NULL, " \t");

		if (wp) {
			if (cef_fib_check_addr(wp)) {
				strcpy (addr[addr_num], wp);
				addr_num++;
			}
		}

		if (addr_num == CefC_Fib_Addr_Max) {
			break;
		}
	}

	return (addr_num);
}

static int
cefnetd_route_msg_create(
	unsigned char *msgbuf,
	uint8_t		op,
	uint8_t		prot,
	const char *uri,
	int			addr_num,
	char		addr[CefC_Fib_Addr_Max][CefC_Fib_Addr_Siz]
) {
	int i, index = 0;
	uint16_t	uri_len = 0;

	if ( !uri || uri[0] <= ' ' )
		return (-1);

	msgbuf[index++] = op;
	msgbuf[index++] = prot;
	uri_len = strlen(uri);
	if ( CefC_NAME_MAXLEN < uri_len ){
		cef_log_write (CefC_Log_Error,
			"URL is too long (%d bytes), cefore does not support T_NAMEs longer than %u bytes.\n",
				uri_len, CefC_NAME_MAXLEN);
		return (-1);
	}
	memcpy(&msgbuf[index], &uri_len, sizeof(uri_len));
	index += sizeof(uri_len);
	memcpy(&msgbuf[index], uri, uri_len);
	index += uri_len;

	for ( i = 0; i < addr_num; i++ ){
		struct addrinfo hints;
		struct addrinfo* gai_res;
		struct addrinfo* gai_cres;
		uint8_t host_len;
		char host[CefC_NAME_BUFSIZ] = {0};
		char addr_str[INET6_ADDRSTRLEN];
		char port_str[INET6_ADDRSTRLEN], *port_ptr = NULL;
		char ifname[INET6_ADDRSTRLEN], *ifname_ptr = NULL;
		char *IPv6_endmark = NULL;
		int	 err;

		memset (&hints, 0, sizeof (hints));
		memset (addr_str, 0, sizeof (addr_str));
		memset (port_str, 0, sizeof (port_str));
		memset (ifname, 0, sizeof (ifname));

		strcpy(host, addr[i]);
		IPv6_endmark = strchr(host, ']');	/* Rules for enclosing IPv6 strings in [] */

		if ( host[0] != '[' ){			/* not IPv6 */
			if ( (port_ptr = strchr(host, ':')) != NULL ){
				strcpy(port_str, port_ptr);
				*port_ptr++ = '\0';
			}
		} else if ( IPv6_endmark ) {	/* IPv6 */
			*IPv6_endmark++ = '\0';
			if ( (port_ptr = strchr(IPv6_endmark, ':')) != NULL ){
				strcpy(port_str, port_ptr);
				*port_ptr++ = '\0';
			}
			strcpy(host, &host[1]);
			/*-----------------------------------------------------------*
				When specifying the next hop with a link-local address,
				you must also specify the interface name with the IFNAME
			 *-----------------------------------------------------------*/
			ifname_ptr = strchr(host, '%');
			if ( ifname_ptr ){
				strcpy(ifname, ifname_ptr);
			}
		}
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "host=%s, port=%s, ifname=%s\n", host, port_str, ifname);
#endif // CefC_Debug

		hints.ai_family = AF_UNSPEC;
		hints.ai_flags = AI_NUMERICSERV;
		if (prot != CefC_Face_Type_Tcp) {
			hints.ai_socktype = SOCK_DGRAM;
		} else {
			hints.ai_socktype = SOCK_STREAM;
		}

		/* This getaddrinfo converts the host name to an IPv4/v6 address */
		if ((err = getaddrinfo (host, port_ptr, &hints, &gai_res)) != 0) {
			cef_log_write (CefC_Log_Error,
				"getaddrinfo(%s)=%s\n", host, gai_strerror(err));
			return (-1);
		}
		for (gai_cres = gai_res ; gai_cres != NULL && !addr_str[0]; gai_cres = gai_cres->ai_next) {
			struct sockaddr_in *ai = (struct sockaddr_in *)(gai_cres->ai_addr);
			struct sockaddr_in6 *ai6 = (struct sockaddr_in6 *)(gai_cres->ai_addr);

			switch ( ai->sin_family ){
			case AF_INET:
				inet_ntop(ai->sin_family, &(ai->sin_addr), addr_str, sizeof(addr_str));
				sprintf(host, "%s", addr_str);
				break;
			case AF_INET6:
				inet_ntop(ai6->sin6_family, &(ai6->sin6_addr), addr_str, sizeof(addr_str));
				if ( ifname[0] ){
					sprintf(host, "[%s%s]", addr_str, ifname);
				} else {
					sprintf(host, "[%s]", addr_str);
				}
				break;
			default:
				continue;
			}
		}
		freeaddrinfo (gai_res);
		if ( port_str[0] ){
			strcat(host, port_str);
		}

#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "host=%s, addr=%s\n", host, addr_str);
#endif // CefC_Debug
		host_len = strlen(host);
		msgbuf[index++] = host_len;
		memcpy(&msgbuf[index], host, host_len);
		index += host_len;
	}
	return index;
}

static int									/* Returns a negative value if it fails 	*/
cefnetd_config_fib_read (
	CefT_Netd_Handle* hdl					/* cefnetd handle							*/
) {
	char	ws[PATH_MAX];
	FILE*	fp = NULL;
	char	buff[BUFSIZ+1];

	cef_client_config_dir_get (ws);
	strcat (ws, "/cefnetd.fib");

	fp = fopen (ws, "r");
	if (fp == NULL) {
		fp = fopen (ws, "w");
		if (fp == NULL) {
			cef_log_write (CefC_Log_Error, "Failed to open the FIB File (%s)\n", ws);
			return (-1);
		}
		fclose (fp);
		fp = fopen (ws, "r");
	}

	while (fgets (buff, sizeof(buff), fp) != NULL) {
		char	uri[CefC_NAME_BUFSIZ];
		char	addr[CefC_Fib_Addr_Max][CefC_Fib_Addr_Siz];
		char	prot[CefC_NAME_BUFSIZ];
		char	face_type = CefC_Face_Type_Udp;
		unsigned char	routemsg[BUFSIZ] = { 0 };
		int		routemsg_len, addr_num;
		int		change_f = 0;

		buff[sizeof(buff)-1] = 0;

		if (strlen (buff) >= BUFSIZ) {
			cef_log_write (CefC_Log_Warn,
				"[cefnetd.fib] Detected the too long line:%s\n", buff);
			continue;
		}

		if ((buff[0] == '#') || isspace(buff[0])) {
			continue;
		}

		/* parse the read line		*/
		addr_num = cefnetd_fib_parse_line (buff, uri, prot, addr);
		if (addr_num < 1) {
			cef_log_write (CefC_Log_Warn, "[cefnetd.fib] Invalid line:%s\n", buff);
			continue;
		}
		if ( !strcasecmp(prot, "TCP") ){
			face_type = CefC_Face_Type_Tcp;
		}

		routemsg_len = cefnetd_route_msg_create(routemsg,
				CefC_Fib_Route_Ope_Add, face_type, uri, addr_num, addr);

		if ( routemsg_len <= 0 )
			continue;

		if ( cefnetd_route_msg_check (hdl, routemsg, routemsg_len) < 0 )
			continue;

		cef_fib_route_msg_read (hdl->fib, routemsg, routemsg_len,
				CefC_Fib_Entry_Static, &change_f, NULL);
	}

	fclose (fp);

	return (1);
}


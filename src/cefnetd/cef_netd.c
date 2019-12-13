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
 * cef_netd.c
 */

#define __CEF_NETD_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include "cef_netd.h"
#include "cef_status.h"


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

#define CefC_Connection_Type_Num		5
#define CefC_Connection_Type_Udp		0
#define CefC_Connection_Type_Tcp		1
#define CefC_Connection_Type_Csm		2
#define CefC_Connection_Type_Ndn		3
#define CefC_Connection_Type_Ccr		4

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

typedef struct {
	uint16_t 		faceid;
	unsigned char 	name[CefC_Max_Length];
	uint16_t 		name_len;
	uint8_t 		match_type;				/* Exact or Prefix */
} CefT_App_Reg;

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

#ifdef CefC_ContentStore
static uint64_t cefinfo_push_time = 0;
#endif // CefC_ContentStore

#ifdef CefC_Debug
static char cnd_dbg_msg[2048];
#endif // CefC_Debug

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Reads the config file
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_config_read (
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
	unsigned char* rsp, 
	int fd
);
/*--------------------------------------------------------------------------------------
	Handles the message to reg/dereg application name
----------------------------------------------------------------------------------------*/
static int
cefnetd_input_app_reg_command (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	CefT_Parsed_Message* pm, 				/* Parsed CEFORE message					*/
	CefT_Parsed_Opheader* poh,				/* Parsed Option Header						*/
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
	unsigned char* buff
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
/*--------------------------------------------------------------------------------------
	Handles the input message from NDN network
----------------------------------------------------------------------------------------*/
static int
cefnetd_ndn_input_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	int faceid									/* Face-ID that message arrived 		*/
);
/*--------------------------------------------------------------------------------------
	Handles the input message from ccored
----------------------------------------------------------------------------------------*/
static int
cefnetd_ccr_input_process (
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
	cefnetd_udp_input_process,
	cefnetd_tcp_input_process,
	cefnetd_csm_input_process,
	cefnetd_ndn_input_process, 
	cefnetd_ccr_input_process
};
#ifdef CefC_Ccore
/*--------------------------------------------------------------------------------------
	Handles the operation from ccored
----------------------------------------------------------------------------------------*/
static int
cefnetd_ccr_invalid_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	unsigned char* msg, 
	int msg_len
);
static int
cefnetd_ccr_r_neighbor_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	unsigned char* msg, 
	int msg_len
);
static int
cefnetd_ccr_r_fib_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	unsigned char* msg, 
	int msg_len
);
static int
cefnetd_ccr_s_fib_add_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	unsigned char* msg, 
	int msg_len
);
static int
cefnetd_ccr_s_fib_del_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	unsigned char* msg, 
	int msg_len
);
static int
cefnetd_ccr_r_cache_prefix_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	unsigned char* msg, 
	int msg_len
);
static int
cefnetd_ccr_r_cache_cap_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	unsigned char* msg, 
	int msg_len
);
static int
cefnetd_ccr_s_cache_cap_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	unsigned char* msg, 
	int msg_len
);
static int
cefnetd_ccr_s_lifetime_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	unsigned char* msg, 
	int msg_len
);
static int
cefnetd_ccr_s_write_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	unsigned char* msg, 
	int msg_len
);
static int
cefnetd_ccr_r_status_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	unsigned char* msg, 
	int msg_len
);
static int
cefnetd_ccr_s_status_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	unsigned char* msg, 
	int msg_len
);

static int	
(*cefnetd_ccr_operation_process[CcoreC_Ope_Num]) (
	CefT_Netd_Handle* hdl,
	int fd,
	unsigned char* msg, 
	int msg_len
) = {
	cefnetd_ccr_invalid_process,
	cefnetd_ccr_r_neighbor_process,
	cefnetd_ccr_r_fib_process,
	cefnetd_ccr_s_fib_add_process, 
	cefnetd_ccr_s_fib_del_process, 
	cefnetd_ccr_r_cache_prefix_process, 
	cefnetd_ccr_r_cache_cap_process, 
	cefnetd_ccr_s_cache_cap_process, 
	cefnetd_ccr_s_lifetime_process, 
	cefnetd_ccr_s_write_process, 
	cefnetd_ccr_r_status_process, 
	cefnetd_ccr_s_status_process
};
#endif // CefC_Ccore

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
	int msg_size							/* size of received message(s)				*/
);
/*--------------------------------------------------------------------------------------
	Seeks the top of the frame from the receive buffer
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_messege_head_seek (
	CefT_Face* face,						/* the face structure						*/
	uint16_t* payload_len,
	uint16_t* header_len
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
	uint16_t header_len						/* Header Length of this message			*/
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
	uint16_t header_len						/* Header Length of this message			*/
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
	uint16_t header_len						/* Header Length of this message			*/
);
/*--------------------------------------------------------------------------------------
	Handles the received Cefping Request
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_pingreq_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len						/* Header Length of this message			*/
);
/*--------------------------------------------------------------------------------------
	Handles the received Cefping Replay
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_pingrep_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len						/* Header Length of this message			*/
);
/*--------------------------------------------------------------------------------------
	Handles the received Cefinfo Request
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_tracereq_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len						/* Header Length of this message			*/
);
/*--------------------------------------------------------------------------------------
	Handles the received Cefinfo Replay
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_tracerep_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len						/* Header Length of this message			*/
);

static int									/* Returns a negative value if it fails 	*/
(*cefnetd_incoming_msg_process[CefC_Msg_Process_Num]) (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len						/* Header Length of this message			*/
) = {
	cefnetd_incoming_interest_process,
	cefnetd_incoming_object_process,
	cefnetd_incoming_intreturn_process,
	cefnetd_incoming_tracereq_process,
	cefnetd_incoming_tracerep_process,
	cefnetd_incoming_pingreq_process,
	cefnetd_incoming_pingrep_process
};
/*--------------------------------------------------------------------------------------
	Handles the received Interest message has the Symbolic Code
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_interest_with_symbolic_code_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	CefT_Parsed_Message* pm, 				/* Parsed CEFORE message					*/
	CefT_Parsed_Opheader* poh				/* Parsed Option Header						*/
);
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
#ifdef CefC_ContentStore
/*--------------------------------------------------------------------------------------
	Handles the received message(s) from csmgrd
----------------------------------------------------------------------------------------*/
static int										/* No care now							*/
cefnetd_input_message_from_csmgrd_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	unsigned char* msg, 						/* the received message(s)				*/
	int msg_size								/* size of received message(s)			*/
);
/*--------------------------------------------------------------------------------------
	Seeks the top of the frame from the receive buffer
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_csmgrd_messege_head_seek (
	CefT_Cs_Stat* cs_stat, 
	uint16_t* payload_len,
	uint16_t* header_len
);
/*--------------------------------------------------------------------------------------
	Handles the received Interest message
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_csmgrd_interest_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len						/* Header Length of this message			*/
);
/*--------------------------------------------------------------------------------------
	Handles the received Content Object message
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_csmgrd_object_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len						/* Header Length of this message			*/
);
/*--------------------------------------------------------------------------------------
	Handles the received Cefping Request
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_csmgrd_pingreq_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len						/* Header Length of this message			*/
);
/*--------------------------------------------------------------------------------------
	Handles the received Cefinfo Request
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_csmgrd_tracereq_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len						/* Header Length of this message			*/
);

static int									/* Returns a negative value if it fails 	*/
(*cefnetd_incoming_csmgrd_msg_process[CefC_Msg_Process_Num]) (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len						/* Header Length of this message			*/
) = {
	cefnetd_incoming_csmgrd_interest_process,
	cefnetd_incoming_csmgrd_object_process,
	cefnetd_incoming_intreturn_process,
	cefnetd_incoming_csmgrd_tracereq_process,
	cefnetd_incoming_tracerep_process,
	cefnetd_incoming_csmgrd_pingreq_process,
	cefnetd_incoming_pingrep_process
};

#ifdef CefC_Cefinfo
/*--------------------------------------------------------------------------------------
	Seeks the csmgrd and creates the cefinfo response
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_external_cache_seek (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	CefT_Parsed_Message* pm,				/* Structure to set parsed CEFORE message	*/
	CefT_Parsed_Opheader* poh
);
#endif // CefC_Cefinfo

#endif // CefC_ContentStore
/*--------------------------------------------------------------------------------------
	Clean PIT entries
----------------------------------------------------------------------------------------*/
static void
cefnetd_pit_cleanup (
	CefT_Netd_Handle* hdl, 						/* cefnetd handle						*/
	uint64_t nowt								/* current time (usec) 					*/
);
/*--------------------------------------------------------------------------------------
	Clean FIB entries
----------------------------------------------------------------------------------------*/
static void
cefnetd_fib_cleanup (
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
	CefT_Parsed_Message* pm					/* Structure to set parsed CEFORE message	*/
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
	CefT_Parsed_Message* pm					/* Structure to set parsed CEFORE message	*/
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
	CefT_Parsed_Message* pm					/* Structure to set parsed CEFORE message	*/
);

static int									/* Returns a negative value if it fails 	*/
(*cefnetd_command_process[CefC_Cmd_Num]) (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	CefT_Parsed_Message* pm					/* Structure to set parsed CEFORE message	*/
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
	CefT_Parsed_Message* pm					/* Structure to set parsed CEFORE message	*/
);
/*--------------------------------------------------------------------------------------
	Accepts and receives the frame(s) from local face
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cefnetd_input_from_local_process (
	CefT_Netd_Handle* hdl					/* cefnetd handle							*/
);

/*--------------------------------------------------------------------------------------
	Handles the elements of TX queue
----------------------------------------------------------------------------------------*/
static int										/* No care now							*/
cefnetd_input_from_txque_process (
	CefT_Netd_Handle* hdl						/* cefnetd handle						*/
);
/*--------------------------------------------------------------------------------------
	Prepares the UDP and TCP sockets to be polled
----------------------------------------------------------------------------------------*/
static int										/* number of the poll which has events	*/
cefnetd_poll_socket_prepare (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	struct pollfd fds[],
	int fd_type[],
	int faceids[]
);
/*--------------------------------------------------------------------------------------
	Obtains my NodeID (IP Address)
----------------------------------------------------------------------------------------*/
static void
cefnetd_node_id_get (
	CefT_Netd_Handle* hdl						/* cefnetd handle						*/
);

#if defined (CefC_Cefping) || defined (CefC_Cefinfo)

#ifndef CefC_Android
/*--------------------------------------------------------------------------------------
	Obtains my NodeID (IP Address)
----------------------------------------------------------------------------------------*/
static int 
cefnetd_matched_node_id_get (
	CefT_Netd_Handle* hdl, 
	unsigned char* peer_node_id, 
	int peer_node_id_len, 
	unsigned char* node_id
);
#endif // CefC_Android

#endif // (CefC_Cefping || CefC_Cefinfo)

#ifdef CefC_Dtc
/*--------------------------------------------------------------------------------------
	Resend Cefore-DTC Interest
----------------------------------------------------------------------------------------*/
void
cefnetd_dtc_resnd (
	CefT_Netd_Handle* hdl, 						/* cefnetd handle						*/
	uint64_t nowt								/* current time (usec) 					*/
);
#endif // CefC_Dtc

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
	char 	conf_path[1024];
	
	/* Allocates a block of memory for cefnetd handle 	*/
	hdl = (CefT_Netd_Handle*) malloc (sizeof (CefT_Netd_Handle));
	if (hdl == NULL) {
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
	
	/* Initialize the frame module 						*/
	cef_client_config_dir_get (conf_path);
	cef_frame_init ();
	res = cef_valid_init (conf_path);
	if (res < 0) {
		cef_log_write (CefC_Log_Error, "Failed to read the cefnetd.key\n");
		return (NULL);
	}
	cef_log_write (CefC_Log_Info, "Loading cefnetd.key ... OK\n");
	
	/* Reads the config file 				*/
	hdl->port_num = cef_client_listen_port_get ();
	res = cefnetd_config_read (hdl);
	if (res < 0) {
		cef_log_write (CefC_Log_Error, "Failed to read the cefnetd.conf\n");
		return (NULL);
	}
	cef_log_write (CefC_Log_Info, "Loading cefnetd.conf ... OK\n");
	
	/* Creates listening socket(s)			*/
	res = cefnetd_faces_init (hdl);
	if (res < 0) {
		return (NULL);
	}
	srand ((unsigned) time (NULL));
	hdl->cefrt_seed = (uint8_t)(rand () + 1);
	cef_log_write (CefC_Log_Info, "Creation the listen faces ... OK\n");
	
	/* Creates and initialize FIB			*/
	hdl->fib = cef_hash_tbl_create ((uint16_t) hdl->fib_max_size);
	cef_fib_init (hdl->fib);
	cef_face_update_listen_faces (
		hdl->inudpfds, hdl->inudpfaces, &hdl->inudpfdc, 
		hdl->intcpfds, hdl->intcpfaces, &hdl->intcpfdc);
	hdl->fib_clean_t = cef_client_present_timeus_calc () + 1000000;
	cef_log_write (CefC_Log_Info, "Creation FIB ... OK\n");
	
	/* Creates the Command Filter(s) 		*/
	cefnetd_command_filter_init (hdl);
	
	/* Creates PIT 							*/
	hdl->pit = cef_hash_tbl_create ((uint16_t) hdl->pit_max_size);
	hdl->pit_clean_t = cef_client_present_timeus_calc () + 1000000;
	cef_log_write (CefC_Log_Info, "Creation PIT ... OK\n");
	
	/* Prepares sockets for applications 	*/
	for (res = 0 ; res < CefC_App_Conn_Num ; res++) {
		hdl->app_fds[res] = -1;
		hdl->app_faces[res] = -1;
	}
	hdl->app_fds_num = 0;
	
#ifdef CefC_ContentStore
	/* Reads the config file 				*/
	hdl->cs_stat = cef_csmgr_stat_create ();
	if (hdl->cs_stat == NULL) {
		cef_log_write (CefC_Log_Error, "Failed to init Content Store\n");
		return (NULL);
	}
	if (hdl->cs_stat->cache_type == CefC_Cache_Type_Excache) {
		cef_log_write (CefC_Log_Info, "Initialization Content Store ... OK\n");
	} else {
		cef_log_write (CefC_Log_Info, "Not use Content Store\n");
	}
	
	/* set send content rate 	*/
	hdl->send_rate = (double)(8.0 / (double) hdl->fwd_rate);
	hdl->send_next = 0;
#elif CefC_Dtc
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "DTC stat create\n");
#endif // CefC_Debug
	hdl->cs_stat = cef_csmgr_dtc_stat_create ();
	if (hdl->cs_stat == NULL) {
		cef_log_write (CefC_Log_Error, "Failed to init Content Store\n");
		return (NULL);
	}
	/* set send content rate 	*/
	hdl->send_rate = (double)(8.0 / (double) hdl->fwd_rate);
	hdl->send_next = 0;
	hdl->dtc_resnd_t = cef_client_present_timeus_calc () + 10000000;
	if (cef_pit_dtc_init() < 0) {
		cef_log_write (CefC_Log_Error, "Failed to init Cefore-DTC PIT\n");
		return (NULL);
	}
#else // CefC_ContentStore
	hdl->cs_stat = NULL;
#endif // CefC_ContentStore
	
#ifdef CefC_Neighbour
	/* Inits neighbor managements 	*/
	cefnetd_nbr_init (hdl);
#endif // CefC_Neighbour
	/* Obtains my NodeID (IP Address) 	*/
	cefnetd_node_id_get (hdl);
	
	/* Creates App Reg table 		*/
	hdl->app_reg = cef_hash_tbl_create (64);
	
	/* Inits the plugin 			*/
	cef_plugin_init (&(hdl->plugin_hdl));
	
#ifdef CefC_Mobility
	cef_mb_plugin_init (
		&hdl->plugin_hdl.mb, hdl->plugin_hdl.tx_que, hdl->plugin_hdl.tx_que_mp, 
		hdl->rtts, hdl->nbr_num, (uint32_t)(hdl->nbr_mng_intv / 1000), &vret);
#endif // CefC_Mobility
	
	cef_tp_plugin_init (
		&hdl->plugin_hdl.tp, hdl->plugin_hdl.tx_que, hdl->plugin_hdl.tx_que_mp, vret);
	
#ifdef CefC_NdnPlugin
	res = cef_ndn_plugin_init (&hdl->plugin_hdl.ndn, hdl->fib);
	
	if (res > 0) {
		res = cef_face_ndn_listen_face_create (hdl->plugin_hdl.ndn->port_num);
		
		if (res > 0) {
			/* Prepares file descriptors to listen 		*/
			hdl->inndnfaces[0] = (uint16_t) res;
			hdl->inndnfds[0].fd = cef_face_get_fd_from_faceid ((uint16_t) res);
			hdl->inndnfds[0].events = POLLIN | POLLERR;
			hdl->inndnfdc = 1;
			
			hdl->plugin_hdl.ndn->listen_faceid 	= hdl->inndnfaces[0];
			hdl->plugin_hdl.ndn->listen_fd 		= hdl->inndnfds[0].fd;
			
			cef_log_write (CefC_Log_Info, "Initialization the NDN plugin ... OK\n");
		} else {
			cefnetd_handle_destroy (hdl);
			cef_log_write (CefC_Log_Error, 
				"NDN init is failed, cause NFD is running\n");
			return (NULL);
		}
	}
#endif // CefC_NdnPlugin
	
	/* Records the user which launched cefnetd 		*/
#ifdef CefC_Android
	wp = cef_android_user_name_get ();
#else // CefC_Android
	wp = getenv ("USER");
#endif // CefC_Android

	if (wp == NULL) {
		cefnetd_handle_destroy (hdl);
		cef_log_write (CefC_Log_Error, 
			"Failed to obtain $USER launched cefnetd\n");
		return (NULL);
	}
	memset (hdl->launched_user_name, 0, CefC_Ctrl_User_Len);
	strcpy (hdl->launched_user_name, wp);
	
#ifdef CefC_Ccore
	hdl->rt_hdl = ccore_router_handle_create (conf_path);
	
	if (hdl->rt_hdl) {
		
		res = ccore_valid_cefnetd_init (conf_path);
		
		if (res < 0) {
			cefnetd_handle_destroy (hdl);
			return (NULL);
		}
		if (hdl->rt_hdl->sock != -1) {
			cef_log_write (CefC_Log_Info, "Initialization controller ... OK\n");
		} else {
			hdl->rt_hdl->reconnect_time = hdl->nowtus + 3000000;
		}
	}
#endif // CefC_Ccore
#ifdef CefC_Ser_Log
	if (cef_ser_log_init (conf_path) < 0) {
		cefnetd_handle_destroy (hdl);
		return (NULL);
	}
#endif // CefC_Ser_Log
	
	return (hdl);
}
/*--------------------------------------------------------------------------------------
	Destroys the cefnetd handle
----------------------------------------------------------------------------------------*/
void
cefnetd_handle_destroy (
	CefT_Netd_Handle* hdl						/* cefnetd handle to destroy			*/
) {
	char sock_path[1024];
	
	/* destroy plugins 		*/
#ifdef CefC_NdnPlugin
	cef_ndn_plugin_destroy (hdl->plugin_hdl.ndn);
#endif // CefC_NdnPlugin
	cef_tp_plugin_destroy (hdl->plugin_hdl.tp);
#ifdef CefC_Mobility
	cef_mb_plugin_destroy (hdl->plugin_hdl.mb);
#endif // CefC_Mobility
	cef_plugin_destroy (&(hdl->plugin_hdl));
	
#ifdef CefC_Neighbour
	/* destroy neighbor management 	*/
	cefnetd_nbr_destroy (hdl);
#endif // CefC_Neighbour
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, 
		"<STAT> Rx Frames      = "FMTU64"\n", hdl->stat_recv_frames);
	cef_dbg_write (CefC_Dbg_Fine, 
		"<STAT> Tx Frames      = "FMTU64"\n", hdl->stat_send_frames);
	cef_dbg_write (CefC_Dbg_Fine, 
		"<STAT> No PIT Frames  = "FMTU64"\n", stat_nopit_frames);
	cef_dbg_write (CefC_Dbg_Fine, 
		"<STAT> Frame Size Cnt = "FMTU64"\n", stat_rcv_size_cnt);
	cef_dbg_write (CefC_Dbg_Fine, 
		"<STAT> Frame Size Sum = "FMTU64"\n", stat_rcv_size_sum);
	if (stat_rcv_size_min > 65535) {
		stat_rcv_size_min = 0;
	}
	cef_dbg_write (CefC_Dbg_Fine, 
		"<STAT> Frame Size Min = "FMTU64"\n", stat_rcv_size_min);
	cef_dbg_write (CefC_Dbg_Fine, 
		"<STAT> Frame Size Max = "FMTU64"\n", stat_rcv_size_max);
#endif // CefC_Debug

	cefnetd_faces_destroy (hdl);
#ifdef CefC_ContentStore
	cef_csmgr_stat_destroy (&hdl->cs_stat);
#elif CefC_Dtc
	/* Destroy Cefore-DTC */
	cef_pit_dtc_destroy();
	/* Destroy CS Stat */
	cef_csmgr_dtc_stat_destroy (&hdl->cs_stat);
#endif // CefC_ContentStore
#ifdef CefC_Ser_Log
	cef_ser_log_destroy ();
#endif // CefC_Ser_Log
	free (hdl);
#ifdef CefC_Android
	/* Process for Android next running	*/
	hdl = NULL;
	stat_nopit_frames = 0;
	stat_nopit_frames = 0;
	stat_rcv_size_cnt = 0;
	stat_rcv_size_min = 65536;
	stat_rcv_size_max = 0;
	stat_rcv_size_sum = 0;
#endif // CefC_Android
	
	cef_client_local_sock_name_get (sock_path);
	unlink (sock_path);
	
#ifdef CefC_Ccore
	ccore_handle_destroy (&hdl->rt_hdl);
#endif // CefC_Ccore
	
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
	int fd_type[CefC_Listen_Face_Max * 2];
	int faceids[CefC_Listen_Face_Max * 2];
	int fdnum;
	
#ifdef CefC_Ccore
	uint64_t ret_cnt = 5;
#endif
	
	while (cefnetd_running_f) {
		
		/* Calculates the present time 						*/
		nowt = cef_client_present_timeus_calc ();
		hdl->nowtus = nowt;
		
#ifdef CefC_Ccore
		if (hdl->rt_hdl) {
			/* Re-connect to ccored 		*/
			if ((hdl->rt_hdl->sock == -1) &&
				(hdl->nowtus > hdl->rt_hdl->reconnect_time)) {
				cef_log_write (CefC_Log_Info, 
						"cefnetd is trying to connect with ccored ...\n");
				hdl->rt_hdl->sock = 
					ccore_connect_tcp_to_ccored (
							hdl->rt_hdl->controller_id, hdl->rt_hdl->port_str);
				if (hdl->rt_hdl->sock != -1) {
					cef_log_write (CefC_Log_Info, 
						"cefnetd connects to that ccored\n");
					hdl->rt_hdl->reconnect_time = 0;
					ret_cnt = 3;
				} else {
					cef_log_write (CefC_Log_Info, 
						"cefnetd failed to connect with ccored\n");
					nowt = cef_client_present_timeus_calc ();
					hdl->nowtus = nowt;
					hdl->rt_hdl->reconnect_time = hdl->nowtus + 1000000 * ret_cnt;
					
					if (ret_cnt < 60) {
						ret_cnt += 5;
					}
				}
			}
		}
#endif // CefC_Ccore
		
		/* Cleans PIT entries 		*/
		cefnetd_pit_cleanup (hdl, nowt);

#ifdef CefC_Dtc
		/* Resend Cefore-DTC Entry */
		cefnetd_dtc_resnd (hdl, nowt);
#endif // CefC_Dtc
		
		/* Cleans FIB entries 		*/
		cefnetd_fib_cleanup (hdl, nowt);
#ifdef CefC_Neighbour
		/* Manages the neighbor cefnetd status				*/
		cefnetd_nbr_management (hdl, nowt);
#endif // CefC_Neighbour
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
		
		/* Receives the frame(s) from the listen port 		*/
		fdnum = cefnetd_poll_socket_prepare (hdl, fds, fd_type, faceids);
		res = poll (fds, fdnum, 1);
		
		for (i = 0 ; res > 0 && i < fdnum ; i++) {
			
			if (fds[i].revents != 0) {
				res--;
				if (fds[i].revents & POLLIN) {
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
					}
				}
				
			}
		}
		
		cefnetd_input_from_txque_process (hdl);
		
#ifdef CefC_ContentStore
		if ((hdl->cs_stat->cache_type != CefC_Cache_Type_None) &&
			(nowt > cefinfo_push_time)) {
			cef_csmgr_excache_item_push (hdl->cs_stat);
			cefinfo_push_time = nowt + 500000;
		}
#endif // CefC_ContentStore
	}
}
/*--------------------------------------------------------------------------------------
	Prepares the UDP and TCP sockets to be polled
----------------------------------------------------------------------------------------*/
static int										/* number of the poll which has events	*/
cefnetd_poll_socket_prepare (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	struct pollfd fds[],
	int fd_type[],
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
		} else {
			for (n = i ; n < hdl->inudpfdc - 1 ; n++) {
				hdl->inudpfds[n].fd = hdl->inudpfds[n + 1].fd;
				hdl->inudpfaces[n] 	= hdl->inudpfaces[n + 1];
			}
			hdl->inudpfdc--;
			i--;
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
#ifdef CefC_Neighbour
	for (i = 0 ; i < hdl->nbr_num ; i++) {
		if ((cef_face_check_active (hdl->nbrs[i].faceid) > 0) &&
			(hdl->nbrs[i].fd_tcp_f)) {
			
			fds[res].events = POLLIN | POLLERR;
			fds[res].fd = hdl->nbrs[i].fd;
			fd_type[res] = CefC_Connection_Type_Tcp;
			faceids[res] = hdl->nbrs[i].faceid;
			res++;
		}
	}
#endif // CefC_Neighbour
	
#ifdef CefC_ContentStore
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
#endif // CefC_ContentStore
	
#ifdef CefC_NdnPlugin
	if (hdl->inndnfdc) {
		fds[res].events = POLLIN | POLLERR;
		fds[res].fd = hdl->inndnfaces[0];
		fd_type[res] = CefC_Connection_Type_Ndn;
		faceids[res] = 0;
		res++;
	}
#endif // CefC_NdnPlugin
	
#ifdef CefC_Ccore
	if (hdl->rt_hdl) {
		if (hdl->rt_hdl->sock != -1) {
			fds[res].events = POLLIN | POLLERR;
			fds[res].fd = hdl->rt_hdl->sock;
			fd_type[res] = CefC_Connection_Type_Ccr;
			faceids[res] = 0;
			res++;
		}
	}
#endif // CefC_Ccore
	
	return (res);
}
/*--------------------------------------------------------------------------------------
	Handles the elements of TX queue
----------------------------------------------------------------------------------------*/
static int										/* No care now							*/
cefnetd_input_from_txque_process (
	CefT_Netd_Handle* hdl						/* cefnetd handle						*/
) {
	CefT_Tx_Elem* tx_elem;
	int i;
	unsigned char hoplimit;
	uint32_t seqnum;

#if (defined CefC_ContentStore) || (defined CefC_Dtc)
	CefT_Cs_Tx_Elem* cs_tx_elem;
	CefT_Cs_Stat* cs_stat = hdl->cs_stat;
	CefT_Cs_Tx_Elem_Cob* cob_temp;
	int send_cnt = 0;
	uint64_t nowt;
	uint64_t data_sum = 0;
#endif // CefC_ContentStore

	while (1) {
		/* Pop one element from the TX Ring Queue 		*/
		tx_elem = (CefT_Tx_Elem*) cef_rngque_pop (hdl->plugin_hdl.tx_que);

		if (tx_elem != NULL) {

			if (tx_elem->type > CefC_Elem_Type_Object) {
				goto FREE_POOLED_BK;
			}

			if (tx_elem->msg[CefC_O_Fix_Type] == CefC_PT_INTEREST) {
				hoplimit = tx_elem->msg[CefC_O_Fix_HopLimit];
			} else {
				hoplimit = 1;
			}
			
			if (hoplimit < 1) {
				goto FREE_POOLED_BK;
			}
			
			for (i = 0 ; i < tx_elem->faceid_num ; i++) {
				if (cef_face_check_active (tx_elem->faceids[i]) > 0) {
					
					if (tx_elem->msg[CefC_O_Fix_Type] == CefC_PT_OBJECT) {
						seqnum = cef_face_get_seqnum_from_faceid (tx_elem->faceids[i]);
						cef_frame_seqence_update (tx_elem->msg, seqnum);
					}
					
					cef_face_frame_send_forced (
						tx_elem->faceids[i], tx_elem->msg, tx_elem->msg_len);
					hdl->stat_send_frames++;
				}
			}

FREE_POOLED_BK:
			/* Free the pooled block 	*/
			cef_mpool_free (hdl->plugin_hdl.tx_que_mp, tx_elem);

		} else {
			break;
		}
	}

#if (defined CefC_ContentStore) || (defined CefC_Dtc)
#ifndef CefC_Dtc
	if ((hdl->cs_stat->cache_type == CefC_Cache_Type_Excache) &&
		((nowt = cef_client_present_timeus_calc ()) > hdl->send_next)) {
#else // CefC_Dtc
	if ((nowt = cef_client_present_timeus_calc ()) > hdl->send_next) {
#endif // CefC_Dtc
		while (1) {
			/* Pop one element from the TX Ring Queue 		*/
			cs_tx_elem = (CefT_Cs_Tx_Elem*) cef_rngque_read (cs_stat->tx_que);

			if (cs_tx_elem == NULL) {
				break;
			}
			if (cs_tx_elem->type == CefC_Cs_Tx_Elem_Type_Cob) {
				cs_tx_elem = (CefT_Cs_Tx_Elem*) cef_rngque_pop (cs_stat->tx_que);

				/* send cob	*/
				cob_temp = (CefT_Cs_Tx_Elem_Cob*) cs_tx_elem->data;
				csmgr_cob_forward (
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
#endif // CefC_ContentStore

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
	unsigned char rsp_msg[CefC_Max_Length];
	struct pollfd send_fds[1];
	
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
		memset (buff, 0, CefC_Max_Length);
		len = recv (hdl->app_fds[i], buff, CefC_Max_Length, 0);
		
		if (len > 0) {
			hdl->app_steps[i] = 0;
			
			if (memcmp (buff, CefC_Ctrl, CefC_Ctrl_Len) == 0) {
				memset (rsp_msg, 0, CefC_Max_Length);
				flag = cefnetd_input_control_message (
						hdl, buff, len, rsp_msg, hdl->app_fds[i]);
				if (flag > 0) {
					send_fds[0].fd = hdl->app_fds[i];
					send_fds[0].events = POLLOUT | POLLERR;
					if (poll (send_fds, 1, 0) > 0) {
						if (send_fds[0].revents & (POLLERR | POLLNVAL | POLLHUP)) {
							cef_log_write (CefC_Log_Warn, 
								"Failed to send to Local peer (%d)\n", send_fds[0].fd);
						} else {
							send (hdl->app_fds[i], rsp_msg, flag, 0);
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
						hdl, CefC_Faceid_Local, hdl->app_faces[i], buff, len);
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
					hdl, buff, len, rsp_msg, hdl->babel_sock);
			if (flag > 0) {
				send (hdl->babel_sock, rsp_msg, flag, 0);
			}
		} else if (memcmp (buff, CefC_Face_Close, len) == 0) {
			cef_face_close (hdl->babel_face);
			hdl->babel_sock = -1;
			hdl->babel_face = -1;
		} else {
			/* NOP */;
		}
	}
	
	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the message to reg/dereg application name
----------------------------------------------------------------------------------------*/
static int
cefnetd_input_app_reg_command (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	CefT_Parsed_Message* pm, 				/* Parsed CEFORE message					*/
	CefT_Parsed_Opheader* poh,				/* Parsed Option Header						*/
	uint16_t faceid
) {
	CefT_App_Reg* wp;
	
#ifdef CefC_Debug
	if (poh->app_reg_f == CefC_App_DeReg) {
		sprintf (cnd_dbg_msg, "Unreg the application name filter [");
	} else if (poh->app_reg_f == CefC_App_Reg){
		sprintf (cnd_dbg_msg, "Reg the application name filter [");
	} else {
		sprintf (cnd_dbg_msg, "Reg(prefix) the application name filter [");
	}
	{
		int dbg_x;
		
		for (dbg_x = 0 ; dbg_x < pm->name_len ; dbg_x++) {
			sprintf (cnd_dbg_msg, "%s %02X", cnd_dbg_msg, pm->name[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Fine, "%s ]\n", cnd_dbg_msg);
	}
#endif // CefC_Debug
	
	if (poh->app_reg_f == CefC_App_Reg || poh->app_reg_f == CefC_App_RegPrefix) {
		wp = (CefT_App_Reg*) malloc (sizeof (CefT_App_Reg));
		wp->faceid = faceid;
		wp->name_len = pm->name_len;
		memcpy (wp->name, pm->name, pm->name_len);
		if (poh->app_reg_f == CefC_App_Reg) {
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
			char uri[2048];
			cef_frame_conversion_name_to_string (pm->name, pm->name_len, uri, "ccn");
			cef_log_write (CefC_Log_Warn, "This Name[%s] has already been registered or can't register any more, so SKIP register\n", uri);
		}
	} else {
		wp = (CefT_App_Reg*) 
				cef_hash_tbl_item_remove (hdl->app_reg, pm->name, pm->name_len);
		
		if (wp) {
			cefnetd_xroute_change_report (hdl, pm->name, pm->name_len, 0);
			free (wp);
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
	unsigned char* buff
) {
	uint16_t msg_len = 3;
	uint16_t length;
	CefT_App_Reg* aentry;
	uint32_t index = 0;
	CefT_Fib_Entry* fentry = NULL;
	int table_num;
	int i;
	
	if (!hdl->babel_use_f) {
		buff[0] = 0x01;
		length = 0;
		memcpy (&buff[1], &length, sizeof (uint16_t));
		return (3);
	}
	
	do {
		aentry = (CefT_App_Reg*) 
					cef_hash_tbl_item_check_from_index (hdl->app_reg, &index);
		
		if (aentry) {
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
		
		memcpy (&buff[msg_len], &fentry->klen, sizeof (uint16_t));
		memcpy (&buff[msg_len + sizeof (uint16_t)], fentry->key, fentry->klen);
		msg_len += sizeof (uint16_t) + fentry->klen;
		
		index++;
	}
	
	buff[0] = 0x01;
	length = msg_len - 3;
	memcpy (&buff[1], &length, sizeof (uint16_t));
	
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
	char uri[CefC_Max_Length];
	int change_f;
	
	if (!hdl->babel_use_f) {
		return (0);
	}
	
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
	if (tlv_hdr->type != 0x0001) {
		return (0);
	}
	node_len   = tlv_hdr->length;
	node_index = index + sizeof (struct tlv_hdr);
	index += sizeof (struct tlv_hdr) + node_len;
	
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
				hdl->fib, buff, index, CefC_Fib_Entry_Dynamic, &change_f);
	}
	
	/* Update FIB with UDP			*/
	if (hdl->babel_route & 0x02) {
		buff[1] = 0x02;
		rct = cef_fib_route_msg_read (
				hdl->fib, buff, index, CefC_Fib_Entry_Dynamic, &change_f);
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
	unsigned char* rsp, 
	int fd
) {
	int index;
	int res = 0;
	int rc, change_f;
	unsigned char name[CefC_Max_Length];
	int name_len;
	
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
		memcmp (&msg[CefC_Ctrl_Len], CefC_Ctrl_Status, CefC_Ctrl_Status_Len) == 0) {
		res = cef_status_stats_output (hdl, rsp);
	} else if (memcmp (&msg[CefC_Ctrl_Len], CefC_Ctrl_Route, CefC_Ctrl_Route_Len) == 0) {
		index = CefC_Ctrl_Len + CefC_Ctrl_Route_Len;
		if ((memcmp (&msg[index], root_user_name, CefC_Ctrl_User_Len) == 0) ||
			(memcmp (&msg[index], hdl->launched_user_name, CefC_Ctrl_User_Len) == 0)) {
			
			rc = cef_fib_route_msg_read (
				hdl->fib,
				&msg[index + CefC_Ctrl_User_Len],
				msg_size - (CefC_Ctrl_Len + CefC_Ctrl_Route_Len + CefC_Ctrl_User_Len),
				CefC_Fib_Entry_Static, &change_f);
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
			cef_log_write (CefC_Log_Warn, "Permission denied (cefroute)\n");
		}
	} else if (memcmp (&msg[CefC_Ctrl_Len], CefC_Ctrl_Babel, CefC_Ctrl_Babel_Len) == 0) {
		index = CefC_Ctrl_Len + CefC_Ctrl_Babel_Len;
		
		switch (msg[index]) {
		case 'R': {
			res = cefnetd_fib_info_get (hdl, rsp);
			break;
		}
		case 'A': {
			res = cefnetd_babel_process (hdl, &msg[index], 
				msg_size - (CefC_Ctrl_Len + CefC_Ctrl_Babel_Len), rsp);
			break;
		}
		case 'D': {
			res = cefnetd_babel_process (hdl, &msg[index], 
				msg_size - (CefC_Ctrl_Len + CefC_Ctrl_Babel_Len), rsp);
			break;
		}
		default: {
			break;
		}
		}
#ifdef CefC_Ser_Log
	} else if (memcmp (
			&msg[CefC_Ctrl_Len], CefC_Ctrl_Ser_Log, CefC_Ctrl_Ser_Log_Len) == 0) {
		index = CefC_Ctrl_Len + CefC_Ctrl_Ser_Log_Len;
		if ((memcmp (&msg[index], root_user_name, CefC_Ctrl_User_Len) == 0) ||
			(memcmp (&msg[index], hdl->launched_user_name, CefC_Ctrl_User_Len) == 0)) {
			cef_ser_log_output ();
			return (0);
		} else {
			cef_log_write (CefC_Log_Warn, "Permission denied (cefserlog)\n");
		}
#endif // CefC_Ser_Log
	}
	
	return (res);
}
/*--------------------------------------------------------------------------------------
	Handles the input message
----------------------------------------------------------------------------------------*/
static int
cefnetd_udp_input_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	int faceid									/* Face-ID that message arrived 		*/
) {
	int protocol;
	size_t recv_len;
	int peer_faceid;
	struct addrinfo sas;
	socklen_t sas_len = (socklen_t) sizeof (struct addrinfo);
	unsigned char buff[CefC_Max_Length];

	/* Receives the message(s) from the specified FD */
	memset (buff, 0, CefC_Max_Length);
	recv_len
		= recvfrom (fd, buff, CefC_Max_Length, 0, (struct sockaddr*) &sas, &sas_len);

	// TBD: process for the special message

	/* Looks up the peer Face-ID 		*/
	protocol = cef_face_get_protocol_from_fd (fd);
	peer_faceid = cef_face_lookup_peer_faceid (&sas, sas_len, protocol);
	if (peer_faceid < 0) {
		return (-1);
	}

	/* Handles the received CEFORE message 	*/
	cefnetd_input_message_process (hdl, faceid, peer_faceid, buff, (int) recv_len);

	return (1);
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

	/* Receives the message(s) from the specified FD */
	memset (buff, 0, CefC_Max_Length);
	recv_len = read (fd, buff, CefC_Max_Length);

	if (recv_len <= 0) {
		cef_log_write (CefC_Log_Warn, "Detected Face#%d (TCP) is down\n", faceid);
//		cef_fib_faceid_cleanup (hdl->fib, faceid);
//		cef_face_close (faceid);
		cef_face_down (faceid);
		return (1);
	}
	// TBD: process for the special message
	
	/* Handles the received CEFORE message 	*/
	cefnetd_input_message_process (hdl, faceid, faceid, buff, recv_len);

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
#ifdef CefC_ContentStore
	int recv_len;
	unsigned char buff[CefC_Max_Length];
	
	recv_len = recv (fd, buff, CefC_Max_Length, 0);
	
	if (recv_len > 0) {
		cefnetd_input_message_from_csmgrd_process (hdl, buff, recv_len);
	} else {
		cef_log_write (CefC_Log_Warn, 
			"csmgrd is down or connection refused, so mode moves to no cache\n");
		csmgr_sock_close (hdl->cs_stat);
		hdl->cs_stat->cache_type = CefC_Cache_Type_None;
	}
#else
	cef_log_write (CefC_Log_Error, "Invalid input from csmgrd\n");
	cefnetd_running_f = 0;
#endif // CefC_ContentStore
	
	return (1);
}

/*--------------------------------------------------------------------------------------
	Handles the input message from NDN network
----------------------------------------------------------------------------------------*/
static int
cefnetd_ndn_input_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	int faceid									/* Face-ID that message arrived 		*/
) {
#ifdef CefC_NdnPlugin
	if ((hdl->plugin_hdl.ndn)->ndn_msg) {
		(*((hdl->plugin_hdl.ndn))->ndn_msg)(hdl->plugin_hdl.ndn);
	}
#else
	cef_log_write (CefC_Log_Error, "Invalid input from NDN network\n");
	cefnetd_running_f = 0;
#endif // CefC_NdnPlugin
	
	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the input message from ccored
----------------------------------------------------------------------------------------*/
static int
cefnetd_ccr_input_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	int faceid									/* Face-ID that message arrived 		*/
) {
#ifdef CefC_Ccore
	int recv_len;
	unsigned char buff[CcoreC_Max_Length];
	struct cefore_fixed_hdr* fixed_hdr;
	struct ccore_tlv_hdr* tlv_hdr;
	uint16_t index = 0;
	uint16_t pkt_len;
	uint16_t msg_type;
	int res;
	
	recv_len = recv (fd, buff, CcoreC_Max_Length, 0);
	
	if (recv_len > 0) {
		while (index < recv_len) {
			fixed_hdr = (struct cefore_fixed_hdr*) &buff[index];
			
			if ((fixed_hdr->version != CcoreC_Cef_Version) || 
				(fixed_hdr->type != CcoreC_PT_CTRL)) {
				index++;
				continue;
			}
			pkt_len = ntohs (fixed_hdr->pkt_len);
			tlv_hdr = (struct ccore_tlv_hdr*) &buff[index + fixed_hdr->hdr_len];
			msg_type = ntohs (tlv_hdr->type) - 0x0F;
			
			if ((msg_type > CcoreC_Ope_Invalid) && (msg_type < CcoreC_Ope_Num)) {
				
				res = ccore_valid_msg_verify (&buff[index], pkt_len);
				
				if (res == 0) {
					(*cefnetd_ccr_operation_process[msg_type]) (
						hdl, fd, &buff[index], pkt_len
					);
				}
#ifdef CefC_Debug
				if (res != 0) {
					cef_dbg_write (CefC_Dbg_Fine, 
						"Verify the received ctrl message is NG.\n");
				}
#endif // CefC_Debug
			}
			index += pkt_len;
		}
		
	} else {
		cef_log_write (CefC_Log_Warn, 
			"ccored is down or connection refused, so attempt to reconnect\n");
		ccore_close_socket (hdl->rt_hdl);
		hdl->rt_hdl->sock = -1;
		hdl->rt_hdl->reconnect_time = hdl->nowtus + 3000000;
	}
#else
	cef_log_write (CefC_Log_Error, "Invalid input from ccored\n");
	cefnetd_running_f = 0;
#endif // CefC_Ccore
	
	return (1);
}
#ifdef CefC_Ccore
/*--------------------------------------------------------------------------------------
	Handles the invalid operation from ccored
----------------------------------------------------------------------------------------*/
static int
cefnetd_ccr_invalid_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	unsigned char* msg, 
	int msg_len
) {
	/* NOP */
	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the r-neighbor operation from ccored
----------------------------------------------------------------------------------------*/
static int
cefnetd_ccr_r_neighbor_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	unsigned char* msg, 
	int msg_len
) {
	char info_buff[CcoreC_Max_Length];
	unsigned char resp_buff[CcoreC_Max_Length];
	int res;
	
	/* Obtains the neighbor information 	*/
	res = cef_face_neighbor_info_get (info_buff);
	if (res == 0) {
		strcpy (info_buff, "Neighbor is empty\n");
		res = strlen (info_buff);
	}
	
	/* Creates the Neighbor response 		*/
	res = ccore_frame_neighbor_res_create (resp_buff, info_buff, res);
	
	/* Sends the Neighbor response to ccored 	*/
	ccore_send_msg (hdl->rt_hdl, resp_buff, res);
	
	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the r-fib operation from ccored
----------------------------------------------------------------------------------------*/
static int
cefnetd_ccr_r_fib_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	unsigned char* msg, 
	int msg_len
) {
	char info_buff[CcoreC_Max_Length];
	unsigned char resp_buff[CcoreC_Max_Length];
	int res;
	struct cefore_fixed_hdr* cefore_hdr;
	struct ccore_tlv_hdr* tlv_hdr;
	uint16_t type, length;
	uint16_t index;
	uint16_t name_len, name_index;
	
	/*-----------------------------------------------------------
		Parses the FIB retrieve request 
	-------------------------------------------------------------*/
	
	cefore_hdr = (struct cefore_fixed_hdr*) &msg[0];
	index = cefore_hdr->hdr_len + CcoreC_S_TL;
	
	/* Obtains the length and offset of Name from the Cefore Message		*/
	tlv_hdr = (struct ccore_tlv_hdr*) &msg[index];
	type   = ntohs (tlv_hdr->type);
	length = ntohs (tlv_hdr->length);
	index += sizeof (struct ccore_tlv_hdr);
	
	if (type != CefC_T_NAME) {
		cef_log_write (CefC_Log_Warn, 
			"Error: Received message (s-fib-add) has not NAME TLV\n");
		return (0);
	}
	name_index = index;
	name_len   = length;
	index += length;
	
	/*-----------------------------------------------------------
		Creates and send the FIB retrieve response
	-------------------------------------------------------------*/
	
	/* Obtains the matched FIB information 		*/
	res = cef_fib_info_get (
		&hdl->fib, info_buff, &msg[name_index], name_len, cefore_hdr->flag);
	if (res == 0) {
		strcpy (info_buff, "No entry has the specified prefix");
		res = strlen (info_buff);
	}
	
	/* Creates the FIB retrieve response 		*/
	res = ccore_frame_fib_res_create (resp_buff, info_buff, res);
	
	/* Sends the FIB retrieve response to ccored 	*/
	ccore_send_msg (hdl->rt_hdl, resp_buff, res);
	
	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the s-fib-add operation from ccored
----------------------------------------------------------------------------------------*/
static int
cefnetd_ccr_s_fib_add_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	unsigned char* msg, 
	int msg_len
) {
	unsigned char buff[CcoreC_Max_Length];
	char uri[CcoreC_Max_Length];
	struct cefore_fixed_hdr* cefore_hdr;
	struct ccore_tlv_hdr* tlv_hdr;
	uint16_t name_len, name_index;
	uint16_t node_len, node_index;
	uint16_t uri_len;
	uint16_t index;
	uint16_t type, length;
	int res;
	int change_f;
	
	/*-----------------------------------------------------------
		Parses the FIB add request 
	-------------------------------------------------------------*/
	cefore_hdr = (struct cefore_fixed_hdr*) &msg[0];
	index = cefore_hdr->hdr_len + CcoreC_S_TL;
	
	/* Obtains the length and offset of Name from the Cefore Message		*/
	tlv_hdr = (struct ccore_tlv_hdr*) &msg[index];
	type   = ntohs (tlv_hdr->type);
	length = ntohs (tlv_hdr->length);
	index += sizeof (struct ccore_tlv_hdr);
	
	if (type != CefC_T_NAME) {
		cef_log_write (CefC_Log_Warn, 
			"Error: Received message (s-fib-add) has not NAME TLV\n");
		return (0);
	}
	name_index = index;
	name_len   = length;
	index += length;
	
	/* Obtains the length and offset of Node from the Cefore Message		*/
	tlv_hdr = (struct ccore_tlv_hdr*) &msg[index];
	type   = ntohs (tlv_hdr->type);
	length = ntohs (tlv_hdr->length);
	index += sizeof (struct ccore_tlv_hdr);
	
	if (type != CcoreC_T_NODE) {
		cef_log_write (CefC_Log_Warn, 
			"Error: Received message (s-fib-add) has not NODE TLV\n");
		return (0);
	}
	node_index = index;
	node_len   = length;
	index += length;
	
	/*-----------------------------------------------------------
		Creates the FIB route message
	-------------------------------------------------------------*/
	index = 0;
	
	/* Set operation 		*/
	buff[index] = 0x01;
	index++;
	
	/* Set protocol 		*/
	buff[index] = cefore_hdr->flag;
	index++;
	
	/* Set URI		 		*/
	cef_frame_conversion_name_to_uri (&msg[name_index], name_len, uri);
	uri_len = (uint16_t) strlen (uri);
	memcpy (&buff[index], &uri_len, sizeof (uri_len));
	index += sizeof (uri_len);
	memcpy (&buff[index], uri, uri_len);
	index += uri_len;
	
	/* Set host		 		*/
	buff[index] = (uint8_t) node_len;
	index++;
	memcpy (&buff[index], &msg[node_index], node_len);
	index += node_len;
	
	/* Update FIB 			*/
	res = cef_fib_route_msg_read (hdl->fib, buff, index, CefC_Fib_Entry_Ctrl, &change_f);
	if (res > 0) {
		cef_face_update_listen_faces (
			hdl->inudpfds, hdl->inudpfaces, &hdl->inudpfdc, 
			hdl->intcpfds, hdl->intcpfaces, &hdl->intcpfdc);
	}
	if (hdl->babel_use_f && change_f) {
		cefnetd_xroute_change_report (
			hdl, &msg[name_index], name_len, (change_f == 0x02) ? 0 : 1);
	}
	
	/*-----------------------------------------------------------
		Creates and send the FIB add response
	-------------------------------------------------------------*/
	res = ccore_frame_fib_add_res_create (buff, res);
	
	/* Sends the FIB add response to ccored 	*/
	ccore_send_msg (hdl->rt_hdl, buff, res);
	
	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the s-fib-del operation from ccored
----------------------------------------------------------------------------------------*/
static int
cefnetd_ccr_s_fib_del_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	unsigned char* msg, 
	int msg_len
) {
	unsigned char buff[CcoreC_Max_Length];
	char uri[CcoreC_Max_Length];
	struct cefore_fixed_hdr* cefore_hdr;
	struct ccore_tlv_hdr* tlv_hdr;
	uint16_t name_len, name_index;
	uint16_t node_len, node_index;
	uint16_t uri_len;
	uint16_t index;
	uint16_t type, length;
	int res;
	int change_f;
	
	/*-----------------------------------------------------------
		Parses the FIB del request 
	-------------------------------------------------------------*/
	cefore_hdr = (struct cefore_fixed_hdr*) &msg[0];
	index = cefore_hdr->hdr_len + CcoreC_S_TL;
	
	/* Obtains the length and offset of Name from the Cefore Message		*/
	tlv_hdr = (struct ccore_tlv_hdr*) &msg[index];
	type   = ntohs (tlv_hdr->type);
	length = ntohs (tlv_hdr->length);
	index += sizeof (struct ccore_tlv_hdr);
	
	if (type != CefC_T_NAME) {
		cef_log_write (CefC_Log_Warn, 
			"Error: Received message (s-fib-add) has not NAME TLV\n");
		return (0);
	}
	name_index = index;
	name_len   = length;
	index += length;
	
	/* Obtains the length and offset of Node from the Cefore Message		*/
	tlv_hdr = (struct ccore_tlv_hdr*) &msg[index];
	type   = ntohs (tlv_hdr->type);
	length = ntohs (tlv_hdr->length);
	index += sizeof (struct ccore_tlv_hdr);
	
	if (type != CcoreC_T_NODE) {
		cef_log_write (CefC_Log_Warn, 
			"Error: Received message (s-fib-add) has not NODE TLV\n");
		return (0);
	}
	node_index = index;
	node_len   = length;
	index += length;
	
	/*-----------------------------------------------------------
		Creates the FIB route message
	-------------------------------------------------------------*/
	index = 0;
	
	/* Set operation 		*/
	buff[index] = 0x02;
	index++;
	
	/* Set protocol 		*/
	buff[index] = cefore_hdr->flag;
	index++;
	
	/* Set URI		 		*/
	cef_frame_conversion_name_to_uri (&msg[name_index], name_len, uri);
	uri_len = (uint16_t) strlen (uri);
	memcpy (&buff[index], &uri_len, sizeof (uri_len));
	index += sizeof (uri_len);
	memcpy (&buff[index], uri, uri_len);
	index += uri_len;
	
	/* Set host		 		*/
	buff[index] = (uint8_t) node_len;
	index++;
	memcpy (&buff[index], &msg[node_index], node_len);
	index += node_len;
	
	/* Update FIB 			*/
	res = cef_fib_route_msg_read (hdl->fib, buff, index, CefC_Fib_Entry_Ctrl, &change_f);
	if (res > 0) {
		cef_face_update_listen_faces (
			hdl->inudpfds, hdl->inudpfaces, &hdl->inudpfdc, 
			hdl->intcpfds, hdl->intcpfaces, &hdl->intcpfdc);
	}
	if (hdl->babel_use_f && change_f) {
		cefnetd_xroute_change_report (
			hdl, &msg[name_index], name_len, (change_f == 0x02) ? 0 : 1);
	}
	
	/*-----------------------------------------------------------
		Creates and send the FIB del response
	-------------------------------------------------------------*/
	res = ccore_frame_fib_del_res_create (buff, res);
	
	/* Sends the FIB add response to ccored 	*/
	ccore_send_msg (hdl->rt_hdl, buff, res);
	
	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the r-cache-prefix operation from ccored
----------------------------------------------------------------------------------------*/
static int
cefnetd_ccr_r_cache_prefix_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	unsigned char* msg, 
	int msg_len
) {
	unsigned char buff[CcoreC_Max_Length] = {0};
	char uri[CcoreC_Max_Length];
	int res;
	uint8_t result = 0;
#ifdef CefC_ContentStore
	struct cefore_fixed_hdr* cefore_hdr;
	struct ccore_tlv_hdr* tlv_hdr;
	uint16_t name_len, name_index;
	uint16_t index;
	uint16_t type;
	uint16_t length;
	uint64_t lifetime = 0;
#endif // CefC_ContentStore

	if ((hdl->cs_stat == NULL) || (hdl->cs_stat->cache_type == CefC_Cache_Type_None)) {
		cef_log_write (CefC_Log_Info, "Incoming ccore message, but CS is not used.\n");
		res = sprintf (uri, "cefnetd don't use CS\n");
		res = ccore_frame_cache_prefix_res_create (buff, uri, res, result);
		ccore_send_msg (hdl->rt_hdl, buff, res);
		return (0);
	}
#ifdef CefC_ContentStore
	/*-----------------------------------------------------------
		Parses the Cache Prefix Retrieve request 
	-------------------------------------------------------------*/
	cefore_hdr = (struct cefore_fixed_hdr*) &msg[0];
	index = cefore_hdr->hdr_len + CcoreC_S_TL;
	
	/* Obtains the length and offset of Name from the Cefore Message		*/
	tlv_hdr = (struct ccore_tlv_hdr*) &msg[index];
	type   = ntohs (tlv_hdr->type);
	length = ntohs (tlv_hdr->length);
	index += sizeof (struct ccore_tlv_hdr);
	
	if (type != CefC_T_NAME) {
		cef_log_write (CefC_Log_Warn, 
			"Error: Received message (r-cache-prefix) has not NAME TLV\n");
		return (0);
	}
	name_index = index;
	name_len   = length;
	index += length;
	
	/*-----------------------------------------------------------
		Creates and send the Cache Prefix Retrieve response
	-------------------------------------------------------------*/
	
	/* Obtains the lifetime of the specified Prefix 		*/
	res = cef_csmgr_con_lifetime_retrieve (
				hdl->cs_stat, (char*)&msg[name_index], name_len, &lifetime);
	if (res < 0) {
		/* case : error */
		sprintf (uri, "Failed to acquire the value inside Content Store.");
		result = 0;
	} else {
		cef_frame_conversion_name_to_uri (&msg[name_index], name_len, (char*)buff);
		if (lifetime) {
			/* usec -> sec */
			lifetime = lifetime / 1000000;
		}
		sprintf ((char*) uri, "%s lifetime "FMTU64"", buff, lifetime);
		result = 1;
	}
	res = (int) strlen ((char*) uri);
	
	/* Creates the Cache Prefix Retrieve response 		*/
	res = ccore_frame_cache_prefix_res_create (buff, uri, res, result);
	
	/* Sends the FIB del response to ccored 	*/
	ccore_send_msg (hdl->rt_hdl, buff, res);
#endif // CefC_ContentStore
	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the r-cache-capacity operation from ccored
----------------------------------------------------------------------------------------*/
static int
cefnetd_ccr_r_cache_cap_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	unsigned char* msg, 
	int msg_len
) {
	unsigned char buff[CcoreC_Max_Length] = {0};
	char capa[CcoreC_Max_Length] = {0};
	int res;
	uint8_t result = 0;
#ifdef CefC_ContentStore
	uint64_t cap;
#endif // CefC_ContentStore

	if ((hdl->cs_stat == NULL) || (hdl->cs_stat->cache_type == CefC_Cache_Type_None)) {
		cef_log_write (CefC_Log_Info, "Incoming ccore message, but CS is not used.\n");
		res = sprintf (capa, "cefnetd don't use CS\n");
		res = ccore_frame_cache_cap_retrieve_res_create (buff, capa, res, result);
		ccore_send_msg (hdl->rt_hdl, buff, res);
		return (0);
	}
#ifdef CefC_ContentStore
	/*-----------------------------------------------------------
		Creates and send the Cache Capacity Retrieve response
	-------------------------------------------------------------*/	
	/* Obtains the capacity of Content Store		*/
	res = cef_csmgr_capacity_retrieve (hdl->cs_stat, &cap);
	if (res < 0) {
		/* case : error */
		// sprintf (capa, "Connection Failed\n");
		result = 0;
	} else {
		if (cap == 0) {
			sprintf (capa, "Unlimited\n");
		} else {
			sprintf (capa, ""FMTU64"\n", cap);
		}
		result = 1;
	}
	res = (int) strlen (capa);
	
	/* Creates the Cache Capacity Retrieve response 		*/
	res = ccore_frame_cache_cap_retrieve_res_create (buff, capa, res, result);

	/* Sends the Cache Capacity Retrieve response to ccored 	*/
	ccore_send_msg (hdl->rt_hdl, buff, res);
#endif // CefC_ContentStore
	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the s-cache-capacity operation from ccored
----------------------------------------------------------------------------------------*/
static int
cefnetd_ccr_s_cache_cap_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	unsigned char* msg, 
	int msg_len
) {
	unsigned char buff[CcoreC_Max_Length] = {0};
	int res;
#ifdef CefC_ContentStore
	uint64_t cap;
	struct cefore_fixed_hdr* cefore_hdr;
	uint16_t index;
	uint16_t length;
	struct ccore_tlv_hdr* tlv_hdr;
	uint16_t cap_index;
#endif // CefC_ContentStore

	if ((hdl->cs_stat == NULL) || (hdl->cs_stat->cache_type == CefC_Cache_Type_None)) {
		cef_log_write (CefC_Log_Info, "Incoming ccore message, but CS is not used.\n");
		res = ccore_frame_cache_lifetime_res_create (buff, 0);
		ccore_send_msg (hdl->rt_hdl, buff, res);
		return (0);
	}
#ifdef CefC_ContentStore
	/*-----------------------------------------------------------
		Creates and send the Cache Capacity Update response
	-------------------------------------------------------------*/
	cefore_hdr = (struct cefore_fixed_hdr*) &msg[0];
	index = cefore_hdr->hdr_len + CcoreC_S_TL;
	/* Obtains the length and offset of capacity from the Cefore Message */
	tlv_hdr = (struct ccore_tlv_hdr*) &msg[index];
	length = ntohs (tlv_hdr->length);
	index += sizeof (struct ccore_tlv_hdr);
	cap_index = index;
	index += length;
	cap = strtoull ((const char*)&msg[cap_index], NULL, 0);

	/* Update the capacity of Content Store		*/
	res = cef_csmgr_capacity_update (hdl->cs_stat, cap);
	if (res < 1) {
		/* case : error */
		res = 0;
	} else {
		res = 1;
	}
	/* Creates the Cache Capacity Update response 		*/
	res = ccore_frame_cache_cap_update_res_create (buff, res);
	
	/* Sends the Cache Capacity Update response to ccored 	*/
	ccore_send_msg (hdl->rt_hdl, buff, res);
#endif // CefC_ContentStore
	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the s-cache-lifetime operation from ccored
----------------------------------------------------------------------------------------*/
static int
cefnetd_ccr_s_lifetime_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	unsigned char* msg, 
	int msg_len
) {
	unsigned char buff[CcoreC_Max_Length];
	int res;
	uint8_t result = 0;
#ifdef CefC_ContentStore
	struct cefore_fixed_hdr* cefore_hdr;
	struct ccore_tlv_hdr* tlv_hdr;
	uint16_t name_len, name_index;
	uint16_t index;
	uint16_t type, length;
	uint16_t life_len, life_index;
	char life_str[CcoreC_Max_Length];
	uint64_t life_val;
#endif // CefC_ContentStore

	if ((hdl->cs_stat == NULL) || (hdl->cs_stat->cache_type == CefC_Cache_Type_None)) {
		cef_log_write (CefC_Log_Info, "Incoming ccore message, but CS is not used.\n");
		// sprintf (err_msg, "Content store is not used.\n");
		res = ccore_frame_cache_lifetime_res_create (buff, result);
		ccore_send_msg (hdl->rt_hdl, buff, res);
		return (0);
	}
#ifdef CefC_ContentStore
	/*-----------------------------------------------------------
		Parses the Cache Lifetime request 
	-------------------------------------------------------------*/
	cefore_hdr = (struct cefore_fixed_hdr*) &msg[0];
	index = cefore_hdr->hdr_len + CcoreC_S_TL;
	
	/* Obtains the length and offset of Name from the Cefore Message		*/
	tlv_hdr = (struct ccore_tlv_hdr*) &msg[index];
	type   = ntohs (tlv_hdr->type);
	length = ntohs (tlv_hdr->length);
	index += sizeof (struct ccore_tlv_hdr);
	
	if (type != CefC_T_NAME) {
		cef_log_write (CefC_Log_Warn, 
			"Error: Received message (s-cache-lifetime) has not NAME TLV\n");
		return (0);
	}
	name_index = index;
	name_len   = length;
	index += length;
	
	/* Obtains the length and offset of lifetime from the Cefore Message		*/
	tlv_hdr = (struct ccore_tlv_hdr*) &msg[index];
	type   = ntohs (tlv_hdr->type);
	length = ntohs (tlv_hdr->length);
	index += sizeof (struct ccore_tlv_hdr);
	
	if (type != CcoreC_T_NEWLIFETIME) {
		cef_log_write (CefC_Log_Warn, 
			"Error: Received message (s-cache-lifetime) has not T_NEWLIFETIME TLV\n");
		return (0);
	}
	life_index = index;
	life_len = length;
	index += length;
	
	/*-----------------------------------------------------------
		Creates and send the Cache Lifetime response
	-------------------------------------------------------------*/
	
	/* Update the lifetime of the specified content		*/
	memcpy (life_str, &msg[life_index], life_len);
	life_str[life_len] = 0;
	life_val = strtoull (life_str, NULL, 0);

	/* Obtains the lifetime of the specified Prefix 		*/
	res = cef_csmgr_con_lifetime_set (
				hdl->cs_stat, (char*)&msg[name_index], name_len, life_val);
	if (res < 0) {
		/* case : error */
		result = 0;
	} else {
		result = 1;
	}
	
	/* Creates the Cache Prefix Retrieve response 		*/
	res = ccore_frame_cache_lifetime_res_create (buff, result);
	
	/* Sends the FIB del response to ccored 	*/
	ccore_send_msg (hdl->rt_hdl, buff, res);
#endif // CefC_ContentStore
	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the s-write-setting operation from ccored
----------------------------------------------------------------------------------------*/
static int
cefnetd_ccr_s_write_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	unsigned char* msg, 
	int msg_len
) {
	unsigned char buff[CcoreC_Max_Length];
	int ret = 0;
	char src_ws[1024];
	char dst_ws[1024];
	FILE* src_fp = NULL;
	CefT_Hash_Handle* hash_handle = &hdl->fib;
	CefT_Fib_Entry* fib_entry;
	int i;
	int res;
	uint32_t index = 0;
	char uri[CefC_Max_Length];
	CefT_Fib_Face* faces;
	int fib_table_num;
	CefT_Face* face;
	char prot_str[3][16] = {"invalid", "tcp", "udp"};
	CefT_Sock* sock;
	CefT_Hash_Handle* sock_tbl;
	char node[NI_MAXHOST];

	/*-----------------------------------------------------------
		Creates backup file
	-------------------------------------------------------------*/
	/* Get directory */
	cef_client_config_dir_get (src_ws);
	if (mkdir (src_ws, 0777) != 0) {
		if (errno == ENOENT) {
			goto CCR_S_WRITE_POST;
		}
	}
	/* Create file name */
	sprintf (src_ws + strlen (src_ws), "/cefnetd.fib");
	sprintf (dst_ws , "%s.sav", src_ws);
	/* Create backup file */
	if (rename (src_ws, dst_ws) < 0) {
		cef_log_write (CefC_Log_Error,
			"<Fail> Write config file (%s)\n", strerror (errno));
		goto CCR_S_WRITE_POST;
	}

	/*-----------------------------------------------------------
		Creates and send the Write Memory response
	-------------------------------------------------------------*/
	/* Open file */
	src_fp = fopen (src_ws, "w");
	if (src_fp == NULL) {
		cef_log_write (CefC_Log_Error,
			"<Fail> Write config file (%s)\n", strerror (errno));
		goto CCR_S_WRITE_POST;
	}
	ret = 1;
	/* Get FIB entry num */
	fib_table_num = cef_hash_tbl_item_num_get (*hash_handle);
	if (fib_table_num == 0) {
		/* FIB entry is empty */
		goto CCR_S_WRITE_POST;
	}
	/* get socket table	*/
	sock_tbl = cef_face_return_sock_table ();
	/* Write to file */
	for (i = 0; i < fib_table_num; i++) {
		/* Get entry */
		fib_entry = (CefT_Fib_Entry*) cef_hash_tbl_elem_get (*hash_handle, &index);
		if (fib_entry == NULL) {
			break;
		}
		
		/* Get uri */
		res = cef_frame_conversion_name_to_uri (fib_entry->key, fib_entry->klen, uri);
		if (res < 0) {
			index++;
			continue;
		}
		/* Get Faces */
		faces = fib_entry->faces.next;
		/* Output TCP Faces */
		while (faces != NULL) {
			/* Check the bit is not dynamic bit only 	*/
			if (faces->type < CefC_Fib_Entry_Static) {
				faces = faces->next;
				continue;
			}
			
			/* Get Face info */
			face = cef_face_get_face_from_faceid (faces->faceid);
			/* Get sock */
			sock = (CefT_Sock*) cef_hash_tbl_item_get_from_index (
						*sock_tbl, face->index);
			if (sock == NULL) {
				faces = faces->next;
				continue;
			}
			/* Get Address */
			res = getnameinfo (sock->ai_addr, sock->ai_addrlen, node, sizeof(node),
							NULL, 0, NI_NUMERICHOST);
			if (res == 0) {
				/* Write information */
				fprintf (src_fp, "%s %s %s:%d\n"
					, uri, prot_str[sock->protocol], node, sock->port_num);
			}
			faces = faces->next;
		}
		index++;
	}
	ret = 1;

CCR_S_WRITE_POST:
	if (src_fp) {
		fclose (src_fp);
	}
	/* Creates the Write response 		*/
	ret = ccore_frame_write_memory_res_create (buff, ret);	
	/* Sends the FIB del response to ccored 	*/
	ccore_send_msg (hdl->rt_hdl, buff, ret);
	
	return (ret);
}
/*--------------------------------------------------------------------------------------
	Handles the r-status operation from ccored
----------------------------------------------------------------------------------------*/
static int
cefnetd_ccr_r_status_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	unsigned char* msg, 
	int msg_len
) {
	// TODO 
	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the s-status operation from ccored
----------------------------------------------------------------------------------------*/
static int
cefnetd_ccr_s_status_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	int fd, 									/* FD which is polled POLLIN			*/
	unsigned char* msg, 
	int msg_len
) {
	// TODO 
	return (1);
}

#endif // CefC_Ccore
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
	int msg_size								/* size of received message(s)			*/
) {
	CefT_Face* face;
	unsigned char* wp;
	uint16_t move_len;
	uint16_t fdv_payload_len;
	uint16_t fdv_header_len;
	int res;
	unsigned char buff[CefC_Max_Length];

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
		if (msg_size > CefC_Max_Length - face->len) {
			move_len = CefC_Max_Length - face->len;
		} else {
			move_len = (uint16_t) msg_size;
		}
		msg_size -= move_len;

		/* Updates the receive buffer 		*/
		memcpy (face->rcv_buff + face->len, msg, move_len);
		face->len += move_len;
		msg += move_len;

		while (face->len > 0) {
			/* Seeks the top of the message */
			res = cefnetd_messege_head_seek (face, &fdv_payload_len, &fdv_header_len);
			if (res < 0) {
				break;
			}

			/* Calls the function corresponding to the type of the message 	*/
			if (face->rcv_buff[1] > CefC_PT_PING_REP) {
				cef_log_write (CefC_Log_Warn, 
					"Detects the unknown PT_XXX=%d\n", face->rcv_buff[1]);
			} else {
				(*cefnetd_incoming_msg_process[face->rcv_buff[1]])
					(hdl, faceid, peer_faceid,
							face->rcv_buff, fdv_payload_len, fdv_header_len);
			}
			
			/* Updates the receive buffer 		*/
			move_len = fdv_payload_len + fdv_header_len;
			wp = face->rcv_buff + move_len;
			memcpy (buff, wp, face->len - move_len);
			memcpy (face->rcv_buff, buff, face->len - move_len);
			face->len -= move_len;
		}
	}
	
	return (1);
}
#ifdef CefC_ContentStore
/*--------------------------------------------------------------------------------------
	Handles the received message(s) from csmgrd
----------------------------------------------------------------------------------------*/
static int										/* No care now							*/
cefnetd_input_message_from_csmgrd_process (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	unsigned char* msg, 						/* the received message(s)				*/
	int msg_size								/* size of received message(s)			*/
) {
	unsigned char* wp;
	uint16_t move_len;
	uint16_t fdv_payload_len;
	uint16_t fdv_header_len;
	int res;
	unsigned char buff[CefC_Max_Length];
	
	/* Handles the received message(s) 		*/
	while (msg_size > 0) {
		/* Calculates the size of the message which have not been yet handled 	*/
		if (msg_size > CefC_Max_Length - hdl->cs_stat->rcv_len) {
			move_len = CefC_Max_Length - hdl->cs_stat->rcv_len;
		} else {
			move_len = (uint16_t) msg_size;
		}
		msg_size -= move_len;

		/* Updates the receive buffer 		*/
		memcpy (hdl->cs_stat->rcv_buff + hdl->cs_stat->rcv_len, msg, move_len);
		hdl->cs_stat->rcv_len += move_len;
		msg += move_len;

		while (hdl->cs_stat->rcv_len > 0) {
			/* Seeks the top of the message */
			res = cefnetd_csmgrd_messege_head_seek (
						hdl->cs_stat, &fdv_payload_len, &fdv_header_len);
			if (res < 0) {
				break;
			}
			
			/* Calls the function corresponding to the type of the message 	*/
			if (hdl->cs_stat->rcv_buff[1] > CefC_PT_PING_REP) {
				cef_log_write (CefC_Log_Warn, 
					"Detects the unknown PT_XXX=%d from csmgrd\n", 
					hdl->cs_stat->rcv_buff[1]);
			} else {
				(*cefnetd_incoming_csmgrd_msg_process[hdl->cs_stat->rcv_buff[1]])
					(hdl, 0, 0, hdl->cs_stat->rcv_buff, fdv_payload_len, fdv_header_len);
			}
			
			/* Updates the receive buffer 		*/
			move_len = fdv_payload_len + fdv_header_len;
			wp = hdl->cs_stat->rcv_buff + move_len;
			memcpy (buff, wp, hdl->cs_stat->rcv_len - move_len);
			memcpy (hdl->cs_stat->rcv_buff, buff, hdl->cs_stat->rcv_len - move_len);
			hdl->cs_stat->rcv_len -= move_len;
		}
	}

	return (1);
}
/*--------------------------------------------------------------------------------------
	Seeks the top of the frame from the receive buffer
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_csmgrd_messege_head_seek (
	CefT_Cs_Stat* cs_stat, 
	uint16_t* payload_len,
	uint16_t* header_len
) {
	uint16_t move_len;
	unsigned char* wp;
	unsigned char* ep;
	unsigned char buff[CefC_Max_Length];
	uint16_t index = 0;
	static uint16_t short_step = 0;
	
	struct cef_hdr* chp;
	uint16_t pkt_len;
	uint16_t hdr_len;

	while (cs_stat->rcv_len > 7) {
		chp = (struct cef_hdr*) &(cs_stat->rcv_buff[index]);

		pkt_len = ntohs (chp->pkt_len);
		hdr_len = chp->hdr_len;

		if (chp->version != CefC_Version) {
			wp = &cs_stat->rcv_buff[index];
			ep = cs_stat->rcv_buff + index + cs_stat->rcv_len;
			move_len = 0;

			while (wp < ep) {
				if (*wp != CefC_Version) {
					wp++;
				} else {
					move_len = ep - wp;
					memcpy (buff, wp, move_len);
					memcpy (cs_stat->rcv_buff, buff, move_len);
					cs_stat->rcv_len -= wp - cs_stat->rcv_buff;
					
					chp = (struct cef_hdr*) &(cs_stat->rcv_buff);
					pkt_len = ntohs (chp->pkt_len);
					hdr_len = chp->hdr_len;
					index = 0;
					
					if ((pkt_len == 0) || (hdr_len == 0)) {
						move_len = 0;
					}
					
					break;
				}
			}
			if (move_len == 0) {
				cs_stat->rcv_len = 0;
				return (-1);
			}
		}

		if (chp->type > CefC_PT_PING_REP) {
			cs_stat->rcv_len--;
			index++;
			continue;
		}

		/* Obtains values of Header Length and Payload Length 	*/
		*payload_len 	= pkt_len - hdr_len;
		*header_len 	= hdr_len;

		if (cs_stat->rcv_len < *payload_len + *header_len) {
			short_step++;
			if (short_step > 2) {
				short_step = 0;
				cs_stat->rcv_len--;
				index++;
				continue;
			}
			return (-1);
		}

		if (index > 0) {
			memmove (cs_stat->rcv_buff, cs_stat->rcv_buff + index, cs_stat->rcv_len);
		}
		short_step = 0;
		return (1);
	}

	return (-1);
}
#endif // CefC_ContentStore
/*--------------------------------------------------------------------------------------
	Seeks the top of the frame from the receive buffer
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_messege_head_seek (
	CefT_Face* face,						/* the face structure						*/
	uint16_t* payload_len,
	uint16_t* header_len
) {
	uint16_t move_len;
	unsigned char* wp;
	unsigned char* ep;
	unsigned char buff[CefC_Max_Length];
	uint16_t index = 0;
	static uint16_t short_step = 0;
	
	struct cef_hdr* chp;
	uint16_t pkt_len;
	uint16_t hdr_len;

	while (face->len > 7) {
		chp = (struct cef_hdr*) &(face->rcv_buff[index]);

		pkt_len = ntohs (chp->pkt_len);
		hdr_len = chp->hdr_len;

		if (chp->version != CefC_Version) {
			wp = &face->rcv_buff[index];
			ep = face->rcv_buff + index + face->len;
			move_len = 0;

			while (wp < ep) {
				if (*wp != CefC_Version) {
					wp++;
				} else {
					move_len = ep - wp;
					memcpy (buff, wp, move_len);
					memcpy (face->rcv_buff, buff, move_len);
					face->len -= wp - face->rcv_buff;

					chp = (struct cef_hdr*) &(face->rcv_buff);
					pkt_len = ntohs (chp->pkt_len);
					hdr_len = chp->hdr_len;
					index = 0;

					break;
				}
			}
			if (move_len == 0) {
				face->len = 0;
				return (-1);
			}
		}

		if (chp->type > CefC_PT_PING_REP) {
			face->len--;
			index++;
			continue;
		}

		/* Obtains values of Header Length and Payload Length 	*/
		*payload_len 	= pkt_len - hdr_len;
		*header_len 	= hdr_len;

		if (face->len < *payload_len + *header_len) {
			short_step++;
			if (short_step > 2) {
				short_step = 0;
				face->len--;
				index++;
				continue;
			}
			return (-1);
		}

		if (index > 0) {
			memmove (face->rcv_buff, face->rcv_buff + index, face->len);
		}
		short_step = 0;
		return (1);
	}

	return (-1);
}
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
	uint16_t header_len						/* Header Length of this message			*/
) {
	CefT_Parsed_Message pm;
	CefT_Parsed_Opheader poh;

	int res;
	int pit_res;
	CefT_Pit_Entry* pe = NULL;
	CefT_Fib_Entry* fe = NULL;
	CefT_Fib_Entry* app_fe = NULL;
	uint16_t name_len;
#if (defined CefC_ContentStore) || (defined CefC_Dtc)
	unsigned int dnfaces = 0;
	int cs_res = -1;
#endif // CefC_ContentStore
	CefT_Rx_Elem elem;
	uint16_t faceids[CefC_Fib_UpFace_Max];
	uint16_t face_num = 0;
	int forward_interest_f = 0;
	int i;
	int tp_plugin_res = CefC_Pi_All_Permission;
	uint16_t* fip;
#ifdef CefC_Ser_Log
	struct tlv_hdr* thdr;
#endif // CefC_Ser_Log
	
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finer, 
		"Process the Interest (%d bytes)\n", payload_len + header_len);
#endif // CefC_Debug
	
	if (payload_len + header_len > CefC_Max_Msg_Size) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Interest is too large\n");
#endif // CefC_Debug
		return (-1);
	}
	
	/* Checks the Validation 			*/
	res = cef_valid_msg_verify (msg, payload_len + header_len);
	if (res != 0) {
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
#ifdef CefC_Debug
	{
		int dbg_x;
//		unsigned char pubkey[CefC_Max_Length];
		
		sprintf (cnd_dbg_msg, "Interest's Name [");
		
		for (dbg_x = 0 ; dbg_x < pm.name_len ; dbg_x++) {
			sprintf (cnd_dbg_msg, "%s %02X", cnd_dbg_msg, pm.name[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finer, "%s ]\n", cnd_dbg_msg);
//		cef_valid_get_pubkey (msg, pubkey);
	}
#endif // CefC_Debug

#ifdef CefC_Ser_Log
	if (pm.org.length) {
		/* NICT Serial Logging process */
		if ((pm.org.pen[0] == 5) && (pm.org.pen[1] == 6) && (pm.org.pen[2] == 4)) {
			/* Insert T_ORG Field. IANA Private Enterprise Numbers is 51564. */
			thdr = (struct tlv_hdr*) pm.org.offset;
			if ((pm.org.length > 1) && (ntohs (thdr->type) == CefC_T_SER_LOG)) {
				cef_ser_log_incoming_message (pm.org.offset, pm.org.length);
			}
		}
	}
#endif // CefC_Ser_Log
	
	/* Checks whether this interest is the command or not */
	res = cefnetd_incoming_command_process (hdl, faceid, peer_faceid, &pm);
	if (res > 0) {
		return (1);
	}
	
	if (poh.app_reg_f > 0) {
		cefnetd_input_app_reg_command (hdl, &pm, &poh, (uint16_t) peer_faceid);
		return (1);
	}
	
	/* Checks the Symbolic Code 		*/
	if (pm.symbolic_code_f) {
		cefnetd_incoming_interest_with_symbolic_code_process (
			hdl, faceid, peer_faceid, msg, payload_len, header_len, &pm, &poh);
		return (1);
	}
	
	/* Searches a PIT entry matching this Interest 	*/
	pe = cef_pit_entry_lookup (hdl->pit, &pm, &poh);

	if (pe == NULL) {
		return (-1);
	}

#if (defined CefC_ContentStore) || (defined CefC_Dtc)
	// TODO change process
	dnfaces = pe->dnfacenum;
#endif // CefC_ContentStore
	
	/* Updates the information of down face that this Interest arrived 	*/
	pit_res = cef_pit_entry_down_face_update (pe, peer_faceid, &pm, &poh, msg);
	
	/* Searches a FIB entry matching this Interest 		*/
	if (pm.chnk_num_f) {
		name_len = pm.name_len - (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
	} else {
		/* Symbolic Interest	*/
		name_len = pm.name_len;
	}
	
	/* Updates the lifetime of FIB for particular application 	*/
	if ((pm.app_comp >= CefC_T_APP_BI_DIRECT) && 
		(pm.app_comp <= CefC_T_APP_MESH)) {
		
		if (!cef_face_is_local_face (peer_faceid)) {
			app_fe = cef_fib_entry_lookup (hdl->fib, pm.name, name_len);
			app_fe->app_comp = pm.app_comp;
			app_fe->lifetime = hdl->nowtus + 10000000;
			cef_fib_faceid_insert (app_fe, peer_faceid);
		}
	}
	
	if (pit_res != 0) {
		/* Searches a FIB entry matching this Interest 		*/
		fe = cef_fib_entry_search (hdl->fib, pm.name, name_len);
		
		/* Obtains Face-ID(s) to forward the Interest */
		if (fe) {
			face_num = cef_fib_forward_faceid_select (fe, peer_faceid, faceids);
		}
		
		if ((poh.piggyback_f) && (pm.payload_f)) {
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
#ifdef CefC_Mobility
	/*--------------------------------------------------------------------
		Mobility Plugin
	----------------------------------------------------------------------*/
	if ((hdl->plugin_hdl.mb)->interest) {
		
		/* Creates CefT_Rx_Elem 		*/
		memset (&elem, 0, sizeof (CefT_Rx_Elem));
		elem.type 				= CefC_Elem_Type_Interest;
		elem.hashv 				= pe->hashv;
		elem.in_faceid 			= (uint16_t) peer_faceid;
		elem.parsed_msg 		= &pm;
		memcpy (&(elem.msg[0]), msg, payload_len + header_len);
		elem.msg_len 			= payload_len + header_len;
		elem.out_faceid_num 	= face_num;
		
		for (i = 0 ; i < face_num ; i++) {
			elem.out_faceids[i] = faceids[i];
		}
		
		/* Callback 		*/
		tp_plugin_res = (*((hdl->plugin_hdl.mb))->interest)(
			hdl->plugin_hdl.mb, &elem
		);
	}
#endif // CefC_Mobility
	
	/*--------------------------------------------------------------------
		Transport Plugin
	----------------------------------------------------------------------*/
	if (poh.tp_variant > CefC_T_OPT_TP_NONE) {
		
		if ((hdl->plugin_hdl.tp)[poh.tp_variant].interest) {
			/* Creates CefT_Rx_Elem 		*/
			memset (&elem, 0, sizeof (CefT_Rx_Elem));
			elem.plugin_variant 	= poh.tp_variant;
			elem.type 				= CefC_Elem_Type_Interest;
			elem.hashv 				= pe->hashv;
			elem.in_faceid 			= (uint16_t) peer_faceid;
			elem.parsed_msg 		= &pm;
			memcpy (&(elem.msg[0]), msg, payload_len + header_len);
			elem.msg_len 			= payload_len + header_len;
			elem.out_faceid_num 	= face_num;

			for (i = 0 ; i < face_num ; i++) {
				elem.out_faceids[i] = faceids[i];
			}

			memcpy (elem.ophdr, poh.tp_value, poh.tp_length);
			elem.ophdr_len = poh.tp_length;

			/* Callback 		*/
			tp_plugin_res = (*(hdl->plugin_hdl.tp)[poh.tp_variant].interest)(
				&(hdl->plugin_hdl.tp[poh.tp_variant]), &elem
			);
		}
	}
	
#ifdef CefC_ContentStore
	/*--------------------------------------------------------------------
		Content Store
	----------------------------------------------------------------------*/
	if (tp_plugin_res & CefC_Pi_Object_Match) {
		
		if (pm.app_comp == CefC_T_APP_FROM_PUB) {
			if (pm.chnk_num_f) {
				name_len = pm.name_len - (CefC_S_TLF + CefC_S_ChunkNum);
			} else {
				name_len = pm.name_len;
			}
			if (cef_hash_tbl_item_check_exact (hdl->app_reg, pm.name, name_len) < 0) {
				forward_interest_f = 1;
				goto FORWARD_INTEREST;
			}
		}
		
		/* Checks Reply 	*/
		if (!poh.longlife_f) {
			if (pit_res != 0) {
				pit_res = cef_csmgr_rep_f_check (pe, peer_faceid);
			}
			if ((pit_res == 0) || (dnfaces == pe->dnfacenum)) {
				goto FORWARD_INTEREST;
			}
		}
		
		/* Checks Content Store */
		if ((hdl->cs_stat->cache_type == CefC_Cache_Type_Excache) && 
			((poh.lifetime_f) && (poh.lifetime > 0))) {
			
			/* Checks the temporary cache in cefnetd 		*/
			cs_res = cef_csmgr_cache_lookup (hdl->cs_stat, peer_faceid, &pm, &poh, pe);
			
			if (cs_res < 0) {
				/* Cache does not exist in the temporary cache in cefnetd, 		*/
				/* so inquiries to the csmgrd 									*/
				cef_csmgr_excache_lookup (hdl->cs_stat, peer_faceid, &pm, &poh, pe);
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Finer, "Forward the Interest to csmgrd\n");
#endif // CefC_Debug
			} else {
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Finer, 
					"Return the Content Object from the buffer\n");
#endif // CefC_Debug
				cef_pit_down_faceid_remove (pe, peer_faceid);
				
				if (pe->dnfacenum == 0) {
					cef_pit_entry_free (hdl->pit, pe);
				}
				return (-1);
			}
		}
	}
	
	if ((pit_res != 0) && (cs_res != 0)) {
		forward_interest_f = 1;
	}
FORWARD_INTEREST:
#elif CefC_Dtc
	/*--------------------------------------------------------------------
		Content Store
	----------------------------------------------------------------------*/
	if (tp_plugin_res & CefC_Pi_Object_Match) {
		
		if (pm.app_comp == CefC_T_APP_FROM_PUB) {
			if (pm.chnk_num_f) {
				name_len = pm.name_len - (CefC_S_TLF + CefC_S_ChunkNum);
			} else {
				name_len = pm.name_len;
			}
			if (cef_hash_tbl_item_check_exact (hdl->app_reg, pm.name, name_len) < 0) {
				forward_interest_f = 1;
				goto FORWARD_INTEREST;
			}
		}
		
		/* Checks Reply 	*/
		if (!poh.longlife_f) {
			if (pit_res != 0) {
				pit_res = cef_csmgr_rep_f_check (pe, peer_faceid);
			}
			if ((pit_res == 0) || (dnfaces == pe->dnfacenum)) {
				goto FORWARD_INTEREST;
			}
		}
		
		/* Checks Content Store */
		if ((poh.lifetime_f) && (poh.lifetime > 0) && (pm.app_comp == CefC_T_APP_DTC)) {
			/* Checks the temporary cache in cefnetd 		*/
			cs_res = cef_csmgr_cache_lookup (hdl->cs_stat, peer_faceid, &pm, &poh, pe);
			
			if (cs_res >= 0) {
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Finer, 
					"Return the Content Object from the buffer\n");
#endif // CefC_Debug
				cef_pit_down_faceid_remove (pe, peer_faceid);
				
				if (pe->dnfacenum == 0) {
					cef_pit_entry_free (hdl->pit, pe);
				}
				return (-1);
			}
			/* Save Interest */
			if (!pe->dtc_f) {
				CefT_Dtc_Pit_Entry* dtc_entry;
				dtc_entry = cef_pit_dtc_entry_create(msg, payload_len + header_len);
				if (dtc_entry) {
					pe->dtc_f = 1;
					pe->dtc_entry = dtc_entry;
					dtc_entry->key_len = pe->klen;
					dtc_entry->key = pe->key;
					dtc_entry->faceid = (uint16_t)peer_faceid;
					cef_pit_dtc_entry_insert(dtc_entry);
				}
			}
		}
	}
	
	if ((pit_res != 0) && (cs_res != 0)) {
		forward_interest_f = 1;
	}
FORWARD_INTEREST:
#else // CefC_ContentStore
	if (pit_res != 0) {
		forward_interest_f = 1;
	}
#endif // CefC_ContentStore

	/*--------------------------------------------------------------------
		Forwards the received Interest
	----------------------------------------------------------------------*/
	if ((tp_plugin_res & CefC_Pi_Interest_Send) && 
		(forward_interest_f) && (face_num > 0)) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finer, "Forward the Interest to the next cefnetd(s)\n");
#endif // CefC_Debug
		cefnetd_interest_forward (
			hdl, faceids, face_num, peer_faceid, msg,
			payload_len, header_len, &pm, &poh, pe, fe
		);
		return (1);
	}
	if (tp_plugin_res & CefC_Pi_Interest_Send) {
		if (pm.chnk_num_f) {
			name_len = pm.name_len - (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
		} else {
			name_len = pm.name_len;
		}
		fip = (uint16_t*) cef_hash_tbl_item_get_for_app (hdl->app_reg, pm.name, name_len);
		
		if (fip) {
			if (cef_face_check_active (*fip) > 0) {
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Finer, 
					"Forward the Interest to the local application(s)\n");
#endif // CefC_Debug
				cef_face_frame_send_forced (
					*fip, msg, (size_t) (payload_len + header_len));
			}
			
			return (1);
		}
		
#ifdef CefC_NdnPlugin
		if ((hdl->plugin_hdl.ndn)->cef_int) {
			if (pe) {
				cef_pit_entry_free (hdl->pit, pe);
			}
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finer, 
				"Forward the Interest to the NFD node(s) via NDN plugin\n");
#endif // CefC_Debug
			(*((hdl->plugin_hdl.ndn))->cef_int)(hdl->plugin_hdl.ndn, 
					msg, payload_len + header_len, &pm, &poh, peer_faceid);
		}
#endif // CefC_NdnPlugin
	}
	
	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the received Interest message has the Symbolic Code
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_interest_with_symbolic_code_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	CefT_Parsed_Message* pm, 				/* Parsed CEFORE message					*/
	CefT_Parsed_Opheader* poh				/* Parsed Option Header						*/
) {
	CefT_Pit_Entry* pe = NULL;
	uint32_t range;
	uint32_t mask;
	uint32_t trg_seq;
	int idx;
	int i, n, start;
	int response_num = 0;
	int res;
	uint32_t bit;
	
	CefT_Fib_Entry* fe = NULL;
	uint16_t faceids[CefC_Fib_UpFace_Max];
	uint16_t face_num = 0;
	unsigned char trg_name[CefC_Max_Length];
	struct value32_tlv value32_fld;
	uint16_t org_name_len;
	uint16_t trg_name_len;
#ifdef CefC_ContentStore
	unsigned int dnfaces = 0;
#endif // CefC_ContentStore
	
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finer, 
		"Process the Interest with the Symbolic Code (%d bytes)\n", 
		payload_len + header_len);
#endif // CefC_Debug
	
#ifdef CefC_Innovate_Debug
	{
		fprintf (stderr, "------------------------------------\n");
		fprintf (stderr, "time=%lu\n", hdl->nowtus);
		
		for (i = 0 ; i < payload_len + header_len ; i++) {
			
			if ((i > 0) && (i % 8 ==0)) {
				fprintf (stderr, "\n");
			}
			fprintf (stderr, "%02X ", msg[i]);
		}
		fprintf (stderr, "\n\n");
		
		fprintf (stderr, "min_seq    = %u\n", pm->min_seq);
		fprintf (stderr, "max_seq    = %u\n", pm->max_seq);
		fprintf (stderr, "number_f   = %u\n", poh->number_f);
		fprintf (stderr, "number     = %u\n", poh->number);
		fprintf (stderr, "bitmap_f   = %u\n", poh->bitmap_f);
		
		fprintf (stderr, "bitmap\n");
		for (i = 0 ; i < CefC_S_Bitmap ; i++) {
			fprintf (stderr, "  [%d] %08X\n", i, poh->bitmap[i]);
		}
	}
#endif // CefC_Innovate_Debug
	
	/* If T_NUMBER dose not exist, adjusting the number 	*/
	if (poh->number_f == 0) {
		poh->number = pm->max_seq - pm->min_seq + 1;
	}
	if (pm->min_seq > pm->max_seq) {
		return (1);
	}
	/* Searches a FIB entry matching this Interest 		*/
	fe = cef_fib_entry_search (hdl->fib, pm->name, pm->name_len);
	
	if (fe) {
		face_num = cef_fib_forward_faceid_select (fe, peer_faceid, faceids);
	}
	
	org_name_len = pm->name_len;
	memcpy (trg_name, pm->name, pm->name_len);
	
	/* Calculation start index to check 		*/
	range 	= pm->max_seq - pm->min_seq + 1;
	idx		= (256 - range) / 32;
	start 	= (256 - range) % 32;
	trg_seq = pm->min_seq;
	
	while (idx < CefC_S_Bitmap) {
		
		for (i = start ; i < 32 ; i++) {
			
			/* Checks the bit (0=request/1=not request) 	*/
			bit = (poh->bitmap[idx] << i) & 0x80000000;
			if (bit) {
				trg_seq++;
				continue;
			}
#ifdef CefC_Innovate_Debug
			fprintf (stderr, " Trg Seq: %u\n", trg_seq);
#endif // CefC_Innovate_Debug
			
			/* Searches the PIT entry 		*/
			trg_name_len = org_name_len;
			value32_fld.type   = htons (CefC_T_CHUNK);
			value32_fld.length = htons (CefC_S_ChunkNum);
			value32_fld.value  = htonl (trg_seq);
			memcpy (&trg_name[trg_name_len], &value32_fld, sizeof (struct value32_tlv));
			trg_name_len += sizeof (struct value32_tlv);
			memcpy (&trg_name[trg_name_len], 
				&msg[pm->symbolic_code_f], CefC_S_TLF + CefC_S_Symbolic_Code);
			trg_name_len += CefC_S_TLF + CefC_S_Symbolic_Code;
			pm->name_len = trg_name_len;
			memcpy (pm->name, trg_name, trg_name_len);
			pm->chnk_num_f 	= 1;
			pm->chnk_num 	= trg_seq;
			
			pe = cef_pit_entry_lookup (hdl->pit, pm, poh);
			
			if (pe == NULL) {
				return (-1);
			}
			
#ifdef CefC_ContentStore
			dnfaces = pe->dnfacenum;
#endif // CefC_ContentStore
			
			/* Updates the information of down face that this Interest arrived 	*/
			cef_pit_entry_down_face_update (pe, peer_faceid, pm, poh, msg);
			
			for (n = 0 ; n < face_num ; n++) {
				cef_pit_entry_up_face_update (pe, faceids[n], pm, poh);
			}
			
#ifdef CefC_ContentStore
			
			if (dnfaces == pe->dnfacenum) {
				trg_seq++;
				continue;
			}
			
			/* Checks Content Store */
			if ((hdl->cs_stat->cache_type == CefC_Cache_Type_Excache) &&
				((poh->lifetime_f) && (poh->lifetime > 0))) {
				
				/* Checks dnface reply flag */
				res = cef_csmgr_rep_f_check (pe, peer_faceid);
				if (res == 0) {
					trg_seq++;
					continue;
				}
				
				/* Checks temporary cache 	*/
				pm->name_len = trg_name_len - (CefC_S_TLF + CefC_S_Symbolic_Code);
				res = cef_csmgr_cache_lookup (hdl->cs_stat, peer_faceid, pm, poh, pe);
				
				/* Checks Content Store */
				if (res < 0) {
					/* Cache does not exist in the temporary cache in cefnetd, 		*/
					/* so inquiries to the csmgrd 									*/
					cef_csmgr_excache_lookup (hdl->cs_stat, peer_faceid, pm, poh, pe);
				} else {
					cef_pit_down_faceid_remove (pe, peer_faceid);
					
					if (pe->dnfacenum == 0) {
						cef_pit_entry_free (hdl->pit, pe);
					}
				}
			} else {
				res = -1;
			}
#else // CefC_ContentStore
			res = -1;
#endif // CefC_ContentStore
			if (res >= 0) {
				mask = 1;
				mask = mask << (32 - i - 1);
				poh->bitmap[idx] |= mask;
				response_num++;
				
#ifdef CefC_Innovate_Debug
				fprintf (stderr, "  Update Bitmap[%d]:%08X\n", idx, poh->bitmap[idx]);
#endif // CefC_Innovate_Debug
			}
			
			if (response_num == poh->number) {
				idx = CefC_S_Bitmap;
				break;
			}
			trg_seq++;
		}
		idx++;
		start = 0;
	}
	
	if (response_num == poh->number) {
		if (pe != NULL) {
			cef_pit_entry_free (hdl->pit, pe);
		}
		return (1);
	}
	
	/*--------------------------------------------------------------------
		Forwards the received Interest
	----------------------------------------------------------------------*/
	poh->number -= response_num;
	
	/* Searches a FIB entry matching this Interest 		*/
	pm->name_len = org_name_len;
	pm->chnk_num_f = 0;
	
	/* Obtains Face-ID(s) to forward the Interest */
	if (fe) {
		pe = cef_pit_entry_lookup (hdl->pit, pm, poh);
		
		if (pe == NULL) {
			return (-1);
		}
		cef_pit_entry_down_face_update (pe, peer_faceid, pm, poh, msg);
		
		/* Updates the T_INNOVATIVE and T_NUMBER 		*/
		if (response_num > 0) {
			cef_frame_innovative_update (
				msg, poh->bitmap, poh->bitmap_f, poh->number, poh->number_f);
			
#ifdef CefC_Innovate_Debug
			{
				fprintf (stderr, "\n");
				fprintf (stderr, "############## Forward Interest ##############\n");
				
				fprintf (stderr, "number_f   = %u\n", poh->number_f);
				fprintf (stderr, "number     = %u\n", poh->number);
				
				fprintf (stderr, "bitmap\n");
				for (i = 0 ; i < CefC_S_Bitmap ; i++) {
					fprintf (stderr, "  [%d] %08X\n", i, poh->bitmap[i]);
				}
				fprintf (stderr, "\n");
				
				for (i = 0 ; i < payload_len + header_len ; i++) {
					
					if ((i > 0) && (i % 8 ==0)) {
						fprintf (stderr, "\n");
					}
					fprintf (stderr, "%02X ", msg[i]);
				}
				fprintf (stderr, "\n\n");
			}
#endif // CefC_Innovate_Debug
		}
		
		face_num = cef_fib_forward_faceid_select (fe, peer_faceid, faceids);
		
		cefnetd_interest_forward (
			hdl, faceids, face_num, peer_faceid, msg,
			payload_len, header_len, pm, poh, pe, fe);
	}
	
	return (1);
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
	uint16_t header_len						/* Header Length of this message			*/
) {
	CefT_Parsed_Message pm;
	CefT_Parsed_Opheader poh;
	CefT_Pit_Entry* pe;
	int res;
	uint16_t faceids[CefC_Fib_UpFace_Max];
	uint16_t face_num = 0;
	CefT_Down_Faces* face;
	CefT_Rx_Elem elem;
	int i;
	int tp_plugin_res = CefC_Pi_All_Permission;
	
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finer, 
		"Process the Content Object (%d bytes)\n", payload_len + header_len);
#endif // CefC_Debug
	
	if (payload_len + header_len > CefC_Max_Msg_Size) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Content Object is too large\n");
#endif // CefC_Debug
		return (-1);
	}
	
	/* Checks the Validation 			*/
	res = cef_valid_msg_verify (msg, payload_len + header_len);
	if (res != 0) {
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
	{
		int dbg_x;
//		unsigned char pubkey[CefC_Max_Length];
		
		sprintf (cnd_dbg_msg, "Object's Name [");
		
		for (dbg_x = 0 ; dbg_x < pm.name_len ; dbg_x++) {
			sprintf (cnd_dbg_msg, "%s %02X", cnd_dbg_msg, pm.name[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finer, "%s ]\n", cnd_dbg_msg);
//		cef_valid_get_pubkey (msg, pubkey);
	}
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

#ifdef CefC_ContentStore
	/*--------------------------------------------------------------------
		Content Store
	----------------------------------------------------------------------*/
	/* Stores Content Object to Content Store 		*/
	if ((pm.expiry > 0) && (hdl->cs_stat->cache_type == CefC_Cache_Type_Excache)) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finer, "Forward the Content Object to csmgrd\n");
#endif // CefC_Debug
		cef_csmgr_excache_item_put (
			hdl->cs_stat, msg, payload_len + header_len, peer_faceid, &pm, &poh);
	}
#elif CefC_Dtc
	/*--------------------------------------------------------------------
		Cefore-DTC temp cache
	----------------------------------------------------------------------*/
	if (pm.expiry > 0) {
		cef_csmgr_dtc_item_put (
			hdl->cs_stat, msg, payload_len + header_len, &pm, &poh);
	}
#endif // CefC_ContentStore
	
	/* Searches a PIT entry matching this Object 	*/
	pe = cef_pit_entry_search (hdl->pit, &pm, &poh);
	
	if (pe) {
		face = &(pe->dnfaces);
		
		while (face->next) {
			face = face->next;
			faceids[face_num] = face->faceid;
			face_num++;
		}
#ifdef CefC_Innovate_Debug
		fprintf (stderr, "# HIT PIT : %u\n", pm.chnk_num);
#endif // CefC_Innovate_Debug
	} else {
		stat_nopit_frames++;
		
#ifdef CefC_NdnPlugin
		if ((hdl->plugin_hdl.ndn)->cef_cob) {
			(*((hdl->plugin_hdl.ndn))->cef_cob)(
				hdl->plugin_hdl.ndn, msg, payload_len + header_len, &pm, &poh);
		}
#endif // CefC_NdnPlugin
		return (-1);
	}

#ifdef CefC_Mobility
	/*--------------------------------------------------------------------
		Mobility Plugin
	----------------------------------------------------------------------*/
	if ((hdl->plugin_hdl.mb)->cob) {
		
		/* Creates CefT_Rx_Elem 		*/
		pm.seqnum = poh.seqnum;
		memset (&elem, 0, sizeof (CefT_Rx_Elem));
		elem.type 				= CefC_Elem_Type_Object;
		elem.hashv 				= pe->hashv;
		elem.in_faceid 			= (uint16_t) peer_faceid;
		elem.parsed_msg 		= &pm;
		memcpy (&(elem.msg[0]), msg, payload_len + header_len);
		elem.msg_len 			= payload_len + header_len;
		elem.out_faceid_num 	= face_num;
		
		for (i = 0 ; i < face_num ; i++) {
			elem.out_faceids[i] = faceids[i];
		}
		
		/* Callback 		*/
		tp_plugin_res = (*((hdl->plugin_hdl.mb))->cob)(
			hdl->plugin_hdl.mb, &elem
		);
	}
#endif // CefC_Mobility

	/*--------------------------------------------------------------------
		Transport Plugin
	----------------------------------------------------------------------*/
	if (poh.tp_variant > CefC_T_OPT_TP_NONE) {

		if (hdl->plugin_hdl.tp[poh.tp_variant].cob) {

			/* Creates CefT_Rx_Elem 		*/
			memset (&elem, 0, sizeof (CefT_Rx_Elem));
			elem.plugin_variant 	= poh.tp_variant;
			elem.type 				= CefC_Elem_Type_Object;
			elem.hashv 				= pe->hashv;
			elem.in_faceid 			= (uint16_t) peer_faceid;
			elem.parsed_msg 		= &pm;
			memcpy (&(elem.msg[0]), msg, payload_len + header_len);
			elem.msg_len 			= payload_len + header_len;
			elem.out_faceid_num 	= face_num;

			for (i = 0 ; i < face_num ; i++) {
				elem.out_faceids[i] = faceids[i];
			}

			memcpy (elem.ophdr, poh.tp_value, poh.tp_length);
			elem.ophdr_len = poh.tp_length;

			/* Callback 		*/
			tp_plugin_res = (*(hdl->plugin_hdl.tp)[poh.tp_variant].cob)(
				&(hdl->plugin_hdl.tp[poh.tp_variant]), &elem
			);
		}
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
				cef_pit_entry_free (hdl->pit, pe);
			}
			return (1);
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
	uint16_t header_len						/* Header Length of this message			*/
) {
	// TODO
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
	CefT_Parsed_Message pm;
	CefT_Parsed_Opheader poh;
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
	{
		int dbg_x;
		
		sprintf (cnd_dbg_msg, "Piggyback Interest's Name [");
		
		for (dbg_x = 0 ; dbg_x < pm.name_len ; dbg_x++) {
			sprintf (cnd_dbg_msg, "%s %02X", cnd_dbg_msg, pm.name[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finer, "%s ]\n", cnd_dbg_msg);
	}
#endif // CefC_Debug
	
#ifdef CefC_ContentStore
	/*--------------------------------------------------------------------
		Content Store
	----------------------------------------------------------------------*/
	/* Stores Content Object to Content Store 		*/
	if ((pm.expiry > 0) && (hdl->cs_stat->cache_type == CefC_Cache_Type_Excache)) {
		cef_csmgr_excache_item_put (
			hdl->cs_stat, pkt, (msg_len + header_len), peer_faceid, &pm, &poh);
	}
#endif // CefC_ContentStore
	
	/* Searches a PIT entry matching this Object 	*/
	if (pm.chnk_num_f) {
		pm.name_len -= (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
	}
	
	pe = cef_pit_entry_search (hdl->pit, &pm, &poh);
	
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
	Handles the received Cefping Request
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_pingreq_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len						/* Header Length of this message			*/
) {
#ifdef CefC_Cefping
	CefT_Parsed_Message pm;
	CefT_Parsed_Opheader poh;

	int res, i;
	CefT_Pit_Entry* pe;
	CefT_Fib_Entry* fe = NULL;
	uint16_t name_len;
	uint8_t return_code;
	uint16_t faceids[CefC_Fib_UpFace_Max];
	uint16_t face_num = 0;
	int responder_f = 0;
	int cached_f = 0;
	unsigned char buff[CefC_Max_Length];
	
#ifndef CefC_Android
	unsigned char peer_node_id[16];
	unsigned char node_id[16];
	int id_len;
#endif // CefC_Android
	
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finer, 
		"Process the Ping Request (%d bytes)\n", payload_len + header_len);
#endif // CefC_Debug
	
	if (payload_len + header_len > CefC_Max_Msg_Size) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Ping Request is too large\n");
#endif // CefC_Debug
		return (-1);
	}
	
	/* Parses the received  Cefping Request	*/
	res = cef_frame_message_parse (
					msg, payload_len, header_len, &poh, &pm, CefC_PT_PING_REQ);
	if (res < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Detects the invalid Ping Request\n");
#endif // CefC_Debug
		return (-1);
	}
#ifdef CefC_Debug
	{
		int dbg_x;
		
		sprintf (cnd_dbg_msg, "Ping Request's Name [");
		
		for (dbg_x = 0 ; dbg_x < pm.name_len ; dbg_x++) {
			sprintf (cnd_dbg_msg, "%s %02X", cnd_dbg_msg, pm.name[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finer, "%s ]\n", cnd_dbg_msg);
	}
#endif // CefC_Debug
	
#ifdef CefC_ContentStore
	/* Check whether the Cob exists in cache or not 	*/
	cached_f = 0;
	return_code = CefC_CpRc_NoCache;
	
	if (hdl->cs_stat->cache_type == CefC_Cache_Type_Excache) {
		res = cef_csmgr_excache_item_check (hdl->cs_stat, pm.name, pm.name_len);
		if (res > 0) {
			cached_f = 1;
			return_code = CefC_CpRc_Cache;
		}
	}
#else // CefC_ContentStore
	cached_f = 0;
	return_code = CefC_CpRc_NoCache;
#endif // CefC_ContentStore

	/* Check whether I am the responder or not 		*/
	if (poh.responder_f > 0) {
		if (poh.responder_f > 4) {
			for (i = 0 ; i < hdl->nodeid16_num ; i++) {
				if (memcmp (&hdl->nodeid16[i][0], poh.responder_id, 16) == 0) {
					responder_f = 1;
					break;
				}
			}
		} else {
			for (i = 0 ; i < hdl->nodeid4_num ; i++) {
				if (memcmp (&hdl->nodeid4[i][0], poh.responder_id, 4) == 0) {
					responder_f = 1;
					break;
				}
			}
		}
	} else {
#ifndef CefC_Android
		id_len = cef_face_node_id_get (peer_faceid, peer_node_id);
		id_len = cefnetd_matched_node_id_get (hdl, peer_node_id, id_len, node_id);
		memcpy (poh.responder_id, node_id, id_len);
		poh.responder_f = id_len;
#else // CefC_Android
		memcpy (poh.responder_id, hdl->top_nodeid, hdl->top_nodeid_len);
		poh.responder_f = hdl->top_nodeid_len;
#endif // CefC_Android
		if (cached_f) {
			responder_f = 1;
		}
	}
	
	if (responder_f) {
		memset (buff, 0, CefC_Max_Length);
		
		res = cef_frame_cefping_rep_create (buff, return_code, poh.responder_id,
			poh.responder_f, pm.name, pm.name_len);
		
		if (res > 0) {
			cef_face_frame_send_forced (peer_faceid, buff, (size_t) res);
		}
		return (1);
	}
	
	/* Searches a FIB entry matching this request 		*/
	if (pm.chnk_num_f) {
		name_len = pm.name_len - (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
	} else {
		/* Symbolic Interest	*/
		name_len = pm.name_len;
	}
	
	/* Searches a FIB entry matching this request 		*/
	fe = cef_fib_entry_search (hdl->fib, pm.name, name_len);
	
	/* Obtains Face-ID(s) to forward the request */
	if (fe) {
		face_num = cef_fib_forward_faceid_select (fe, peer_faceid, faceids);
	} else {
		return_code = CefC_CpRc_NoRoute;
		memset (buff, 0, CefC_Max_Length);
		
		res = cef_frame_cefping_rep_create (buff, return_code, poh.responder_id,
			poh.responder_f, pm.name, pm.name_len);
		
		if (res > 0) {
			cef_face_frame_send_forced (peer_faceid, buff, (size_t) res);
		}
		return (1);
	}
	
	/* Searches a PIT entry matching this request 	*/
	pe = cef_pit_entry_lookup (hdl->pit, &pm, &poh);
	
	if (pe == NULL) {
		return (-1);
	}
	
	/* Updates the information of down face that this request arrived 	*/
	res = cef_pit_entry_down_face_update (pe, peer_faceid, &pm, &poh, msg);
	
	/* Forwards the received Cefping Request */
	if (res != 0) {
		cefnetd_interest_forward (
			hdl, faceids, face_num, peer_faceid, msg,
			payload_len, header_len, &pm, &poh, pe, fe);
	}
	
#endif // CefC_Cefping
	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the received Cefping Replay
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_pingrep_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len						/* Header Length of this message			*/
) {
#ifdef CefC_Cefping
	CefT_Parsed_Message pm;
	CefT_Parsed_Opheader poh;
	CefT_Pit_Entry* pe;
	int res, i;
	uint16_t faceids[CefC_Fib_UpFace_Max];
	uint16_t face_num = 0;
	CefT_Down_Faces* face;
	
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finer, 
		"Process the Ping Response (%d bytes)\n", payload_len + header_len);
#endif // CefC_Debug
	
	/* Check the message size 		*/
	if (payload_len + header_len > CefC_Max_Msg_Size) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Ping Response is too large\n");
#endif // CefC_Debug
		return (-1);
	}
	
	/* Parses the received  Cefping Replay 	*/
	res = cef_frame_message_parse (
					msg, payload_len, header_len, &poh, &pm, CefC_PT_PING_REP);
	if (res < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Detects the invalid Ping Response\n");
#endif // CefC_Debug
		return (-1);
	}
#ifdef CefC_Debug
	{
		int dbg_x;
		
		sprintf (cnd_dbg_msg, "Ping Response's Name [");
		
		for (dbg_x = 0 ; dbg_x < pm.name_len ; dbg_x++) {
			sprintf (cnd_dbg_msg, "%s %02X", cnd_dbg_msg, pm.name[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finer, "%s ]\n", cnd_dbg_msg);
	}
#endif // CefC_Debug
	
	/* Searches a PIT entry matching this replay 	*/
	pe = cef_pit_entry_search (hdl->pit, &pm, &poh);
	
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
	
	/* Forwards the Cefping Replay 					*/
	for (i = 0 ; i < face_num ; i++) {
		if (cef_face_check_active (faceids[i]) > 0) {
			cef_face_frame_send_forced (faceids[i], msg, payload_len + header_len);
		} else {
			cef_pit_down_faceid_remove (pe, faceids[i]);
		}
	}
	
#endif // CefC_Cefping
	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the received Cefinfo Request
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_tracereq_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len						/* Header Length of this message			*/
) {
#ifdef CefC_Cefinfo
	CefT_Parsed_Message pm;
	CefT_Parsed_Opheader poh;
	int res;
	int forward_req_f = 0;
	uint16_t new_header_len;
	uint16_t return_code = CefC_CtRc_NoError;
	CefT_Pit_Entry* pe;
	CefT_Fib_Entry* fe = NULL;
	uint16_t name_len;
	uint16_t pkt_len;
	uint16_t faceids[CefC_Fib_UpFace_Max];
	uint16_t face_num = 0;
	struct timeval t;
	uint16_t* fip;
	
#ifndef CefC_Android
	unsigned char peer_node_id[16];
	unsigned char node_id[16];
#endif // CefC_Android
	
	unsigned char stamp_node_id[16] = {0};
	int id_len;
	
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finer, 
		"Process the Trace Request (%d bytes)\n", payload_len + header_len);
#endif // CefC_Debug
	
	/* Check the message size 		*/
	if (payload_len + header_len > CefC_Max_Msg_Size) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Trace Request is too large\n");
#endif // CefC_Debug
		return (-1);
	}
	
	/* Parses the received  Cefinfo Request 	*/
	res = cef_frame_message_parse (
					msg, payload_len, header_len, &poh, &pm, CefC_PT_TRACE_REQ);
	if (res < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Detects the invalid Trace Request\n");
#endif // CefC_Debug
		return (-1);
	}
#ifdef CefC_Debug
	{
		int dbg_x;
		
		sprintf (cnd_dbg_msg, "Trace Request's Name [");
		
		for (dbg_x = 0 ; dbg_x < pm.name_len ; dbg_x++) {
			sprintf (cnd_dbg_msg, "%s %02X", cnd_dbg_msg, pm.name[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finer, "%s ]\n", cnd_dbg_msg);
	}
#endif // CefC_Debug
	
	/* Adds the time stamp on this request 		*/
#ifndef CefC_Android
	id_len = cef_face_node_id_get (peer_faceid, peer_node_id);
	id_len = cefnetd_matched_node_id_get (hdl, peer_node_id, id_len, node_id);
	memcpy (stamp_node_id, node_id, id_len);
#else // CefC_Android
	id_len = hdl->top_nodeid_len;
	if (id_len > 0) {
		memcpy (stamp_node_id, hdl->top_nodeid, id_len);
	}
#endif // CefC_Android
	
	new_header_len 
		= header_len + CefC_S_TLF + id_len + CefC_S_ReqArrivalTime;
	
	if ((poh.skip_hop == 0) &&
		(new_header_len <= CefC_Max_Header_Size)) {
		
		gettimeofday (&t, NULL);
		
		pkt_len = cef_frame_cefinfo_req_add_stamp (
						msg, payload_len + header_len, stamp_node_id, id_len, t);
		header_len 	= msg[CefC_O_Fix_HeaderLength];
		payload_len = pkt_len - header_len;
	}
	
	/* Check whether this cefnetd will be the responder 	*/
	if (poh.skip_hop > 0) {
		forward_req_f = 1;
	} else if (new_header_len > CefC_Max_Header_Size) {
		forward_req_f = 0;
		return_code = CefC_CtRc_NoSpace;
#ifdef CefC_ContentStore
	} else if (hdl->cs_stat != NULL) {
		/* Checks whether the specified contents is cached 	*/
		if (hdl->cs_stat->cache_type == CefC_Cache_Type_Excache) {
			res = cef_csmgr_excache_item_check (hdl->cs_stat, pm.name, pm.name_len);
			if (res < 0) {
				forward_req_f = 1;
			} else {
				forward_req_f = 0;
			}
			if (forward_req_f != 1) {
				if (poh.trace_flag & CefC_CtOp_NoCache) {
					/* NOP */;
				} else {
					res = cefnetd_external_cache_seek (
						hdl, peer_faceid, msg, payload_len, header_len, &pm, &poh);
					
					if (res > 0) {
						return (1);
					}
					forward_req_f = 1;
				}
			}
		} else {
			forward_req_f = 1;
		}
#endif // CefC_ContentStore
	} else {
		forward_req_f = 1;
	}
	
	if ((forward_req_f == 1) && (pm.hoplimit == 1)) {
		forward_req_f = 0;
		return_code = CefC_CtRc_NoInfo;
	}
	
	if (forward_req_f) {
		/* Searches a FIB entry matching this request 		*/
		if (pm.chnk_num_f) {
			name_len = pm.name_len - (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
		} else {
			/* Symbolic Interest	*/
			name_len = pm.name_len;
		}
		
		/* Searches a FIB entry matching this request 	*/
		fe = cef_fib_entry_search (hdl->fib, pm.name, name_len);
		
		/* Obtains Face-ID(s) to forward the request 	*/
		if (fe) {
			
			/* Obtains the FaceID(s) to forward the request 	*/
			face_num = cef_fib_forward_faceid_select (fe, peer_faceid, faceids);
			
			/* Searches a PIT entry matching this request 	*/
			pe = cef_pit_entry_lookup (hdl->pit, &pm, &poh);
			
			if (pe == NULL) {
				return (-1);
			}
			
			/* Updates the information of down face that this request arrived 	*/
			res = cef_pit_entry_down_face_update (pe, peer_faceid, &pm, &poh, msg);
			
			/* Forwards the received Cefinfo Request */
			if (res != 0) {
				
				if (!cef_face_is_local_face (peer_faceid)) {
					
					/* Updates the skip hop 					*/
					if (poh.skip_hop > 0) {
						poh.skip_hop--;
						msg[poh.skip_hop_offset] = poh.skip_hop;
					}
				}
				
				/* Forwards 		*/
				cefnetd_interest_forward (
					hdl, faceids, face_num, peer_faceid, msg,
					payload_len, header_len, &pm, &poh, pe, fe);
			}
			return (1);
		} else {
			return_code = CefC_CtRc_NoRoute;
		}
	}
	
	/* Searches a App Reg Table entry matching this request 		*/
	if (pm.chnk_num_f) {
		name_len = pm.name_len - (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
	} else {
		name_len = pm.name_len;
	}
	fip = (uint16_t*) cef_hash_tbl_item_get (hdl->app_reg, pm.name, name_len);
	if (fip) {
		return_code = CefC_CtRc_NoError;
	}
	
	/* Set PacketType and Return Code 		*/
	msg[CefC_O_Fix_Type] 			= CefC_PT_TRACE_REP;
	msg[CefC_O_Fix_Trace_RetCode] 	= return_code;
	
	/* Returns a Cefinfo Reply with error return code 		*/
	cef_face_frame_send_forced (peer_faceid, msg, payload_len + header_len);
	
#endif // CefC_Cefinfo
	
	return (1);
}

#ifdef CefC_ContentStore
#ifdef CefC_Cefinfo
/*--------------------------------------------------------------------------------------
	Seeks the csmgrd and creates the cefinfo response
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_external_cache_seek (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	CefT_Parsed_Message* pm,				/* Structure to set parsed CEFORE message	*/
	CefT_Parsed_Opheader* poh
) {
	unsigned char buff[CefC_Max_Length] = {0};
	int res;
	uint16_t pld_len;
	uint16_t index;
	uint16_t name_len;
	uint16_t msg_len;
	uint16_t pkt_len;
	struct tlv_hdr pyld_tlv_hdr;
	struct fixed_hdr* fix_hdr;
	struct tlv_hdr* tlv_hp;
	struct tlv_hdr* rply_tlv_hdr;
	struct tlv_hdr* name_tlv_hdr;
	
	res = cef_csmgr_excache_info_get (
		hdl->cs_stat, pm->name, pm->name_len, buff, 
						poh->trace_flag & CefC_CtOp_ReqPartial);
	
	if (res < 1) {
		return (0);
	}
	
	/* Returns a Cefinfo Reply 			*/
	if (res) {
		pld_len = (uint16_t) res;
		index   = 0;
		
		while (index < pld_len) {
			rply_tlv_hdr = (struct tlv_hdr*) &buff[index];
			index += CefC_S_TLF + sizeof (struct trace_rep_block);
			
			name_tlv_hdr = (struct tlv_hdr*) &buff[index];
			name_len = ntohs (name_tlv_hdr->length);
			index += CefC_S_TLF;
			
			/* Sets the header of Reply Block 		*/
			if (cef_hash_tbl_item_check_exact (
				hdl->app_reg, &buff[index], name_len) > 0) {
				rply_tlv_hdr->type 
					= htons (CefC_T_TRACE_CONTENT_OWNER | CefC_T_TRACE_ON_CSMGRD);
			} else {
				rply_tlv_hdr->type 
					= htons (CefC_T_TRACE_CONTENT | CefC_T_TRACE_ON_CSMGRD);
			}
			
			index += name_len;
		}
		
		/* Sets type and length of T_PAYLOAD 		*/
		pyld_tlv_hdr.type 	 = htons (CefC_T_PAYLOAD);
		pyld_tlv_hdr.length  = htons (pld_len);
		memcpy (&msg[payload_len + header_len], &pyld_tlv_hdr, sizeof (struct tlv_hdr));
		memcpy (&msg[payload_len + header_len + CefC_S_TLF], buff, pld_len);
		
		/* Sets ICN message length 	*/
		pkt_len = payload_len + header_len + CefC_S_TLF + pld_len;
		msg_len = pkt_len - (header_len + CefC_S_TLF);
		
		tlv_hp = (struct tlv_hdr*) &msg[header_len];
		tlv_hp->length = htons (msg_len);
		
		/* Updates PacketLength and HeaderLength 		*/
		fix_hdr = (struct fixed_hdr*) msg;
		fix_hdr->type 	  = CefC_PT_TRACE_REP;
		fix_hdr->reserve1 = CefC_CtRc_NoError;
		fix_hdr->pkt_len  = htons (pkt_len);
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Trace response is follow:\n");
		cef_dbg_buff_write (CefC_Dbg_Finest, msg, pkt_len);
#endif // CefC_Debug
		cef_face_frame_send_forced (peer_faceid, msg, pkt_len);
		
		return (1);
	}
	
	return (0);
}
#endif // CefC_Cefinfo
#endif // CefC_ContentStore

/*--------------------------------------------------------------------------------------
	Handles the received Cefinfo Replay
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_tracerep_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len						/* Header Length of this message			*/
) {
#ifdef CefC_Cefinfo
	
	CefT_Parsed_Message pm;
	CefT_Parsed_Opheader poh;
	CefT_Pit_Entry* pe;
	int res, i;
	uint16_t faceids[CefC_Fib_UpFace_Max];
	uint16_t face_num = 0;
	CefT_Down_Faces* face;
	
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finer, 
		"Process the Trace Response (%d bytes)\n", payload_len + header_len);
#endif // CefC_Debug
	
	/* Check the message size 		*/
	if (payload_len + header_len > CefC_Max_Msg_Size) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Trace Response is too large\n");
#endif // CefC_Debug
		return (-1);
	}

	/* Parses the received  Cefping Replay 	*/
	res = cef_frame_message_parse (
					msg, payload_len, header_len, &poh, &pm, CefC_PT_TRACE_REP);
	if (res < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Detects the invalid Trace Response\n");
#endif // CefC_Debug
		return (-1);
	}
#ifdef CefC_Debug
	{
		int dbg_x;
		
		sprintf (cnd_dbg_msg, "Trace Response's Name [");
		
		for (dbg_x = 0 ; dbg_x < pm.name_len ; dbg_x++) {
			sprintf (cnd_dbg_msg, "%s %02X", cnd_dbg_msg, pm.name[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finer, "%s ]\n", cnd_dbg_msg);
	}
#endif // CefC_Debug
	
	/* Searches a PIT entry matching this replay 	*/
	pe = cef_pit_entry_search (hdl->pit, &pm, &poh);

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

	/* Forwards the Cefping Replay 					*/
	for (i = 0 ; i < face_num ; i++) {

		if (cef_face_check_active (faceids[i]) > 0) {
			cef_face_frame_send_forced (faceids[i], msg, payload_len + header_len);
		} else {
			cef_pit_down_faceid_remove (pe, faceids[i]);
		}
	}
	
#endif // CefC_Cefinfo
	return (1);
}
#ifdef CefC_ContentStore
/*--------------------------------------------------------------------------------------
	Handles the received Interest from csmgrd
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_csmgrd_interest_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len						/* Header Length of this message			*/
) {
	/* NOP */;
	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the received Object from csmgrd
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_csmgrd_object_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len						/* Header Length of this message			*/
) {
	CefT_Parsed_Message pm;
	CefT_Parsed_Opheader poh;
	CefT_Pit_Entry* pe;
	int res;
	uint16_t faceids[CefC_Fib_UpFace_Max];
	uint16_t face_num = 0;
	CefT_Down_Faces* face;
	
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finer, 
		"Process the Content Object (%d bytes) from csmgrd\n", payload_len + header_len);
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
			"Detects the invalid Content Object from csmgrd\n");
#endif // CefC_Debug
		return (-1);
	}
#ifdef CefC_Debug
	{
		int dbg_x;
		
		sprintf (cnd_dbg_msg, "Object's Name [");
		
		for (dbg_x = 0 ; dbg_x < pm.name_len ; dbg_x++) {
			sprintf (cnd_dbg_msg, "%s %02X", cnd_dbg_msg, pm.name[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finer, "%s ]\n", cnd_dbg_msg);
	}
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
	pe = cef_pit_entry_search (hdl->pit, &pm, &poh);
	
	if (pe) {
		face = &(pe->dnfaces);
		while (face->next) {
			face = face->next;
			faceids[face_num] = face->faceid;
			face_num++;
		}
	}
	
	/*--------------------------------------------------------------------
		Forwards the Content Object
	----------------------------------------------------------------------*/
	if (face_num > 0) {
#ifdef CefC_Debug
		{
			int dbg_x;
			
			sprintf (cnd_dbg_msg, "Recorded PIT Faces:");
			
			for (dbg_x = 0 ; dbg_x < face_num ; dbg_x++) {
				sprintf (cnd_dbg_msg, "%s %d", cnd_dbg_msg, faceids[dbg_x]);
			}
			cef_dbg_write (CefC_Dbg_Finer, "%s\n", cnd_dbg_msg);
		}
		cef_dbg_write (CefC_Dbg_Finer, "Forward the Content Object to cefnetd(s)\n");
#endif // CefC_Debug
		cefnetd_object_forward (hdl, faceids, face_num, msg,
			payload_len, header_len, &pm, &poh, pe);
			
		if (pe->stole_f) {
			cef_pit_entry_free (hdl->pit, pe);
		}
		return (1);
	}
	
	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the received Trace Request from csmgrd
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_csmgrd_tracereq_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len						/* Header Length of this message			*/
) {
	/* NOP */;
	return (1);
}
/*--------------------------------------------------------------------------------------
	Handles the received Ping Request from csmgrd
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_incoming_csmgrd_pingreq_process (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	int faceid, 							/* Face-ID where messages arrived at		*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len						/* Header Length of this message			*/
) {
	/* NOP */;
	return (1);
}
#endif // CefC_ContentStore
/*--------------------------------------------------------------------------------------
	Reads the config file
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_config_read (
	CefT_Netd_Handle* hdl					/* cefnetd handle							*/
) {
	char 	ws[1024];
	FILE*	fp = NULL;
	char 	buff[1024];
	char 	pname[64];
	int 	res;

	/* Obtains the directory path where the cefnetd's config file is located. */
	cef_client_config_dir_get (ws);

	if (mkdir (ws, 0777) != 0) {
		if (errno == ENOENT) {
			cef_log_write (CefC_Log_Error, "<Fail> cefnetd_config_read (mkdir)\n");
			return (-1);
		}
	}
	sprintf (ws, "%s/cefnetd.conf", ws);

	/* Opens the cefnetd's config file. */
	fp = fopen (ws, "r");
	if (fp == NULL) {
		cef_log_write (CefC_Log_Error, "<Fail> cefnetd_config_read (fopen)\n");
		return (-1);
	}

	/* Reads and records written values in the cefnetd's config file. */
	while (fgets (buff, 1023, fp) != NULL) {
		buff[1023] = 0;

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
				cef_log_write (CefC_Log_Warn, "PIT_SIZE must be higher than 0.\n");
				return (-1);
			}
			if (res > 65535) {
				cef_log_write (CefC_Log_Warn, "PIT_SIZE must be lower than 65536.\n");
				return (-1);
			}
			hdl->pit_max_size = (uint16_t) res;
		} else if (strcmp (pname, CefC_ParamName_FibSize) == 0) {
			res = atoi (ws);
			if (res < 1) {
				cef_log_write (CefC_Log_Warn, "FIB_SIZE must be higher than 0.\n");
				return (-1);
			}
			if (res > 65535) {
				cef_log_write (CefC_Log_Warn, "FIB_SIZE must be lower than 65536.\n");
				return (-1);
			}
			hdl->fib_max_size = (uint16_t) res;
		} else if (strcmp (pname, CefC_ParamName_Babel) == 0) {
			res = atoi (ws);
			if ((res != 0) && (res != 1)) {
				cef_log_write (CefC_Log_Warn, "USE_CEFBABEL must be 0 or 1.\n");
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
				cef_log_write (CefC_Log_Warn, 
					"CEFBABEL_ROUTE must be tcp, udp or both\n");
				return (-1);
			}
#ifdef CefC_Neighbour
#ifndef CefC_Android
		} else if (strcmp (pname, CefC_ParamName_NbrSize) == 0) {
			res = atoi (ws);
			if (res < 1) {
				cef_log_write (CefC_Log_Warn, "NBR_SIZE must be higher than 0.\n");
				return (-1);
			}
			if (res > 65535) {
				cef_log_write (CefC_Log_Warn, "NBR_SIZE must be lower than 65536.\n");
				return (-1);
			}
			hdl->nbr_max_size = (uint16_t) res;
		} else if (strcmp (pname, CefC_ParamName_NbrMngInterval) == 0) {
			res = atoi (ws);
			if (res < 100) {
				cef_log_write (CefC_Log_Warn, "NBR_INTERVAL must be higher than 100.\n");
				return (-1);
			}
			if (res > 3600000) {
				cef_log_write (CefC_Log_Warn, 
					"NBR_INTERVAL must be lower than or equal to 3600000.\n");
				return (-1);
			}
			hdl->nbr_mng_intv = (uint64_t)(res * 1000);
		} else if (strcmp (pname, CefC_ParamName_NbrMngThread) == 0) {
			res = atoi (ws);
			if (res < 1) {
				cef_log_write (CefC_Log_Warn, "NBR_THRESH must be higher than 100.\n");
				return (-1);
			}
			if (res > 16) {
				cef_log_write (CefC_Log_Warn, 
					"NBR_THRESH must be lower than or equal to 16.\n");
				return (-1);
			}
			hdl->nbr_mng_thread = (uint16_t) res;
		} else if (strcmp (pname, CefC_ParamName_FwdRate) == 0) {
			hdl->fwd_rate = (uint16_t) atoi (ws);
#endif // CefC_Android
#endif // CefC_Neighbour
#ifdef CefC_ParamName_Sktype
		} else if (strcasecmp (pname, CefC_ParamName_Sktype) == 0) {
			if ( !strcasecmp(ws, "SOCK_SEQPACKET") ){
				hdl->sk_type = SOCK_SEQPACKET;
			} else if ( !strcasecmp(ws, "SOCK_DGRAM") ){
				hdl->sk_type = SOCK_DGRAM;
			} else {
				hdl->sk_type = SOCK_STREAM;
			}
#endif // CefC_ParamName_Sktype
		} else {
			/* NOP */;
		}
	}

	fclose (fp);

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "PORT_NUM = %d\n", hdl->port_num);
	cef_dbg_write (CefC_Dbg_Fine, "PIT_SIZE = %d\n", hdl->pit_max_size);
	cef_dbg_write (CefC_Dbg_Fine, "FIB_SIZE = %d\n", hdl->fib_max_size);
#ifdef CefC_ParamName_Sktype
	cef_dbg_write (CefC_Dbg_Fine, "SockType = %d\n", hdl->sk_type);
#endif // CefC_ParamName_Sktype
#ifdef CefC_Neighbour
	cef_dbg_write (CefC_Dbg_Fine, "NBR_SIZE    = %d\n", hdl->nbr_max_size);
	cef_dbg_write (CefC_Dbg_Fine, "NBR_THRESH  = "FMTU64"\n", hdl->nbr_mng_intv);
#endif // CefC_Neighbour
#endif // CefC_Debug
	return (1);
}

static int
cefnetd_trim_line_string (
	const char* p1, 							/* target string for trimming 			*/
	char* p2,									/* name string after trimming			*/
	char* p3									/* value string after trimming			*/
) {
	char ws[1024];
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
	CefT_Parsed_Message* pm					/* Structure to set parsed CEFORE message	*/
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
	CefT_Parsed_Message* pm					/* Structure to set parsed CEFORE message	*/
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
	CefT_Parsed_Message* pm					/* Structure to set parsed CEFORE message	*/
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
		cef_face_frame_send_forced (peer_faceid, buff, (size_t) msg_len);
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
	CefT_Parsed_Message* pm					/* Structure to set parsed CEFORE message	*/
) {
#ifdef CefC_Neighbour
	uint64_t nowt = cef_client_present_timeus_calc ();
#endif // CefC_Neighbour
	
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finer, 
		"Receive a Object Link message from Face#%d\n", peer_faceid);
#endif // CefC_Debug
	
#ifdef CefC_Neighbour
	/* Records RTT 		*/
	cefnetd_nbr_rtt_record (hdl, nowt, peer_faceid);
#endif // CefC_Neighbour
	return (1);
}
/*--------------------------------------------------------------------------------------
	Creates listening socket(s)
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cefnetd_faces_init (
	CefT_Netd_Handle* hdl					/* cefnetd handle							*/
) {
	int res;

	/* Initialize the face module 		*/
	res = cef_face_init (hdl->node_type);
	if (res < 0) {
		cef_log_write (CefC_Log_Error, "Failed to init Face package.\n");
		return (-1);
	}
	
	/* Creates listening face 			*/
	res = cef_face_udp_listen_face_create (hdl->port_num);
	if (res < 0) {
#ifdef CefC_Android
		/* Process for Android next running	*/
		cef_face_all_face_close ();
#endif // CefC_Android
		cef_log_write (CefC_Log_Error, "Failed to create the UDP listen socket.\n");
		return (-1);
	}
	/* Prepares file descriptors to listen 		*/
	hdl->inudpfaces[hdl->inudpfdc] = (uint16_t) res;
	hdl->inudpfds[hdl->inudpfdc].fd = cef_face_get_fd_from_faceid ((uint16_t) res);
	hdl->inudpfds[hdl->inudpfdc].events = POLLIN | POLLERR;
	hdl->inudpfdc++;

	res = cef_face_tcp_listen_face_create (hdl->port_num);
	if (res < 0) {
#ifdef CefC_Android
		/* Process for Android next running	*/
		cef_face_all_face_close ();
#endif // CefC_Android
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
	
	return (1);
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
	CefT_Rx_Elem_Sig_DelPit sig_delpit;
	int clean_num = 0;
	int rec_index = 0;
	int end_index;
	int end_flag = 0;
	
	if (nowt > hdl->pit_clean_t) {
		end_index = hdl->pit_clean_i;
		
		while (clean_num < 16) {
			pe = (CefT_Pit_Entry*) cef_hash_tbl_elem_get (hdl->pit, &(hdl->pit_clean_i));
			
			if (hdl->pit_clean_i == end_index) {
				end_flag++;
				if (end_flag > 1) {
					break;
				}
			}
			rec_index = hdl->pit_clean_i;
			hdl->pit_clean_i++;
			
			if (pe != NULL) {
				
				cef_pit_clean (hdl->pit, pe);
				clean_num++;
				
				/* Indicates that a PIT entry was deleted to Transport  	*/
				if (hdl->plugin_hdl.tp[pe->tp_variant].pit) {
					
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
				
				if (pe->dnfacenum < 1) {
					pe = (CefT_Pit_Entry*)
							cef_hash_tbl_item_get_from_index (hdl->pit, rec_index);
					cef_pit_entry_free (hdl->pit, pe);
				}
			} else {
				break;
			}
		}
		hdl->pit_clean_t = nowt + 1000000;
	}

	return;
}
/*--------------------------------------------------------------------------------------
	Clean FIB entries
----------------------------------------------------------------------------------------*/
static void
cefnetd_fib_cleanup (
	CefT_Netd_Handle* hdl, 						/* cefnetd handle						*/
	uint64_t nowt								/* current time (usec) 					*/
) {
	
	CefT_Fib_Entry* fe;
	int clean_num = 0;
	int end_index;
	int end_flag = 0;
	
	if (nowt > hdl->fib_clean_t) {
		
		end_index = hdl->fib_clean_i;
		
		while (clean_num < 16) {
			fe = (CefT_Fib_Entry*) cef_hash_tbl_elem_get (hdl->fib, &(hdl->fib_clean_i));
			
			if (hdl->fib_clean_i == end_index) {
				end_flag++;
				if (end_flag > 1) {
					break;
				}
			}
			hdl->fib_clean_i++;
			
			if (fe) {
				clean_num++;
				
				if ((fe->app_comp >= CefC_T_APP_BI_DIRECT) && 
					(fe->app_comp <= CefC_T_APP_MESH)) {
					
					if (hdl->nowtus > fe->lifetime) {
						cef_fib_entry_destroy (hdl->fib, fe->key, fe->klen);
					}
				}
			} else {
				break;
			}
		}
		hdl->fib_clean_t = nowt + 1000000;
	}
	
	return;
}
/*--------------------------------------------------------------------------------------
	Obtains my NodeID (IP Address)
----------------------------------------------------------------------------------------*/
static void
cefnetd_node_id_get (
	CefT_Netd_Handle* hdl						/* cefnetd handle						*/
) {
#ifndef CefC_Android
	struct ifaddrs *ifa_list;
	struct ifaddrs *ifa;
	int n;


	n = getifaddrs (&ifa_list);
	if (n != 0) {
		return;
	}

	hdl->nodeid4_num 	= 0;
	hdl->nodeid16_num 	= 0;

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

	for (n = 0 ; n < hdl->nodeid4_num ; n++) {
		hdl->nodeid4[n] = (unsigned char*) calloc (4, 1);
	}

	hdl->nodeid16 =
		(unsigned char**) calloc (hdl->nodeid16_num, sizeof (unsigned char*));
	for (n = 0 ; n < hdl->nodeid16_num ; n++) {
		hdl->nodeid16[n] = (unsigned char*) calloc (16, 1);
	}

	hdl->nodeid4_num 	= 0;
	hdl->nodeid16_num 	= 0;

	for (ifa = ifa_list ; ifa != NULL ; ifa=ifa->ifa_next) {

		if (ifa->ifa_addr == NULL) {
			continue;
		}
		
		if (ifa->ifa_addr->sa_family == AF_INET) {
			if (ifa->ifa_flags & IFF_LOOPBACK) {
				continue;
			}
			memcpy (&hdl->nodeid4[hdl->nodeid4_num][0],
				&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, 4);
			hdl->nodeid4_num++;
		} else if (ifa->ifa_addr->sa_family == AF_INET6) {
			if (ifa->ifa_flags & IFF_LOOPBACK) {
				continue;
			}

			memcpy (&hdl->nodeid16[hdl->nodeid16_num][0],
				&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, 16);
			hdl->nodeid16_num++;
		} else {
			/* NOP */;
		}
	}
	freeifaddrs (ifa_list);

#else // CefC_Android
	int res;
	hdl->nodeid4_num = 0;
	hdl->nodeid16_num = 0;
	res = cef_android_node_id_get (
					&hdl->nodeid4, &hdl->nodeid4_num, &hdl->nodeid16, &hdl->nodeid16_num);
	if (res < 0) {
		LOGE ("ERROR : cef_android_node_id_get()\n");
		hdl->nodeid4_num = 0;
		hdl->nodeid16_num = 0;
	}
	LOGD ("DEBUG : cef_android_node_id_get() success\n");
	LOGD ("DEBUG : ipv4 num = %d, ipv6 num = %d\n", hdl->nodeid4_num, hdl->nodeid16_num);
#endif // CefC_Android

	if (hdl->nodeid4_num > 0) {
		memcpy (hdl->top_nodeid, hdl->nodeid4[0], 4);
		hdl->top_nodeid_len = 4;
	} else if (hdl->nodeid16_num > 0) {
		memcpy (hdl->top_nodeid, hdl->nodeid16[0], 16);
		hdl->top_nodeid_len = 16;
	} else {
		hdl->top_nodeid[0] = 0x7F;
		hdl->top_nodeid[1] = 0x00;
		hdl->top_nodeid[2] = 0x00;
		hdl->top_nodeid[3] = 0x01;
		hdl->top_nodeid_len = 4;
	}


	return;
}
#ifndef CefC_Android
/*--------------------------------------------------------------------------------------
	Obtains my NodeID (IP Address)
----------------------------------------------------------------------------------------*/
static int 
cefnetd_matched_node_id_get (
	CefT_Netd_Handle* hdl, 
	unsigned char* peer_node_id, 
	int peer_node_id_len, 
	unsigned char* node_id
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
#endif // CefC_Android

#ifdef CefC_Dtc
/*--------------------------------------------------------------------------------------
	Resend Cefore-DTC Interest
----------------------------------------------------------------------------------------*/
void
cefnetd_dtc_resnd (
	CefT_Netd_Handle* hdl, 						/* cefnetd handle						*/
	uint64_t nowt								/* current time (usec) 					*/
) {
	int resnd_num = 0;
	CefT_Fib_Entry* fe = NULL;
	uint16_t faceids[CefC_Fib_UpFace_Max];
	uint16_t face_num = 0;
	int i;
	CefT_Dtc_Pit_Entry* end_entry;
	CefT_Dtc_Pit_Entry* entry;

	if (nowt > hdl->dtc_resnd_t) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finer, "Resend check\n");
#endif // CefC_Debug
		entry = cef_pit_dtc_entry_read();
		if (entry == NULL) {
			/* Empty */
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finer, "PIT Empty\n");
#endif // CefC_Debug
			hdl->dtc_resnd_t = nowt + 10000000;
			return;
		}
		end_entry = entry;
		do {
			resnd_num++;
			fe = cef_fib_entry_search (hdl->fib, entry->key, entry->key_len);
			if (fe) {
				face_num = cef_fib_forward_faceid_select (fe, entry->faceid, faceids);
				for (i = 0 ; i < face_num ; i++) {
					if (entry->faceid == faceids[i]) {
						continue;
					}
					/* Send Interest */
					if (cef_face_check_active (faceids[i]) > 0) {
#ifdef CefC_Debug
						cef_dbg_write (CefC_Dbg_Finer, "Resend exec\n");
#endif // CefC_Debug
						cef_face_frame_send_forced (faceids[i], entry->msg, entry->msg_len);
					}
				}
			}
			entry = cef_pit_dtc_entry_read();
		} while ((resnd_num < 16) && (end_entry != entry));
		hdl->dtc_resnd_t = nowt + 10000000;
	}
	return;
}
#endif // CefC_Dtc

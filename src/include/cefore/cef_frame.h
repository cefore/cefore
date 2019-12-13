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
 * cef_frame.h
 */

#ifndef __CEF_FRAME_HEADER__
#define __CEF_FRAME_HEADER__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/time.h>

#include <cefore/cef_define.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

/*------------------------------------------------------------------*/
/* Maximum Sizes													*/
/*------------------------------------------------------------------*/
#define CefC_Max_Msg_Size			8192		/* Maximum Message Size (8 Kbytes) 		*/
#define CefC_Max_Header_Size 		255			/* Maximum Header Size 					*/
#define CefC_Max_Node_Id 			16
#define CefC_Max_Stamp_Num 			20

/*------------------------------------------------------------------*/
/* Field Length														*/
/*------------------------------------------------------------------*/

#define CefC_S_Type					2			/* Type field is 2 bytes				*/
#define CefC_S_Length				2			/* Length field is 2 bytes				*/
#define CefC_S_TLF					4			/* Type and Length field is 4 bytes		*/
#define CefC_S_Fix_Header			8			/* Fixed Header is 8 bytes				*/
#define CefC_S_ChunkNum				4			/* ChunkNum V is 4 bytes				*/
#define CefC_S_Nonce				8			/* Nonce V is 8 bytes					*/
#define CefC_S_Symbolic_Code		8			/* Symbolic Code V is 8 bytes			*/
#define CefC_S_Innovate				32			/* Innovate Interest 					*/
#define CefC_S_Bitmap				8
#define CefC_S_Number				4			/* Number in Innovate Interest 			*/
#define CefC_S_Lifetime				2			/* Lifetime V is 2 bytes				*/
#define CefC_S_Cachetime			8			/* cache time V is 8 bytes				*/
#define CefC_S_Expiry				8			/* expiry time V is 8 bytes				*/
#define CefC_S_RCT 					8			/* Recommented Cache Time 				*/
#define CefC_S_SeqNum				4			/* Sequence Number 						*/
#define CefC_S_ReqArrivalTime		4			/* Request Arrival Time is 4 bytes 		*/

/*------------------------------------------------------------------*/
/* Field Offset														*/
/*------------------------------------------------------------------*/

/*----- Fixed Header 		-----*/
#define CefC_O_Fix_Ver				0
#define CefC_O_Fix_Type				1
#define CefC_O_Fix_PacketLength		2
#define CefC_O_Fix_HopLimit			4
#define CefC_O_Fix_Trace_RetCode	5
#define CefC_O_Fix_Ping_RetCode		6
#define CefC_O_Fix_HeaderLength		7

/*----- TLV field 			-----*/
#define CefC_O_Type					0
#define CefC_O_Length				2
#define CefC_O_Value				4

/*==========================================================================*/
/* TLV definitions 															*/
/*==========================================================================*/

/*------------------------------------------------------------------*/
/* Packet Type Registry 											*/
/*------------------------------------------------------------------*/
#define CefC_PT_INTEREST			0x00		/* Interest								*/
#define CefC_PT_OBJECT				0x01		/* Content Object						*/
#define CefC_PT_INTRETURN			0x02		/* Interest Return						*/
#define CefC_PT_TRACE_REQ			0x03		/* Cefinfo Request						*/
#define CefC_PT_TRACE_REP			0x04		/* Cefinfo Replay						*/
#define CefC_PT_PING_REQ			0x05		/* Cefping Request						*/
#define CefC_PT_PING_REP			0x06		/* Cefping Replay						*/

#define CefC_PT_CTRL				0x10
#define CefC_PT_BABEL				0x11


/*------------------------------------------------------------------*/
/* Top-Level Type													*/
/*------------------------------------------------------------------*/

#define CefC_T_INTEREST				0x0001		/* Interest								*/
#define CefC_T_OBJECT				0x0002		/* Content Object						*/
#define CefC_T_VALIDATION_ALG		0x0003		/* Validation Algorithm					*/
#define CefC_T_VALIDATION_PAYLOAD	0x0004		/* Validation Payload 					*/
#define CefC_T_TRACE				0x0005		/* Cefinfo 							*/
#define CefC_T_PING					0x0006		/* Cefping 								*/
#define CefC_T_TOP_TLV_NUM			0x0007

/*------------------------------------------------------------------*/
/* Message Type														*/
/*------------------------------------------------------------------*/

#define CefC_T_NAME					0x0000		/* Name									*/
#define CefC_T_PAYLOAD				0x0001		/* Payload								*/
#define CefC_T_KEYIDRESTR			0x0002		/* KeyIdRestriction						*/
#define CefC_T_OBJHASHRESTR			0x0003		/* ContentObjectHashRestriction			*/
#define CefC_T_PAYLDTYPE			0x0005		/* PayloadType							*/
#define CefC_T_EXPIRY				0x0006		/* ExpiryTime 							*/
#define CefC_T_TRACE_REPLY			0x0008		/* Reply (content) Block				*/
#define CefC_T_MSG_TLV_NUM			0x000A

/*----- Sub TLVs of T_TRACE_REPLY	-----*/
#define CefC_T_TRACE_CONTENT		0x0001		/* Reply (content) Block				*/
#define CefC_T_TRACE_CONTENT_OWNER	0x0002		/* Reply (content) Block				*/
#define CefC_T_TRACE_DEVICE			0x0003		/* Reply (device) Block					*/
#define CefC_T_TRACE_FUNCTION		0x0004		/* Reply (function) Block				*/
#define CefC_T_TRACE_ON_CSMGRD		0x8000		/* Content is on csmgrd					*/

/*----- Organization-Specific TLVs -----*/
#define CefC_T_SER_LOG				0x1001		/* Serial Logging						*/

/*------------------------------------------------------------------*/
/* Name Segment Type												*/
/*------------------------------------------------------------------*/

#define CefC_T_NAMESEGMENT			0x0001		/* Name Segment							*/
#define CefC_T_IPID					0x0002		/* Interest Payload ID 					*/
#define CefC_T_CHUNK				0x0010		/* Chunk Number							*/
#define CefC_T_META					0x0011		/* Chunk Metadata						*/
#define CefC_T_NONCE				0x0012		/* Nonce 								*/
#define CefC_T_SYMBOLIC_CODE		0x0013		/* Symbolic Code 						*/
#define CefC_T_NAME_TLV_NUM			0x0014

/*----- Application Components 		-----*/
#define CefC_T_APP_MIN 				0x1000		/* Min Index of Application Components 	*/
#define CefC_T_APP_MAX 				0x1FFF		/* Max Index of Application Components 	*/
#define CefC_T_APP_BI_DIRECT		0x1400		/* Bidirectional Application 			*/
#define CefC_T_APP_MESH				0x1401		/* Mesh Application 					*/
#define CefC_T_APP_FROM_PUB			0x1402		/* Require to get the content from the 	*/
												/* publisher							*/
#define CefC_T_APP_DTC				0x1403		/* Android DTC Application			 	*/

/*----- Chunk Metadata Name Component 	-----*/
#define CefC_T_ENDChunk				0x0019		/* EndChunkNumber						*/
#define CefC_T_META_TLV_NUM			0x0020

/*------------------------------------------------------------------*/
/* Hash Function Type Registry										*/
/*------------------------------------------------------------------*/

#define CefC_T_SHA_INVALID			0x0000
#define CefC_T_SHA_256				0x0001
#define CefC_T_SHA_512				0x0002

/*------------------------------------------------------------------*/
/* Validation Algorithm Type										*/
/*------------------------------------------------------------------*/

#define CefC_T_ALG_INVALID			0x0000
#define CefC_T_CRC32C				0x0002
#define CefC_T_HMAC_SHA256			0x0004
#define CefC_T_RSA_SHA256			0x0005
#define CefC_T_EC_SECP_256K1		0x0006
#define CefC_T_EC_SECP_384R1		0x0007
#define CefC_T_KEY_CHECK			0x1001

/*------------------------------------------------------------------*/
/* Validation Dependent Data Type Registry							*/
/*------------------------------------------------------------------*/

#define CefC_T_ALG_DATA_INVALID		0x0000
#define CefC_T_KEYID				0x0009
#define CefC_T_PUBLICKEYLOC			0x0010
#define CefC_T_PUBLICKEY			0x0011
#define CefC_T_CERT					0x0012
#define CefC_T_LINK					0x0013
#define CefC_T_KEYLINK				0x0014
#define CefC_T_SIGTIME				0x0015

#define CefC_T_CERT_FORWARDER		0x1001

/*------------------------------------------------------------------*/
/* Hop-by-Hop Type													*/
/*------------------------------------------------------------------*/

#define CefC_T_OPT_INVALID			0x0000		/* Invalid								*/
#define CefC_T_OPT_INTLIFE			0x0001		/* Interest Lifetime 					*/
#define CefC_T_OPT_CACHETIME		0x0002		/* Recommended Cache Time (RCT) 		*/
#define CefC_T_OPT_MSGHASH			0x0003		/* Message Hash							*/
#define CefC_T_OPT_TRACE_REQ		0x0008		/* Cefinfo Request Block				*/
#define CefC_T_OPT_TRACE_RPT		0x0009		/* Cefinfo Report Block				*/
#define CefC_T_OPT_PING_REQ			0x000A		/* Cefping Request Block				*/
#define CefC_T_OPT_TLV_NUM			0x000B

#define CefC_T_OPT_ORG				0x0FFF		/* Vendor Specific Information			*/
#define CefC_T_OPT_SYMBOLIC			0x1001		/* Symbolic Interest					*/
#define CefC_T_OPT_TRANSPORT		0x1002		/* Transport Plugin Variant				*/
#define CefC_T_OPT_EFI				0x1003		/* External Function Invocation			*/
#define CefC_T_OPT_IUR				0x1004		/* Interest User Request				*/
#define CefC_T_OPT_SEQNUM			0x1005		/* Sequence Number						*/
#define CefC_T_OPT_USR_TLV_NUM		0x1006

/*----- TLVs for use in the CefC_T_OPT_SYMBOLIC TLV -----*/
#define CefC_T_OPT_REGULAR			0x0000		/* Regular Interest (just for form) 	*/
#define CefC_T_OPT_LONGLIFE			0x0001		/* Long Life Interest					*/
#define CefC_T_OPT_INNOVATIVE		0x0002		/* Innovative Interest					*/
#define CefC_T_OPT_PIGGYBACK		0x0003		/* Piggyback Interest 					*/
#define CefC_T_OPT_NUMBER			0x0004		/* Number of requested Cobs 			*/
#define CefC_T_OPT_SCODE			0x0005		/* Symbolic Code						*/

#define CefC_T_OPT_APP_REG			0x1001
#define CefC_T_OPT_APP_DEREG		0x1002

/*----- TLVs for use in the CefC_T_OPT_MSGHASH TLV -----*/
#define CefC_T_OPT_MH_INVALID		0x0000		/* Invalid								*/
#define CefC_T_OPT_MH_SHA_256		0x0001		/* SHA-256								*/
#define CefC_T_OPT_MH_SHA_512		0x0002		/* SHA-512								*/

/*==========================================================================*/
/* for process																*/
/*==========================================================================*/

/*------------------------------------------------------------------*/
/* Type of Command 				 									*/
/*------------------------------------------------------------------*/

#define CefC_Cmd_Num				3
#define CefC_Cmd_Invalid			0x00		/* Invalid								*/
#define CefC_Cmd_Link_Req			0x01		/* Link Request							*/
#define CefC_Cmd_Link_Res			0x02		/* Link Response						*/

/*------------------------------------------------------------------*/
/* Return Code for Cefping Replay 									*/
/*------------------------------------------------------------------*/
#define CefC_CpRc_Cache 			0x00
#define CefC_CpRc_NoCache 			0x01
#define CefC_CpRc_NoRoute 			0x02
#define CefC_CpRc_AdProhibit 		0x03

/*------------------------------------------------------------------*/
/* Option for Cefinfo Request 										*/
/*------------------------------------------------------------------*/

/* Sets to Flag of Request Block 			*/
#define CefC_CtOp_None 				0x00
#define CefC_CtOp_ReqPartial 		0x01
#define CefC_CtOp_NoCache 			0x02
#define CefC_CtOp_Publisher			0x04

/* Sets to Scheme Name of Request Block 	*/
#define CefC_CtSn_Ccnx 				0x00
#define CefC_CtSn_Ndnx 				0x01
#define CefC_CtSn_Cefore			0x02

/*------------------------------------------------------------------*/
/* Return Code for Cefinfo Replay 									*/
/*------------------------------------------------------------------*/
#define CefC_CtRc_NoError 			0x00
#define CefC_CtRc_WrongIf 			0x01
#define CefC_CtRc_NoRoute 			0x02
#define CefC_CtRc_NoInfo 			0x03
#define CefC_CtRc_NoSpace 			0x04
#define CefC_CtRc_InfoHidden		0x05
#define CefC_CtRc_ReachGw			0x06
#define CefC_CtRc_NoMoreHop			0x07			// TBD
#define CefC_CtRc_AdProhibit		0x0E
#define CefC_CtRc_UnknownReq		0x0F


/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/

/*--------------------------------------------------------------*/
/* Headers														*/
/*--------------------------------------------------------------*/

struct cef_app_frame {
	uint32_t		version;
	uint32_t		type;
	unsigned char 	name[CefC_Max_Length];
	uint16_t 		name_len;
	uint32_t		chunk_num;
	unsigned char 	payload[CefC_Max_Msg_Size];
	uint16_t 		payload_len;
} __attribute__((__packed__));

struct cef_app_hdr {
	uint32_t		ver;
	uint32_t		type;
	uint32_t		len;
	uint32_t		chnk_num;
} __attribute__((__packed__));

struct fixed_hdr {
	uint8_t 	version;
	uint8_t 	type;
	uint16_t 	pkt_len;
	uint8_t		hoplimit;
	uint8_t		reserve1;
	uint8_t		reserve2;
	uint8_t 	hdr_len;
} __attribute__((__packed__));

struct tlv_hdr {
	uint16_t 	type;
	uint16_t 	length;
} __attribute__((__packed__));

struct value16_tlv {
	uint16_t 	type;
	uint16_t 	length;
	uint16_t 	value;
} __attribute__((__packed__));

struct value32_tlv {
	uint16_t 	type;
	uint16_t 	length;
	uint32_t 	value;
} __attribute__((__packed__));

struct value32x2_tlv {
	uint16_t 	type;
	uint16_t 	length;
	uint32_t 	value1;
	uint32_t 	value2;
} __attribute__((__packed__));

struct value32x8_tlv {
	uint16_t 	type;
	uint16_t 	length;
	uint32_t 	value1;
	uint32_t 	value2;
	uint32_t 	value3;
	uint32_t 	value4;
	uint32_t 	value5;
	uint32_t 	value6;
	uint32_t 	value7;
	uint32_t 	value8;
} __attribute__((__packed__));

struct value64_tlv {
	uint16_t 	type;
	uint16_t 	length;
	uint64_t 	value;
} __attribute__((__packed__));

struct trace_req_block {
	uint8_t 	scheme_name;
	uint8_t 	skiphop;
	uint8_t 	timeout;
	uint8_t 	mbz;
	uint16_t 	req_id;
	uint16_t 	flag;
} __attribute__((__packed__));

struct trace_rep_block {
	uint32_t 	cont_size;
	uint32_t 	cont_cnt;
	uint32_t 	rcv_int;
	uint32_t 	first_seq;
	uint32_t 	last_seq;
	uint64_t 	cache_time;
	uint64_t 	remain_time;
} __attribute__((__packed__));

/*--------------------------------------------------------------*/
/* Parameters to set Option Header of Interest/Object	 		*/
/*--------------------------------------------------------------*/
typedef struct {

	/***** Interest Lifetime 			*****/
	uint8_t				lifetime_f;				/* flag to set Lifetime					*/
	uint16_t			lifetime;				/* Lifetime [unit: ms] 					*/
	
	/***** Recommended Cache Time (RCT) *****/
	uint8_t				cachetime_f;			/* flag to set RCT						*/
	uint64_t			cachetime;				/* Recommended Cache Time[unit: ms]		*/
	
	/***** Message Hash					*****/
	// TBD
	
	/***** Vendor Specific Information	*****/
	// TBD
	
	/***** Cefping						*****/
	uint16_t			responder_f;		/* flag to set Responder Identifier 		*/
											/* it is length of Responder Identifier 	*/
	unsigned char   	responder_id[CefC_Max_Node_Id];
												/* Responder Identifier 					*/
	
	/***** Cefinfo						*****/
	uint16_t 			req_id;					/* Request ID of Request Block			*/
	uint8_t 			skip_hop;				/* SkipHopCount of Request Block		*/
	uint16_t 			trace_flag;				/* Flags of Request Block				*/
	uint8_t				timeout;				/* Timeout of Request Block				*/
	uint8_t 			scheme_name;			/* SchemeName of Request Block			*/
	
	/***** Long Life Interest			*****/
	uint16_t 			symbolic_f;				/* value of CefC_T_OPT_SYMBOLIC Sub TLV */
	
	/***** Innovative Interest 			*****/
	uint32_t 			number;					/* Number of Cobs required				*/
												/* If it is 0, T_NUMBER is not set in	*/
												/* hop-by-hop option header 			*/
	uint8_t 			bitmap_f;				/* If it is not 0, bitmap variable is 	*/
												/* set to T_NUMBER TLV. Otherwise 		*/
												/* T_NUMBER is automatically set.		*/
	uint32_t 			bitmap[CefC_S_Bitmap];	/* bitmap is set to T_NUMBER 			*/
	
	/***** Transport Plugin Variant		*****/
	uint16_t 	tp_variant;							/* Transport Variant 				*/
	uint8_t 	tp_length;							/* length of value field 			*/
	unsigned char tp_value[CefC_Max_Header_Size];	/* value field 						*/
	
	/***** External Function Invocation *****/
	// TBD
	
	/***** Interest User Request		*****/
	// TBD
	
} CefT_Option_TLVs;

/*--------------------------------------------------------------*/
/* Parameters to set Validation Algorithm of Interest/Object	*/
/*--------------------------------------------------------------*/
typedef struct {

	/***** ValidationType 				*****/
	uint16_t 			valid_type;				/* Validation Type 						*/
												/* e.g. CefC_T_CRC32C 					*/
	
	/* HOP-BY-HOP */
	/***** Hop-by-Hop Validation 		*****/
	uint16_t 			hop_by_hop_f;
	
} CefT_Valid_Alg_TLVs;

/*--------------------------------------------------------------*/
/* Parameters to set Interest 							 		*/
/*--------------------------------------------------------------*/
typedef struct {

	/***** Hop Limit 		*****/
	uint8_t 				hoplimit;				/* Hop Limit of Interest 			*/

	/***** NAME TLV			*****/
	unsigned char 			name[CefC_Max_Length];	/* Name 							*/
	uint16_t				name_len;				/* Length of Name 					*/
	
	uint8_t 				chunk_num_f;			/* flag to set Chunk Number			*/
	uint32_t				chunk_num;				/* Chunk Number						*/
	
	uint8_t 				nonce_f;				/* flag to set Nonce 				*/
	uint64_t 				nonce;					/* Nonce 							*/
	
	/* Symbolic Code 	*/
	uint8_t 				symbolic_code_f;		/* flag to set Symbolic Code 		*/
	uint32_t 				min_seq;				/* min sequence number 				*/
	uint32_t 				max_seq;				/* max sequence number 				*/
	
	unsigned char 			cob[CefC_Max_Length];	/* Cob for Piggyback Interest 		*/
	uint16_t 				cob_len;				/* length of Cob 					*/
	
	/* Application Components */
	uint16_t 				app_comp;				/* Index of App Components  		*/
													/* sets CefC_T_APP_XXXXX 			*/
	uint16_t 				app_comp_len;			/* length of app_comp_val 			*/
	unsigned char 			app_comp_val[CefC_Max_Length];
													/* value of App Components TLV 		*/
	
	/***** Option Header	*****/
	CefT_Option_TLVs 		opt;					/* Parameters to set Option Header 	*/
	
	/***** Validation Algorithm TLV 	*****/
	CefT_Valid_Alg_TLVs 	alg;
	
} CefT_Interest_TLVs;

/*--------------------------------------------------------------*/
/* Parameters to set Object 									*/
/*--------------------------------------------------------------*/
typedef struct {

	/***** NAME TLV			*****/
	unsigned char 			name[CefC_Max_Length];	/* Name 							*/
	uint16_t				name_len;				/* Length of Name 					*/

	uint8_t					chnk_num_f;				/* Flag to set Chunk Number 		*/
	uint32_t				chnk_num;				/* Chunk Number 					*/
	
	unsigned char 			meta[CefC_Max_Length];	/* Meta 							*/
	uint16_t 				meta_len;
	
	/***** Option Header	*****/
	CefT_Option_TLVs 		opt;					/* Parameters to set Option Header 	*/
	
	/***** PAYLOAD TLV 		*****/
	unsigned char 			payload[CefC_Max_Length];
													/* Payload 							*/
	uint16_t				payload_len;			/* Length of Payload 				*/
	
	/***** Metadata TLV		*****/
	uint64_t				expiry;					/* The time at which the Payload	*/
													/* expires [unit: ms]				*/
	
	/***** Validation Algorithm TLV 	*****/
	CefT_Valid_Alg_TLVs 	alg;
	
} CefT_Object_TLVs;

/*--------------------------------------------------------------*/
/* Parameters to set Cefping 									*/
/*--------------------------------------------------------------*/
typedef struct {

	/***** Hop Limit 		*****/
	uint8_t 				hoplimit;				/* Hop Limit of Interest 			*/

	/***** NAME TLV			*****/
	unsigned char 			name[CefC_Max_Length];	/* Name 							*/
	uint16_t				name_len;				/* Length of Name 					*/
	
	/***** Option Header	*****/
	CefT_Option_TLVs 		opt;					/* Parameters to set Option Header 	*/

} CefT_Ping_TLVs;

/*--------------------------------------------------------------*/
/* Parameters to set Cefinfo 									*/
/*--------------------------------------------------------------*/
typedef struct {

	/***** Hop Limit 		*****/
	uint8_t 				hoplimit;				/* Hop Limit of Interest 			*/

	/***** NAME TLV			*****/
	unsigned char 			name[CefC_Max_Length];	/* Name 							*/
	uint16_t				name_len;				/* Length of Name 					*/
	
	/***** Option Header	*****/
	CefT_Option_TLVs 		opt;					/* Parameters to set Option Header 	*/

} CefT_Trace_TLVs;

#ifdef CefC_Ser_Log
/*--------------------------------------------------------------*/
/* Parameters to Organization-Specific Parameters 				*/
/*--------------------------------------------------------------*/
typedef struct CefT_Org_Params {

	/***** IANA Private Enterprise Numbers	*****/
	uint8_t 				pen[3];

	/***** NAME TLV							*****/
	unsigned char*			offset;					/* Vendor Specific Value offset		*/
	uint16_t				length;					/* Length of value					*/

} CefT_Org_Params;
#endif // CefC_Ser_Log

/*--------------------------------------------------------------*/
/* Parsed Option Header 										*/
/*--------------------------------------------------------------*/
typedef struct {
	
	/***** Interest Lifetime 			*****/
	uint16_t			lifetime_f;				/* flag to set Lifetime					*/
	uint16_t			lifetime;				/* Lifetime [unit: sec] 				*/
	
	/***** Recommended Cache Time (RCT) *****/
	uint16_t			cachetime_f;			/* flag to set RCT						*/
	uint64_t			cachetime;				/* Recommended Cache Time[unit: usec]	*/
	
	/***** Message Hash					*****/
	// TBD
	
	/***** Vendor Specific Information	*****/
	// TBD
	
	/***** Cefping						*****/
	uint16_t			responder_f;		/* flag to set Responder Identifier 		*/
											/* it is length of Responder Identifier		*/
	unsigned char   	responder_id[CefC_Max_Node_Id];
												/* Responder Identifier 				*/
	
	/***** Cefinfo Request Block		*****/
	uint16_t 			req_id;					/* Request ID of Request Block			*/
	uint8_t 			skip_hop;				/* SkipHopCount of Request Block		*/
	uint16_t 			skip_hop_offset;		/* Offset from the top of message 		*/
	uint16_t 			trace_flag;				/* Flags of Request Block				*/
	uint8_t				timeout;				/* Timeout of Request Block				*/
	uint8_t 			scheme_name;			/* SchemeName of Request Block			*/
	
	/***** Cefinfo Report Block		*****/
	uint16_t 			rpt_block_offset;
	
	/***** Symbolic Interest			*****/
	uint8_t 			longlife_f;				/* Long Life Interest 					*/
	uint8_t				piggyback_f; 			/* Piggyback Interest 					*/
	uint8_t 			app_reg_f;				/* App Register 						*/
	uint16_t 			bitmap_f;
	uint32_t 			bitmap[CefC_S_Bitmap];
	uint16_t 			number_f;
	uint32_t 			number;
	
	/***** Transport Plugin Variant		*****/
	uint16_t 			tp_variant;				/* Transport Variant 					*/
	uint8_t 			tp_length;				/* length of value field 				*/
	unsigned char tp_value[CefC_Max_Header_Size];	/* value field 						*/
	
	/***** Sequence Number 				*****/
	uint32_t 			seqnum;
	
	/***** Symbolic Coder 				*****/
	uint16_t 				symbolic_code_f;		/* flag to set Symbolic Code 		*/
	struct value32x2_tlv 	symbolic_code;			/* Symbolic Code 					*/

	
	/***** External Function Invocation *****/
	// TBD
	
	/***** Interest User Request		*****/
	// TBD
	
} CefT_Parsed_Opheader;

/*--------------------------------------------------------------*/
/* Parsed CEFORE message										*/
/*--------------------------------------------------------------*/
typedef struct {
	
	/***** Fixed Header 	*****/
	uint8_t			hoplimit;					/* Hop Limit of Interest 				*/
	uint8_t			ping_retcode;				/* Cefping ReturnCode 					*/
	
	/***** Cefore Message 	*****/
	uint16_t 		pkt_type;					/* Top-Level Type 						*/
	
	/***** NAME TLV			*****/
	uint16_t		name_f;						/* Offset of Name 						*/
	unsigned char 	name[CefC_Max_Length];		/* Name 								*/
	uint16_t		name_len;					/* Length of Name 						*/
	uint16_t		chnk_num_f;					/* Offset of Chunk Number 				*/
	uint32_t		chnk_num;					/* Chunk Number 						*/
	
	uint64_t		nonce;						/* Nonce 								*/
	
	uint16_t 		symbolic_code_f;			/* Symbolic Code 						*/
	uint32_t 		min_seq;					/* min sequence number 					*/
	uint32_t 		max_seq;					/* max sequence number 					*/
	
	uint16_t 		meta_f;						/* Meta 								*/
	uint16_t 		meta_len;
	
	uint16_t 		app_comp;					/* Index of App Components  			*/
	uint16_t 		app_comp_len;				/* Length of App Components  			*/
	uint16_t 		app_comp_offset;			/* Offset of value App Components from 	*/
												/* the top of the message 				*/
	
	/***** PAYLOAD TLV 		*****/
	uint16_t		payload_f;					/* Offset of Payload					*/
	unsigned char 	payload[CefC_Max_Length]; 	/* Payload 								*/
	uint16_t		payload_len;				/* Length of Payload 					*/

	/***** Metadata TLV		*****/
	uint64_t		expiry;						/* The time at which the Payload		*/
												/* expires [unit: ms]					*/
	
	/***** Sequence Number 				*****/
	uint32_t 		seqnum;

#ifdef CefC_Ser_Log
	/***** Organization-Specific Parameters	*****/
	CefT_Org_Params org;
#endif // CefC_Ser_Log
	
} CefT_Parsed_Message;


/****************************************************************************************
 Global Variables
 ****************************************************************************************/



/****************************************************************************************
 Function Declarations
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Initialize the frame module
----------------------------------------------------------------------------------------*/
void cef_frame_init (
	void
);
/*--------------------------------------------------------------------------------------
	Converts the URI to Name
----------------------------------------------------------------------------------------*/
int											/* Length of Name 							*/
cef_frame_conversion_uri_to_name (
	const char* inuri, 						/* URI										*/
	unsigned char* name						/* buffer to set Name 						*/
);
/*--------------------------------------------------------------------------------------
	Creates a Link Request message
----------------------------------------------------------------------------------------*/
int 										/* Length of the message 					*/
cef_frame_interest_link_msg_create (
	unsigned char* buff						/* buffer to set a message					*/
);
/*--------------------------------------------------------------------------------------
	Creates a Link Response message
----------------------------------------------------------------------------------------*/
int 										/* length of created message 				*/
cef_frame_object_link_msg_create (
	unsigned char* buff						/* buffer to set a message					*/
);
/*--------------------------------------------------------------------------------------
	Creates the Interest from the specified Parameters
----------------------------------------------------------------------------------------*/
int 										/* Length of Interest message 				*/
cef_frame_interest_create (
	unsigned char* buff, 					/* buffer to set Interest					*/
	CefT_Interest_TLVs* tlvs				/* Parameters to set Interest 				*/
);
/*--------------------------------------------------------------------------------------
	Creates the Content Object from the specified Parameters
----------------------------------------------------------------------------------------*/
int 										/* Length of Content Object message 		*/
cef_frame_object_create (
	unsigned char* buff, 					/* buffer to set Content Object				*/
	CefT_Object_TLVs* tlvs					/* Parameters to set Content Object 		*/
);
/*--------------------------------------------------------------------------------------
	Creates the Cefping Request from the specified Parameters
----------------------------------------------------------------------------------------*/
int 										/* Length of Cefping message 				*/
cef_frame_cefping_req_create (
	unsigned char* buff, 					/* buffer to set Cefping Request			*/
	CefT_Ping_TLVs* tlvs					/* Parameters to set Cefping Request 		*/
);
/*--------------------------------------------------------------------------------------
	Creates the Cefinfo Request from the specified Parameters
----------------------------------------------------------------------------------------*/
int 										/* Length of Cefinfo message 				*/
cef_frame_cefinfo_req_create (
	unsigned char* buff, 					/* buffer to set Cefinfo Request			*/
	CefT_Trace_TLVs* tlvs					/* Parameters to set Cefinfo Request 		*/
);
/*--------------------------------------------------------------------------------------
	Adds a time stamp on Cefinfo Request
----------------------------------------------------------------------------------------*/
int 										/* Length of Cefinfo message 				*/
cef_frame_cefinfo_req_add_stamp (
	unsigned char* buff, 					/* Cefinfo Request							*/
	uint16_t msg_len, 
	unsigned char* node_id, 				/* Node ID 									*/
	uint16_t id_len, 						/* length of Node ID 						*/
	struct timeval t 						/* current time in UNIX-time(us) 			*/
);
/*--------------------------------------------------------------------------------------
	Creates the Cefping Replay from the specified Parameters
----------------------------------------------------------------------------------------*/
int 										/* Length of Cefping message 				*/
cef_frame_cefping_rep_create (
	unsigned char* buff, 					/* buffer to set Cefping Request			*/
	uint8_t ret_code, 
	unsigned char* responder_id, 
	uint16_t id_len, 
	unsigned char* name, 
	uint16_t name_len
);
/*--------------------------------------------------------------------------------------
	Updates the sequence number 
----------------------------------------------------------------------------------------*/
void 
cef_frame_seqence_update (
	unsigned char* buff, 					/* packet									*/
	uint32_t seqnum
);
/*--------------------------------------------------------------------------------------
	Adds the Symbolic Code to the Content Object
----------------------------------------------------------------------------------------*/
int 										/* Length of Content Object					*/
cef_frame_symbolic_code_add (
	unsigned char* buff, 					/* Content Object							*/
	uint16_t msg_len, 						/* Length of Cob 							*/
	CefT_Parsed_Message* pm					/* Symbolic Code in TLV format 				*/
);
/*--------------------------------------------------------------------------------------
	Updates the T_INNOVATIVE and T_NUMBER
----------------------------------------------------------------------------------------*/
void 
cef_frame_innovative_update (
	unsigned char* buff, 					/* packet									*/
	uint32_t* bitmap, 
	uint16_t bitmap_offset, 
	uint32_t number, 
	uint16_t number_offset
);
/*--------------------------------------------------------------------------------------
	Parses a message
----------------------------------------------------------------------------------------*/
int 										/* Returns a negative value if it fails 	*/
cef_frame_message_parse (
	unsigned char* msg, 					/* the message to parse						*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len, 					/* Header Length of this message			*/
	CefT_Parsed_Opheader* poh, 				/* Structure to set parsed Option Header(s)	*/
	CefT_Parsed_Message* pm, 				/* Structure to set parsed CEFORE message	*/
	int target_type							/* Type of the message to expect			*/
);
/*--------------------------------------------------------------------------------------
	Obtains a Link Request message
----------------------------------------------------------------------------------------*/
int 										/* length of Link Request message 			*/
cef_frame_link_req_cmd_get (
	unsigned char* cmd						/* buffer to set a message					*/
);
/*--------------------------------------------------------------------------------------
	Obtains a Link Response message
----------------------------------------------------------------------------------------*/
int 										/* length of Link Response message 			*/
cef_frame_link_res_cmd_get (
	unsigned char* cmd 						/* buffer to set a message					*/
);
uint64_t
cef_frame_htonb (
	uint64_t x
);
uint64_t
cef_frame_ntohb (
	uint64_t x
);
/*--------------------------------------------------------------------------------------
	Convert name to uri
----------------------------------------------------------------------------------------*/
int
cef_frame_conversion_name_to_uri (
	unsigned char* name,
	unsigned int name_len,
	char* uri
);
/*--------------------------------------------------------------------------------------
	Convert name to string
----------------------------------------------------------------------------------------*/
int
cef_frame_conversion_name_to_string (
	unsigned char* name,
	unsigned int name_len,
	char* uri, 
	char* protocol
);
/*--------------------------------------------------------------------------------------
	Parses a payload form the specified message
----------------------------------------------------------------------------------------*/
void 
cef_frame_payload_parse (
	unsigned char* msg, 
	uint16_t msg_len, 
	uint16_t* name_offset, 
	uint16_t* name_len, 
	uint16_t* payload_offset, 
	uint16_t* payload_len
);

#endif // __CEF_FRAME_HEADER__

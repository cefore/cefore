/*
 * Copyright (c) 2016-2021, National Institute of Information and Communications
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
#define CefC_NICT_PEN				0x00C96C	/* Private Enterprise Number			*/

/***** Whether to use OPT_SEQNUM *****/
#define CefC_OptSeqnum_NotUse			0
#define CefC_OptSeqnum_UnUse			-1		/* When using							*/
#define CefC_OptSeqnum_Use				1		/* When finished using					*/

/*------------------------------------------------------------------*/
/* Maximum Sizes													*/
/*------------------------------------------------------------------*/
#define CefC_Max_Msg_Size			65535		/* Maximum Message Size (64Kbytes) 		*/

#define CefC_Max_Header_Size 		255			/* Maximum Header Size 					*/
#define CefC_Max_Node_Id 			1025
#define CefC_Max_Stamp_Num 			20

/*------------------------------------------------------------------*/
/* Field Length														*/
/*------------------------------------------------------------------*/

#define CefC_S_Type					2			/* Type field is 2 bytes				*/
#define CefC_S_Length				2			/* Length field is 2 bytes				*/
#define CefC_S_TLF					4			/* Type and Length field is 4 bytes		*/
#define CefC_S_Fix_Header			8			/* Fixed Header is 8 bytes				*/
#define CefC_S_ChunkNum				4			/* ChunkNum V is 4 bytes				*/
#define CefC_S_EndChunkNum			4			/* EndChunkNum V is 4 bytes				*/
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
#define CefC_O_Fix_Ccninfo_RetCode	5
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
#define CefC_PT_REQUEST				0x03		/* Ccninfo Request						*/
#define CefC_PT_REPLY				0x04		/* Ccninfo Replay						*/
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
#define CefC_T_DISCOVERY			0x0005		/* Ccninfo 								*/
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
#define CefC_T_DISC_REQ				0x0007		/* CCNinfo Request Block ccninfo-05		*/
#define CefC_T_DISC_REPLY			0x0008		/* CCNinfo Reply Block ccninfo-05		*/
#define CefC_T_ENDCHUNK				0x000C		/* EndChunkNumber						*/
#define CefC_T_MSG_TLV_NUM			0x000D
#define CefC_T_ORG					0x0FFF		/* Vendor Specific Information			*/

/*----- Reply sub-block TLVs of T_DISC_REPLY	-----*/
#define CefC_T_DISC_CONTENT			0x0000		/* Type for cache						*/
#define CefC_T_DISC_CONTENT_PUBLISHER	0x0001		/* Type for FHR							*/
#define CefC_T_DISC_CONTENT_OWNER	CefC_T_DISC_CONTENT_PUBLISHER

/*----- Organization-Specific TLVs -----*/
#define CefC_T_SYMBOLIC				0x0001		/* Symbolic Interest					*/
#define CefC_T_LONGLIFE				0x0002		/* Long Life Interest					*/
#define CefC_T_SELECTIVE			0x8003		/* Selective Interest					*/
#define CefC_T_SER_LOG				0x8009		/* Serial Logging						*/
#define	CefC_T_VERSION				0x800B		/* T_VERSION Type 0..8.3c				*/
#define CefC_T_PUTVERIFY			0x800C		/* PutVerify Type						*/

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
//#define CefC_T_OPT_DISC_REQ			0x0008		/* Ccninfo Request Block ccninfo-05	*/
#define CefC_T_OPT_DISC_REQHDR		0x0008		/* Ccninfo Request Header Block	ccninfo-05 */
#define CefC_T_OPT_DISC_REPORT		0x0009		/* Ccninfo Report Block					*/
#define CefC_T_OPT_PING_REQ			0x000A		/* Cefping Request Block				*/
#define CefC_T_OPT_TLV_NUM			0x000B

#define CefC_T_OPT_ORG				0x0FFF		/* Vendor Specific Information			*/
#define CefC_T_OPT_SYMBOLIC			0x1001		/* Symbolic Interest					*/
// #920 #define CefC_T_OPT_TRANSPORT		0x1002		/* Transport Plugin Variant				*/
#define CefC_T_OPT_TRANSPORT		0x8004		/* Transport Plugin Variant				*/
#define CefC_T_OPT_EFI				0x1003		/* External Function Invocation			*/
#define CefC_T_OPT_IUR				0x1004		/* Interest User Request				*/
#define CefC_T_OPT_USR_TLV_NUM		0x1005
#define CefC_T_OPT_SEQNUM			0x8008		/* Sequence Number						*/

/*----- TLVs for use in the CefC_T_OPT_SYMBOLIC TLV -----*/
#define CefC_T_OPT_REGULAR			0x0000		/* Regular Interest (just for form) 	*/
#define CefC_T_OPT_INNOVATIVE		0x0002		/* Innovative Interest					*/
#define CefC_T_OPT_PIGGYBACK		0x0003		/* Piggyback Interest 					*/
#define CefC_T_OPT_NUMBER			0x0004		/* Number of requested Cobs 			*/
#define CefC_T_OPT_SCODE			0x0005		/* Symbolic Code						*/
#define CefC_T_OPT_NWPROC			0x0006		/* NWProc Interest						*/

#define CefC_T_OPT_APP_REG			0x1001
#define CefC_T_OPT_APP_DEREG		0x1002
#define CefC_T_OPT_APP_REG_P		0x1003		/* Accept prefix match of Name			*/
#define CefC_T_OPT_APP_PIT_REG		0x1004		/* Register Name in PIT					*/
#define CefC_T_OPT_APP_PIT_DEREG	0x1005		/* DeRegister Name in PIT				*/
#define CefC_T_OPT_DEV_REG_PIT		0x1006		/* Register Name in PIT (develop)		*/

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
/* Option for Ccninfo Request 										*/
/*------------------------------------------------------------------*/

/* Sets to Flag of Request Block 			*/
#define CefC_CtOp_None 				0x00
#define CefC_CtOp_FullDisCover 		0x04
#define CefC_CtOp_Cache 			0x01
#define CefC_CtOp_Publisher			0x02
#define CefC_CtOp_ReqValidation		0x08	/* ccninfo-05 */

/* Sets to Scheme Name of Request Block 	*/
#define CefC_CtSn_Ccnx 				0x00
#define CefC_CtSn_Ndnx 				0x01
#define CefC_CtSn_Cefore			0x02

/*------------------------------------------------------------------*/
/* Return Code for Ccninfo Replay 									*/
/*------------------------------------------------------------------*/
#define CefC_CtRc_NO_ERROR 			0x00
#define CefC_CtRc_WRONG_IF 			0x01
#define CefC_CtRc_INVALID_REQUEST	0x02
#define CefC_CtRc_NO_ROUTE 			0x03
#define CefC_CtRc_NO_INFO 			0x04
#define CefC_CtRc_NO_SPACE			0x05
#define CefC_CtRc_INFO_HIDDEN		0x06
#define CefC_CtRc_ADMIN_PROHIB		0x0E
#define CefC_CtRc_UNKNOWN_REQUEST	0x0F
#define CefC_CtRc_FATAL_ERROR		0x80


#define	CefC_URI_NOT_ACCEPT_CHUNK	0
#define	CefC_URI_ACCEPT_CHUNK		1

#define		CefC_NOT_C3				0
#define		CefC_C3_JOIN			1
#define		CefC_C3_LEAVE			2
#define		CefC_C3_PUBLISH			3

#if 0
//0.8.3
/*------------------------------------------------------------------*/
/* INTERESTRETURN Type			 									*/
/*------------------------------------------------------------------*/
#define	CefC_IR_NO_ROUTE			0x01
#define	CefC_IR_HOPLIMIT_EXCEEDED	0x02
#define	CefC_IR_NO_RESOURCE			0x03
#define	CefC_IR_PATH_ERROR			0x04
#define	CefC_IR_PROHIBITED			0x05
#define	CefC_IR_CONGESION			0x06
#define	CefC_IR_MTU_TOO_LAREG		0x07
#define	CefC_IR_UNSUPPORTED_COBHASH 0x08
#define	CefC_IR_MALFORMED_INTEREST	0x09
#endif

/*------------------------------------------------------------------*/
/* Option for PutVerify		 										*/
/*------------------------------------------------------------------*/
#define CefC_CpvOp_ContInfoMsg		0x15
#define CefC_CpvOp_FibRegMsg		0x16

/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/

/*--------------------------------------------------------------*/
/* Headers														*/
/*--------------------------------------------------------------*/
struct cef_app_frame {
	uint32_t        version;
	uint32_t        type;
	uint8_t			returncode;
	uint64_t        actual_data_len;	/* version~payload_len							*/
										/* + name_len + payload_len + length of trailer	*/
										/*	length of trailer: sizeof(MagicNo)			*/
	unsigned char*  name;
	uint16_t        name_len;
	uint8_t			version_f;
	uint16_t		ver_len;
	unsigned char	ver_value[CefC_Max_Length];
	uint8_t			putverify_f;
	uint8_t			putverify_msgtype;
	uint16_t		chunk_num_f;					/* chunk_num 0:No 1:Yes				*/
	uint32_t        chunk_num;
	int64_t			end_chunk_num;
	unsigned char*  payload;
	uint16_t        payload_len;
	unsigned char   data_entity[CefC_Max_Length];	/* Variable length data(name,payload)	*/
} __attribute__((__packed__));

struct cef_app_request {
	uint32_t        version;
	uint32_t        type;
	uint16_t        symbolic_f;						/* Symbolic Identifier					*/
	unsigned char*  name;
	uint16_t        name_len;
	uint16_t        total_segs_len;					/* total length of T_NAMESEGMENT part	*/
	uint16_t		chnk_num_f;						/* Offset of Chunk Number 				*/
	uint32_t        chunk_num;
	unsigned char   data_entity[CefC_Max_Length];	/* Variable length data(name)			*/
	uint8_t			version_f;						/* 0.8.3c */
	uint16_t		ver_len;						/* 0.8.3c */
	unsigned char	ver_value[CefC_Max_Length];		/* 0.8.3c */
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

#if 0
struct ccninfo_req_block {
	uint16_t 	req_id;
	uint8_t 	skiphop;
	uint8_t 	flag;
	uint32_t	req_arrival_time;
} __attribute__((__packed__));
#endif

struct ccninfo_req_block {
	uint32_t	req_arrival_time;
} __attribute__((__packed__));

struct ccninfo_reqhdr_block {		/* ccninfo-05 */
	uint16_t 	req_id;
	uint8_t 	skiphop;
	uint8_t 	flag;
} __attribute__((__packed__));

struct ccninfo_rep_block {
	uint32_t 	cont_size;
	uint32_t 	cont_cnt;
	uint32_t 	rcv_int;
	uint32_t 	first_seq;
	uint32_t 	last_seq;
	uint32_t 	cache_time;
	uint32_t 	remain_time;
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
	uint8_t				version_f;				/* 0.8.3c */
	uint16_t			ver_len;				/* 0.8.3c */
	unsigned char		version[CefC_Max_Length];/* 0.8.3c */
	
	/***** Cefping						*****/
	uint16_t			responder_f;		/* flag to set Responder Identifier 		*/
											/* it is length of Responder Identifier 	*/
	unsigned char   	responder_id[CefC_Max_Node_Id];
												/* Responder Identifier 					*/
	
	/***** Ccninfo						*****/
	uint16_t 			req_id;					/* Request ID of Request Block			*/
	uint8_t 			skip_hop;				/* SkipHopCount of Request Block		*/
	uint16_t 			ccninfo_flag;			/* Flags of Request Block				*/
	uint16_t 			node_id_len;
	unsigned char   	node_identifer[CefC_Max_Node_Id];
	
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
	
	//0.8.3
	uint16_t 			selective_f;			/* value of CefC_T_SELECTIVE Sub TLV */
	uint32_t			req_num;
	uint32_t			first_chunk;
	uint8_t				last_chunk_f;			//0.8.3c
	uint32_t			last_chunk;
	
	uint8_t				putverify_f;			/* If it is not 0, T_PUTVERIFY is set	*/
	uint8_t				putverify_msgtype;		/* message type in T_PUTVERIFY Value	*/
	uint32_t 			putverify_sseq;
	uint32_t 			putverify_eseq;
	
	/***** External Function Invocation *****/
	// TBD
	
	/***** Interest User Request		*****/
	// TBD

	int			c3_f;
	
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

/* For Application Components */
typedef struct _ceft_appcomp {
	uint16_t 				app_comp;				/* Index of App Components  		*/
													/* sets CefC_T_APP_XXXXX 			*/
	uint16_t 				app_comp_len;			/* length of app_comp_val 			*/
	unsigned char 			app_comp_val[CefC_Max_Length];
													/* value of App Components TLV 		*/
	void*					next_p;
} CefT_AppComp;

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
	uint16_t				AppComp_num;			/* Number of Application Components */
	CefT_AppComp*			AppComp;
	
	/***** Option Header	*****/
	CefT_Option_TLVs 		opt;					/* Parameters to set Option Header 	*/
	
	/***** Validation Algorithm TLV 	*****/
	CefT_Valid_Alg_TLVs 	alg;
	
	//0.8.3
	/***** KeyIdRestriction *****/
	uint8_t					KeyIdRest_f;			/* KeyIdRestriction */
	unsigned char			KeyIdRestSel[32];
	/***** ObjHashRestriction *****/
	uint8_t					CobHRest_f;				/* ObjHashRestriction */
	unsigned char			CobHash[32];
	
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
	uint8_t					end_chunk_num_f;		/* Flag to set End Chunk Number		*/
	uint32_t				end_chunk_num;			/* End Chunk Number					*/
	
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
	
	/* Application Components */
	uint16_t				AppComp_num;			/* Number of Application Components */
	CefT_AppComp*			AppComp;

	//0.8.3
	/***** KeyIdRestriction *****/
	uint8_t					KeyIdRest_f;			/* KeyIdRestriction */
//	unsigned char			KeyId[32];
//	uint16_t 				pubkey_len;
//	unsigned char 			pubkey[CefC_Max_Length];
	
	/***** ObjHashRestriction *****/
	uint8_t					CobHRest_f;				/* ObjHashRestriction */
	unsigned char			CobHash[32];
	
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
/* Parameters to set Ccninfo 									*/
/*--------------------------------------------------------------*/
typedef struct {

	/***** Hop Limit 		*****/
	uint8_t 				hoplimit;				/* Hop Limit of Interest 			*/

	/***** NAME TLV			*****/
	unsigned char 			name[CefC_Max_Length];	/* Name 							*/
	uint16_t				name_len;				/* Length of Name 					*/
	uint32_t				chunk_num;				/* Chunk#							*/
	int						chunk_num_f;			/* Chunk# exist flag				*/
	
	/***** Option Header	*****/
	CefT_Option_TLVs 		opt;					/* Parameters to set Option Header 	*/

	/***** Validation Algorithm TLV 	*****/
	CefT_Valid_Alg_TLVs 	alg;

} CefT_Ccninfo_TLVs;

/*--------------------------------------------------------------*/
/* Parameters to Organization-Specific Parameters 				*/
/*--------------------------------------------------------------*/
typedef struct CefT_Org_Params {

	/***** IANA Private Enterprise Numbers	*****/
	uint32_t				nict_pen[3];

	/***** ORG TLV							*****/
	unsigned char*			offset;					/* Vendor Specific Value offset		*/
	uint16_t				length;					/* Length of T_ORG value(exclude PEN)*/

	uint8_t 				symbolic_f;				/* Symbolic Interest 				*/
	uint8_t 				longlife_f;				/* Long Life Interest 				*/

	//0.8.3
	uint8_t 				selective_f;			/* Selectieve Interest 				*/
	uint32_t				req_chunk;
	uint32_t				first_chunk;
	uint8_t 				last_chunk_f;			/* 0.8.3c */
	uint32_t				last_chunk;

	uint8_t					version_f;				/* 0.8.3c */
	uint16_t				ver_len;				/* 0.8.3c */
	unsigned char			content_ver[CefC_Max_Length];	/* 0.8.3c */

	uint8_t					putverify_f;			/* If it is not 0, T_PUTVERIFY is set	*/
	uint8_t					putverify_msgtype;		/* message type in T_PUTVERIFY Value	*/
	uint32_t 				putverify_sseq;
	uint32_t 				putverify_eseq;

#ifdef CefC_Ser_Log
	unsigned char*			sl_offset;				/* Serial Log offset				*/
	uint16_t				sl_length;				/* Length of SerLog					*/
#endif // CefC_Ser_Log

	int						c3_f;
	uint16_t				c3_length;

} CefT_Org_Params;

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
	
	/***** Ccninfo Request Block		*****/
	uint16_t 			req_id;					/* Request ID of Request Block			*/
	uint8_t 			skip_hop;				/* SkipHopCount of Request Block		*/
	uint16_t 			skip_hop_offset;		/* Offset from the top of message 		*/
	uint16_t 			ccninfo_flag;			/* Flags of Request Block				*/
	uint32_t			req_arrival_time;		/* Request Arrival Time of Request Block*/
	uint16_t 			id_len;
	unsigned char   	node_id[CefC_Max_Node_Id];			/* Node Identifier(e.g. IPv4 address)	*/
	
	/***** Ccninfo Report Block		*****/
	uint16_t 			rpt_block_offset;
	
	/***** Symbolic Interest			*****/
	uint8_t				piggyback_f; 			/* Piggyback Interest 					*/
	uint8_t 			app_reg_f;				/* App Register 						*/
	uint16_t 			bitmap_f;
	uint32_t 			bitmap[CefC_S_Bitmap];
	uint16_t 			number_f;
	uint32_t 			number;
#ifdef CefC_Nwproc
	uint8_t 			nwproc_f;				/* NWProc Interest 						*/
#endif // CefC_Nwproc
	
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
	uint16_t 		top_level_type;				/* Top-Level Type 						*/
	
	/***** NAME TLV			*****/
	uint16_t		name_f;						/* Offset of Name 						*/
	unsigned char 	name[CefC_Max_Length];		/* Name 								*/
	uint16_t		name_len;					/* Length of Name 						*/
#ifdef CefC_Nwproc
	unsigned char 	name_wo_attr[CefC_Max_Length];	/* Name without Attr				*/
	uint16_t		name_wo_attr_len;			/* Length of Name without Attr			*/
	unsigned char 	name_wo_cid[CefC_Max_Length];	/* Name without CID					*/
	uint16_t		name_wo_cid_len;			/* Length of Name without CID			*/
	unsigned char 	cid[CefC_Max_Length];		/* CID 									*/
	uint16_t		cid_len;					/* Length of CID 						*/
#endif // CefC_Nwproc
	uint16_t		chnk_num_f;					/* Offset of Chunk Number 				*/
	uint32_t		chnk_num;					/* Chunk Number 						*/
	uint16_t		chunk_len;					/* Length of Chunk Number 				*/
	uint16_t		end_chunk_num_f;			/* Offset of End Chunk Number			*/
	uint32_t		end_chunk_num;				/* End Chunk Number						*/
	uint16_t		end_chunk_len;				/* Length of End Chunk Number 			*/
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
	uint16_t				AppComp_num;			/* Number of Application Components */
	CefT_AppComp*			AppComp;
	
	/***** PAYLOAD TLV 		*****/
	uint16_t		payload_f;					/* Offset of Payload					*/
	unsigned char 	payload[CefC_Max_Length]; 	/* Payload 								*/
	uint16_t		payload_len;				/* Length of Payload 					*/

	/***** DISC_REPLY TLV		*****/
	uint16_t		discreply_f;				/* Offset of Disc Reply					*/
	unsigned char 	discreply[CefC_Max_Length]; /* Disc Reply 							*/
	uint16_t		discreply_len;				/* Length of Disc Reply 				*/
	
	/***** Metadata TLV		*****/
	int				expiry_f;					/* *0.8.3c */
	uint64_t		expiry;						/* The time at which the Payload		*/
												/* expires [unit: ms]					*/
	
	/***** Sequence Number 				*****/
	uint32_t 		seqnum;

	/***** Organization-Specific Parameters	*****/
	CefT_Org_Params org;
	
	//0.8.3
	/***** for more infomation	*****/
	int				InterestType;				/* for PIT marking */
	/***** KeyIdRester *****/
	uint16_t		KeyIdRester_f;				/* Offset of KeyIdRester				*/
	uint16_t		KeyIdRester_sel_len;		/* Length of KeyIdRester_selector		*/
	unsigned char 	KeyIdRester_selector[32];	/* KeyIdRester_selector					*/
	/***** ObjHashRester *****/
	uint16_t		ObjHash_f;					/* Offset of ObjHashRester				*/
	uint16_t		ObjHash_len;				/* Length of ObjHash					*/
	unsigned char 	ObjHash[32];				/* ObjHash								*/

} CefT_Parsed_Message;

/*--------------------------------------------------------------*/
/* Parsed Ccninfo message										*/
/*--------------------------------------------------------------*/
typedef struct ccninfo_rpt {
	uint32_t			req_arrival_time;		/* Request Arrival Time of Request Block		*/
	uint16_t 			id_len;
	unsigned char*   	node_id;				/* Node Identifier(e.g. IPv4 address)			*/
	
	struct ccninfo_rpt*	next;
} CefT_Ccninfo_Rpt;

typedef struct ccninfo_rep {
	uint16_t			rep_type;				/* Type											*/
	uint16_t			length;					/* Length										*/
	uint32_t			obj_size;				/* Object Size									*/
	uint32_t			obj_cnt;				/* Object Count									*/
	uint32_t			rcv_interest_cnt;		/* # Received Interest							*/
	uint32_t			first_seq;				/* First Seqnum									*/
	uint32_t			last_seq;				/* Last Seqnum									*/
	uint32_t			cache_time;				/* Elapsed Cache Time							*/
	uint32_t			lifetime;				/* Remain Cache Lifetime						*/
	
	unsigned char*		rep_name;				/* Name 										*/
	uint16_t			rep_name_len;			/* Length of Name 								*/
	
	unsigned char*		rep_range;				/* range(reply)									*/
	uint16_t			rep_range_len;			/* length of range(reply)						*/
	
	struct ccninfo_rep*	next;
} CefT_Ccninfo_Rep;

typedef struct {
	uint16_t			pkt_type;				/* PacketType									*/
	uint16_t			ret_code;				/* ReturnCode									*/
	uint8_t				hoplimit;				/* Hop Limit									*/
	
	/***** Request Block *****/
	uint16_t 			req_id;					/* Request ID of Request Block					*/
	uint8_t 			skip_hop;				/* SkipHopCount of Request Block				*/
	uint16_t 			skip_hop_offset;		/* Offset from the top of message 				*/
	uint16_t 			ccninfo_flag;			/* Flags of Request Block						*/
	uint32_t			req_arrival_time;		/* Request Arrival Time of Request Block		*/
	uint16_t 			id_len;
	unsigned char   	node_id[CefC_Max_Node_Id];	/* Node Identifier(e.g. IPv4 address)		*/
	
	/***** Report Block *****/
	uint8_t				rpt_blk_num;
	CefT_Ccninfo_Rpt*	rpt_blk;				/* Report block TLV								*/
	CefT_Ccninfo_Rpt*	rpt_blk_tail;
	
	/***** Discovery *****/
	unsigned char*		disc_name;				/* Name 										*/
	uint16_t			disc_name_len;			/* Length of Name 								*/
	
	/***** Reply Block *****/
	uint8_t				rep_blk_num;
	CefT_Ccninfo_Rep*	rep_blk;				/* Report block TLV								*/
	CefT_Ccninfo_Rep*	rep_blk_tail;
	uint32_t			reply_req_arrival_time;	/* Request Arrival Time of Request Block		*/
	uint16_t 			reply_node_len;
	unsigned char*   	reply_reply_node;		/* Node Identifier(e.g. IPv4 address)			*/
	
	/***** put_verify *****/
	uint8_t				putverify_f;
	uint8_t				putverify_msgtype;		/* message type									*/
	uint32_t 			putverify_sseq;			/* start chunk number							*/
	uint32_t 			putverify_eseq;			/* end chunk number								*/
} CefT_Parsed_Ccninfo;

typedef struct {
	uint8_t fl_4bit: 4;
	uint8_t sh_4bit: 4;
} CEF_FRAME_SKIPHOP_T;

/**
 * Clap Corner
 *  */
/**  */
#define PEN_SIZE          3  // Private Enterprise Number
#define HEX_UUID_SIZE     32 // UUID
#define MAX_NAME_SEGMENTS 1  // Name TLV
#define MAX_NUM_SIZE      4  // TLV

#define PT_CONTENT        0x02   // PT_CONTENT
#define PT_REQUEST        0x04   // PT_REQUEST
#define PT_REPLY          0x05   // PT_REPLY
#define T_INTEREST        0x0001 // 
#define T_OBJECT          0x0002 // 
#define T_COMM_CREATE     0x8101 // 
#define T_COMM_DESTROY    0x8102 // 
#define T_COMM_JOIN       0x8103 // 
#define T_COMM_LEAVE      0x8104 // 
#define T_COMM_PUBLISH    0x8105 // 
// 0x8106 reserved

// Name TLV
#define T_NAME            0x0000
#define T_MESSAGEMENT     0x0001
#define T_CHUNK           0x0010
#define T_APP             0x1000   // T_APP=0x1XXX XXX 000-FFF
#define T_APP_0           0x1000   // T_APP:0
#define T_APP_1           0x1001   // T_APP:1
#define T_APP_2           0x1002   // T_APP:2
//
#define T_APP_4095        0x1FFF   // T_APP:4095

// End Chunk
#define T_ENDCHUNK        0x000C

// 
#define T_COMM_OWNER      0x8107
#define T_COMM_USER       0x8108
#define T_COMM_DEVICE     0x8109
#define T_COMM_PASS       0x810a
#define T_COMM_RWPASS     0x810b
#define T_COMM_START      0x810c
#define T_COMM_END        0x810d
#define T_COMM_LOCATION   0x810e
#define T_ORG             0x0fff
#define NICT_PEN          0x00C96C

/**  */

// Name TLV
struct c3_name_segment {
    uint16_t     type;
	uint16_t     length;
	uint8_t      segment[HEX_UUID_SIZE];
} __attribute__((__packed__));

// 
struct c3_number {
    uint16_t     type;                  // T_CHUNK(0x0010) T_ENDCHUNK(0x000C)
	                                    // T_APP:1-T_APP:4095(0x1001-0x1FFF)
	uint16_t     length;                // 1-4
	uint8_t      data[MAX_NUM_SIZE];    // 
	                                    // 
} __attribute__((__packed__));

// Name TLV
// JOIN, LEAVE, CREATE, DESTROY
struct c3_simple_name {
	uint16_t                type;     // T_NAME(0x0000)
	uint16_t                length;
	struct c3_name_segment  segments[MAX_NAME_SEGMENTS];
} __attribute__((__packed__));

// Name TLV
// PUBLISH
struct c3_name {
	uint16_t                type;       // T_NAME(0x0000)
	uint16_t                length;
	struct c3_name_segment  segments[MAX_NAME_SEGMENTS];
	struct c3_number         datatype;  // type T_APP:1-T_APP:4095 (0x1001-0x1FFF)
	struct c3_number         chunk;     // type T_CHUNK(0x0010)
} __attribute__((__packed__));

// Vendor TLV
struct c3_vendor {
	uint16_t    type;     // T_ORG(0x0FFF)
    uint16_t    length;   // length of (PEN + Vendor Specific Value)
	uint8_t     pen[PEN_SIZE]; // Private Enterprise Number (NICT: 0x00C96C)
	uint8_t     value[CefC_Max_Length]; // Vendor Specific Value
} __attribute__((__packed__));

// Message TLV
// JOIN, LEAVE, CREATE, DESTROY
struct c3_message {
	uint16_t                type;    // T_INTEREST(0x0001)
	uint16_t                length;  // length of (Name TLV + Vendor TLV)
    struct c3_simple_name   name;    // Name TLV
	struct c3_vendor        vendor;  // Vendor TLV
} __attribute__((__packed__));

// Payload TLV
struct c3_payload {
	uint16_t    type;                    // T_PAYLOAD(0x0001)
	uint16_t    length;                  // length of Payload (0 is possible)
	uint8_t     value[CefC_Max_Length];  // Payload
} __attribute__((__packed__));

// Payload TLV Message TLV
// PUBLISH
 struct c3_mes_payload {
	uint16_t           type;     // T_OBJECT(0x0002)
	uint16_t           length;   // length of (Name TLV + Vendor TLV)
    struct c3_name     name;     // Name TLV
	struct c3_number   endchunk; // End Chunk TLV (Optional) T_ENDCHUNK (0x000C)
	struct c3_vendor   vendor;   // Vendor TLV
	struct c3_payload  payload;  // Payload TLV (Optional)
} __attribute__((__packed__));

// Clap Corner Interest
struct c3_interest {
	struct fixed_hdr    header;   // PT_REQUEST(0x04) PT_REPLY(0x05) PT_CONTENT (0x)
	struct c3_message   messsage;
} __attribute__((__packed__));

// Clap Corner Object
struct c3_object {
	struct fixed_hdr    header;   // Type PT_REPLY (0x05)
	struct c3_mes_payload   messsage; // 
} __attribute__((__packed__));


/**
 * Vendor Specific Value 
 */
#define C3_MAX_SUB_VALUES   6   // 
#define C3_MAX_VALUE_SIZE   256 // 

// T_COMM_OWNER (0x8107), T_COMM_USER (0x8108), T_COMM_DEVICE(0x8109),
// T_COMM_PASS (0x810a), T_COMM_RW_PASS (0x810b), T_COMM_START (0x810c),
// T_COMM_END (0x810d), T_COMM_LOCATION (0x810e)
struct c3_tlv {
    uint16_t  type;
	uint16_t  length;
	uint8_t   value[C3_MAX_VALUE_SIZE];
} __attribute__((__packed__));

// Vendor Speficic Value
// T_COMM_CREATE (0x8101), T_COMM_DESTROY (0x8102),T_COMM_JOIN (0x8103),
// T_COMM_LEAVE (0x8104), T_COMM_PUBLISH (0x8105) 
struct c3_vendor_tlv {
	uint16_t        type;
	uint16_t        length;
	struct c3_tlv   values[C3_MAX_SUB_VALUES];
} __attribute__((__packed__));



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
int 										/* Length of Content Object message 		*/
cef_frame_object_create_for_csmgrd (
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
	Creates the Ccninfo Request from the specified Parameters
----------------------------------------------------------------------------------------*/
int 										/* Length of Ccninfo message 				*/
cef_frame_ccninfo_req_create (
	unsigned char* buff, 					/* buffer to set Ccninfo Request			*/
	CefT_Ccninfo_TLVs* tlvs					/* Parameters to set Ccninfo Request 		*/
);
/*--------------------------------------------------------------------------------------
	Adds a time stamp on Ccninfo Request
----------------------------------------------------------------------------------------*/
int 										/* Length of Ccninfo message 				*/
cef_frame_ccninfo_req_add_stamp (
	unsigned char* buff, 					/* Ccninfo Request							*/
	uint16_t msg_len, 
	unsigned char* node_id, 				/* Node ID 									*/
	uint16_t id_len, 						/* length of Node ID 						*/
	struct timeval t 						/* current time in UNIX-time(us) 			*/
);
/*--------------------------------------------------------------------------------------
	Creates the Validation TLVs for Ccninfo Reply message
----------------------------------------------------------------------------------------*/
int 										/* Length of Ccninfo message 				*/
cef_frame_ccninfo_vald_create_for_reply (
	unsigned char* buff, 					/* Ccninfo Reply message					*/
	CefT_Ccninfo_TLVs* tlvs					/* Parameters to set Ccninfo Reply 			*/
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
size_t										/* length of buff/new_buff					*/
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
	Update cache time
----------------------------------------------------------------------------------------*/
void 										/* Returns a negative value if it fails 	*/
cef_frame_opheader_cachetime_update (
	unsigned char* 	cob, 					/* the cob message to parse					*/
	uint64_t		cachetime
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
	Convert name to uri without ChunkNum
----------------------------------------------------------------------------------------*/
int
cef_frame_conversion_name_to_uri_without_chunknum (
	unsigned char* name,
	unsigned int name_len,
	char* uri
);
/*--------------------------------------------------------------------------------------
	Separate name and CID
----------------------------------------------------------------------------------------*/
int
cef_frame_separate_name_and_cid (
	unsigned char* org_name,
	unsigned int org_name_len,
	unsigned char* name_wo_cid,				/* Name without CID removed from org_name	*/
	unsigned int* name_wo_cid_len,
	unsigned char* cid,						/* CID(;CID=...)							*/
	unsigned int* cid_len
);
/*--------------------------------------------------------------------------------------
	Conversion CID to HexChar and Add to name
----------------------------------------------------------------------------------------*/
int											/* 0:Already contains CID, 1:Added			*/
cef_frame_conversion_hexch_cid_add_to_name (
	unsigned char* name,
	unsigned int name_len,
	unsigned char* cid,
	unsigned int cid_len,
	unsigned char* new_name,
	unsigned int* new_name_len
);
/*--------------------------------------------------------------------------------------
	Get name without attributes
----------------------------------------------------------------------------------------*/
int
cef_frame_get_name_wo_attr (
	unsigned char* org_name,
	unsigned int org_name_len,
	unsigned char* new_name,					/* name without attributes				*/
	unsigned int* name_wo_attr_len				/* name length without attributes		*/
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
	Get total length of T_NAMESEGMENT part
----------------------------------------------------------------------------------------*/
unsigned int
cef_frame_get_len_total_namesegments (
	unsigned char* name,
	unsigned int name_len
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


/*--------------------------------------------------------------------------------------
	Set flag whether to use OPT_SEQNUM
----------------------------------------------------------------------------------------*/
void
cef_frame_set_opt_seqnum_f (
	int				use_f				/* When not using     : CefC_OptSeqnum_NotUse	*/
										/* When using         : CefC_OptSeqnum_Use		*/
										/* When finished using: CefC_OptSeqnum_UnUse	*/
);
/*--------------------------------------------------------------------------------------
	Get flag whether to use OPT_SEQNUM
----------------------------------------------------------------------------------------*/
uint16_t
cef_frame_get_opt_seqnum_f (
	void
);
/*--------------------------------------------------------------------------------------
	get Name without chunkno
----------------------------------------------------------------------------------------*/
uint16_t										/* index of T_CHUNK						*/
cef_frame_get_name_without_chunkno (
	unsigned char* name,						/* content name							*/
	uint16_t name_len,							/* content name Length					*/
	uint32_t* ret_seq							/* chunk number							*/
);
/*--------------------------------------------------------------------------------------
	Parses a Ccninfo message
----------------------------------------------------------------------------------------*/
int
cef_frame_ccninfo_parse (
	unsigned char* msg, 					/* the message to parse						*/
	CefT_Parsed_Ccninfo* pci 				/* Structure to set parsed Ccninfo message	*/
);
/*--------------------------------------------------------------------------------------
	Frees a Parsed Ccninfo message
----------------------------------------------------------------------------------------*/
void
cef_frame_ccninfo_parsed_free (
	CefT_Parsed_Ccninfo* pci 				/* Structure to set parsed Ccninfo message	*/
);
/*--------------------------------------------------------------------------------------
	debug print
----------------------------------------------------------------------------------------*/
void
cef_frame_debug_print_buff (
	unsigned char* buff,				/* The buffer that want to output stderr		*/
	uint16_t buff_len,					/* Length of buff								*/
	uint8_t n_per_line					/* Number of 1 line (0 is nothing to do)		*/
);

int
cef_frame_input_uri_pre_check(
	const char* inuri, 						/* URI										*/
	unsigned char* name_1,					/* buffer to set Name 						*/
	int			chunk_f						/* "/Chunk=" Accept or Not Accept			*/
);

int
cef_frame_input_uri_pre_check2(
	const char* inuri, 						/* URI										*/
	unsigned char* name_1,					/* buffer to set Name 						*/
	int			chunk_f						/* "/Chunk=" Accept or Not Accept			*/
);

void
cef_frame_app_components_free(  uint16_t		AppComp_num,
								 CefT_AppComp*	AppComp
);

//0.8.3
/*--------------------------------------------------------------------------------------
	Creates the Interest Return from the specified Parameters
----------------------------------------------------------------------------------------*/
int 										/* Length of Interest Return Message		*/
cef_frame_interest_return_create (
	unsigned char* msg, 					/* Input Interest msg						*/
	uint16_t msg_len, 
	unsigned char* buff, 					/* buffer to set Interest Return			*/
	uint8_t	IR_type							/* Interest Return 							*/
);

#endif // __CEF_FRAME_HEADER__

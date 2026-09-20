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
 * cef_define.h
 */

#ifndef __CEF_DEFINE_HEADER__
#define __CEF_DEFINE_HEADER__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <inttypes.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

#ifdef __APPLE__
#include "TargetConditionals.h"
#if TARGET_IPHONE_SIMULATOR
    // iOS Simulator
#elif TARGET_OS_IPHONE
    // iOS device
#elif TARGET_OS_MAC
    // Other kinds of Mac OS
    #define CefC_MACOS   1
#else
#   error "Unknown Apple platform"
#endif // TARGET_IPHONE_SIMULATOR

//#define FMTU64 		"%llu"	//20210408
#define FMT64 		"%"PRId64
#define FMTU64 		"%"PRIu64
#define FMTLINT 	"%03d"

#else // __APPLE__

//#define FMTU64 		"%lu"	//20210408
#define FMT64 		"%"PRId64
#define FMTU64 		"%"PRIu64
#define FMTLINT 	"%03ld"

#endif // __APPLE__

#define CefFp_Usage  stderr

/*************** Version 		****************/
#define CefC_Version					0x01

/*************** User Directry 	****************/
#define CefC_CEFORE_DIR					"CEFORE_DIR"
#define CefC_CEFORE_DIR_DEF				"/usr/local/cefore"
#define CefC_CEFORE_USER_DIR			"CEFORE_USER_DIR"

/*************** Clock	 		****************/
#define CefC_Clock						500
#define CefC_Pit_Clock_Clean			1000000

/*************** Type of Node 	****************/
#define CefC_Node_Type_Invalid			0x00
#define CefC_Node_Type_Receiver			0x01
#define CefC_Node_Type_Publisher		0x02
#define CefC_Node_Type_Router			0x04

#define CefC_Max_Length					65535
#define CefC_Min_Block					1
#define CefC_Max_Block					57344

/*************** Type of object sender Node ****************/
#define CefC_OBJ_Sender_Type_Neighbor	0x00
#define CefC_OBJ_Sender_Type_Csmgr		0x01
#define CefC_OBJ_Sender_Type_Localcache	0x02

/*************** Flag of PIT search key ****************/
#define CefC_PitKey_With_KEYID		1
#define CefC_PitKey_With_COBHASH	2
#define CefC_PitKey_With_NAME		4

/*************** Prameter Names ***************/
#define CefC_ParamName_PortNum			"PORT_NUM"
#define CefC_ParamName_PitSize			"PIT_SIZE"
#define CefC_ParamName_FibSize			"FIB_SIZE"
#define CefC_ParamName_LocalSockId		"LOCAL_SOCK_ID"
#define CefC_ParamName_PrvKey			"PRIVATE_KEY"
#define CefC_ParamName_NbrSize			"NBR_SIZE"
#define CefC_ParamName_NbrMngInterval	"NBR_INTERVAL"
#define CefC_ParamName_NbrMngThread 	"NBR_THRESH"
#define CefC_ParamName_FwdRate 			"FWD_RATE"
#define CefC_ParamName_Sktype			"SOCK_TYPE"
#define CefC_ParamName_Babel			"USE_CEFBABEL"
#define CefC_ParamName_Babel_Route		"CEFBABEL_ROUTE"
#define CefC_ParamName_Cs_Mode			"CS_MODE"
#define CefC_ParamName_Forwarding_Strategy	"FORWARDING_STRATEGY"
//2020
#define CefC_ParamName_Node_Name		"NODE_NAME"
#define CefC_ParamName_PitSize_App		"PIT_SIZE_APP"
#define CefC_ParamName_FibSize_App		"FIB_SIZE_APP"
//0.8.3
#define	CefC_ParamName_InterestRetrans	"INTEREST_RETRANSMISSION"
#define	CefC_ParamName_SelectiveForward	"SELECTIVE_FORWARDING"
#define	CefC_ParamName_SymbolicBackBuff	"SYMBOLIC_BACKBUFFER"
#define	CefC_ParamName_IR_Congestion	"INTEREST_RETURN_CONGESTION_THRESHOLD"
#define	CefC_ParamName_BANDWIDTH_INTVAL	"BANDWIDTH_STAT_INTERVAL"
#define	CefC_ParamName_SYMBOLIC_LIFETIME "SYMBOLIC_INTEREST_MAX_LIFETIME"
#define	CefC_ParamName_REGULAR_LIFETIME	"REGULAR_INTEREST_MAX_LIFETIME"
#define CefC_ParamName_CSMGR_ACCESS		"CSMGR_ACCESS"
#define CefC_ParamName_BUFFER_CACHE_TIME	"BUFFER_CACHE_TIME"
#define CefC_ParamName_LOCAL_CACHE_DEFAULT_RCT	"LOCAL_CACHE_DEFAULT_RCT"
//202108
#define CefC_ParamName_IR_Option		"ENABLE_INTEREST_RETURN"
#define CefC_ParamName_IR_Enabled		"ENABLED_RETURN_CODE"
//20220311
#define CefC_ParamName_SELECTIVE_MAX	"SELECTIVE_INTEREST_MAX_RANGE"

#define CefC_ParamName_CcninfoAccessPolicy	"CCNINFO_ACCESS_POLICY"
#define CefC_ParamName_CcninfoFullDiscovery	"CCNINFO_FULL_DISCOVERY"
#define CefC_ParamName_CcninfoValidAlg		"CCNINFO_VALID_ALG"
#define CefC_ParamName_CcninfoSha256KeyPrfx	"CCNINFO_SHA256_KEY_PRFX"
#define CefC_ParamName_CcninfoReplyTimeout	"CCNINFO_REPLY_TIMEOUT"

/*************** Default Values ***************/
#define CefC_Default_PortNum			9695
#define CefC_Default_PitSize			65535
#define CefC_Maximum_PitSize			16777215	/* 16777216=2^24 */
#define CefC_Default_FibSize			1024
#define CefC_Maximum_FibSize			16777215
#define CefC_Default_ValidKey_Table_Size	1024
#define CefC_Maximum_ValidKey_Table_Size	65535
#define CefC_Default_Sktype				SOCK_STREAM
#define CefC_Default_NbrInterval		10000000
#define CefC_Default_LifetimeSec		2
#define CefC_Default_LifetimeUs			2000000
#define CefC_Default_ForwardingStrategy	"default"
//2020
#define	CefC_Default_PitAppSize			1024
#define	CefC_Default_FibAppSize			1024
#define	CefC_PitAppSize_MAX				4096
#define	CefC_FibAppSize_MAX				1024000
//0.8.3
#define CefC_Default_InterestRetrans	"RFC8569"
#define CefC_Default_SelectiveForward	1
#define CefC_Default_SymbolicBackBuff	100
#define CefC_Default_IR_Congestion		90.0
#define CefC_Default_BANDWIDTH_STAT_INTERVAL	1
#define CefC_Default_SYMBOLIC_LIFETIME	4000
#define CefC_Default_REGULAR_LIFETIME	2000
#define CefC_Default_CSMGR_ACCESS_RW	0
#define CefC_Default_CSMGR_ACCESS_RO	1
#define CefC_Default_BUFFER_CACHE_TIME	10000

#define CefC_Default_CcninfoAccessPolicy	0
#define CefC_Default_CcninfoFullDiscovery	0
#define CefC_Default_CcninfoValidAlg		"crc32c"		/* ccninfo-05 */
#define CefC_Default_CcninfoSha256KeyPrfx	"cefore"
#define CefC_Default_CcninfoReplyTimeout	4

/*************** Applications   ***************/
#define CefC_App_Version				0xCEF00101
#define CefC_App_Type_Internal			0x10000000
#define CefC_App_Header_Size			16
#define CefC_App_FibSize				200000
#define CefC_App_PitSize				256

/*************** Upper limit of Face 	***************/
#define CefC_Face_Receiver_Max		64
#define CefC_Face_Router_Max		1024
#define CefC_Face_Publisher_Max		256

//0.8.3
#define	CefC_IntRetrans_Type_RFC	0
#define	CefC_IntRetrans_Type_NOSUP	1	/* NO_SUPPRESSION */
#define	CefC_Selet_FWD_OFF			0
#define	CefC_Selet_FWD_ON			1
typedef	enum	{
	CefC_PIT_TYPE_Rgl = 0,
	CefC_PIT_TYPE_Sym = 1,
	CefC_PIT_TYPE_Sel = 2,
	CefC_PIT_TYPE_MAX
}	CefT_PIT_TYPE;
#define	CefC_Select_Cob_Num	256
#define	CefC_MANIFEST_NAME	"/manifest"
#define	CefC_MANIFEST_REC_MAX	200

/*==========================================================================*/
/*	Start of the section relocated from cef_frame.h on August 28, 2026		*/
/*==========================================================================*/

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

#define CefC_MAX_KEYID_NUM 			64

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
#define CefC_S_Bitmap				8
#define CefC_S_Lifetime				2			/* Lifetime V is 2 bytes				*/
#define CefC_S_Cachetime			8			/* cache time V is 8 bytes				*/
#define CefC_S_Expiry				8			/* expiry time V is 8 bytes				*/
#define CefC_S_RCT 					8			/* Recommented Cache Time 				*/
#define CefC_S_SeqNum				4			/* Sequence Number 						*/
#define CefC_S_ReqArrivalTime		4			/* Request Arrival Time is 4 bytes 		*/
#define CefC_S_PutVerify			1			/* MessageType is 1 bytes 				*/
#define CefC_S_Pending				2			/* MessageType is 1 bytes 				*/
#define	CefC_S_PUBLICKEY			512			/* Public key is 512 bytes				*/
#ifdef	SHA512_DIGEST_LENGTH
#define	CefC_S_KeyId	SHA512_DIGEST_LENGTH	/* KeyId is SHA512_DIGEST_LENGTH bytes	*/
#else	// SHA512_DIGEST_LENGTH
#define	CefC_S_KeyId				64			/* KeyId is 64 bytes					*/
#endif	// SHA512_DIGEST_LENGTH

/*------------------------------------------------------------------*/
/* Field Offset														*/
/*------------------------------------------------------------------*/

/*----- Fixed Header 		-----*/
#define CefC_O_Fix_Ver				0
#define CefC_O_Fix_Type				1
#define CefC_O_Fix_PacketLength		2
#define CefC_O_Fix_HopLimit			4
#define CefC_O_Fix_Ccninfo_RetCode	5
#define CefC_O_Fix_HeaderLength		7

/*----- TLV field 			-----*/
#define CefC_O_Type					0
#define CefC_O_Length				2
#define CefC_O_Value				4

/*==========================================================================*/
/* TLV definitions 															*/
/*		Content-Centric Networking (CCNx)									*/
/*		https://www.iana.org/assignments/ccnx/ccnx.xhtml					*/
/*==========================================================================*/

/*------------------------------------------------------------------*/
/* 4.1.  Packet Type Registry										*/
/*------------------------------------------------------------------*/
#define CefC_PT_INTEREST			0x00		/* Interest					*/
#define CefC_PT_OBJECT				0x01		/* Content Object			*/
#define CefC_PT_INTRETURN			0x02		/* Interest Return			*/
#define CefC_PT_REQUEST				0x03		/* Ccninfo Request			*/
#define CefC_PT_REPLY				0x04		/* Ccninfo Reply			*/
#define CefC_PT_MAX			CefC_PT_REPLY		/* MAX						*/

#define CefC_PT_ECHO_REQUEST		0x05		/* Ping Request (RFC9508:Not support)	*/
#define CefC_PT_ECHO_REPLY			0x06		/* Ping Reply   (RFC9508:Not support)	*/
#define CefC_PT_TR_REQUEST			0x07		/* Ping Request (RFC9507:Not support)	*/
#define CefC_PT_TR_REPLY			0x08		/* Ping Reply   (RFC9507:Not support)	*/

#define CefC_PT_CTRL				0x10
#define CefC_PT_BABEL				0x11

/*------------------------------------------------------------------*/
/* 4.2.  Interest Return Code Registry								*/
/*------------------------------------------------------------------*/
#define	CefC_IR_TYPE_NUM			9
#define	CefC_IR_NO_ROUTE			0x01
#define	CefC_IR_HOPLIMIT_EXCEEDED	0x02
#define	CefC_IR_NO_RESOURCE			0x03
#define	CefC_IR_PATH_ERROR			0x04
#define	CefC_IR_PROHIBITED			0x05
#define	CefC_IR_CONGESTION			0x06
#define	CefC_IR_MTU_TOO_LAREG		0x07
#define	CefC_IR_UNSUPPORTED_COBHASH 0x08
#define	CefC_IR_MALFORMED_INTEREST	0x09

/*------------------------------------------------------------------*/
/* 4.4.  Top-Level Type Registry									*/
/*------------------------------------------------------------------*/

#define CefC_T_INTEREST				0x0001		/* Interest					*/
#define CefC_T_OBJECT				0x0002		/* Content Object			*/
#define CefC_T_VALIDATION_ALG		0x0003		/* Validation Algorithm		*/
#define CefC_T_VALIDATION_PAYLOAD	0x0004		/* Validation Payload 		*/
#define CefC_T_DISCOVERY			0x0005		/* Ccninfo 					*/
#define CefC_T_TOP_TLV_NUM			0x0006

/*------------------------------------------------------------------*/
/* 4.6.  Message Type Registry										*/
/*------------------------------------------------------------------*/

#define CefC_T_NAME					0x0000		/* Name									*/
#define CefC_T_PAYLOAD				0x0001		/* Payload								*/
#define CefC_T_KEYIDRESTR			0x0002		/* KeyIdRestriction						*/
#define CefC_T_OBJHASHRESTR			0x0003		/* ContentObjectHashRestriction			*/
								/*	0x0004 Unassigned */
#define CefC_T_PAYLDTYPE			0x0005		/* PayloadType							*/
#define CefC_T_EXPIRY				0x0006		/* ExpiryTime 							*/
#define CefC_T_ENDCHUNK				0x0007		/* EndChunkNumber						*/
#define CefC_T_CHUNK_SIZE			0x0008		/* ChunkSize							*/
#define CefC_T_MSG_TLV_NUM			(CefC_T_CHUNK_SIZE+1)

#define CefC_T_DISC_REQ				0x000D		/* CCNinfo Request Block	(RFC9344)	*/
#define CefC_T_DISC_REPLY			0x000E		/* CCNinfo Reply Block		(RFC9344)	*/
#define CefC_T_ORG					0x0FFF		/* Vendor Specific Information			*/

/*----- Reply sub-block TLVs of T_DISC_REPLY	-----*/
#define CefC_T_DISC_CONTENT			0x0000		/* Type for cache						*/
#define CefC_T_DISC_CONTENT_PUBLISHER	0x0001		/* Type for FHR						*/
#define CefC_T_DISC_CONTENT_OWNER	CefC_T_DISC_CONTENT_PUBLISHER

/*----- Organization-Specific TLVs -----*/
#define CefC_T_SYMBOLIC				0x0001		/* Symbolic Interest					*/
#define CefC_T_LONGLIFE				0x0002		/* Long Life Interest					*/
#define CefC_T_FROM_PUB				0x000D		/* Require to get the content from the 	*/
												/* publisher (a.k.a T_APP_FROM_PUB)		*/
#define CefC_T_REFLEXIVE_SMI 		0x0013		/* Flag of SMI for Reflexive			*/

/*------------------------------------------------------------------*/
/* 4.5.  Name Segment Type Registry									*/
/*------------------------------------------------------------------*/

#define CefC_T_NAMESEGMENT			0x0001		/* Name Segment							*/
#define CefC_T_IPID					0x0002		/* Interest Payload ID 					*/
#define CefC_T_NONCE				0x0003		/* Nonce 								*/
#define CefC_T_VERSION				0x0004		/* Version								*/
#define CefC_T_CHUNK				0x0005		/* Chunk Number							*/
#define CefC_T_REFLEXIVE_NAME		0x0006		/* Reflexive Name Prefix				*/
/* 0x0010-0x0013    Reserved    [RFC8609] */
/* 0x0014-0x0FFE    Unassigned            */

/*----- Application Components 		-----*/
#define CefC_T_APP_MIN 				0x1000		/* Min Index of Application Components 	*/
#define CefC_T_APP_MAX 				0x1FFF		/* Max Index of Application Components 	*/

/*----- Chunk Metadata Name Component 	-----*/
#define CefC_T_META_TLV_NUM			0x0020

/*----- PIT search key extension for KeyId/CoBHash restriction	-----*/
#define CefC_T_PIT_KEYID		(CefC_T_APP_MAX+CefC_T_KEYIDRESTR)
#define CefC_T_PIT_COBHASH		(CefC_T_APP_MAX+CefC_T_OBJHASHRESTR)

/*----- Reflexive forwarding	-----*/
#define CefC_T_TPIT				(CefC_T_APP_MAX+CefC_T_REFLEXIVE_NAME)	/* t-PIT flag */

/*------------------------------------------------------------------*/
/* 4.7.  Payload Type Registry										*/
/*------------------------------------------------------------------*/

#define CefC_T_PAYLOADTYPE_DATA		0x0000
#define CefC_T_PAYLOADTYPE_KEY		0x0001
#define CefC_T_PAYLOADTYPE_LINK		0x0002

/*------------------------------------------------------------------*/
/* 4.8.  Validation Algorithm Type Registry							*/
/*------------------------------------------------------------------*/

#define CefC_T_ALG_INVALID			0x0000
#define CefC_T_CRC32C				0x0002
#define CefC_T_HMAC_SHA256			0x0004
#define CefC_T_RSA_SHA256			0x0005
#define CefC_T_EC_SECP_256K1		0x0006
#define CefC_T_EC_SECP_384R1		0x0007

/*------------------------------------------------------------------*/
/* 4.9.  Validation-Dependent Data Type Registry					*/
/*------------------------------------------------------------------*/

#define CefC_T_ALG_DATA_INVALID		0x0000
#define CefC_T_KEYID				0x0009
#define CefC_T_PUBLICKEYLOC			0x000A
#define CefC_T_PUBLICKEY			0x000B
#define CefC_T_CERT					0x000C
#define CefC_T_LINK					0x000D
#define CefC_T_KEYLINK				0x000E
#define CefC_T_SIGTIME				0x000F

#define CefC_T_CERT_FORWARDER		0x1001

/*------------------------------------------------------------------*/
/* 4.10.  Hash Function Type Registry								*/
/*------------------------------------------------------------------*/

#define CefC_T_SHA_INVALID			0x0000
#define CefC_T_SHA_256				0x0001
#define CefC_T_SHA_512				0x0002

/*------------------------------------------------------------------*/
/* 4.3.  Hop-by-Hop Type Registry									*/
/*------------------------------------------------------------------*/

/* Parsed by cef_frame_opheader_tlv_parse */
#define CefC_T_OPT_INVALID			0x0000		/* Invalid								*/
#define CefC_T_OPT_INTLIFE			0x0001		/* Interest Lifetime 					*/
#define CefC_T_OPT_CACHETIME		0x0002		/* Recommended Cache Time (RCT) 		*/
#define CefC_T_OPT_MSGHASH			0x0003		/* Message Hash							*/
#define CefC_T_OPT_DISC_REQHDR		0x0008		/* Ccninfo Request Header Block	ccninfo-05 */
#define CefC_T_OPT_DISC_REPORT		0x0009		/* Ccninfo Report Block					*/
#define CefC_T_OPT_TLV_NUM			0x000A

/* Parsed by cef_frame_opheader_user_tlv_parse */
#define CefC_T_OPT_ORG				0x0FFF		/* Vendor Specific Information			*/
#define CefC_T_OPT_USER_TLV			0x1000		/* User Local Information (legacy)		*/

/*----- TLVs for use in the CefC_T_OPT_ORG -----*/
#define CefC_T_OPT_TRANSPORT		0x8004		/* Transport Plugin Variant				*/
#define CefC_T_OPT_SEQNUM			0x8005		/* Sequence Number						*/

/*----- TLVs for use in the CefC_T_OPT_USER_TLV -----*/
#define CefC_T_OPT_APP_REG			0x1001
#define CefC_T_OPT_APP_DEREG		0x1002
#define CefC_T_OPT_APP_REG_P		0x1003		/* Accept prefix match of Name			*/
#define CefC_T_OPT_APP_PIT_REG		0x1004		/* Register Name in PIT					*/
#define CefC_T_OPT_APP_PIT_DEREG	0x1005		/* DeRegister Name in PIT				*/
#define CefC_T_OPT_DEV_REG_PIT		0x1006		/* Register Name in PIT (develop)		*/

#define CefC_T_OPT_ROUTE_ADD		0x1007		/* Accept prefix match of Name for network	*/
#define CefC_T_OPT_ROUTE_DEL		0x1008

/*----- TLVs for use in the CefC_T_OPT_INT TLV -----*/
#define CefC_T_OPT_INT				0x8701		/* In-band Network Telemetry			*/
#define CefC_T_OPT_INT_NODE			0x0001
#define CefC_T_OPT_INT_APP_ID		0x0002
#define CefC_T_OPT_INT_IFINDEX		0x0003
#define CefC_T_OPT_INT_BANDWIDTH	0x0004
#define CefC_T_OPT_INT_RESOURCE		0x0005
#define CefC_T_OPT_INT_RESOURCEGENMIN	0x0006
#define CefC_T_OPT_INT_RESOURCEGENMAX	0x0007
#define CefC_T_OPT_INT_CAPACITY		0x0008
#define CefC_T_OPT_INT_AVAILABILITY	0x0009

#define CefC_T_OPT_ROUTE_TRACE		0x8702		/* Route Trace (CeforeSim only)			*/

/*----- TLVs for use in the CefC_T_OPT_MSGHASH TLV -----*/
#define CefC_T_OPT_MH_INVALID		0x0000		/* Invalid			*/
#define CefC_T_OPT_MH_SHA_256		0x0001		/* SHA-256			*/
#define CefC_T_OPT_MH_SHA_512		0x0002		/* SHA-512			*/

/*----- TLVs for use in the H/W router acceleration flags TLV -----*/
#define CefC_T_HW_FLAGS					0x0500
#define CefC_T_HW_FLAGS_SYMBOLIC		0x0010
#define CefC_T_HW_FLAGS_ENABLECACHE		0x0001

#define CefC_T_HW_TIMESTAMP				0x8601

/*----- TLVs for use in the CefC_T_ENCRYPT_ALG TLV -----*/
#define CefC_T_EA_CPABE				0x0001
#define CefC_T_EA_CPABPRE			0x0002

/*==========================================================================*/
/* for process																*/
/*==========================================================================*/

/*------------------------------------------------------------------*/
/* Type of Command 				 									*/
/*------------------------------------------------------------------*/

#define CefC_Cmd_Num				3
#define CefC_Cmd_Invalid			0x00		/* Invalid			*/
#define CefC_Cmd_Link_Req			0x01		/* Link Request		*/
#define CefC_Cmd_Link_Res			0x02		/* Link Response	*/

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

/*------------------------------------------------------------------*/
/* Option for PutVerify		 										*/
/*------------------------------------------------------------------*/
#define CefC_CpvOp_ContInfoMsg		0x15
#define CefC_CpvOp_FibRegMsg		0x16

/*==========================================================================*/
/*	End of the section relocated from cef_frame.h on August 28, 2026		*/
/*==========================================================================*/

//0.8.3c S
#define	CefC_DB_LOCK			"LOCK"
#define	CefC_DB_STAT_TBL		"DB_STAT_TBL"
#define	CefC_DB_STAT_TBL_BODY	"DB_STAT_TBL_BODY"
#define	CefC_DB_STAT_RCD		"DB_STAT_RCD"
#define CefC_DB_COB_MAP_n		"DB_COB_MAP_%d"
#define	CefC_DB_CSMGRD_TBL		"CSMGRD_TBL"
#define	CefC_DB_CSMGRD_TBL_BODY	"CSMGRD_TBL_BODY"

#define	CefC_REDIS_IP			"REDIS_IP"
#define	CefC_REDIS_PORT			"REDIS_PORT"
//0.8.3c E
//20220311
#define	CefC_SELECTIVE_MIN			1
#define	CefC_SELECTIVE_MAX			2048
#define	CefC_Default_SELECTIVE_MAX	512

#define CefC_InbandTelem_Size	64			/* In-band Telemetry Metric Size		*/

/* Clarified that it is not dependent on the operating environment */
/* For example, OpenWRT's BUFSIZ is 1024 */
#define	BUFSIZ_32	32
#define	BUFSIZ_64	64
#define	BUFSIZ_128	128
#define	BUFSIZ_256	256
#define	BUFSIZ_512	512
#define	BUFSIZ_1K	1024
#define	BUFSIZ_2K	(BUFSIZ_1K*2)
#define	BUFSIZ_4K	(BUFSIZ_1K*4)
#define	BUFSIZ_8K	(BUFSIZ_1K*8)
#define	CefC_BUFSIZ	BUFSIZ_8K

/* Linux has a restriction that "Network Interface names can be up to 15 characters."	*/
#define	CefC_IFNAME_SIZ		16

/* Both the segment length and overall length of the name have the same upper limit. */
#define	CefC_NAME_MAXLEN	1024

/* Expand non-displayable characters into hexadecimal strings, so double CefC_NAME_MAXLEN */
#define	CefC_NAME_BUFSIZ	(CefC_NAME_MAXLEN*2)

/* Both the segment length and overall length of the name have the same upper limit. */
#ifdef	SHA256_DIGEST_LENGTH
#define	CefC_KeyId_SIZ	SHA256_DIGEST_LENGTH
#else	// else
#define	CefC_KeyId_SIZ	32
#endif	// SHA256_DIGEST_LENGTH

#define	CefC_PUBKEY_BUFSIZ	1024
#define	CefC_Tiny_BUFSIZ	32
#define	CefC_NumBufSiz		CefC_Tiny_BUFSIZ
#define	CefC_LOCAL_SOCK_ID_SIZ	16

#define	CefC_Connect_Retries	10

#define	CefC_GET_MEMORY_INFO_SH	"get_memory_info.sh"

extern char *CEF_PROGRAM_ID;

/*------------------------------------------------------------------*/
/* Reflexive Forwarding                                             */
/*------------------------------------------------------------------*/
#define REFLEXIVE_FORWARDING
#ifdef REFLEXIVE_FORWARDING
#define CefC_RNP_Len		16
#define CefC_Reflexive_Msg	0x01
#define CefC_Trigger_Msg	0x02
#define CefC_TPIT_LIFETIME_BUFF	1000
#endif // REFLEXIVE_FORWARDING

#endif // __CEF_DEFINE_HEADER__

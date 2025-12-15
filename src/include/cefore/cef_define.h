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

//0.8.3
/*------------------------------------------------------------------*/
/* INTERESTRETURN Type			 									*/
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

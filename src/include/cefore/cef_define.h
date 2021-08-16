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
//#ifdef CefC_Android			//20210408
#include <inttypes.h>
//#endif // CefC_Android		//20210408

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
#define FMTU64 		"%"PRIu64
#define FMTLINT 	"%03d"

#else // __APPLE__

#ifdef CefC_Android
#define FMTU64 		"%"PRIu64
#else // CefC_Android
//#define FMTU64 		"%lu"	//20210408
#define FMTU64 		"%"PRIu64
#define FMTLINT 	"%03ld"
#endif // CefC_Android

#endif // __APPLE__

#ifndef CefC_Android
//#define CefC_DebugOld
#endif // CefC_Android

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
#define CefC_Max_Block					57344

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
#define CefC_ParamName_ForwardingInfoStrategy	"FORWARDING_INFO_STRATEGY"
//2020
#define CefC_ParamName_Node_Name		"NODE_NAME"
#define CefC_ParamName_PitSize_App		"PIT_SIZE_APP"
#define CefC_ParamName_FibSize_App		"FIB_SIZE_APP"
//C3
#define CefC_ParamName_C3Log			"CEF_C3_LOG"
#define CefC_ParamName_C3Log_Dir		"CEF_C3_LOG_DIR"
#define CefC_ParamName_C3log_Period		"CEF_C3_LOG_PERIOD"
#define	CefC_C3_LOG_TAPP_MAX			32
#define	CefC_C3_URI_Prefix				"ccnx:/ClapCorner"
#define	CefC_C3_URI_Prefix_Len			strlen(CefC_C3_URI_Prefix)
//0.8.3
#define	CefC_ParamName_InterestRetrans	"INTEREST_RETRANSMISSION"
#define	CefC_ParamName_SelectiveForward	"SELECTIVE_FORWARDING"
#define	CefC_ParamName_SymbolicBackBuff	"SYMBOLIC_BACKBUFFER"
#define	CefC_ParamName_IR_Congesion		"INTEREST_RETURN_CONGESTION_THRESHOLD"
#define	CefC_ParamName_BANDWIDTH_INTVAL	"BANDWIDTH_STAT_INTERVAL"
#define	CefC_ParamName_SYMBOLIC_LIFETIME "SYMBOLIC_INTEREST_MAX_LIFETIME"
#define	CefC_ParamName_REGULAR_LIFETIME	"REGULAR_INTEREST_MAX_LIFETIME"
#define CefC_ParamName_BW_STAT_PLUGIN	"BANDWIDTH_STAT_PLUGIN"
#define CefC_ParamName_CSMGR_ACCESS		"CSMGR_ACCESS"
#define CefC_ParamName_BUFFER_CACHE_TIME	"BUFFER_CACHE_TIME"
#define CefC_ParamName_LOCAL_CACHE_DEFAULT_RCT	"LOCAL_CACHE_DEFAULT_RCT"
//202108
#define CefC_ParamName_IR_Option		"ENABLE_INTEREST_RETURN"

#ifdef CefC_Ser_Log
#define CefC_ParamName_Log_Size			"SER_LOG_SIZE"
#define CefC_ParamName_Log_Enable		"SER_LOG_ENABLE"
#define CefC_ParamName_Log_Dir			"SER_LOG_DIR"
#endif // CefC_Ser_Log
#ifdef CefC_Ccninfo
#define CefC_ParamName_CcninfoAccessPolicy	"CCNINFO_ACCESS_POLICY"
#define CefC_ParamName_CcninfoFullDiscovery	"CCNINFO_FULL_DISCOVERY"
#define CefC_ParamName_CcninfoValidAlg		"CCNINFO_VALID_ALG"
#define CefC_ParamName_CcninfoSha256KeyPrfx	"CCNINFO_SHA256_KEY_PRFX"
#define CefC_ParamName_CcninfoReplyTimeout	"CCNINFO_REPLY_TIMEOUT"
#endif // CefC_Ccninfo
/*************** Default Values ***************/
#define CefC_Default_PortNum			9896
#ifndef CefC_Nwproc
#define CefC_Default_PitSize			2048
#else // CefC_Nwproc
#define CefC_Default_PitSize			40000
#endif // CefC_Nwproc
#define CefC_Default_FibSize			1024
#define CefC_Default_Sktype				SOCK_STREAM
#define CefC_Default_NbrSize			1
#define CefC_Default_NbrInterval		10000000
#define CefC_Default_NbrThread			3
#define CefC_Default_LifetimeSec		2
#define CefC_Default_LifetimeUs			2000000
#define CefC_Default_ForwardingInfoStrategy	0
//2020
#define	CefC_Default_PitAppSize			64
#define	CefC_Default_FibAppSize			64
#define	CefC_PitAppSize_MAX				1025
#define	CefC_FibAppSize_MAX				1024000
//0.8.3
#define CefC_Default_InterestRetrans	"RFC8569"
#define CefC_Default_SelectiveForward	1
#define CefC_Default_SymbolicBackBuff	100
#define CefC_Default_IR_Congesion		90.0
#define CefC_Default_BANDWIDTH_STAT_INTERVAL	1
#define CefC_Default_SYMBOLIC_LIFETIME	4000
#define CefC_Default_REGULAR_LIFETIME	2000
#define CefC_Default_CSMGR_ACCESS_RW	0
#define CefC_Default_CSMGR_ACCESS_RO	1
#define CefC_Default_BUFFER_CACHE_TIME	10000

#ifdef CefC_Ccninfo
#define CefC_Default_CcninfoAccessPolicy	0
#define CefC_Default_CcninfoFullDiscovery	0
#define CefC_Default_CcninfoValidAlg		"crc32"		/* ccninfo-05 */
#define CefC_Default_CcninfoSha256KeyPrfx	"cefore"
#define CefC_Default_CcninfoReplyTimeout	4
#endif // CefC_Ccninfo

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

#ifdef CefC_Nwproc
/*************** For NWProc ***************/
#define CefC_NWP_Delimiter			';'
#define CefC_NWP_CID_Prefix			";CID="
#define CefC_NWP_CID_Prefix_Len		(sizeof (CefC_NWP_CID_Prefix) - 1)	/* Except terminating characters */
#endif // CefC_Nwproc

//0.8.3
#define	CefC_IntRetrans_Type_RFC	0
#define	CefC_IntRetrans_Type_SUP	1
#define	CefC_Selet_FWD_OFF			0
#define	CefC_Selet_FWD_ON			1
#define	CefC_PIT_TYPE_Reg	0
#define	CefC_PIT_TYPE_Sym	1
#define	CefC_PIT_TYPE_Sel	2
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
#define	CefC_IR_CONGESION			0x06
#define	CefC_IR_MTU_TOO_LAREG		0x07
#define	CefC_IR_UNSUPPORTED_COBHASH 0x08
#define	CefC_IR_MALFORMED_INTEREST	0x09

//0.8.3	NONPUBLIC
#define	CefC_PIT_TYPE_Osym	9



#ifdef CefC_DebugOld
/****************************************************************************************
 For Debug Trace
 ****************************************************************************************/

extern char *CEF_PROGRAM_ID;
extern unsigned int CEF_DEBUG;

/***** Debug Level 		*****/
#define CefC_Dbg_None					0x00
#define CefC_Dbg_Basic					0x01
#define CefC_Dbg_Tpp					0x02
#define CefC_Dbg_Rsv2					0x04
#define CefC_Dbg_Rsv3					0x08
#define CefC_Dbg_Interest				0x10
#define CefC_Dbg_Object					0x20
#define CefC_Dbg_Rsv6					0x40
#define CefC_Dbg_Dev					0x80
#define CefC_Dbg_All					0xFF


#endif // CefC_DebugOld

#endif // __CEF_DEFINE_HEADER__

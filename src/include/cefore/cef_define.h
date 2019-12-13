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
#ifdef CefC_Android
#include <inttypes.h>
#endif // CefC_Android

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

#define FMTU64 		"%llu"
#define FMTLINT 	"%03d"

#else // __APPLE__

#ifdef CefC_Android
#define FMTU64 		"%"PRIu64
#else // CefC_Android
#define FMTU64 		"%lu"
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
#ifdef CefC_Ser_Log
#define CefC_ParamName_Log_Size			"SER_LOG_SIZE"
#define CefC_ParamName_Log_Enable		"SER_LOG_ENABLE"
#define CefC_ParamName_Log_Dir			"SER_LOG_DIR"
#endif // CefC_Ser_Log

/*************** Default Values ***************/
#define CefC_Default_PortNum			9896
#define CefC_Default_PitSize			2048
#define CefC_Default_FibSize			1024
#define CefC_Default_Sktype				SOCK_STREAM
#define CefC_Default_NbrSize			1
#define CefC_Default_NbrInterval		10000000
#define CefC_Default_NbrThread			3
#define CefC_Default_LifetimeSec		4
#define CefC_Default_LifetimeUs			4000000

/*************** Applications   ***************/
#define CefC_App_Version				0xCEF00101
#define CefC_App_Type_Internal			0x10000000
#define CefC_App_Header_Size			16

/*************** Upper limit of Face 	***************/
#define CefC_Face_Receiver_Max		64
#define CefC_Face_Router_Max		1024
#define CefC_Face_Publisher_Max		256

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

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
 * cef_log.h
 */

#ifndef __CEF_LOG_HEADER__
#define __CEF_LOG_HEADER__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

#define CefC_Log_Info 		0				/* Log Level : INFO 					*/
#define CefC_Log_Warn 		1				/* Log Level : WARNING 					*/
#define CefC_Log_Error 		2				/* Log Level : ERROR 					*/
#define CefC_Log_Critical	3				/* Log Level : CRITICAL 				*/

#define CefC_Dbg_None 		0x00			/* Debug Level : None 					*/
#define CefC_Dbg_Fine 		0x01			/* Debug Level : Fine 					*/
#define CefC_Dbg_Finer 		0x02			/* Debug Level : Finer 					*/
#define CefC_Dbg_Finest 	0x03			/* Debug Level : Finest 				*/

#ifdef CefC_Debug
#define cef_dbg_buff_write_name(...)  cef_dbg_buff_write_name_with_line(__func__,__LINE__,__VA_ARGS__)
#define cef_dbg_write(...)  cef_dbg_write_with_line(__func__,__LINE__,__VA_ARGS__)
#define CEF_DBG_OUT(...)    cef_dbg_write_with_line(__func__,__LINE__,CefC_Dbg_Fine,__VA_ARGS__)
#define CEF_DBG_Fine(...)   cef_dbg_write_with_line(__func__,__LINE__,CefC_Dbg_Fine,__VA_ARGS__)
#define CEF_DBG_Finer(...)  cef_dbg_write_with_line(__func__,__LINE__,CefC_Dbg_Finer,__VA_ARGS__)
#define CEF_DBG_Finest(...) cef_dbg_write_with_line(__func__,__LINE__,CefC_Dbg_Finest,__VA_ARGS__)
#define CEF_DBG_Finest(...) cef_dbg_write_with_line(__func__,__LINE__,CefC_Dbg_Finest,__VA_ARGS__)
#else  // CefC_Debug
#define cef_dbg_buff_write_name(...)
#define cef_dbg_write(...)
#define CEF_DBG_OUT(...)
#define CEF_DBG_Fine(...)
#define CEF_DBG_Finer(...)
#define CEF_DBG_Finest(...)
#endif // CefC_Debug


/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/


/****************************************************************************************
 Global Variables
 ****************************************************************************************/

/****************************************************************************************
 Function Declarations
 ****************************************************************************************/

void
cef_log_init (
	const char*	proc_name,
	int			level
);

void
cef_log_init2 (
	const char* config_file_dir,
	int cefnetd_f
);

void
cef_log_write (
	int level, 										/* logging level 					*/
	const char* fmt, 								/* output format					*/
	...												/* parameters						*/
);

extern void cef_log_fopen (int port_num);
extern void cef_log_fprintf (const char *fmt, ...);
extern void cef_log_flush (void);

void
cef_dbg_init (
	const char* proc_name,
	const char* config_file_dir,
	int cefnetd_f
);

void
#ifdef	cef_dbg_write
cef_dbg_write_origin (
#else	//	cef_dbg_write
cef_dbg_write (
#endif	//	cef_dbg_write
	int level, 										/* debug level 						*/
	const char* fmt, 								/* output format					*/
	...												/* parameters						*/
);

void
cef_dbg_write_with_line (
	const char* func, 								/* function name					*/
	const int   lineno, 							/* line number						*/
	int level, 										/* debug level 						*/
	const char* usrfmt,								/* output format					*/
	...												/* parameters						*/
);

void
cef_dbg_buff_write (
	int level, 										/* debug level 						*/
	const unsigned char* buff,
	int len
);

void
#ifndef	cef_dbg_buff_write_name
cef_dbg_buff_write_name (
#else	//	cef_dbg_buff_write_name
cef_dbg_buff_write_name_with_line (
	const char* func, 								/* function name					*/
	const int   lineno, 							/* line number						*/
#endif	//	cef_dbg_buff_write_name
	int level, 										/* debug level 						*/
	const unsigned char* hdr_buff,
	int hdr_len,
	const unsigned char* buff,
	int len,
	const unsigned char* ftr_buff,
	int ftr_len
);

#endif // __CEF_LOG_HEADER__


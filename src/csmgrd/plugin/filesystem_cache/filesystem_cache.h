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
 * filesystem_cache.h
 */
#ifndef __CSMGRD_FILESYSTEM_CACHE_HEADER__
#define __CSMGRD_FILESYSTEM_CACHE_HEADER__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <netinet/in.h>
#include <stdint.h>

#include <cefore/cef_define.h>
#include <cefore/cef_csmgr.h>
#include <cefore/cef_rngque.h>
#include <csmgrd/csmgrd_plugin.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

#define FscC_Max_Node_Inf_Num			1024			/* Max NodeInformation Num		*/

/*------------------------------------------------------------------
	Limitation
--------------------------------------------------------------------*/

/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/

typedef struct {
	
	/********** FileSystem Cache Information ***********/
	char			fsc_root_path[CefC_Csmgr_File_Path_Length];
												/* FileSystemCache root dir				*/
	
	/********** cache algorithm library **********/
	char 			algo_name[1024];			/* algorithm to replece cache entries	*/
	int				algo_name_size;				/* average name size of Cob processed 	*/
												/* by algorithm							*/
	int				algo_cob_size;				/* average Cob size of Cob processed 	*/
                                  				/* by algorithm							*/

	uint64_t 		cache_capacity;				/* size of cache capacity 				*/

	uint64_t 		extend_lifetime;			/* time to extend lifetime 				*/
	
} FscT_Config_Param;

typedef struct {
	/********** File Element ***********/
	uint16_t		msg_len;					/* Message length						*/
} FscT_File_Head_Element;

typedef struct {

	/********** FileSystemCache Status ***********/
	char			fsc_root_path[CefC_Csmgr_File_Path_Length];
	char			fsc_cache_path[CefC_Csmgr_File_Path_Length];
												/* FileSystemCache root dir				*/
	char			fsc_csmng_file_name[CefC_Csmgr_File_Path_Length];
												/* Csmng dir path						*/
	uint32_t		interval;					/* Interval that to check cache			*/
	uint32_t		fsc_id;						/* FileSystemCache ID					*/
	
	int contmng_id;								/* Content manager memory id			*/

	/********** cache algorithm library **********/
	void* 			algo_lib;					/* records to the loaded library 		*/
	CsmgrdT_Lib_Interface algo_apis;
	char 			algo_name[1024];			/* algorithm to replece cache entries	*/
	int				algo_name_size;				/* average name size of Cob processed 	*/
												/* by algorithm							*/
	int				algo_cob_size;				/* average Cob size of Cob processed 	*/
                                  				/* by algorithm							*/
	uint64_t 		cache_cobs;
	uint64_t		cache_capacity;
	CefT_Mp_Handle	mem_rm_key;

} FscT_Cache_Handle;

#endif // __CSMGRD_FILESYSTEM_CACHE_HEADER__

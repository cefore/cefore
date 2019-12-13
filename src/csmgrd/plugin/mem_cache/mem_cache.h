/*
 * Copyright (c) 2016-2019, National Institute of Information and Communications
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
 * mem_cache.h
 */
#ifndef __CSMGRD_MEM_CACHE_HEADER__
#define __CSMGRD_MEM_CACHE_HEADER__

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

/*------------------------------------------------------------------
	Limitation
--------------------------------------------------------------------*/
#define MemC_Max_Capacity				655360
#define MemC_Max_Child_Num				8			/* Num of child (fork process)		*/
#define MemC_Max_Block_Num				100			/* Num of send cob at once			*/
#define MemC_Block_Send_Rate			16			/* Num of send cob at once			*/


/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/

typedef struct {
	
	char 			algo_name[1024];			/* algorithm to replece cache entries	*/
	int 			capacity;					/* size of cache table 					*/
	
} MemT_Config_Param;

typedef struct {
	
	/********** parameters 		***********/
	char 			algo_name[1024];			/* algorithm to replece cache entries	*/
	int 			capacity;					/* size of cache table 					*/
	
	/********** memory cache 	***********/
	CefT_Mp_Handle	 mem_cache_cob_mp;			/* for cob entry						*/
	CefT_Hash_Handle mem_cache_table;			/* Memory Cache Table					*/
	
	/********** cache algorithm library **********/
	void* 			algo_lib;					/* records to the loaded library 		*/
	CsmgrdT_Lib_Interface algo_apis;
	
} MemT_Cache_Handle;

typedef struct {

	/********** Child pid list ***********/
	pid_t			child_pid;
	unsigned char	key[CsmgrdC_Key_Max];
	int 			key_len;
	uint32_t		seq_num;
	int				sock;

} MemT_Ch_Pid_List;


#endif // __CSMGRD_MEM_CACHE_HEADER__

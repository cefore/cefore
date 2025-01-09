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
 * cef_mpool.h
 */

#ifndef __CEF_MPOOL_HEADER__
#define __CEF_MPOOL_HEADER__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <time.h>

#include <cefore/cef_define.h>
#ifndef CefC_MACOS
#include <malloc.h>
#else
#include <malloc/malloc.h>
#endif

#include <pthread.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/
/***** default size of ring buffer 		*****/
#define CefC_Tx_Que_Size 				512
#define CefC_Rx_Que_Size 				256

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/
typedef size_t CefT_Mp_Handle;

/****************************************************************************************
 Function declaration
 ****************************************************************************************/
CefT_Mp_Handle
cef_mpool_init (
	const char* 	key,
	size_t 			size,
	int 			increment
);

void
cef_mpool_destroy (
	CefT_Mp_Handle ph
);

void*
cef_mpool_alloc (
	CefT_Mp_Handle ph
);

void
cef_mpool_free (
	CefT_Mp_Handle ph,
	void* ptr
);
#endif // __CEF_MPOOL_HEADER__

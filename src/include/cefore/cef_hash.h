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
 * cef_hash.h
 */

#ifndef __CEF_HASH_HEADER__
#define __CEF_HASH_HEADER__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>

#include <cefore/cef_define.h>
#ifndef CefC_MACOS
#include <malloc.h>
#else // CefC_MACOS
#include <malloc/malloc.h>
#endif // CefC_MACOS

#include <time.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/
#define CefC_Hash_False			0
#define CefC_Hash_True			1

#define CefC_Hash_Faile			-1
#define CefC_Hash_New			1
#define CefC_Hash_Old			2

#if 1
#define CefC_Max_KLen 				1024
#endif

/* [Coefficients for expanding hash tables]                                         */
/* Hash tables other than the following do not use coefficients.                    */
#define CefC_Hash_Coef_FIB			1			/* for FIB (Normal, App, c3)                       */
#define CefC_Hash_Coef_PIT			1			/* for PIT (Normal, App, c3)                       */
#define CefC_Hash_Coef_Cache		1			/* for Work Buffer, Memory Cache(conpubd/csmgrd),  */
												/*     Cache Algorithm(csmgrd/conpubd/local cache) */

/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/
typedef size_t CefT_Hash_Handle;

#if 1
typedef struct CefT_Hash_Table {
	uint32_t 		hash;
	unsigned char 	key[CefC_Max_KLen + 1];
	void* 			elem;
	uint32_t 		klen;
	uint8_t			opt_f;
} CefT_Hash_Table;

typedef struct CefT_Hash {
	uint32_t 			seed;
	CefT_Hash_Table*	tbl;
	uint32_t 			elem_max;			/* Prime numbers larger than the user defined maximum size */
	uint32_t 			elem_num;
	uint32_t 			def_elem_max;		/* User defined maximum size	*/
} CefT_Hash;
#endif
/****************************************************************************************
 Global Variables
 ****************************************************************************************/



/****************************************************************************************
 Function Declarations
 ****************************************************************************************/

CefT_Hash_Handle
cef_hash_tbl_create (
	uint32_t table_size
);

CefT_Hash_Handle
cef_hash_tbl_create_ext (
	uint32_t table_size,
	uint8_t coef
);

void
cef_hash_tbl_destroy (
	CefT_Hash_Handle handle
);
int
cef_hash_tbl_item_set (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen,
	void* elem
);
int
cef_hash_tbl_item_set_for_app (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen,
	uint8_t opt,
	void* elem
);

uint32_t
cef_hash_tbl_hashv_get (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen
);

void*
cef_hash_tbl_item_get (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen
);
void*
cef_hash_tbl_item_get_for_app (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen
);

void*
cef_hash_tbl_item_remove (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen
);
void*
cef_hash_tbl_item_get_from_index (
	CefT_Hash_Handle handle,
	uint32_t index
);
void*
cef_hash_tbl_item_check_from_index (
	CefT_Hash_Handle handle,
	uint32_t* index
);
void*
cef_hash_tbl_item_remove_from_index (
	CefT_Hash_Handle handle,
	uint32_t index
);
int
cef_hash_tbl_item_num_get (
	CefT_Hash_Handle handle
);
int
cef_hash_tbl_def_max_get (
	CefT_Hash_Handle handle
);
int
cef_hash_tbl_item_max_idx_get (
	CefT_Hash_Handle handle
);
void*
cef_hash_tbl_elem_get (
	CefT_Hash_Handle handle,
	uint32_t* index
);
void*
cef_hash_tbl_no_col_item_get (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen
);

void*
cef_hash_tbl_item_check (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen
);
int
cef_hash_tbl_item_check_exact (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen
);
void* 
cef_hash_tbl_item_set_prg (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen,
	void* elem
);
void* 
cef_hash_tbl_item_get_prg (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen
);

CefT_Hash_Handle
cef_lhash_tbl_create (
	uint32_t table_size
);

CefT_Hash_Handle
cef_lhash_tbl_create_ext (
	uint32_t table_size,
	uint8_t coef
);

CefT_Hash_Handle
cef_lhash_tbl_create_u32 (
	uint32_t table_size
);

CefT_Hash_Handle
cef_lhash_tbl_create_u32_ext (
	uint32_t table_size,
	uint8_t coef
);

void
cef_lhash_tbl_destroy (
	CefT_Hash_Handle handle
);
int
cef_lhash_tbl_item_set (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen,
	void* elem
);
void*
cef_lhash_tbl_item_get (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen
);
void*
cef_lhash_tbl_item_remove (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen
);

//+++++ 0.9.0b : 2022.07.11
int
cef_lhash_tbl_item_num_get (
	CefT_Hash_Handle handle
);

int
cef_lhash_tbl_def_max_get (
	CefT_Hash_Handle handle
);

int
cef_lhash_tbl_item_max_idx_get (
	CefT_Hash_Handle handle
);

void*
cef_lhash_tbl_elem_get (
	CefT_Hash_Handle handle,
	uint32_t* index,
	uint32_t* elem_num
);

uint32_t
cef_lhash_tbl_hashv_get (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen
);

void*
cef_lhash_tbl_item_get_from_index (
	CefT_Hash_Handle handle,
	uint32_t index,
	uint32_t lindex
);

int
cef_lhash_tbl_item_set_for_app (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen,
	uint8_t opt,
	void* elem
);

void*
cef_lhash_tbl_item_get_for_app (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen
);

int
cef_lhash_tbl_item_check_exact (
	CefT_Hash_Handle handle,
	const unsigned char* key,
	uint32_t klen
);
//----- 0.9.0b : 2022.07.11
#endif // __CEF_HASH_HEADER__

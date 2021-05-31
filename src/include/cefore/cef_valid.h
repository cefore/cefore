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
 * cef_valid.h
 */

#ifndef __CEF_VALID_HEADER__
#define __CEF_VALID_HEADER__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/

/****************************************************************************************
 Global Variables
 ****************************************************************************************/

/****************************************************************************************
 Function Declarations
 ****************************************************************************************/

int
cef_valid_init (
	const char* conf_path
);
#ifdef CefC_Ccninfo
int
cef_valid_init_ccninfoUSER (
	const char* conf_path,
	uint16_t 	valid_type
);

int
cef_valid_init_ccninfoRT (
	const char* conf_path
);
#endif //CefC_Ccninfo
int
cef_valid_type_get (
	const char* type
);
uint32_t 
cef_valid_crc32_calc (
	const unsigned char* buf, 
	size_t len
);
int
cef_valid_get_pubkey (
	const unsigned char* msg, 
	unsigned char* key 
);
int 
cef_valid_keyid_create (
	unsigned char* name, 
	int name_len, 
	unsigned char* pubkey, 
	unsigned char* keyid
);
int
cef_valid_dosign (
	const unsigned char* msg, 
	uint16_t msg_len, 
	const unsigned char* name, 
	int name_len, 
	unsigned char* sign, 
	unsigned int* sign_len
);
int 								/* If the return value is 0 the code is equal, 		*/
									/* otherwise the code is different. 				*/
cef_valid_msg_verify (
	const unsigned char* msg, 
	int msg_len
);
#ifdef CefC_Ccninfo
int 
cef_valid_keyid_create_forccninfo (
	unsigned char* pubkey, 
	unsigned char* keyid
);
int
cef_valid_get_pubkey_forccninfo (
	const unsigned char* msg, 
	unsigned char* key 
);
int
cef_valid_dosign_forccninfo (
	const unsigned char* msg, 
	uint16_t msg_len, 
	unsigned char* sign, 
	unsigned int* sign_len
);
int 								/* If the return value is 0 the code is equal, 		*/
									/* otherwise the code is different. 				*/
cef_valid_msg_verify_forccninfo (
	const unsigned char* msg, 
	int msg_len,
	int* 				rcvdpub_key_bi_len_p,
	unsigned char** 	rcvdpub_key_bi_pp
);

uint16_t							/* new msg length									*/
cef_valid_remove_valdsegs_fr_msg_forccninfo (
	const unsigned char* msg, 
	int msg_len
);

#endif //CefC_Ccninfo





#endif // __CEF_VALID_HEADER__


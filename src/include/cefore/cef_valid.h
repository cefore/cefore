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
#define	CefC_ValidTypeStr_CRC32C "crc32c"
#define	CefC_ValidTypeStr_RSA256 "rsa-sha256"
#define	CefC_ValidTypeStr_EC256K1 "ecdsa-256k1"
#define	CefC_ValidTypeStr_EC384R1 "ecdsa-384r1"
// #define CRC32C_POLY 0x1EDC6F41    /* Forward polynomial of CRC. */

#define Cef_Is_Pkey_Type(type)				\
	(((type) == CefC_T_RSA_SHA256) ||		\
	 ((type) == CefC_T_EC_SECP_256K1) ||	\
	 ((type) == CefC_T_EC_SECP_384R1))

#define CefC_ValidKey_KeyIdLen32 32
#define CefC_ValidKey_KeyIdLen64 64

#define CefC_Valid_HashStr_SHA256 "sha256"
#define CefC_Valid_HashStr_SHA512 "sha512"

#define CefC_ValidKey_Err_NoFile		-1
#define CefC_ValidKey_Err_BadKey		-2
#define CefC_ValidKey_Err_Mismatch		-3
#define CefC_ValidKey_Err_NoMemory		-4
#define CefC_ValidKey_Err_TableFull		-5
#define CefC_ValidKey_Err_NotFound		-6
#define CefC_ValidKey_Err_InvalidArg	-7

/* Validation mode */
#define CefC_ValidMode_NONE 		0x00 // Do not verify
#define CefC_ValidMode_InBand 		0x01 // Verify only for In-Band cases
#define CefC_ValidMode_OutOfBand 	0x02 // Verify only for out-of-band cases

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

int
cef_valid_init_ccninfoUSER (
	const char* conf_path,
	const char* valid_type_str,
	uint16_t* valid_type
);

int
cef_valid_init_ccninfoRT (
	const char* conf_path,
	uint16_t* valid_type
);

int
cef_valid_type_get (
	const char* type
);
int
cef_valid_type_get_forccninfo (
	const char* type
);
uint32_t
cef_valid_crc32c_calc (
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
cef_valid_signature_sign (
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
	int msg_len,
	int* cache_f
);

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
cef_valid_signature_sign_forccninfo (
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

/* for OpenSSL 3.x */
unsigned char*
cef_valid_sha256 (
	const unsigned char *d,
	size_t n,
	unsigned char *md,
	size_t *md_len
);

unsigned char*
cef_valid_sha384 (
	const unsigned char *d,
	size_t n,
	unsigned char *md,
	size_t *md_len
);

unsigned char*
cef_valid_sha512 (
	const unsigned char *d,
	size_t n,
	unsigned char *md,
	size_t *md_len
);

unsigned char*
cef_valid_md5 (
	const unsigned char *d,
	size_t n,
	unsigned char *md
);

int
cef_valid_get_keyid_from_specified_pubkey (
	const char* key_path,	// path of publickey
	unsigned char* buff,	// buffer to store the KeyID
	int buff_len			// length of buffer
);
int
cef_valid_verify_str (
	const char* key_path,	/* path of Publickey	*/
	unsigned char* str,		/* pointer of plaintext	*/
	int str_len,			/* length of plaintext	*/
	unsigned char* sign,	/* poitner of sign		*/
	int sign_len			/* length of sing		*/
);

int
cef_valid_init_fortools (
	const char* prv_key_path
);

void
cef_valid_validkey_table_destroy (
	void
);

int
cef_valid_validkey_add (
	const char* pubkey_path,
	const unsigned char* keyid_hexstr,
	uint16_t keyid_len,
	uint16_t hash_type
);

int
cef_valid_validkey_del (
	const unsigned char* keyid_hexstr,
	uint16_t keyid_len,
	uint16_t hash_type
);

int
cef_valid_validkey_show (
	char* buff,
	int buff_size
);

int
cef_valid_validkey_table_init (
	const char* file_path,
	int validkey_table_size,
	int valid_mode
);

int
cef_valid_validkey_exist (
	const unsigned char* keyid,
	uint16_t keyid_len,
	uint16_t hash_type
);

int
cef_valid_keyid_create_from_hashtype (
	unsigned char* keyid,
	uint16_t hash_type,
	unsigned char* pubkey,
	uint16_t* pub_key_bi_len
);

#endif // __CEF_VALID_HEADER__

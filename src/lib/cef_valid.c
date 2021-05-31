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
 * cef_valid.c
 */

#define __CEF_VALID_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/

#include <string.h>
#include <limits.h>
#include <arpa/inet.h>

#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/objects.h>
#include <openssl/pem.h>

#include <cefore/cef_define.h>
#include <cefore/cef_log.h>
#include <cefore/cef_client.h>
#include <cefore/cef_frame.h>
#include <cefore/cef_valid.h>
#include <cefore/cef_hash.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

typedef struct {
	
	unsigned char 	name[CefC_Max_Length];
	int				name_len;
	char 			prv_key_path[PATH_MAX];
	char 			pub_key_path[PATH_MAX];
	
	unsigned char* 	pub_key_bi;
	int 			pub_key_bi_len;
	
	RSA*  			prv_key;
	RSA*  			pub_key;
	
} CefT_Keys;

/****************************************************************************************
 State Variables
 ****************************************************************************************/

static uint32_t 			crc_table[256];
static CefT_Hash_Handle		key_table;
static CefT_Keys* 			default_key_entry = NULL;
static char					ccninfo_sha256_prvkey_path[PATH_MAX];
static char					ccninfo_sha256_pubkey_path[PATH_MAX];
unsigned char* 				ccninfo_sha256_pub_key_bi;
int 						ccninfo_sha256_pub_key_bi_len;
RSA*  						ccninfo_sha256_pub_key;
RSA*  						ccninfo_sha256_prv_key;

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

static void 
cef_valid_crc_init (
	void
);
static int
cef_valid_conf_value_get (
	const char* p, 
	char* name,
	char* prv_key,
	char* pub_key
);
static int
cef_valid_trim_line_string (
	const char* p1,
	char* p2,
	char* p3
);

static void 
cef_valid_key_entry_free (
	CefT_Keys* key_entry
);
static int
cef_valid_read_conf (
	const char* conf_path
);
static CefT_Keys* 
cef_valid_key_entry_search (
	const unsigned char* name, 
	uint16_t name_len	
);
#ifdef CefC_Ccninfo
static int 							/* If the return value is 0 the code is equal, 		*/
									/* otherwise the code is different. 				*/
cef_valid_rsa_sha256_verify_forccninfo (
	const unsigned char* msg, 
	uint16_t pkt_len, 				/* PacketLength 									*/
	uint16_t hdr_len, 				/* HeaderLength (offset of CCN Message)				*/
	uint16_t alg_offset, 			/* offset of T_VALIDATION_ALG 						*/
	uint16_t pld_offset,	 		/* offset of T_VALIDATION_PAYLOAD 					*/
	int* 				rcvdpub_key_bi_len_p,
	unsigned char** 	rcvdpub_key_bi_pp
);
static int
cef_valid_create_keyinfo_forccninfo ();

static int 							/* If the return value is 0 the code is equal, 		*/
									/* otherwise the code is different. 				*/
cef_valid_rsa_sha256_std_verify_forccninfo (
	const unsigned char* msg, 
	uint16_t pkt_len, 				/* PacketLength 									*/
	uint16_t hdr_len, 				/* HeaderLength (offset of CCN Message)				*/
	uint16_t alg_offset, 			/* offset of T_VALIDATION_ALG 						*/
	uint16_t pld_offset,	 		/* offset of T_VALIDATION_PAYLOAD 					*/
	int* 				rcvdpub_key_bi_len_p,
	unsigned char** 	rcvdpub_key_bi_pp
);
static int 
cef_valid_sha256_keypass_ccninfoRT(
	const char* conf_path
);
#endif //CefC_Ccninfo

static int 							/* If the return value is 0 the code is equal, 		*/
									/* otherwise the code is different. 				*/
cef_valid_crc_verify (
	const unsigned char* msg, 
	uint16_t pkt_len, 				/* PacketLength 									*/
	uint16_t hdr_len, 				/* HeaderLength (offset of CCN Message)				*/
	uint16_t alg_offset, 			/* offset of T_VALIDATION_ALG 						*/
	uint16_t pld_offset		 		/* offset of T_VALIDATION_PAYLOAD 					*/
);
static int 							/* If the return value is 0 the code is equal, 		*/
									/* otherwise the code is different. 				*/
cef_valid_rsa_sha256_verify (
	const unsigned char* msg, 
	uint16_t pkt_len, 				/* PacketLength 									*/
	uint16_t hdr_len, 				/* HeaderLength (offset of CCN Message)				*/
	uint16_t alg_offset, 			/* offset of T_VALIDATION_ALG 						*/
	uint16_t pld_offset		 		/* offset of T_VALIDATION_PAYLOAD 					*/
);
static int 							/* If the return value is 0 the code is equal, 		*/
									/* otherwise the code is different. 				*/
cef_valid_rsa_sha256_std_verify (
	const unsigned char* msg, 
	uint16_t pkt_len, 				/* PacketLength 									*/
	uint16_t hdr_len, 				/* HeaderLength (offset of CCN Message)				*/
	uint16_t alg_offset, 			/* offset of T_VALIDATION_ALG 						*/
	uint16_t pld_offset		 		/* offset of T_VALIDATION_PAYLOAD 					*/
);
static int 							/* If the return value is 0 the code is equal, 		*/
									/* otherwise the code is different. 				*/
cef_valid_rsa_sha256_hby_verify (
	const unsigned char* msg, 
	uint16_t pkt_len, 				/* PacketLength 									*/
	uint16_t hdr_len, 				/* HeaderLength (offset of CCN Message)				*/
	uint16_t alg_offset, 			/* offset of T_VALIDATION_ALG 						*/
	uint16_t pld_offset		 		/* offset of T_VALIDATION_PAYLOAD 					*/
);

/****************************************************************************************
 ****************************************************************************************/

int
cef_valid_init (
	const char* conf_path
) {
	int res = 0;
	
	cef_valid_crc_init ();
	res = cef_valid_read_conf (conf_path);
	
	return (res);
}

#ifdef CefC_Ccninfo
int
cef_valid_init_ccninfoUSER (
	const char* conf_path,
	uint16_t 	valid_type
) {
	int res = 0;
	
	cef_valid_crc_init ();
	if (valid_type == CefC_T_RSA_SHA256) {
		sprintf(ccninfo_sha256_prvkey_path, "%s/.ccninfo/ccninfo_user-private-key"
				, getenv("HOME"));
		sprintf(ccninfo_sha256_pubkey_path, "%s/.ccninfo/ccninfo_user-public-key"
				, getenv("HOME"));
#ifdef DEB_CCNINFO
{
	fprintf (stderr, "DEB_CCNINFO: [%s] ccninfo_sha256_prvkey_path=%s\n"
				   , __FUNCTION__, ccninfo_sha256_prvkey_path);
	fprintf (stderr, "DEB_CCNINFO: [%s] ccninfo_sha256_pubkey_path=%s\n"
				   , __FUNCTION__, ccninfo_sha256_pubkey_path);
}
#endif //DEB_CCNINFO
		res = cef_valid_create_keyinfo_forccninfo();
	}
	return (res);
}
#endif //CefC_Ccninfo
#ifdef CefC_Ccninfo
int
cef_valid_init_ccninfoRT (
	const char* conf_path
) {
	int res = 0;
	
	/* Create sha256 key file name for ccninfo */
	res = cef_valid_sha256_keypass_ccninfoRT (conf_path);
	if (res < 0) {
		return (res);
	}
	res = cef_valid_create_keyinfo_forccninfo();
	
	return (res);
}
#endif //CefC_Ccninfo

int
cef_valid_type_get (
	const char* type
) {
	int res = CefC_T_ALG_INVALID;
	
	if (strcmp (type, "sha256") == 0) {
		res = CefC_T_RSA_SHA256;
	} else if (strcmp (type, "crc32") == 0) {
		res = CefC_T_CRC32C;
	}
	
	return (res);
}

uint32_t 
cef_valid_crc32_calc (
	const unsigned char* buf, 
	size_t len
) {
	uint32_t c = 0xFFFFFFFF;
	size_t i;
	
	for (i = 0 ; i < len ; i++) {
		c = crc_table[(c ^ buf[i]) & 0xFF] ^ (c >> 8);
	}
	
	return (c ^ 0xFFFFFFFF);
}

int 
cef_valid_keyid_create (
	unsigned char* name, 
	int name_len, 
	unsigned char* pubkey, 
	unsigned char* keyid
) {
	CefT_Keys* key_entry;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	
	key_entry = (CefT_Keys*) cef_valid_key_entry_search (name, name_len);
	
	if (key_entry == NULL) {
		return (0);
	}
	SHA256(key_entry->pub_key_bi, key_entry->pub_key_bi_len, hash);
	memcpy (pubkey, key_entry->pub_key_bi, key_entry->pub_key_bi_len);
	memcpy (keyid, hash, 32);
	
	return (key_entry->pub_key_bi_len);
}

int
cef_valid_get_pubkey (
	const unsigned char* msg, 
	unsigned char* key 
) {
	
	struct fixed_hdr* 	fixed_hp;
	struct tlv_hdr* 	tlv_ptr;
	
	uint16_t 	index;
	uint16_t 	pkt_len;
	uint16_t 	hdr_len;
	uint16_t 	val_len;
	uint16_t 	type;
	
	
	/* Obtains header length and packet length 		*/
	fixed_hp = (struct fixed_hdr*) msg;
	pkt_len  = ntohs (fixed_hp->pkt_len);
	hdr_len  = fixed_hp->hdr_len;
	
	/* Obtains CCN message size 		*/
	tlv_ptr = (struct tlv_hdr*) &msg[hdr_len];
	val_len = ntohs (tlv_ptr->length);
	if (hdr_len + CefC_S_TLF + val_len >= pkt_len) {
		return (0);
	}
	index = hdr_len + CefC_S_TLF + val_len;
	
	/*
		 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		+---------------+---------------+---------------+---------------+
		|       T_VALIDATION_ALG        |      44 + Variable Length     |
		+---------------+---------------+---------------+---------------+
		|          T_RSA-SHA256         |      40 + Variable Length     |
		+---------------+---------------+---------------+---------------+
		|             T_KEYID           |               32              |
		+---------------+---------------+---------------+---------------+
		/                            KeyId                              /
		/---------------+---------------+-------------------------------+
		|          T_PUBLICKEY          |   Variable Length (~ 160)     |
		+---------------+---------------+---------------+---------------+
		/                Public Key (DER encoded SPKI)                  /
		+---------------+---------------+---------------+---------------+
	*/
	
	/* Obtains Validation Algorithm TLV size 		*/
	if (pkt_len - index < CefC_S_TLF) {
		return (0);
	}
	tlv_ptr = (struct tlv_hdr*) &msg[index];
	val_len = ntohs (tlv_ptr->length);
	if (index + CefC_S_TLF + val_len > pkt_len) {
		return (0);
	}
	type = ntohs (tlv_ptr->type);
	if (type != CefC_T_VALIDATION_ALG) {
		return (0);
	}
	index += CefC_S_TLF + 40;
	
	/* Obtains the public key 		*/
	tlv_ptr = (struct tlv_hdr*) &msg[index];
	val_len = ntohs (tlv_ptr->length);
	type    = ntohs (tlv_ptr->type);
	
	if ((type != CefC_T_PUBLICKEY) ||
		(index + CefC_S_TLF + val_len > pkt_len)) {
		return (0);
	}
	index += CefC_S_TLF;
	memcpy (key, &msg[index], val_len);
	
#ifndef CefC_Android
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, "Get the public key (%d bytes)\n", val_len);
	cef_dbg_buff_write (CefC_Dbg_Finest, key, val_len);
#endif // CefC_Debug
#endif // CefC_Android
	
	return ((int) val_len);
}

int
cef_valid_dosign (
	const unsigned char* msg, 
	uint16_t msg_len, 
	const unsigned char* name, 
	int name_len, 
	unsigned char* sign, 
	unsigned int* sign_len
) {
	unsigned char hash[SHA256_DIGEST_LENGTH];
	int res;
	CefT_Keys* key_entry;
	
	key_entry = (CefT_Keys*) cef_valid_key_entry_search (name, name_len);
	
	if (key_entry == NULL) {
		return (0);
	}
	
	SHA256 (msg, msg_len, hash);
	res = RSA_sign (
		NID_sha256, hash, SHA256_DIGEST_LENGTH, sign, sign_len, key_entry->prv_key);
	
	
	return (res);
}

int 								/* If the return value is 0 the code is equal, 		*/
									/* otherwise the code is different. 				*/
cef_valid_msg_verify (
	const unsigned char* msg, 
	int msg_len
) {
	int res = -1;
	struct fixed_hdr* 	fixed_hp;
	struct tlv_hdr* 	tlv_ptr;
	
	uint16_t 	index;
	uint16_t 	pkt_len;
	uint16_t 	hdr_len;
	uint16_t 	val_len;
	uint16_t 	type, alg_type;
	uint16_t 	alg_offset = 0;
	uint16_t 	pld_offset = 0;
	
	/* Obtains header length and packet length 		*/
	fixed_hp = (struct fixed_hdr*) msg;
	pkt_len  = ntohs (fixed_hp->pkt_len);
	if (pkt_len != msg_len) {
		return (-1);
	}
	hdr_len = fixed_hp->hdr_len;
	
	/* Obtains CCN message size 		*/
	tlv_ptr = (struct tlv_hdr*) &msg[hdr_len];
	val_len = ntohs (tlv_ptr->length);
	if (hdr_len + CefC_S_TLF + val_len == pkt_len) {
		return (0);
	}
	index = hdr_len + CefC_S_TLF + val_len;
	
	/* Checks Validation Algorithm TLVs 	*/
	alg_offset = index;
	tlv_ptr = (struct tlv_hdr*) &msg[alg_offset];
	type = ntohs (tlv_ptr->type);
	if (type != CefC_T_VALIDATION_ALG) {
		return (-1);
	}
	
	val_len = ntohs (tlv_ptr->length);
	if (index + CefC_S_TLF + val_len >= pkt_len) {
		return (-1);
	}
	index += CefC_S_TLF;
	
	/* Checks Algorithm Type 		*/
	tlv_ptr = (struct tlv_hdr*) &msg[index];
	alg_type = ntohs (tlv_ptr->type);
	index += val_len;
	
	/* Checks Validation Payload TLVs 	*/
	pld_offset = index;
	tlv_ptr = (struct tlv_hdr*) &msg[pld_offset];
	type = ntohs (tlv_ptr->type);
	if (type != CefC_T_VALIDATION_PAYLOAD) {
		return (-1);
	}
	
	val_len = ntohs (tlv_ptr->length);
	if (index + CefC_S_TLF + val_len > pkt_len) {
		return (-1);
	}
	
	switch (alg_type) {
		case CefC_T_CRC32C: {
			res = cef_valid_crc_verify (
					msg, pkt_len, hdr_len, alg_offset, pld_offset);
			break;
		}
		case CefC_T_RSA_SHA256: {
			res = cef_valid_rsa_sha256_verify (
					msg, pkt_len, hdr_len, alg_offset, pld_offset);
			break;
		}
		default: {
			break;
		}
	}
	
	return (res);
}
#ifdef CefC_Ccninfo
int 
cef_valid_keyid_create_forccninfo (
	unsigned char* pubkey, 
	unsigned char* keyid
) {
	unsigned char	hash[SHA256_DIGEST_LENGTH];

	SHA256(ccninfo_sha256_pub_key_bi, ccninfo_sha256_pub_key_bi_len, hash);
	memcpy (pubkey, ccninfo_sha256_pub_key_bi, ccninfo_sha256_pub_key_bi_len);
	memcpy (keyid, hash, 32);
	
	return (ccninfo_sha256_pub_key_bi_len);
}

int
cef_valid_get_pubkey_forccninfo (
	const unsigned char* msg, 
	unsigned char* key 
) {
	
	struct fixed_hdr* 	fixed_hp;
	struct tlv_hdr* 	tlv_ptr;
	
	uint16_t 	index;
	uint16_t 	pkt_len;
	uint16_t 	hdr_len;
	uint16_t 	val_len;
	uint16_t 	type;
	
	
	/* Obtains header length and packet length 		*/
	fixed_hp = (struct fixed_hdr*) msg;
	pkt_len  = ntohs (fixed_hp->pkt_len);
	hdr_len  = fixed_hp->hdr_len;
	
	/* Obtains CCN message size 		*/
	tlv_ptr = (struct tlv_hdr*) &msg[hdr_len];
	val_len = ntohs (tlv_ptr->length);
	if (hdr_len + CefC_S_TLF + val_len >= pkt_len) {
		return (0);
	}
	index = hdr_len + CefC_S_TLF + val_len;
	
	/*
		 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		+---------------+---------------+---------------+---------------+
		|       T_VALIDATION_ALG        |      44 + Variable Length     |
		+---------------+---------------+---------------+---------------+
		|          T_RSA-SHA256         |      40 + Variable Length     |
		+---------------+---------------+---------------+---------------+
		|             T_KEYID           |               32              |
		+---------------+---------------+---------------+---------------+
		/                            KeyId                              /
		/---------------+---------------+-------------------------------+
		|          T_PUBLICKEY          |   Variable Length (~ 160)     |
		+---------------+---------------+---------------+---------------+
		/                Public Key (DER encoded SPKI)                  /
		+---------------+---------------+---------------+---------------+
	*/
	
	/* Obtains Validation Algorithm TLV size 		*/
	if (pkt_len - index < CefC_S_TLF) {
		return (0);
	}
	tlv_ptr = (struct tlv_hdr*) &msg[index];
	val_len = ntohs (tlv_ptr->length);
	if (index + CefC_S_TLF + val_len > pkt_len) {
		return (0);
	}
	type = ntohs (tlv_ptr->type);
	if (type != CefC_T_VALIDATION_ALG) {
		return (0);
	}
	index += CefC_S_TLF + 40;
	
	/* Obtains the public key 		*/
	tlv_ptr = (struct tlv_hdr*) &msg[index];
	val_len = ntohs (tlv_ptr->length);
	type    = ntohs (tlv_ptr->type);
	
	if ((type != CefC_T_PUBLICKEY) ||
		(index + CefC_S_TLF + val_len > pkt_len)) {
		return (0);
	}
	index += CefC_S_TLF;
	memcpy (key, &msg[index], val_len);
	
#ifndef CefC_Android
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, "Get the public key (%d bytes)\n", val_len);
	cef_dbg_buff_write (CefC_Dbg_Finest, key, val_len);
#endif // CefC_Debug
#endif // CefC_Android
	
	return ((int) val_len);
}

int
cef_valid_dosign_forccninfo (
	const unsigned char* msg, 
	uint16_t msg_len, 
	unsigned char* sign, 
	unsigned int* sign_len
) {
	unsigned char 	hash[SHA256_DIGEST_LENGTH];
	int res;

	SHA256 (msg, msg_len, hash);
	res = RSA_sign (
		NID_sha256, hash, SHA256_DIGEST_LENGTH, sign, sign_len, ccninfo_sha256_prv_key);
	
	return (res);
}

int 								/* If the return value is 0 the code is equal, 		*/
									/* otherwise the code is different. 				*/
cef_valid_msg_verify_forccninfo (
	const unsigned char* 	msg, 
	int 					msg_len,
	int* 					rcvdpub_key_bi_len_p,
	unsigned char** 		rcvdpub_key_bi_pp
	
) {
	int res = -1;
	struct fixed_hdr* 	fixed_hp;
	struct tlv_hdr* 	tlv_ptr;
	
	uint16_t 	index;
	uint16_t 	pkt_len;
	uint16_t 	hdr_len;
	uint16_t 	val_len;
	uint16_t 	type, alg_type;
	uint16_t 	alg_offset = 0;
	uint16_t 	pld_offset = 0;
	
	/* Clear Rcvd public key info */
	if (rcvdpub_key_bi_len_p != NULL) {
		*rcvdpub_key_bi_len_p = 0;
	}
	if (rcvdpub_key_bi_pp != NULL) {
		if (*rcvdpub_key_bi_pp != NULL) {
			free (*rcvdpub_key_bi_pp);
			*rcvdpub_key_bi_pp = NULL;
		}
	}

	/* Obtains header length and packet length 		*/
	fixed_hp = (struct fixed_hdr*) msg;
	pkt_len  = ntohs (fixed_hp->pkt_len);
	if (pkt_len != msg_len) {
		return (-1);
	}
	hdr_len = fixed_hp->hdr_len;
	
	/* Obtains CCN message size 		*/
	tlv_ptr = (struct tlv_hdr*) &msg[hdr_len];
	val_len = ntohs (tlv_ptr->length);
	if (hdr_len + CefC_S_TLF + val_len == pkt_len) {
		return (0);
	}
	index = hdr_len + CefC_S_TLF + val_len;
	
	/* Checks Validation Algorithm TLVs 	*/
	alg_offset = index;
	tlv_ptr = (struct tlv_hdr*) &msg[alg_offset];
	type = ntohs (tlv_ptr->type);
	if (type != CefC_T_VALIDATION_ALG) {
		return (-1);
	}
	
	val_len = ntohs (tlv_ptr->length);
	if (index + CefC_S_TLF + val_len >= pkt_len) {
		return (-1);
	}
	index += CefC_S_TLF;
	
	/* Checks Algorithm Type 		*/
	tlv_ptr = (struct tlv_hdr*) &msg[index];
	alg_type = ntohs (tlv_ptr->type);
	index += val_len;
	
	/* Checks Validation Payload TLVs 	*/
	pld_offset = index;
	tlv_ptr = (struct tlv_hdr*) &msg[pld_offset];
	type = ntohs (tlv_ptr->type);
	if (type != CefC_T_VALIDATION_PAYLOAD) {
		return (-1);
	}
	
	val_len = ntohs (tlv_ptr->length);
	if (index + CefC_S_TLF + val_len > pkt_len) {
		return (-1);
	}
	
	switch (alg_type) {
		case CefC_T_CRC32C: {
			res = cef_valid_crc_verify (
					msg, pkt_len, hdr_len, alg_offset, pld_offset);
			break;
		}
		case CefC_T_RSA_SHA256: {
			res = cef_valid_rsa_sha256_verify_forccninfo (
					msg, pkt_len, hdr_len, alg_offset, pld_offset, 
					rcvdpub_key_bi_len_p, rcvdpub_key_bi_pp);
			break;
		}
		default: {
			break;
		}
	}
	
	return (res);
}
uint16_t							/* new msg length									*/
cef_valid_remove_valdsegs_fr_msg_forccninfo (
	const unsigned char* msg, 
	int msg_len
) {
	struct fixed_hdr* 	fixed_hp;
	struct tlv_hdr* 	tlv_ptr;
	uint16_t 	hdr_len;
	uint16_t 	dsc_len;
	
	/* Obtains header length 		*/
	fixed_hp = (struct fixed_hdr*) msg;
	hdr_len = fixed_hp->hdr_len;
	/* Obtains T_DISCOVER message size 		*/
	tlv_ptr = (struct tlv_hdr*) &msg[hdr_len];
	dsc_len = ntohs (tlv_ptr->length);
	fixed_hp->pkt_len = htons (hdr_len + CefC_S_TLF + dsc_len);
	return (hdr_len + CefC_S_TLF + dsc_len);
}

#endif //CefC_Ccninfo
static int 							/* If the return value is 0 the code is equal, 		*/
									/* otherwise the code is different. 				*/
cef_valid_crc_verify (
	const unsigned char* msg, 
	uint16_t pkt_len, 				/* PacketLength 									*/
	uint16_t hdr_len, 				/* HeaderLength (offset of CCN Message)				*/
	uint16_t alg_offset, 			/* offset of T_VALIDATION_ALG 						*/
	uint16_t pld_offset		 		/* offset of T_VALIDATION_PAYLOAD 					*/
) {
	/*
		+---------------+---------------+---------------+---------------+
		|    Version    |     PT_XXX    |         PacketLength          |
		+---------------+---------------+---------------+---------------+
		|                     Reserved                  | HeaderLength  |
		+---------------+---------------+---------------+---------------+
		/                   Optional Hop-by-hop Header                  /
		+---------------+---------------+---------------+---------------+
		|                          CCN Message                          /
		+---------------+---------------+---------------+---------------+
		|      T_VALIDATION_ALG         |               4               |
		+---------------+---------------+---------------+---------------+
		|            T_CRC32C           |               0               |
		+---------------+---------------+---------------+---------------+
		|     T_VALIDATION_PAYLOAD      |               4               |
		+---------------+---------------+---------------+---------------+
		|                           CRC Code                            /
		+---------------+---------------+---------------+---------------+
	*/
	
	struct tlv_hdr* 	tlv_ptr;
	
	uint16_t 	index;
	uint16_t 	val_len;
	uint32_t	calc_crc, cmp_crc;
	
	/* Obtains CCN message size 		*/
	tlv_ptr = (struct tlv_hdr*) &msg[hdr_len];
	val_len = ntohs (tlv_ptr->length);
	if (hdr_len + CefC_S_TLF + val_len >= pkt_len) {
		return (-1);
	}
	
	/* Checks Validation Algorithm TLVs 	*/
	tlv_ptr = (struct tlv_hdr*) &msg[alg_offset];
	val_len = ntohs (tlv_ptr->length);
	if (val_len != 4) {
		return (-1);
	}
	
	/* Checks Validation Payload TLV 	*/
	tlv_ptr = (struct tlv_hdr*) &msg[pld_offset];
	val_len = ntohs (tlv_ptr->length);
	if (val_len != 4) {
		return (-1);
	}
	index = pld_offset + CefC_S_TLF;
	
	/*  Verifies the CRC Code		*/
	memcpy (&cmp_crc, &msg[index], 4);
	cmp_crc = ntohl (cmp_crc);
	calc_crc = cef_valid_crc32_calc (&msg[hdr_len], pkt_len - (hdr_len + 8));
	
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, 
		"CRC [pld=%u] [calc=%u] ... %s\n"
		, cmp_crc, calc_crc, (int)(cmp_crc - calc_crc) ? "NG" : "OK");
#endif // CefC_Debug
	
	return ((int)(cmp_crc - calc_crc));
}

static int 							/* If the return value is 0 the code is equal, 		*/
									/* otherwise the code is different. 				*/
cef_valid_rsa_sha256_verify (
	const unsigned char* msg, 
	uint16_t pkt_len, 				/* PacketLength 									*/
	uint16_t hdr_len, 				/* HeaderLength (offset of CCN Message)				*/
	uint16_t alg_offset, 			/* offset of T_VALIDATION_ALG 						*/
	uint16_t pld_offset		 		/* offset of T_VALIDATION_PAYLOAD 					*/
) {
	struct tlv_hdr* 	tlv_ptr;
	int res;
	uint16_t 	index;
	uint16_t 	type;
	uint16_t 	val_len;
	
	/* Obtains CCN message size 		*/
	tlv_ptr = (struct tlv_hdr*) &msg[hdr_len];
	val_len = ntohs (tlv_ptr->length);
	if (hdr_len + CefC_S_TLF + val_len >= pkt_len) {
		return (-1);
	}
	
	/* Checks Validation Algorithm TLVs 	*/
	index = alg_offset + CefC_S_TLF + CefC_S_TLF;
	tlv_ptr = (struct tlv_hdr*) &msg[index];
	type = ntohs (tlv_ptr->type);
	
	if (type == CefC_T_CERT_FORWARDER) {
		/* HOP-BY-HOP */
		res = cef_valid_rsa_sha256_hby_verify (
					msg, pkt_len, hdr_len, alg_offset, pld_offset);
	} else {
		res = cef_valid_rsa_sha256_std_verify (
					msg, pkt_len, hdr_len, alg_offset, pld_offset);
	}
	
	return (res);
}

static int 							/* If the return value is 0 the code is equal, 		*/
									/* otherwise the code is different. 				*/
cef_valid_rsa_sha256_std_verify (
	const unsigned char* msg, 
	uint16_t pkt_len, 				/* PacketLength 									*/
	uint16_t hdr_len, 				/* HeaderLength (offset of CCN Message)				*/
	uint16_t alg_offset, 			/* offset of T_VALIDATION_ALG 						*/
	uint16_t pld_offset		 		/* offset of T_VALIDATION_PAYLOAD 					*/
) {
	struct tlv_hdr* 	tlv_ptr;
	uint16_t 			index;
	uint16_t 			length;
	unsigned char 		hash[SHA256_DIGEST_LENGTH];
	int 				res;
	unsigned char* 		pub_key_bi;
	int 				pub_key_bi_len;
	RSA*  				pub_key;
	
	/* Obtains the Name 		*/
	index = hdr_len + CefC_S_TLF;
	tlv_ptr = (struct tlv_hdr*) &msg[index];
	length = ntohs (tlv_ptr->length);
	index += CefC_S_TLF;
	
	/* Obtains the Public Key		 		*/
	{
		uint16_t 		pkey_offset;
		uint16_t 		type;
		unsigned char* 	ptr_for_free;

		pkey_offset = alg_offset;
		pkey_offset += CefC_S_TLF; 			/* Move offset by TL size of T_VALIDATION_ALG	*/
		pkey_offset += CefC_S_TLF; 			/* Move offset by TL size of T_RSA-SHA256		*/
		tlv_ptr = (struct tlv_hdr*) 		/* Move offset by TLV size of T_KEYID			*/
					&msg[pkey_offset];
		length = ntohs (tlv_ptr->length);
		pkey_offset += (CefC_S_TLF + length);
		/* Obtain */
		tlv_ptr = (struct tlv_hdr*) &msg[pkey_offset];
		type = ntohs (tlv_ptr->type);
		length = ntohs (tlv_ptr->length);
		if (type != CefC_T_PUBLICKEY) {
			return (1);
		}
		length = ntohs (tlv_ptr->length);
		ptr_for_free = pub_key_bi = (unsigned char*)calloc(length, 1);
		pub_key_bi_len = length;
		memcpy (pub_key_bi, &msg[pkey_offset+CefC_S_TLF], pub_key_bi_len);

		pub_key = d2i_RSA_PUBKEY(NULL, (const unsigned char**)&pub_key_bi, pub_key_bi_len);
		free(ptr_for_free);
		if (pub_key == NULL) {
			return (1);
		}
	}
	/* Obtains the Validation Payload 		*/
	tlv_ptr = (struct tlv_hdr*) &msg[pld_offset];
	length = ntohs (tlv_ptr->length);
	index = pld_offset + CefC_S_TLF;
	
	/* Verification the sign 				*/
	SHA256 (&msg[hdr_len], pld_offset - hdr_len, hash);
	
	res = RSA_verify (
		NID_sha256, hash, SHA256_DIGEST_LENGTH, &msg[index], length, pub_key);
	RSA_free (pub_key);
	
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, 
		"[SHA256] validation is %s\n", (res == 1) ? "OK" : "NG");
#endif // CefC_Debug
	
	return ((res == 1) ? 0 : 1);
}
static int 							/* If the return value is 0 the code is equal, 		*/
									/* otherwise the code is different. 				*/
cef_valid_rsa_sha256_hby_verify (
	const unsigned char* msg, 
	uint16_t pkt_len, 				/* PacketLength 									*/
	uint16_t hdr_len, 				/* HeaderLength (offset of CCN Message)				*/
	uint16_t alg_offset, 			/* offset of T_VALIDATION_ALG 						*/
	uint16_t pld_offset		 		/* offset of T_VALIDATION_PAYLOAD 					*/
) {
	/* HOP-BY-HOP */
	fprintf (stderr, "cef_valid_rsa_sha256_hby_verify ()\n");
	return (0);
}

static CefT_Keys* 
cef_valid_key_entry_search (
	const unsigned char* name, 
	uint16_t name_len	
) {
	CefT_Keys* key_entry;
	unsigned char* msp;
	unsigned char* mep;
	uint16_t len = name_len;
	uint16_t length;
	
	while (len > 0) {
		key_entry = (CefT_Keys*) cef_hash_tbl_item_get (key_table, name, len);
		
		if (key_entry != NULL) {
			return (key_entry);
		}
		
		msp = (unsigned char*) name;
		mep = (unsigned char*)(name + len - 1);
		while (msp < mep) {
			memcpy (&length, &msp[CefC_S_Length], CefC_S_Length);
			length = ntohs (length);
			
			if (msp + CefC_S_Type + CefC_S_Length + length < mep) {
				msp += CefC_S_Type + CefC_S_Length + length;
			} else {
				break;
			}
		}
		len = msp - name;
	}
	return (default_key_entry);
}
#ifdef CefC_Ccninfo
static int
cef_valid_create_keyinfo_forccninfo (
) {
	FILE* 			key_fp;
	key_fp = fopen (ccninfo_sha256_pubkey_path, "r");
	if (key_fp == NULL) {
		cef_log_write (CefC_Log_Error, 
			"Failed to open public key (%s)\n", ccninfo_sha256_pubkey_path);
		return (-1);
	}
	
	ccninfo_sha256_pub_key = PEM_read_RSA_PUBKEY (key_fp, NULL, NULL, NULL);
	if (ccninfo_sha256_pub_key == NULL) {
		cef_log_write (CefC_Log_Error, 
			"Invalid public key (%s)\n", ccninfo_sha256_pubkey_path);
		fclose (key_fp);
		return (-1);
	}
	
	ccninfo_sha256_pub_key_bi_len 
		= i2d_RSA_PUBKEY (ccninfo_sha256_pub_key, &ccninfo_sha256_pub_key_bi);
	if (ccninfo_sha256_pub_key_bi_len < 1) {
		cef_log_write (CefC_Log_Error, 
			"Invalid public key (%s)\n", ccninfo_sha256_pubkey_path);
		fclose (key_fp);
		return (-1);
	}
	fclose (key_fp);
	key_fp = fopen (ccninfo_sha256_prvkey_path, "r");
	if (key_fp == NULL) {
		cef_log_write (CefC_Log_Error, 
			"Failed to open (%s)\n", ccninfo_sha256_prvkey_path);
		return (-1);
	}
	
	ccninfo_sha256_prv_key = PEM_read_RSAPrivateKey (key_fp, NULL, NULL, NULL);
	if (ccninfo_sha256_prv_key == NULL) {
		fclose (key_fp);
		cef_log_write (CefC_Log_Error, 
			"Invalid private key (%s)\n", ccninfo_sha256_prvkey_path);
		return (-1);
	}
	fclose (key_fp);
	return (0);
}
static int 							/* If the return value is 0 the code is equal, 		*/
									/* otherwise the code is different. 				*/
cef_valid_rsa_sha256_verify_forccninfo (
	const unsigned char* msg, 
	uint16_t pkt_len, 				/* PacketLength 									*/
	uint16_t hdr_len, 				/* HeaderLength (offset of CCN Message)				*/
	uint16_t alg_offset, 			/* offset of T_VALIDATION_ALG 						*/
	uint16_t pld_offset,	 		/* offset of T_VALIDATION_PAYLOAD 					*/
	int* 				rcvdpub_key_bi_len_p,
	unsigned char** 	rcvdpub_key_bi_pp
) {
	struct tlv_hdr* 	tlv_ptr;
	int res;
	uint16_t 	index;
	uint16_t 	type;
	uint16_t 	val_len;
	
	/* Obtains CCN message size 		*/
	tlv_ptr = (struct tlv_hdr*) &msg[hdr_len];
	val_len = ntohs (tlv_ptr->length);
	if (hdr_len + CefC_S_TLF + val_len >= pkt_len) {
		return (-1);
	}
	
	/* Checks Validation Algorithm TLVs 	*/
	index = alg_offset + CefC_S_TLF + CefC_S_TLF;
	tlv_ptr = (struct tlv_hdr*) &msg[index];
	type = ntohs (tlv_ptr->type);
	
	if (type == CefC_T_CERT_FORWARDER) {
		/* HOP-BY-HOP */
		return (-1);
	} else {
		res = cef_valid_rsa_sha256_std_verify_forccninfo (
					msg, pkt_len, hdr_len, alg_offset, pld_offset,
					rcvdpub_key_bi_len_p, rcvdpub_key_bi_pp);
	}
	
	return (res);
}

static int 							/* If the return value is 0 the code is equal, 		*/
									/* otherwise the code is different. 				*/
cef_valid_rsa_sha256_std_verify_forccninfo (
	const unsigned char* msg, 
	uint16_t pkt_len, 				/* PacketLength 									*/
	uint16_t hdr_len, 				/* HeaderLength (offset of CCN Message)				*/
	uint16_t alg_offset, 			/* offset of T_VALIDATION_ALG 						*/
	uint16_t pld_offset,	 		/* offset of T_VALIDATION_PAYLOAD 					*/
	int* 				rcvdpub_key_bi_len_p,
	unsigned char** 	rcvdpub_key_bi_pp
) {
	struct tlv_hdr* 	tlv_ptr;
	uint16_t 			index;
	uint16_t 			length;
	unsigned char 		hash[SHA256_DIGEST_LENGTH];
	int 				res;
	int 				rtc;
	unsigned char* 		pub_key_bi;
	int 				pub_key_bi_len;
	RSA*  				pub_key;
	
	/* Obtains the Name 		*/
	index = hdr_len + CefC_S_TLF;
	tlv_ptr = (struct tlv_hdr*) &msg[index];
	length = ntohs (tlv_ptr->length);
	index += CefC_S_TLF;
	
	/* Obtains the Public Key		 		*/
	{
		uint16_t 		pkey_offset;
		uint16_t 		type;
		unsigned char* 	ptr_for_free;

		pkey_offset = alg_offset;
		pkey_offset += CefC_S_TLF; 			/* Move offset by TL size of T_VALIDATION_ALG	*/
		pkey_offset += CefC_S_TLF; 			/* Move offset by TL size of T_RSA-SHA256		*/
		tlv_ptr = (struct tlv_hdr*) 		/* Move offset by TLV size of T_KEYID			*/
					&msg[pkey_offset];
		length = ntohs (tlv_ptr->length);
		pkey_offset += (CefC_S_TLF + length);
		/* Obtain */
		tlv_ptr = (struct tlv_hdr*) &msg[pkey_offset];
		type = ntohs (tlv_ptr->type);
		length = ntohs (tlv_ptr->length);
		if (type != CefC_T_PUBLICKEY) {
			return (1);
		}
		length = ntohs (tlv_ptr->length);
		ptr_for_free = pub_key_bi = (unsigned char*)calloc(length, 1);
		pub_key_bi_len = length;
		memcpy (pub_key_bi, &msg[pkey_offset+CefC_S_TLF], pub_key_bi_len);
		if (rcvdpub_key_bi_len_p != NULL && rcvdpub_key_bi_pp != NULL) {
			/* Set information used in authentication & authorization */
			*rcvdpub_key_bi_len_p = pub_key_bi_len;
			*rcvdpub_key_bi_pp = (unsigned char*)calloc(pub_key_bi_len, 1);
			memcpy (*rcvdpub_key_bi_pp, pub_key_bi, pub_key_bi_len);
		}
		pub_key = d2i_RSA_PUBKEY(NULL, (const unsigned char**)&pub_key_bi, pub_key_bi_len);
		free(ptr_for_free);
		if (pub_key == NULL) {
			return (1);
		}
	}
	/* Obtains the Validation Payload 		*/
	tlv_ptr = (struct tlv_hdr*) &msg[pld_offset];
	length = ntohs (tlv_ptr->length);
	index = pld_offset + CefC_S_TLF;
	
	/* Verification the sign 				*/
	SHA256 (&msg[hdr_len], pld_offset - hdr_len, hash);
	
	res = RSA_verify (
		NID_sha256, hash, SHA256_DIGEST_LENGTH, &msg[index], length, pub_key);
	RSA_free (pub_key);
	
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, 
		"[SHA256] validation is %s\n", (res == 1) ? "OK" : "NG");
#endif // CefC_Debug

	rtc = ((res == 1) ? 0 : 1);
	if (rtc == 1 && rcvdpub_key_bi_len_p != NULL && rcvdpub_key_bi_pp != NULL) {
		/* Clear information used in authentication & authorization */
		*rcvdpub_key_bi_len_p = 0;
		if (*rcvdpub_key_bi_pp != NULL) {
			free (*rcvdpub_key_bi_pp);
			*rcvdpub_key_bi_pp = NULL;
		}
	}
	return (rtc);
}
#endif //CefC_Ccninfo
static int
cef_valid_read_conf (
	const char* conf_path
) {
#ifndef CefC_Android
	char*	wp;
	FILE* 	fp;
	FILE* 	key_fp;
	char 	file_path[PATH_MAX];
	char	buff[1024];
	char 	pname[1024];
	char 	pprv_key[1024];
	char 	ppub_key[1024];
	int 	res = -1;
	unsigned char name[CefC_Max_Length];
	CefT_Keys* 	key_entry;
	
	
	key_table = cef_hash_tbl_create (128);
	
	
	if ((conf_path != NULL) && (conf_path[0] != 0x00)) {
		sprintf (file_path, "%s/cefnetd.key", conf_path);
	} else {
		wp = getenv (CefC_CEFORE_DIR);
		if (wp != NULL && wp[0] != 0) {
			sprintf (file_path, "%s/cefore/cefnetd.key", wp);
		} else {
			sprintf (file_path, "%s/cefnetd.key", CefC_CEFORE_DIR_DEF);
		}
	}
	
	fp = fopen (file_path, "r");
	if (fp == NULL) {
		cef_log_write (CefC_Log_Error, 
				"Failed to open %s\n", file_path);
		return (-1);
	}
	
	/* Reads and records written values in the cefnetd's config file. */
	file_path[0] = 0x00;
	while (fgets (buff, 1023, fp) != NULL) {
		buff[1023] = 0;
		
		if (buff[0] == 0x23/* '#' */) {
			continue;
		}
		res = cef_valid_conf_value_get (buff, pname, pprv_key, ppub_key);
		if (res < 0) {
			cef_log_write (CefC_Log_Error, 
				"Invalid line (%s) is specified in cefnetd.key\n", pname);
			return (-1);
		}
		
		/* Creates the name from the URI 		*/
		res = cef_frame_conversion_uri_to_name (pname, name);
		
		if (res < 1) {
			cef_log_write (CefC_Log_Error, 
				"Invalid name (%s) is specified in cefnetd.key\n", pname);
			return (-1);
		}
		
		key_entry = (CefT_Keys*) cef_hash_tbl_item_get (key_table, name, res);
		
		if (key_entry) {
			continue;
		}
		key_entry = (CefT_Keys*) malloc (sizeof (CefT_Keys));
		memset (key_entry, 0, sizeof (CefT_Keys));
		
		memcpy (key_entry->name, name, res);
		key_entry->name_len = res;
		strcpy (key_entry->prv_key_path, pprv_key);
		strcpy (key_entry->pub_key_path, ppub_key);
		
		/* Prepares the public key 		*/
		key_fp = fopen (key_entry->pub_key_path, "r");
		if (key_fp == NULL) {
			cef_log_write (CefC_Log_Error, 
				"Invalid public key (%s) is specified in cefnetd.key\n", 
				key_entry->pub_key_path);
			free (key_entry);
			return (-1);
		}
		
		key_entry->pub_key = PEM_read_RSA_PUBKEY (key_fp, NULL, NULL, NULL);
		if (key_entry->pub_key == NULL) {
			cef_log_write (CefC_Log_Error, 
				"Invalid public key (%s) is specified in cefnetd.key\n", 
				key_entry->pub_key_path);
			fclose (key_fp);
			cef_valid_key_entry_free (key_entry);
			return (-1);
		}
		
		key_entry->pub_key_bi_len 
			= i2d_RSA_PUBKEY (key_entry->pub_key, &key_entry->pub_key_bi);
		if (key_entry->pub_key_bi_len < 1) {
			cef_log_write (CefC_Log_Error, 
				"Invalid public key (%s) is specified in cefnetd.key\n", 
				key_entry->pub_key_path);
			fclose (key_fp);
			cef_valid_key_entry_free (key_entry);
			return (-1);
		}
		fclose (key_fp);
		
		/* Prepares the private key 		*/
		key_fp = fopen (key_entry->prv_key_path, "r");
		if (key_fp == NULL) {
			cef_log_write (CefC_Log_Error, 
				"Invalid private key (%s) is specified in cefnetd.key\n", 
				key_entry->prv_key_path);
			cef_valid_key_entry_free (key_entry);
			continue;
		}
		
		key_entry->prv_key = PEM_read_RSAPrivateKey (key_fp, NULL, NULL, NULL);
		if (key_entry->prv_key == NULL) {
			fclose (key_fp);
			cef_valid_key_entry_free (key_entry);
			return (-1);
		}
		fclose (key_fp);
		
		if (key_entry->name_len != 4) {
			cef_hash_tbl_item_set (
				key_table, key_entry->name, key_entry->name_len, key_entry);
		} else {
			default_key_entry = key_entry;
		}
	}
	fclose (fp);
	
	return (1);
#else // CefC_Android
	// TODO
	return (0);
#endif // CefC_Android
}

static void 
cef_valid_key_entry_free (
	CefT_Keys* key_entry
) {
	
	if (key_entry->prv_key) {
		RSA_free (key_entry->prv_key);
	}
	if (key_entry->pub_key) {
		RSA_free (key_entry->pub_key);
	}
	if (key_entry->pub_key_bi_len > 0) {
		free (key_entry->pub_key_bi);
	}
	free (key_entry);
}
static int 
cef_valid_sha256_keypass_ccninfoRT(
	const char* conf_path
) {
	char*	wp;
	FILE* 	fp;
	char 	file_path[PATH_MAX];
	char 	cef_conf_dir[PATH_MAX];
	char	buff[1024];
	char 	ws[1024];
	char 	pname[1024];
	int 	res;
	char	key_prfx[PATH_MAX];
	
	strcpy(key_prfx, "ccninfo_rt");
	
	if (conf_path[0] != 0x00) {
		sprintf (file_path, "%s/cefnetd.conf", conf_path);
		strcpy (cef_conf_dir, conf_path);
	} else {
		wp = getenv (CefC_CEFORE_DIR);
		if (wp != NULL && wp[0] != 0) {
			sprintf (file_path, "%s/cefore/cefnetd.conf", wp);
			sprintf (cef_conf_dir, "%s/cefore", wp);
		} else {
			sprintf (file_path, "%s/cefnetd.conf", CefC_CEFORE_DIR_DEF);
			strcpy (cef_conf_dir, CefC_CEFORE_DIR_DEF);
		}
	}
	
	fp = fopen (file_path, "r");
	if (fp == NULL) {
		cef_log_write (CefC_Log_Error, "[client] Failed to open %s\n", file_path);
		return (-1);
	}
	
	/* Reads and records written values in the cefnetd's config file. */
	while (fgets (buff, 1023, fp) != NULL) {
		buff[1023] = 0;
		
		if (buff[0] == 0x23/* '#' */) {
			continue;
		}
		
		res = cef_valid_trim_line_string (buff, pname, ws);
		if (res < 0) {
			continue;
		}
		if (strcmp (pname, "CCNINFO_SHA256_KEY_PRFX") == 0) {
			strcpy(key_prfx, ws);
		}
	}
	fclose (fp);
	
	sprintf(ccninfo_sha256_prvkey_path, "%s/.ccninfo/%s-private-key"
			, cef_conf_dir, key_prfx);
	sprintf(ccninfo_sha256_pubkey_path, "%s/.ccninfo/%s-public-key"
			, cef_conf_dir, key_prfx);
#ifdef DEB_CCNINFO
{
	fprintf (stderr, "DEB_CCNINFO: [%s] ccninfo_sha256_prvkey_path=%s\n"
				   , __FUNCTION__, ccninfo_sha256_prvkey_path);
	fprintf (stderr, "DEB_CCNINFO: [%s] ccninfo_sha256_pubkey_path=%s\n"
				   , __FUNCTION__, ccninfo_sha256_pubkey_path);
}
#endif //DEB_CCNINFO
	
	return (0);
}

static void 
cef_valid_crc_init (
	void
) {
	uint32_t i, c;
	int j;
	
	for (i = 0 ; i < 256 ; i++) {
		c = i;
		for (j = 0 ; j < 8 ; j++) {
			c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
		}
		crc_table[i] = c;
	}
}

static int
cef_valid_conf_value_get (
	const char* p, 
	char* name,
	char* prv_key,
	char* pub_key
) {
	int parame = 0;
	int delm_f = 0;

	while (*p) {
		if ((*p == 0x0D) || (*p == 0x0A)) {
			return (-1);
		}

		if ((*p == 0x20) || (*p == 0x09)) {
			p++;
			continue;
		}
		break;
	}

	while (*p) {
		if ((*p == 0x0D) || (*p == 0x0A)) {
			break;
		}

		if ((*p == 0x20) || (*p == 0x09)) {
			delm_f = 1;
			p++;
			continue;
		}
		if (delm_f) {
			parame++;
		}

		switch (parame) {
			case 0: {	/* Name */
				*name = *p;
				name++;
				break;
			}
			case 1: {	 /* Private key */
				*prv_key = *p;
				prv_key++;
				break;
			}
			case 2: {	 /* Public Key */
				*pub_key = *p;
				pub_key++;
				break;
			}
			default: {
				/* NOP */;
				break;
			}
		}
		p++;
		delm_f = 0;
	}
	*name 	 = 0x00;
	*pub_key = 0x00;
	*prv_key = 0x00;
	
	if (parame >= 3) {
		delm_f = -1;
	}
	
	return (delm_f);
}
/*--------------------------------------------------------------------------------------
	Trims the string buffer read from the config file
----------------------------------------------------------------------------------------*/
static int
cef_valid_trim_line_string (
	const char* p1, 							/* target string for trimming 			*/
	char* p2,									/* name string after trimming			*/
	char* p3									/* value string after trimming			*/
) {
	char ws[1024];
	char* wp = ws;
	char* rp = p2;
	int equal_f = -1;

	while (*p1) {
		if ((*p1 == 0x0D) || (*p1 == 0x0A)) {
			break;
		}

		if ((*p1 == 0x20) || (*p1 == 0x09)) {
			p1++;
			continue;
		} else {
			*wp = *p1;
		}

		p1++;
		wp++;
	}
	*wp = 0x00;
	wp = ws;

	while (*wp) {
		if (*wp == 0x3d /* '=' */) {
			if (equal_f > 0) {
				return (-1);
			}
			equal_f = 1;
			*rp = 0x00;
			rp = p3;
		} else {
			*rp = *wp;
			rp++;
		}
		wp++;
	}
	*rp = 0x00;

	return (equal_f);
}



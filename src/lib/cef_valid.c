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
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/err.h>

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

	EVP_PKEY*		prv_key;
	EVP_PKEY*		pub_key;

} CefT_Keys;

typedef struct {

	unsigned char keyid[CefC_S_KeyId];
	uint16_t hash_type;
	uint16_t keyid_len;
	unsigned char* pub_key_bi;
	uint16_t pub_key_bi_len;
	EVP_PKEY* pub_key;
	char pubkey_path[PATH_MAX];

} CefT_valid_Key;

/****************************************************************************************
 State Variables
 ****************************************************************************************/

static uint32_t 			crc_table[256] =  /* this lookup table made with normal form polynomial 0x1EDC6F41. */
                                {
                                    0x00000000, 0x1edc6f41, 0x3db8de82, 0x2364b1c3, 0x7b71bd04, 0x65add245, 0x46c96386, 0x58150cc7,
                                    0xf6e37a08, 0xe83f1549, 0xcb5ba48a, 0xd587cbcb, 0x8d92c70c, 0x934ea84d, 0xb02a198e, 0xaef676cf,
                                    0xf31a9b51, 0xedc6f410, 0xcea245d3, 0xd07e2a92, 0x886b2655, 0x96b74914, 0xb5d3f8d7, 0xab0f9796,
                                    0x05f9e159, 0x1b258e18, 0x38413fdb, 0x269d509a, 0x7e885c5d, 0x6054331c, 0x433082df, 0x5deced9e,
                                    0xf8e959e3, 0xe63536a2, 0xc5518761, 0xdb8de820, 0x8398e4e7, 0x9d448ba6, 0xbe203a65, 0xa0fc5524,
                                    0x0e0a23eb, 0x10d64caa, 0x33b2fd69, 0x2d6e9228, 0x757b9eef, 0x6ba7f1ae, 0x48c3406d, 0x561f2f2c,
                                    0x0bf3c2b2, 0x152fadf3, 0x364b1c30, 0x28977371, 0x70827fb6, 0x6e5e10f7, 0x4d3aa134, 0x53e6ce75,
                                    0xfd10b8ba, 0xe3ccd7fb, 0xc0a86638, 0xde740979, 0x866105be, 0x98bd6aff, 0xbbd9db3c, 0xa505b47d,
                                    0xef0edc87, 0xf1d2b3c6, 0xd2b60205, 0xcc6a6d44, 0x947f6183, 0x8aa30ec2, 0xa9c7bf01, 0xb71bd040,
                                    0x19eda68f, 0x0731c9ce, 0x2455780d, 0x3a89174c, 0x629c1b8b, 0x7c4074ca, 0x5f24c509, 0x41f8aa48,
                                    0x1c1447d6, 0x02c82897, 0x21ac9954, 0x3f70f615, 0x6765fad2, 0x79b99593, 0x5add2450, 0x44014b11,
                                    0xeaf73dde, 0xf42b529f, 0xd74fe35c, 0xc9938c1d, 0x918680da, 0x8f5aef9b, 0xac3e5e58, 0xb2e23119,
                                    0x17e78564, 0x093bea25, 0x2a5f5be6, 0x348334a7, 0x6c963860, 0x724a5721, 0x512ee6e2, 0x4ff289a3,
                                    0xe104ff6c, 0xffd8902d, 0xdcbc21ee, 0xc2604eaf, 0x9a754268, 0x84a92d29, 0xa7cd9cea, 0xb911f3ab,
                                    0xe4fd1e35, 0xfa217174, 0xd945c0b7, 0xc799aff6, 0x9f8ca331, 0x8150cc70, 0xa2347db3, 0xbce812f2,
                                    0x121e643d, 0x0cc20b7c, 0x2fa6babf, 0x317ad5fe, 0x696fd939, 0x77b3b678, 0x54d707bb, 0x4a0b68fa,
                                    0xc0c1d64f, 0xde1db90e, 0xfd7908cd, 0xe3a5678c, 0xbbb06b4b, 0xa56c040a, 0x8608b5c9, 0x98d4da88,
                                    0x3622ac47, 0x28fec306, 0x0b9a72c5, 0x15461d84, 0x4d531143, 0x538f7e02, 0x70ebcfc1, 0x6e37a080,
                                    0x33db4d1e, 0x2d07225f, 0x0e63939c, 0x10bffcdd, 0x48aaf01a, 0x56769f5b, 0x75122e98, 0x6bce41d9,
                                    0xc5383716, 0xdbe45857, 0xf880e994, 0xe65c86d5, 0xbe498a12, 0xa095e553, 0x83f15490, 0x9d2d3bd1,
                                    0x38288fac, 0x26f4e0ed, 0x0590512e, 0x1b4c3e6f, 0x435932a8, 0x5d855de9, 0x7ee1ec2a, 0x603d836b,
                                    0xcecbf5a4, 0xd0179ae5, 0xf3732b26, 0xedaf4467, 0xb5ba48a0, 0xab6627e1, 0x88029622, 0x96def963,
                                    0xcb3214fd, 0xd5ee7bbc, 0xf68aca7f, 0xe856a53e, 0xb043a9f9, 0xae9fc6b8, 0x8dfb777b, 0x9327183a,
                                    0x3dd16ef5, 0x230d01b4, 0x0069b077, 0x1eb5df36, 0x46a0d3f1, 0x587cbcb0, 0x7b180d73, 0x65c46232,
                                    0x2fcf0ac8, 0x31136589, 0x1277d44a, 0x0cabbb0b, 0x54beb7cc, 0x4a62d88d, 0x6906694e, 0x77da060f,
                                    0xd92c70c0, 0xc7f01f81, 0xe494ae42, 0xfa48c103, 0xa25dcdc4, 0xbc81a285, 0x9fe51346, 0x81397c07,
                                    0xdcd59199, 0xc209fed8, 0xe16d4f1b, 0xffb1205a, 0xa7a42c9d, 0xb97843dc, 0x9a1cf21f, 0x84c09d5e,
                                    0x2a36eb91, 0x34ea84d0, 0x178e3513, 0x09525a52, 0x51475695, 0x4f9b39d4, 0x6cff8817, 0x7223e756,
                                    0xd726532b, 0xc9fa3c6a, 0xea9e8da9, 0xf442e2e8, 0xac57ee2f, 0xb28b816e, 0x91ef30ad, 0x8f335fec,
                                    0x21c52923, 0x3f194662, 0x1c7df7a1, 0x02a198e0, 0x5ab49427, 0x4468fb66, 0x670c4aa5, 0x79d025e4,
                                    0x243cc87a, 0x3ae0a73b, 0x198416f8, 0x075879b9, 0x5f4d757e, 0x41911a3f, 0x62f5abfc, 0x7c29c4bd,
                                    0xd2dfb272, 0xcc03dd33, 0xef676cf0, 0xf1bb03b1, 0xa9ae0f76, 0xb7726037, 0x9416d1f4, 0x8acabeb5
                                };
static CefT_Hash_Handle		key_table;
static CefT_Hash_Handle		keyid_table;
static CefT_Keys* 			default_key_entry = NULL;
static char					ccninfo_prvkey_path[PATH_MAX*2];
static char					ccninfo_pubkey_path[PATH_MAX*2];
unsigned char* 				ccninfo_pub_key_bi;
size_t 						ccninfo_pub_key_bi_len;
EVP_PKEY*					ccninfo_pub_key;
EVP_PKEY*					ccninfo_prv_key;
int							validation_mode = CefC_ValidMode_InBand;

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

static void
cef_valid_crc32c_init (
	void
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

static int 							/* If the return value is 0 the code is equal, 		*/
									/* otherwise the code is different. 				*/
cef_valid_signature_verify_forccninfo (
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
cef_valid_signature_std_verify_forccninfo (
	const unsigned char* msg,
	uint16_t pkt_len, 				/* PacketLength 									*/
	uint16_t hdr_len, 				/* HeaderLength (offset of CCN Message)				*/
	uint16_t alg_offset, 			/* offset of T_VALIDATION_ALG 						*/
	uint16_t pld_offset,	 		/* offset of T_VALIDATION_PAYLOAD 					*/
	int* 				rcvdpub_key_bi_len_p,
	unsigned char** 	rcvdpub_key_bi_pp
);
static int
cef_valid_keypath_ccninfoRT(
	const char* conf_path
);

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
cef_valid_signature_verify (
	const unsigned char* msg,
	uint16_t pkt_len, 				/* PacketLength 									*/
	uint16_t hdr_len, 				/* HeaderLength (offset of CCN Message)				*/
	uint16_t alg_offset, 			/* offset of T_VALIDATION_ALG 						*/
	uint16_t pld_offset,	 		/* offset of T_VALIDATION_PAYLOAD 					*/
	int* cache_f					/* Flag indicating whether caching is allowed		*/
);
static int 							/* If the return value is 0 the code is equal, 		*/
									/* otherwise the code is different. 				*/
cef_valid_signature_std_verify (
	const unsigned char* msg,
	uint16_t pkt_len, 				/* PacketLength 									*/
	uint16_t hdr_len, 				/* HeaderLength (offset of CCN Message)				*/
	uint16_t alg_offset, 			/* offset of T_VALIDATION_ALG 						*/
	uint16_t pld_offset,	 		/* offset of T_VALIDATION_PAYLOAD 					*/
	int* cache_f					/* Flag indicating whether caching is allowed		*/
);
static int 							/* If the return value is 0 the code is equal, 		*/
									/* otherwise the code is different. 				*/
cef_valid_signature_hby_verify (
	const unsigned char* msg,
	uint16_t pkt_len, 				/* PacketLength 									*/
	uint16_t hdr_len, 				/* HeaderLength (offset of CCN Message)				*/
	uint16_t alg_offset, 			/* offset of T_VALIDATION_ALG 						*/
	uint16_t pld_offset,	 		/* offset of T_VALIDATION_PAYLOAD 					*/
	int* cache_f					/* Flag indicating whether caching is allowed		*/
);

static void
cef_valid_encoder_from_data (
	EVP_PKEY*		pkey,
	int				selection,
	const char*		output_type,
	const char*		structure,
	unsigned char**	pdata,
	size_t*			pdata_len
);

static size_t
cef_valid_i2d_pubkey (
	EVP_PKEY*		pkey,
	unsigned char**	pdata
);

static EVP_PKEY *
cef_valid_decoder_from (
	const char*				format,
	const char*             structure,
	const char*				keytype,
	int						selection,
	FILE*					fp,
	const unsigned char**	pdata,
	size_t*					pdata_len
);

static EVP_PKEY *
cef_valid_pem_read_pub_key (
	FILE*	fp
);

static EVP_PKEY *
cef_valid_pem_read_private_key (
	FILE*	fp
);

static EVP_PKEY *
cef_valid_d2i_pubkey (
	const unsigned char**	pp,
	size_t					length
);

static int
cef_valid_signature_sign_core (
	int						type,
	const unsigned char*	msg,
	unsigned int			msg_len,
	unsigned char*			sigret,
	unsigned int*			siglen,
	EVP_PKEY*				pkey
);

static int
cef_valid_signature_verify_core (
	int						type,
	const unsigned char*	msg,
	unsigned int			msg_len,
    const unsigned char*	sigbuf,
	unsigned int			siglen,
	EVP_PKEY*				pkey
);

static int
cef_valid_type_get_from_key (
	EVP_PKEY* key
);

static int 							/* If the return value is 1, the verification succeeded,	*/
									/* otherwise, the verification failed.						*/
cef_valid_is_key_pair (
	EVP_PKEY *prv_key,
	EVP_PKEY *pub_key
);

static int
cef_valid_hexstr_to_bin (
	const char* hexstr,
	unsigned char* bin,
	int bin_len
);

static CefT_valid_Key*
cef_valid_validkey_get (
	const unsigned char* keyid,
	uint16_t keyid_len,
	uint16_t hash_type
);

/****************************************************************************************
 ****************************************************************************************/

int
cef_valid_init (
	const char* conf_path
) {
	int res = 0;

	cef_valid_crc32c_init ();
	res = cef_valid_read_conf (conf_path);

	if (res != 1) {
		cef_log_write (CefC_Log_Warn,
			"Failed to load configuration file.\n");
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest,
			"Failed to load configuration file.\n");
#endif // CefC_Debug
		goto err;
	}

	res = cef_valid_is_key_pair (default_key_entry->prv_key, default_key_entry->pub_key);
	if (res != 1) {
		cef_log_write (CefC_Log_Warn,
			"The public key and private key do not match.\n");
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest,
			"The public key and private key do not match.\n");
#endif // CefC_Debug
		goto err;
	}

err:
	return (res);
}

int
cef_valid_init_ccninfoUSER (
	const char* conf_path,
	const char* valid_type_str,
	uint16_t* valid_type
) {
	int res = 0;

	cef_valid_crc32c_init ();
	if (strcmp (valid_type_str, CefC_ValidTypeStr_RSA256) == 0) {
		sprintf(ccninfo_prvkey_path, "%s/.ccninfo/ccninfo_user-private-key"
				, getenv("HOME"));
		sprintf(ccninfo_pubkey_path, "%s/.ccninfo/ccninfo_user-public-key"
				, getenv("HOME"));
#ifdef DEB_CCNINFO
{
	fprintf (stderr, "DEB_CCNINFO: [%s] ccninfo_prvkey_path=%s\n"
				   , __FUNCTION__, ccninfo_prvkey_path);
	fprintf (stderr, "DEB_CCNINFO: [%s] ccninfo_pubkey_path=%s\n"
				   , __FUNCTION__, ccninfo_pubkey_path);
}
#endif //DEB_CCNINFO

		res = cef_valid_create_keyinfo_forccninfo();
		if (res < 0) {
			cef_log_write (CefC_Log_Warn,
				"Failed to load specified private key or public key.\n");
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest,
				"Failed to load specified private key or public key.\n");
#endif // CefC_Debug
			goto err;
		}

		*valid_type = (uint16_t) cef_valid_type_get_from_key(ccninfo_pub_key);
		if (*valid_type <= 0) {
			cef_log_write (CefC_Log_Warn,
				"The public key is invalid algorithm Type.\n");
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest,
				"The public key is invalid algorithm Type.\n");
#endif // CefC_Debug
			goto err;
		}

		res = cef_valid_is_key_pair (ccninfo_prv_key, ccninfo_pub_key);
		if (res != 1) {
			cef_log_write (CefC_Log_Warn,
				"The public key and private key do not match.\n");
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest,
				"The public key and private key do not match.\n");
#endif // CefC_Debug
			goto err;
		}
	}

err:
	return (res);
}

int
cef_valid_init_ccninfoRT (
	const char* conf_path,
	uint16_t* valid_type
) {
	int res = 0;

	/* Create sha256 key file name for ccninfo */
	res = cef_valid_keypath_ccninfoRT (conf_path);
	if (res < 0) {
		return (res);
	}
	res = cef_valid_create_keyinfo_forccninfo();
	if (res < 0) {
		cef_log_write (CefC_Log_Warn,
			"Failed to load specified private key or public key.\n");
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest,
			"Failed to load specified private key or public key.\n");
#endif // CefC_Debug
		goto err;
	}

	res = cef_valid_type_get_from_key(ccninfo_pub_key);
	if (res <= 0) {
		cef_log_write (CefC_Log_Warn,
			"The public key is invalid algorithm Type.\n");
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest,
			"The public key is invalid algorithm Type.\n");
#endif // CefC_Debug
		goto err;
	}

	res = cef_valid_is_key_pair (ccninfo_prv_key, ccninfo_pub_key);
	if (res != 1) {
		cef_log_write (CefC_Log_Warn,
			"The public key and private key do not match.\n");
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest,
			"The public key and private key do not match.\n");
#endif // CefC_Debug
		goto err;
	}

err:
	return (res);
}

int
cef_valid_type_get (
	const char* type
) {
	int res = CefC_T_ALG_INVALID;

	if (strcmp (type, CefC_ValidTypeStr_RSA256) == 0) {
		res = cef_valid_type_get_from_key(default_key_entry->pub_key);
	} else if (strcmp (type, CefC_ValidTypeStr_CRC32C) == 0) {
		res = CefC_T_CRC32C;
	} else if (strcmp (type, default_key_entry->prv_key_path) == 0) {
		res = cef_valid_type_get_from_key(default_key_entry->prv_key);
	} else if (strcmp (type, default_key_entry->pub_key_path) == 0) {
		res = cef_valid_type_get_from_key(default_key_entry->pub_key);
	}

	return (res);
}

int
cef_valid_type_get_forccninfo (
	const char* type
) {
	int res = CefC_T_ALG_INVALID;

	if (strcmp (type, CefC_ValidTypeStr_RSA256) == 0) {
		res = cef_valid_type_get_from_key(ccninfo_pub_key);
	} else if (strcmp (type, CefC_ValidTypeStr_CRC32C) == 0) {
		res = CefC_T_CRC32C;
	}

	return (res);
}

uint32_t
reverse_bit(
    uint32_t input,
    size_t len
) {
    uint32_t output = 0;
    for(size_t i = 0; i < len; i++){
        output = (output << 1) | ((input >> i) & 1);
    }
    return output;
}

uint32_t
cef_valid_crc32c_calc (
	const unsigned char* buf,
	size_t len
) {
    uint32_t c = 0xFFFFFFFF;

    while(len--){
        c = crc_table[ (c >> 24) ^ reverse_bit(*buf++, 8)] ^ (c << 8);
    }

    c = reverse_bit(c, 32);
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
	size_t hash_len = 0;

	key_entry = (CefT_Keys*) cef_valid_key_entry_search (name, name_len);

	if (key_entry == NULL) {
		return (0);
	}
//	SHA256(key_entry->pub_key_bi, key_entry->pub_key_bi_len, hash);
	cef_valid_sha256( key_entry->pub_key_bi, key_entry->pub_key_bi_len, hash, &hash_len);	/* for OpenSSL 3.x */
	memcpy (pubkey, key_entry->pub_key_bi, key_entry->pub_key_bi_len);
	memcpy (keyid, hash, hash_len);

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

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, "Get the public key (%d bytes)\n", val_len);
	cef_dbg_buff_write (CefC_Dbg_Finest, key, val_len);
#endif // CefC_Debug

	return ((int) val_len);
}

int
cef_valid_signature_sign (
	const unsigned char* msg,
	uint16_t msg_len,
	const unsigned char* name,
	int name_len,
	unsigned char* sign,
	unsigned int* sign_len
) {
	unsigned char hash[EVP_MAX_MD_SIZE+1] = {0};
	size_t hash_len = 0;
	int res;
	int type;
	CefT_Keys* key_entry;

	key_entry = (CefT_Keys*) cef_valid_key_entry_search (name, name_len);

	if (key_entry == NULL) {
		return (0);
	}

	type = cef_valid_type_get_from_key(key_entry->prv_key);
	switch (type) {
	case CefC_T_RSA_SHA256:
	case CefC_T_EC_SECP_256K1:
		cef_valid_sha256( msg, msg_len, hash, &hash_len );	/* for OpenSSL 3.x */
		break;
	case CefC_T_EC_SECP_384R1:
		cef_valid_sha384( msg, msg_len, hash, &hash_len );	/* for OpenSSL 3.x */
		break;
	default:
		cef_log_write (CefC_Log_Warn,
			"Invalid digital signature algorithm (%s).\n", key_entry->prv_key_path);
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest,
			"Invalid digital signature algorithm (%s).\n", key_entry->prv_key_path);
#endif // CefC_Debug
		return (-1);
	}

	res = cef_valid_signature_sign_core (
		type, hash, hash_len, sign, sign_len, key_entry->prv_key);

	return (res);
}

int 								/* If the return value is 0 the code is equal, 		*/
									/* otherwise the code is different. 				*/
cef_valid_msg_verify (
	const unsigned char* msg,
	int msg_len,
	int* cache_f
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

	if (cache_f != NULL) {
		*cache_f = 0;
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
		if (cache_f != NULL) {
			*cache_f = 1;
		}
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest, "This msg don't have validation tlvs, skip verification.\n");
#endif // CefC_Debug
		return (0);
	}
	index = hdr_len + CefC_S_TLF + val_len;

	if (validation_mode == CefC_ValidMode_NONE) {
		/* Skip validation in this validation mode. */
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest, "CefC_ValidMode_NONE mode, so skip Validation. (So caching isn't allowed)\n");
#endif // CefC_Debug
		return (0);
	}

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
			if ((res == 0) && (cache_f != NULL)) {
				*cache_f = 1;
			}
			break;
		}
		case CefC_T_RSA_SHA256:
		case CefC_T_EC_SECP_256K1:
		case CefC_T_EC_SECP_384R1:
		{
			res = cef_valid_signature_verify (
					msg, pkt_len, hdr_len, alg_offset, pld_offset, cache_f);
			break;
		}
		default: {
			cef_log_write (CefC_Log_Warn,
				"Invalid digital signature algorithm (type value=%d).\n", alg_type);
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest,
				"Invalid digital signature algorithm (type value=%d).\n", alg_type);
#endif // CefC_Debug
			break;
		}
	}

	return (res);
}

int
cef_valid_keyid_create_forccninfo (
	unsigned char* pubkey,
	unsigned char* keyid
) {
	unsigned char	hash[SHA256_DIGEST_LENGTH];
	size_t hash_len = 0;

//	SHA256(ccninfo_pub_key_bi, ccninfo_pub_key_bi_len, hash);
	cef_valid_sha256( ccninfo_pub_key_bi, ccninfo_pub_key_bi_len, hash, &hash_len);	/* for OpenSSL 3.x */
	memcpy (pubkey, ccninfo_pub_key_bi, ccninfo_pub_key_bi_len);
	memcpy (keyid, hash, hash_len);

	return (ccninfo_pub_key_bi_len);
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

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, "Get the public key (%d bytes)\n", val_len);
	cef_dbg_buff_write (CefC_Dbg_Finest, key, val_len);
#endif // CefC_Debug

	return ((int) val_len);
}

int
cef_valid_signature_sign_forccninfo (
	const unsigned char* msg,
	uint16_t msg_len,
	unsigned char* sign,
	unsigned int* sign_len
) {
	unsigned char 	hash[EVP_MAX_MD_SIZE+1] = {0};
	size_t hash_len = 0;
	int res;
	int type;

	type = cef_valid_type_get_from_key (ccninfo_prv_key);

	switch (type) {
	case CefC_T_RSA_SHA256:
	case CefC_T_EC_SECP_256K1:
		cef_valid_sha256( msg, msg_len, hash, &hash_len );	/* for OpenSSL 3.x */
		break;

	case CefC_T_EC_SECP_384R1:
		cef_valid_sha384( msg, msg_len, hash, &hash_len );	/* for OpenSSL 3.x */
		break;

	default:
		cef_log_write (CefC_Log_Warn,
			"Invalid digital signature algorithm (%s).\n", ccninfo_prvkey_path);
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest,
			"Invalid digital signature algorithm (%s).\n", ccninfo_prvkey_path);
#endif // CefC_Debug
		return (0);
	}

//	SHA256 (msg, msg_len, hash);
	res = cef_valid_signature_sign_core (
		type, hash, hash_len, sign, sign_len, ccninfo_prv_key);

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
		case CefC_T_RSA_SHA256:
		case CefC_T_EC_SECP_256K1:
		case CefC_T_EC_SECP_384R1:
		{
			res = cef_valid_signature_verify_forccninfo (
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
	calc_crc = cef_valid_crc32c_calc (&msg[hdr_len], pkt_len - (hdr_len + 8));

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest,
		"CRC32C [pld=%u] [calc=%u] ... %s\n"
		, cmp_crc, calc_crc, (int)(cmp_crc - calc_crc) ? "NG" : "OK");
#endif // CefC_Debug

	return ((int)(cmp_crc - calc_crc));
}

static int 							/* If the return value is 0 the code is equal, 		*/
									/* otherwise the code is different. 				*/
cef_valid_signature_verify (
	const unsigned char* msg,
	uint16_t pkt_len, 				/* PacketLength 									*/
	uint16_t hdr_len, 				/* HeaderLength (offset of CCN Message)				*/
	uint16_t alg_offset, 			/* offset of T_VALIDATION_ALG 						*/
	uint16_t pld_offset,	 		/* offset of T_VALIDATION_PAYLOAD 					*/
	int* cache_f					/* Flag indicating whether caching is allowed		*/
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
		res = cef_valid_signature_hby_verify (
					msg, pkt_len, hdr_len, alg_offset, pld_offset, cache_f);
	} else {
		res = cef_valid_signature_std_verify (
					msg, pkt_len, hdr_len, alg_offset, pld_offset, cache_f);
	}

	return (res);
}

static int 							/* If the return value is 0 the code is equal, 		*/
									/* otherwise the code is different. 				*/
cef_valid_signature_std_verify (
	const unsigned char* msg,
	uint16_t pkt_len, 				/* PacketLength 									*/
	uint16_t hdr_len, 				/* HeaderLength (offset of CCN Message)				*/
	uint16_t alg_offset, 			/* offset of T_VALIDATION_ALG 						*/
	uint16_t pld_offset,	 		/* offset of T_VALIDATION_PAYLOAD 					*/
	int* cache_f					/* Flag indicating whether caching is allowed		*/
) {
	struct tlv_hdr* 	tlv_ptr;
	uint16_t 			index;
	uint16_t 			length;
	unsigned char 		hash[EVP_MAX_MD_SIZE];
	size_t				hash_len = 0;
	int 				res;
	unsigned char* 		pub_key_bi;
	int 				pub_key_bi_len;
	EVP_PKEY*			pub_key;

	/* Obtains the Name 		*/
	index = hdr_len + CefC_S_TLF;
	tlv_ptr = (struct tlv_hdr*) &msg[index];
	length = ntohs (tlv_ptr->length);
	index += CefC_S_TLF;

	if (validation_mode == CefC_ValidMode_InBand) {
		/* Obtains the EVP_PKEY by pubkey included in the message. */
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

		tlv_ptr = (struct tlv_hdr*) &msg[pkey_offset];
		type = ntohs (tlv_ptr->type);
		length = ntohs (tlv_ptr->length);
		if (type != CefC_T_PUBLICKEY) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Validation mode is CefC_ValidMode_InBand, " \
					"but the message don't have T_PUBLICKEY, "\
					"so the messages can be forwarded, but it cannot be cached.\n");
#endif // CefC_Debug
			return (0);
		}
		length = ntohs (tlv_ptr->length);
		ptr_for_free = pub_key_bi = (unsigned char*)calloc(length, 1);
		pub_key_bi_len = length;
		memcpy (pub_key_bi, &msg[pkey_offset+CefC_S_TLF], pub_key_bi_len);

		pub_key = cef_valid_d2i_pubkey ((const unsigned char**)&pub_key_bi, pub_key_bi_len);
		free(ptr_for_free);
		if (pub_key == NULL) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Failed to get EVP_PKEY from pub_key included in the message.\n");
#endif // CefC_Debug
			return (1);
		}

	} else if (validation_mode == CefC_ValidMode_OutOfBand) {
		/* Obtains the EVP_PKEY from keyid_table by searching for the KeyID included in the message. */
		CefT_valid_Key*	validkey_entry = NULL;
		uint16_t 		pkey_offset;
		uint16_t 		type;

		pkey_offset = alg_offset;
		pkey_offset += CefC_S_TLF; 			/* Move offset by TL size of T_VALIDATION_ALG	*/
		pkey_offset += CefC_S_TLF; 			/* Move offset by TL size of T_RSA-SHA256		*/
		tlv_ptr = (struct tlv_hdr*) 		/* Parse the T_KEYID							*/
					&msg[pkey_offset];
		type = ntohs (tlv_ptr->type);
		if (type != CefC_T_KEYID) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "This message don't have CefC_T_KEYID.\n");
#endif // CefC_Debug
			return (1);
		}

		CefT_HashData keyid;
		pkey_offset += CefC_S_TLF;
		tlv_ptr = (struct tlv_hdr*) &msg[pkey_offset];
		keyid.hash_type = ntohs (tlv_ptr->type);
		keyid.hash_length = ntohs (tlv_ptr->length);
		memcpy (&keyid.hash_value, &msg[pkey_offset + CefC_S_TLF], keyid.hash_length);

		validkey_entry = cef_valid_validkey_get (keyid.hash_value, keyid.hash_length, keyid.hash_type);
		if (validkey_entry == NULL) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "No matching keyid entry exists in the keyid table.\n");
#endif // CefC_Debug
			return (1);
		}

		if (validkey_entry->pubkey_path[0] == '\0') {
			/* Do Lightweight verification, if the matching CefT_valid_Key entry have no pubkey's path. */
			/* It accept if the KeyID in the message matches the KeyID registered with CefT_valid_Key.  */
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Validation is OK. (by Lightweight verification)\n");
#endif // CefC_Debug
			return (0);
		}

		if (validkey_entry->pub_key == NULL) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Matching keyid entry is invalid. (EVP_PKEY entry is Invalid)\n");
#endif // CefC_Debug
			return (1);
		}
		pub_key = validkey_entry->pub_key;

	} else {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest, "Invalid Validation mode.\n");
#endif // CefC_Debug
		return (1);
	}
	/* Obtains the Validation Payload 		*/
	tlv_ptr = (struct tlv_hdr*) &msg[pld_offset];
	length = ntohs (tlv_ptr->length);
	index = pld_offset + CefC_S_TLF;

	/* Verification the sign 				*/
	res = cef_valid_type_get_from_key (pub_key);
	switch (res) {
	case CefC_T_RSA_SHA256:
	case CefC_T_EC_SECP_256K1:
		cef_valid_sha256( &msg[hdr_len], pld_offset - hdr_len, hash, &hash_len);	/* for OpenSSL 3.x */
		break;

	case CefC_T_EC_SECP_384R1:
		cef_valid_sha384( &msg[hdr_len], pld_offset - hdr_len, hash, &hash_len);	/* for OpenSSL 3.x */
		break;

	default:
		cef_log_write (CefC_Log_Warn,
			"Invalid digital signature algorithm (type value=%d).\n", res);
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest,
			"Invalid digital signature algorithm (type value=%d).\n", res);
#endif // CefC_Debug
		return (1);
	}

	res = cef_valid_signature_verify_core (
		res, hash, hash_len, &msg[index], length, pub_key);
	if (validation_mode == CefC_ValidMode_InBand) {
		EVP_PKEY_free (pub_key);
	}
	if ((res == 1) && (cache_f != NULL)) {
		*cache_f = 1;
	}

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest,
		"Validation is %s\n", (res == 1) ? "OK" : "NG");
#endif // CefC_Debug

	return ((res == 1) ? 0 : 1);
}
static int 							/* If the return value is 0 the code is equal, 		*/
									/* otherwise the code is different. 				*/
cef_valid_signature_hby_verify (
	const unsigned char* msg,
	uint16_t pkt_len, 				/* PacketLength 									*/
	uint16_t hdr_len, 				/* HeaderLength (offset of CCN Message)				*/
	uint16_t alg_offset, 			/* offset of T_VALIDATION_ALG 						*/
	uint16_t pld_offset,	 		/* offset of T_VALIDATION_PAYLOAD 					*/
	int* cache_f					/* Flag indicating whether caching is allowed		*/
) {
	/* HOP-BY-HOP */
	fprintf (stderr, "cef_valid_signature_hby_verify ()\n");
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

static int
cef_valid_create_keyinfo_forccninfo (
) {
	FILE* 			key_fp;
	key_fp = fopen (ccninfo_pubkey_path, "r");
	if (key_fp == NULL) {
		cef_log_write (CefC_Log_Error,
			"Failed to open public key (%s)\n", ccninfo_pubkey_path);
		return (-1);
	}

	ccninfo_pub_key = cef_valid_pem_read_pub_key (key_fp);
	if (ccninfo_pub_key == NULL) {
		cef_log_write (CefC_Log_Error,
			"Invalid public key (%s)\n", ccninfo_pubkey_path);
		fclose (key_fp);
		return (-1);
	}

	ccninfo_pub_key_bi_len
		= cef_valid_i2d_pubkey (ccninfo_pub_key, &ccninfo_pub_key_bi);
	if (ccninfo_pub_key_bi_len < 1) {
		cef_log_write (CefC_Log_Error,
			"Invalid public key (%s)\n", ccninfo_pubkey_path);
		fclose (key_fp);
		return (-1);
	}
	fclose (key_fp);
	key_fp = fopen (ccninfo_prvkey_path, "r");
	if (key_fp == NULL) {
		cef_log_write (CefC_Log_Error,
			"Failed to open (%s)\n", ccninfo_prvkey_path);
		return (-1);
	}

	ccninfo_prv_key = cef_valid_pem_read_private_key (key_fp);
	if (ccninfo_prv_key == NULL) {
		fclose (key_fp);
		cef_log_write (CefC_Log_Error,
			"Invalid private key (%s)\n", ccninfo_prvkey_path);
		return (-1);
	}
	fclose (key_fp);
	return (0);
}
static int 							/* If the return value is 0 the code is equal, 		*/
									/* otherwise the code is different. 				*/
cef_valid_signature_verify_forccninfo (
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
		res = cef_valid_signature_std_verify_forccninfo (
					msg, pkt_len, hdr_len, alg_offset, pld_offset,
					rcvdpub_key_bi_len_p, rcvdpub_key_bi_pp);
	}

	return (res);
}

static int 							/* If the return value is 0 the code is equal, 		*/
									/* otherwise the code is different. 				*/
cef_valid_signature_std_verify_forccninfo (
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
	unsigned char 		hash[EVP_MAX_MD_SIZE];
	size_t				hash_len = 0;
	int 				res;
	int 				rtc;
	unsigned char* 		pub_key_bi;
	int 				pub_key_bi_len;
	EVP_PKEY*			pub_key;

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
		pub_key = cef_valid_d2i_pubkey ((const unsigned char**)&pub_key_bi, pub_key_bi_len);
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
	res = cef_valid_type_get_from_key (pub_key);
	switch (res) {
	case CefC_T_RSA_SHA256:
	case CefC_T_EC_SECP_256K1:
//	SHA256 (&msg[hdr_len], pld_offset - hdr_len, hash);
		cef_valid_sha256( &msg[hdr_len], pld_offset - hdr_len, hash, &hash_len );	/* for OpenSSL 3.x */
		break;

	case CefC_T_EC_SECP_384R1:
		cef_valid_sha384( &msg[hdr_len], pld_offset - hdr_len, hash, &hash_len );	/* for OpenSSL 3.x */
		break;

	default:
		cef_log_write (CefC_Log_Warn,
			"Invalid digital signature algorithm (type value=%d).\n", res);
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest,
			"Invalid digital signature algorithm (type value=%d).\n", res);
#endif // CefC_Debug
		return (1);
	}

	res = cef_valid_signature_verify_core (
		res, hash, hash_len, &msg[index], length, pub_key);
	EVP_PKEY_free (pub_key);

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

static int
cef_valid_read_conf (
	const char* conf_path
) {
	char 	file_path[PATH_MAX];
	char	buff[BUFSIZ_1K];
	FILE	*fp;
	char	ccn_uri[] = { "ccnx:/" };
	char	pprv_key[PATH_MAX] = { "/usr/local/cefore/default-private-key" };
	char	ppub_key[PATH_MAX] = { "/usr/local/cefore/default-public-key" };
	int 	res = -1;
	unsigned char t_name[CefC_Max_Length];
	CefT_Keys* 	key_entry;

	key_table = cef_hash_tbl_create (128);

	if (conf_path[0] != 0x00) {
		sprintf (file_path, "%s/cefnetd.conf", conf_path);
	} else {
		char*	wp = getenv (CefC_CEFORE_DIR);
		if (wp != NULL && wp[0] != 0) {
			sprintf (file_path, "%s/cefore/cefnetd.conf", wp);
		} else {
			sprintf (file_path, "%s/cefnetd.conf", CefC_CEFORE_DIR_DEF);
		}
	}

	fp = fopen (file_path, "r");
	if (fp == NULL) {
		cef_log_write (CefC_Log_Error, "[client] Failed to open %s\n", file_path);
		return (-1);
	}

	/* Reads and records written values in the cefnetd's config file. */
	while (fgets (buff, (BUFSIZ_1K-1), fp) != NULL) {
		char 	keyword[BUFSIZ_1K];
		char 	value[BUFSIZ_1K];

		buff[(BUFSIZ_1K-1)] = 0;

		if ( buff[0] == '#' ) {
			continue;
		}

		res = cef_valid_trim_line_string (buff, keyword, value);
		if (res < 0) {
			continue;
		}
		if (strcasecmp (keyword, "PATH_PRIVATE_KEY") == 0) {
			strcpy(pprv_key, value);
		} else if (strcasecmp (keyword, "PATH_PUBLIC_KEY") == 0) {
			strcpy(ppub_key, value);
		}
	}
	fclose (fp);

	/* Creates the name from the URI 		*/
	res = cef_frame_conversion_uri_to_name (ccn_uri, t_name);

	if (res < 1) {
		cef_log_write (CefC_Log_Error, "Invalid ccn uri (%s)\n", ccn_uri);
		return (-1);
	}

	key_entry = (CefT_Keys*) cef_hash_tbl_item_get (key_table, t_name, res);

	if (key_entry) {
		cef_log_write (CefC_Log_Error,
			"cef_hash_tbl_item_get() failure.\n");
		return (-1);
	}
	key_entry = (CefT_Keys*) malloc (sizeof (CefT_Keys));
	memset (key_entry, 0, sizeof (CefT_Keys));

	memcpy (key_entry->name, t_name, res);
	key_entry->name_len = res;
	strcpy (key_entry->prv_key_path, pprv_key);
	strcpy (key_entry->pub_key_path, ppub_key);

	/* Prepares the public key 		*/
	fp = fopen (key_entry->pub_key_path, "r");
	if (fp == NULL) {
		cef_log_write (CefC_Log_Error,
		"Invalid public key (%s) is specified in cefnetd.conf\n",
			key_entry->pub_key_path);
		cef_valid_key_entry_free (key_entry);
		return (-1);
	}

	key_entry->pub_key = cef_valid_pem_read_pub_key (fp);
	fclose (fp);
	if (key_entry->pub_key == NULL) {
		cef_log_write (CefC_Log_Error,
		"pem_read_pub_key failure, %s.\n", key_entry->pub_key_path);
		cef_valid_key_entry_free (key_entry);
		return (-1);
	}
	res = EVP_PKEY_get_base_id(key_entry->pub_key);
	if (res != EVP_PKEY_RSA && res != EVP_PKEY_EC) {
		cef_log_write (CefC_Log_Error,
		"EVP_PKEY_get_base_id failure, %s.\n", key_entry->pub_key_path);
		cef_valid_key_entry_free (key_entry);
		return (-1);
	}

	key_entry->pub_key_bi_len
		= cef_valid_i2d_pubkey (key_entry->pub_key, &key_entry->pub_key_bi);
	if (key_entry->pub_key_bi_len < 1) {
		cef_log_write (CefC_Log_Error,
		"Invalid public key (%s) is specified in cefnetd.conf\n",
			key_entry->pub_key_path);
		cef_valid_key_entry_free (key_entry);
		return (-1);
	}

		/* Prepares the private key 		*/
	fp = fopen (key_entry->prv_key_path, "r");
	if (fp == NULL) {
		cef_log_write (CefC_Log_Error,
		"Invalid private key (%s) is specified in cefnetd.conf\n",
			key_entry->prv_key_path);
		cef_valid_key_entry_free (key_entry);
		return (-1);
	}

	key_entry->prv_key = cef_valid_pem_read_private_key (fp);
	fclose (fp);

	if (key_entry->prv_key == NULL) {
		cef_log_write (CefC_Log_Error,
		"pem_read_private_key failure, %s.\n", key_entry->prv_key_path);
		cef_valid_key_entry_free (key_entry);
		return (-1);
	}
	res = EVP_PKEY_get_base_id(key_entry->prv_key);
	if (res != EVP_PKEY_RSA && res != EVP_PKEY_EC) {
		cef_log_write (CefC_Log_Error,
		"EVP_PKEY_get_base_id failure, %s.\n", key_entry->prv_key_path);
		cef_valid_key_entry_free (key_entry);
		return (-1);
	}

	default_key_entry = key_entry;

	return (1);
}

static void
cef_valid_key_entry_free (
	CefT_Keys* key_entry
) {

	if (key_entry->prv_key) {
		EVP_PKEY_free (key_entry->prv_key);
	}
	if (key_entry->pub_key) {
		EVP_PKEY_free (key_entry->pub_key);
	}
	if (key_entry->pub_key_bi_len > 0) {
		free (key_entry->pub_key_bi);
	}
	free (key_entry);
}
static int
cef_valid_keypath_ccninfoRT(
	const char* conf_path
) {
	char*	wp;
	FILE* 	fp;
	char 	file_path[PATH_MAX];
	char 	cef_conf_dir[PATH_MAX];
	char	buff[BUFSIZ_1K];
	char 	ws[BUFSIZ_1K];
	char 	pname[BUFSIZ_1K];
	int 	res;
	char	key_prfx[BUFSIZ_2K];

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
	while (fgets (buff, (BUFSIZ_1K-1), fp) != NULL) {
		buff[(BUFSIZ_1K-1)] = 0;

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

	sprintf(ccninfo_prvkey_path, "%s/.ccninfo/%s-private-key"
			, cef_conf_dir, key_prfx);
	sprintf(ccninfo_pubkey_path, "%s/.ccninfo/%s-public-key"
			, cef_conf_dir, key_prfx);
#ifdef DEB_CCNINFO
{
	fprintf (stderr, "DEB_CCNINFO: [%s] ccninfo_prvkey_path=%s\n"
				   , __FUNCTION__, ccninfo_prvkey_path);
	fprintf (stderr, "DEB_CCNINFO: [%s] ccninfo_pubkey_path=%s\n"
				   , __FUNCTION__, ccninfo_pubkey_path);
}
#endif //DEB_CCNINFO

	return (0);
}

static void
cef_valid_crc32c_init (
	void
) {
    /*
    Castagnoli CRC32 (iSCSI, ext4, etc.) with normal form polynomial 0x1EDC6F41.
    From "Description" of "Table 10: CCNx Validation Types" of RFC8609.
    */

#ifdef CRC32C_POLY
    uint32_t i, c;
    int j;

    // initialize lookup table
    for (i = 0; i < 256; i++) {
      crc_table[i] = 0;
    }

    // make lookup table
    for (i = 0; i < 256; i++) {
        c = i << 24;
        for (j = 0; j < 8; j++) {
            if(c & (1L << 31))
               c = (c << 1) ^ CRC32C_POLY;
            else
               c = (c << 1);
        }
        crc_table[i] = c;
    }
#endif
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
	char ws[BUFSIZ_1K];
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

/* for OpenSSL 3.x */
unsigned char*
cef_valid_sha256 (
	const unsigned char *d,
	size_t n,
	unsigned char *md,
	size_t *md_len
) {

	if (md == NULL)
		return NULL;
	return EVP_Q_digest(NULL, "SHA256", NULL, d, n, md, md_len) ? md : NULL;

}

unsigned char*
cef_valid_sha384 (
	const unsigned char *d,
	size_t n,
	unsigned char *md,
	size_t *md_len
) {

	if (md == NULL)
		return NULL;
	return EVP_Q_digest(NULL, "SHA384", NULL, d, n, md, md_len) ? md : NULL;

}

unsigned char*
cef_valid_sha512 (
	const unsigned char *d,
	size_t n,
	unsigned char *md,
	size_t *md_len
) {

	if (md == NULL)
		return NULL;
	return EVP_Q_digest(NULL, "SHA512", NULL, d, n, md, md_len) ? md : NULL;

}

unsigned char*
cef_valid_md5 (
	const unsigned char *d,
	size_t n,
	unsigned char *md
) {

	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	unsigned int md_len;

	if (md == NULL)
		return NULL;

	EVP_DigestInit_ex2(mdctx, EVP_md5(), NULL);
	EVP_DigestUpdate(mdctx, d, n);
	EVP_DigestFinal_ex(mdctx, md, &md_len);
	EVP_MD_CTX_free(mdctx);
	return md;

}

static void
cef_valid_encoder_from_data (
	EVP_PKEY*		pkey,
	int				selection,
	const char*		output_type,
	const char*		structure,
	unsigned char**	pdata,
	size_t*			pdata_len
) {
	OSSL_ENCODER_CTX *ctx = OSSL_ENCODER_CTX_new_for_pkey (pkey, selection,
		output_type, structure, NULL);
	if (ctx == NULL) {
		/* fatal error handling */
		return;
	}

	if (OSSL_ENCODER_CTX_get_num_encoders (ctx) == 0) {
		/* non-fatal error handling */
		OSSL_ENCODER_CTX_free(ctx);
		return;
	}

	if (!OSSL_ENCODER_to_data (ctx, pdata, pdata_len)) {
		/* error handling */
		cef_log_write (CefC_Log_Error, "OSSL_ENCODER_to_data(), ERR_error_string:%s\n",
			ERR_error_string (ERR_get_error (), NULL));
	}

	OSSL_ENCODER_CTX_free (ctx);
}

static size_t
cef_valid_i2d_pubkey (
	EVP_PKEY*		pkey,
	unsigned char**	pdata
) {
	size_t pdata_len = 0;
	int selection = EVP_PKEY_PUBLIC_KEY;
	const char *output_type = "DER";
	const char *structure = "SubjectPublicKeyInfo";

	cef_valid_encoder_from_data (pkey, selection, output_type, structure,
		pdata, &pdata_len);

	return pdata_len;
}

static EVP_PKEY *
cef_valid_decoder_from (
	const char*				format,
	const char*             structure,
	const char*				keytype,
	int						selection,
	FILE*					fp,
	const unsigned char**	pdata,
	size_t*					pdata_len
) {
	EVP_PKEY *pkey = NULL;
	OSSL_DECODER_CTX *dctx;

	dctx = OSSL_DECODER_CTX_new_for_pkey (&pkey, format, structure,
		keytype, selection, NULL, NULL);
	if (dctx == NULL) {
	    /* error: no suitable potential decoders found */
    	EVP_PKEY_free (pkey);
		return NULL;
	}

	if (fp != NULL) {
		if (!OSSL_DECODER_from_fp (dctx, fp)) {
		    /* decoding failure */
			cef_log_write (CefC_Log_Error, "OSSL_DECODER_from_fp(), ERR_error_string:%s\n",
				ERR_error_string (ERR_get_error (), NULL));
   		 	EVP_PKEY_free (pkey);
			pkey = NULL;
		}
	} else if (pdata != NULL && *pdata != NULL && pdata_len != NULL && *pdata_len > 0) {
		if (!OSSL_DECODER_from_data (dctx, pdata, pdata_len)) {
		    /* decoding failure */
			cef_log_write (CefC_Log_Error, "OSSL_DECODER_from_data(), ERR_error_string:%s\n",
				ERR_error_string (ERR_get_error (), NULL));
   		 	EVP_PKEY_free (pkey);
			pkey = NULL;
		}
	} else {
  	 	EVP_PKEY_free (pkey);
		pkey = NULL;
	}

	OSSL_DECODER_CTX_free (dctx);

	return pkey;
}

static EVP_PKEY *
cef_valid_pem_read_pub_key (
	FILE*	fp
) {
	const char *format = "PEM";
	const char *structure = NULL;
	int selection = OSSL_KEYMGMT_SELECT_PUBLIC_KEY;

	return (cef_valid_decoder_from (format, structure, NULL, selection, fp, NULL, NULL));
}

static EVP_PKEY *
cef_valid_pem_read_private_key (
	FILE*	fp
) {
	const char *format = "PEM";
	const char *structure = "NULL";
	int selection = OSSL_KEYMGMT_SELECT_PRIVATE_KEY;

	return (cef_valid_decoder_from (format, structure, NULL, selection, fp, NULL, NULL));
}

static EVP_PKEY *
cef_valid_d2i_pubkey (
	const unsigned char**	pp,
	size_t					length
) {
	const char *format = "DER";
	const char *structure = NULL;
	int selection = OSSL_KEYMGMT_SELECT_PUBLIC_KEY;

	return (cef_valid_decoder_from (format, structure, NULL, selection, NULL, pp, &length));
}

static int
cef_valid_signature_sign_core (
	int						type,
	const unsigned char*	msg,
	unsigned int			msg_len,
	unsigned char*			sigret,
	unsigned int*			siglen,
	EVP_PKEY*				pkey
) {
	EVP_PKEY_CTX *ctx;
	int ret = 0;
	unsigned char* sig = NULL;
	const EVP_MD *md = NULL;
	size_t siglen_tmp;

	ctx = EVP_PKEY_CTX_new (pkey, NULL);
	if (!ctx) {
		cef_log_write (CefC_Log_Warn, "EVP_PKEY_CTX_new()=%d, ERR_error_string:%s\n",
			ret, ERR_error_string (ERR_get_error (), NULL));
		goto err;
	}
	if ((ret = EVP_PKEY_sign_init (ctx)) <= 0) {
		cef_log_write (CefC_Log_Warn, "EVP_PKEY_sign_init()=%d, ERR_error_string:%s\n",
			ret, ERR_error_string (ERR_get_error (), NULL));
		goto err;
	}

	switch (type) {
	case CefC_T_RSA_SHA256:
	case CefC_T_EC_SECP_256K1:
		md = EVP_sha256();
		break;
	case CefC_T_EC_SECP_384R1:
		md = EVP_sha384();
		break;
	default:
		cef_log_write (CefC_Log_Warn,
			"Invalid digital signature algorithm (type value=%d).\n", type);
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest,
			"Invalid digital signature algorithm (type value=%d).\n", type);
#endif // CefC_Debug
		goto err;		/* Error occurred */
	}

	if ((ret = EVP_PKEY_CTX_set_signature_md (ctx, md)) <= 0) {
		cef_log_write (CefC_Log_Warn, "EVP_PKEY_CTX_set_signature_md()=%d, ERR_error_string:%s\n",
			ret, ERR_error_string (ERR_get_error (), NULL));
		goto err;		/* Error occurred */
	}

	if ((ret = EVP_PKEY_sign (ctx, NULL, &siglen_tmp, msg, msg_len)) <= 0) {
		cef_log_write (CefC_Log_Warn, "EVP_PKEY_sign(NULL)=%d, ERR_error_string:%s\n",
			ret, ERR_error_string (ERR_get_error (), NULL));
		goto err;
	}
	sig = OPENSSL_malloc(siglen_tmp);
	if (sig == NULL) {
		cef_log_write (CefC_Log_Warn, "Failed to allocation signing buffer\n");
		goto err;
	}
	ret = EVP_PKEY_sign (ctx, sig, &siglen_tmp, msg, msg_len);
	if (ret <= 0) {
		cef_log_write (CefC_Log_Warn, "EVP_PKEY_sign(%p)=%d, ERR_error_string:%s\n",
			sigret, ret, ERR_error_string (ERR_get_error (), NULL));
		goto err;
	} else  {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest, "EVP_PKEY_sign()=OK\n");
#endif // CefC_Debug
	}

	*siglen = (unsigned int)siglen_tmp;
	memcpy (sigret, sig, *siglen);

err:
	EVP_PKEY_CTX_free (ctx);
	OPENSSL_free (sig);
	if (ret != 1) {
		cef_log_write (CefC_Log_Error, "Error return (ret = %d).\n", ret);
		return 0;
	}

	return ret;
}

static int
cef_valid_signature_verify_core (
	int						type,
	const unsigned char*	msg,
	unsigned int			msg_len,
    const unsigned char*	sigbuf,
	unsigned int			siglen,
	EVP_PKEY*				pkey
) {
	EVP_PKEY_CTX *ctx;
	int ret = 0;
	const EVP_MD *md = NULL;

	ctx = EVP_PKEY_CTX_new (pkey, NULL);
	if (!ctx) {
		cef_log_write (CefC_Log_Warn, "EVP_PKEY_CTX_new()=%p, ERR_error_string:%s\n",
			ctx, ERR_error_string (ERR_get_error (), NULL));
		goto err;
	}
	if ((ret = EVP_PKEY_verify_init (ctx)) <= 0) {
		cef_log_write (CefC_Log_Warn, "EVP_PKEY_verify_init()=%d, ERR_error_string:%s\n",
			ret, ERR_error_string (ERR_get_error (), NULL));
		goto err;
	}

	switch (type) {
	case CefC_T_RSA_SHA256:
	case CefC_T_EC_SECP_256K1:
		md = EVP_sha256();
		break;
	case CefC_T_EC_SECP_384R1:
		md = EVP_sha384();
		break;
	default:
		cef_log_write (CefC_Log_Warn,
			"Invalid digital signature algorithm (type value=%d).\n", type);
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest,
			"Invalid digital signature algorithm (type value=%d).\n", type);
#endif // CefC_Debug
		goto err;		/* Error occurred */
	}

	if ((ret = EVP_PKEY_CTX_set_signature_md (ctx, md)) <= 0) {
		cef_log_write (CefC_Log_Warn, "EVP_PKEY_CTX_set_signature_md()=%d, ERR_error_string:%s\n",
			ret, ERR_error_string (ERR_get_error (), NULL));
		goto err;		/* Error occurred */
	}

	/* Perform operation */
	ret = EVP_PKEY_verify (ctx, sigbuf, siglen, msg, msg_len);
	if (ret != 1) {
		cef_log_write (CefC_Log_Warn, "EVP_PKEY_verify()=%d, ERR_error_string:%s\n",
			ret, ERR_error_string (ERR_get_error (), NULL));
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest, "EVP_PKEY_verify()=%d, ERR_error_string:%s\n",
			ret, ERR_error_string (ERR_get_error (), NULL));
#endif // CefC_Debug
	} else  {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest, "EVP_PKEY_verify()=OK\n");
#endif // CefC_Debug
	}

err:
	EVP_PKEY_CTX_free (ctx);
	if (ret != 1) {
		cef_log_write (CefC_Log_Error, "Error return (ret = %d).\n", ret);
		return 0;
	}
	return ret;
}

int
cef_valid_get_keyid_from_specified_pubkey (
	const char* key_path,	// path of publickey
	unsigned char* buff,	// buffer to store the KeyID
	int buff_len			// length of buffer
) {
	FILE* key_fp;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	size_t hash_len = 0;

	unsigned char*  pub_key_bi = NULL;
	int pub_key_bi_len = 0;
	EVP_PKEY* pub_key;

	/* Check if buffer size is larger than required. */
	if (buff_len < (sizeof(hash) / sizeof(hash[0]))) {
		cef_log_write (CefC_Log_Error,"Size of buffer to store keyID is small. \n");
		return (-1);
	}

	key_fp = fopen (key_path, "r");
	if (key_fp == NULL) {
		cef_log_write (CefC_Log_Error,"Failed to open %s\n", key_path);
		return (-1);
	}

	/* read the public key  */
	pub_key = cef_valid_pem_read_pub_key (key_fp);
	if (pub_key == NULL) {
		cef_log_write (CefC_Log_Error,
			"Invalid public key (%s) is specified.\n", key_path);
		fclose (key_fp);
		return (-1);
	}
	fclose (key_fp);

	pub_key_bi_len = cef_valid_i2d_pubkey (pub_key, &pub_key_bi);

	if (pub_key_bi_len < 1) {
		cef_log_write (CefC_Log_Error,
			"Invalid public key (%s) is specified.\n", key_path);
		if (pub_key) {
			EVP_PKEY_free (pub_key);
		}
		if (pub_key_bi_len > 0) {
			free (pub_key_bi);
		}
		return (-1);
	}
	if (pub_key) {
		EVP_PKEY_free (pub_key);
	}

	cef_valid_sha256( pub_key_bi, pub_key_bi_len, hash, &hash_len);
	memcpy (buff, hash, (sizeof(hash) / sizeof(hash[0])) );

	if (pub_key_bi_len > 0) {
		free (pub_key_bi);
	}

	return (1);
}
int
cef_valid_verify_str (
	const char* key_path,	/* path of Publickey	*/
	unsigned char* str,		/* pointer of plaintext	*/
	int str_len,			/* length of plaintext	*/
	unsigned char* sign,	/* poitner of sign		*/
	int sign_len			/* length of sing		*/
) {
	int res = 0;
	FILE* key_fp;
	unsigned char hash[EVP_MAX_MD_SIZE];
	size_t hash_len = 0;
	int type;

	EVP_PKEY* pub_key;

	key_fp = fopen (key_path, "r");
	if (key_fp == NULL) {
		cef_log_write (CefC_Log_Error,"Failed to open %s\n", key_path);
		return (-1);
	}

	/* read the public key  */
	pub_key = cef_valid_pem_read_pub_key (key_fp);
	if (pub_key == NULL) {
		cef_log_write (CefC_Log_Error,
			"Invalid public key (%s) is specified.\n", key_path);
		fclose (key_fp);
		return (-1);
	}
	fclose (key_fp);

	type = EVP_PKEY_get_base_id(pub_key);
	switch (type) {
	case CefC_T_RSA_SHA256:
	case CefC_T_EC_SECP_256K1:
		cef_valid_sha256( str, str_len, hash, &hash_len);
		break;
	case CefC_T_EC_SECP_384R1:
		cef_valid_sha384( str, str_len, hash, &hash_len);
		break;
	default:
		EVP_PKEY_free (pub_key);
		cef_log_write (CefC_Log_Warn,
			"Invalid digital signature algorithm (%s).\n", key_path);
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest,
			"Invalid digital signature algorithm (%s).\n", key_path);
#endif // CefC_Debug
		return (-1);
	}

	res = cef_valid_signature_verify_core (type, hash, hash_len, sign, sign_len, pub_key);

	if (pub_key) {
		EVP_PKEY_free (pub_key);
	}

	return (res);
}

static int
cef_valid_type_get_from_key (
	EVP_PKEY* key
) {
	int type = CefC_T_ALG_INVALID;
	int res;
	res = EVP_PKEY_get_base_id(key);

	switch (res) {
	case EVP_PKEY_RSA:
		type = CefC_T_RSA_SHA256;
		break;

	case EVP_PKEY_EC:
        {
            const EC_KEY *ec;
            const EC_GROUP *group;

            ec = EVP_PKEY_get0_EC_KEY(key);
            if (!ec) {
                break;
            }

            group = EC_KEY_get0_group(ec);
            res = EC_GROUP_get_curve_name(group);

            switch (res) {
            case NID_secp256k1:
                type = CefC_T_EC_SECP_256K1;
                break;

            case NID_secp384r1:
                type =CefC_T_EC_SECP_384R1;
                break;

            default:
                cef_log_write (CefC_Log_Warn,
                    "Invalid elliptic curve identifier from EC_GROUP (NID=%d).\n", res);
#ifdef CefC_Debug
                cef_dbg_write (CefC_Dbg_Finest,
                    "Invalid elliptic curve identifier from EC_GROUP (NID=%d).\n", res);
#endif // CefC_Debug
                break;
            }
        }

		break;

	default:
		cef_log_write (CefC_Log_Warn,
			"Invalid digital signature algorithm (type value=%d).\n", res);
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest,
			"Invalid digital signature algorithm (type value=%d).\n", res);
#endif // CefC_Debug
		break;
	}

	return (type);
}

static int 							/* If the return value is 1, the verification succeeded,	*/
									/* otherwise, the verification failed.						*/
cef_valid_is_key_pair (
	EVP_PKEY *prv_key,
	EVP_PKEY *pub_key
) {
	int res;
	unsigned char sign[256];
	unsigned int sign_len = 0;
	unsigned char hash[EVP_MAX_MD_SIZE + 1] = {0};
	size_t hash_len = 0;
	const unsigned char data[256] = "key-pair-check";
	int type;

	type = cef_valid_type_get_from_key(prv_key);
	switch (type) {
	case CefC_T_RSA_SHA256:
	case CefC_T_EC_SECP_256K1:
		cef_valid_sha256( data, sizeof(data), hash, &hash_len );	/* for OpenSSL 3.x */
		break;
	case CefC_T_EC_SECP_384R1:
		cef_valid_sha384( data, sizeof(data), hash, &hash_len );	/* for OpenSSL 3.x */
		break;
	default:
		cef_log_write (CefC_Log_Warn,
			"Invalid digital signature algorithm (type value=%d).\n", type);
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest,
			"Invalid digital signature algorithm (type value=%d).\n", type);
#endif // CefC_Debug
		return (-1);
	}



	res = cef_valid_signature_sign_core (
		type, hash, (unsigned int)hash_len, sign, &sign_len, prv_key);
	if (res != 1) {
		cef_log_write (CefC_Log_Warn,
			"Failed to sign.\n");
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest,
			"Failed to sign.\n");
#endif // CefC_Debug
		return (-1);
	}
	res = cef_valid_signature_verify_core (
		type, hash, (unsigned int)hash_len, sign, sign_len, pub_key);
	if (res != 1) {
		cef_log_write (CefC_Log_Warn,
			"Failed to verify signature.\n");
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest,
			"Failed to verify signature.\n");
#endif // CefC_Debug
		return (-1);
	}

	return (1);

}

int
cef_valid_init_fortools (
	const char* prv_key_path
) {
	FILE* fp = NULL;
	int res = 0;
	unsigned char t_name[CefC_Max_Length];
	char ccn_uri[] = { "ccnx:/" };
	CefT_Keys* key_entry;

	/* Initialize CRC */
	cef_valid_crc32c_init();

	/* If crc32c is specified, finish here */
	if (strcmp(prv_key_path, CefC_ValidTypeStr_CRC32C) == 0) {
		return (1);
	}

	/* Initialize key table */
	key_table = cef_hash_tbl_create (128);

	/* Convert URI to Name */
	res = cef_frame_conversion_uri_to_name (ccn_uri, t_name);
	if (res < 1) {
		cef_log_write (CefC_Log_Error, "Invalid ccn uri (%s)\n", ccn_uri);
		return (-1);
	}

	/* Check existing entry */
	key_entry = (CefT_Keys*) cef_hash_tbl_item_get (key_table, t_name, res);
	if (key_entry) {
		cef_log_write (CefC_Log_Error, "cef_hash_tbl_item_get() failure.\n");
		return (-1);
	}

	/* Create new entry */
	key_entry = (CefT_Keys*) malloc (sizeof (CefT_Keys));
	if (key_entry == NULL) {
		return (-1);
	}
	memset (key_entry, 0, sizeof (CefT_Keys));

	memcpy (key_entry->name, t_name, res);
	key_entry->name_len = res;

	/* Set path */
	strcpy (key_entry->prv_key_path, prv_key_path);

	/* Load private key */
	fp = fopen (prv_key_path, "r");
	if (fp == NULL) {
		cef_log_write (CefC_Log_Error, "Invalid private key (%s)\n", prv_key_path);
		cef_valid_key_entry_free (key_entry);
		return (-1);
	}

	key_entry->prv_key = cef_valid_pem_read_private_key (fp);
	fclose (fp);

	if (key_entry->prv_key == NULL) {
		cef_log_write (CefC_Log_Error, "pem_read_private_key failure, %s.\n", prv_key_path);
		cef_valid_key_entry_free (key_entry);
		return (-1);
	}

	res = EVP_PKEY_get_base_id(key_entry->prv_key);
	if (res != EVP_PKEY_RSA && res != EVP_PKEY_EC) {
		cef_log_write (CefC_Log_Error, "EVP_PKEY_get_base_id failure, %s.\n", prv_key_path);
		cef_valid_key_entry_free (key_entry);
		return (-1);
	}

	/* Generate public key from private key */
	key_entry->pub_key = EVP_PKEY_dup(key_entry->prv_key);
	if (key_entry->pub_key == NULL) {
		cef_log_write (CefC_Log_Error, "Public key duplication failure.\n");
		cef_valid_key_entry_free (key_entry);
		return (-1);
	}

	res = EVP_PKEY_get_base_id(key_entry->pub_key);
	if (res != EVP_PKEY_RSA && res != EVP_PKEY_EC) {
		cef_log_write (CefC_Log_Error, "EVP_PKEY_get_base_id failure (pubkey).\n");
		cef_valid_key_entry_free (key_entry);
		return (-1);
	}

	/* Generate public key binary image */
	key_entry->pub_key_bi_len = cef_valid_i2d_pubkey (key_entry->pub_key, &key_entry->pub_key_bi);
	if (key_entry->pub_key_bi_len < 1) {
		cef_log_write (CefC_Log_Error, "Invalid public key (generated from private key).\n");
		cef_valid_key_entry_free (key_entry);
		return (-1);
	}

	/* Set as default key */
	default_key_entry = key_entry;

	return (1);
}

void
cef_valid_validkey_table_destroy (
	void
) {
	uint32_t index = 0;
	CefT_valid_Key* entry;

	if (keyid_table == NULL) {
		return;
	}

	/* Delete each FIB entry */
	/* Scan all entries in the table */
	for (index = 0; index < cef_hash_tbl_def_max_get(keyid_table); index++) {
		entry = (CefT_valid_Key*)cef_hash_tbl_item_remove_from_index(keyid_table, index);

		if (entry == NULL) {
			continue;
		}

		if (entry->pub_key) {
			EVP_PKEY_free(entry->pub_key);
		}

		if (entry->pub_key_bi) {
			free(entry->pub_key_bi);
		}

		free(entry);
	}

	/* Delete table */
	cef_hash_tbl_destroy(keyid_table);
}

int
cef_valid_validkey_add (
	const char* pubkey_path,
	const unsigned char* keyid_hexstr,
	uint16_t keyid_len,
	uint16_t hash_type
) {
	unsigned char keyid[CefC_S_KeyId];
	unsigned char hash[SHA512_DIGEST_LENGTH];
	size_t hash_len = 0;
	CefT_valid_Key* entry = NULL;
	FILE* fp = NULL;
	int res;

	unsigned char generated_keyid[CefC_S_KeyId];
	unsigned char conf_keyid[CefC_S_KeyId];

	if (!((hash_type == CefC_T_SHA_256 && keyid_len == CefC_ValidKey_KeyIdLen32) ||
		(hash_type == CefC_T_SHA_512 && keyid_len == CefC_ValidKey_KeyIdLen32) ||
		(hash_type == CefC_T_SHA_512 && keyid_len == CefC_ValidKey_KeyIdLen64))) {

		cef_log_write(
			CefC_Log_Warn,
			"Failed to add validkey: invalid KeyID length (%u) or hash type (%u) was specified.\n",
			keyid_len,
			hash_type
		);

		return (CefC_ValidKey_Err_InvalidArg);
	}

	memset(keyid, 0, sizeof(keyid));
	memset(generated_keyid, 0, sizeof(generated_keyid));
	memset(conf_keyid, 0, sizeof(conf_keyid));

	/* allocate entry */
	entry = (CefT_valid_Key*)calloc(1, sizeof(CefT_valid_Key));

	if (entry == NULL) {
		cef_log_write(
			CefC_Log_Warn,
			"Failed to add validkey: memory allocation failed.\n"
		);

		return (CefC_ValidKey_Err_NoMemory);
	}

	/* pubkey only / public key + keyid */
	if (pubkey_path != NULL) {

		fp = fopen(pubkey_path, "rb");

		if (fp == NULL) {
			cef_log_write(
				CefC_Log_Warn,
				"Failed to add validkey: public key file '%s' could not be opened.\n",
				pubkey_path
			);

			free(entry);
			return (CefC_ValidKey_Err_NoFile);
		}

		/* PEM -> EVP_PKEY */
		entry->pub_key = cef_valid_pem_read_pub_key(fp);
		fclose(fp);

		if (entry->pub_key == NULL) {
			cef_log_write(CefC_Log_Warn,
				"Failed to add validkey: '%s' is not a valid public key file.\n",
				pubkey_path
			);

			free(entry);
			return (CefC_ValidKey_Err_BadKey);
		}

		/* key type check */
		res = EVP_PKEY_get_base_id(entry->pub_key);

		if (res != EVP_PKEY_RSA && res != EVP_PKEY_EC) {
			cef_log_write(
				CefC_Log_Warn,
				"Failed to add validkey: unsupported public key type was found in '%s'.\n",
				pubkey_path
			);

			EVP_PKEY_free(entry->pub_key);
			free(entry);
			return (CefC_ValidKey_Err_BadKey);
		}

		/* EVP_PKEY -> DER binary */
		entry->pub_key_bi_len = cef_valid_i2d_pubkey(entry->pub_key, &entry->pub_key_bi);

		if (entry->pub_key_bi_len < 1) {
			cef_log_write(
				CefC_Log_Warn,
				"Failed to add validkey: public key conversion failed for '%s'.\n",
				pubkey_path
			);

			EVP_PKEY_free(entry->pub_key);
			free(entry);
			return (CefC_ValidKey_Err_BadKey);
		}

		/* create KeyID from pubkey hash */
		if (hash_type == CefC_T_SHA_256) {

			cef_valid_sha256(entry->pub_key_bi, entry->pub_key_bi_len, hash, &hash_len);

		} else if (hash_type == CefC_T_SHA_512) {

			cef_valid_sha512(entry->pub_key_bi, entry->pub_key_bi_len, hash, &hash_len);

		} else {
			cef_log_write(
				CefC_Log_Warn,
				"Failed to add validkey: unsupported hash type (%u) was specified.\n",
				hash_type
			);

			EVP_PKEY_free(entry->pub_key);

			if (entry->pub_key_bi) {
				free(entry->pub_key_bi);
			}

			free(entry);
			return (CefC_ValidKey_Err_InvalidArg);
		}

		if (hash_type == CefC_T_SHA_256) {
			/* SHA256 is fixed at 32 bytes. */
			memcpy(generated_keyid, hash, CefC_ValidKey_KeyIdLen32);
			entry->keyid_len = CefC_ValidKey_KeyIdLen32;
		} else {
			/*
				SHA512 is either 32 bytes or 64 bytes.
				keyid_len is the value specified by the caller.
			*/
			memcpy(generated_keyid, hash, keyid_len);
			entry->keyid_len = keyid_len;
		}

		/* if KeyID is also specified,verify generated KeyID == configured KeyID */
		if (keyid_hexstr != NULL) {
			cef_valid_hexstr_to_bin((const char*)keyid_hexstr, conf_keyid, keyid_len);

			if (memcmp(generated_keyid, conf_keyid, keyid_len) != 0) {
				cef_log_write(
					CefC_Log_Warn,
					"Failed to add validkey: the specified KeyID does not match the KeyID generated from public key '%s'.\n",
					pubkey_path
				);

				/* KeyID mismatch */
				EVP_PKEY_free(entry->pub_key);

				if (entry->pub_key_bi) {
					free(entry->pub_key_bi);
				}

				free(entry);
				return (CefC_ValidKey_Err_Mismatch);
			}
		}

		memcpy(keyid, generated_keyid, entry->keyid_len);

		entry->hash_type = hash_type;

		/* public key path is stored in a structure */
		strncpy(entry->pubkey_path, pubkey_path, sizeof(entry->pubkey_path) - 1);
	}

	/* keyid mode */
	else if (keyid_hexstr != NULL) {

		/* hex string -> binary */
		cef_valid_hexstr_to_bin((const char*)keyid_hexstr, keyid, keyid_len);

		entry->keyid_len = keyid_len;
		entry->hash_type = hash_type;

		memset(entry->pubkey_path, 0, sizeof(entry->pubkey_path));

	} else {
		cef_log_write(
			CefC_Log_Warn,
			"Failed to add validkey: neither a KeyID nor a public key was specified.\n"
		);

		free(entry);
		return (CefC_ValidKey_Err_InvalidArg);
	}

	/* store keyid into entry */
	memcpy(entry->keyid, keyid, entry->keyid_len);

	/* duplicate check */
	if (cef_valid_validkey_exist(entry->keyid, entry->keyid_len, entry->hash_type)) {

		cef_log_write(
			CefC_Log_Info,
			"validkey duplicate entry ignored "
			"(HashType=%s KeyLength=%u KeyID=%s)\n",
			(entry->hash_type == CefC_T_SHA_256) ?
				CefC_Valid_HashStr_SHA256 :
				CefC_Valid_HashStr_SHA512,
			entry->keyid_len,
			keyid_hexstr
		);

		if (entry->pub_key) {
			EVP_PKEY_free(entry->pub_key);
		}

		if (entry->pub_key_bi) {
			free(entry->pub_key_bi);
		}

		free(entry);
		/* skip registration */
		return (0);
	}

    /* register */
	if (cef_hash_tbl_item_set(keyid_table, entry->keyid, entry->keyid_len, entry) < 0) {

		cef_log_write(
			CefC_Log_Warn,
			"Failed to add validkey: registration to the validkey table failed.\n"
		);

		if (entry->pub_key) {
			EVP_PKEY_free(entry->pub_key);
		}

		if (entry->pub_key_bi) {
			free(entry->pub_key_bi);
		}

		free(entry);
		return (CefC_ValidKey_Err_TableFull);
	}

	return (0);
}


int
cef_valid_validkey_del (
	const unsigned char* keyid_hexstr,
	uint16_t keyid_len,
	uint16_t hash_type
) {
	unsigned char keyid[CefC_S_KeyId];
	CefT_valid_Key* entry;

	memset(keyid, 0, sizeof(keyid));

	/* hex string -> binary */
	cef_valid_hexstr_to_bin((const char*)keyid_hexstr, keyid, keyid_len);

	/* search entry */
	entry = (CefT_valid_Key*)cef_hash_tbl_item_get(keyid_table, keyid, keyid_len);

	if (entry == NULL) {
		cef_log_write(
			CefC_Log_Warn,
			"Failed to delete validkey: the specified KeyID was not found.\n"
		);

		return (CefC_ValidKey_Err_NotFound);
	}

	/* hash_type check */
	if (entry->hash_type != hash_type) {
		cef_log_write(
			CefC_Log_Warn,
			"Failed to delete validkey: the specified hash type does not match the registered key information.\n"
		);

		return (CefC_ValidKey_Err_Mismatch);
	}

	/* remove */
	cef_hash_tbl_item_remove(keyid_table, keyid, keyid_len);

	/* free resources */
	if (entry->pub_key) {
		EVP_PKEY_free(entry->pub_key);
	}

	if (entry->pub_key_bi) {
		free(entry->pub_key_bi);
	}

	free(entry);

	return (0);
}

int
cef_valid_validkey_show (
	char* buff,
	int buff_size
) {
	CefT_valid_Key* entry;
	uint32_t index = 0;
	int offset = 0;
	int offset_pre = 0;
	int i;
	int written;
	int truncate_f = 0;
	char truncate_str[BUFSIZ_32] = "and more...\n";

	if ((buff == NULL) || (buff_size == 0)) {
		return (-1);
	}

	if (keyid_table == NULL) {
		return (0);
	}

	buff[0] = '\0';

	for (index = 0; index < cef_hash_tbl_def_max_get(keyid_table); index++) {
		offset_pre = offset;
		entry = (CefT_valid_Key*)cef_hash_tbl_item_get_from_index(keyid_table, index);

		if (entry == NULL) {
			continue;
		}

		/* KeyID prefix */
		written = snprintf(buff + offset, buff_size - offset, "0x");

		if (written < 0) {
			return (-1);
		} else if (written >= (buff_size - offset)) {
			truncate_f = 1;
			break;
		}

		offset += written;

		/* KeyID */
		for (i = 0; i < entry->keyid_len; i++) {
			written = snprintf(buff + offset, buff_size - offset, "%02x", entry->keyid[i]);

			if (written < 0) {
				return (-1);
			} else if (written >= (buff_size - offset)) {
				truncate_f = 1;
				break;
			}

			offset += written;
		}

		/* hash_type */
		if (entry->hash_type == CefC_T_SHA_256) {
			written = snprintf(buff + offset, buff_size - offset, " " CefC_Valid_HashStr_SHA256 " ");
		} else if (entry->hash_type == CefC_T_SHA_512) {
			written = snprintf(buff + offset, buff_size - offset, " " CefC_Valid_HashStr_SHA512 " ");
		} else {
			written = snprintf(buff + offset, buff_size - offset, " unknown ");
		}

		if (written < 0) {
			return (-1);
		} else if (written >= (buff_size - offset)) {
			truncate_f = 1;
			break;
		}

		offset += written;

		/* key length */
		written = snprintf(buff + offset, buff_size - offset, "%u", entry->keyid_len);

		if (written < 0) {
			return (-1);
		} else if (written >= (buff_size - offset)) {
			truncate_f = 1;
			break;
		}

		offset += written;

		/* pubkey path */
		if (entry->pubkey_path[0] != '\0') {
			written = snprintf(buff + offset, buff_size - offset, " %s\n", entry->pubkey_path);
		} else {
			written = snprintf(buff + offset, buff_size - offset, "\n");
		}

		if (written < 0) {
			return (-1);
		} else if (written >= (buff_size - offset)) {
			truncate_f = 1;
			break;
		}

		offset += written;

		if (buff_size < offset + strlen(truncate_str) ) {
			truncate_f = 1;
			break;
		}
	}

	/* Handling cases where records don't fit in the buffer */
	if (truncate_f == 1) {
		offset = offset_pre;
		written = snprintf(buff + offset, buff_size - offset, "%s", truncate_str);
		if (written < 0) {
			return (-1);
		}
		offset += written;
	}

	return offset;
}

static int
cef_valid_hexstr_to_bin (
	const char* hexstr,
	unsigned char* bin,
	int bin_len
) {
	int i;
	char wk[3];

	wk[2] = '\0';

	for (i = 0 ; i < bin_len ; i++) {

		wk[0] = hexstr[i * 2];
		wk[1] = hexstr[i * 2 + 1];

		bin[i] = (unsigned char) strtoul(wk, NULL, 16);
	}

	return (0);
}

int
cef_valid_validkey_table_init (
	const char* file_path,
	int validkey_table_size,
	int valid_mode
) {
	char buff[BUFSIZ_1K];
	FILE* fp;
	int line_no = 0;

	validation_mode = valid_mode;
	keyid_table = cef_hash_tbl_create(validkey_table_size);

	fp = fopen(file_path, "r");

	if (fp == NULL) {
		cef_log_write(CefC_Log_Warn, "keyid.list is not found (%s)\n", file_path);
		return (0);
	}

	while (fgets(buff, sizeof(buff), fp) != NULL) {

		char keyid[BUFSIZ_256] = {0};
		char hash_str[BUFSIZ_32] = {0};
		char pubkey_path[PATH_MAX] = {0};
		uint16_t hash_type;
		uint16_t key_len;
		char* token = NULL;
		char* saveptr = NULL;

		line_no++;
		buff[strcspn(buff, "\r\n")] = '\0';

		/* comment */
		if (buff[0] == '#') {
			continue;
		}

		/* empty line */
		if (buff[0] == '\0') {
			continue;
		}

		/* format : <KeyID> <hash_type> <key_length> [pubkey] */
		/* field1 : keyid */
		token = strtok_r(buff, " \t\r\n", &saveptr);

		if (token == NULL) {
			continue;
		}

		strncpy(keyid, token, sizeof(keyid) - 1);

		/* support 0x prefix */
		if ((strlen(keyid) > 2) && (keyid[0] == '0') && (tolower((unsigned char)keyid[1]) == 'x')) {

			memmove(keyid, keyid + 2, strlen(keyid + 2) + 1);
		}

		/* field2 : hash type */
		token = strtok_r(NULL, " \t\r\n", &saveptr);

		if (token == NULL) {
			cef_log_write(CefC_Log_Warn, "keyid.list line=%d field=hash_type error=missing\n", line_no);
			continue;
		}

		strncpy(hash_str, token, sizeof(hash_str) - 1);

		/* hash type conversion */
		if (strcasecmp(hash_str, CefC_Valid_HashStr_SHA256) == 0) {

			hash_type = CefC_T_SHA_256;

		} else if (strcasecmp(hash_str, CefC_Valid_HashStr_SHA512) == 0) {

			hash_type = CefC_T_SHA_512;

		} else {

			cef_log_write(CefC_Log_Warn, "keyid.list line %d invalid hash type\n", line_no);

			continue;
		}

		/* field3 : key length */
		token = strtok_r(NULL, " \t\r\n", &saveptr);

		if (token == NULL) {
			cef_log_write(CefC_Log_Warn, "keyid.list line=%d field=key_length error=missing\n", line_no);
			continue;
		}

		key_len = (uint16_t)atoi(token);

		/* field4 : pubkey path (optional) */
		token = strtok_r(NULL, " \t\r\n", &saveptr);

		if (token != NULL) {
			strncpy(pubkey_path, token, sizeof(pubkey_path) - 1);
		}

		if (strcasecmp(keyid, "none") == 0) {

			if (pubkey_path[0] == '\0') {

				cef_log_write(CefC_Log_Warn, "keyid.list line %d pubkey path missing\n", line_no);

				continue;
			}

			if (cef_valid_validkey_add(pubkey_path, NULL, key_len, hash_type) < 0) {

				cef_log_write(CefC_Log_Warn, "keyid.list line %d add pubkey failed\n", line_no);
			}

		} else {

			size_t expect_len = key_len * 2;

			if (strlen(keyid) != expect_len) {

				cef_log_write(CefC_Log_Warn, "keyid.list line %d invalid keyid length\n", line_no);

				continue;
			}

			if (pubkey_path[0] != '\0') {

				if (cef_valid_validkey_add(pubkey_path, (const unsigned char*)keyid, key_len, hash_type) < 0) {

					cef_log_write(CefC_Log_Warn, "keyid.list line %d add keyid pubkey failed\n", line_no);
				}

			} else {

				if (cef_valid_validkey_add(NULL, (const unsigned char*)keyid, key_len, hash_type) < 0) {

					cef_log_write(CefC_Log_Warn, "keyid.list line %d add keyid failed\n", line_no);
				}
			}
		}
	}

	fclose(fp);

	return (0);
}

static CefT_valid_Key*
cef_valid_validkey_get (
	const unsigned char* keyid,
	uint16_t keyid_len,
	uint16_t hash_type
) {
	CefT_valid_Key *entry;

	if (keyid == NULL) {
		return NULL;
	}

	/* search entry */
	entry = (CefT_valid_Key*)cef_hash_tbl_item_get(keyid_table, keyid, keyid_len);

	/* check the hash_type */
	if ((entry != NULL) && (entry->hash_type != hash_type)) {
		return NULL;
	}

	return entry;
}

int
cef_valid_validkey_exist (
	const unsigned char* keyid,
	uint16_t keyid_len,
	uint16_t hash_type
) {
	CefT_valid_Key*	validkey_entry = NULL;

	validkey_entry = cef_valid_validkey_get (keyid, keyid_len, hash_type);
	if (validkey_entry == NULL) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest, "No matching keyid entry exists in the keyid table.\n");
#endif // CefC_Debug
		return (0);
	}
	return (1);
}

int
cef_valid_keyid_create_from_hashtype (
	unsigned char* keyid,
	uint16_t hash_type,
	unsigned char* pubkey,
	uint16_t* pub_key_bi_len
) {
	size_t	hash_len = 0;
	if (default_key_entry == NULL) {
		return 0;
	}

	/* Create KeyID by the pubkey and specified hash type. */
	if (hash_type == CefC_T_SHA_256) {
		cef_valid_sha256(default_key_entry->pub_key_bi, default_key_entry->pub_key_bi_len, keyid, &hash_len);

	} else if (hash_type == CefC_T_SHA_512) {
		cef_valid_sha512(default_key_entry->pub_key_bi, default_key_entry->pub_key_bi_len, keyid, &hash_len);
	}

	/* Set the pubkey info */
	memcpy (pubkey, default_key_entry->pub_key_bi, default_key_entry->pub_key_bi_len);
	*pub_key_bi_len = default_key_entry->pub_key_bi_len;

	return hash_len;
}

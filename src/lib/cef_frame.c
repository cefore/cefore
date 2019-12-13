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
 * cef_frame.c
 */

#define __CEF_FRAME_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include <cefore/cef_define.h>
#ifndef CefC_MACOS
#include <endian.h>
#else // CefC_MACOS
#include <machine/endian.h>
#endif // CefC_MACOS
#ifdef CefC_Android
#include <cefore/cef_android.h>
#endif // CefC_Android

#include <cefore/cef_frame.h>
#include <cefore/cef_client.h>
#include <cefore/cef_print.h>
#include <cefore/cef_log.h>
#include <cefore/cef_plugin.h>
#include <cefore/cef_valid.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

#define BFF_SET(_p, _num)									\
	do {													\
		int _idx = 8;										\
		int _range;											\
		int _shift_bits;									\
		_p[0] = 0xFFFFFFFF;									\
		_p[1] = 0xFFFFFFFF;									\
		_p[2] = 0xFFFFFFFF;									\
		_p[3] = 0xFFFFFFFF;									\
		_p[4] = 0xFFFFFFFF;									\
		_p[5] = 0xFFFFFFFF;									\
		_p[6] = 0xFFFFFFFF;									\
		_p[7] = 0xFFFFFFFF;									\
		if (_num > 256) {									\
			_range = 256;									\
		} else {											\
			_range = _num;									\
		}													\
		do {												\
			_idx--;											\
			if (_range > 31) {								\
				_shift_bits = 32;							\
				_p[_idx] = 0;								\
			} else {										\
				_shift_bits = _range;						\
				_p[_idx] = htonl (_p[_idx] << _shift_bits);	\
			}												\
			_range -= _shift_bits;							\
		} while (_range > 0);								\
	} while (0)

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/



/****************************************************************************************
 State Variables
 ****************************************************************************************/
static char cefprefix1[] = {"cef:/"};
static char cefprefix2[] = {"cef://"};
static size_t cefprefix1_len = sizeof (cefprefix1) - 1; /* without NULL */
static size_t cefprefix2_len = sizeof (cefprefix2) - 1; /* without NULL */

/*------------------------------------------------------------------
	the Link Message template
 -------------------------------------------------------------------*/
static unsigned char* link_msg = NULL;
static int link_msg_len = -1;

/*------------------------------------------------------------------
	the Link Command template
 -------------------------------------------------------------------*/
static unsigned char* link_cmd = NULL;
static int link_cmd_len = -1;

/*------------------------------------------------------------------
	the Default Name template
 -------------------------------------------------------------------*/
static unsigned char default_name[4];
static int default_name_len = 0;

/*------------------------------------------------------------------
	the value of type field in host-byte-order
 -------------------------------------------------------------------*/

/***** for Common 						*****/
static uint16_t ftvh_1byte			= 1;
static uint16_t ftvh_2byte			= 2;
static uint16_t ftvh_4byte			= 4;
static uint16_t ftvh_8byte			= 8;
static uint16_t ftvh_32byte			= 32;

/***** for Cefore Message 				*****/
static uint16_t ftvh_pktype_int 	= CefC_T_INTEREST;
static uint16_t ftvh_pktype_obj 	= CefC_T_OBJECT;
static uint16_t ftvh_valid_alg 		= CefC_T_VALIDATION_ALG;
static uint16_t ftvh_valid_pld 		= CefC_T_VALIDATION_PAYLOAD;
static uint16_t ftvh_pktype_ping 	= CefC_T_PING;
static uint16_t ftvh_pktype_trace 	= CefC_T_TRACE;
static uint16_t ftvh_name 			= CefC_T_NAME;
static uint16_t ftvh_payload 		= CefC_T_PAYLOAD;
static uint16_t ftvh_nameseg 		= CefC_T_NAMESEGMENT;
static uint16_t ftvh_ipid 			= CefC_T_IPID;
static uint16_t ftvh_chunk 			= CefC_T_CHUNK;
static uint16_t ftvh_nonce 			= CefC_T_NONCE;
static uint16_t ftvh_symcode 		= CefC_T_SYMBOLIC_CODE;
static uint16_t ftvh_meta 			= CefC_T_META;
static uint16_t ftvh_payldtype 		= CefC_T_PAYLDTYPE;
static uint16_t ftvh_expiry 		= CefC_T_EXPIRY;
static uint16_t ftvh_endchunk 		= CefC_T_ENDChunk;

/***** for hop-by-hop option header 	*****/
static uint16_t ftvh_intlife 		= CefC_T_OPT_INTLIFE;
static uint16_t ftvh_rct 			= CefC_T_OPT_CACHETIME;
static uint16_t ftvh_seqnum 		= CefC_T_OPT_SEQNUM;
static uint16_t ftvh_msghash 		= CefC_T_OPT_MSGHASH;
static uint16_t ftvh_ping_req 		= CefC_T_OPT_PING_REQ;
static uint16_t ftvh_trace_req		= CefC_T_OPT_TRACE_REQ;
static uint16_t ftvh_trace_rpt		= CefC_T_OPT_TRACE_RPT;
static uint16_t ftvh_org 			= CefC_T_OPT_ORG;
static uint16_t ftvh_symbolic 		= CefC_T_OPT_SYMBOLIC;
static uint16_t ftvh_longlife 		= CefC_T_OPT_LONGLIFE;
static uint16_t ftvh_innovate 		= CefC_T_OPT_INNOVATIVE;
static uint16_t ftvh_number 		= CefC_T_OPT_NUMBER;
static uint16_t ftvh_piggyback 		= CefC_T_OPT_PIGGYBACK;
static uint16_t ftvh_app_reg 		= CefC_T_OPT_APP_REG;
static uint16_t ftvh_app_dereg 		= CefC_T_OPT_APP_DEREG;
static uint16_t ftvh_transport 		= CefC_T_OPT_TRANSPORT;
static uint16_t ftvh_efi 			= CefC_T_OPT_EFI;
static uint16_t ftvh_iur 			= CefC_T_OPT_IUR;

/***** for Validation Algorithm 		*****/
static uint16_t ftvh_crc32 			= CefC_T_CRC32C;
static uint16_t ftvh_hmac_sha256 	= CefC_T_HMAC_SHA256;
static uint16_t ftvh_rsa_sha256 	= CefC_T_RSA_SHA256;
static uint16_t ftvh_ecs_256 		= CefC_T_EC_SECP_256K1;
static uint16_t ftvh_ecs_384 		= CefC_T_EC_SECP_384R1;

static uint16_t ftvh_keyid 			= CefC_T_KEYID;
static uint16_t ftvh_pubkeyloc		= CefC_T_PUBLICKEYLOC;
static uint16_t ftvh_pubkey 		= CefC_T_PUBLICKEY;
static uint16_t ftvh_cert 			= CefC_T_CERT;
static uint16_t ftvh_link 			= CefC_T_LINK;
static uint16_t ftvh_keylink		= CefC_T_KEYLINK;
static uint16_t ftvh_sigtime		= CefC_T_SIGTIME;


/*------------------------------------------------------------------
	the value of type field in network-byte-order
 -------------------------------------------------------------------*/

/***** for Common 						*****/
static uint16_t ftvn_1byte;
static uint16_t ftvn_2byte;
static uint16_t ftvn_4byte;
static uint16_t ftvn_8byte;
static uint16_t ftvn_32byte;

/***** for Cefore Message 				*****/
static uint16_t ftvn_pktype_int;
static uint16_t ftvn_pktype_obj;
static uint16_t ftvn_valid_alg;
static uint16_t ftvn_valid_pld;
static uint16_t ftvn_pktype_ping;
static uint16_t ftvn_pktype_trace;
static uint16_t ftvn_name;
static uint16_t ftvn_payload;
static uint16_t ftvn_nameseg;
static uint16_t ftvn_ipid;
static uint16_t ftvn_chunk;
static uint16_t ftvn_nonce;
static uint16_t ftvn_symcode;
static uint16_t ftvn_meta;
static uint16_t ftvn_payldtype;
static uint16_t ftvn_expiry;
static uint16_t ftvn_endchunk;

/***** for hop-by-hop option header 	*****/
static uint16_t ftvn_intlife;
static uint16_t ftvn_rct;
static uint16_t ftvn_seqnum;
static uint16_t ftvn_msghash;
static uint16_t ftvn_ping_req;
static uint16_t ftvn_trace_req;
static uint16_t ftvn_trace_rpt;
static uint16_t ftvn_org;
static uint16_t ftvn_symbolic;
static uint16_t ftvn_longlife;
static uint16_t ftvn_innovate;
static uint16_t ftvn_number;
static uint16_t ftvn_piggyback;
static uint16_t ftvn_app_reg;
static uint16_t ftvn_app_dereg;
static uint16_t ftvn_transport;
static uint16_t ftvn_efi;
static uint16_t ftvn_iur;

/***** for Validation Algorithm 		*****/

static uint16_t ftvn_crc32;
static uint16_t ftvn_hmac_sha256;
static uint16_t ftvn_rsa_sha256;
static uint16_t ftvn_ecs_256;
static uint16_t ftvn_ecs_384;

static uint16_t ftvn_keyid;
static uint16_t ftvn_pubkeyloc;
static uint16_t ftvn_pubkey;
static uint16_t ftvn_cert;
static uint16_t ftvn_link;
static uint16_t ftvn_keylink;
static uint16_t ftvn_sigtime;

/*------------------------------------------------------------------
	size of value fields
 -------------------------------------------------------------------*/
static uint16_t flvh_lifetime 	= CefC_S_Lifetime;
static uint16_t flvh_chunknum 	= CefC_S_ChunkNum;
static uint16_t flvh_nonce 		= CefC_S_Nonce;
static uint16_t flvh_symcode 	= CefC_S_Symbolic_Code;
static uint16_t flvh_innovate 	= CefC_S_Innovate;
static uint16_t flvh_number 	= CefC_S_Number;
static uint16_t flvh_cachetime 	= CefC_S_Cachetime;
static uint16_t flvh_expiry 	= CefC_S_Expiry;
static uint16_t flvh_rct 		= CefC_S_RCT;
static uint16_t flvh_seqnum 	= CefC_S_SeqNum;

static uint16_t flvn_lifetime;
static uint16_t flvn_chunknum;
static uint16_t flvn_nonce;
static uint16_t flvn_symcode;
static uint16_t flvn_innovate;
static uint16_t flvn_number;
static uint16_t flvn_cachetime;
static uint16_t flvn_expiry;
static uint16_t flvn_rct;
static uint16_t flvn_seqnum;

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Creates the Link Message template
----------------------------------------------------------------------------------------*/
static void
cef_frame_link_msg_prepare (
	void
);
/*--------------------------------------------------------------------------------------
	Parses an Invalid TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_invalid_tlv_parse (
	CefT_Parsed_Message* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);
/*--------------------------------------------------------------------------------------
	Parses a Name TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_name_tlv_parse (
	CefT_Parsed_Message* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);
/*--------------------------------------------------------------------------------------
	Parses a ExpiryTime TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_expiry_tlv_parse (
	CefT_Parsed_Message* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);
/*--------------------------------------------------------------------------------------
	Parses a Payload TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_payload_tlv_parse (
	CefT_Parsed_Message* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);

/*--------------------------------------------------------------------------------------
	Parses a KeyIdRestriction TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_keyidrestr_tlv_parse (
	CefT_Parsed_Message* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);
/*--------------------------------------------------------------------------------------
	Parses a ContentObjectHashRestriction TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_objhashrestr_tlv_parse (
	CefT_Parsed_Message* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);
/*--------------------------------------------------------------------------------------
	Parses a PayloadType TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_payloadtype_tlv_parse (
	CefT_Parsed_Message* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);

static int									/* No care now								*/
(*cef_frame_message_tlv_parse[CefC_T_MSG_TLV_NUM]) (
	CefT_Parsed_Message* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) = {
	cef_frame_message_name_tlv_parse,
	cef_frame_message_payload_tlv_parse,
	cef_frame_message_keyidrestr_tlv_parse,
	cef_frame_message_objhashrestr_tlv_parse,
	cef_frame_message_invalid_tlv_parse,
	cef_frame_message_payloadtype_tlv_parse,
	cef_frame_message_expiry_tlv_parse
};
/*--------------------------------------------------------------------------------------
	Parses an Invalid TLV in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_invalid_tlv_parse (
	CefT_Parsed_Opheader* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);
/*--------------------------------------------------------------------------------------
	Parses an Interest Lifetime TLV in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_lifetime_tlv_parse (
	CefT_Parsed_Opheader* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);
/*--------------------------------------------------------------------------------------
	Parses a Cache Time TLV in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_cachetime_tlv_parse (
	CefT_Parsed_Opheader* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);
/*--------------------------------------------------------------------------------------
	Parses a Message Hash TLV in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_msghash_tlv_parse (
	CefT_Parsed_Opheader* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);
/*--------------------------------------------------------------------------------------
	Parses a Cefping TLV in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_cefping_tlv_parse (
	CefT_Parsed_Opheader* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);
/*--------------------------------------------------------------------------------------
	Parses a Cefinfo Request Block in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_trace_req_tlv_parse (
	CefT_Parsed_Opheader* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);
/*--------------------------------------------------------------------------------------
	Parses a Cefinfo Report Block in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_trace_rep_tlv_parse (
	CefT_Parsed_Opheader* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);

static int									/* No care now								*/
(*cef_frame_opheader_tlv_parse[CefC_T_OPT_TLV_NUM]) (
	CefT_Parsed_Opheader* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) = {
	cef_frame_opheader_invalid_tlv_parse,
	cef_frame_opheader_lifetime_tlv_parse,
	cef_frame_opheader_cachetime_tlv_parse,
	cef_frame_opheader_msghash_tlv_parse,
	cef_frame_opheader_invalid_tlv_parse,
	cef_frame_opheader_invalid_tlv_parse,
	cef_frame_opheader_invalid_tlv_parse,
	cef_frame_opheader_invalid_tlv_parse,
	cef_frame_opheader_trace_req_tlv_parse,
	cef_frame_opheader_trace_rep_tlv_parse,
	cef_frame_opheader_cefping_tlv_parse
};
/*--------------------------------------------------------------------------------------
	Parses a User Specific TLV in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_user_tlv_parse (
	CefT_Parsed_Opheader* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t type, 							/* Type of this TLV						*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);

/*--------------------------------------------------------------------------------------
	Creates the Option Header of Interest
----------------------------------------------------------------------------------------*/
static uint16_t								/* Length of Option Header					*/
cef_frame_interest_opt_header_create (
	unsigned char* buff, 					/* buffer to set a message					*/
	CefT_Interest_TLVs* tlvs				/* Parameters to set Interest 				*/
);
/*--------------------------------------------------------------------------------------
	Creates the Option Header of Content Object
----------------------------------------------------------------------------------------*/
static uint16_t								/* Length of Option Header					*/
cef_frame_object_opt_header_create (
	unsigned char* buff, 					/* buffer to set a message					*/
	CefT_Object_TLVs* tlvs					/* Parameters to set Content Object			*/
);
#ifdef CefC_Cefping
/*--------------------------------------------------------------------------------------
	Creates the Option Header of Cefping Request
----------------------------------------------------------------------------------------*/
static uint16_t								/* Length of Option Header					*/
cef_frame_conpig_req_opt_header_create (
	unsigned char* buff, 					/* buffer to set a message					*/
	CefT_Ping_TLVs* tlvs					/* Parameters to set Cefping Request		*/
);
#endif // CefC_Cefping

#ifdef CefC_Cefinfo
/*--------------------------------------------------------------------------------------
	Creates the Option Header of Cefinfo Request
----------------------------------------------------------------------------------------*/
static uint16_t								/* Length of Option Header					*/
cef_frame_cefinfo_req_opt_header_create (
	unsigned char* buff, 					/* buffer to set a message					*/
	CefT_Trace_TLVs* tlvs					/* Parameters to set Cefinfo Request		*/
);
#endif // CefC_Cefinfo
/*--------------------------------------------------------------------------------------
	Creates the Validation Algorithm TLV
----------------------------------------------------------------------------------------*/
static uint16_t								/* Length of Option Header					*/
cef_frame_validation_alg_tlv_create (
	unsigned char* buff, 					/* buffer to set a message					*/
	CefT_Valid_Alg_TLVs* tlvs,				/* Parameters to set Interest 				*/
	unsigned char* name, 
	int name_len
);
/*--------------------------------------------------------------------------------------
	Creates the Validation Payload TLV
----------------------------------------------------------------------------------------*/
static uint16_t								/* Length of Option Header					*/
cef_frame_validation_pld_tlv_create (
	unsigned char* buff, 					/* buffer to set a message					*/
	uint16_t buff_len, 
	unsigned char* name, 
	int name_len, 
	CefT_Valid_Alg_TLVs* tlvs				/* Parameters to set Interest 				*/
);
/*--------------------------------------------------------------------------------------
	Creates the Default Name template
----------------------------------------------------------------------------------------*/
static void
cef_frame_default_name_prepare (
	void
);
/*--------------------------------------------------------------------------------------
	Obtains the default Name (cef:/ or cef://)
----------------------------------------------------------------------------------------*/
static int 									/* Length of the default Name				*/
cef_frame_default_name_get (
	unsigned char* buff 					/* buffer to set a message					*/
);
#ifdef CefC_Ser_Log
/*--------------------------------------------------------------------------------------
	Parses a ORG TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_user_tlv_parse (
	CefT_Parsed_Message* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);
#endif // CefC_Ser_Log

// static void
// cef_frame_tlv_print (
// 	const unsigned char* tlv
// );

/****************************************************************************************
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Initialize the frame module
----------------------------------------------------------------------------------------*/
void
cef_frame_init (
	void
){
	/* Prepares values of fields 					*/
	ftvn_1byte 		= htons (ftvh_1byte);
	ftvn_2byte 		= htons (ftvh_2byte);
	ftvn_4byte 		= htons (ftvh_4byte);
	ftvn_8byte 		= htons (ftvh_8byte);
	ftvn_32byte 	= htons (ftvh_32byte);
	
	ftvn_pktype_int 	= htons (ftvh_pktype_int);
	ftvn_pktype_obj 	= htons (ftvh_pktype_obj);
	ftvn_valid_alg 		= htons (ftvh_valid_alg);
	ftvn_valid_pld 		= htons (ftvh_valid_pld);
	ftvn_pktype_ping 	= htons (ftvh_pktype_ping);
	ftvn_pktype_trace 	= htons (ftvh_pktype_trace);

	ftvn_name 			= htons (ftvh_name);
	ftvn_payload 		= htons (ftvh_payload);
	ftvn_nameseg 		= htons (ftvh_nameseg);
	ftvn_ipid 			= htons (ftvh_ipid);
	ftvn_chunk 			= htons (ftvh_chunk);
	ftvn_nonce 			= htons (ftvh_nonce);
	ftvn_symcode		= htons (ftvh_symcode);
	ftvn_meta 			= htons (ftvh_meta);
	ftvn_payldtype 		= htons (ftvh_payldtype);
	ftvn_expiry 		= htons (ftvh_expiry);
	ftvn_endchunk 		= htons (ftvh_endchunk);
	ftvn_intlife 		= htons (ftvh_intlife);
	ftvn_seqnum 		= htons (ftvh_seqnum);
	ftvn_rct 			= htons (ftvh_rct);
	ftvn_msghash 		= htons (ftvh_msghash);
	ftvn_ping_req 		= htons (ftvh_ping_req);
	ftvn_trace_req 		= htons (ftvh_trace_req);
	ftvn_trace_rpt 		= htons (ftvh_trace_rpt);
	ftvn_org 			= htons (ftvh_org);
	ftvn_longlife 		= htons (ftvh_longlife);
	ftvn_innovate 		= htons (ftvh_innovate);
	ftvn_number 		= htons (ftvh_number);
	ftvn_piggyback 		= htons (ftvh_piggyback);
	ftvn_app_reg 		= htons (ftvh_app_reg);
	ftvn_app_dereg 		= htons (ftvh_app_dereg);
	ftvn_symbolic 		= htons (ftvh_symbolic);
	ftvn_transport 		= htons (ftvh_transport);
	ftvn_efi 			= htons (ftvh_efi);
	ftvn_iur 			= htons (ftvh_iur);

	ftvn_crc32 			= htons (ftvh_crc32);
	ftvn_hmac_sha256 	= htons (ftvh_hmac_sha256);
	ftvn_rsa_sha256 	= htons (ftvh_rsa_sha256);
	ftvn_ecs_256 		= htons (ftvh_ecs_256);
	ftvn_ecs_384 		= htons (ftvh_ecs_384);

	ftvn_keyid 			= htons (ftvh_keyid);
	ftvn_pubkeyloc 		= htons (ftvh_pubkeyloc);
	ftvn_pubkey 		= htons (ftvh_pubkey);
	ftvn_cert 			= htons (ftvh_cert);
	ftvn_link 			= htons (ftvh_link);
	ftvn_keylink 		= htons (ftvh_keylink);
	ftvn_sigtime 		= htons (ftvh_sigtime);
	
	flvn_lifetime 		= htons (flvh_lifetime);
	flvn_chunknum 		= htons (flvh_chunknum);
	flvn_nonce 			= htons (flvh_nonce);
	flvn_symcode 		= htons (flvh_symcode);
	flvn_innovate 		= htons (flvh_innovate);
	flvn_number	 		= htons (flvh_number);
	flvn_cachetime		= htons (flvh_cachetime);
	flvn_expiry 		= htons (flvh_expiry);
	flvn_rct			= htons (flvh_rct);
	flvn_seqnum			= htons (flvh_seqnum);

	/* Creates the Link Message template			*/
	cef_frame_link_msg_prepare ();

	/* Creates the Default Name template			*/
	cef_frame_default_name_prepare ();
}
/*--------------------------------------------------------------------------------------
	Parses a message
----------------------------------------------------------------------------------------*/
int 										/* Returns a negative value if it fails 	*/
cef_frame_message_parse (
	unsigned char* msg, 					/* the message to parse						*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len, 					/* Header Length of this message			*/
	CefT_Parsed_Opheader* poh, 				/* Structure to set parsed Option Header(s)	*/
	CefT_Parsed_Message* pm, 				/* Structure to set parsed CEFORE message	*/
	int target_type							/* Type of the message to expect			*/
) {
	unsigned char* smp;
	unsigned char* emp;
	unsigned char* wmp;
	uint16_t length;
	uint16_t type;
	uint16_t offset;
	int res;
	struct tlv_hdr* thdr;

#ifdef CefC_Dbg_Tpp_Tlvs
	if (CEF_DEBUG & CefC_Dbg_Tpp_Tlvs) {
		cef_print ("%s():type=%d, header_len=%u, payload_len=%u\n"
			, __func__, target_type, header_len, payload_len);
	}
#endif // CefC_Dbg_Tpp_Tlvs

	memset (poh, 0, sizeof (CefT_Parsed_Opheader));
	memset (pm, 0, sizeof (CefT_Parsed_Message));

	/*----------------------------------------------------------------------*/
	/* Parses Option Header				 									*/
	/*----------------------------------------------------------------------*/
	smp = msg + CefC_S_Fix_Header;
	offset = CefC_S_Fix_Header;
	length = msg[CefC_O_Fix_HeaderLength] - CefC_S_Fix_Header;

	wmp = smp;
	emp = smp + length;

	while (wmp < emp) {
		thdr = (struct tlv_hdr*) &wmp[CefC_O_Type];
		type   = ntohs (thdr->type);
		length = ntohs (thdr->length);

		if ((type > CefC_T_OPT_INVALID) && (type < CefC_T_OPT_TLV_NUM)) {
			(*cef_frame_opheader_tlv_parse[type])(poh, length, &wmp[4], offset);
		} else if ((type >= CefC_T_OPT_ORG) && (type < CefC_T_OPT_USR_TLV_NUM)) {
			cef_frame_opheader_user_tlv_parse (poh, type, length, &wmp[4], offset);
		}
		wmp += CefC_S_TLF + length;
		offset += CefC_S_TLF + length;
	}

	/*----------------------------------------------------------------------*/
	/* Parses CEFORE message 												*/
	/*----------------------------------------------------------------------*/
	smp = msg + header_len;

	thdr = (struct tlv_hdr*) &smp[CefC_O_Type];
	pm->pkt_type = ntohs (thdr->type);
	length = ntohs (thdr->length);

	if (length + CefC_S_TLF > payload_len) {
		return (-1);
	}

	wmp = smp + CefC_S_TLF;
	emp = wmp + length;
	offset = header_len + CefC_S_TLF;

	while (wmp < emp) {
		thdr = (struct tlv_hdr*) &wmp[CefC_O_Type];
		type   = ntohs (thdr->type);
		length = ntohs (thdr->length);

		if (type < CefC_T_MSG_TLV_NUM) {
			res = (*cef_frame_message_tlv_parse[type])(
										pm, length, &wmp[CefC_O_Value], offset);
			if (res < 0) {
				return (-1);
			}
#ifdef CefC_Ser_Log
		} else if (type == CefC_T_OPT_ORG) {
			res = cef_frame_message_user_tlv_parse (
						pm, length, &wmp[CefC_O_Value], offset);
			if (res < 0) {
				return (-1);
			}
#endif // CefC_Ser_Log
		}
		wmp += CefC_S_TLF + length;
		offset += CefC_S_TLF + length;
	}

	/*----------------------------------------------------------------------*/
	/* Parses Fixed Header			 										*/
	/*----------------------------------------------------------------------*/
	if ((target_type == CefC_PT_INTEREST) ||
		(target_type == CefC_PT_TRACE_REQ) ||
		(target_type == CefC_PT_PING_REQ)) {
		pm->hoplimit = msg[CefC_O_Fix_HopLimit];
		if (pm->hoplimit < 1) {
			return (-1);
		}
	}
#ifdef CefC_Cefping
	if (target_type == CefC_PT_PING_REP) {
		pm->ping_retcode = msg[CefC_O_Fix_Ping_RetCode];
	}
#endif // CefC_Cefping

	return (1);
}
/*--------------------------------------------------------------------------------------
	Parses a payload form the specified message
----------------------------------------------------------------------------------------*/
void 
cef_frame_payload_parse (
	unsigned char* msg, 
	uint16_t msg_len, 
	uint16_t* name_offset, 
	uint16_t* name_len, 
	uint16_t* payload_offset, 
	uint16_t* payload_len
) {
	struct fixed_hdr* fhp;
	struct tlv_hdr* thdr;
	uint16_t index;
	uint16_t x;
	uint16_t pkt_len;
	uint16_t length;
	uint16_t type;
	
	*name_offset 	= 0;
	*name_len 		= 0;
	*payload_offset = 0;
	*payload_len 	= 0;
	
	/* check the header and packet length 		*/
	fhp = (struct fixed_hdr*) &msg[0];
	pkt_len = ntohs (fhp->pkt_len);
	
	if (pkt_len != msg_len) {
		fprintf (stderr, "###### %d (%d)\n", pkt_len, msg_len);
		return;
	}
	index = fhp->hdr_len + CefC_S_TLF;
	
	/* check the name		*/
	thdr   = (struct tlv_hdr*) &msg[index];
	type   = ntohs (thdr->type);
	length = ntohs (thdr->length);
	
	if (type != CefC_T_NAME) {
		fprintf (stderr, "###### NAME\n");
		return;
	}
	*name_offset = index + CefC_S_TLF;
	*name_len    = length;
	
	x = index + CefC_S_TLF;
	index += CefC_S_TLF + length;
	
	while (x < msg_len) {
		thdr   = (struct tlv_hdr*) &msg[x];
		type   = ntohs (thdr->type);
		length = ntohs (thdr->length);
		
		if (type != CefC_T_NAMESEGMENT) {
			*name_len -= (index - x);
			break;
		}
		x += CefC_S_TLF + length;
	}
	
	while (index < msg_len) {
		thdr = (struct tlv_hdr*) &msg[index];
		type   = ntohs (thdr->type);
		length = ntohs (thdr->length);
		
		if (type != CefC_T_PAYLOAD) {
			index += CefC_S_TLF + length;
			continue;
		}
		*payload_offset = index + CefC_S_TLF;
		*payload_len 	= length;
		break;
	}
	
	return;
}
/*--------------------------------------------------------------------------------------
	Converts the URI to Name
----------------------------------------------------------------------------------------*/
int											/* Length of Name 							*/
cef_frame_conversion_uri_to_name (
	const char* inuri, 						/* URI										*/
	unsigned char* name						/* buffer to set Name 						*/
) {
	unsigned char* ruri = (unsigned char*) inuri;
	unsigned char* wp = name;

	unsigned char* curi;
	unsigned char* suri;
	uint16_t value;

	char protocol[1024];
	uint16_t name_len, prot_len, n;

	strcpy (protocol, "cef");

	/* Parses the prefix of Name 	*/
	if (memcmp (cefprefix2, ruri, cefprefix2_len) == 0) {
		/* prefix is "cef://" 		*/
		curi = ruri + cefprefix2_len;
	} else if (memcmp (cefprefix1, ruri, cefprefix1_len) == 0) {
		/* prefix is "cef:/" 		*/
		curi = ruri + cefprefix1_len;
	} else {
		/* prefix is "xxxxx:/" or "xxxxx://" or none */
		curi = ruri;
		name_len = strlen ((const char*) ruri);
		prot_len = 0;

		for (n = 0 ; n < name_len ; n++) {
			if (curi[n] != ':') {
				protocol[prot_len] = curi[n];
				prot_len++;
			} else {
				protocol[prot_len] = 0x00;
				break;
			}
		}
		if (n == name_len) {
			if (curi[0] != '/') {
				curi = ruri;
			} else {
				curi = ruri + 1;
			}
			strcpy (protocol, "cef");
		} else {
			if (curi[prot_len + 1] != '/') {
				return (-1);
			} else {
				if (curi[prot_len + 2] != '/') {
					curi = ruri + prot_len + 2;
				} else {
					curi = ruri + prot_len + 3;
				}
			}
		}
	}
	suri = curi;

	if (*curi == 0x00) {
		value = cef_frame_default_name_get (name);
		return ((int) value);
	}

	while (*curi) {
		if ((*curi < 0x2c) ||
			((*curi > 0x2d) && (*curi < 0x2f)) ||
			((*curi > 0x39) && (*curi < 0x41)) ||
			((*curi > 0x5a) && (*curi < 0x61)) ||
			(*curi > 0x7a)) {
			return (-1);
		}
		ruri = curi + 1;

		if ((*curi == 0x2f) || (*ruri == 0x00)) {
			if (*ruri == 0x2f) {
				return (-1);
			}
			if ((*ruri == 0x00) && (*curi != 0x2f)) {
				curi++;
			}
			memcpy (wp, &ftvn_nameseg, CefC_S_Type);
			wp += CefC_S_Type;
			value = (uint16_t)(curi - suri);
			value = htons (value);
			memcpy (wp, &value, CefC_S_Length);
			wp += CefC_S_Length;
			while (suri < curi) {
				*wp = *suri;
				wp++;
				suri++;
			}
			if (*curi == 0x2f) {
				suri++;
			}
			if (*curi == 0x00) {
				break;
			}
		}
		curi++;
	}

	return ((int)(wp - name));
}
/*--------------------------------------------------------------------------------------
	Creates the Interest from the specified Parameters
----------------------------------------------------------------------------------------*/
int 										/* Length of Interest message 				*/
cef_frame_interest_create (
	unsigned char* buff, 					/* buffer to set Interest					*/
	CefT_Interest_TLVs* tlvs				/* Parameters to set Interest 				*/
) {
	struct fixed_hdr fix_hdr;
	struct tlv_hdr fld_thdr;
	struct value32_tlv value32_fld;
	struct value32x2_tlv value32x2_fld;
	struct value64_tlv value64_fld;
	uint16_t opt_header_len;
	uint16_t payload_len;
	uint16_t index = 0;
	uint16_t rec_index;

	/*----------------------------------------------------------*/
	/* Option Header 											*/
	/*----------------------------------------------------------*/
	/* Constructs the option header */
	opt_header_len = cef_frame_interest_opt_header_create (
											&buff[CefC_S_Fix_Header], tlvs);

	index = CefC_S_Fix_Header + opt_header_len;

	/*----------------------------------------------------------*/
	/* CEFORE message 											*/
	/*----------------------------------------------------------*/
	index += CefC_S_TLF;

	/*=========================================
		NAME TLV
	===========================================*/
	if (tlvs->name_len < CefC_S_TLF + 1) {
		return (0);
	}
	/* Records top index of Name TLV	*/
	rec_index = index;
	index += CefC_S_TLF + tlvs->name_len;

	/* Sets chunk number	*/
	if (tlvs->chunk_num_f) {
		value32_fld.type   = ftvn_chunk;
		value32_fld.length = flvn_chunknum;
		value32_fld.value  = htonl (tlvs->chunk_num);
		memcpy (&buff[index], &value32_fld, sizeof (struct value32_tlv));
		index += CefC_S_TLF + CefC_S_ChunkNum;
	}

	/* Sets Nonce			*/
	if (tlvs->nonce_f) {
		value64_fld.type   = ftvn_nonce;
		value64_fld.length = flvn_nonce;
		value64_fld.value  = cef_frame_htonb (tlvs->nonce);
		memcpy (&buff[index], &value64_fld, sizeof (struct value64_tlv));
		index += CefC_S_TLF + CefC_S_Nonce;
	}

	/* Sets Symbolic Code	*/
	if (tlvs->symbolic_code_f) {
		value32x2_fld.type 		= ftvn_symcode;
		value32x2_fld.length 	= flvn_symcode;
		value32x2_fld.value1  	= htonl (tlvs->min_seq);
		value32x2_fld.value2  	= htonl (tlvs->max_seq);
		memcpy (&buff[index], &value32x2_fld, sizeof (struct value32x2_tlv));
		index += CefC_S_TLF + CefC_S_Symbolic_Code;
	}

	/* Sets App Components */
	if ((tlvs->app_comp >= CefC_T_APP_MIN) &&
		(tlvs->app_comp <= CefC_T_APP_MAX)) {
		fld_thdr.type 	= htons (tlvs->app_comp);
		fld_thdr.length = htons (tlvs->app_comp_len);

		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		index += CefC_S_TLF;

		if (tlvs->app_comp_len) {
			memcpy (&buff[index], tlvs->app_comp_val, tlvs->app_comp_len);
			index += tlvs->app_comp_len;
		}
	}

	/* Sets T_NAME		*/
	fld_thdr.type 	= ftvn_name;
	fld_thdr.length = htons (index - (rec_index + CefC_S_TLF));
	memcpy (&buff[rec_index], &fld_thdr, sizeof (struct tlv_hdr));
	memcpy (&buff[rec_index + CefC_O_Value], tlvs->name, tlvs->name_len);

	/*=========================================
		PAYLOAD TLV (only piggyback)
	===========================================*/
	if ((tlvs->opt.symbolic_f == CefC_T_OPT_PIGGYBACK) &&
		(tlvs->cob_len > 0)) {
		fld_thdr.type   = ftvn_payload;
		fld_thdr.length = htons (tlvs->cob_len);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		memcpy (&buff[index + CefC_O_Value], tlvs->cob, tlvs->cob_len);
		index += CefC_S_TLF + tlvs->cob_len;
	}

#ifdef CefC_Android
	/*=========================================
		ORG TLV (only Android)
	===========================================*/
	/*
		+---------------+---------------+---------------+---------------+
		|             T_ORG             |              11               |
		+---------------+---------------+---------------+---------------+
		|     PEN[0]    |     PEN[1]    |     PEN[2]    |   T_SER_LOG   /
		+---------------+---------------+---------------+---------------+
		/               |               4               |    CRC32      /
		+---------------+-------------------------------+---------------+
		/                                               |
		+-----------------------------------------------+
	*/
	/* Insert T_ORG Field. IANA Private Enterprise Numbers is 51564. */
	fld_thdr.type = ftvn_org;
	fld_thdr.length = htons (11);
	memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
	index += CefC_S_TLF;
	/* Insert 564 */
	buff[index] = 5;
	buff[index + 1] = 6;
	buff[index + 2] = 4;
	index += 3;
	/* Original field (Serial Log) */
	value32_fld.type = htons (CefC_T_SER_LOG);
	value32_fld.length = ftvn_4byte;
	/* Value is Android sirial num (CRC32) */
	value32_fld.value = htonl (cef_android_serial_num_get ());
	memcpy (&buff[index], &value32_fld, sizeof (struct value32_tlv));
	index += sizeof (struct value32_tlv);
#endif // CefC_Android

	/*=========================================
		CEFORE message header
	===========================================*/
	payload_len =
		index - (CefC_S_Fix_Header + opt_header_len + CefC_S_TLF);
	fld_thdr.length = htons (payload_len);
	fld_thdr.type 	= ftvn_pktype_int;
	memcpy (
		&buff[CefC_S_Fix_Header + opt_header_len], &fld_thdr, sizeof (struct tlv_hdr));

	/*----------------------------------------------------------*/
	/* Validations	 											*/
	/*----------------------------------------------------------*/
	rec_index = index;
	index += cef_frame_validation_alg_tlv_create (
					&buff[index], &tlvs->alg, tlvs->name, tlvs->name_len);
	if (rec_index != index) {
		index += cef_frame_validation_pld_tlv_create (
			&buff[CefC_S_Fix_Header + opt_header_len], 
			index - (CefC_S_Fix_Header + opt_header_len), 
			tlvs->name, tlvs->name_len, &tlvs->alg);
	}
	
	/*----------------------------------------------------------*/
	/* Fixed Header												*/
	/*----------------------------------------------------------*/
	fix_hdr.version 	= CefC_Version;
	fix_hdr.type 		= CefC_PT_INTEREST;
	fix_hdr.pkt_len 	= htons (index);
	fix_hdr.hoplimit 	= tlvs->hoplimit;
	fix_hdr.reserve1 	= 0x00;
	fix_hdr.reserve2 	= 0x00;
	fix_hdr.hdr_len 	= CefC_S_Fix_Header + opt_header_len;

	memcpy (buff, &fix_hdr, sizeof (struct fixed_hdr));

	return (index);
}

/*--------------------------------------------------------------------------------------
	Creates the Content Object from the specified Parameters
----------------------------------------------------------------------------------------*/
int 										/* Length of Content Object message 		*/
cef_frame_object_create (
	unsigned char* buff, 					/* buffer to set Content Object				*/
	CefT_Object_TLVs* tlvs					/* Parameters to set Content Object 		*/
) {
	struct fixed_hdr fix_hdr;
	struct tlv_hdr fld_thdr;
	struct value32_tlv value32_fld;
	struct value64_tlv value64_fld;
	uint16_t opt_header_len;
	uint16_t payload_len;
	uint16_t index = 0;
	uint16_t rec_index;

	/*----------------------------------------------------------*/
	/* Option Header 											*/
	/*----------------------------------------------------------*/
	/* Constructs the option header */
	opt_header_len = cef_frame_object_opt_header_create (
											&buff[CefC_S_Fix_Header], tlvs);

	index = CefC_S_Fix_Header + opt_header_len;
#ifdef CefC_Dbg_Tpp_Tlvs
	if (CEF_DEBUG & CefC_Dbg_Tpp_Tlvs) {
		cef_print ("%s():index=%u, opt_header_len=%u, payload_len=%u\n", 
			__func__, index, opt_header_len, tlvs->payload_len);
	}
#endif // CefC_Dbg_Tpp_Tlvs

	/*----------------------------------------------------------*/
	/* CEFORE message 											*/
	/*----------------------------------------------------------*/
	index += CefC_S_TLF;

	/*=========================================
		NAME TLV
	===========================================*/
	if (tlvs->name_len < CefC_S_TLF + 1) {
		return (0);
	}

	/* Records top index of Name TLV	*/
	rec_index = index;
	index += CefC_S_TLF + tlvs->name_len;

	/* Sets ChunkNumber		*/
	if (tlvs->chnk_num_f) {
		value32_fld.type   = ftvn_chunk;
		value32_fld.length = flvn_chunknum;
		value32_fld.value  = htonl (tlvs->chnk_num);
		memcpy (&buff[index], &value32_fld, sizeof (struct value32_tlv));
		index += CefC_S_TLF + CefC_S_ChunkNum;
	}

	/* Sets Meta			*/
	if (tlvs->meta_len > 0) {
		fld_thdr.type   = ftvn_meta;
		fld_thdr.length = htons (tlvs->meta_len);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		memcpy (&buff[index + CefC_O_Value], tlvs->meta, tlvs->meta_len);
		index += CefC_S_TLF + tlvs->meta_len;
	}

	/* Sets T_NAME		*/
	fld_thdr.type 	= ftvn_name;
	fld_thdr.length = htons (index - (rec_index + CefC_S_TLF));
	memcpy (&buff[rec_index], &fld_thdr, sizeof (struct tlv_hdr));
	memcpy (&buff[rec_index + CefC_O_Value], tlvs->name, tlvs->name_len);

	/*----- EXPIRY TLV 			-----*/
	value64_fld.type   = ftvn_expiry;
	value64_fld.length = flvn_expiry;
	value64_fld.value  = cef_frame_htonb (tlvs->expiry);
	memcpy (&buff[index], &value64_fld, sizeof (struct value64_tlv));
	index += CefC_S_TLF + CefC_S_Expiry;

	/*----- PAYLOAD TLV 			-----*/
	if (tlvs->payload_len > 0) {
		fld_thdr.type   = ftvn_payload;
		fld_thdr.length = htons (tlvs->payload_len);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		memcpy (&buff[index + CefC_O_Value], tlvs->payload, tlvs->payload_len);
		index += CefC_S_TLF + tlvs->payload_len;
	}

	/*----- CEFORE message header 	-----*/
	payload_len =
		index - (CefC_S_Fix_Header + opt_header_len + CefC_S_TLF);
	fld_thdr.length = htons (payload_len);
	fld_thdr.type 	= ftvn_pktype_obj;
	memcpy (
		&buff[CefC_S_Fix_Header + opt_header_len], &fld_thdr, sizeof (struct tlv_hdr));

	/*----------------------------------------------------------*/
	/* Validations	 											*/
	/*----------------------------------------------------------*/
	rec_index = index;
	index += cef_frame_validation_alg_tlv_create (
					&buff[index], &tlvs->alg, tlvs->name, tlvs->name_len);
	if (rec_index != index) {
		index += cef_frame_validation_pld_tlv_create (
			&buff[CefC_S_Fix_Header + opt_header_len], 
			index - (CefC_S_Fix_Header + opt_header_len), 
			tlvs->name, tlvs->name_len, &tlvs->alg);
	}
	
	/*----------------------------------------------------------*/
	/* Frame Header 											*/
	/*----------------------------------------------------------*/
	fix_hdr.version 	= CefC_Version;
	fix_hdr.type 		= CefC_PT_OBJECT;
	fix_hdr.pkt_len 	= htons (index);
	fix_hdr.hoplimit 	= 0x00;
	fix_hdr.reserve1 	= 0x00;
	fix_hdr.reserve2 	= 0x00;
	fix_hdr.hdr_len 	= CefC_S_Fix_Header + opt_header_len;

	memcpy (buff, &fix_hdr, sizeof (struct fixed_hdr));

	return (index);
}
/*--------------------------------------------------------------------------------------
	Creates the Cefping Request from the specified Parameters
----------------------------------------------------------------------------------------*/
int 										/* Length of Cefping message 				*/
cef_frame_cefping_req_create (
	unsigned char* buff, 					/* buffer to set Cefping Request			*/
	CefT_Ping_TLVs* tlvs					/* Parameters to set Cefping Request 		*/
) {
#ifdef CefC_Cefping
	struct fixed_hdr fix_hdr;
	struct tlv_hdr fld_thdr;
	uint16_t opt_header_len;
	uint16_t msg_len;
	uint16_t index = 0;

	/*
		+---------------+---------------+---------------+---------------+
		|    Version    |  PT_PING_REQ  |         PacketLength          |
		+---------------+---------------+---------------+---------------+
		|    HopLimit   |            Reserved           | HeaderLength  |
		+---------------+---------------+---------------+---------------+
		|           T_PING_REQ          |            Length             |
		+---------------+---------------+---------------+---------------+
		|                      Responder Identifier                      /
		+---------------+---------------+---------------+---------------+
		|            T_PING             |            Length             |
		+---------------+---------------+---------------+---------------+
		|            T_NAME             |            Length             |
		+---------------+---------------+---------------+---------------+
		|                       Name segment TLVs                       /
		+---------------+---------------+---------------+---------------+
	*/

	/*----------------------------------------------------------*/
	/* Option Header 											*/
	/*----------------------------------------------------------*/
	/* Constructs the option header */
	opt_header_len = cef_frame_conpig_req_opt_header_create (
											&buff[CefC_S_Fix_Header], tlvs);
	index = CefC_S_Fix_Header + opt_header_len;

	/*----------------------------------------------------------*/
	/* CEFORE message 											*/
	/*----------------------------------------------------------*/
	index += CefC_S_TLF;

	/*----- NAME TLV 				-----*/
	if (tlvs->name_len < CefC_S_TLF + 1) {
		return (0);
	}
	fld_thdr.type 	= ftvn_name;
	fld_thdr.length = htons (tlvs->name_len);
	memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
	memcpy (&buff[index + CefC_O_Value], tlvs->name, tlvs->name_len);
	index += CefC_S_TLF + tlvs->name_len;

	/*----- CEFORE message header 	-----*/
	msg_len = index - (CefC_S_Fix_Header + opt_header_len + CefC_S_TLF);
	fld_thdr.length = htons (msg_len);
	fld_thdr.type   = ftvn_pktype_ping;
	memcpy (
		&buff[CefC_S_Fix_Header + opt_header_len], &fld_thdr, sizeof (struct tlv_hdr));

	/*----------------------------------------------------------*/
	/* Validations	 											*/
	/*----------------------------------------------------------*/
	// TBD

	/*----------------------------------------------------------*/
	/* Frame Header 											*/
	/*----------------------------------------------------------*/
	fix_hdr.version 	= CefC_Version;
	fix_hdr.type 		= CefC_PT_PING_REQ;
	fix_hdr.pkt_len 	= htons (index);
	fix_hdr.hoplimit 	= tlvs->hoplimit;
	fix_hdr.reserve1 	= 0x00;
	fix_hdr.reserve2 	= 0x00;
	fix_hdr.hdr_len 	= CefC_S_Fix_Header + opt_header_len;

	memcpy (buff, &fix_hdr, sizeof (struct fixed_hdr));

	return (index);
#else // CefC_Cefping
	return (0);
#endif // CefC_Cefping
}

/*--------------------------------------------------------------------------------------
	Creates the Cefping Replay from the specified Parameters
----------------------------------------------------------------------------------------*/
int 										/* Length of Cefping message 				*/
cef_frame_cefping_rep_create (
	unsigned char* buff, 					/* buffer to set Cefping Request			*/
	uint8_t ret_code,
	unsigned char* responder_id,
	uint16_t id_len,
	unsigned char* name,
	uint16_t name_len
) {
#ifdef CefC_Cefping
	struct fixed_hdr fix_hdr;
	struct tlv_hdr fld_thdr;
	uint16_t msg_len;
	uint16_t index = 0;

	/*
		+---------------+---------------+---------------+---------------+
		|    Version    |  PT_PING_REP  |         PacketLength          |
		+---------------+---------------+---------------+---------------+
		|            Reserved           |   ReturnCode  | HeaderLength  |
		+---------------+---------------+---------------+---------------+
		|            T_PING             |            Length             |
		+---------------+---------------+---------------+---------------+
		|            T_NAME             |            Length             |
		+---------------+---------------+---------------+---------------+
		|                       Name segment TLVs                       /
		+---------------+---------------+---------------+---------------+
		|           T_PAYLOAD           |            Length             |
		+---------------+---------------+---------------+---------------+
		|                      Responder Identifier                      /
		+---------------+---------------+---------------+---------------+
							figure: Cefping Reply
	*/

	/*----------------------------------------------------------*/
	/* Option Header 											*/
	/*----------------------------------------------------------*/
	/* Cefping Replay has no option header 		*/
	index = CefC_S_Fix_Header;

	/*----------------------------------------------------------*/
	/* CEFORE message 											*/
	/*----------------------------------------------------------*/
	index += CefC_S_TLF;

	/*----- NAME TLV 				-----*/
	if (name_len < CefC_S_TLF + 1) {
		return (0);
	}
	fld_thdr.type   = ftvn_name;
	fld_thdr.length = htons (name_len);
	memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
	memcpy (&buff[index + CefC_O_Value], name, name_len);
	index += CefC_S_TLF + name_len;

	/*----- PAYLOAD TLV 			-----*/
	fld_thdr.type   = ftvn_payload;
	fld_thdr.length = htons (id_len);
	memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
	memcpy (&buff[index + CefC_O_Value], responder_id, id_len);
	index += CefC_S_TLF + id_len;

	/*----- CEFORE message header 	-----*/
	msg_len = index - (CefC_S_Fix_Header + CefC_S_TLF);
	fld_thdr.length = htons (msg_len);
	fld_thdr.type   = ftvn_pktype_ping;
	memcpy (&buff[CefC_S_Fix_Header], &fld_thdr, sizeof (struct tlv_hdr));

	/*----------------------------------------------------------*/
	/* Validations	 											*/
	/*----------------------------------------------------------*/
	// TBD

	/*----------------------------------------------------------*/
	/* Frame Header 											*/
	/*----------------------------------------------------------*/
	fix_hdr.version 	= CefC_Version;
	fix_hdr.type 		= CefC_PT_PING_REP;
	fix_hdr.pkt_len 	= htons (index);
	fix_hdr.hoplimit 	= 0x00;
	fix_hdr.reserve1 	= 0x00;
	fix_hdr.reserve2 	= ret_code;
	fix_hdr.hdr_len 	= CefC_S_Fix_Header;

	memcpy (buff, &fix_hdr, sizeof (struct fixed_hdr));

	return (index);
#else // CefC_Cefping
	return (0);
#endif // CefC_Cefping
}

/*--------------------------------------------------------------------------------------
	Creates the Cefinfo Request from the specified Parameters
----------------------------------------------------------------------------------------*/
int 										/* Length of Cefinfo message 				*/
cef_frame_cefinfo_req_create (
	unsigned char* buff, 					/* buffer to set Cefinfo Request			*/
	CefT_Trace_TLVs* tlvs					/* Parameters to set Cefinfo Request 		*/
) {
#ifdef CefC_Cefinfo
	uint16_t opt_header_len;
	uint16_t index = 0;
	struct fixed_hdr fix_hdr;
	struct tlv_hdr fld_thdr;
	uint16_t msg_len;

	/*
		+---------------+---------------+---------------+---------------+
		|    Version    | PT_TRACE_REQ  |         PacketLength          |
		+---------------+---------------+---------------+---------------+
		|    HopLimit   |   ReturnCode  |Reserved (MBZ) | HeaderLength  |
		+===============+===============+===============+===============+
		|                                                               |
		+                       Request block TLV                       +
		|                                                               |
		+===============+===============+===============+===============+
		|            T_TRACE            |         MessageLength         |
		+---------------+---------------+---------------+---------------+
		|            T_NAME             |             Length            |
		+---------------+---------------+---------------+---------------+
		/                         Name segment TLVs                     /
		+---------------+---------------+---------------+---------------+
		/ Optional CCNx ValidationAlgorithm TLV                         /
		+---------------+---------------+---------------+---------------+
		/ Optional CCNx ValidationPayload TLV (ValidationAlg required)  /
		+---------------+---------------+---------------+---------------+
							figure: Cefinfo Request
	*/

	/*----------------------------------------------------------*/
	/* Option Header 											*/
	/*----------------------------------------------------------*/
	/* Constructs the option header */
	opt_header_len = cef_frame_cefinfo_req_opt_header_create (
											&buff[CefC_S_Fix_Header], tlvs);
	index = CefC_S_Fix_Header + opt_header_len;

	/*----------------------------------------------------------*/
	/* CEFORE message 											*/
	/*----------------------------------------------------------*/
	index += CefC_S_TLF;

	/*----- NAME TLV 				-----*/
	if (tlvs->name_len < CefC_S_TLF + 1) {
		return (0);
	}
	fld_thdr.type 	= ftvn_name;
	fld_thdr.length = htons (tlvs->name_len);
	memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
	memcpy (&buff[index + CefC_O_Value], tlvs->name, tlvs->name_len);
	index += CefC_S_TLF + tlvs->name_len;

	/*----- CEFORE message header 	-----*/
	msg_len = index - (CefC_S_Fix_Header + opt_header_len + CefC_S_TLF);
	fld_thdr.length = htons (msg_len);
	fld_thdr.type   = ftvn_pktype_trace;
	memcpy (
		&buff[CefC_S_Fix_Header + opt_header_len], &fld_thdr, sizeof (struct tlv_hdr));

	/*----------------------------------------------------------*/
	/* Validations	 											*/
	/*----------------------------------------------------------*/
	// TBD

	/*----------------------------------------------------------*/
	/* Fixed Header 											*/
	/*----------------------------------------------------------*/
	fix_hdr.version 	= CefC_Version;
	fix_hdr.type 		= CefC_PT_TRACE_REQ;
	fix_hdr.pkt_len 	= htons (index);
	fix_hdr.hoplimit 	= tlvs->hoplimit;;
	fix_hdr.reserve1 	= 0x00;
	fix_hdr.reserve2 	= 0x00;
	fix_hdr.hdr_len 	= CefC_S_Fix_Header + opt_header_len;

	memcpy (buff, &fix_hdr, sizeof (struct fixed_hdr));

	return (index);
#else // CefC_Cefinfo
	return (0);
#endif // CefC_Cefinfo
}
/*--------------------------------------------------------------------------------------
	Adds a time stamp on Cefinfo Request
----------------------------------------------------------------------------------------*/
int 										/* Length of Cefinfo message 				*/
cef_frame_cefinfo_req_add_stamp (
	unsigned char* buff, 					/* Cefinfo Request							*/
	uint16_t msg_len,
	unsigned char* node_id, 				/* Node ID 									*/
	uint16_t id_len, 						/* length of Node ID 						*/
	struct timeval t 						/* current time in UNIX-time(us) 			*/
) {
#ifdef CefC_Cefinfo
	unsigned char work[CefC_Max_Length];
	uint8_t header_len;
	uint16_t index;
	struct value64_tlv value64_tlv;
	struct fixed_hdr* fix_hdr;

	/*
		+---------------+---------------+---------------+---------------+
		|          T_TRACE_RPT          |             Length            |
		+---------------+---------------+---------------+---------------+
		|                     Request Arrival Time                      |
		+---------------+---------------+---------------+---------------+
		/                        Node Identifier                        /
		+---------------+---------------+---------------+---------------+
							figure: Report Block
	*/
	/* Copy the payload of Cefinfo Request 	*/
	header_len = buff[CefC_O_Fix_HeaderLength];
	memcpy (work, &buff[header_len], msg_len - header_len);

	/* Add a time stamp on the end of the option header 	*/
	value64_tlv.type 	= ftvn_trace_rpt;
	value64_tlv.length 	= htons (id_len + ftvh_8byte);
	value64_tlv.value 	= cef_client_htonb (t.tv_sec * 1000000 + t.tv_usec);
	memcpy (&buff[header_len], &value64_tlv, sizeof (struct value64_tlv));
	index = header_len + CefC_S_TLF + ftvh_8byte;

	memcpy (&buff[index], node_id, id_len);
	index += id_len;

	/* Sets the payload 			*/
	memcpy (&buff[index], work, msg_len - header_len);
	header_len = index;
	index = msg_len + CefC_S_TLF + ftvh_8byte + id_len;

	/* Updates PacketLength and HeaderLength 		*/
	fix_hdr = (struct fixed_hdr*) buff;
	fix_hdr->pkt_len = htons (index);
	fix_hdr->hdr_len = header_len;

	return (index);
#else // CefC_Cefinfo
	return (0);
#endif // CefC_Cefinfo
}

/*--------------------------------------------------------------------------------------
	Updates the sequence number
----------------------------------------------------------------------------------------*/
void
cef_frame_seqence_update (
	unsigned char* buff, 					/* packet									*/
	uint32_t seqnum
) {
	struct value32_tlv* value32_fld;
	uint16_t type;
	uint16_t length;

	value32_fld = (struct value32_tlv*) &buff[CefC_S_Fix_Header];
	type   = ntohs (value32_fld->type);
	length = ntohs (value32_fld->length);

	if ((type == CefC_T_OPT_SEQNUM) && (length == CefC_S_SeqNum)) {
		value32_fld->value = htonl (seqnum);
	}

	return;
}

/*--------------------------------------------------------------------------------------
	Updates the T_INNOVATIVE and T_NUMBER
----------------------------------------------------------------------------------------*/
void
cef_frame_innovative_update (
	unsigned char* buff, 					/* packet									*/
	uint32_t* bitmap,
	uint16_t bitmap_offset,
	uint32_t number,
	uint16_t number_offset
) {
	struct value32x8_tlv* val32x8_fld;
	struct value32_tlv* val32_fld;
	uint16_t type;
	uint16_t length;

	if (bitmap_offset) {
		val32x8_fld = (struct value32x8_tlv*) &buff[bitmap_offset];
		type   = ntohs (val32x8_fld->type);
		length = ntohs (val32x8_fld->length);

		if ((type == CefC_T_OPT_INNOVATIVE) && (length == CefC_S_Innovate)) {
			val32x8_fld->value1 = htonl (bitmap[0]);
			val32x8_fld->value2 = htonl (bitmap[1]);
			val32x8_fld->value3 = htonl (bitmap[2]);
			val32x8_fld->value4 = htonl (bitmap[3]);
			val32x8_fld->value5 = htonl (bitmap[4]);
			val32x8_fld->value6 = htonl (bitmap[5]);
			val32x8_fld->value7 = htonl (bitmap[6]);
			val32x8_fld->value8 = htonl (bitmap[7]);
		}
	}

	if (number_offset) {
		val32_fld = (struct value32_tlv*) &buff[number_offset];
		type   = ntohs (val32_fld->type);
		length = ntohs (val32_fld->length);

		if ((type == CefC_T_OPT_NUMBER) && (length == CefC_S_Number)) {
			val32_fld->value = htonl (number);
		}
	}

	return;
}

/*--------------------------------------------------------------------------------------
	Adds the Symbolic Code to the Content Object
----------------------------------------------------------------------------------------*/
int 										/* Length of Content Object					*/
cef_frame_symbolic_code_add (
	unsigned char* buff, 					/* Content Object							*/
	uint16_t msg_len, 						/* Length of Cob 							*/
	CefT_Parsed_Message* pm					/* Symbolic Code in TLV format 				*/
) {
	unsigned char work[CefC_Max_Length];
	uint8_t header_len;
	uint16_t index;
	struct fixed_hdr* fix_hdr;

	struct symbolic_code {
		uint16_t 	type1;
		uint16_t 	length1;
		uint16_t 	type2;
		uint16_t 	length2;
		uint32_t	value1;
		uint32_t	value2;
	} __attribute__((__packed__));

	struct symbolic_code fld_syb;

	/* Copy the payload of Content Object		*/
	header_len = buff[CefC_O_Fix_HeaderLength];
	index = header_len;
	memcpy (work, &buff[index], msg_len - header_len);

	/* Add the Symbolic Code on the end of the option header 	*/
	fld_syb.type1 		= ftvn_symbolic;
	fld_syb.length1 	= htons (CefC_S_TLF + CefC_S_Symbolic_Code);
	fld_syb.type2 		= htons (CefC_T_OPT_SCODE);
	fld_syb.length2 	= flvn_symcode;
	fld_syb.value1 		= htonl (pm->min_seq);
	fld_syb.value2 		= htonl (pm->max_seq);
	memcpy (&buff[index], &fld_syb, sizeof (struct symbolic_code));
	index += sizeof (struct symbolic_code);

	/* Sets the payload 			*/
	memcpy (&buff[index], work, msg_len - header_len);
	header_len = index;
	index = msg_len + sizeof (struct symbolic_code);

	/* Updates PacketLength and HeaderLength 		*/
	fix_hdr = (struct fixed_hdr*) buff;
	fix_hdr->pkt_len = htons (index);
	fix_hdr->hdr_len = header_len;

	return (index);
}

/*--------------------------------------------------------------------------------------
	Creates the Option Header of Interest
----------------------------------------------------------------------------------------*/
static uint16_t								/* Length of Option Header					*/
cef_frame_interest_opt_header_create (
	unsigned char* buff, 					/* buffer to set a message					*/
	CefT_Interest_TLVs* tlvs				/* Parameters to set Interest 				*/
) {
	unsigned int index = 0;
	unsigned int rec_index;
	struct tlv_hdr fld_thdr;
	struct value16_tlv value16_fld;
	struct value32_tlv value32_fld;
	uint32_t bitmap[8];
	uint32_t req_num;

	/* Sets Lifetime 				*/
	if (tlvs->opt.lifetime_f) {
		if (tlvs->opt.lifetime > 0) {
			value16_fld.type   = ftvn_intlife;
			value16_fld.length = ftvn_2byte;
			value16_fld.value  = htons (tlvs->opt.lifetime);
			memcpy (&buff[index], &value16_fld, sizeof (struct value16_tlv));
			index += CefC_S_TLF + ftvh_2byte;
		} else {
			fld_thdr.type 	= ftvn_intlife;
			fld_thdr.length = ftvn_1byte;
			memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
			buff[index + CefC_O_Value] = 0x00;
			index += CefC_S_TLF + ftvh_1byte;
		}
	}

	/* Sets the Long Life Variant 	*/
	rec_index = index;
	index += CefC_S_TLF;

	switch (tlvs->opt.symbolic_f) {
		case CefC_T_OPT_LONGLIFE: {
			fld_thdr.type 	= ftvn_longlife;
			fld_thdr.length = 0x0000;
			memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
			index += CefC_S_TLF;
			break;
		}
		case CefC_T_OPT_INNOVATIVE: {
			if ((tlvs->symbolic_code_f > 0) &&
				(tlvs->max_seq >= tlvs->min_seq)) {
				if (tlvs->opt.bitmap_f > 0) {
					bitmap[0] = htonl (tlvs->opt.bitmap[0]);
					bitmap[1] = htonl (tlvs->opt.bitmap[1]);
					bitmap[2] = htonl (tlvs->opt.bitmap[2]);
					bitmap[3] = htonl (tlvs->opt.bitmap[3]);
					bitmap[4] = htonl (tlvs->opt.bitmap[4]);
					bitmap[5] = htonl (tlvs->opt.bitmap[5]);
					bitmap[6] = htonl (tlvs->opt.bitmap[6]);
					bitmap[7] = htonl (tlvs->opt.bitmap[7]);
				} else {
					req_num = tlvs->max_seq - tlvs->min_seq + 1;
					BFF_SET(bitmap, req_num);
				}
				fld_thdr.type 	= ftvn_innovate;
				fld_thdr.length = flvn_innovate;
				memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
				memcpy (&buff[index + CefC_O_Value], bitmap, CefC_S_Innovate);
				index += CefC_S_TLF + CefC_S_Innovate;

				if (tlvs->opt.number > 0) {
					value32_fld.type 	= ftvn_number;
					value32_fld.length  = flvn_number;
					value32_fld.value 	= htonl (tlvs->opt.number);
					memcpy (&buff[index], &value32_fld, sizeof (struct value32_tlv));
					index += CefC_S_TLF + CefC_S_Number;
				}
			}
			break;
		}
		case CefC_T_OPT_PIGGYBACK: {
			if (tlvs->cob_len > 0) {
				fld_thdr.type 	= ftvn_piggyback;
				fld_thdr.length = 0x0000;
				memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
				index += CefC_S_TLF;
			}
			break;
		}
		case CefC_T_OPT_APP_REG: {
			fld_thdr.type 	= ftvn_app_reg;
			fld_thdr.length = 0x0000;
			memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
			index += CefC_S_TLF;
			break;
		}
		case CefC_T_OPT_APP_DEREG: {
			fld_thdr.type 	= ftvn_app_dereg;
			fld_thdr.length = 0x0000;
			memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
			index += CefC_S_TLF;
			break;
		}
		default: {
			/* NOP */;
			break;
		}
	}

	if (rec_index + CefC_S_TLF != index) {
		fld_thdr.type 	= ftvn_symbolic;
		fld_thdr.length = htons (index - (CefC_S_TLF + rec_index));
		memcpy (&buff[rec_index], &fld_thdr, sizeof (struct tlv_hdr));
	} else {
		index = rec_index;
	}

	/* Sets the Transport Variant 	*/
	if (tlvs->opt.tp_variant) {
		/* Sets the type and length fields of the top of Transport 		*/
		fld_thdr.type 	= ftvn_transport;
		fld_thdr.length = htons (CefC_S_TLF + tlvs->opt.tp_length);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		index += CefC_S_TLF;

		/* Sets the transport variant 	*/
		fld_thdr.type 	= htons (tlvs->opt.tp_variant);
		fld_thdr.length = htons (tlvs->opt.tp_length);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		if (tlvs->opt.tp_length > 0) {
			memcpy (&buff[index + CefC_O_Value], tlvs->opt.tp_value, tlvs->opt.tp_length);
		}
		index += CefC_S_TLF + tlvs->opt.tp_length;
	}

	/* Checks error 				*/
	if (index + CefC_S_Fix_Header > CefC_Max_Header_Size) {
		cef_log_write (CefC_Log_Warn, 
			"[frame] Size of the created Interest option header (%d bytes) is"
			" greater than 247 bytes\n", index);
		return (0);
	}

	return ((uint16_t) index);
}
/*--------------------------------------------------------------------------------------
	Creates the Option Header of Content Object
----------------------------------------------------------------------------------------*/
static uint16_t								/* Length of Option Header					*/
cef_frame_object_opt_header_create (
	unsigned char* buff, 					/* buffer to set a message					*/
	CefT_Object_TLVs* tlvs					/* Parameters to set Content Object			*/
) {
	unsigned int index = 0;
	struct tlv_hdr fld_thdr;
	struct value32_tlv value32_fld;
	struct value64_tlv value64_fld;

	/* Sets Sequence Number 				*/
	value32_fld.type   = ftvn_seqnum;
	value32_fld.length = flvn_seqnum;
	value32_fld.value  = 0;
	memcpy (&buff[index], &value32_fld, sizeof (struct value32_tlv));
	index += CefC_S_TLF + flvh_seqnum;

	/* Sets Recommended Cache Time (RCT)	*/
	if (tlvs->opt.cachetime_f) {
		value64_fld.type   = ftvn_rct;
		value64_fld.length = flvn_rct;
		value64_fld.value  = cef_frame_htonb (tlvs->opt.cachetime);
		memcpy (&buff[index], &value64_fld, sizeof (struct value64_tlv));

		index += CefC_S_TLF + flvh_rct;
	}

	/* Sets the Transport Variant 	*/
	if (tlvs->opt.tp_variant) {

		/* Sets the type and length fields of the top of Transport 		*/
		fld_thdr.type 	= ftvn_transport;
		fld_thdr.length = htons (CefC_S_TLF + tlvs->opt.tp_length);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		index += CefC_S_TLF;

		/* Sets the transport variant 	*/
		fld_thdr.type 	= htons (tlvs->opt.tp_variant);
		fld_thdr.length = htons (tlvs->opt.tp_length);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		if (tlvs->opt.tp_length > 0) {
			memcpy (&buff[index + CefC_O_Value], tlvs->opt.tp_value, tlvs->opt.tp_length);
		}
		index += CefC_S_TLF + tlvs->opt.tp_length;
	}

	if (index + CefC_S_Fix_Header > CefC_Max_Header_Size) {
		cef_log_write (CefC_Log_Warn, 
			"[frame] Size of the created Object option header (%d bytes) is"
			" greater than 247 bytes\n", index);
		return (0);
	}

	return ((uint16_t) index);
}
#ifdef CefC_Cefping
/*--------------------------------------------------------------------------------------
	Creates the Option Header of Cefping Request
----------------------------------------------------------------------------------------*/
static uint16_t								/* Length of Option Header					*/
cef_frame_conpig_req_opt_header_create (
	unsigned char* buff, 					/* buffer to set a message					*/
	CefT_Ping_TLVs* tlvs					/* Parameters to set Cefping Request		*/
) {
	unsigned int index = 0;
	struct tlv_hdr fld_thdr;

	/* Sets Responder Identifier		*/
	if (tlvs->opt.responder_f > 0) {
		fld_thdr.type 	= ftvn_ping_req;
		fld_thdr.length = htons (tlvs->opt.responder_f);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		memcpy (&buff[index + CefC_O_Value],
			tlvs->opt.responder_id, tlvs->opt.responder_f);

		index += CefC_S_TLF + tlvs->opt.responder_f;
	}

	if (index + CefC_S_Fix_Header > CefC_Max_Header_Size) {
		cef_log_write (CefC_Log_Warn, 
			"[frame] Size of the created Ping option header (%d bytes) is"
			" greater than 247 bytes\n", index);
		return (0);
	}

	return ((uint16_t) index);
}
#endif // CefC_Cefping

#ifdef CefC_Cefinfo
/*--------------------------------------------------------------------------------------
	Creates the Option Header of Cefinfo Request
----------------------------------------------------------------------------------------*/
static uint16_t								/* Length of Option Header					*/
cef_frame_cefinfo_req_opt_header_create (
	unsigned char* buff, 					/* buffer to set a message					*/
	CefT_Trace_TLVs* tlvs					/* Parameters to set Cefinfo Request		*/
) {
	uint16_t index = 0;
	struct tlv_hdr fld_thdr;
	struct trace_req_block req_blk;

	/*
		+---------------+---------------+---------------+---------------+
		|          T_TRACE_REQ          |             Length            |
		+---------------+---------------+---------------+---------------+
		|  SchemeName   | SkipHopCount  |    Timeout    |Reserved (MBZ) |
		+---------------+---------------+---------------+---------------+
		|           Request ID          |             Flags             |
		+---------------+---------------+---------------+---------------+
							figure: Request Block
	*/

	/* Sets Type and Length fields 	*/
	fld_thdr.type 	= ftvn_trace_req;
	fld_thdr.length = ftvn_8byte;
	memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
	index += CefC_S_TLF;

	/* Sets the Request ID 			*/
	req_blk.scheme_name = tlvs->opt.scheme_name;
	req_blk.skiphop 	= tlvs->opt.skip_hop;
	req_blk.timeout 	= tlvs->opt.timeout;
	req_blk.mbz 		= 0x00;
	req_blk.req_id 		= htons (tlvs->opt.req_id);
	req_blk.flag 		= htons (tlvs->opt.trace_flag);
	memcpy (&buff[index], &req_blk, sizeof (struct trace_req_block));
	index += ftvh_8byte;

	if (index + CefC_S_Fix_Header > CefC_Max_Header_Size) {
		cef_log_write (CefC_Log_Warn, 
			"[frame] Size of the created Trace option header (%d bytes) is"
			" greater than 247 bytes\n", index);
		return (0);
	}

	return (index);
}
#endif // CefC_Cefinfo
/*--------------------------------------------------------------------------------------
	Creates the Validation Algorithm TLV
----------------------------------------------------------------------------------------*/
static uint16_t								/* Length of Option Header					*/
cef_frame_validation_alg_tlv_create (
	unsigned char* buff, 					/* buffer to set a message					*/
	CefT_Valid_Alg_TLVs* tlvs,				/* Parameters to set Interest 				*/
	unsigned char* name, 
	int name_len
) {
	unsigned int index 		= 0;
	unsigned int value_len 	= 0;
	struct tlv_hdr fld_thdr;
	unsigned char keyid[32];
	uint16_t 		pubkey_len;
	unsigned char 	pubkey[CefC_Max_Length];
	
	if (tlvs->hop_by_hop_f) {
		/* HOP-BY-HOP */
	} else if (tlvs->valid_type == CefC_T_CRC32C) {
		index += CefC_S_TLF;
		
		fld_thdr.type 	= ftvn_crc32;
		fld_thdr.length = 0;
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		index += CefC_S_TLF;
		value_len += CefC_S_TLF;
		
	} else if (tlvs->valid_type == CefC_T_RSA_SHA256) {
		
		pubkey_len = (uint16_t) cef_valid_keyid_create (name, name_len, pubkey, keyid);
		if (pubkey_len == 0) {
			return (0);
		}
		index += CefC_S_TLF;
		
		fld_thdr.type 	= ftvn_rsa_sha256;
		fld_thdr.length = htons (40 + pubkey_len);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		index += CefC_S_TLF;
		
		fld_thdr.type 	= ftvn_keyid;
		fld_thdr.length = ftvn_32byte;
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		index += CefC_S_TLF;
		
		memcpy (&buff[index], keyid, 32);
		index += 32;
		
		fld_thdr.type 	= ftvn_pubkey;
		fld_thdr.length = htons (pubkey_len);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		memcpy (&buff[index + CefC_S_TLF], pubkey, pubkey_len);
		index += CefC_S_TLF + pubkey_len;
		
		value_len += 44 + pubkey_len;
		
	} else if (tlvs->valid_type == CefC_T_KEY_CHECK) {
		
		pubkey_len = (uint16_t) cef_valid_keyid_create (name, name_len, pubkey, keyid);
		if (pubkey_len == 0) {
			return (0);
		}
		index += CefC_S_TLF;
		
		fld_thdr.type 	= ftvn_rsa_sha256;
		fld_thdr.length = htons (40 + pubkey_len);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		index += CefC_S_TLF;
		
		fld_thdr.type 	= ftvn_keyid;
		fld_thdr.length = ftvn_32byte;
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		index += CefC_S_TLF;
		
		memcpy (&buff[index], keyid, 32);
		index += 32;
		
		fld_thdr.type 	= ftvn_pubkey;
		fld_thdr.length = htons (pubkey_len);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		memcpy (&buff[index + CefC_S_TLF], pubkey, pubkey_len);
		index += CefC_S_TLF + pubkey_len;
		
		value_len += 44 + pubkey_len;
	}
	
	if (value_len > 0) {
		fld_thdr.type 	= ftvn_valid_alg;
		fld_thdr.length = htons (value_len);
		memcpy (&buff[0], &fld_thdr, sizeof (struct tlv_hdr));
	}
	
	return ((uint16_t) index);
}

/*--------------------------------------------------------------------------------------
	Creates the Validation Payload TLV
----------------------------------------------------------------------------------------*/
static uint16_t								/* Length of Option Header					*/
cef_frame_validation_pld_tlv_create (
	unsigned char* buff, 					/* buffer to set a message					*/
	uint16_t buff_len, 
	unsigned char* name, 
	int name_len, 
	CefT_Valid_Alg_TLVs* tlvs				/* Parameters to set Interest 				*/
) {
	unsigned int index = 0;
	uint32_t crc_code;
	struct tlv_hdr fld_thdr;
	struct value32_tlv v32_thdr;
	unsigned char sign[256];
	unsigned int sign_len;
	int res;
	
	if (tlvs->hop_by_hop_f) {
		/* HOP-BY-HOP */
	} else if (tlvs->valid_type == CefC_T_CRC32C) {
		crc_code = cef_valid_crc32_calc (buff, buff_len);
		v32_thdr.type 	= ftvn_valid_pld;
		v32_thdr.length = ftvn_4byte;
		v32_thdr.value  = htonl (crc_code);
		memcpy (&buff[buff_len], &v32_thdr, sizeof (struct value32_tlv));
		index = sizeof (struct value32_tlv);
		
	} else if (tlvs->valid_type == CefC_T_RSA_SHA256) {
		
		res = cef_valid_dosign (buff, buff_len, name, name_len, sign, &sign_len);
		
		if (res == 1) {
			if (sign_len > 256) {
				sign_len = 256;
			}
			fld_thdr.type 	= ftvn_valid_pld;
			fld_thdr.length = htons (sign_len);
			memcpy (&buff[buff_len], &fld_thdr, sizeof (struct tlv_hdr));
			memcpy (&buff[buff_len + CefC_S_TLF], sign, sign_len);
			
			index += CefC_S_TLF + sign_len;
		}
	}
	return ((uint16_t) index);
}

/*--------------------------------------------------------------------------------------
	Creates a Link Request message
----------------------------------------------------------------------------------------*/
int 										/* Length of the message 					*/
cef_frame_interest_link_msg_create (
	unsigned char* buff						/* buffer to set a message					*/
) {
	if (link_msg) {
		link_msg[1] = CefC_PT_INTEREST;
		link_msg[9] = CefC_T_INTEREST;
		link_msg[23] = CefC_Cmd_Link_Req;
		memcpy (buff, link_msg, link_msg_len);
		return (link_msg_len);
	}

	return (0);
}
/*--------------------------------------------------------------------------------------
	Obtains the default Name (cef:/ or cef://)
----------------------------------------------------------------------------------------*/
static int 									/* Length of the default Name				*/
cef_frame_default_name_get (
	unsigned char* buff 					/* buffer to set a message					*/
) {
	if (default_name_len > 0) {
		memcpy (buff, default_name, default_name_len);
	}
	return (default_name_len);
}
/*--------------------------------------------------------------------------------------
	Creates a Link Response message
----------------------------------------------------------------------------------------*/
int 										/* length of created message 				*/
cef_frame_object_link_msg_create (
	unsigned char* buff						/* buffer to set a message					*/
) {
	if (link_msg) {
		link_msg[1] = CefC_PT_OBJECT;
		link_msg[9] = CefC_T_OBJECT;
		link_msg[23] = CefC_Cmd_Link_Res;
		memcpy (buff, link_msg, link_msg_len);
		return (link_msg_len);
	}

	return (0);
}
/*--------------------------------------------------------------------------------------
	Obtains a Link Request message
----------------------------------------------------------------------------------------*/
int 										/* length of Link Request message 			*/
cef_frame_link_req_cmd_get (
	unsigned char* cmd						/* buffer to set a message					*/
) {
	if (link_cmd == NULL) {
		return (0);
	}
	link_cmd[7]  = CefC_Cmd_Link_Req;
	memcpy (cmd, link_cmd, link_cmd_len);
	return (link_cmd_len);
}
/*--------------------------------------------------------------------------------------
	Obtains a Link Response message
----------------------------------------------------------------------------------------*/
int 										/* length of Link Response message 			*/
cef_frame_link_res_cmd_get (
	unsigned char* cmd 						/* buffer to set a message					*/
) {
	if (link_cmd == NULL) {
		return (0);
	}
	link_cmd[7]  = CefC_Cmd_Link_Res;
	memcpy (cmd, link_cmd, link_cmd_len);
	return (link_cmd_len);
}
/*--------------------------------------------------------------------------------------
	Parses an Invalid TLV in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_invalid_tlv_parse (
	CefT_Parsed_Opheader* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
	/* Ignores the invalid TLV */
	return (1);
}
/*--------------------------------------------------------------------------------------
	Parses an Interest Lifetime TLV in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_lifetime_tlv_parse (
	CefT_Parsed_Opheader* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
	if (length != CefC_S_Lifetime) {
		poh->lifetime 	= 0;
	} else {
		poh->lifetime	= *((uint32_t*) value);
		poh->lifetime 	= ntohs (poh->lifetime);
	}
	poh->lifetime_f = offset + CefC_S_TLF;

	return (1);
}
/*--------------------------------------------------------------------------------------
	Parses a Cache Time TLV in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_cachetime_tlv_parse (
	CefT_Parsed_Opheader* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
	memcpy (&poh->cachetime, value, sizeof (uint64_t));
	poh->cachetime 	 = cef_frame_ntohb (poh->cachetime) * 1000;
	poh->cachetime_f = offset;

	return (1);
}
/*--------------------------------------------------------------------------------------
	Parses a Message Hash TLV in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_msghash_tlv_parse (
	CefT_Parsed_Opheader* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
	// TBD
	return (1);
}
/*--------------------------------------------------------------------------------------
	Parses a Cefping TLV in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_cefping_tlv_parse (
	CefT_Parsed_Opheader* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
#ifdef CefC_Cefping
	poh->responder_f = length;
	memcpy (poh->responder_id, value, length);
#endif // CefC_Cefping
	return (1);
}
/*--------------------------------------------------------------------------------------
	Parses a Cefinfo Request Block in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_trace_req_tlv_parse (
	CefT_Parsed_Opheader* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
#ifdef CefC_Cefinfo
	struct trace_req_block* req_blk;

	req_blk = (struct trace_req_block*) value;

	poh->scheme_name = req_blk->scheme_name;
	poh->skip_hop 	 = req_blk->skiphop;
	poh->timeout 	 = req_blk->timeout;
	poh->req_id 	 = ntohs (req_blk->req_id);
	poh->trace_flag  = ntohs (req_blk->flag);
	poh->skip_hop_offset = offset + CefC_S_TLF + 1;

#endif // CefC_Cefinfo
	return (1);
}
/*--------------------------------------------------------------------------------------
	Parses a Cefinfo Report Block in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_trace_rep_tlv_parse (
	CefT_Parsed_Opheader* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
#ifdef CefC_Cefinfo
	if (poh->rpt_block_offset) {
		return (1);
	}
	poh->rpt_block_offset = offset;
#endif // CefC_Cefinfo
	return (1);
}
/*--------------------------------------------------------------------------------------
	Parses a User Specific TLV in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_user_tlv_parse (
	CefT_Parsed_Opheader* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t type, 							/* Type of this TLV						*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
	uint16_t sub_type;
	uint16_t sub_len;
	uint16_t index = 0;
	struct tlv_hdr* thdr;
	int i;
	uint32_t* v32p;

	switch (type) {

		case CefC_T_OPT_SYMBOLIC: {

			while (index < length) {
				thdr = (struct tlv_hdr*) &value[index];
				sub_type = ntohs (thdr->type);
				sub_len  = ntohs (thdr->length);
				index += CefC_S_TLF;

				if (sub_type == CefC_T_OPT_LONGLIFE) {
					poh->longlife_f = offset;
				} else if (sub_type == CefC_T_OPT_PIGGYBACK) {
					poh->piggyback_f = offset;
				} else if (sub_type == CefC_T_OPT_APP_REG) {
					poh->app_reg_f = CefC_App_Reg;
				} else if (sub_type == CefC_T_OPT_APP_DEREG) {
					poh->app_reg_f = CefC_App_DeReg;
				} else if (sub_type == CefC_T_OPT_INNOVATIVE) {
					poh->bitmap_f = offset + index;
					memcpy (poh->bitmap, &value[index], CefC_S_Innovate);
					for (i = 0 ; i < CefC_S_Bitmap ; i++) {
						poh->bitmap[i] = ntohl (poh->bitmap[i]);
					}
				} else if (sub_type == CefC_T_OPT_NUMBER) {
					poh->number_f = offset + index;
					v32p = (uint32_t*)(&value[index]);
					poh->number = ntohl (*v32p);
				} else if (sub_type == CefC_T_OPT_SCODE) {
					poh->symbolic_code_f = offset + index;
					poh->symbolic_code.type   = ftvn_symcode;
					poh->symbolic_code.length = flvn_symcode;
					v32p = (uint32_t*)(&value[index]);
					poh->symbolic_code.value1 = *v32p;
					v32p = (uint32_t*)(&value[index + sizeof (uint32_t)]);
					poh->symbolic_code.value2 = *v32p;
				} else {
					/* Ignore */;
				}

				index += sub_len;
			}
			break;
		}
		case CefC_T_OPT_TRANSPORT: {
			/* Obtains type and length of the transport variant 	*/
			thdr = (struct tlv_hdr*) &value[index];
			poh->tp_variant = ntohs (thdr->type);
			poh->tp_length  = ntohs (thdr->length);
			index += CefC_S_TLF;

			/* Obtains the value field of transport variant 	*/
			if (poh->tp_variant < CefC_T_OPT_TP_NUM) {
				if (poh->tp_length > 0) {
					memcpy (poh->tp_value, &value[index], poh->tp_length);
				}
			} else {
				poh->tp_variant = CefC_T_OPT_TP_NONE;
				poh->tp_length  = 0;
			}
			break;
		}
		case CefC_T_OPT_SEQNUM: {
			poh->seqnum = ntohl ((uint32_t)(*((uint32_t*) value)));
			break;
		}
		default: {
			break;
		}
	}
	return (1);
}
/*--------------------------------------------------------------------------------------
	Parses an Invalid TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_invalid_tlv_parse (
	CefT_Parsed_Message* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
	/* ignore the invalid TLV */
	return (1);
}
/*--------------------------------------------------------------------------------------
	Parses a Name TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_name_tlv_parse (
	CefT_Parsed_Message* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {

	struct tlv_hdr* thdr;
	uint16_t sub_type;
	uint16_t sub_length;
	uint16_t index = 0;
	uint16_t name_len = 0;
	uint32_t* v32p;

	/* Parses Name 					*/
	while (index < length) {
		thdr = (struct tlv_hdr*) &value[index];
		sub_type 	= ntohs (thdr->type);
		sub_length  = ntohs (thdr->length);
		index += CefC_S_TLF;

		switch (sub_type) {
			case CefC_T_NAMESEGMENT: {
				name_len += CefC_S_TLF + sub_length;
				break;
			}
			case CefC_T_CHUNK: {
				pm->chnk_num = *((uint32_t*) &value[index]);
				pm->chnk_num = ntohl (pm->chnk_num);
				pm->chnk_num_f = index - CefC_S_TLF;
				break;
			}
			case CefC_T_NONCE: {
				memcpy (&pm->nonce, &value[index], sizeof (uint64_t));
				pm->nonce = cef_frame_ntohb (pm->nonce);
				break;
			}
			case CefC_T_SYMBOLIC_CODE: {
				pm->symbolic_code_f = offset + index;

				v32p = (uint32_t*)(&value[index]);
				pm->min_seq = ntohl (*v32p);
				v32p = (uint32_t*)(&value[index + sizeof (uint32_t)]);
				pm->max_seq = ntohl (*v32p);
				break;
			}
			case CefC_T_META: {
				pm->meta_f 	 = offset + index + CefC_S_TLF;
				pm->meta_len = sub_length;
				break;
			}
			default: {
				if ((sub_type >= CefC_T_APP_MIN) &&
					(sub_type <= CefC_T_APP_MAX)) {
					pm->app_comp = sub_type;
					pm->app_comp_len = sub_length;

					if (sub_length > 0) {
						pm->app_comp_offset = offset + index + CefC_S_TLF;
					}
				} else {
					/* Ignore 		*/
				}
				break;
			}
		}
		index += sub_length;
	}

	/* Recordss Name 				*/
	pm->name_f = offset;
	pm->name_len = name_len;
	memcpy (pm->name, value, name_len);

	if (pm->chnk_num_f) {
		memcpy (&(pm->name[name_len]),
			&value[pm->chnk_num_f], CefC_S_TLF + CefC_S_ChunkNum);
		pm->name_len += CefC_S_TLF + CefC_S_ChunkNum;
	}

	return (1);
}
/*--------------------------------------------------------------------------------------
	Parses a ExpiryTime TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_expiry_tlv_parse (
	CefT_Parsed_Message* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
	memcpy (&pm->expiry, value, sizeof (uint64_t));
	pm->expiry = cef_frame_ntohb (pm->expiry) * 1000;

	return (1);
}
/*--------------------------------------------------------------------------------------
	Parses a Payload TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_payload_tlv_parse (
	CefT_Parsed_Message* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
	pm->payload_f = offset;
	memcpy (pm->payload, value, length);
	pm->payload_len = length;

	return (1);
}
/*--------------------------------------------------------------------------------------
	Parses a KeyIdRestriction TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_keyidrestr_tlv_parse (
	CefT_Parsed_Message* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
	// TODO
	return (1);
}
/*--------------------------------------------------------------------------------------
	Parses a ContentObjectHashRestriction TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_objhashrestr_tlv_parse (
	CefT_Parsed_Message* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
	// TODO
	return (1);
}
/*--------------------------------------------------------------------------------------
	Parses a PayloadType TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_payloadtype_tlv_parse (
	CefT_Parsed_Message* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
	// TODO
	return (1);
}

/*--------------------------------------------------------------------------------------
	Creates the Link Message template
----------------------------------------------------------------------------------------*/
static void
cef_frame_link_msg_prepare (
	void
) {
	if (link_msg) {
		return;
	}
	/*
		 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		+---------------+---------------+---------------+---------------+
		|    Version    |  PacketType   |         PacketLength          |
		+---------------+---------------+---------------+---------------+
		|    HopLimit   |  reserved     |  reserved     | HeaderLength  |
		+---------------+---------------+---------------+---------------+
		|            (T_MSG)            |           0x10 (16)           |
		+---------------+---------------+---------------+---------------+
		|            (T_NAME)           |           0x0C (12)           |
		+---------------+---------------+---------------+---------------+
		|        (T_NAMESEGMENT)        |           0x08 (8)            |
		+---------------+---------------+---------------+---------------+
		|     0xC0      |     0xC1      |     0xCC      |     0x01      |
		+---------------+---------------+---------------+---------------+
		|     0x00      |     0xCC      |     0xC1      |     0xC0      |
		+---------------+---------------+---------------+---------------+

		PacketType		 1		Interest
		PacketLength	28		Length of CEFORE message
		HeaderLength	 8		Length of Fixed Header
	*/
	link_cmd_len = 12;
	link_cmd = (unsigned char*) malloc (link_cmd_len);


	link_cmd[0]  = 0x00;				/* T_NAMESEGMENT 			*/
	link_cmd[1]  = 0x01;				/* T_NAMESEGMENT 			*/
	link_cmd[2]  = 0x00;				/* T_NAMESEGMENT Length		*/
	link_cmd[3]  = 0x08;				/* T_NAMESEGMENT Length		*/

	link_cmd[4]  = 0xC0;				/* Command Header			*/
	link_cmd[5]  = 0xC1;				/* Command Header			*/
	link_cmd[6]  = 0xCC;				/* Command Header			*/
	link_cmd[7]  = CefC_Cmd_Link_Req;	/* Command Type				*/
	link_cmd[8]  = 0x00;				/* Command Type				*/
	link_cmd[9]  = 0xCC;				/* Command Footer			*/
	link_cmd[10] = 0xC1;				/* Command Footer			*/
	link_cmd[11] = 0xC0;				/* Command Footer			*/

	link_msg_len = 28;
	link_msg = (unsigned char*) malloc (link_msg_len);
	memset (link_msg, 0, link_msg_len);

	/***** Fixed Header 		*****/
	link_msg[0]  = CefC_Version;	/* Version				*/
	link_msg[1]  = 0x00;			/* PacketType			*/
	link_msg[3]  = 0x1C;			/* PacketLength			*/
	link_msg[4]  = 0x01;			/* HopLimit				*/
	link_msg[7]  = 0x08;			/* HeaderLength			*/

	/***** Cefore Message 		*****/
	link_msg[11] = 0x10;			/* CEFORE Msg Length	*/

	link_msg[13] = 0x00;			/* T_NAME				*/
	link_msg[15] = 0x0C;			/* T_NAME Length		*/

	link_msg[16] = link_cmd[0];		/* T_NAMESEGMENT (Link Command)			*/
	link_msg[17] = link_cmd[1];		/* T_NAMESEGMENT (Link Command)			*/
	link_msg[18] = link_cmd[2];		/* T_NAMESEGMENT Length (Link Command)	*/
	link_msg[19] = link_cmd[3];		/* T_NAMESEGMENT Length (Link Command)	*/

	link_msg[20] = link_cmd[4];		/* Link Command			*/
	link_msg[21] = link_cmd[5];		/* Link Command			*/
	link_msg[22] = link_cmd[6];		/* Link Command			*/
	link_msg[23] = link_cmd[7];		/* Link Command			*/

	link_msg[24] = link_cmd[8];		/* Link Command			*/
	link_msg[25] = link_cmd[9];		/* Link Command			*/
	link_msg[26] = link_cmd[10];	/* Link Command			*/
	link_msg[27] = link_cmd[11];	/* Link Command			*/

	return;
}
/*--------------------------------------------------------------------------------------
	Creates the Default Name template
----------------------------------------------------------------------------------------*/
static void
cef_frame_default_name_prepare (
	void
) {

	default_name_len = 4;

	default_name[0]  = 0x01;			/* T_NAMESEGMENT 			*/
	default_name[1]  = 0x00;			/* T_NAMESEGMENT 			*/
	default_name[2]  = 0x00;			/* T_NAMESEGMENT Length		*/
	default_name[3]  = 0x00;			/* T_NAMESEGMENT Length		*/

	return;
}

uint64_t
cef_frame_htonb (
	uint64_t x
) {
	int y = 1;
	if (*(char*)&y) {
		/* host is little endian. */
		return ((x & 0xFF00000000000000ull) >> 56) |
			   ((x & 0x00FF000000000000ull) >> 40) |
			   ((x & 0x0000FF0000000000ull) >> 24) |
			   ((x & 0x000000FF00000000ull) >>  8) |
			   ((x & 0x00000000FF000000ull) <<  8) |
			   ((x & 0x0000000000FF0000ull) << 24) |
			   ((x & 0x000000000000FF00ull) << 40) |
			   ((x & 0x00000000000000FFull) << 56);
	} else {
		/* host is Big endian. */
		return (x);
	}
}

uint64_t
cef_frame_ntohb (
	uint64_t x
) {
	return (cef_frame_htonb (x));
}
/*--------------------------------------------------------------------------------------
	Convert name to uri
----------------------------------------------------------------------------------------*/
int
cef_frame_conversion_name_to_uri (
	unsigned char* name,
	unsigned int name_len,
	char* uri
) {
	int i;
	int x = 0;
	int seg_len, uri_len;
	struct tlv_hdr* tlv_hdr;
	char work[16];
	unsigned char def_name[CefC_Max_Length];
	int def_name_len;

	strcpy (uri, "ccn:/");
	uri_len = strlen ("ccn:/");

	/* Check default name */
	def_name_len = cef_frame_default_name_get (def_name);
	if ((name_len == def_name_len) && (memcmp (name, def_name, name_len)) == 0) {
		return (uri_len);
	}

	while (x < name_len) {
		tlv_hdr = (struct tlv_hdr*) &name[x];
		seg_len = ntohs (tlv_hdr->length);
		x += CefC_S_TLF;

		for (i = 0 ; i < seg_len ; i++) {
			if ((name[x + i] < 0x2c) ||
				((name[x + i] > 0x2d) && (name[x + i] < 0x2f)) ||
				((name[x + i] > 0x39) && (name[x + i] < 0x41)) ||
				((name[x + i] > 0x5a) && (name[x + i] < 0x61)) ||
				(name[x + i] > 0x7a)) {

				sprintf (work, "%02X", name[x + i]);
				strcpy (&uri[uri_len], work);
				uri_len += strlen (work);
			} else {
				uri[uri_len] = name[x + i];
				uri_len++;
			}
		}
		uri[uri_len] = '/';
		uri_len++;

		x += seg_len;
	}
	uri[uri_len] = 0x00;

	return (uri_len);
}
/*--------------------------------------------------------------------------------------
	Convert name to string
----------------------------------------------------------------------------------------*/
int
cef_frame_conversion_name_to_string (
	unsigned char* name,
	unsigned int name_len,
	char* uri,
	char* protocol
) {
	unsigned int uri_len 	= 0;
	unsigned int read_len 	= 0;
	unsigned int sec_len 	= 0;
	char* uri_p = uri;
	unsigned char* name_p = name;

	/* set prefix	*/
	if (protocol) {
		sprintf (uri_p, "%s:/", protocol);
		uri_len = strlen (protocol) + 2/* ":/" */;
	}

	/* convert name to uri	*/
	while (read_len < name_len) {
		sec_len = (name_p[CefC_S_Type] << 8) + (name_p[CefC_S_Type + 1]);
		if (sec_len == 0) {
			break;
		}
		name_p += CefC_S_TLF;
		memcpy (uri_p + uri_len, name_p, sec_len);
		uri_p[uri_len + sec_len] = '/';
		name_p += sec_len;
		read_len = name_p - name;
		uri_len += sec_len + 1;
	}
	uri_p[uri_len] = 0x00;

	return (uri_len);
}
#ifdef CefC_Ser_Log
/*--------------------------------------------------------------------------------------
	Parses a ORG TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_user_tlv_parse (
	CefT_Parsed_Message* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
	if (length < 4) {
		return (-1);
	}

	/* Get IANA Private Enterprise Numbers */
	pm->org.pen[0] = value[0];
	pm->org.pen[1] = value[1];
	pm->org.pen[2] = value[2];
	/* Get Length */
	pm->org.length = (uint16_t)(length - 3);
	/* Get Message header */
	pm->org.offset = value + 3;
	return (1);
}
#endif // CefC_Ser_Log
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
 * cef_frame.c
 */

#define __CEF_FRAME_SOURECE__

#define _GNU_SOURCE

//#define	DEB_CCNINFO
//#define		__RESTRICT__
//#define		__SELECTIVE__
/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <cefore/cef_define.h>
#ifndef CefC_MACOS
#include <endian.h>
#else // CefC_MACOS
#include <machine/endian.h>
#endif // CefC_MACOS

#include <openssl/sha.h>	//0.8.3

#include <cefore/cef_frame.h>
#include <cefore/cef_client.h>
#include <cefore/cef_print.h>
#include <cefore/cef_log.h>
#include <cefore/cef_plugin.h>
#include <cefore/cef_valid.h>

#ifdef DEB_CCNINFO
#include <ctype.h>
#endif //DEB_CCNINFO

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

#define Opt_T_Org_exist				0x0100
#define Opt_T_OrgSeq_exist			0x0010
#define Opt_T_OrgOther_exist		0x0001

/* If the expiry/cachetime is less than 2001-01-01 00:00:00 Unixtime microseconds,		*/
/* use it as is. If it's larger, convert it to milliseconds.							*/
#define CefC_Frame_us2ms(_t)		\
	if (978274800000000UL < _t) {	\
		_t/=1000;					\
	}
/* If the expiry/cachetime is greater than 2001-01-01 00:00:00 Unixtime microseconds,	*/
/* use it as is. If it is smaller, convert it to microseconds.							*/
#define CefC_Frame_ms2us(_t)		\
	if (978274800000000UL > _t) {	\
		_t*=1000;					\
	}

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/



/****************************************************************************************
 State Variables
 ****************************************************************************************/
static char ccnprefix1[] = {"ccnx:/"};
static char ccnprefix2[] = {"ccnx://"};
static size_t ccnprefix1_len = sizeof (ccnprefix1) - 1; /* without NULL */
static size_t ccnprefix2_len = sizeof (ccnprefix2) - 1; /* without NULL */

static int cef_opt_seqnum_f = CefC_OptSeqnum_NotUse;

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
	T_NAMESEGMENT with ZERO length≒ROOT NAMESEGMENT
 -------------------------------------------------------------------*/
static const unsigned char root_namesegment[4] = {
	0x01,			/* T_NAMESEGMENT 			*/
	0x00,			/* T_NAMESEGMENT 			*/
	0x00,			/* T_NAMESEGMENT Length		*/
	0x00			/* T_NAMESEGMENT Length		*/
};

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
static uint16_t ftvh_pktype_int 		= CefC_T_INTEREST;
static uint16_t ftvh_pktype_obj 		= CefC_T_OBJECT;
static uint16_t ftvh_valid_alg 			= CefC_T_VALIDATION_ALG;
static uint16_t ftvh_valid_pld 			= CefC_T_VALIDATION_PAYLOAD;
static uint16_t ftvh_pktype_discovery	= CefC_T_DISCOVERY;
static uint16_t ftvh_name 				= CefC_T_NAME;
static uint16_t ftvh_payload 			= CefC_T_PAYLOAD;
static uint16_t ftvh_nameseg 			= CefC_T_NAMESEGMENT;
static uint16_t ftvh_ipid 				= CefC_T_IPID;
static uint16_t ftvh_chunk 				= CefC_T_CHUNK;
#ifdef REFLEXIVE_FORWARDING
static uint16_t ftvh_rnp				= CefC_T_REFLEXIVE_NAME;
static uint16_t ftvh_tpit				= CefC_T_TPIT;
#endif // REFLEXIVE_FORWARDING
//0.8.3
static uint16_t ftvh_keyidrestr			= CefC_T_KEYIDRESTR;
static uint16_t ftvh_objhashrestr		= CefC_T_OBJHASHRESTR;

static uint16_t ftvh_payldtype 			= CefC_T_PAYLDTYPE;
static uint16_t ftvh_expiry 			= CefC_T_EXPIRY;
static uint16_t ftvh_endchunk			= CefC_T_ENDCHUNK;

/***** for hop-by-hop option header 	*****/
static uint16_t ftvh_intlife 		= CefC_T_OPT_INTLIFE;
static uint16_t ftvh_rct 			= CefC_T_OPT_CACHETIME;
static uint16_t ftvh_seqnum 		= CefC_T_OPT_SEQNUM;
static uint16_t ftvh_msghash 		= CefC_T_OPT_MSGHASH;
static uint16_t ftvh_disc_reqhdr	= CefC_T_OPT_DISC_REQHDR;
static uint16_t ftvh_disc_rpt		= CefC_T_OPT_DISC_REPORT;
static uint16_t ftvh_org 			= CefC_T_OPT_ORG;
static uint16_t ftvh_app_reg 		= CefC_T_OPT_APP_REG;
static uint16_t ftvh_app_dereg 		= CefC_T_OPT_APP_DEREG;
static uint16_t ftvh_app_reg_p		= CefC_T_OPT_APP_REG_P;
static uint16_t ftvh_app_reg_pit 	= CefC_T_OPT_APP_PIT_REG;
static uint16_t ftvh_app_dereg_pit 	= CefC_T_OPT_APP_PIT_DEREG;
static uint16_t ftvh_dev_reg_pit	= CefC_T_OPT_DEV_REG_PIT;
static uint16_t ftvh_transport 		= CefC_T_OPT_TRANSPORT;

/***** for Validation Algorithm 		*****/
static uint16_t ftvh_crc32c			= CefC_T_CRC32C;
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
static uint16_t ftvn_pktype_discovery;
static uint16_t ftvn_name;
static uint16_t ftvn_payload;
static uint16_t ftvn_nameseg;
static uint16_t ftvn_ipid;
static uint16_t ftvn_chunk;
static uint16_t ftvn_payldtype;
static uint16_t ftvn_expiry;
static uint16_t ftvn_endchunk;
#ifdef REFLEXIVE_FORWARDING
static uint16_t ftvn_rnp;
static uint16_t ftvn_tpit;
#endif // REFLEXIVE_FORWARDING
//0.8.3
static uint16_t ftvn_keyidrestr;
static uint16_t ftvn_objhashrestr;

/***** for hop-by-hop option header 	*****/
static uint16_t ftvn_intlife;
static uint16_t ftvn_rct;
static uint16_t ftvn_seqnum;
static uint16_t ftvn_msghash;
static uint16_t ftvn_disc_reqhdr;	/* ccninfo-05 */
static uint16_t ftvn_disc_rpt;
static uint16_t ftvn_org;
static uint16_t ftvn_app_reg;
static uint16_t ftvn_app_dereg;
static uint16_t ftvn_app_reg_p;
static uint16_t ftvn_app_reg_pit;
static uint16_t ftvn_app_dereg_pit;
static uint16_t ftvn_dev_reg_pit;
static uint16_t ftvn_transport;

/***** for Validation Algorithm 		*****/

static uint16_t ftvn_crc32c;
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
static uint16_t flvh_cachetime 	= CefC_S_Cachetime;
static uint16_t flvh_expiry 	= CefC_S_Expiry;
static uint16_t flvh_rct 		= CefC_S_RCT;
static uint16_t flvh_seqnum 	= CefC_S_SeqNum;

static uint16_t flvn_lifetime;
static uint16_t flvn_chunknum;
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
	Parses a Name TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_name_tlv_parse (
	CefT_CcnMsg_MsgBdy* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);
/*--------------------------------------------------------------------------------------
	Parses a ExpiryTime TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_expiry_tlv_parse (
	CefT_CcnMsg_MsgBdy* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);
/*--------------------------------------------------------------------------------------
	Parses a Payload TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_payload_tlv_parse (
	CefT_CcnMsg_MsgBdy* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);

/*--------------------------------------------------------------------------------------
	Parses a KeyIdRestriction TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_keyidrestr_tlv_parse (
	CefT_CcnMsg_MsgBdy* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);
/*--------------------------------------------------------------------------------------
	Parses a ContentObjectHashRestriction TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_objhashrestr_tlv_parse (
	CefT_CcnMsg_MsgBdy* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);
/*--------------------------------------------------------------------------------------
	Parses a PayloadType TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_payloadtype_tlv_parse (
	CefT_CcnMsg_MsgBdy* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);
/*--------------------------------------------------------------------------------------
	Parses a EndChunkNumber TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_endchunk_tlv_parse (
	CefT_CcnMsg_MsgBdy* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);

static int									/* No care now								*/
(*cef_frame_message_tlv_parse[CefC_T_MSG_TLV_NUM]) (
	CefT_CcnMsg_MsgBdy* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) = {
	cef_frame_message_name_tlv_parse,
	cef_frame_message_payload_tlv_parse,
	cef_frame_message_keyidrestr_tlv_parse,
	cef_frame_message_objhashrestr_tlv_parse,
	NULL,	/* Unassigned */
	cef_frame_message_payloadtype_tlv_parse,
	cef_frame_message_expiry_tlv_parse,
	NULL,	/* T_CURVERSION(7) */
	cef_frame_message_endchunk_tlv_parse,
	NULL,	/* T_CHUNK_SIZE(9) */
};
/*--------------------------------------------------------------------------------------
	Parses an Invalid TLV in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_invalid_tlv_parse (
	CefT_CcnMsg_OptHdr* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);
/*--------------------------------------------------------------------------------------
	Parses an Interest Lifetime TLV in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_lifetime_tlv_parse (
	CefT_CcnMsg_OptHdr* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);
/*--------------------------------------------------------------------------------------
	Parses a Cache Time TLV in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_cachetime_tlv_parse (
	CefT_CcnMsg_OptHdr* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);
/*--------------------------------------------------------------------------------------
	Parses a Message Hash TLV in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_msghash_tlv_parse (
	CefT_CcnMsg_OptHdr* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);
/*--------------------------------------------------------------------------------------
	Parses a Ccninfo Request Block in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_ccninfo_req_tlv_parse (
	CefT_CcnMsg_OptHdr* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);
/*--------------------------------------------------------------------------------------
	Parses a Ccninfo Report Block in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_ccninfo_rep_tlv_parse (
	CefT_CcnMsg_OptHdr* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);

static int									/* No care now								*/
(*cef_frame_opheader_tlv_parse[CefC_T_OPT_TLV_NUM]) (
	CefT_CcnMsg_OptHdr* poh, 				/* Structure to set parsed Option Header	*/
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
	cef_frame_opheader_ccninfo_req_tlv_parse,
	cef_frame_opheader_ccninfo_rep_tlv_parse
};
/*--------------------------------------------------------------------------------------
	Parses a User Specific TLV in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_user_tlv_parse (
	CefT_CcnMsg_OptHdr* poh, 				/* Structure to set parsed Option Header	*/
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
	CefT_CcnMsg_OptHdr* opt				/* parameters to Option Header(s)			*/
);
/*--------------------------------------------------------------------------------------
	Creates the Option Header of Content Object
----------------------------------------------------------------------------------------*/
static uint16_t								/* Length of Option Header					*/
cef_frame_object_opt_header_create (
	unsigned char* buff, 					/* buffer to set a message					*/
	CefT_CcnMsg_OptHdr* opt				/* parameters to Option Header(s)			*/
);

/*--------------------------------------------------------------------------------------
	Creates the Option Header of Ccninfo Request
----------------------------------------------------------------------------------------*/
static uint16_t								/* Length of Option Header					*/
cef_frame_ccninfo_req_opt_header_create (
	unsigned char* buff, 					/* buffer to set a message					*/
	CefT_Ccninfo_TLVs* tlvs					/* Parameters to set Ccninfo Request		*/
);
/*--------------------------------------------------------------------------------------
	Creates the Validation Algorithm TLV
----------------------------------------------------------------------------------------*/
static uint16_t
cef_frame_ccninfo_validation_alg_tlv_create (
	unsigned char* buff, 					/* buffer to set a message					*/
	CefT_Valid_Alg_TLVs* tlvs				/* Parameters to set Ccninfo 				*/
);
/*--------------------------------------------------------------------------------------
	Creates the Validation Payload TLV
----------------------------------------------------------------------------------------*/
static uint16_t								/* Length of Option Header					*/
cef_frame_ccninfo_validation_pld_tlv_create (
	unsigned char* buff, 					/* buffer to set a message					*/
	uint16_t buff_len,
	CefT_Valid_Alg_TLVs* tlvs				/* Parameters to set Interest 				*/
);

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
	Parses a ORG TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_user_tlv_parse (
	CefT_CcnMsg_MsgBdy* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
);
/*--------------------------------------------------------------------------------------
	Sets T_ORG Field to OptionHeader from the specified Parameters
----------------------------------------------------------------------------------------*/
static uint16_t
cef_frame_opheader_torg_set (
	unsigned char* buff, 					/* buffer to set a message					*/
	CefT_CcnMsg_OptHdr* tlvs				/* Parameters to CCNxMessage			 	*/
);
/*--------------------------------------------------------------------------------------
	Sets T_ORG Field to CCNxMessage from the specified Parameters
----------------------------------------------------------------------------------------*/
static uint16_t
cef_frame_message_torg_set (
	unsigned char* buff, 					/* buffer to set a message					*/
	CefT_CcnMsg_MsgBdy* tlvs				/* Parameters to CCNxMessage			 	*/
);
/*--------------------------------------------------------------------------------------
	Search the position of T_ORG and OPT_SEQNUM in ContentObject
----------------------------------------------------------------------------------------*/
static uint16_t								/* Flag indicating the existence of a field	*/
cef_frame_opheader_seqnum_pos_search (
	unsigned char* buff,					/* Head of ContentObject					*/
	int* t_org_idx,							/* OUT: position of T_ORG					*/
	int* t_seqnum_idx						/* OUT: position of OPT_SEQNUM				*/
);

/****************************************************************************************
 ****************************************************************************************/

#define	CefC_S_PEN	3		/* Length of Private Enterprise Number */

static const uchar_t	pen_nict[CefC_S_PEN] = {
		/* Sets IANA Private Enterprise Numbers */
		(0xFF0000 & CefC_NICT_PEN) >> 16,
		(0x00FF00 & CefC_NICT_PEN) >> 8,
		(0x0000FF & CefC_NICT_PEN)
	};

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
	ftvn_pktype_discovery 	= htons (ftvh_pktype_discovery);

	ftvn_name 			= htons (ftvh_name);
	ftvn_payload 		= htons (ftvh_payload);
	ftvn_nameseg 		= htons (ftvh_nameseg);
	ftvn_ipid 			= htons (ftvh_ipid);
	ftvn_chunk 			= htons (ftvh_chunk);
#ifdef REFLEXIVE_FORWARDING
	ftvn_rnp			= htons (ftvh_rnp);
	ftvn_tpit			= htons (ftvh_tpit);
#endif // REFLEXIVE_FORWARDING
	//0.8.3
	ftvn_keyidrestr		= htons (ftvh_keyidrestr);
	ftvn_objhashrestr	= htons (ftvh_objhashrestr);

	ftvn_payldtype 		= htons (ftvh_payldtype);
	ftvn_expiry 		= htons (ftvh_expiry);
	ftvn_endchunk 		= htons (ftvh_endchunk);
	ftvn_intlife 		= htons (ftvh_intlife);
	ftvn_seqnum 		= htons (ftvh_seqnum);
	ftvn_rct 			= htons (ftvh_rct);
	ftvn_msghash 		= htons (ftvh_msghash);
	ftvn_disc_reqhdr	= htons (ftvh_disc_reqhdr);	/* ccninfo-05 */
	ftvn_disc_rpt 		= htons (ftvh_disc_rpt);
	ftvn_org 			= htons (ftvh_org);
	ftvn_app_reg 		= htons (ftvh_app_reg);
	ftvn_app_dereg 		= htons (ftvh_app_dereg);
	ftvn_app_reg_p 		= htons (ftvh_app_reg_p);
	ftvn_app_reg_pit	= htons (ftvh_app_reg_pit);
	ftvn_app_dereg_pit	= htons (ftvh_app_dereg_pit);
	ftvn_dev_reg_pit	= htons (ftvh_dev_reg_pit);
	ftvn_transport 		= htons (ftvh_transport);

	ftvn_crc32c			= htons (ftvh_crc32c);
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
	flvn_cachetime		= htons (flvh_cachetime);
	flvn_expiry 		= htons (flvh_expiry);
	flvn_rct			= htons (flvh_rct);
	flvn_seqnum			= htons (flvh_seqnum);

	/* Creates the Link Message template			*/
	cef_frame_link_msg_prepare ();
}
/*--------------------------------------------------------------------------------------
	Parses a message
----------------------------------------------------------------------------------------*/
int 										/* Returns a negative value if it fails 	*/
cef_frame_message_parse (
	unsigned char* msg, 					/* the message to parse						*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len, 					/* Header Length of this message			*/
	CefT_CcnMsg_OptHdr* poh, 				/* Structure to set parsed Option Header(s)	*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Structure to set parsed CEFORE message	*/
	int target_type							/* Type of the message to expect			*/
) {
	unsigned char* smp;
	unsigned char* emp;
	unsigned char* wmp;
	uint16_t opthdr_len, msg_len;
	uint16_t offset;
	int res;
	struct tlv_hdr* thdr;

	cef_dbg_write(CefC_Dbg_Finest, "target_type=%d, header_len=%u, payload_len=%u\n", target_type, header_len, payload_len);

	/*----------------------------------------------------------------------*/
	/* Parses Option Header				 									*/
	/*----------------------------------------------------------------------*/
	smp = msg + CefC_S_Fix_Header;
	offset = CefC_S_Fix_Header;
	opthdr_len = msg[CefC_O_Fix_HeaderLength] - CefC_S_Fix_Header;

	wmp = smp;
	emp = smp + opthdr_len;

	while (wmp < emp) {
		thdr = (struct tlv_hdr*) &wmp[CefC_O_Type];
		int	tlv_type = ntohs (thdr->type);
		int tlv_len  = ntohs (thdr->length);

		if ((tlv_type > CefC_T_OPT_INVALID) && (tlv_type < CefC_T_OPT_TLV_NUM)) {
			(*cef_frame_opheader_tlv_parse[tlv_type])(poh, tlv_len, &wmp[4], offset);
		} else if ((tlv_type == CefC_T_OPT_USER_TLV) || (tlv_type == CefC_T_OPT_ORG)) {
			cef_frame_opheader_user_tlv_parse (poh, tlv_type, tlv_len, &wmp[4], offset);
		}
		wmp += CefC_S_TLF + tlv_len;
		offset += CefC_S_TLF + tlv_len;
	}

	/*** Calculate cobhash of this message ***/
	if ( !poh->MsgHash_len ){
		uint16_t MsgHash_index = header_len;
		uint16_t MsgHash_len = payload_len;

		cef_valid_sha256( &msg[MsgHash_index], MsgHash_len, poh->MsgHash.hash_value ); /* for OpenSSL 3.x */
		poh->MsgHash_len = CefC_HashVal_Len + CefC_S_TLF;
		poh->MsgHash.hash_type = CefC_T_SHA_256;
		poh->MsgHash.hash_length = CefC_HashVal_Len;
	}

	/*----------------------------------------------------------------------*/
	/* Parses CEFORE message 												*/
	/*----------------------------------------------------------------------*/
	smp = msg + header_len;

	thdr = (struct tlv_hdr*) &smp[CefC_O_Type];
	pm->top_level_type = ntohs (thdr->type);
	msg_len = ntohs (thdr->length);
#ifdef	CefC_Debug
cef_dbg_write(CefC_Dbg_Finest, "msg_len=%d, msg_len=%u\n", payload_len, msg_len);
#endif	// CefC_Debug

	if ((msg_len + CefC_S_TLF) > payload_len) {
		return (-1);
	}

	wmp = smp + CefC_S_TLF;
	emp = wmp + msg_len;
	offset = header_len + CefC_S_TLF;

	while (wmp < emp) {
		thdr = (struct tlv_hdr*) &wmp[CefC_O_Type];
		int	tlv_type = ntohs (thdr->type);
		int tlv_len  = ntohs (thdr->length);

		res = 0;
		switch (tlv_type){
		case CefC_T_DISC_REQ:
		case CefC_T_DISC_REPLY:
						/* Don't look at the TLV value */
			res = 0;	/* continue the parsing the next TLV. */
			break;
		case CefC_T_ORG:
			res = cef_frame_message_user_tlv_parse (
						pm, tlv_len, &wmp[CefC_O_Value], offset);
			break;
		default:
			if (tlv_type < CefC_T_MSG_TLV_NUM && cef_frame_message_tlv_parse[tlv_type] ){
				res = (*cef_frame_message_tlv_parse[tlv_type])(
										pm, tlv_len, &wmp[CefC_O_Value], offset);
			} else {
#ifdef	CefC_Debug
cef_dbg_write(CefC_Dbg_Fine,
				"Unknown Message TLV, Type=0x%x, Length=%d.\n", tlv_type, tlv_len);
#endif	// CefC_Debug
				cef_log_write (CefC_Log_Info,
					"Unknown Message TLV, Type=0x%x, Length=%d.\n", tlv_type, tlv_len);
				res = 0;	/* continue the parsing the next TLV. */
			}
			break;
		}
		if (res < 0) {
			return (-1);
		}

		if ( CefC_NAME_MAXLEN < pm->name_len ){
			cef_log_write (CefC_Log_Warn,
				"T_NAME is too long (%d bytes), cefore does not support T_NAMEs longer than %u bytes and will be discarded.\n",
					pm->name_len, CefC_NAME_MAXLEN);
			return (-1);
		}

		wmp += CefC_S_TLF + tlv_len;
		offset += CefC_S_TLF + tlv_len;
	}

	/*----------------------------------------------------------------------*/
	/* Parses Fixed Header			 										*/
	/*----------------------------------------------------------------------*/
	if ((target_type == CefC_PT_INTEREST) ||
		(target_type == CefC_PT_REQUEST)) {
		pm->hoplimit = msg[CefC_O_Fix_HopLimit];
//		if (pm->hoplimit < 1) {
		if (pm->hoplimit < 0) {
			return (-1);
		}
	}

	/*----------------------------------------------------------------------*/
	/* Parses Trailer				 										*/
	/*----------------------------------------------------------------------*/
	int trailer_len = (payload_len - (CefC_S_TLF + msg_len));
#ifdef	CefC_Debug
cef_dbg_write(CefC_Dbg_Finest, "payload_len=%d, msg_len=%u\n", payload_len, msg_len);
#endif	// CefC_Debug

	while ( CefC_S_TLF < trailer_len ){
		int		alg_type = 0, alg_len = 0;
		int		trail_type, trail_len;

		thdr = (struct tlv_hdr*) &wmp[CefC_O_Type];
		trail_type = ntohs (thdr->type);
		trail_len  = ntohs (thdr->length);
#ifdef	CefC_Debug
cef_dbg_write(CefC_Dbg_Finest, "type=%d, length=%u\n", ntohs (thdr->type), ntohs (thdr->length));
#endif	// CefC_Debug

		switch ( trail_type ){
		case CefC_T_VALIDATION_ALG:
			++thdr;
			alg_type = ntohs (thdr->type);
			alg_len = ntohs (thdr->length);
#ifdef	CefC_Debug
cef_dbg_write(CefC_Dbg_Finest, "VALIDATION_ALG:type=%d, length=%u\n", alg_type, alg_len);
#endif	// CefC_Debug
			++thdr;
			switch ( alg_type ){
			case CefC_T_HMAC_SHA256:
			case CefC_T_RSA_SHA256:
				pm->alg.valid_type = alg_type;
				while ( 0 < alg_len ){
					int		sub_type, sub_len;
					sub_type = ntohs (thdr->type);
					sub_len = ntohs (thdr->length);
#ifdef	CefC_Debug
cef_dbg_write(CefC_Dbg_Finest, "sub_type=%d, sub_len=%u, alg_len=%d\n", sub_type, sub_len, alg_len);
#endif	// CefC_Debug
					switch ( sub_type ){
					case CefC_T_KEYID:
						pm->alg.keyid.hash_type = ntohs (thdr[1].type);
						pm->alg.keyid.hash_length = ntohs (thdr[1].length);
						memcpy(pm->alg.keyid.hash_value, &thdr[2], pm->alg.keyid.hash_length);
						pm->alg.keyid_len = CefC_S_TLF + pm->alg.keyid.hash_length;
						break;
					case CefC_T_PUBLICKEY:
						if ( sub_len < CefC_S_PUBLICKEY ){
							pm->alg.publickey_len = sub_len;
							memcpy(pm->alg.publickey, &thdr[1], sub_len);
						} else {
							cef_log_write (CefC_Log_Warn,
								"T_PUBLICKEY is too long (%d bytes), cefore does not support T_PUBLICKEYs longer than %u bytes and will be discarded.\n",
									sub_len, CefC_S_PUBLICKEY);
						}
						break;
					}
					thdr = (struct tlv_hdr*)((unsigned char *)thdr + CefC_S_TLF + sub_len);
					alg_len -= (CefC_S_TLF + sub_len);
				}
				break;
			default:
#ifdef	CefC_Debug
cef_dbg_write(CefC_Dbg_Fine,
					"Unknown VALIDATION_ALG:type=%d, length=%u\n", alg_type, alg_len);
#endif	// CefC_Debug
				cef_log_write (CefC_Log_Warn,
					"Unknown VALIDATION_ALG:type=%d, length=%u\n", alg_type, alg_len);
				pm->alg.valid_type = 0;
				pm->alg.keyid_len = 0;
				goto ret;
			}
			break;

		case CefC_T_VALIDATION_PAYLOAD:
#ifdef	CefC_Debug
cef_dbg_write(CefC_Dbg_Finest, "T_VALIDATION_PAYLOAD:trail_len=%u\n", trail_len);
#endif	// CefC_Debug
			break;

		default:
#ifdef	CefC_Debug
cef_dbg_write(CefC_Dbg_Fine,
				"Unknown Trailer:Type=0x%x, Length=%u\n", trail_type, trail_len);
#endif	// CefC_Debug
			cef_log_write (CefC_Log_Info,
				"Unknown Trailer, Type=0x%x, Length=%d.\n", trail_type, trail_len);
			goto ret;
		}
		wmp += CefC_S_TLF + trail_len;
		trailer_len -= (CefC_S_TLF + trail_len);
#ifdef	CefC_Debug
cef_dbg_write(CefC_Dbg_Finest, "trailer_len=%u\n", trailer_len);
#endif	// CefC_Debug
	}

ret:
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

	char protocol[CefC_NAME_MAXLEN];
	uint16_t name_len, prot_len, n;

	uint16_t T_APP_XXX;
	uint16_t T_APP_XXX_n;
	int app_f = -1;
	int	ii;
	int chunk_f = -1;
	char* eq_p;
	char* slash_p;
	unsigned char 	chk_uri[CefC_Max_Length];
	int ret_c;
	unsigned int hex_num;
	uint16_t HEX_TYPE = 0;
	int hex_type_f = -1;
	int chunk_accept = CefC_URI_ACCEPT_CHUNK;


	memset( chk_uri, 0x00, sizeof(chk_uri) );
	ret_c = cef_frame_input_uri_pre_check2(inuri, chk_uri, chunk_accept);
	if ( ret_c != 0 ) {
		return (-1);
	}
	ruri = (unsigned char*) chk_uri;

	strcpy (protocol, "ccnx");

	/* Parses the prefix of Name 	*/
	if (memcmp (ccnprefix2, ruri, ccnprefix2_len) == 0) {
		/* prefix is "ccnx://" 		*/
		curi = ruri + ccnprefix2_len;
	} else if (memcmp (ccnprefix1, ruri, ccnprefix1_len) == 0) {
		/* prefix is "ccnx:/" 		*/
		curi = ruri + ccnprefix1_len;
	} else {
		/* prefix is "xxxxx:/" or "xxxxx://" or none */
		curi = ruri;
		name_len = strlen ((const char*) ruri);
		prot_len = 0;

		for (n = 0 ; n < name_len && prot_len < CefC_NAME_MAXLEN; n++) {
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
			strcpy (protocol, "ccnx");
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
		memcpy (name, root_namesegment, sizeof(root_namesegment));
		return ((int) sizeof(root_namesegment));
	}

	while (*curi) {

		slash_p = strchr( (char*)suri, '/' );
		eq_p    = strchr( (char*)suri, '=' );
		if ( eq_p == NULL ) {
			goto IS_NAMESEG;
		} else if ( slash_p != NULL ) {
			if ( slash_p < eq_p ) {
				goto IS_NAMESEG;
			}
		}

		if ( strncasecmp( (char*)suri, "App:", 4 ) == 0 ) {		/* /APP:xx= */
			char	num_buff[CefC_NumBufSiz];
			memset( num_buff, 0x00, sizeof(num_buff) );

			suri += 4;

			/* get Num */
			for( ii = 0; ii < sizeof(num_buff); ) {
				if ( (*suri >= '0') && (*suri <= '9') ) {
					num_buff[ii] = *suri;
					ii++;
					suri++;
				} else {
					break;
				}
			}
			if ( strlen(num_buff) <= 0 ) {
				/* Error */
				return (-1);
			}
			if ( *suri == '=' ) {
				app_f = atoll(num_buff);
				suri++;
				curi = suri;

				if (*curi == 0x00) {
					/* T-APP 0-Length */
					T_APP_XXX = CefC_T_APP_MIN + app_f;
					T_APP_XXX_n = htons (T_APP_XXX);
					memcpy (wp, &T_APP_XXX_n, CefC_S_Type);
					wp += CefC_S_Type;
					value = 0;
					memcpy (wp, &value, CefC_S_Length);
					wp += CefC_S_Length;
					break;
				}
			} else {
				/* Error */
				return (-1);
			}
		}	/* /APP:xx= */

		if ( strncasecmp( (char*)suri, "Chunk=", 6 ) == 0 ) {		/* /Chunk= */
			suri += 6;
			chunk_f = 1;
			curi = suri;
		}		/* /Chunk= */

		if ( (app_f == -1) && (chunk_f == -1) ) {
			char	num_buff[CefC_NumBufSiz];
			memset( num_buff, 0x00, sizeof(num_buff) );

			if ( strncasecmp( (char*)suri, "0x", 2 ) == 0 ) {			/* HEX Type */
				/* get HEX Type */
				num_buff[0] = '0';
				num_buff[1] = 'x';
				suri += 2;
				for( ii = 2; ii < sizeof(num_buff); ) {
					if ( isxdigit(*suri) ) {
						num_buff[ii] = *suri;
						ii++;
						suri++;
					} else {
						break;
					}
				}
				if ( *suri == '=' ) {
					suri++;
				}
				/* Already Len=6 check is pre_check */
				sscanf(num_buff, "%x", &hex_num);
				HEX_TYPE = (uint16_t)hex_num;

				if ( HEX_TYPE == CefC_T_CHUNK ) {
					chunk_f = 1;
				} else {
					hex_type_f = 1;
				}
				curi = suri;
				if (*curi == 0x00) {
					/* HEX_TYPE 0-Length */
					uint16_t HEX_TYPE_n = htons(HEX_TYPE);
					memcpy (wp, &HEX_TYPE_n, CefC_S_Type);
					wp += CefC_S_Type;
					value = 0;
					memcpy (wp, &value, CefC_S_Length);
					wp += CefC_S_Length;
					hex_type_f = -1;
					break;
				}
			}	/* HEX Type */
		}

IS_NAMESEG:

		if((*curi < 0x30) ||							/* NOT 0~9,A~Z,a~z */
			((*curi > 0x39) && (*curi < 0x41)) ||
			((*curi > 0x5a) && (*curi < 0x61)) ||
			(*curi > 0x7a)) {

			if(*curi != 0x2d &&							/* - */
				*curi != 0x2e &&						/* . */
				*curi != 0x2f &&						/* / */
				*curi != 0x3f &&						/* ? */
				*curi != 0x25 &&						/* % */
				*curi != 0x26 &&						/* & */
				*curi != 0x5f &&						/* _ */
				*curi != 0x7e) {						/* ~ */
				return(-1);
			}
		}
		ruri = curi + 1;

		if ((*curi == 0x2f) || (*ruri == 0x00)) {

			if ((*ruri == 0x00) && (*curi != 0x2f)) {
				curi++;
			}
			if (memcmp("0x", suri, 2) != 0) { /* none HEX Name */

				if ( app_f >= 0 ) {
					/* T_APP */
					T_APP_XXX = CefC_T_APP_MIN + app_f;
					T_APP_XXX_n = htons (T_APP_XXX);
					memcpy (wp, &T_APP_XXX_n, CefC_S_Type);
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
					app_f = -1;
				} else if ( chunk_f >= 0 ) {
					uint16_t chunk_len;
					uint16_t chunk_len_ns;
					uint64_t value;
					char buffer[128];
				 	int  i = 0;
				 	int mustContinue = 0;

					char	num_buff[CefC_NumBufSiz];
					memset( num_buff, 0x00, sizeof(num_buff) );

					/* get Num */
					for( ii = 0; ii < sizeof(num_buff); ) {
						if ( (*suri >= '0') && (*suri <= '9') ) {
							num_buff[ii] = *suri;
							ii++;
							suri++;
						} else {
							break;
						}
					}

					value = atoi(num_buff);
					memset(buffer, 0, sizeof(buffer));
					for (int byte = 7; byte >= 0; byte--) {
						uint8_t b = (value >> (byte * 8)) & 0xFF;
						if (b != 0 || byte == 0 || mustContinue) {
							buffer[i] = b;
							i++;
							mustContinue = 1;
						}
					}
					chunk_len = i;

					memcpy (wp, &ftvn_chunk, CefC_S_Type);
					wp += CefC_S_Type;
					chunk_len_ns = htons(chunk_len);
					memcpy (wp, &chunk_len_ns, CefC_S_Length);
					wp += CefC_S_Length;
					memcpy (wp, buffer, chunk_len);
					wp += chunk_len;
					chunk_f = -1;
				} else if ( hex_type_f > 0 ) {
					uint16_t HEX_TYPE_n = htons(HEX_TYPE);
					memcpy (wp, &HEX_TYPE_n, CefC_S_Type);
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
					hex_type_f = -1;
				} else if ( *suri != 0x2f ) {
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
				}

				if ( *curi == 0x2f )  {
					if ( *ruri == 0x2f ) {
						/* *curi='/' && *ruri='/' */
						if ( app_f >= 0 ) {
							/* T_APP */
							T_APP_XXX = CefC_T_APP_MIN + app_f;
							T_APP_XXX_n = htons (T_APP_XXX);
							memcpy (wp, &T_APP_XXX_n, CefC_S_Type);
							wp += CefC_S_Type;
							value = 0;
							memcpy (wp, &value, CefC_S_Length);
							wp += CefC_S_Length;
							suri++;
							curi++;
							app_f = -1;
						} else if ( hex_type_f > 0 ) {
							/* HEX_TYPE */
							uint16_t HEX_TYPE_n = htons(HEX_TYPE);
							memcpy (wp, &HEX_TYPE_n, CefC_S_Type);
							wp += CefC_S_Type;
							value = 0;
							memcpy (wp, &value, CefC_S_Length);
							wp += CefC_S_Length;
							suri++;
							curi++;
							hex_type_f = -1;
						} else {
							/* create 0-Length TLV */
							memcpy (wp, &ftvn_nameseg, CefC_S_Type);
							wp += CefC_S_Type;
							value = 0;
							memcpy (wp, &value, CefC_S_Length);
							wp += CefC_S_Length;
						}
					} else if ( *ruri == 0x00 ) {
						/* Last '/' */
						if ( app_f >= 0 ) {
							/* T_APP */
							T_APP_XXX = CefC_T_APP_MIN + app_f;
							T_APP_XXX_n = htons (T_APP_XXX);
							memcpy (wp, &T_APP_XXX_n, CefC_S_Type);
							wp += CefC_S_Type;
							value = 0;
							memcpy (wp, &value, CefC_S_Length);
							wp += CefC_S_Length;
							suri++;
							curi++;
							app_f = -1;
						} else if ( hex_type_f > 0 ) {
							/* HEX_TYPE */
							uint16_t HEX_TYPE_n = htons(HEX_TYPE);
							memcpy (wp, &HEX_TYPE_n, CefC_S_Type);
							wp += CefC_S_Type;
							value = 0;
							memcpy (wp, &value, CefC_S_Length);
							wp += CefC_S_Length;
							suri++;
							curi++;
							hex_type_f = -1;
						} else {
					  		/* create 0-Length TLV */
							memcpy (wp, &ftvn_nameseg, CefC_S_Type);
							wp += CefC_S_Type;
							value = 0;
							memcpy (wp, &value, CefC_S_Length);
							wp += CefC_S_Length;
							suri++;
							curi++;
						}
					}
					suri++;
				}

				if (*curi == 0x00) {
					break;
				}
			} else  { /* HEX Name */
				char hcbuff[1024];
				int  hclen;
			  	char *hcp;
			  	char hvbuff[1024];
				int  hvlen;
			  	int  i;
			  	memset (hcbuff, 0 , sizeof(hcbuff));
			  	hcp = hcbuff;
			  	memset (hvbuff, 0 , sizeof(hvbuff));
				while (suri < curi) {
					*hcp = *suri;
					hcp++;
					suri++;
				}
				/* length check */
				hclen = strlen(hcbuff);
				hclen -= 2; /* Subtract the length of "0x" */
				if(hclen < 2) {
					return(-1);
				}
				if ((hclen%2) != 0) {
					return(-1);
				}
				/* HEX char check */
				for (i=0; i<hclen; i++) {
					if(isxdigit(hcbuff[2+i]) == 0) {
						return(-1);
					}
				}
				/* conv. HEX char to val */
			    for (i=0; i<hclen; i+=2) {
					unsigned int x;
					sscanf((char *)((hcbuff+2)+i), "%02x", &x);
					if (x == '/' && !app_f && !hex_type_f) {
						return(-1); /* '/' Is not allowed in HEX */
			    	}
					hvbuff[i/2] = x;
				}
			  	hvlen = hclen / 2 ;
			  	/* create TLV */
				if ( app_f >= 0 ) {
					/* T_APP */
					T_APP_XXX = CefC_T_APP_MIN + app_f;
					T_APP_XXX_n = htons (T_APP_XXX);
					memcpy (wp, &T_APP_XXX_n, CefC_S_Type);
					wp += CefC_S_Type;
					app_f = -1;
				} else if ( hex_type_f > 0 ) {
					uint16_t HEX_TYPE_n = htons(HEX_TYPE);
					memcpy (wp, &HEX_TYPE_n, CefC_S_Type);
					wp += CefC_S_Type;
					hex_type_f = -1;
				} else {
					memcpy (wp, &ftvn_nameseg, CefC_S_Type);
					wp += CefC_S_Type;
				}
				value = (uint16_t)(hvlen);
				value = htons (value);
				memcpy (wp, &value, CefC_S_Length);
				wp += CefC_S_Length;
			  	memcpy (wp, hvbuff, hvlen);
			  	wp += hvlen;

				if ( *curi == 0x2f )  {
					if ( *ruri == 0x2f ) {
						/* *curi='/' && *ruri='/' */
				  		/* create 0-Length TLV */
						memcpy (wp, &ftvn_nameseg, CefC_S_Type);
						wp += CefC_S_Type;
						value = 0;
						memcpy (wp, &value, CefC_S_Length);
						wp += CefC_S_Length;
					} else if ( *ruri == 0x00 ) {
						/* Last '/' */
				  		/* create 0-Length TLV */
						memcpy (wp, &ftvn_nameseg, CefC_S_Type);
						wp += CefC_S_Type;
						value = 0;
						memcpy (wp, &value, CefC_S_Length);
						wp += CefC_S_Length;
						suri++;
						curi++;
					}
				}
				suri++;

				if (*curi == 0x00) {
					break;
				}
			}
		} else if (*curi == ';' ) {
			if ( app_f >= 0 ) {
				/* T_APP */
				T_APP_XXX = CefC_T_APP_MIN + app_f;
				T_APP_XXX_n = htons (T_APP_XXX);
				memcpy (wp, &T_APP_XXX_n, CefC_S_Type);
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
				app_f = -1;
			} else if ( hex_type_f > 0 ) {
				uint16_t HEX_TYPE_n = htons(HEX_TYPE);
				memcpy (wp, &HEX_TYPE_n, CefC_S_Type);
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
				hex_type_f = -1;
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
	CefT_CcnMsg_OptHdr* opt,				/* parameters to Option Header(s)			*/
	CefT_CcnMsg_MsgBdy* tlvs				/* Parameters to set Interest 				*/
) {
	struct fixed_hdr fix_hdr;
	struct tlv_hdr fld_thdr;
	uint16_t opt_header_len = 0;
	uint16_t payload_len;
	uint16_t index = 0;
	uint16_t rec_index;

	/*----------------------------------------------------------*/
	/* Option Header 											*/
	/*----------------------------------------------------------*/
	/* Constructs the option header */
	if ( opt != NULL ){
		opt_header_len = cef_frame_interest_opt_header_create (
											&buff[CefC_S_Fix_Header], opt);
	}

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
	if (CefC_NAME_MAXLEN < tlvs->name_len) {
		cef_log_write (CefC_Log_Error,
			"T_NAME is too long (%d bytes), cefore does not support T_NAMEs longer than %u bytes.\n",
				tlvs->name_len, CefC_NAME_MAXLEN);
		return (-1);
	}

	/* Records top index of Name TLV	*/
	rec_index = index;
	index += CefC_S_TLF + tlvs->name_len;

	//0.8.3
	if ( index > CefC_Max_Length ) {
		return( index * -1 );
	}

	/* Sets chunk number	*/
	if (tlvs->chunk_num_f) {
		uint16_t chunk_len;
		uint16_t chunk_len_ns;
		uint64_t value;
		char buffer[128];
	 	int  i = 0;
	 	int mustContinue = 0;

		value = tlvs->chunk_num;
		memset(buffer, 0, sizeof(buffer));
		for (int byte = 7; byte >= 0; byte--) {
			uint8_t b = (value >> (byte * 8)) & 0xFF;
			if (b != 0 || byte == 0 || mustContinue) {
				buffer[i] = b;
				i++;
				mustContinue = 1;
			}
		}
		chunk_len = i;

//		memcpy (&buff[index], &ftvn_chunk, sizeof(CefC_S_Type));
		memcpy (&buff[index], &ftvn_chunk, CefC_S_Type);
		index += CefC_S_Type;
		chunk_len_ns = htons(chunk_len);
//		memcpy (&buff[index], &chunk_len_ns, sizeof(CefC_S_Length));
		memcpy (&buff[index], &chunk_len_ns, CefC_S_Length);
		index += CefC_S_Length;
		memcpy (&buff[index], buffer, chunk_len);
		index += chunk_len;
	}

	//0.8.3
	if ( index > CefC_Max_Length ) {
#ifdef	CefC_Debug
cef_dbg_write(CefC_Dbg_Fine, "index=%d\n", index);
#endif	// CefC_Debug
		return( index * -1 );
	}

#ifdef	__RESTRICT__
		printf( "%s Sets Name rec_index;%d   index:%d\n", __func__, rec_index, index );
#endif

	/* Sets T_NAME		*/
	fld_thdr.type 	= ftvn_name;
	fld_thdr.length = htons (index - (rec_index + CefC_S_TLF));
	memcpy (&buff[rec_index], &fld_thdr, sizeof (struct tlv_hdr));
	memcpy (&buff[rec_index + CefC_O_Value], tlvs->name, tlvs->name_len);

	/*=========================================
		PAYLOAD TLV (only piggyback)
	===========================================*/
	if ((tlvs->payload_len > 0)) {
		fld_thdr.type   = ftvn_payload;
		fld_thdr.length = htons (tlvs->payload_len);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		memcpy (&buff[index + CefC_O_Value], tlvs->payload, tlvs->payload_len);
		index += CefC_S_TLF + tlvs->payload_len;
	}

	//0.8.3
	if ( index > CefC_Max_Length ) {
#ifdef	CefC_Debug
cef_dbg_write(CefC_Dbg_Fine, "index=%d\n", index);
#endif	// CefC_Debug
		return( index * -1 );
	}

	//0.8.3
	/* Sets KeyIdRestr */
	if ( tlvs->KeyIdRestr_f ) {
#ifdef	__RESTRICT__
		printf( "%s Sets KeyIdRestr\n", __func__ );
#endif
		fld_thdr.type 	= ftvn_keyidrestr;
		fld_thdr.length = htons(CefC_HashVal_Len + 4);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		index += CefC_S_TLF;
		fld_thdr.type 	= htons(CefC_T_SHA_256);
		fld_thdr.length = htons(CefC_HashVal_Len);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		index += CefC_S_TLF;
		memcpy (&buff[index], tlvs->KeyIdRestr.hash_value, CefC_HashVal_Len);
		index += CefC_HashVal_Len;
	}

	//0.8.3
	if ( index > CefC_Max_Length ) {
#ifdef	CefC_Debug
cef_dbg_write(CefC_Dbg_Fine, "index=%d\n", index);
#endif	// CefC_Debug
		return( index * -1 );
	}

	//0.8.3
	/* Sets ObjHashRestr */
	if ( tlvs->ObjHashRestr_f ) {
#ifdef	__RESTRICT__
		printf( "%s Sets ObjHashRestr index:%d\n", __func__, index );
#endif
		fld_thdr.type 	= ftvn_objhashrestr;
		fld_thdr.length	= htons(tlvs->ObjHashRestr.hash_length + CefC_S_TLF);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		index += CefC_S_TLF;
#ifdef	__RESTRICT__
		printf( "\t index:%d\n", index );
#endif
		fld_thdr.type 	= htons(tlvs->ObjHashRestr.hash_type);
		fld_thdr.length	= htons(tlvs->ObjHashRestr.hash_length);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		index += CefC_S_TLF;
#ifdef	__RESTRICT__
		printf( "\t index:%d\n", index );
#endif
		memcpy (&buff[index], tlvs->ObjHashRestr.hash_value, tlvs->ObjHashRestr.hash_length);
		index += tlvs->ObjHashRestr.hash_length;
#ifdef	__RESTRICT__
		printf( "\t index:%d\n", index );
#endif
	}

	//0.8.3
	if ( index > CefC_Max_Length ) {
#ifdef	CefC_Debug
cef_dbg_write(CefC_Dbg_Fine, "index=%d\n", index);
#endif	// CefC_Debug
		return( index * -1 );
	}

	/*=========================================
		ORG TLV
	===========================================*/
	index +=
		cef_frame_message_torg_set (&buff[index], tlvs);

	//0.8.3
	if ( index > CefC_Max_Length ) {
#ifdef	CefC_Debug
cef_dbg_write(CefC_Dbg_Fine, "index=%d\n", index);
#endif	// CefC_Debug
		return( index * -1 );
	}

	/*=========================================
		CEFORE message header
	===========================================*/
	payload_len =
		index - (CefC_S_Fix_Header + opt_header_len + CefC_S_TLF);
	fld_thdr.length = htons (payload_len);
	fld_thdr.type 	= ftvn_pktype_int;
	memcpy (
		&buff[CefC_S_Fix_Header + opt_header_len], &fld_thdr, sizeof (struct tlv_hdr));

#ifdef	__RESTRICT__
		printf( "\t payload_len:%d\n", payload_len );
#endif

	/*----------------------------------------------------------*/
	/* Validations	 											*/
	/*----------------------------------------------------------*/
	rec_index = index;
	index += cef_frame_validation_alg_tlv_create (
					&buff[index], &tlvs->alg, tlvs->name, tlvs->name_len);

	//0.8.3
	if ( index > CefC_Max_Length ) {
#ifdef	CefC_Debug
cef_dbg_write(CefC_Dbg_Fine, "index=%d\n", index);
#endif	// CefC_Debug
		return( index * -1 );
	}

	if (rec_index != index) {
		index += cef_frame_validation_pld_tlv_create (
			&buff[CefC_S_Fix_Header + opt_header_len],
			index - (CefC_S_Fix_Header + opt_header_len),
			tlvs->name, tlvs->name_len, &tlvs->alg);
	}

	//0.8.3
	if ( index > CefC_Max_Length ) {
#ifdef	CefC_Debug
cef_dbg_write(CefC_Dbg_Fine, "index=%d\n", index);
#endif	// CefC_Debug
		return( index * -1 );
	}

	/*----------------------------------------------------------*/
	/* Fixed Header												*/
	/*----------------------------------------------------------*/
	fix_hdr.ccn_ver 	= CefC_Version;
	fix_hdr.type 		= CefC_PT_INTEREST;
	fix_hdr.pkt_len 	= htons (index);
	fix_hdr.hoplimit 	= tlvs->hoplimit;
	fix_hdr.reserve1 	= 0x00;
	fix_hdr.reserve2 	= 0x00;
	fix_hdr.hdr_len 	= CefC_S_Fix_Header + opt_header_len;

	memcpy (buff, &fix_hdr, sizeof (struct fixed_hdr));

#ifdef	__RESTRICT__
		printf( "%s Interest pkt_len:%d\n", __func__, index );
	{
		int dbg_x;
		fprintf (stderr, "Create Interest Msg [ ");
		for (dbg_x = 0 ; dbg_x < index ; dbg_x++) {
			fprintf (stderr, "%02x ", buff[dbg_x]);
		}
		fprintf (stderr, "](%d)\n", index);
	}
#endif
#ifdef	__SELECTIVE__
		printf( "%s Interest pkt_len:%d\n", __func__, index );
	{
		int dbg_x;
		fprintf (stderr, "Create Interest Msg [ ");
		for (dbg_x = 0 ; dbg_x < index ; dbg_x++) {
			fprintf (stderr, "%02x ", buff[dbg_x]);
		}
		fprintf (stderr, "](%d)\n", index);
	}
#endif

	return (index);
}
/*--------------------------------------------------------------------------------------
	Sets T_ORG Field to OptionHeader from the specified Parameters
----------------------------------------------------------------------------------------*/
uint16_t
cef_frame_build_hdrorg_value (
	unsigned char* buff, 					/* buffer to set a binary data		*/
	CefT_HdrOrg_Params* org					/* Vender specific Parameters 		*/
) {
	uint16_t index = 0;

	/*
		+---------------+---------------+---------------+---------------+
		|             T_ORG             |             Length            |
		+---------------+---------------+---------------+---------------+
		|     PEN[0]    |     PEN[1]    |     PEN[2]    |               /
		+---------------+---------------+---------------+---------------+
		/                     Vendor Specific Value                     |
		+---------------+-------------------------------+---------------+
		If the first bit is 0, the length does not follow the Type.
		+---------------+
		|0|<-- 15bit -->|
		+---------------+
		If the first bit is 1, the length follows the Type.
		+---------------+---------------+---------------+---------------+
		|1|<-- 15bit -->|             Length            |     Value     /
		+---------------+---------------+---------------+---------------+
	*/

	/* Sets the H/W router acceleration flags */
	if (org->t_hw_flags_f) {
		struct tlv_hdr fld_thdr;
		uint16_t	t_hw_flags = CefC_T_HW_FLAGS;

		if (org->t_hw_flags_symbolic_f){
			t_hw_flags |= CefC_T_HW_FLAGS_SYMBOLIC;
		}
		if (org->t_hw_flags_enablecache_f){
			t_hw_flags |= CefC_T_HW_FLAGS_ENABLECACHE;
		}

		/* Sets the type fields of the top of t_hw_flags */
		fld_thdr.type = htons(t_hw_flags);
		memcpy (&buff[index], &fld_thdr.type, sizeof (fld_thdr.type));
		index += sizeof (fld_thdr.type);

		if (org->t_hw_timestamp_f) {
			uint16_t	t_hw_timestamp = CefC_T_HW_TIMESTAMP;
			uint16_t	t_hw_timestamp_len = (org->t_hw_timestamp_long_f ? 16 : 8);

			/* Sets the type fields of the top of t_hw_timestamp */
			fld_thdr.type 	= htons(t_hw_timestamp);
			fld_thdr.length	= htons(t_hw_timestamp_len);
			memcpy (&buff[index], &fld_thdr, sizeof (fld_thdr));
			index += sizeof (CefC_S_TLF);
			memset (&buff[index], 0x00, t_hw_timestamp_len);
			index += t_hw_timestamp_len;
		}
	}

	/* Sets the Transport Variant 	*/
	if (org->tp_variant) {
		struct tlv_hdr fld_thdr;

		/* Sets the type and length fields of the top of Transport 		*/
		fld_thdr.type 	= ftvn_transport;
		fld_thdr.length = htons (CefC_S_TLF + org->tp_len);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		index += CefC_S_TLF;

		/* Sets the transport variant 	*/
		fld_thdr.type 	= htons (org->tp_variant);
		fld_thdr.length = htons (org->tp_len);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		if (org->tp_len > 0) {
			memcpy (&buff[index + CefC_O_Value], org->tp_val, org->tp_len);
		}
		index += CefC_S_TLF + org->tp_len;
	}

	/* Sets Sequence Number TLV	(OPT_SEQNUM)	*/
	if(cef_frame_get_opt_seqnum_f()) {
		struct value32_tlv value32_fld;

		value32_fld.type   = ftvn_seqnum;
		value32_fld.length = flvn_seqnum;
		value32_fld.value  = 0;
		memcpy (&buff[index], &value32_fld, sizeof (struct value32_tlv));
		index += CefC_S_TLF + flvh_seqnum;
	}

	return (index);
}
/*--------------------------------------------------------------------------------------
	Sets T_ORG Field to Message from the specified Parameters
----------------------------------------------------------------------------------------*/
uint16_t
cef_frame_build_msgorg_value (
	unsigned char* buff, 					/* buffer to set a binary data		*/
	CefT_MsgOrg_Params* org					/* Vender specific Parameters 		*/
) {
	uint16_t index = 0;

	/*
		+---------------+---------------+---------------+---------------+
		|             T_ORG             |             Length            |
		+---------------+---------------+---------------+---------------+
		|     PEN[0]    |     PEN[1]    |     PEN[2]    |               /
		+---------------+---------------+---------------+---------------+
		/                     Vendor Specific Value                     |
		+---------------+-------------------------------+---------------+
		If the first bit is 0, the length does not follow the Type.
		+---------------+
		|0|<-- 15bit -->|
		+---------------+
		If the first bit is 1, the length follows the Type.
		+---------------+---------------+---------------+---------------+
		|1|<-- 15bit -->|             Length            |     Value     /
		+---------------+---------------+---------------+---------------+
	*/

	if (org->symbolic_f != 0) {
		/* Sets Type of Symbolic Interest */
		uint16_t vsv =htons (CefC_T_SYMBOLIC);
		memcpy (&buff[index], &vsv, sizeof (vsv));
		index += sizeof (vsv);
	}

	if (org->longlife_f != 0) {
		/* Sets Type of Longlife Interest */
		uint16_t vsv =htons (CefC_T_LONGLIFE);
		memcpy (&buff[index], &vsv, sizeof (vsv));
		index += sizeof (vsv);
	}
#ifdef REFLEXIVE_FORWARDING

	if (org->reflexive_smi_f != 0) {
		/* Sets config of SMI for reflexive */
		uint16_t vsv =htons (CefC_T_REFLEXIVE_SMI);
		memcpy (&buff[index], &vsv, sizeof (vsv));
		index += sizeof (vsv);
	}
#endif // REFLEXIVE_FORWARDING

	if (org->from_pub_f != 0) {
		/* Sets Type of T_FROM_PUB(aka T_APP_FROM_PUB) Interest */
		uint16_t vsv =htons (CefC_T_FROM_PUB);
		memcpy (&buff[index], &vsv, sizeof (vsv));
		index += sizeof (vsv);
	}

	return (index);
}
/*--------------------------------------------------------------------------------------
	Sets T_ORG Field to Object from the specified Parameters
----------------------------------------------------------------------------------------*/
static uint16_t
cef_frame_opheader_torg_set (
	unsigned char* buff, 					/* buffer to set a message					*/
	CefT_CcnMsg_OptHdr* tlvs				/* Parameters to set Interest 				*/
) {
	/*
		+---------------+---------------+---------------+---------------+
		|             T_ORG             |             Length            |
		+---------------+---------------+---------------+---------------+
		|     PEN[0]    |     PEN[1]    |     PEN[2]    |               /
		+---------------+---------------+---------------+---------------+
		/                     Vendor Specific Value                     |
		+---------------+-------------------------------+---------------+
	*/
	int		index = 0;

	/* Sets IANA Private Enterprise Numbers */
/*	pen_nict[0] = (0xFF0000 & CefC_NICT_PEN) >> 16;
	pen_nict[1] = (0x00FF00 & CefC_NICT_PEN) >> 8;
	pen_nict[2] = (0x0000FF & CefC_NICT_PEN);
*/
	if ( !tlvs->org_len ){
		tlvs->org_len = cef_frame_build_hdrorg_value(tlvs->org_val, &(tlvs->org));
	}

	if ( tlvs->org_len ){
		struct tlv_hdr fld_thdr;

		index += CefC_S_TLF;

		/* Sets IANA Private Enterprise Numbers */
		memcpy(&buff[index], pen_nict, sizeof(pen_nict));
		index += sizeof(pen_nict);

		memcpy(&buff[index], tlvs->org_val, tlvs->org_len);
		index += tlvs->org_len;

		/* Sets T_OPT_ORG Type,Length */
		fld_thdr.type = htons (CefC_T_OPT_ORG);
		fld_thdr.length = htons (sizeof(pen_nict)+tlvs->org_len);
		memcpy (buff, &fld_thdr, sizeof (struct tlv_hdr));
	}

	return (index);
}
/*--------------------------------------------------------------------------------------
	Sets T_ORG Field to Object from the specified Parameters
----------------------------------------------------------------------------------------*/
static uint16_t
cef_frame_message_torg_set (
	unsigned char* buff, 					/* buffer to set a message					*/
	CefT_CcnMsg_MsgBdy* tlvs				/* Parameters to set Interest 				*/
) {
	/*
		+---------------+---------------+---------------+---------------+
		|             T_ORG             |             Length            |
		+---------------+---------------+---------------+---------------+
		|     PEN[0]    |     PEN[1]    |     PEN[2]    |               /
		+---------------+---------------+---------------+---------------+
		/                     Vendor Specific Value                     |
		+---------------+-------------------------------+---------------+
	*/
	int		index = 0;

	/* Sets IANA Private Enterprise Numbers */
/*	pen_nict[0] = (0xFF0000 & CefC_NICT_PEN) >> 16;
	pen_nict[1] = (0x00FF00 & CefC_NICT_PEN) >> 8;
	pen_nict[2] = (0x0000FF & CefC_NICT_PEN);
*/
	if ( !tlvs->org_len ){
		tlvs->org_len = cef_frame_build_msgorg_value(tlvs->org_val, &(tlvs->org));
	}

	if ( tlvs->org_len ){
		struct tlv_hdr fld_thdr;

		index += CefC_S_TLF;

		/* Sets IANA Private Enterprise Numbers */
		memcpy(&buff[index], pen_nict, sizeof(pen_nict));
		index += sizeof(pen_nict);

		memcpy(&buff[index], tlvs->org_val, tlvs->org_len);
		index += tlvs->org_len;

		/* Sets T_ORG Type,Length */
		fld_thdr.type = htons (CefC_T_ORG);
		fld_thdr.length = htons (sizeof(pen_nict)+tlvs->org_len);
		memcpy (buff, &fld_thdr, sizeof (struct tlv_hdr));
	}
	return index;
}
/*--------------------------------------------------------------------------------------
	Creates the Content Object from the specified Parameters
----------------------------------------------------------------------------------------*/
int 										/* Length of Content Object message 		*/
cef_frame_object_create (
	unsigned char* buff, 					/* buffer to set Content Object				*/
	CefT_CcnMsg_OptHdr* opt,				/* parameters to Option Header(s)			*/
	CefT_CcnMsg_MsgBdy* tlvs				/* Parameters to set Content Object 		*/
) {
	struct fixed_hdr fix_hdr;
	struct tlv_hdr fld_thdr;
	struct value64_tlv value64_fld;
	uint16_t opt_header_len = 0;
	uint16_t payload_len;
	uint16_t index = 0;
	uint16_t rec_index;
	uint64_t expiry;

	/*----------------------------------------------------------*/
	/* Option Header 											*/
	/*----------------------------------------------------------*/
	/* Constructs the option header */
	if ( opt != NULL ){
		opt_header_len = cef_frame_object_opt_header_create (
											&buff[CefC_S_Fix_Header], opt);
	}

	index = CefC_S_Fix_Header + opt_header_len;

	//0.8.3
	if ( index > CefC_Max_Length ) {
		return( index * -1 );
	}

	/*----------------------------------------------------------*/
	/* CEFORE message 											*/
	/*----------------------------------------------------------*/
	index += CefC_S_TLF;

	//0.8.3
	if ( index > CefC_Max_Length ) {
		return( index * -1 );
	}

	/*=========================================
		NAME TLV
	===========================================*/
	if (tlvs->name_len < CefC_S_TLF + 1) {
		return (0);
	}
	if (CefC_NAME_MAXLEN < tlvs->name_len) {
		cef_log_write (CefC_Log_Error,
			"T_NAME is too long (%d bytes), cefore does not support T_NAMEs longer than %u bytes.\n",
				tlvs->name_len, CefC_NAME_MAXLEN);
		return (-1);
	}

	/* Records top index of Name TLV	*/
	rec_index = index;
	index += CefC_S_TLF + tlvs->name_len;

	//0.8.3
	if ( index > CefC_Max_Length ) {
		return( index * -1 );
	}

	/* Sets ChunkNumber		*/
	if (tlvs->chunk_num_f) {
		uint16_t chunk_len;
		uint16_t chunk_len_ns;
		uint64_t value;
		char buffer[128];
	 	int  i = 0;
	 	int mustContinue = 0;

		value = tlvs->chunk_num;
		memset(buffer, 0, sizeof(buffer));
		for (int byte = 7; byte >= 0; byte--) {
			uint8_t b = (value >> (byte * 8)) & 0xFF;
			if (b != 0 || byte == 0 || mustContinue) {
				buffer[i] = b;
				i++;
				mustContinue = 1;
			}
		}
		chunk_len = i;

//		memcpy (&buff[index], &ftvn_chunk, sizeof(CefC_S_Type));
		memcpy (&buff[index], &ftvn_chunk, CefC_S_Type);
		index += CefC_S_Type;
		chunk_len_ns = htons(chunk_len);
//		memcpy (&buff[index], &chunk_len_ns, sizeof(CefC_S_Length));
		memcpy (&buff[index], &chunk_len_ns, CefC_S_Length);
		index += CefC_S_Length;
		memcpy (&buff[index], buffer, chunk_len);
		index += chunk_len;
	}

	//0.8.3
	if ( index > CefC_Max_Length ) {
		return( index * -1 );
	}

	/* Sets T_NAME		*/
	fld_thdr.type 	= ftvn_name;
	fld_thdr.length = htons (index - (rec_index + CefC_S_TLF));
	memcpy (&buff[rec_index], &fld_thdr, sizeof (struct tlv_hdr));
	memcpy (&buff[rec_index + CefC_O_Value], tlvs->name, tlvs->name_len);

	/*----- EXPIRY TLV 			-----*/
	expiry = tlvs->expiry;
	CefC_Frame_us2ms (expiry);
	value64_fld.type   = ftvn_expiry;
	value64_fld.length = flvn_expiry;
	value64_fld.value  = cef_frame_htonb (expiry);
	memcpy (&buff[index], &value64_fld, sizeof (struct value64_tlv));
	index += CefC_S_TLF + CefC_S_Expiry;

	//0.8.3
	if ( index > CefC_Max_Length ) {
		return( index * -1 );
	}

	/*----- Sets T_ENDCHUNK		-----*/
	if (tlvs->end_chunk_num_f) {
		uint16_t end_chunk_len;
		uint16_t end_chunk_len_ns;
		uint64_t value;
		char buffer[128];
	 	int  i = 0;
	 	int mustContinue = 0;

		value = tlvs->end_chunk_num;
		memset(buffer, 0, sizeof(buffer));
		for (int byte = 7; byte >= 0; byte--) {
			uint8_t b = (value >> (byte * 8)) & 0xFF;
			if (b != 0 || byte == 0 || mustContinue) {
				buffer[i] = b;
				i++;
				mustContinue = 1;
			}
		}
		end_chunk_len = i;

		memcpy (&buff[index], &ftvn_endchunk, CefC_S_Type);
		index += CefC_S_Type;
		end_chunk_len_ns = htons(end_chunk_len);
		memcpy (&buff[index], &end_chunk_len_ns, CefC_S_Length);
		index += CefC_S_Length;
		memcpy (&buff[index], buffer, end_chunk_len);
		index += end_chunk_len;
	}

	//0.8.3
	if ( index > CefC_Max_Length ) {
		return( index * -1 );
	}

	/*----- ORG TLV 			-----*/
	index +=
		cef_frame_message_torg_set (&buff[index], tlvs);

	/*----- PAYLOAD TLV 			-----*/
	if (tlvs->payload_len > 0) {
		fld_thdr.type   = ftvn_payload;
		fld_thdr.length = htons (tlvs->payload_len);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		memcpy (&buff[index + CefC_O_Value], tlvs->payload, tlvs->payload_len);
		index += CefC_S_TLF + tlvs->payload_len;
	}

	//0.8.3
	if ( index > CefC_Max_Length ) {
		return( index * -1 );
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

	//0.8.3
	if ( index > CefC_Max_Length ) {
		return( index * -1 );
	}

	if (rec_index != index) {
		index += cef_frame_validation_pld_tlv_create (
			&buff[CefC_S_Fix_Header + opt_header_len],
			index - (CefC_S_Fix_Header + opt_header_len),
			tlvs->name, tlvs->name_len, &tlvs->alg);
	}

	//0.8.3
	if ( index > CefC_Max_Length ) {
		return( index * -1 );
	}

	/*----------------------------------------------------------*/
	/* Frame Header 											*/
	/*----------------------------------------------------------*/
	fix_hdr.ccn_ver 	= CefC_Version;
	fix_hdr.type 		= CefC_PT_OBJECT;
	fix_hdr.pkt_len 	= htons (index);
	fix_hdr.hoplimit 	= 0x00;
	fix_hdr.reserve1 	= 0x00;
	fix_hdr.reserve2 	= 0x00;
	fix_hdr.hdr_len 	= CefC_S_Fix_Header + opt_header_len;

	memcpy (buff, &fix_hdr, sizeof (struct fixed_hdr));

	//0.8.3 ObjHashRestr
	if ( tlvs->ObjHashRestr_f ) {
//		SHA256_CTX		ctx;
		uint16_t		CobHash_index;
		uint16_t		CobHash_len;
		unsigned char 	hash[SHA256_DIGEST_LENGTH];

		CobHash_index = CefC_S_Fix_Header + opt_header_len;
		CobHash_len   = index - (CefC_S_Fix_Header + opt_header_len);
//		SHA256_Init (&ctx);
//		SHA256_Update (&ctx, &buff[CobHash_index], CobHash_len);
//		SHA256_Final (hash, &ctx);
		cef_valid_sha256( &buff[CobHash_index], CobHash_len, hash );	/* for OpenSSL 3.x */
		tlvs->ObjHashRestr.hash_type = CefC_T_SHA_256;
		tlvs->ObjHashRestr.hash_length = CefC_HashVal_Len;
		memcpy( tlvs->ObjHashRestr.hash_value, hash, CefC_HashVal_Len );
	}

	return (index);
}
int 										/* Length of Content Object message 		*/
cef_frame_object_create_for_csmgrd (
	unsigned char* buff, 					/* buffer to set Content Object				*/
	CefT_CcnMsg_OptHdr* opt,				/* parameters to Option Header(s)			*/
	CefT_CcnMsg_MsgBdy* tlvs				/* Parameters to set Content Object 		*/
) {
	struct fixed_hdr fix_hdr;
	struct tlv_hdr fld_thdr;
	struct value64_tlv value64_fld;
	uint16_t opt_header_len = 0;
	uint16_t payload_len;
	uint16_t index = 0;
	uint16_t rec_index;
	uint64_t expiry;

	/*----------------------------------------------------------*/
	/* Option Header 											*/
	/*----------------------------------------------------------*/
	/* Constructs the option header */
	if ( opt != NULL ){
		opt_header_len = cef_frame_object_opt_header_create (
											&buff[CefC_S_Fix_Header], opt);
	}

	index = CefC_S_Fix_Header + opt_header_len;

	if ( index > CefC_Max_Length ) {
		return( index * -1 );
	}

	/*----------------------------------------------------------*/
	/* CEFORE message 											*/
	/*----------------------------------------------------------*/
	index += CefC_S_TLF;

	if ( index > CefC_Max_Length ) {
		return( index * -1 );
	}

	/*=========================================
		NAME TLV
	===========================================*/
	if (tlvs->name_len < CefC_S_TLF + 1) {
		return (0);
	}
	if (CefC_NAME_MAXLEN < tlvs->name_len){
		cef_log_write (CefC_Log_Error,
			"T_NAME is too long (%d bytes), cefore does not support T_NAMEs longer than %u bytes.\n",
				tlvs->name_len, CefC_NAME_MAXLEN);
		return (-1);
	}

	/* Records top index of Name TLV	*/
	rec_index = index;
	index += CefC_S_TLF + tlvs->name_len;

	if ( index > CefC_Max_Length ) {
		return( index * -1 );
	}

	/* Sets ChunkNumber		*/
	if (tlvs->chunk_num_f) {
		uint16_t chunk_len;
		uint16_t chunk_len_ns;
		uint64_t value;
		char buffer[128];
	 	int  i = 0;
	 	int mustContinue = 0;

		value = tlvs->chunk_num;
		memset(buffer, 0, sizeof(buffer));
		for (int byte = 7; byte >= 0; byte--) {
			uint8_t b = (value >> (byte * 8)) & 0xFF;
			if (b != 0 || byte == 0 || mustContinue) {
				buffer[i] = b;
				i++;
				mustContinue = 1;
			}
		}
		chunk_len = i;

		memcpy (&buff[index], &ftvn_chunk, CefC_S_Type);
		index += CefC_S_Type;
		chunk_len_ns = htons(chunk_len);
		memcpy (&buff[index], &chunk_len_ns, CefC_S_Length);
		index += CefC_S_Length;
		memcpy (&buff[index], buffer, chunk_len);
		index += chunk_len;
	}

	if ( index > CefC_Max_Length ) {
		return( index * -1 );
	}

	/* Sets T_NAME		*/
	fld_thdr.type 	= ftvn_name;
	fld_thdr.length = htons (index - (rec_index + CefC_S_TLF));
	memcpy (&buff[rec_index], &fld_thdr, sizeof (struct tlv_hdr));
	memcpy (&buff[rec_index + CefC_O_Value], tlvs->name, tlvs->name_len);

	/*----- EXPIRY TLV 			-----*/
	expiry = tlvs->expiry;
	CefC_Frame_us2ms (expiry);
	value64_fld.type   = ftvn_expiry;
	value64_fld.length = flvn_expiry;
	value64_fld.value  = cef_frame_htonb (expiry);
	memcpy (&buff[index], &value64_fld, sizeof (struct value64_tlv));
	index += CefC_S_TLF + CefC_S_Expiry;

	if ( index > CefC_Max_Length ) {
		return( index * -1 );
	}

	/*----- Sets T_ENDCHUNK		-----*/
	if (tlvs->end_chunk_num_f) {
		uint16_t end_chunk_len;
		uint16_t end_chunk_len_ns;
		uint64_t value;
		char buffer[128];
	 	int  i = 0;
	 	int mustContinue = 0;

		value = tlvs->end_chunk_num;
		memset(buffer, 0, sizeof(buffer));
		for (int byte = 7; byte >= 0; byte--) {
			uint8_t b = (value >> (byte * 8)) & 0xFF;
			if (b != 0 || byte == 0 || mustContinue) {
				buffer[i] = b;
				i++;
				mustContinue = 1;
			}
		}
		end_chunk_len = i;

		memcpy (&buff[index], &ftvn_endchunk, CefC_S_Type);
		index += CefC_S_Type;
		end_chunk_len_ns = htons(end_chunk_len);
		memcpy (&buff[index], &end_chunk_len_ns, CefC_S_Length);
		index += CefC_S_Length;
		memcpy (&buff[index], buffer, end_chunk_len);
		index += end_chunk_len;
	}

	if ( index > CefC_Max_Length ) {
		return( index * -1 );
	}

	/*----- ORG TLV 			-----*/
	if (tlvs->org.version_f) {
		index +=
			cef_frame_message_torg_set (&buff[index], tlvs);
	}

	/*----- PAYLOAD TLV 			-----*/
	if (tlvs->payload_len > 0) {
		fld_thdr.type   = ftvn_payload;
		fld_thdr.length = htons (tlvs->payload_len);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		memcpy (&buff[index + CefC_O_Value], tlvs->payload, tlvs->payload_len);
		index += CefC_S_TLF + tlvs->payload_len;
	}

	if ( index > CefC_Max_Length ) {
		return( index * -1 );
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

	if ( index > CefC_Max_Length ) {
		return( index * -1 );
	}

	if (rec_index != index) {
		index += cef_frame_validation_pld_tlv_create (
			&buff[CefC_S_Fix_Header + opt_header_len],
			index - (CefC_S_Fix_Header + opt_header_len),
			tlvs->name, tlvs->name_len, &tlvs->alg);
	}

	if ( index > CefC_Max_Length ) {
		return( index * -1 );
	}

	/*----------------------------------------------------------*/
	/* Frame Header 											*/
	/*----------------------------------------------------------*/
	fix_hdr.ccn_ver 	= CefC_Version;
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
	Creates the Ccninfo Request from the specified Parameters
----------------------------------------------------------------------------------------*/
int 										/* Length of Ccninfo message 				*/
cef_frame_ccninfo_req_create (
	unsigned char* buff, 					/* buffer to set Ccninfo Request			*/
	CefT_Ccninfo_TLVs* tlvs					/* Parameters to set Ccninfo Request 		*/
) {
	uint16_t opt_header_len;
	uint16_t index = 0;
	uint16_t rec_index;
	struct fixed_hdr fix_hdr;
	struct tlv_hdr fld_thdr;
	uint16_t msg_len;
	int res;
	uint16_t name_hdr_idx;
	uint16_t req_blk_idx;				/* ccninfo-o5 */
	struct ccninfo_req_block req_blk;	/* ccninfo-o5 */

	/*
     +---------------+---------------+---------------+---------------+
     |    Version    |  PacketType   |         PacketLength          |
     +---------------+---------------+---------------+---------------+
     |    HopLimit   |   ReturnCode  | Reserved(MBZ) | HeaderLength  |
     +===============+===============+===============+===============+
     /                    Request header block TLV                   /
     +---------------+---------------+---------------+---------------+
     /                      Report block TLV 1                       /
     +---------------+---------------+---------------+---------------+
     /                      Report block TLV 2                       /
     +---------------+---------------+---------------+---------------+
     /                               .                               /
     /                               .                               /
     +---------------+---------------+---------------+---------------+
     /                      Report block TLV n                       /
     +===============+===============+===============+===============+
     |      Type (=T_DISCOVERY)      |         MessageLength         |
     +---------------+---------------+---------------+---------------+
     |            T_NAME             |             Length            |
     +---------------+---------------+---------------+---------------+
     /   Name segment TLVs (name prefix specified by CCNinfo user)   /
     +---------------+---------------+---------------+---------------+
     /                       Request block TLV                       /
     +---------------+---------------+---------------+---------------+
     / Optional CCNx ValidationAlgorithm TLV                         /
     +---------------+---------------+---------------+---------------+
     / Optional CCNx ValidationPayload TLV (ValidationAlg rRequestequired)  /
     +---------------+---------------+---------------+---------------+
							figure: Ccninfo Request
	*/

#ifdef	DEB_CCNINFO
	fprintf( stderr, "[%s] IN\n",
				"cef_frame_ccninfo_req_create" );
#endif

	/*----------------------------------------------------------*/
	/* Option Header 											*/
	/*----------------------------------------------------------*/
	/* Constructs the option header */
	opt_header_len = cef_frame_ccninfo_req_opt_header_create (
											&buff[CefC_S_Fix_Header], tlvs);
	if (opt_header_len == 0){
		return (-1);
	}
	index = CefC_S_Fix_Header + opt_header_len;

	/*----------------------------------------------------------*/
	/* CEFORE message 											*/
	/*----------------------------------------------------------*/
	index += CefC_S_TLF;

	/*----- NAME TLV 				-----*/
	if (tlvs->name_len < CefC_S_TLF + 1) {
		return (0);
	}
	if (CefC_NAME_MAXLEN < tlvs->name_len) {
		cef_log_write (CefC_Log_Error,
			"T_NAME is too long (%d bytes), cefore does not support T_NAMEs longer than %u bytes.\n",
				tlvs->name_len, CefC_NAME_MAXLEN);
		return (-1);
	}
	fld_thdr.type 	= ftvn_name;
	fld_thdr.length = htons (tlvs->name_len);
	memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
	memcpy (&buff[index + CefC_O_Value], tlvs->name, tlvs->name_len);
	name_hdr_idx = index;
	index += CefC_S_TLF + tlvs->name_len;

	/* Sets chunk number	*/
	if (tlvs->chunk_num_f) {
		uint16_t chunk_len;
		uint16_t chunk_len_ns;
		uint64_t value;
		char buffer[128];
	 	int  i = 0;
	 	int mustContinue = 0;

		value = tlvs->chunk_num;
		memset(buffer, 0, sizeof(buffer));
		for (int byte = 7; byte >= 0; byte--) {
			uint8_t b = (value >> (byte * 8)) & 0xFF;
			if (b != 0 || byte == 0 || mustContinue) {
				buffer[i] = b;
				i++;
				mustContinue = 1;
			}
		}
		chunk_len = i;

//		memcpy (&buff[index], &ftvn_chunk, sizeof(CefC_S_Type));
		memcpy (&buff[index], &ftvn_chunk, CefC_S_Type);
		index += CefC_S_Type;
		chunk_len_ns = htons(chunk_len);
//		memcpy (&buff[index], &chunk_len_ns, sizeof(CefC_S_Length));
		memcpy (&buff[index], &chunk_len_ns, CefC_S_Length);
		index += CefC_S_Length;
		memcpy (&buff[index], buffer, chunk_len);
		index += chunk_len;

		/* set Name length */
		fld_thdr.type 	= ftvn_name;
		fld_thdr.length = htons (tlvs->name_len + CefC_S_TLF + chunk_len);
		memcpy (&buff[name_hdr_idx], &fld_thdr, sizeof (struct tlv_hdr));
	}

	/* Request Block ccninfo-05 */
	req_blk_idx = index;
	index += CefC_S_TLF;
	{	/* set 32bit-NTP time */
    	struct timespec tv;
		uint32_t ntp32b;
		clock_gettime(CLOCK_REALTIME, &tv);
		ntp32b = ((tv.tv_sec + 32384) << 16) + ((tv.tv_nsec << 7) / 1953125);
		req_blk.req_arrival_time 	= htonl (ntp32b);
	}
	memcpy (&buff[index], &req_blk, sizeof (struct ccninfo_req_block));
	index += sizeof (struct ccninfo_req_block);
	/* Node Identifier */
	memcpy (&buff[index], tlvs->opt.node_identifer, tlvs->opt.node_id_len);
	index += tlvs->opt.node_id_len;
	/* set Request Block length */
	fld_thdr.type 	= htons (CefC_T_DISC_REQ);
	fld_thdr.length = htons (tlvs->opt.node_id_len + sizeof (struct ccninfo_req_block));
	memcpy (&buff[req_blk_idx], &fld_thdr, sizeof (struct tlv_hdr));

	/*----- CEFORE message header 	-----*/
	msg_len = index - (CefC_S_Fix_Header + opt_header_len + CefC_S_TLF);
	fld_thdr.length = htons (msg_len);
	fld_thdr.type   = ftvn_pktype_discovery;
	memcpy (
		&buff[CefC_S_Fix_Header + opt_header_len], &fld_thdr, sizeof (struct tlv_hdr));

	/*----------------------------------------------------------*/
	/* Validations	 											*/
	/*----------------------------------------------------------*/
	rec_index = index;
	res = cef_frame_ccninfo_validation_alg_tlv_create (&buff[index], &tlvs->alg);
	if (res < 0) {
		return (-1);
	}
	index += res;
	if (rec_index != index) {
		index += cef_frame_ccninfo_validation_pld_tlv_create (
					&buff[CefC_S_Fix_Header + opt_header_len],
					index - (CefC_S_Fix_Header + opt_header_len),
					&tlvs->alg);
	}

	/*----------------------------------------------------------*/
	/* Fixed Header 											*/
	/*----------------------------------------------------------*/
	fix_hdr.ccn_ver 	= CefC_Version;
	fix_hdr.type 		= CefC_PT_REQUEST;
	fix_hdr.pkt_len 	= htons (index);
	fix_hdr.hoplimit 	= tlvs->hoplimit;;
	fix_hdr.reserve1 	= 0x00;
	fix_hdr.reserve2 	= 0x00;
	fix_hdr.hdr_len 	= CefC_S_Fix_Header + opt_header_len;

	memcpy (buff, &fix_hdr, sizeof (struct fixed_hdr));

#ifdef	DEB_CCNINFO
{
	int dbg_x;
	uint16_t plen = ntohs (fix_hdr.pkt_len);
	fprintf (stderr, "Req: msg[ ");
	for (dbg_x = 0; dbg_x < plen; dbg_x++)
		fprintf (stderr, "%02x ", buff[dbg_x]);
	fprintf (stderr, "](length=%d)\n", plen);
}
#endif

#ifdef	DEB_CCNINFO
	fprintf( stderr, "[%s] OUT\n",
				"cef_frame_ccninfo_req_create" );
#endif

	return (index);
}
/*--------------------------------------------------------------------------------------
	Adds a time stamp on Ccninfo Request
----------------------------------------------------------------------------------------*/
int 										/* Length of Ccninfo message 				*/
cef_frame_ccninfo_req_add_stamp (
	unsigned char* buff, 					/* Ccninfo Request							*/
	uint16_t msg_len,
	unsigned char* node_id, 				/* Node ID 									*/
	uint16_t id_len, 						/* length of Node ID 						*/
	struct timeval t 						/* current time in UNIX-time(us) 			*/
) {
	unsigned char work[CefC_Max_Length];
	uint8_t header_len;
	uint16_t index;
	struct value32_tlv value32_tlv;
	struct fixed_hdr* fix_hdr;

	/*
		+---------------+---------------+---------------+---------------+
		|         T_DISC_REPORT         |             Length            |
		+---------------+---------------+---------------+---------------+
		|                     Request Arrival Time                      |
		+---------------+---------------+---------------+---------------+
		/                        Node Identifier                        /
		+---------------+---------------+---------------+---------------+
							figure: Report Block
	*/
	/* Copy the payload of Ccninfo Request 	*/
	header_len = buff[CefC_O_Fix_HeaderLength];
	memcpy (work, &buff[header_len], msg_len - header_len);

	/* Add a time stamp on the end of the option header 	*/
	value32_tlv.type 	= ftvn_disc_rpt;
	value32_tlv.length 	= htons (id_len + ftvh_4byte);
	{	/* set 32bit-NTP time */
    	struct timespec tv;
		uint32_t ntp32b;
		clock_gettime(CLOCK_REALTIME, &tv);
		ntp32b = ((tv.tv_sec + 32384) << 16) + ((tv.tv_nsec << 7) / 1953125);
		value32_tlv.value 	= htonl (ntp32b);
		memcpy (&buff[header_len], &value32_tlv, sizeof (struct value32_tlv));
		index = header_len + CefC_S_TLF + ftvh_4byte;
	}

	memcpy (&buff[index], node_id, id_len);
	index += id_len;

	/* Sets the payload 			*/
	memcpy (&buff[index], work, msg_len - header_len);
	header_len = index;
	index = msg_len + CefC_S_TLF + ftvh_4byte + id_len;

	/* Updates PacketLength and HeaderLength 		*/
	fix_hdr = (struct fixed_hdr*) buff;
	fix_hdr->pkt_len = htons (index);
	fix_hdr->hdr_len = header_len;

	return (index);
}
/*--------------------------------------------------------------------------------------
	Creates the Validation TLVs for Ccninfo Reply message
----------------------------------------------------------------------------------------*/
int 										/* Length of Ccninfo message 				*/
cef_frame_ccninfo_vald_create_for_reply (
	unsigned char* buff, 					/* Ccninfo Reply message					*/
	CefT_Ccninfo_TLVs* tlvs					/* Parameters to set Ccninfo Reply 			*/
) {

	uint16_t rec_index;
	int res;
	struct fixed_hdr* 	fixed_hp;
	uint16_t 	hdr_len;
	uint16_t 	pkt_len;

	/* Obtains header length and packet length 		*/
	fixed_hp = (struct fixed_hdr*) buff;
	hdr_len = fixed_hp->hdr_len;
	pkt_len = ntohs (fixed_hp->pkt_len);

	/*----------------------------------------------------------*/
	/* Validations	 											*/
	/*----------------------------------------------------------*/
	rec_index = pkt_len;
	res = cef_frame_ccninfo_validation_alg_tlv_create (&buff[pkt_len], &tlvs->alg);
	pkt_len += res;
	if (rec_index != pkt_len) {
		pkt_len += cef_frame_ccninfo_validation_pld_tlv_create (
						&buff[hdr_len], (pkt_len - hdr_len), &tlvs->alg);
	}

	fixed_hp->pkt_len 	= htons (pkt_len);
	return (pkt_len);
}

/*--------------------------------------------------------------------------------------
	Updates the sequence number
----------------------------------------------------------------------------------------*/
size_t										/* length of buff/out_buff					*/
cef_frame_seqence_update (
	unsigned char* out_buff, 				/* out) updated packet buffer				*/
	unsigned char* in_buff, 				/*  in) base message packet					*/
	uint32_t seqnum
) {
	size_t packet_len = 0;
	struct fixed_hdr* fix_hdr;
	uint16_t ret = 0x0000;
	int t_org_index = -1;
	int seq_index = -1;
	const size_t st32tlv_size = sizeof(struct value32_tlv);
	int nidx = 0;
	int bidx = 0;

	fix_hdr = (struct fixed_hdr*) in_buff;
	packet_len = ntohs (fix_hdr->pkt_len);

	/* Search the position of T_ORG and OPT_SEQNUM in ContentObject */
	ret = cef_frame_opheader_seqnum_pos_search (in_buff, &t_org_index, &seq_index);

#ifdef	CefC_Debug
cef_dbg_write(CefC_Dbg_Finer, "ret=0x%04x, t_org_index=%d, seq_index=%d\n", ret, t_org_index, seq_index);
#endif	// CefC_Debug

	if(cef_frame_get_opt_seqnum_f()) {
		uint8_t hdr_len = fix_hdr->hdr_len;
		uint16_t pay_len = packet_len - hdr_len;
		uint16_t pkt_len = packet_len;
		struct value32_tlv value32_fld;
		struct tlv_hdr* thdr;

		if (ret&Opt_T_Org_exist && ret&Opt_T_OrgSeq_exist && CefC_S_Fix_Header <= seq_index) {
			/*----------------------------------------------------------*/
			/* update OPT_SEQNUM											*/
			/*----------------------------------------------------------*/
			memcpy(out_buff, in_buff, packet_len);
			struct value32_tlv* value32_fld_p;
			value32_fld_p = (struct value32_tlv*) &out_buff[seq_index];
			value32_fld_p->value = htonl (seqnum);
			return (packet_len);
		} else if (ret&Opt_T_Org_exist && CefC_S_Fix_Header <= t_org_index) {
			/*----------------------------------------------------------*/
			/* set OPT_SEQNUM												*/
			/*----------------------------------------------------------*/
			uint16_t old_torg_len;
			uint16_t new_torg_len;

			/* copy Fixed/Option Header */
			memcpy(out_buff, in_buff, fix_hdr->hdr_len);

			/* seek T_ORG */
			thdr = (struct tlv_hdr*) &in_buff[t_org_index];
			old_torg_len = ntohs(thdr->length);
			new_torg_len = old_torg_len + st32tlv_size;
#ifdef	CefC_Debug
cef_dbg_write(CefC_Dbg_Finest, "old_torg_len=%d, new_torg_len=%d\n", old_torg_len, new_torg_len);
#endif	// CefC_Debug

			memcpy(&out_buff[t_org_index], &in_buff[t_org_index], old_torg_len);
			thdr = (struct tlv_hdr*) &out_buff[t_org_index];
			thdr->length = htons(new_torg_len);

			/* set OPT_SEQNUM */
			value32_fld.type   = ftvn_seqnum;
			value32_fld.length = flvn_seqnum;
			value32_fld.value  = htonl (seqnum);
			nidx = t_org_index + CefC_S_TLF + old_torg_len;
			memcpy (&out_buff[nidx], &value32_fld, st32tlv_size);

			/* copy (remain Option Header and) payload */
			nidx += st32tlv_size;
			bidx = t_org_index + CefC_S_TLF + old_torg_len;
			memcpy(&out_buff[nidx], &in_buff[bidx], (pkt_len - bidx));

			/* Calc Length */
			hdr_len = fix_hdr->hdr_len + st32tlv_size;
			packet_len = ntohs (fix_hdr->pkt_len) + st32tlv_size;
			pkt_len = htons(packet_len);
		} else {
			/*----------------------------------------------------------*/
			/* set T_ORG and OPT_SEQNUM									*/
			/*----------------------------------------------------------*/
			struct tlv_hdr thdr;

			/* copy Fixed Header and Option Header */
			memcpy(out_buff, in_buff, hdr_len);
			nidx = hdr_len;
			bidx = hdr_len;
			/* create T_ORG */
			thdr.type = htons (CefC_T_ORG);
			thdr.length = htons (CefC_S_PEN + st32tlv_size);
			memcpy (&out_buff[nidx], &thdr, sizeof (struct tlv_hdr));
			nidx += CefC_S_TLF;
			/* Sets IANA Private Enterprise Numbers */
			out_buff[nidx++] = (0xFF0000 & CefC_NICT_PEN) >> 16;
			out_buff[nidx++] = (0x00FF00 & CefC_NICT_PEN) >> 8;
			out_buff[nidx++] = (0x0000FF & CefC_NICT_PEN);
			/* set OPT_SEQNUM */
			value32_fld.type   = ftvn_seqnum;
			value32_fld.length = flvn_seqnum;
			value32_fld.value  = htonl (seqnum);
			memcpy (&out_buff[nidx], &value32_fld, st32tlv_size);
			nidx += CefC_S_TLF + flvh_seqnum;
			/* copy payload */
			memcpy (&out_buff[nidx], &in_buff[bidx], pay_len);

			/* Calc Length */
			hdr_len += (sizeof(struct tlv_hdr) + CefC_S_PEN + st32tlv_size);
			packet_len = ntohs (fix_hdr->pkt_len)
									+ sizeof(struct tlv_hdr)		/* new T_ORG */
									+ CefC_S_PEN					/* PEN */
									+ st32tlv_size;					/* OPT_SEQNUM */
			pkt_len = htons(packet_len);
		}
#ifdef	CefC_Debug
cef_dbg_write(CefC_Dbg_Finer, "nidx=%d, bidx=%d\n", nidx, bidx);
cef_dbg_write(CefC_Dbg_Finer, "out_buff=0x%p, packet_len=%zu\n", out_buff, packet_len);
cef_dbg_write(CefC_Dbg_Finer, "hdr_len=%d, pkt_len=%d\n", hdr_len, ntohs(pkt_len));
#endif	// CefC_Debug

		/* Sets Length */
		memcpy(&out_buff[CefC_O_Fix_HeaderLength], &hdr_len, sizeof(hdr_len));
		memcpy(&out_buff[CefC_O_Fix_PacketLength], &pkt_len, sizeof(pkt_len));

		return (packet_len);
	} else {
		uint16_t new_torg_len;
		uint16_t pay_len;
		struct tlv_hdr* thdr;

		pay_len = packet_len - fix_hdr->hdr_len;

		if (ret&Opt_T_OrgSeq_exist && ret&Opt_T_OrgOther_exist && CefC_S_Fix_Header <= seq_index) {
			/*----------------------------------------------------------*/
			/* Remove OPT_SEQNUM from this frame.						*/
			/*----------------------------------------------------------*/
			packet_len = ntohs (fix_hdr->pkt_len) - st32tlv_size;
			/* copy Fixed Header and Option Header */
			fix_hdr->pkt_len = htons(packet_len);
			fix_hdr->hdr_len = packet_len - pay_len;
			memcpy(out_buff, in_buff, seq_index);
			nidx += seq_index;
			bidx += seq_index;
			/* remove OPT_SEQNUM */
			bidx += st32tlv_size;
			thdr = (struct tlv_hdr*) &in_buff[t_org_index];
			new_torg_len = ntohs (thdr->length) - st32tlv_size;
			thdr->length = htons(new_torg_len);
			/* copy (remain Option Header and) payload */
			memcpy(&out_buff[nidx], &in_buff[bidx], (packet_len - seq_index));
#if	0	/* We will not remove the OPT_SEQNUM TLV as it may be reused. */
		} else if (ret&Opt_T_OrgSeq_exist && CefC_S_Fix_Header <= t_org_index) {
			/*----------------------------------------------------------*/
			/* Remove OPT_SEQNUM (and T_ORG) from this frame.			*/
			/*----------------------------------------------------------*/
			packet_len = packet_len
								- sizeof(struct tlv_hdr)		/* new T_ORG */
								- CefC_S_PEN					/* PEN */
								- st32tlv_size;
			/* copy Fixed Header and Option Header */
			fix_hdr->pkt_len = htons(packet_len);
			fix_hdr->hdr_len = packet_len - pay_len;
			memcpy(out_buff, in_buff, t_org_index);
			nidx += t_org_index;
			bidx += t_org_index;
			/* remove T_ORG */
			bidx += (sizeof(struct tlv_hdr) + CefC_S_PEN + st32tlv_size);
			/* copy (remain Option Header and) payload */
			memcpy(&out_buff[nidx], &in_buff[bidx], (packet_len - t_org_index));
#endif
		} else {
			/*----------------------------------------------------------*/
			/* This frame is not attached with OPT_SEQNUM.				*/
			/*----------------------------------------------------------*/
			memcpy(out_buff, in_buff, packet_len);
		}
		return (packet_len);
	}
}
/*--------------------------------------------------------------------------------------
	Search the position of T_ORG and OPT_SEQNUM in ContentObject
----------------------------------------------------------------------------------------*/
static uint16_t								/* Flag indicating the existence of a field	*/
cef_frame_opheader_seqnum_pos_search (
	unsigned char* buff,					/* Head of ContentObject					*/
	int* t_org_idx,							/* OUT: position of T_ORG					*/
	int* t_seqnum_idx						/* OUT: position of OPT_SEQNUM				*/
){
	uint16_t ret = 0x0000;
	unsigned char* wmp;
	unsigned char* emp;
	struct fixed_hdr* fix_hdr = (struct fixed_hdr*) buff;

	*t_org_idx = -1;
	*t_seqnum_idx = -1;

	/* head position of option header */
	wmp = &buff[CefC_S_Fix_Header];
	/* end of header = start of payload */
	emp = buff + fix_hdr->hdr_len;
	while (wmp < emp) {
		uint16_t type;
		uint16_t length;
		struct tlv_hdr* thdr;

		thdr = (struct tlv_hdr*) wmp;
		type   = ntohs (thdr->type);
		length = ntohs (thdr->length);

		if(type == CefC_T_OPT_ORG) {
			unsigned char* ewmp;
			/* Check IANA Private Enterprise Numbers */
			if( (((CefC_NICT_PEN & 0xFF0000) >> 16) != wmp[CefC_S_TLF])   ||
				(((CefC_NICT_PEN & 0x00FF00) >>  8) != wmp[CefC_S_TLF+1]) ||
				(((CefC_NICT_PEN & 0x0000FF)      ) != wmp[CefC_S_TLF+2])){
				/* Unknown PEN */
				wmp += (CefC_S_TLF + length);
			} else {
				*t_org_idx = (wmp - buff);	/* position of T_ORG */
				ret |= Opt_T_Org_exist;
				wmp += 7;	/* type + length + PEN */
				ewmp = wmp + (length - CefC_S_PEN);
				while (wmp < ewmp) {
					thdr = (struct tlv_hdr*) &wmp[0];
					switch (ntohs(thdr->type)) {
						case CefC_T_OPT_SEQNUM: {
							*t_seqnum_idx = (wmp - buff);
							ret |= Opt_T_OrgSeq_exist;
							wmp += (CefC_S_TLF + ntohs(thdr->length));
							break;
						}
						default:
							if (wmp[0] & 0x80){
								/* exist length field */
								wmp += (CefC_S_TLF + ntohs(thdr->length));
							} else {
								/* only type field */
								wmp += CefC_S_Type;
							}
							ret |= Opt_T_OrgOther_exist;
							break;
					}
				}
			}
		} else {
			wmp += (CefC_S_TLF + length);
		}
	}

	return(ret);
}
/*--------------------------------------------------------------------------------------
	Update cache time
----------------------------------------------------------------------------------------*/
void 										/* Returns a negative value if it fails 	*/
cef_frame_opheader_cachetime_update (
	unsigned char* 	cob, 					/* the cob message to parse					*/
	uint64_t		cachetime
) {
	unsigned char* scp;
	unsigned char* ecp;
	unsigned char* wcp;
	struct tlv_hdr* thdr;
	uint16_t length;
	uint16_t type;
	uint64_t val64u;

	/*----------------------------------------------------------------------*/
	/* Parses Option Header				 									*/
	/*----------------------------------------------------------------------*/
	scp = cob + CefC_S_Fix_Header;
	length = cob[CefC_O_Fix_HeaderLength] - CefC_S_Fix_Header;

	wcp = scp;
	ecp = scp + length;

	while (wcp < ecp) {
		thdr = (struct tlv_hdr*) wcp;
		type   = ntohs (thdr->type);
		length = ntohs (thdr->length);

		if (type == CefC_T_OPT_CACHETIME) {
			/* set */
			val64u = cachetime;
			CefC_Frame_us2ms (val64u);
			val64u  = cef_frame_htonb (val64u);
			memcpy(&wcp[CefC_S_TLF], &val64u, sizeof (val64u));
		}

		wcp += CefC_S_TLF + length;
	}
}

/*--------------------------------------------------------------------------------------
	Creates the Option Header of Interest
----------------------------------------------------------------------------------------*/
static uint16_t								/* Length of Option Header					*/
cef_frame_interest_opt_header_create (
	unsigned char* buff, 					/* buffer to set a message					*/
	CefT_CcnMsg_OptHdr* opt				/* parameters to Option Header(s)			*/
) {
	unsigned int index = 0;
	unsigned int rec_index;
	struct tlv_hdr fld_thdr;
	struct value16_tlv value16_fld;

	/* Sets the T_ORG	(t_hw_flags_f must be the top of option header)	*/
	if (opt->org_len || opt->org.t_hw_flags_f || opt->org.tp_variant){
		index += cef_frame_opheader_torg_set (&buff[index], opt);
	}

	/* Sets Lifetime 				*/
	if (opt->lifetime_f) {
		if (opt->lifetime > 0) {
			value16_fld.type   = ftvn_intlife;
			value16_fld.length = ftvn_2byte;
			value16_fld.value  = htons (opt->lifetime);
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

	/* Sets the User Local Variant 	*/
	rec_index = index;
	index += CefC_S_TLF;

	switch (opt->app_reg_f) {
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
		case CefC_T_OPT_APP_REG_P: {
			fld_thdr.type 	= ftvn_app_reg_p;
			fld_thdr.length = 0x0000;
			memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
			index += CefC_S_TLF;
			break;
		}
		case CefC_T_OPT_APP_PIT_REG: {
			fld_thdr.type 	= ftvn_app_reg_pit;
			fld_thdr.length = 0x0000;
			memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
			index += CefC_S_TLF;
			break;
		}
		case CefC_T_OPT_APP_PIT_DEREG: {
			fld_thdr.type 	= ftvn_app_dereg_pit;
			fld_thdr.length = 0x0000;
			memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
			index += CefC_S_TLF;
			break;
		}
		case CefC_T_OPT_DEV_REG_PIT: {
			struct value32_tlv value32_fld;
			struct value64_tlv value64_fld;
			uint64_t cachetime = opt->cachetime;
			CefC_Frame_us2ms (cachetime);

			value32_fld.type 	= ftvn_dev_reg_pit;
			value32_fld.length  = htons (sizeof(uint32_t));
			value32_fld.value 	= htonl (opt->dev_reg_pit_num);
			memcpy (&buff[index], &value32_fld, sizeof (value32_fld));
			index += CefC_S_TLF + sizeof(uint32_t);

			/* Use cache time instead of lifetime */
			value64_fld.type   = ftvn_rct;
			value64_fld.length = flvn_rct;
			value64_fld.value  = cef_frame_htonb (cachetime);
			memcpy (&buff[index], &value64_fld, sizeof (struct value64_tlv));
			index += CefC_S_TLF + flvh_rct;

			break;
		}
		default: {
			if ( CefC_T_OPT_USER_TLV <= opt->app_reg_f ){
				fld_thdr.type 	= htons(opt->app_reg_f);
				fld_thdr.length = 0x0000;		/* without value */
				memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
				index += CefC_S_TLF;
			}
			/* NOP */;
			break;
		}
	}

	if (rec_index + CefC_S_TLF != index) {
		fld_thdr.type 	= htons (CefC_T_OPT_USER_TLV);
		fld_thdr.length = htons (index - (CefC_S_TLF + rec_index));
		memcpy (&buff[rec_index], &fld_thdr, sizeof (struct tlv_hdr));
	} else {
		index = rec_index;
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
	CefT_CcnMsg_OptHdr* opt				/* parameters to Option Header(s)			*/
) {
	unsigned int index = 0;
	struct value64_tlv value64_fld;

	/* Sets the T_ORG	(t_hw_flags_f must be the top of option header)	*/
	if (opt->org_len || opt->org.t_hw_flags_f || opt->org.tp_variant){
		index += cef_frame_opheader_torg_set (&buff[index], opt);
	}

	/* Sets Recommended Cache Time (RCT)	*/
	if (opt->cachetime_f) {
		uint64_t cachetime = opt->cachetime;
		CefC_Frame_us2ms (cachetime);
		value64_fld.type   = ftvn_rct;
		value64_fld.length = flvn_rct;
		value64_fld.value  = cef_frame_htonb (cachetime);
		memcpy (&buff[index], &value64_fld, sizeof (struct value64_tlv));

		index += CefC_S_TLF + flvh_rct;
	}

	/* Sets Message Hash Value (MsgHash)	*/
	if (opt->MsgHash_f && 0 < opt->MsgHash_len) {
		struct tlv_hdr fld_thdr;

		fld_thdr.type   = ftvn_msghash;
		fld_thdr.length = htons(opt->MsgHash_len);
		memcpy (&buff[index], &fld_thdr, sizeof (fld_thdr));
		index += CefC_S_TLF;

		memcpy (&buff[index], &(opt->MsgHash), opt->MsgHash_len);
		index += opt->MsgHash_len;
	}

	if (index + CefC_S_Fix_Header > CefC_Max_Header_Size) {
		cef_log_write (CefC_Log_Warn,
			"[frame] Size of the created Object option header (%d bytes) is"
			" greater than 247 bytes\n", index);
		return (0);
	}

	return ((uint16_t) index);
}

/*--------------------------------------------------------------------------------------
	Creates the Option Header of Ccninfo Request
----------------------------------------------------------------------------------------*/
static uint16_t								/* Length of Option Header					*/
cef_frame_ccninfo_req_opt_header_create (
	unsigned char* buff, 					/* buffer to set a message					*/
	CefT_Ccninfo_TLVs* tlvs					/* Parameters to set Ccninfo Request		*/
) {
	uint16_t index = 0;
	struct tlv_hdr fld_thdr;
	struct ccninfo_reqhdr_block req_blk;
	CEF_FRAME_SKIPHOP_T	w_skiphop;
	/*
		+---------------+---------------+---------------+---------------+
		|     Type (=T_DISC_REQHDR)     |             Length            |
		+---------------+---------------+-------+-------+-------+-+-+-+-+
		|           Request ID          |SkipHop|      Flags    |V|F|O|C|
		+---------------+---------------+-------+-------+-------+-+-+-+-+

		+---------------+---------------+---------------+---------------+
		|             T_ORG             |     Length (3+value length)   |
		+---------------+---------------+---------------+---------------+
		|     PEN[0]    |    PEN[1]     |     PEN[2]    |               /
		+---------------+---------------+---------------+               +
		/                  Vendor Specific Value                        /
		+---------------+---------------+---------------+---------------+
	*/

	/* Sets Type and Length fields index */
	index += CefC_S_TLF;

	/* Sets the Request ID 			*/
	req_blk.req_id				= htons (tlvs->opt.req_id);
//JK	req_blk.skiphop				= tlvs->opt.skip_hop;
	w_skiphop.sh_4bit = tlvs->opt.skip_hop;
	w_skiphop.fl_4bit = 0;
	memcpy(&req_blk.skiphop, &w_skiphop, 1);

	req_blk.flag				= tlvs->opt.ccninfo_flag;

#if 0
	{	/* set 32bit-NTP time */
    	struct timespec tv;
		uint32_t ntp32b;
		clock_gettime(CLOCK_REALTIME, &tv);
		ntp32b = ((tv.tv_sec + 32384) << 16) + ((tv.tv_nsec << 7) / 1953125);
		req_blk.req_arrival_time 	= htonl (ntp32b);
	}
	memcpy (&buff[index], &req_blk, sizeof (struct ccninfo_req_block));
	index += sizeof (struct ccninfo_req_block);
	/* Node Identifier */
	memcpy (&buff[index], tlvs->opt.node_identifer, tlvs->opt.node_id_len);
	index += tlvs->opt.node_id_len;
#endif

	memcpy (&buff[index], &req_blk, sizeof (struct ccninfo_reqhdr_block));
	index += sizeof (struct ccninfo_reqhdr_block);

	/* Sets Type and Length fields 	*/
	fld_thdr.type 	= ftvn_disc_reqhdr;			/* ccninfo-05 */
	fld_thdr.length = htons (index-CefC_S_TLF);
	memcpy (&buff[0], &fld_thdr, sizeof (struct tlv_hdr));

	if (index + CefC_S_Fix_Header > CefC_Max_Header_Size) {
		cef_log_write (CefC_Log_Warn,
			"[frame] Size of the created Ccninfo option header (%d bytes) is"
			" greater than 247 bytes\n", index);
		return (0);
	}

	return (index);
}
/*--------------------------------------------------------------------------------------
	Creates the Validation Algorithm TLV
----------------------------------------------------------------------------------------*/
static uint16_t								/* Length of Option Header					*/
cef_frame_ccninfo_validation_alg_tlv_create (
	unsigned char* buff, 					/* buffer to set a message					*/
	CefT_Valid_Alg_TLVs* tlvs				/* Parameters to set Interest 				*/
) {
	unsigned int index 		= 0;
	unsigned int value_len 	= 0;
	struct tlv_hdr fld_thdr;
	uint16_t 		pubkey_len;
	unsigned char 	pubkey[CefC_PUBKEY_BUFSIZ];

	if (tlvs->valid_type == CefC_T_CRC32C) {
		index += CefC_S_TLF;

		fld_thdr.type 	= ftvn_crc32c;
		fld_thdr.length = 0;
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		index += CefC_S_TLF;
		value_len += CefC_S_TLF;

	} else if (tlvs->valid_type == CefC_T_RSA_SHA256) {
		CefT_HashData	 keyid = { CefC_T_SHA_256, CefC_KeyId_SIZ, "" };	/* KeyId */

		pubkey_len = (uint16_t) cef_valid_keyid_create_forccninfo (pubkey, keyid.hash_value);;
		if (pubkey_len == 0) {
			return (0);
		}
		index += CefC_S_TLF;

		fld_thdr.type 	= ftvn_rsa_sha256;
		fld_thdr.length = htons (CefC_S_TLF + CefC_S_TLF + keyid.hash_length \
								+ CefC_S_TLF + pubkey_len);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		index += CefC_S_TLF;

		fld_thdr.type 	= htons(CefC_T_KEYID);
		fld_thdr.length = htons(keyid.hash_length + CefC_S_TLF);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		index += CefC_S_TLF;

		fld_thdr.type 	= htons(keyid.hash_type);
		fld_thdr.length = htons(keyid.hash_length);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		index += CefC_S_TLF;

		memcpy (&buff[index], keyid.hash_value, CefC_KeyId_SIZ);
		index += CefC_KeyId_SIZ;

		fld_thdr.type 	= ftvn_pubkey;
		fld_thdr.length = htons (pubkey_len);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		memcpy (&buff[index + CefC_S_TLF], pubkey, pubkey_len);
		index += CefC_S_TLF + pubkey_len;

		value_len += (index - CefC_S_TLF);

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
cef_frame_ccninfo_validation_pld_tlv_create (
	unsigned char* buff, 					/* buffer to set a message					*/
	uint16_t buff_len,
	CefT_Valid_Alg_TLVs* tlvs				/* Parameters to set Interest 				*/
) {
	unsigned int index = 0;
	uint32_t crc_code;
	struct tlv_hdr fld_thdr;
	struct value32_tlv v32_thdr;
	unsigned char sign[256];
	unsigned int sign_len;
	int res;

	if (tlvs->valid_type == CefC_T_CRC32C) {
		crc_code = cef_valid_crc32c_calc (buff, buff_len);
		v32_thdr.type 	= ftvn_valid_pld;
		v32_thdr.length = ftvn_4byte;
		v32_thdr.value  = htonl (crc_code);
		memcpy (&buff[buff_len], &v32_thdr, sizeof (struct value32_tlv));
		index = sizeof (struct value32_tlv);

	} else if (tlvs->valid_type == CefC_T_RSA_SHA256) {

		res = cef_valid_rsa_sha256_dosign_forccninfo (buff, buff_len, sign, &sign_len);
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
	uint16_t 		pubkey_len;
	unsigned char 	pubkey[CefC_PUBKEY_BUFSIZ];

	if (tlvs->hop_by_hop_f) {
		/* HOP-BY-HOP */
	} else if (tlvs->valid_type == CefC_T_CRC32C) {
		index += CefC_S_TLF;

		fld_thdr.type 	= ftvn_crc32c;
		fld_thdr.length = 0;
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		index += CefC_S_TLF;
		value_len += CefC_S_TLF;

	} else if (tlvs->valid_type == CefC_T_RSA_SHA256) {
		CefT_HashData	 keyid = { CefC_T_SHA_256, CefC_KeyId_SIZ, "" };	/* KeyId */

		// Note: cef_valid_keyid_create only supports SHA256 hash.
		pubkey_len = (uint16_t) cef_valid_keyid_create (name, name_len, pubkey, keyid.hash_value);
		if (pubkey_len == 0) {
			return (0);
		}
		index += CefC_S_TLF;

		fld_thdr.type 	= ftvn_rsa_sha256;
		fld_thdr.length = htons (CefC_S_TLF + CefC_S_TLF + keyid.hash_length \
								+ CefC_S_TLF + pubkey_len);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		index += CefC_S_TLF;

		fld_thdr.type 	= htons(CefC_T_KEYID);
		fld_thdr.length = htons(keyid.hash_length + CefC_S_TLF);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		index += CefC_S_TLF;

		fld_thdr.type 	= htons(keyid.hash_type);
		fld_thdr.length = htons(keyid.hash_length);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		index += CefC_S_TLF;

#ifdef	__RESTRICT__
		{
			printf( "%s\n", __func__ );
			int dbg_x;
			fprintf (stderr, "KeyId [ ");
			for (dbg_x = 0 ; dbg_x < keyid.hash_length ; dbg_x++) {
				fprintf (stderr, "%02x ", keyid.hash_value[dbg_x]);
			}
			fprintf (stderr, "]\n");
		}
#endif

		memcpy (&buff[index], keyid.hash_value, keyid.hash_length);
		index += keyid.hash_length;

		fld_thdr.type 	= ftvn_pubkey;
		fld_thdr.length = htons (pubkey_len);
		memcpy (&buff[index], &fld_thdr, sizeof (struct tlv_hdr));
		memcpy (&buff[index + CefC_S_TLF], pubkey, pubkey_len);
		index += CefC_S_TLF + pubkey_len;

		value_len += (index - CefC_S_TLF);

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
		crc_code = cef_valid_crc32c_calc (buff, buff_len);
		v32_thdr.type 	= ftvn_valid_pld;
		v32_thdr.length = ftvn_4byte;
		v32_thdr.value  = htonl (crc_code);
		memcpy (&buff[buff_len], &v32_thdr, sizeof (struct value32_tlv));
		index = sizeof (struct value32_tlv);

	} else if (tlvs->valid_type == CefC_T_RSA_SHA256) {

		res = cef_valid_rsa_sha256_dosign (buff, buff_len, name, name_len, sign, &sign_len);

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
	CefT_CcnMsg_OptHdr* poh, 				/* Structure to set parsed Option Header	*/
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
	CefT_CcnMsg_OptHdr* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
	if (length != CefC_S_Lifetime) {
		poh->lifetime 	= 0;
	} else {
		poh->lifetime	= *((uint16_t*) value);
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
	CefT_CcnMsg_OptHdr* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
	memcpy (&poh->cachetime, value, sizeof (uint64_t));
	poh->cachetime 	 = cef_frame_ntohb (poh->cachetime);
	CefC_Frame_ms2us (poh->cachetime);
	poh->cachetime_f = offset;
	return (1);
}
/*--------------------------------------------------------------------------------------
	Parses a Message Hash TLV in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_msghash_tlv_parse (
	CefT_CcnMsg_OptHdr* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
	uint16_t	*u16_value = (uint16_t *)value;

	memset( &(poh->MsgHash), 0x00, sizeof(poh->MsgHash) );

	poh->MsgHash_len = length;
	poh->MsgHash.hash_type = ntohs(u16_value[0]);
	poh->MsgHash.hash_length = ntohs(u16_value[1]);
	memcpy( poh->MsgHash.hash_value, &value[CefC_S_TLF], poh->MsgHash.hash_length);
	poh->MsgHash_f = offset + CefC_S_TLF;

	return (1);
}
/*--------------------------------------------------------------------------------------
	Parses a Ccninfo Request Block in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_ccninfo_req_tlv_parse (
	CefT_CcnMsg_OptHdr* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
//	struct ccninfo_req_block* req_blk;
	struct ccninfo_reqhdr_block* req_blk;
	CEF_FRAME_SKIPHOP_T	w_skiphop;

	req_blk = (struct ccninfo_reqhdr_block*) value;

//	uint16_t index = 0;
	poh->req_id				= ntohs (req_blk->req_id);
//	poh->skip_hop			= req_blk->skiphop;
	memcpy(&w_skiphop, &req_blk->skiphop, 1);
	poh->skip_hop = w_skiphop.sh_4bit;

	poh->skip_hop_offset	= offset + CefC_S_TLF + 2;
	poh->ccninfo_flag			= req_blk->flag;
//	poh->req_arrival_time	= ntohl (req_blk->req_arrival_time);
//	index = sizeof (struct ccninfo_req_block);
//	poh->id_len = length - index;
//	memcpy(poh->node_id, &value[index], poh->id_len);

	return (1);
}
/*--------------------------------------------------------------------------------------
	Parses a Ccninfo Report Block in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_ccninfo_rep_tlv_parse (
	CefT_CcnMsg_OptHdr* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
	if (poh->rpt_block_offset) {
		return (1);
	}
	poh->rpt_block_offset = offset;
	return (1);
}
/*--------------------------------------------------------------------------------------
	Parses a User Specific TLV in an Option Header
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_opheader_user_tlv_parse (
	CefT_CcnMsg_OptHdr* poh, 				/* Structure to set parsed Option Header	*/
	uint16_t type, 							/* Type of this TLV						*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
	uint16_t sub_type;
	uint16_t sub_len;
	uint16_t index = 0;
	struct tlv_hdr* thdr;

#ifdef	__JK_TEST_CODE__
			printf( "[%s] length=%d\n",
					"cef_frame_opheader_user_tlv_parse", length );
#endif

	switch (type) {

		case CefC_T_OPT_USER_TLV: {

			while (index < length) {
				thdr = (struct tlv_hdr*) &value[index];
				sub_type = ntohs (thdr->type);
				sub_len  = ntohs (thdr->length);
				index += CefC_S_TLF;

				if ( CefC_T_OPT_USER_TLV < sub_type ) {
					poh->app_reg_f = sub_type;
				}
				if (sub_type == CefC_T_OPT_DEV_REG_PIT) {
					uint32_t* v32p = (uint32_t*)(&value[index]);

					if ( sub_len == sizeof(*v32p) ){
						poh->dev_reg_pit_num = ntohl (*v32p);
					}

					/* Use cache time instead of lifetime */
					memcpy (&poh->cachetime, &value[index+sub_len+CefC_S_TLF], sizeof (uint64_t));
					poh->cachetime 	 = cef_frame_ntohb (poh->cachetime);
					CefC_Frame_ms2us (poh->cachetime);
					poh->cachetime_f = index + sub_len;
					index += CefC_S_TLF + flvh_rct;
				}

				index += sub_len;
			}
			break;
		}
		case CefC_T_OPT_ORG: {
#ifdef	__JK_TEST_CODE__
			printf( "[%s] CefC_T_OPT_ORG\n",
					"cef_frame_opheader_user_tlv_parse" );
#endif
			unsigned char* wp;
			unsigned char* ewp;

			if (length < 4) {
				/* PEN+a */
				break;
			}
			/* Get IANA Private Enterprise Numbers */
			if( (((CefC_NICT_PEN & 0xFF0000) >> 16) != value[index])
				  ||
				(((CefC_NICT_PEN & 0x00FF00) >>  8) != value[++index])
				  ||
				(((CefC_NICT_PEN & 0x0000FF)      ) != value[++index])){
					break;
			}
			index++;

			wp = &value[index];
			ewp = &value[index+length-CefC_S_PEN];

			/* Get T_ORG Length */
			poh->org_len = (ewp - wp);
			/* Get T_ORG Value */
			memcpy(&poh->org_val, wp, poh->org_len);

			while (wp < ewp) {
				uint16_t	t_typ;
				thdr = (struct tlv_hdr*) &wp[0];
				t_typ = ntohs(thdr->type);
				switch ( t_typ ) {
					case CefC_T_OPT_SEQNUM:
						poh->seqnum = ntohl ((uint32_t)(*((uint32_t*) &wp[CefC_S_TLF])));
						wp += (CefC_S_TLF + ntohs(thdr->length));
						index += (CefC_S_TLF + ntohs(thdr->length));
						break;
					case CefC_T_OPT_TRANSPORT:
						/* Obtains type and length of the transport variant 	*/
						thdr = (struct tlv_hdr*) &value[index + CefC_S_Type + CefC_S_Length];
						poh->org.tp_variant = ntohs (thdr->type);
						poh->org.tp_len  = ntohs (thdr->length);
						wp += (CefC_S_TLF + ntohs(thdr->length));
						index += (CefC_S_TLF		/* TL of transport plugin */
									+ CefC_S_TLF);	/* TL of transport variant */

						/* Obtains the value field of transport variant 	*/
						if (poh->org.tp_variant < CefC_T_OPT_TP_NUM) {
							if (poh->org.tp_len > 0) {
								memcpy (poh->org.tp_val, &value[index], poh->org.tp_len);
								index += poh->org.tp_len;
							}
						} else {
							poh->org.tp_variant = CefC_T_OPT_TP_NONE;
							poh->org.tp_len  = 0;
						}
						break;
					case CefC_T_HW_FLAGS:
					case (CefC_T_HW_FLAGS|CefC_T_HW_FLAGS_SYMBOLIC):
					case (CefC_T_HW_FLAGS|CefC_T_HW_FLAGS_ENABLECACHE):
					case (CefC_T_HW_FLAGS|CefC_T_HW_FLAGS_SYMBOLIC|CefC_T_HW_FLAGS_ENABLECACHE):
						poh->org.t_hw_flags_f = 1;
						poh->org.t_hw_flags_symbolic_f = (t_typ & CefC_T_HW_FLAGS_SYMBOLIC) ? 1 : 0;
						poh->org.t_hw_flags_enablecache_f = (t_typ & CefC_T_HW_FLAGS_ENABLECACHE) ? 1 : 0;
						wp += CefC_S_Type;
						index += CefC_S_Type;
						break;
					case CefC_T_HW_TIMESTAMP:{
						uint16_t ts_len = ntohs(thdr->length);
						poh->org.t_hw_timestamp_f = 1;
						if ( (sizeof(uint32_t) * 2) < ts_len ){
							poh->org.t_hw_timestamp_long_f = 1;
							poh->org.t_hw_timestamp_in = ntohl ((uint64_t)(*((uint64_t*) &wp[CefC_S_TLF])));
							poh->org.t_hw_timestamp_out = ntohl ((uint64_t)(*((uint64_t*) &wp[CefC_S_TLF+sizeof(uint64_t)])));
						} else {
							poh->org.t_hw_timestamp_long_f = 0;
							poh->org.t_hw_timestamp_in = ntohl ((uint32_t)(*((uint32_t*) &wp[CefC_S_TLF])));
							poh->org.t_hw_timestamp_out = ntohl ((uint32_t)(*((uint32_t*) &wp[CefC_S_TLF+sizeof(uint32_t)])));
						}
						wp += (CefC_S_TLF + ts_len);
						index += (CefC_S_TLF + ts_len);
						break;
					}
					default:
#ifdef	__JK_TEST_CODE__
			printf( "[%s] CefC_T_OPT_ORG  default\n",
					"cef_frame_opheader_user_tlv_parse" );
#endif
						if (wp[0] & 0x80){
							/* exist length field */
							wp += (CefC_S_TLF + ntohs(thdr->length));
							index += (CefC_S_TLF + ntohs(thdr->length));
						} else {
							/* only type field */
							wp += CefC_S_Type;
							index += CefC_S_Type;
						}
						break;
				}
			}

			break;
		}
		default: {
			break;
		}
	}
	return (1);
}
/*--------------------------------------------------------------------------------------
	Parses a Name TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_name_tlv_parse (
	CefT_CcnMsg_MsgBdy* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {

	struct tlv_hdr* thdr;
	uint16_t sub_type;
	uint16_t sub_length;
	uint16_t index = 0;
	uint16_t name_len = 0;
	uint16_t chunk_len = 0;

#ifdef	__RESTRICT__
	printf( "%s \n", __func__ );
#endif

#ifdef REFLEXIVE_FORWARDING
	pm->rnp_pos = -1;
#endif // REFLEXIVE_FORWARDING

	/* Parses Name 					*/
	while ((index + CefC_S_TLF) <= length) {
		thdr = (struct tlv_hdr*) &value[index];
		sub_type 	= ntohs (thdr->type);
		sub_length  = ntohs (thdr->length);
		index += CefC_S_TLF;

		if ( length < (index + sub_length) ){
			/* Inconsistent sub-TLV */
#ifdef	CefC_Debug
			cef_dbg_write(CefC_Dbg_Fine, "Inconsistent Name sub-TLV:index=%d, length=%u, sub_type=%d, sub_length=%u\n", index, length, sub_type, sub_length);
			cef_dbg_buff_write (CefC_Dbg_Fine, (void *)thdr, 128);
			sleep(1);
#endif	// CefC_Debug
			return (-1);	// invalid TLV
		}

		switch (sub_type) {
			case CefC_T_NAMESEGMENT: {
				name_len += CefC_S_TLF + sub_length;
				break;
			}
			case CefC_T_CHUNK: {
				pm->chunk_num = 0;
		    	for (int i = 0; i < sub_length; i++) {
					pm->chunk_num = (pm->chunk_num << 8) | value[index+i];
		    	}
				pm->chunk_num_f = 1;
				chunk_len = sub_length;
				break;
			}
#ifdef REFLEXIVE_FORWARDING
			case CefC_T_REFLEXIVE_NAME: {
				pm->rnp_pos = name_len;
				name_len += CefC_S_TLF + sub_length;
				break;
			}
#endif // REFLEXIVE_FORWARDING
			default: {
				if ((sub_type >= CefC_T_APP_MIN) &&
					(sub_type <= CefC_T_APP_MAX)) {
					name_len += CefC_S_TLF + sub_length;	//20190918 For HEX_Type
				} else {
					/* Ignore 		*/
					name_len += CefC_S_TLF + sub_length;	//20190918 For HEX_Type
				}
				break;
			}
		}
		index += sub_length;
	}

	/* Recordss Name 				*/
	pm->name_f = offset;
	pm->name_len = name_len;
	pm->chunk_len = chunk_len;
	memcpy (pm->name, value, name_len);

	if (pm->chunk_num_f) {
		uint32_t chunk_num_wk;
		uint16_t chunk_len_wk;
		int		 indx;
		chunk_num_wk = htonl(pm->chunk_num);
		chunk_len_wk = htons(CefC_S_ChunkNum);

		indx = 0;
//		memcpy (&(pm->name[name_len+indx]), &ftvn_chunk, sizeof(CefC_S_Type));
		memcpy (&(pm->name[name_len+indx]), &ftvn_chunk, CefC_S_Type);
		indx += CefC_S_Type;
//		memcpy (&(pm->name[name_len+indx]), &chunk_len_wk, sizeof(CefC_S_Length));
		memcpy (&(pm->name[name_len+indx]), &chunk_len_wk, CefC_S_Length);
		indx += CefC_S_Length;
//		memcpy (&(pm->name[name_len+indx]), &chunk_num_wk, sizeof(CefC_S_ChunkNum));
		memcpy (&(pm->name[name_len+indx]), &chunk_num_wk, CefC_S_ChunkNum);
		pm->name_len += (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
		indx += CefC_S_ChunkNum;
	}

	return (1);
}
/*--------------------------------------------------------------------------------------
	Parses a ExpiryTime TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_expiry_tlv_parse (
	CefT_CcnMsg_MsgBdy* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
	memcpy (&pm->expiry, value, sizeof (uint64_t));
	pm->expiry = cef_frame_ntohb (pm->expiry);
	CefC_Frame_ms2us (pm->expiry);
	//0.8.3c
	pm->expiry_f = 1;
	return (1);
}
/*--------------------------------------------------------------------------------------
	Parses a Payload TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_payload_tlv_parse (
	CefT_CcnMsg_MsgBdy* pm, 				/* Structure to set parsed CEFORE message	*/
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
	CefT_CcnMsg_MsgBdy* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
	//0.8.3
	struct tlv_hdr* thdr;
	uint16_t index = 0;


#ifdef	__RESTRICT__
	printf( "%s length:%d   offset:%d   index:%d\n", __func__, length, offset, index );
#endif

	pm->KeyIdRestr_f = offset;

	//T_SHA_256
	thdr = (struct tlv_hdr*) &value[index];
	pm->KeyIdRestr.hash_type   = ntohs (thdr->type);
	pm->KeyIdRestr.hash_length = ntohs (thdr->length);
	index += CefC_S_TLF;
#ifdef	__RESTRICT__
	printf( "\t sub_length:%d   offset:%d   index:%d\n", pm->KeyIdRestr.hash_length, offset, index );
#endif
	memcpy( pm->KeyIdRestr.hash_value, &value[index], pm->KeyIdRestr.hash_length);
	pm->KeyIdRestr_len = length;

#ifdef	__RESTRICT__
		{
			int dbg_x;
			fprintf (stderr, "KeyIdRestr [ ");
			for (dbg_x = 0 ; dbg_x < 32 ; dbg_x++) {
				fprintf (stderr, "%02x ", pm->KeyIdRestr.hash_value[dbg_x]);
			}
			fprintf (stderr, "]\n");
		}
#endif


	return (1);
}
/*--------------------------------------------------------------------------------------
	Parses a ContentObjectHashRestriction TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_objhashrestr_tlv_parse (
	CefT_CcnMsg_MsgBdy* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
	//0.8.3
	struct tlv_hdr* thdr;
	uint16_t index = 0;

#ifdef	__RESTRICT__
	printf( "%s length:%d   offset:%d   index:%d\n", __func__, length, offset, index );
#endif

	pm->ObjHashRestr_f = offset;

	//T_SHA_256
	thdr = (struct tlv_hdr*) &value[index];
	pm->ObjHashRestr.hash_type = ntohs (thdr->type);
	pm->ObjHashRestr.hash_length = ntohs (thdr->length);
	index += CefC_S_TLF;
#ifdef	__RESTRICT__
	printf( "\t sub_length:%d   offset:%d   index:%d\n", pm->ObjHashRestr.hash_length, offset, index );
#endif
	memcpy( pm->ObjHashRestr.hash_value, &value[index], pm->ObjHashRestr.hash_length );
	pm->ObjHashRestr_len = length;

	return (1);
}
/*--------------------------------------------------------------------------------------
	Parses a PayloadType TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_payloadtype_tlv_parse (
	CefT_CcnMsg_MsgBdy* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
	// TODO
	return (1);
}
/*--------------------------------------------------------------------------------------
	Parses a EndChunkNumber TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_endchunk_tlv_parse (
	CefT_CcnMsg_MsgBdy* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
	pm->end_chunk_num_f = offset;
	pm->end_chunk_num = 0;
	for (int i = 0; i < length; i++) {
		pm->end_chunk_num = (pm->end_chunk_num << 8) | value[i];
	}
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

	uint16_t sub_type;
	uint16_t app_num;

	strcpy (uri, "ccnx:/");
	uri_len = strlen ("ccnx:/");

	/* Check root name */
	if ((name_len == sizeof(root_namesegment)) &&
		(memcmp (name, root_namesegment, sizeof(root_namesegment))) == 0) {
		return (uri_len);
	}

	if ( name_len == 0 ){
		return (strlen(uri));
	}

	while (x < name_len) {
		int hname = 0;
		tlv_hdr = (struct tlv_hdr*) &name[x];
		seg_len = ntohs (tlv_hdr->length);
		x += CefC_S_TLF;

		/* Check if it contains non-print character */
		for (i = 0 ; i < seg_len ; i++) {
			if(!(isprint(name[x+i]))) { /* HEX Name */
				hname = 1;
				break;
			}
		}
		if(hname == 0){

			char char_num[8];
			int	 num_len;
			sub_type = ntohs (tlv_hdr->type);
			if ((sub_type >= CefC_T_APP_MIN) &&
				(sub_type <= CefC_T_APP_MAX)) {
				memset( char_num, 0x00, 8 );
				/* T_APP */
				app_num = sub_type - CefC_T_APP_MIN;
				sprintf( char_num, "%d", app_num );
				num_len = strlen( char_num );
				memcpy( &uri[uri_len], "APP:", 4 );
				uri_len += 4;
				memcpy( &uri[uri_len], char_num, num_len );
				uri_len += num_len;
				uri[uri_len] = '=';
				uri_len++;
			} else if ( sub_type == CefC_T_NAMESEGMENT ) {
				/* T_NAMESEGMENT */
			} else {
				/* HEX Type */
				unsigned char	sub_wk[8];
				memset( sub_wk, 0x00, 8 );
				memcpy( sub_wk, &tlv_hdr->type, 2 );
				memset( char_num, 0x00, 8 );
				uri[uri_len++] = '0';
				uri[uri_len++] = 'x';
				sprintf( char_num, "%02x", sub_wk[0] );
				memcpy( &uri[uri_len], char_num, 2 );
				uri_len += 2;
				sprintf( char_num, "%02x", sub_wk[1] );
				memcpy( &uri[uri_len], char_num, 2 );
				uri_len += 2;
				uri[uri_len] = '=';
				uri_len++;
			}

			for (i = 0 ; i < seg_len ; i++) {
				if(((name[x + i] >= 0x30) && (name[x + i] <= 0x39)) ||		/* 0~9 */
					((name[x + i] >= 0x41) && (name[x + i] <= 0x5a)) ||		/* A~Z */
					((name[x + i] >= 0x61) && (name[x + i] <= 0x7a))) {		/* a~z */

					uri[uri_len] = name[x + i];
					uri_len++;
				} else if ((name[x + i] == 0x2d) ||						/* - */
						(name[x + i] == 0x2e) ||						/* . */
						(name[x + i] == 0x2f) ||						/* / */
						(name[x + i] == 0x5f) ||						/* _ */
						(name[x + i] == 0x3f) ||						/* ? */
						(name[x + i] == 0x25) ||						/* % */
						(name[x + i] == 0x26) ||						/* & */
						(name[x + i] == 0x7e)) {						/* ~ */
					uri[uri_len] = name[x + i];
					uri_len++;
				} else {
						sprintf (work, "%02x", name[x + i]);
						strcpy (&uri[uri_len], work);
						uri_len += strlen (work);
				}
			}
		} else {

			char char_num[8];
			int	 num_len;
			sub_type = ntohs (tlv_hdr->type);
			if ((sub_type >= CefC_T_APP_MIN) &&
				(sub_type <= CefC_T_APP_MAX)) {
				memset( char_num, 0x00, 8 );
				/* T_APP */
				app_num = sub_type - CefC_T_APP_MIN;
				sprintf( char_num, "%d", app_num );
				num_len = strlen( char_num );
				memcpy( &uri[uri_len], "APP:", 4 );
				uri_len += 4;
				memcpy( &uri[uri_len], char_num, num_len );
				uri_len += num_len;
				uri[uri_len] = '=';
				uri_len++;
			} else if ( sub_type == CefC_T_NAMESEGMENT ) {
				/* T_NAMESEGMENT */
			} else {
				/* HEX Type */
				unsigned char	sub_wk[8];
				memset( sub_wk, 0x00, 8 );
				memcpy( sub_wk, &tlv_hdr->type, 2 );
				memset( char_num, 0x00, 8 );
				uri[uri_len++] = '0';
				uri[uri_len++] = 'x';
				sprintf( char_num, "%02x", sub_wk[0] );
				memcpy( &uri[uri_len], char_num, 2 );
				uri_len += 2;
				sprintf( char_num, "%02x", sub_wk[1] );
				memcpy( &uri[uri_len], char_num, 2 );
				uri_len += 2;
				uri[uri_len] = '=';
				uri_len++;
			}

			uri[uri_len++] = '0';
			uri[uri_len++] = 'x';
			for (i = 0 ; i < seg_len ; i++) {
				sprintf (work, "%02x", name[x + i]);
				strcpy (&uri[uri_len], work);
				uri_len += strlen (work);
			}
		}
		uri[uri_len] = '/';
		uri_len++;

		x += seg_len;
	}
	uri[uri_len] = 0x00;
	/* delete last '/' */
	if(uri[uri_len-1] == '/'){
		uri[uri_len-1] = 0x00;
		uri_len--;
	}

	return (uri_len);
}
#ifdef REFLEXIVE_FORWARDING
/*--------------------------------------------------------------------------------------
	Convert name to refrexive name
----------------------------------------------------------------------------------------*/
int
cef_frame_conversion_name_to_reflexivename (
	unsigned char* name,
	unsigned int name_len,
	unsigned char* name_ref,
	int tpit_f,
	int rnp_pos
) {
	int x = 0, x_ref = 0;
	int seg_len;
	struct tlv_hdr* tlv_hdr;
	uint16_t sub_type;

	if (rnp_pos < 0) {
		while (x < name_len) {
			tlv_hdr = (struct tlv_hdr*) &name[x];
			seg_len = ntohs (tlv_hdr->length);
			sub_type = ntohs (tlv_hdr->type);
			if ( sub_type == CefC_T_REFLEXIVE_NAME ) {
				/* Add RNP TLV contained in name of arg */
				memcpy(&name_ref[x_ref] , &name[x], CefC_S_TLF + seg_len);
				x_ref += CefC_S_TLF + seg_len;
				break;
			}
			x += CefC_S_TLF + seg_len;
		}
		if (x_ref <= 0) {
			return (-1);
		}

	} else {
		tlv_hdr = (struct tlv_hdr*) &name[rnp_pos];
		seg_len = ntohs (tlv_hdr->length);
		sub_type = ntohs (tlv_hdr->type);
		if ( sub_type != CefC_T_REFLEXIVE_NAME ) {
			return (-1);
		}

		memcpy(&name_ref[x_ref] , &name[rnp_pos], CefC_S_TLF + seg_len);
		x_ref += CefC_S_TLF + seg_len;
	}

	if (tpit_f == 1) {
		/* Add t-PIT TLV */
		uint16_t tpit_len = 0;
		uint16_t tpit_len_ns = htons(tpit_len);

		memcpy (&name_ref[x_ref], &ftvn_tpit, CefC_S_Type);
		x_ref += CefC_S_Type;
		memcpy (&name_ref[x_ref], &tpit_len_ns, CefC_S_Length);
		x_ref += CefC_S_Length;
	}

	return (x_ref);
}
#endif // REFLEXIVE_FORWARDING
/*--------------------------------------------------------------------------------------
	Convert name to uri without ChunkNum
----------------------------------------------------------------------------------------*/
int
cef_frame_conversion_name_to_uri_without_chunknum (
	unsigned char* name,
	unsigned int name_len,
	char* uri
) {
	int i;
	int x = 0;
	int seg_len, uri_len;
	struct tlv_hdr* tlv_hdr;
	char work[16];

	strcpy (uri, "ccnx:/");
	uri_len = strlen ("ccnx:/");

	/* Check root name */
	if ((name_len == sizeof(root_namesegment)) &&
		(memcmp (name, root_namesegment, sizeof(root_namesegment))) == 0) {
		return (uri_len);
	}

	while (x < name_len) {
		int hname = 0;
		tlv_hdr = (struct tlv_hdr*) &name[x];
		if (ntohs(tlv_hdr->type) == CefC_T_CHUNK) {
			break;
		}

		seg_len = ntohs (tlv_hdr->length);
		x += CefC_S_TLF;
		/* Check if it contains non-print character */
		for (i = 0 ; i < seg_len ; i++) {
			if(!(isprint(name[x+i]))) { /* HEX Name */
				hname = 1;
				break;
			}
		}
#ifdef REFLEXIVE_FORWARDING
		if (ntohs(tlv_hdr->type) == CefC_T_REFLEXIVE_NAME) {
			/* parse rnp with "0xXXXX=" */
			char char_num[8];
			unsigned char   sub_wk[8];
			memset( char_num, 0x00, 8);
			memset( sub_wk, 0x00, 8);
			memcpy( sub_wk, &tlv_hdr->type, 2 );

			uri[uri_len++] = '0';
			uri[uri_len++] = 'x';
			sprintf( char_num, "%02x", sub_wk[0] );
			memcpy( &uri[uri_len], char_num, 2 );
			uri_len += 2;
			sprintf( char_num, "%02x", sub_wk[1] );
			memcpy( &uri[uri_len], char_num, 2 );

			uri_len += 2;
			uri[uri_len++] = '=';
		}
#endif // REFLEXIVE_FORWARDING
		if(hname == 0){
			for (i = 0 ; i < seg_len ; i++) {
				if(((name[x + i] >= 0x30) && (name[x + i] <= 0x39)) ||		/* 0~9 */
					((name[x + i] >= 0x41) && (name[x + i] <= 0x5a)) ||		/* A~Z */
					((name[x + i] >= 0x61) && (name[x + i] <= 0x7a))) {		/* a~z */

					uri[uri_len] = name[x + i];
					uri_len++;
				} else if ((name[x + i] == 0x2d) ||						/* - */
						(name[x + i] == 0x2e) ||						/* . */
						(name[x + i] == 0x2f) ||						/* / */
						(name[x + i] == 0x5f) ||						/* _ */
						(name[x + i] == 0x3f) ||						/* ? */
						(name[x + i] == 0x25) ||						/* % */
						(name[x + i] == 0x26) ||						/* & */
						(name[x + i] == 0x7e)) {						/* ~ */
					uri[uri_len] = name[x + i];
					uri_len++;
				} else {
						sprintf (work, "%02x", name[x + i]);
						strcpy (&uri[uri_len], work);
						uri_len += strlen (work);
				}
			}
		} else {
			uri[uri_len++] = '0';
			uri[uri_len++] = 'x';
			for (i = 0 ; i < seg_len ; i++) {
				sprintf (work, "%02x", name[x + i]);
				strcpy (&uri[uri_len], work);
				uri_len += strlen (work);
			}
		}
		uri[uri_len] = '/';
		uri_len++;

		x += seg_len;
	}

	if ((uri_len > strlen ("ccnx:/")) && (uri[uri_len-1] == 0x2f)) {
		uri_len--;
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
	char* protocol			/* NOTE: 													*/
							/*	This argument is unused.								*/
							/*	"ccnx:/" is fixedly used as a protocol.					*/
) {
	int uri_len;

	uri_len = cef_frame_conversion_name_to_uri (name, name_len, uri);
	return (uri_len);
}
/*--------------------------------------------------------------------------------------
	Get total length of T_NAMESEGMENT part
----------------------------------------------------------------------------------------*/
unsigned int
cef_frame_get_len_total_namesegments (
	unsigned char* name,
	unsigned int name_len
) {
	int x = 0;
	struct tlv_hdr* tlv_hdr;
	unsigned int seg_tlen = 0;
	unsigned int len = 0;

	while (x < name_len) {
		tlv_hdr = (struct tlv_hdr*) &name[x];
		len = ntohs (tlv_hdr->length);

		if ((ntohs(tlv_hdr->type) == CefC_T_NAMESEGMENT) ||
			((ntohs(tlv_hdr->type) >= CefC_T_APP_MIN) &&
			 (ntohs(tlv_hdr->type) <= CefC_T_APP_MAX))) {
			seg_tlen += CefC_S_TLF + len;
		}
		else if (ntohs(tlv_hdr->type) == CefC_T_CHUNK) {
			/* NOP */
		} else {
			seg_tlen += CefC_S_TLF + len;
		}
		x += (CefC_S_TLF + len);
	}
	return (seg_tlen);
}
/*--------------------------------------------------------------------------------------
	Parses a ORG TLV in a CEFORE message
----------------------------------------------------------------------------------------*/
static int									/* No care now								*/
cef_frame_message_user_tlv_parse (
	CefT_CcnMsg_MsgBdy* pm, 				/* Structure to set parsed CEFORE message	*/
	uint16_t length, 						/* Length of this TLV						*/
	unsigned char* value,					/* Value of this TLV						*/
	uint16_t offset							/* Offset from the top of message 			*/
) {
	unsigned char* wp;
	unsigned char* ewp;

	if (length < CefC_S_PEN) {
		/* length of PEN */
		return (-1);
	}

	/* Get IANA Private Enterprise Numbers */
	if ( memcmp(value, pen_nict, sizeof(pen_nict)) ){
		return (-1);
	}

	/* Get Length */
	pm->org_len = (uint16_t)(length - CefC_S_PEN);

	/* Get Message header */
	memcpy(pm->org_val, &value[CefC_S_PEN], pm->org_len);

	wp = pm->org_val;
	ewp = pm->org_val + pm->org_len;
	ewp -= sizeof(uint16_t);			/* length of TLV->type */
	while (wp <= ewp) {
		struct tlv_hdr* tlv_hdr;

		tlv_hdr = (struct tlv_hdr*) &wp[0];
/* [Restriction] */
/* For renovation in FY 2018, T_ORG is supported only for Symbolic, LongLife. */
		switch (ntohs(tlv_hdr->type)) {
			case CefC_T_SYMBOLIC:
				pm->InterestType = CefC_PIT_TYPE_Sym;	//0.8.3
				pm->org.symbolic_f = 1;
				wp += CefC_S_Type;
				break;
			case CefC_T_LONGLIFE:
				pm->org.longlife_f = 1;
				wp += CefC_S_Type;
				break;
#ifdef REFLEXIVE_FORWARDING
			case CefC_T_REFLEXIVE_SMI:
				pm->org.reflexive_smi_f = 1;
				wp += CefC_S_Type;
				break;
#endif // REFLEXIVE_FORWARDING

			default:
				if (wp[0] & 0x80){
					/* exist length field */
					wp += (CefC_S_TLF + ntohs(tlv_hdr->length));
				} else {
					/* only type field */
					wp += CefC_S_Type;
				}
				break;
		}
	}

	return (1);
}
/*--------------------------------------------------------------------------------------
	Set flag whether to use OPT_SEQNUM
----------------------------------------------------------------------------------------*/
void
cef_frame_set_opt_seqnum_f (
	int				use_f				/* When using         : CefC_OptSeqnum_Use		*/
										/* When finished using: CefC_OptSeqnum_UnUse	*/
) {
	cef_opt_seqnum_f += use_f;
	if(cef_opt_seqnum_f < 0)
		cef_opt_seqnum_f = CefC_OptSeqnum_NotUse;
	return;
}
/*--------------------------------------------------------------------------------------
	Get flag whether to use OPT_SEQNUM
----------------------------------------------------------------------------------------*/
uint16_t
cef_frame_get_opt_seqnum_f (
	void
) {
	return(cef_opt_seqnum_f);
}
/*--------------------------------------------------------------------------------------
	get Name without chunkno
----------------------------------------------------------------------------------------*/
uint16_t										/* index of T_CHUNK						*/
cef_frame_get_name_without_chunkno (
	unsigned char* name,						/* content name							*/
	uint16_t name_len,							/* content name Length					*/
	uint32_t* ret_seq							/* chunk number							*/
) {
	uint16_t index = 0;
	struct tlv_hdr* thdr;
	uint16_t sub_type;
	uint16_t sub_length;
	uint32_t* v32p;

	while (index < name_len) {
		thdr = (struct tlv_hdr*) &name[index];
		sub_type 	= ntohs (thdr->type);
		sub_length  = ntohs (thdr->length);
		if (sub_type == CefC_T_CHUNK) {
			v32p = (uint32_t*)(&name[index + CefC_S_TLF]);
			*ret_seq = ntohl (*v32p);
			return (index);
		}
		index += CefC_S_TLF + sub_length;
	}

	return (0);
}
/*--------------------------------------------------------------------------------------
	Parses a Ccninfo message
----------------------------------------------------------------------------------------*/
CefT_Parsed_Ccninfo*
cef_frame_ccninfo_parse (
	unsigned char* msg 					/* the message to parse						*/
) {
	CefT_Parsed_Ccninfo* pci;	/* Structure for parsed Ccninfo message	*/
	unsigned char* emp;
	unsigned char* wmp;
	uint16_t length;
	uint16_t type;
	uint16_t index = 0;
	struct tlv_hdr* thdr;
	struct fixed_hdr* fhdr;
	CEF_FRAME_SKIPHOP_T	w_skiphop;
	int		disc_reply_node_f = 0;	/* ccninfo-05 */
	int		disc_reqhdr_f = 0;		/* ccninfo-05 */

#ifdef	DEB_CCNINFO
	fprintf( stderr, "[%s] IN\n",
				"cef_frame_ccninfo_parse" );
#endif

	pci = (CefT_Parsed_Ccninfo*) malloc (sizeof(CefT_Parsed_Ccninfo));
	if ( !pci ){
		cef_log_write (CefC_Log_Error, "Failed to allocate memory for CefT_Parsed_Ccninfo.\n");
		return NULL;
	}
	memset (pci, 0x00, sizeof (CefT_Parsed_Ccninfo));

	fhdr = (struct fixed_hdr*) msg;
	pci->pkt_type = fhdr->type;
	pci->hoplimit = fhdr->hoplimit;
	pci->ret_code = fhdr->reserve1;

#ifdef DEB_CCNINFO
{
	int dbg_x;
	uint16_t plen = ntohs (fhdr->pkt_len);
	fprintf (stderr, "DBG_PCI: msg[ ");
	for (dbg_x = 0; dbg_x < plen; dbg_x++)
		fprintf (stderr, "%02x ", msg[dbg_x]);
	fprintf (stderr, "](length=%d)\n", plen);
}
#endif

	index = CefC_S_Fix_Header;
	wmp = &msg[index];
	emp = msg + ntohs (fhdr->pkt_len);

	/* Search range is only the first Top-Level TLV */
	thdr = (struct tlv_hdr*) &msg[fhdr->hdr_len];
	emp = &msg[fhdr->hdr_len] + CefC_S_TLF + ntohs (thdr->length);

#ifdef	DEB_CCNINFO
	printf( "\tindex=%d   fhdr->pkt_len=%d, hdr_len=%d, Top-Level:type=%d, length=%d\n",
			index,  ntohs (fhdr->pkt_len), fhdr->hdr_len, ntohs (thdr->type), ntohs (thdr->length));
#endif

	while (wmp < emp) {
		thdr = (struct tlv_hdr*) &wmp[CefC_O_Type];
		type   = ntohs (thdr->type);
		length = ntohs (thdr->length);
#ifdef	DEB_CCNINFO
		printf( "\tindex=%d   length=%d\n", index, length );
#endif

		if ((type == CefC_T_OPT_DISC_REQHDR) && (disc_reqhdr_f == 0)) {	/* ccninfo-05 */
#ifdef	DEB_CCNINFO
			printf( "\t CefC_T_OPT_DISC_REQHDR S  index=%d   length=%d\n", index, length );
#endif
			/* Request Header Block */
			struct ccninfo_reqhdr_block* req_blk;
			req_blk = (struct ccninfo_reqhdr_block*) &wmp[CefC_S_TLF];

			pci->req_id				= ntohs (req_blk->req_id);
			memcpy(&w_skiphop, &req_blk->skiphop, 1);
			pci->skip_hop = w_skiphop.sh_4bit;

			pci->skip_hop_offset	= index + CefC_S_TLF + 2;
			pci->ccninfo_flag		= req_blk->flag;
			disc_reqhdr_f = 1;	/* ccninfo-05 */

			pci->putverify_f = 0;
			if (length > sizeof (struct ccninfo_reqhdr_block)) {
				uint16_t tmp_idx = 0;
				uint16_t tmp_len;
				uint8_t msg_type;
				tmp_idx = index + CefC_S_TLF + sizeof (struct ccninfo_reqhdr_block) - CefC_S_Fix_Header;
				thdr = (struct tlv_hdr*) &wmp[tmp_idx];
				type   = ntohs (thdr->type);
				tmp_len = ntohs (thdr->length);
				tmp_idx += CefC_S_TLF;
				if (type == CefC_T_OPT_ORG && tmp_len == 16) {
					/* PEN(3)+Type+Len+MsgType(1)+seq*2(8) */
					if( (((CefC_NICT_PEN & 0xFF0000) >> 16) == wmp[tmp_idx])
						  &&
						(((CefC_NICT_PEN & 0x00FF00) >>  8) == wmp[tmp_idx+1])
						  &&
						(((CefC_NICT_PEN & 0x0000FF)      ) == wmp[tmp_idx+2])){
						tmp_idx += CefC_S_PEN;
						/* T_PUTVERIFY */
						thdr = (struct tlv_hdr*) &wmp[tmp_idx];
						type   = ntohs (thdr->type);
						tmp_len = ntohs (thdr->length);
						tmp_idx += CefC_S_TLF;
						msg_type = wmp[tmp_idx];
						tmp_idx += 1;
						if (msg_type == CefC_CpvOp_ContInfoMsg) {
							uint32_t* value32;
							pci->putverify_f = 1;
							pci->putverify_msgtype = msg_type;
							value32 = (uint32_t*)(&wmp[tmp_idx]);
							pci->putverify_sseq = ntohl (*value32);
							tmp_idx += 4;
							value32 = (uint32_t*)(&wmp[tmp_idx]);
							pci->putverify_eseq = ntohl (*value32);
						}
					}
				}
			}
			index += CefC_S_TLF + length;
			wmp += CefC_S_TLF + length;

#ifdef	DEB_CCNINFO
			printf( "\t CefC_T_OPT_DISC_REQHDR E  index=%d   length=%d\n", index, length );
#endif
		} else if(type == CefC_T_DISC_REQ) {
#ifdef	DEB_CCNINFO
			printf( "\t CefC_T_DISC_REQ S  index=%d   length=%d\n", index, length );
#endif
			/* Request Block ccninfo-05 */
			struct ccninfo_req_block* req_blk;
			uint16_t idx = 0;
			req_blk = (struct ccninfo_req_block*) &wmp[CefC_S_TLF];
			pci->req_arrival_time	= ntohl (req_blk->req_arrival_time);
			idx = sizeof (struct ccninfo_req_block);
			pci->id_len = length - idx;
			memcpy(pci->node_id, &wmp[(CefC_S_TLF + idx)], pci->id_len);

			index += CefC_S_TLF + length;
			wmp += CefC_S_TLF + length;
#ifdef	DEB_CCNINFO
			printf( "\t CefC_T_DISC_REQ E  index=%d   length=%d\n", index, length );
#endif
		} else if(type == CefC_T_OPT_DISC_REPORT) {
#ifdef	DEB_CCNINFO
			printf( "\t CefC_T_OPT_DISC_REPORT S  index=%d   length=%d   pci->rpt_blk_num=%d\n", index, length, pci->rpt_blk_num );
#endif
			/* Report Block */
			CefT_Request_RptBlk* rpt_p;
			uint32_t* value32;

			rpt_p = (CefT_Request_RptBlk*) malloc (sizeof(CefT_Request_RptBlk));
			if ( !rpt_p ){
				cef_log_write (CefC_Log_Error, "Failed to allocate memory for CefT_Request_RptBlk.\n");
				return ( pci );
			}
			value32 = (uint32_t*)(&wmp[CefC_S_TLF]);
			rpt_p->req_arrival_time = ntohl (*value32);
			rpt_p->id_len = length - sizeof(uint32_t);
			rpt_p->node_id = (unsigned char*) malloc (rpt_p->id_len);
			if ( !rpt_p->node_id ){
				cef_log_write (CefC_Log_Error, "Failed to allocate memory for node_id(id_len=%d).\n", rpt_p->id_len);
				return ( pci );
			}
			memcpy(rpt_p->node_id, &wmp[CefC_S_TLF + sizeof(uint32_t)], rpt_p->id_len);
			if (pci->rpt_blk_num == 0) {
				pci->rpt_blk = rpt_p;
				pci->rpt_blk_tail = rpt_p;
			} else {
				pci->rpt_blk_tail->next = rpt_p;
				pci->rpt_blk_tail = rpt_p;
			}
			pci->rpt_blk_num++;

			index += CefC_S_TLF + length;
			wmp += CefC_S_TLF + length;
#ifdef	DEB_CCNINFO
			printf( "\t CefC_T_OPT_DISC_REPORT E  index=%d   length=%d   pci->rpt_blk_num=%d\n", index, length, pci->rpt_blk_num );
#endif
		} else if (type == CefC_T_DISCOVERY) {
#ifdef	DEB_CCNINFO
			printf( "\t CefC_T_DISCOVERY S  index=%d   length=%d\n", index, length );
#endif
			/* Discovery */
			thdr = (struct tlv_hdr*) &wmp[CefC_S_TLF];
			index += CefC_S_TLF;
			wmp += CefC_S_TLF;

			type   = ntohs (thdr->type);
			length = ntohs (thdr->length);
			if (type == CefC_T_NAME) {
				pci->disc_name_len = length;
				pci->disc_name = (unsigned char*) malloc (length);
				if ( !pci->disc_name ){
					cef_log_write (CefC_Log_Error, "Failed to allocate memory for disc_name(length=%d).\n", length);
					return ( pci );
				}
				memcpy (pci->disc_name, &wmp[CefC_S_TLF], length);
			} else {
				cef_frame_ccninfo_parsed_free(pci);
				return ( NULL );
			}
			index += CefC_S_TLF + length;
			wmp += CefC_S_TLF + length;
#ifdef	DEB_CCNINFO
			printf( "\t CefC_T_DISCOVERY E  index=%d   length=%d\n", index, length );
#endif
		} else if ((type == CefC_T_DISC_REPLY) && (disc_reqhdr_f != 0)) {	/* ccninfo-05 */
#ifdef	DEB_CCNINFO
			printf( "\t CefC_T_DISC_REPLY S  index=%d   length=%d\n", index, length );
#endif
			/* Disc Reply ccninfo-05 */
			uint32_t* value32;

			thdr = (struct tlv_hdr*) &wmp[CefC_O_Type];
			index += CefC_S_TLF;
			wmp += CefC_S_TLF;
			type   = ntohs (thdr->type);
			length = ntohs (thdr->length);
#ifdef	DEB_CCNINFO
			printf( "\t CefC_T_DISC_REPLY M-01  index=%d   length=%d\n", index, length );
#endif

			disc_reply_node_f = 1;
			value32 = (uint32_t*)(&wmp[CefC_O_Type]);
			pci->reply_req_arrival_time = ntohl (*value32);
			index += CefC_S_TLF;
			wmp += CefC_S_TLF;
#ifdef	DEB_CCNINFO
			printf( "\t CefC_T_DISC_REPLY M-02  index=%d   length=%d\n", index, length );
#endif

			thdr = (struct tlv_hdr*) &wmp[CefC_O_Type];
//			index += CefC_S_TLF;
//			wmp += CefC_S_TLF;
#ifdef	DEB_CCNINFO
			printf( "\t CefC_T_DISC_REPLY M-03  index=%d   length=%d\n", index, length );
#endif
			type   = ntohs (thdr->type);
			length = ntohs (thdr->length);
#ifdef	DEB_CCNINFO
			printf( "\t CefC_T_DISC_REPLY M-04  index=%d   length=%d\n", index, length );
#endif
			pci->reply_node_len = CefC_S_TLF + length;
			pci->reply_reply_node = (unsigned char*) malloc (pci->reply_node_len);
			if ( !pci->reply_reply_node ){
				cef_log_write (CefC_Log_Error, "Failed to allocate memory for reply_reply_node(length=%d).\n", pci->reply_node_len);
				return ( pci );
			}
			memcpy (pci->reply_reply_node, &wmp[CefC_O_Type], pci->reply_node_len);

//			index += CefC_S_TLF + length;
//			wmp += CefC_S_TLF + length;
			index += pci->reply_node_len;
			wmp += pci->reply_node_len;
#ifdef	DEB_CCNINFO
			printf( "\t CefC_T_DISC_REPLY M-05  index=%d   length=%d\n", index, length );
#endif

			if (wmp < emp) {
				/* NOP */
			} else {
				goto SKIP_REP_BLK;
			}

			thdr = (struct tlv_hdr*) &wmp[CefC_O_Type];
			type   = ntohs (thdr->type);
			length = ntohs (thdr->length);
			/* ccninfo-05 */

			/* Reply (T_DISC_CONTENT)*/
			CefT_Reply_SubBlk*	rep_p;
			uint16_t rep_end_index = index + length;
#ifdef	DEB_CCNINFO
			printf( "\t                      rep_end_index=%d\n", rep_end_index );
#endif

			while(index < rep_end_index) {
				thdr = (struct tlv_hdr*) &wmp[CefC_O_Type];
				type   = ntohs (thdr->type);
				length = ntohs (thdr->length);

				if ( type != CefC_T_DISC_CONTENT ){
#ifdef	CefC_Debug
					cef_dbg_write(CefC_Dbg_Fine, "Inconsistent T_DISC_REPLY sub-TLV:index=%d, type=0x%04x, length=%u\n", index, type, length);
#endif	// CefC_Debug
					index += CefC_S_TLF + length;
					wmp += CefC_S_TLF + length;
					continue;
				}

				rep_p = (CefT_Reply_SubBlk*) malloc (sizeof(CefT_Reply_SubBlk));
				if ( !rep_p ){
					cef_log_write (CefC_Log_Error, "Failed to allocate memory for CefT_Reply_SubBlk.\n");
					return ( pci );
				}
				memset(rep_p, 0x00, sizeof(CefT_Reply_SubBlk));

		/*=======================================================================*
			+---------------+---------------+---------------+---------------+
			|     Type (=T_DISC_CONTENT)    |             Length            |
			+---------------+---------------+---------------+---------------+
			|                          Object Size                          |
			+---------------+---------------+---------------+---------------+
			|                         Object Count                          |
			+---------------+---------------+---------------+---------------+
			|                      # Received Interest                      |
			+---------------+---------------+---------------+---------------+
			|                         First Seqnum                          |
			+---------------+---------------+---------------+---------------+
			|                          Last Seqnum                          |
			+---------------+---------------+---------------+---------------+
			|                       Elapsed Cache Time                      |
			+---------------+---------------+---------------+---------------+
			|                      Remain Cache Lifetime                    |
			+---------------+---------------+---------------+---------------+
			|            T_NAME             |             Length            |
			+---------------+---------------+---------------+---------------+
			/                       Name Segment TLVs                       /
			+---------------+---------------+---------------+---------------+
			|       RespRange Length        |                               /
			+---------------+---------------+---------------+---------------+
			|                        RespRange(string)                      /
			+---------------+---------------+---------------+---------------+
		*=======================================================================*/

				thdr = (struct tlv_hdr*) &wmp[CefC_O_Type];
				rep_p->rep_type   = ntohs (thdr->type);
				rep_p->length = ntohs (thdr->length);

				{	struct ccninfo_rep_block*	wk_p = (struct ccninfo_rep_block*) &wmp[CefC_S_TLF];

					rep_p->obj_size			= ntohl (wk_p->cont_size);
					rep_p->obj_cnt			= ntohl (wk_p->cont_cnt);
					rep_p->first_seq		= ntohl (wk_p->first_seq);
					rep_p->rcv_interest_cnt	= ntohl (wk_p->rcv_int);
					rep_p->last_seq			= ntohl (wk_p->last_seq);
					rep_p->cache_time		= ntohl (wk_p->cache_time);
					rep_p->lifetime			= ntohl (wk_p->remain_time);
				}

				index += CefC_S_TLF + sizeof(struct ccninfo_rep_block);
				wmp += CefC_S_TLF + sizeof(struct ccninfo_rep_block);

				thdr = (struct tlv_hdr*) wmp;
				type   = ntohs (thdr->type);
				length = ntohs (thdr->length);

				if (type == CefC_T_NAME) {
					rep_p->rep_name_len = length;
					rep_p->rep_name = (unsigned char*) malloc (length);
					if ( !rep_p->rep_name ){
#ifdef	CefC_Debug
						cef_dbg_write(CefC_Dbg_Fine, "Failed to allocate memory for rep_name(length=%d).\n", length);
#endif	// CefC_Debug
						cef_log_write (CefC_Log_Error, "Failed to allocate memory for rep_name(length=%d).\n", length);
						return ( pci );
					}
					memcpy (rep_p->rep_name, &wmp[CefC_S_TLF], length);
				} else {
#ifdef	CefC_Debug
cef_dbg_write(CefC_Dbg_Fine, "missing T_NAME, type=0x%04x, length=%d.\n", type, length);
#endif	// CefC_Debug
					cef_frame_ccninfo_parsed_free(pci);
					return (NULL);
				}
				index += CefC_S_TLF + length;
				wmp += CefC_S_TLF + length;

				rep_p->rep_range_len = 0;
				if (pci->putverify_f &&
					pci->putverify_msgtype == CefC_CpvOp_ContInfoMsg) {
					rep_p->rep_range_len = ntohs (*(uint16_t *)wmp);	/* RespRange Length (without type) */
					if (rep_p->rep_range_len) {
						rep_p->rep_range = (unsigned char*) malloc (rep_p->rep_range_len + 1);
						if ( !rep_p->rep_range ){
#ifdef	CefC_Debug
							cef_dbg_write(CefC_Dbg_Fine, "Failed to allocate memory for rep_name(length=%d).\n", rep_p->rep_range_len + 1);
#endif	// CefC_Debug
							cef_log_write (CefC_Log_Error, "Failed to allocate memory for rep_range(length=%d).\n", rep_p->rep_range_len + 1);
							return ( pci );
						}
						memcpy (rep_p->rep_range, &wmp[sizeof(uint16_t)], rep_p->rep_range_len);
						rep_p->rep_range[rep_p->rep_range_len] = 0x00;
#ifdef	CefC_Debug
cef_dbg_write(CefC_Dbg_Finer, "rep_range=[%s].\n", rep_p->rep_range);
#endif	// CefC_Debug
					} else {
						rep_p->rep_range = NULL;
					}
					index += sizeof(uint16_t) + rep_p->rep_range_len;
					wmp += sizeof(uint16_t) + rep_p->rep_range_len;
				}

				if (pci->rep_blk_num == 0) {
					pci->rep_blk = rep_p;
					pci->rep_blk_tail = rep_p;
				} else {
					pci->rep_blk_tail->next = rep_p;
					pci->rep_blk_tail = rep_p;
				}
				pci->rep_blk_num++;
			}
SKIP_REP_BLK:;
#ifdef	DEB_CCNINFO
			printf( "\t CefC_T_DISC_REPLY E  index=%d   length=%d\n", index, length );
#endif
		} else if (type == CefC_T_VALIDATION_ALG ||
					type == CefC_T_VALIDATION_PAYLOAD) {
			index += CefC_S_TLF + length;
			wmp += CefC_S_TLF + length;
		} else {
#ifdef	CefC_Debug
cef_dbg_write(CefC_Dbg_Fine, "invalid TLV, type=0x%04x, length=%d.\n", type, length);
#endif	// CefC_Debug
			cef_frame_ccninfo_parsed_free(pci);
			return ( NULL );
		}
	}

	/*  */
	if ( disc_reply_node_f == 1 ) {
		CefT_Request_RptBlk*	add_rpt_p;

		add_rpt_p = (CefT_Request_RptBlk*) malloc (sizeof(CefT_Request_RptBlk));
		if ( !add_rpt_p ){
			cef_log_write (CefC_Log_Error, "Failed to allocate memory for CefT_Request_RptBlk.\n");
			return ( pci );
		}
		add_rpt_p->req_arrival_time = pci->reply_req_arrival_time;
		add_rpt_p->id_len = pci->reply_node_len;
		add_rpt_p->node_id = (unsigned char*) malloc (add_rpt_p->id_len);
		if ( !add_rpt_p->node_id ){
			cef_log_write (CefC_Log_Error, "Failed to allocate memory for node_id(id_len=%d).\n", add_rpt_p->id_len);
			return ( pci );
		}
		memcpy (add_rpt_p->node_id, pci->reply_reply_node, add_rpt_p->id_len);

		if (pci->rpt_blk_num == 0) {
			pci->rpt_blk = add_rpt_p;
			pci->rpt_blk_tail = add_rpt_p;
		} else {
			pci->rpt_blk_tail->next = add_rpt_p;
			pci->rpt_blk_tail = add_rpt_p;
		}
		pci->rpt_blk_num++;
	}
#ifdef	DEB_CCNINFO
	fprintf( stderr, "[%s] OUT pci->rpt_blk_num=%d\n",
				"cef_frame_ccninfo_parse", pci->rpt_blk_num );
#endif

	return ( pci );
}
/*--------------------------------------------------------------------------------------
	Frees a Parsed Ccninfo message
----------------------------------------------------------------------------------------*/
void
cef_frame_ccninfo_parsed_free (
	CefT_Parsed_Ccninfo* pci 				/* Structure to set parsed Ccninfo message	*/
) {
	CefT_Request_RptBlk*	rpt_p;
	CefT_Reply_SubBlk*	rep_p;
	int					i;

	if( !pci )
		return;

	rpt_p = pci->rpt_blk;
	for (i = 0; rpt_p != NULL && i < pci->rpt_blk_num; i++) {
		CefT_Request_RptBlk*	wk_rpt_p = rpt_p;

		if (rpt_p->node_id){
			free (rpt_p->node_id);
			rpt_p->node_id = NULL;
		}
		rpt_p = rpt_p->next;

		free (wk_rpt_p);
	}

	if ( pci->disc_name ){
		free (pci->disc_name);
		pci->disc_name = NULL;
	}

	rep_p = pci->rep_blk;
	for (i = 0; rep_p != NULL && i < pci->rep_blk_num; i++) {
		CefT_Reply_SubBlk*	wk_rep_p = rep_p;

		if ( rep_p->rep_name ){
			free (rep_p->rep_name);
			rep_p->rep_name = NULL;
		}
		if ( rep_p->rep_range ) {
			free (rep_p->rep_range);
			rep_p->rep_range = NULL;
		}
		rep_p = rep_p->next;

		free (wk_rep_p);
	}

	/* ccninfo-05 */
	if ( pci->reply_reply_node != NULL ) {
		free( pci->reply_reply_node );
		pci->reply_reply_node = NULL;
	}
	/* ccninfo-05 */

	free(pci);
}
/*--------------------------------------------------------------------------------------
	debug print
----------------------------------------------------------------------------------------*/
void
cef_frame_debug_print_buff (
	unsigned char* buff,				/* The buffer that want to output stderr		*/
	uint16_t buff_len,					/* Length of buff								*/
	uint8_t n_per_line					/* Number of 1 line (0 is nothing to do)		*/
) {
	int bidx;
	if (n_per_line < 0) n_per_line = 0;
	fprintf (stderr, "----------\n");

//	for (bidx = 0; bidx < buff_len; bidx++) {
//		fprintf (stderr, "%02x ", buff[bidx]);
//		if (n_per_line != 0 &&
//			(bidx+1) % n_per_line == 0)
//			fprintf (stderr, "\n");
//	}
	for (bidx = 0; bidx < buff_len; bidx++) {
		if (isprint (buff[bidx])) {
			fprintf (stderr, ".%c", buff[bidx]);
		} else {
			fprintf (stderr, "%02X", buff[bidx]);
		}
		if (n_per_line != 0 &&
			(bidx+1) % n_per_line == 0)
			fprintf (stderr, "\n");
	}

	fprintf (stderr, "\n----------(%d)\n", bidx);
	return;
}


int
cef_frame_input_uri_pre_check(
	const char* inuri, 						/* URI										*/
	unsigned char* name_1,					/* buffer to set After Check URI			*/
	int			chunk_f						/* "/Chunk=" Accept or Not Accept			*/
) {
	unsigned char chk_1[CefC_NAME_BUFSIZ];
	unsigned char tmp_str[CefC_NAME_BUFSIZ];
	int		i;
	int		num_test;
	int		tmp_str_len;
	int		tmp_len;
	int		first_seg_f = 1;	/* 1:first segmment 0:not */
	int		find_eq = 0;
	int		chunk_ctr = 0;
	int		find_chunk = 0;
	char* break_p;
	char* n1_p;
	char* c1_p;
	unsigned int hex_test;

	memset( chk_1, 0x00, sizeof(chk_1) );

	/* Need #define _GNU_SOURCE */
	memcpy( chk_1, inuri, strlen(inuri) );

	n1_p = (char*)name_1;
	c1_p = (char*)chk_1;
	break_p = strchr( (char*)chk_1, '/' );		/* search / */
	if ( break_p == NULL ) {
		/* Error */
		return (-1);
	}

	break_p++;
	tmp_len = break_p - c1_p;
	memcpy( n1_p, chk_1, tmp_len );				/* first / */

	n1_p += tmp_len;
	c1_p += tmp_len;

	if ( *break_p == '/' ) {				/* // */
		/* Error // */
		return (-1);
	}

	while( *c1_p ) {
		memset( tmp_str, 0x00, sizeof(tmp_str) );
		break_p = strchr( c1_p, '/' );			/* Next / */
		if ( break_p == NULL ) {
			tmp_len = strlen( c1_p );
		} else {
			tmp_len = break_p - c1_p;
		}
		memcpy( tmp_str, c1_p, tmp_len );		/* / */
		tmp_str_len = (int)strlen((char*)tmp_str);

		if ( strncasecmp((char*)tmp_str, "NAME=", 5) == 0  ) {
			/* NAME= */
			if ( (tmp_str_len == 5) && (first_seg_f == 1) ) {
				/* Error first is "NAME=" */
				return (-1);
			}
			tmp_str_len -= 5;
			if ( tmp_str_len > 0 ) {
				for ( i = 0; i < tmp_str_len; i++ ) {
					if ( tmp_str[5+i] != '"' ) {
						*n1_p = tmp_str[5+i];
						n1_p++;
					} else {
						/* NOP */
					}
				}
			}
			c1_p += tmp_len;
		} else if ( strncasecmp((char*)tmp_str, "Chunk=", 6) == 0  ) {
			char	num_buff[CefC_NumBufSiz];
			memset( num_buff, 0x00, sizeof(num_buff) );
			if ( first_seg_f == 1 ) {
				/* Error */
				return (-1);
			}
//			if ( tmp_str[5] != '=' ) {
//				/* Error Not "Chunk=" */
//				return (-1);
//			}
			find_chunk = 1;
			if ( chunk_f == CefC_URI_NOT_ACCEPT_CHUNK ) {
				/* Error */
				return (-1);
			}
			chunk_ctr++;
			if ( chunk_ctr > 1 ) {
				/* Error */
				return (-1);
			}
			for( i = 0; i < sizeof(num_buff); ) {
				if ( tmp_str[6+i] == 0x00 ) {
					break;
				}
				if ( tmp_str[6+i] == '/' ) {
					/* Error Not Last seg */
					return (-1);
					break;
				}
				if ( (tmp_str[6+i] >= '0') && (tmp_str[6+i] <= '9') ) {
					num_buff[i] = tmp_str[6+i];
					i++;
				} else {
					/* Error Not numeric */
					return (-1);
				}
			}
			if ( strlen(num_buff) <= 0 ) {
				/* Error Not set */
				return (-1);
			}
			/* OK */
			memcpy( n1_p, tmp_str, tmp_len );
			n1_p += tmp_len;
			c1_p += tmp_len;
		} else if ( strncasecmp( (char*)tmp_str, "App:", 4 ) == 0 ) {
			char	num_buff[CefC_NumBufSiz];
			memset( num_buff, 0x00, sizeof(num_buff) );
			find_eq = 0;
			for( i = 0; i < sizeof(num_buff); ) {
				if ( tmp_str[4+i] == 0x00 ) {
					break;
				}
				if ( tmp_str[4+i] == '=' ) {
					find_eq = 1;
					i++;
					break;
				}
				if ( (tmp_str[4+i] >= '0') && (tmp_str[4+i] <= '9') ) {
					num_buff[i] = tmp_str[4+i];
					i++;
				} else {
					/* Error Not numeric */
					return (-1);
				}
			}
			if ( (tmp_str[4+i] == 0x00) && (first_seg_f == 1) ) {
				/* Error /APP:n=/ && first_seg */
					return (-1);
			}
			if ( (strlen(num_buff) <= 0) || (find_eq == 0) ) {
				/* Error Not set */
				return (-1);
			} else {
				num_test = atoi( num_buff );
				if ( (num_test < 0) || (num_test > 4095) ) {
					/* Error Out-of-Range */
					return (-1);
				}
			}
			/* OK */
			for ( i = 0; i < tmp_len; i++ ) {
				if ( tmp_str[i] != '"' ) {
					*n1_p = tmp_str[i];
					n1_p++;
				} else {
					/* NOP */
				}
			}
			c1_p += tmp_len;
		} else if ( strncasecmp( (char*)tmp_str, "0x", 2 ) == 0 ) {
			char	num_buff[CefC_NumBufSiz];
			memset( num_buff, 0x00, sizeof(num_buff) );

			/* HEX Type */
			num_buff[0] ='0';
			num_buff[1] ='x';
			for( i = 0; i < sizeof(num_buff); ) {
				if ( tmp_str[2+i] == 0x00 ) {
					break;
				}
				if ( tmp_str[2+i] == '=' ) {
					break;
				}
				if ( isxdigit(tmp_str[2+i]) ) {
					num_buff[2+i] = tmp_str[2+i];
					i++;
				} else {
					/* Error Not xdigit */
					return (-1);
				}
			}
			if ( strlen(num_buff) != 6 ) {
				/* Error Not set */
				return (-1);
			} else if ( (tmp_str_len == 7) && (first_seg_f == 1) ) {
				/* Error 0xXXXX=/ && First_SEG*/
				return (-1);
			} else {
				sscanf(num_buff, "%x", &hex_test);
				if ( hex_test == CefC_T_NAMESEGMENT ) {
					/* OK */
				} else if ( (hex_test >= CefC_T_APP_MIN) && (hex_test <= CefC_T_APP_MAX) ) {
					/* OK */
				} else if ( hex_test == CefC_T_CHUNK ) {
					if ( chunk_f == CefC_URI_NOT_ACCEPT_CHUNK ) {
						/* Error */
						return (-1);
					}
					find_chunk = 1;
					/* OK */
				} else {
					/* OK */
				}
			}
			/* OK */
			for ( i = 0; i < tmp_len; i++ ) {
				if ( tmp_str[i] != '"' ) {
					*n1_p = tmp_str[i];
					n1_p++;
				} else {
					/* NOP */
				}
			}
			/* OK */
//			memcpy( n1_p, tmp_str, tmp_len );
//			n1_p += tmp_len;
			c1_p += tmp_len;
		} else {
			/* OK */
			for ( i = 0; i < tmp_len; i++ ) {
				if ( tmp_str[i] != '"' ) {
					*n1_p = tmp_str[i];
					n1_p++;
				} else {
					/* NOP */
				}
			}
//			memcpy( n1_p, tmp_str, tmp_len );
//			n1_p += tmp_len;
			c1_p += tmp_len;
		}
		if ( break_p != NULL ) {
			if ( find_chunk == 1 ) {
				/* /Chunk= or 0x0010 is not Last segment */
				return (-1);
			}
			memset( n1_p, '/', 1 );
			n1_p++;
			c1_p++;
		}

		first_seg_f = 0;
	}

	return (0);
}


int
cef_frame_input_uri_pre_check2(
	const char* inuri, 						/* URI										*/
	unsigned char* name_1,					/* buffer to set After Check URI			*/
	int			chunk_f						/* "/Chunk=" Accept or Not Accept			*/
) {
	unsigned char chk_1[CefC_NAME_BUFSIZ];
	unsigned char tmp_str[CefC_NAME_BUFSIZ];
	int		i;
	int		num_test;
	int		tmp_str_len;
	int		tmp_len;
	int		first_seg_f = 1;	/* 1:first segmment 0:not */
	int		find_eq = 0;
	int		chunk_ctr = 0;
	int		find_chunk = 0;
	char* break_p;
	char* n1_p;
	char* c1_p;
	char* eq_p;
	unsigned int hex_test;

	memset( chk_1, 0x00, sizeof(chk_1) );

	/* ccnx:/ */
	if ( strncmp( inuri, "ccnx:/", 6 ) != 0 ) {
		/* Error */
		return (-1);
	}

	/* Need #define _GNU_SOURCE */
	memcpy( chk_1, inuri, strlen(inuri) );

	n1_p = (char*)name_1;
	c1_p = (char*)chk_1;
	break_p = strchr( (char*)chk_1, '/' );		/* search / */
	if ( break_p == NULL ) {
		/* Error */
		return (-1);
	}

	break_p++;
	tmp_len = break_p - c1_p;
	memcpy( n1_p, chk_1, tmp_len );				/* first / */

	n1_p += tmp_len;
	c1_p += tmp_len;

	if ( *break_p == '/' ) {				/* // */
		/* Error // */
		return (-1);
	}

	while( *c1_p ) {
		memset( tmp_str, 0x00, sizeof(tmp_str) );
		break_p = strchr( c1_p, '/' );			/* Next / */
		if ( break_p == NULL ) {
			tmp_len = strlen( c1_p );
		} else {
			tmp_len = break_p - c1_p;
		}
		memcpy( tmp_str, c1_p, tmp_len );		/*  pre '/' */
		tmp_str_len = (int)strlen((char*)tmp_str);

		/* /xxxxxxxxx/ */
		/* search '=' */
		eq_p = strchr( (char*)tmp_str, '=' );
		if ( eq_p == NULL ) {
			/* OK */
			for ( i = 0; i < tmp_len; i++ ) {
				if ( tmp_str[i] != '"' ) {
					*n1_p = tmp_str[i];
					n1_p++;
				} else {
					/* NOP */
				}
			}
			c1_p += tmp_len;
			if ( break_p != NULL ) {
				if ( find_chunk == 1 ) {
					/* /Chunk= or 0x0010 is not Last segment */
					return (-1);
				}
				memset( n1_p, '/', 1 );
				n1_p++;
				c1_p++;
			}
			first_seg_f = 0;
			continue;
		}

		if ( strncasecmp((char*)tmp_str, "NAME=", 5) == 0  ) {
			/* NAME= */
			if ( (tmp_str_len == 5) && (first_seg_f == 1) ) {
				/* Error first is "NAME=" */
				return (-1);
			}
			tmp_str_len -= 5;
			if ( tmp_str_len > 0 ) {
				for ( i = 0; i < tmp_str_len; i++ ) {
					if ( tmp_str[5+i] != '"' ) {
						*n1_p = tmp_str[5+i];
						n1_p++;
					} else {
						/* NOP */
					}
				}
			}
			c1_p += tmp_len;
		} else if ( strncasecmp((char*)tmp_str, "Chunk=", 6) == 0  ) {
			char	num_buff[CefC_NumBufSiz];
			memset( num_buff, 0x00, sizeof(num_buff) );

			if ( first_seg_f == 1 ) {
				/* Error */
				return (-1);
			}
			find_chunk = 1;
			if ( chunk_f == CefC_URI_NOT_ACCEPT_CHUNK ) {
				/* Error */
				return (-1);
			}
			chunk_ctr++;
			if ( chunk_ctr > 1 ) {
				/* Error */
				return (-1);
			}
			for( i = 0; i < sizeof(num_buff); ) {
				if ( tmp_str[6+i] == 0x00 ) {
					break;
				}
				if ( tmp_str[6+i] == '/' ) {
					/* Error Not Last seg */
					return (-1);
					break;
				}
				if ( (tmp_str[6+i] >= '0') && (tmp_str[6+i] <= '9') ) {
					num_buff[i] = tmp_str[6+i];
					i++;
				} else {
					/* Error Not numeric */
					return (-1);
				}
			}
			if ( strlen(num_buff) <= 0 ) {
				/* Error Not set */
				return (-1);
			}
			/* OK */
			memcpy( n1_p, tmp_str, tmp_len );
			n1_p += tmp_len;
			c1_p += tmp_len;
		} else if ( strncasecmp( (char*)tmp_str, "App:", 4 ) == 0 ) {
			char	num_buff[CefC_NumBufSiz];
			memset( num_buff, 0x00, sizeof(num_buff) );

			find_eq = 0;
			for( i = 0; i < sizeof(num_buff); ) {
				if ( tmp_str[4+i] == 0x00 ) {
					break;
				}
				if ( tmp_str[4+i] == '=' ) {
					find_eq = 1;
					i++;
					break;
				}
				if ( (tmp_str[4+i] >= '0') && (tmp_str[4+i] <= '9') ) {
					num_buff[i] = tmp_str[4+i];
					i++;
				} else {
					/* Error Not numeric */
					return (-1);
				}
			}
			if ( (tmp_str[4+i] == 0x00) && (first_seg_f == 1) ) {
				/* Error /APP:n=/ && first_seg */
					return (-1);
			}
			if ( (strlen(num_buff) <= 0) || (find_eq == 0) ) {
				/* Error Not set */
				return (-1);
			} else {
				num_test = atoi( num_buff );
				if ( (num_test < 0) || (num_test > 4095) ) {
					/* Error Out-of-Range */
					return (-1);
				}
			}
			/* OK */
			for ( i = 0; i < tmp_len; i++ ) {
				if ( tmp_str[i] != '"' ) {
					*n1_p = tmp_str[i];
					n1_p++;
				} else {
					/* NOP */
				}
			}
			c1_p += tmp_len;
		} else if ( strncasecmp( (char*)tmp_str, "0x", 2 ) == 0 ) {
			char	num_buff[CefC_NumBufSiz];
			memset( num_buff, 0x00, sizeof(num_buff) );

			/* HEX Type */
			num_buff[0] ='0';
			num_buff[1] ='x';
			for( i = 0; i < sizeof(num_buff); ) {
				if ( tmp_str[2+i] == 0x00 ) {
					break;
				}
				if ( tmp_str[2+i] == '=' ) {
					break;
				}
				if ( isxdigit(tmp_str[2+i]) ) {
					num_buff[2+i] = tmp_str[2+i];
					i++;
				} else {
					/* Error Not xdigit */
					return (-1);
				}
			}
			if ( strlen(num_buff) != 6 ) {
				/* Error Not set */
				return (-1);
			} else if ( (tmp_str_len == 7) && (first_seg_f == 1) ) {
				/* Error 0xXXXX=/ && First_SEG*/
				return (-1);
			} else {
				sscanf(num_buff, "%x", &hex_test);
				if ( hex_test == CefC_T_NAMESEGMENT ) {
					/* OK */
				} else if ( (hex_test >= CefC_T_APP_MIN) && (hex_test <= CefC_T_APP_MAX) ) {
					/* OK */
				} else if ( hex_test == CefC_T_CHUNK ) {
					if ( chunk_f == CefC_URI_NOT_ACCEPT_CHUNK ) {
						/* Error */
						return (-1);
					}
					find_chunk = 1;
					/* OK */
				} else {
					/* OK */
				}
			}
			/* OK */
			for ( i = 0; i < tmp_len; i++ ) {
				if ( tmp_str[i] != '"' ) {
					*n1_p = tmp_str[i];
					n1_p++;
				} else {
					/* NOP */
				}
			}
			/* OK */
//			memcpy( n1_p, tmp_str, tmp_len );
//			n1_p += tmp_len;
			c1_p += tmp_len;
		} else {
			/* OK */
			for ( i = 0; i < tmp_len; i++ ) {
				if ( tmp_str[i] != '"' ) {
					*n1_p = tmp_str[i];
					n1_p++;
				} else {
					/* NOP */
				}
			}
//			memcpy( n1_p, tmp_str, tmp_len );
//			n1_p += tmp_len;
			c1_p += tmp_len;
		}
		if ( break_p != NULL ) {
			if ( find_chunk == 1 ) {
				/* /Chunk= or 0x0010 is not Last segment */
				return (-1);
			}
			memset( n1_p, '/', 1 );
			n1_p++;
			c1_p++;
		}

		first_seg_f = 0;
	}

	return (0);
}

//0.8.3
/*--------------------------------------------------------------------------------------
	Creates the Interest Return from the specified Parameters
----------------------------------------------------------------------------------------*/
int 										/* Length of Interest Return Message		*/
cef_frame_interest_return_create (
	unsigned char* msg, 					/* Input Interest msg						*/
	uint16_t msg_len,
	unsigned char* buff, 					/* buffer to set Interest Return			*/
	uint8_t	IR_type							/* Interest Return 							*/
) {

	memcpy( buff, msg, msg_len );
	buff[1] = CefC_PT_INTRETURN;
	buff[5] = IR_type;

	return(msg_len);

}

/*--------------------------------------------------------------------------------------
	Get the info of Restriction flags from parsed CEFORE message
----------------------------------------------------------------------------------------*/
unsigned int
cef_frame_get_restr_type_from_pm (
	CefT_CcnMsg_MsgBdy* pm		/* Parsed CEFORE message */
) {
	unsigned int restr_type = 0;

	if ( pm->KeyIdRestr_f > 0 ) {
		restr_type |= CefC_PitKey_With_KEYID;
	}

	if (pm->ObjHashRestr_f > 0) {
		restr_type |= CefC_PitKey_With_COBHASH;
	}

	restr_type |= CefC_PitKey_With_NAME;

	return restr_type;
}


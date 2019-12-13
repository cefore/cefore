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
 * cef_plugin_ndn_v050.c
 */
#define __CEF_PLUGIN_NDN_V050__SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

#include <openssl/sha.h>

#include <cefore/cef_client.h>
#include <cefore/cef_face.h>
#include <cefore/cef_fib.h>
#include <cefore/cef_frame.h>
#include <cefore/cef_plugin.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

#define CefC_Ndn_Fib_Max				128
#define CefC_Ndn_Pit_Max				1024
#define CefC_Ndn_Face_Max				128

#define CefC_Ndn_Fib_Param_Num			3
#define CefC_Ndn_Fib_Param_Name			0
#define CefC_Ndn_Fib_Param_Prot			1
#define CefC_Ndn_Fib_Param_Addr			2

#define CefC_Ndn_Face_Type_Invalid		0x00
#define CefC_Ndn_Face_Type_Tcp			0x01
#define CefC_Ndn_Face_Type_Udp			0x02
#define CefC_Ndn_Face_Type_Local		0x03


#define PARSE_LENGTH(_p, _len, _val)									\
	do {													\
		unsigned char* _wp = (unsigned char*) _p;			\
		uint16_t _value16;				\
		uint32_t _value32;				\
		if (_wp[0] == 253) {				\
			memcpy (&_value16, &_wp[1], sizeof (uint16_t));				\
			_val = ntohs (_value16);				\
			_len = 3;				\
		} else if (_wp[1] == 254) {				\
			memcpy (&_value32, &_wp[1], sizeof (uint32_t));				\
			_val = (uint16_t) ntohl (_value32);				\
			_len = 5;				\
		} else {				\
			_val = (uint16_t) _wp[0];				\
			_len = 1;				\
		}														\
	} while (0)


/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

/*** Face Information 			***/
typedef struct _CefT_Ndn_Face {
	
	uint16_t 	faceid;
	uint16_t 	index;
	int 		fd;
	
} CefT_Ndn_Face;

/*** Connection Information 	***/
typedef struct _CefT_Ndn_Sock {
	struct sockaddr* 	ai_addr;
	socklen_t 			ai_addrlen;
	int 				sock;
	int 				faceid;
	uint8_t 			protocol;
} CefT_Ndn_Sock;

/*** FIB Information 			***/
typedef struct _CefC_Ndn_Fib_Face {

	int 							faceid;
	struct _CefC_Ndn_Fib_Face* 		next;

} CefC_Ndn_Fib_Face;

/*** FIB entry 					***/
typedef struct _CefC_Ndn_Fib_Entry {
	
	unsigned char* 			key;
	unsigned int 			klen;
	CefC_Ndn_Fib_Face		faces;
	
} CefC_Ndn_Fib_Entry;

/*** PIT entry 					***/

typedef struct _CefC_Ndn_Pit_Face {

	int 							faceid;
	struct _CefC_Ndn_Pit_Face* 		next;

} CefC_Ndn_Pit_Face;

typedef struct {

	unsigned char* 		key;				/* Key of the PIT entry 					*/
	unsigned int 		klen;				/* Length of this key 						*/
	CefC_Ndn_Pit_Face	faces;				/* Down Stream Face entries 				*/
	
} CefC_Ndn_Pit_Entry;

/****************************************************************************************
 State Variables
 ****************************************************************************************/

static int m_ndn_plugin_f 		= 0;
static int m_stat_output_f 		= 0;
static uint64_t m_stat_cef_rx 	= 0;
static uint64_t m_stat_ndn_rx 	= 0;
static uint64_t m_stat_cef_tx 	= 0;
static uint64_t m_stat_ndn_tx 	= 0;

static unsigned char 	recv_buff[CefC_Max_Length];
static uint16_t 		buff_idx;
static uint16_t 		buff_len;

static CefT_Hash_Handle 	cef_fib;

static CefT_Hash_Handle 	sock_tbl;
static CefT_Hash_Handle 	ndn_fib;
static CefT_Hash_Handle 	ndn_pit;

static CefT_Ndn_Face 		ndn_faces[CefC_Ndn_Face_Max];
static int 					assigned_faceid;
static uint16_t 			ndn_port_num;

static uint16_t ftvh_name 		= CefC_T_NAME;
static uint16_t ftvh_nameseg 	= CefC_T_NAMESEGMENT;
static uint16_t ftvh_meta 		= CefC_T_META;
static uint16_t ftvn_name;
static uint16_t ftvn_nameseg;
static uint16_t ftvn_meta;

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

static void 
cef_plugin_ndn_fib_create (
	void 
);
static int
cef_plugin_ndn_trim_line_string (
	const char* p, 								/* target string for trimming 			*/
	char* name,									/* name string after trimming			*/
	char* prot,									/* protocol string after trimming		*/
	char* addr									/* address string after trimming		*/
);
static int									/* Face-ID									*/
cef_plugin_ndn_lookup_faceid_from_addrstr (
	const char* destination,				/* String of destination address 			*/
	const char* protocol					/* protoco (udp,tcp,local) 					*/
);
static int									/* Face-ID									*/
cef_plugin_ndn_lookup_faceid (
	const char* destination, 				/* String of the destination address 		*/
	int protocol							/* protoco (udp,tcp,local) 					*/
);
static void
cef_plugin_ndn_addrinfo_free (
	struct addrinfo* ai							/* addrinfo to free 					*/
);
static int										/* Face-ID that is not used				*/
cef_plugin_ndn_faceid_search (
	void
);
static int									/* Peer Face-ID 							*/
cef_plugin_ndn_lookup_peer_faceid (
	struct addrinfo* sas, 					/* sockaddr_storage structure				*/
	socklen_t sas_len						/* length of sockaddr_storage				*/
);
static void
cef_plugin_ndn_sock_entry_destroy (
	CefT_Ndn_Sock* entry						/* the entry to destroy					*/
);
static CefT_Ndn_Sock*							/* the created new entry				*/
cef_plugin_ndn_sock_entry_create (
	int sock, 									/* file descriptor to register			*/
	struct sockaddr* ai_addr,
	socklen_t ai_addrlen
);
static int									/* Returns a negative value if it fails 	*/
cef_plugin_ndn_messege_head_seek (
	void
);
static int									/* Returns a negative value if it fails 	*/
cef_plugin_ndn_interest_process (
	unsigned char* 		msg, 
	uint16_t 			msg_len, 
	uint16_t 			peer_faceid
);
static int									/* Returns a negative value if it fails 	*/
cef_plugin_ndn_data_process (
	unsigned char* 		msg, 
	uint16_t 			msg_len, 
	uint16_t 			peer_faceid
);
static uint16_t								/* length of Cefore Name 					*/
cef_plugin_ndn_n2c_name_convert (
	unsigned char* 		ndn_name, 
	uint16_t 			ndn_name_len, 
	unsigned char* 		cef_name
);
static CefC_Ndn_Pit_Entry* 					/* a PIT entry								*/
cef_plugin_ndn_pit_entry_update (
	CefT_Hash_Handle pit,					/* PIT										*/
	unsigned char* name, 
	uint16_t name_len, 
	uint16_t faceid
);
static CefC_Ndn_Fib_Entry* 					/* FIB entry 								*/
cef_plugin_ndn_fib_entry_search (
	unsigned char* name, 					/* Key of the FIB entry						*/
	uint16_t name_len						/* Length of Key							*/
);
static uint16_t								/* length of NDN Name 						*/
cef_plugin_ndn_c2n_name_convert (
	unsigned char* 		cef_name, 
	uint16_t 			cef_name_len, 
	unsigned char* 		ndn_name
);


/****************************************************************************************
 For Debug Trace
 ****************************************************************************************/


/****************************************************************************************
 ****************************************************************************************/
 
/*--------------------------------------------------------------------------------------
	Callback for init process
----------------------------------------------------------------------------------------*/
int 												/* variant caused the problem		*/
cef_plugin_ndn_init (
	CefT_Plugin_Ndn* ndn, 							/* NDN Plugin Handle				*/
	const CefT_Hash_Handle cefore_fib				/* FIB of cefnetd (Cefore) 			*/
) {
	CefT_List* lp 		= NULL;
	char* value_str 	= NULL;
	
	/*--------------------------------------------------------------
		Obtains the attributes
	----------------------------------------------------------------*/
	m_ndn_plugin_f = 1;
	
	/* Outputs Log 			*/
	lp = cef_plugin_parameter_value_get ("NDN", "stat");
	
	if (lp) {
		value_str = (char*) cef_plugin_list_access (lp, 0);
		
		if (strcmp (value_str, "yes") == 0) {
			m_stat_output_f = 1;
		}
	}
	
	/* Port to connect NDN 		*/
	ndn_port_num 	= 6363;
	ndn->port_num 	= ndn_port_num;
	lp = cef_plugin_parameter_value_get ("NDN", "port");
	
	if (lp) {
		value_str = (char*) cef_plugin_list_access (lp, 0);
		
		if (value_str) {
			ndn->port_num = atoi (value_str);
			if (ndn->port_num < 1024) {
				ndn->port_num = 6363;
			}
		}
	}
	
	/*--------------------------------------------------------------
		Records the address of Cefore FIB
	----------------------------------------------------------------*/
	cef_fib = cefore_fib;
	
	/*--------------------------------------------------------------
		Records the address of NDN FIB
	----------------------------------------------------------------*/
	assigned_faceid = 0;
	buff_idx 		= 0;
	buff_len 		= 0;
	memset (ndn_faces, 0, sizeof (CefT_Ndn_Face) * CefC_Ndn_Face_Max);
	
	ndn_fib  = cef_hash_tbl_create (CefC_Ndn_Fib_Max);
	sock_tbl = cef_hash_tbl_create (CefC_Ndn_Fib_Max);
	cef_plugin_ndn_fib_create ();
	
	/*--------------------------------------------------------------
		Records the address of NDN PIT
	----------------------------------------------------------------*/
	ndn_pit = cef_hash_tbl_create (CefC_Ndn_Pit_Max);
	
	ftvn_name 		= htons (ftvh_name);
	ftvn_nameseg 	= htons (ftvh_nameseg);
	ftvn_meta 		= htons (ftvh_meta);
	
	return (1);
}
/*--------------------------------------------------------------------------------------
	Callback for incoming NDN msg process
----------------------------------------------------------------------------------------*/
int
cef_plugin_ndn_ndnmsg (
	CefT_Plugin_Ndn* 	ndn							/* NDN Plugin Handle				*/
) {
	unsigned char 	pkt[CefC_Max_Length];
	unsigned char 	buff[CefC_Max_Length];
	unsigned char* 	msg;
	unsigned char* 	wp;
	int 		recv_len;
	uint16_t 	move_len;
	int 		res;
	struct addrinfo sas;
	socklen_t sas_len = (socklen_t) sizeof (struct addrinfo);
	int 		peer_faceid;
	
	/* Updates statistics 		*/
	m_stat_ndn_rx++;
	
	/*---------------------------------------------------
		Receives the message(s) from the specified FD
	-----------------------------------------------------*/
	recv_len = recvfrom (ndn->listen_fd, pkt, CefC_Max_Length, 0
									, (struct sockaddr*) &sas, &sas_len);
	
	if (recv_len < 0) {
		return (0);
	}
	peer_faceid = cef_plugin_ndn_lookup_peer_faceid (&sas, sas_len);
	if (peer_faceid < 0) {
		return (-1);
	}
	
	msg = pkt;
	
	/*---------------------------------------------------
		Seeks the head of NDN message
	-----------------------------------------------------*/
	while (recv_len > 0) {
		/* Calculates the size of the message which have not been yet handled 	*/
		if (recv_len > CefC_Max_Length - buff_len) {
			move_len = CefC_Max_Length - buff_len;
		} else {
			move_len = (uint16_t) recv_len;
		}
		recv_len -= move_len;
		
		/* Updates the receive buffer 		*/
		memcpy (recv_buff + buff_len, msg, move_len);
		buff_len += move_len;
		msg += move_len;
		
		while (buff_len > 0) {
			/* Seeks the top of the message */
			res = cef_plugin_ndn_messege_head_seek ();
			if (res < 0) {
				break;
			}
			
			/* Calls the function corresponding to the type of the message 	*/
			switch (recv_buff[0]) {
				/*** Interest 		***/
				case (0x05): {
					cef_plugin_ndn_interest_process (
							recv_buff, (uint16_t) res, (uint16_t) peer_faceid);
					break;
				}
				/*** Data 			***/
				case (0x06): {
					cef_plugin_ndn_data_process (
							recv_buff, (uint16_t) res, (uint16_t) peer_faceid);
					break;
				}
				/*** NDNLP (0x64)	***/
				/*** Unknown 		***/
				default: {
					/* NOP */
					break;
				}
			}
			
			/* Updates the receive buffer 		*/
			move_len = (uint16_t) res;
			wp = recv_buff + move_len;
			memcpy (buff, wp, buff_len - move_len);
			memcpy (recv_buff, buff, buff_len - move_len);
			buff_len -= move_len;
		}
	}
	
	return (0);
}

/*--------------------------------------------------------------------------------------
	Callback for incoming Cefore msg process
----------------------------------------------------------------------------------------*/
int
cef_plugin_ndn_cefint (
	CefT_Plugin_Ndn* 		ndn,					/* NDN Plugin Handle				*/
	unsigned char* 			cef_msg, 
	uint16_t 				cef_msg_len, 
	CefT_Parsed_Message* 	pm, 					/* Parsed CEFORE message			*/
	CefT_Parsed_Opheader* 	poh,					/* Parsed Option Header				*/
	uint16_t 				peer_faceid
) {
	CefC_Ndn_Fib_Entry* fib_entry;
	unsigned char ndn_name[CefC_Max_Length];
	unsigned char ndn_msg[CefC_Max_Length];
	uint16_t ndn_name_len;
	uint16_t ndn_idx = 0;
	uint16_t ndn_msg_len = 0;
	uint16_t value16;
	uint32_t value32;
	CefC_Ndn_Fib_Face* face;
	CefT_Ndn_Sock* sock_entry;
	
	
	/* Updates statistics 		*/
	m_stat_cef_rx++;
	
	/* Searches Name from NDN FIB 		*/
	fib_entry = cef_plugin_ndn_fib_entry_search (pm->name, pm->name_len);
	
	if (fib_entry == NULL) {
		return (0);
	}
	
	/* Converts the Cefore Name to NDN Name 		*/
	ndn_name_len = cef_plugin_ndn_c2n_name_convert (pm->name, pm->name_len, ndn_name);
	
	if (ndn_name_len == 0) {
		return (0);
	}
	
	/* Sets PacketType and PacketLen 		*/
	ndn_msg[ndn_idx] = 0x05;
	ndn_idx++;
	
	if (ndn_name_len < 253) {
		/* NameType(1) + NameLen(1) + NameValue + NonceTLV(6) 		*/
		ndn_msg_len = ndn_name_len + 8;
	} else {
		/* NameType(1) + NameLen(3) + NameValue + NonceTLV(6) 		*/
		ndn_msg_len = ndn_name_len + 10;
	}
	
	if (ndn_msg_len < 253) {
		ndn_msg[ndn_idx] = (unsigned char) ndn_msg_len;
		ndn_idx++;
	} else {
		value16 = htons (ndn_msg_len);
		memcpy (&ndn_msg[ndn_idx], &value16, sizeof (uint16_t));
		ndn_idx += 3;
	}
	
	/* Sets Name TLVs 		*/
	ndn_msg[ndn_idx] = 0x07;
	ndn_idx++;
	
	if (ndn_name_len < 253) {
		ndn_msg[ndn_idx] = (unsigned char) ndn_name_len;
		ndn_idx++;
	} else {
		value16 = htons (ndn_name_len);
		memcpy (&ndn_msg[ndn_idx], &value16, sizeof (uint16_t));
		ndn_idx += 3;
	}
	memcpy (&ndn_msg[ndn_idx], ndn_name, ndn_name_len);
	ndn_idx += ndn_name_len;
	
	/* Sets Nonce TLVs 		*/
	ndn_msg[ndn_idx] 	 = 0x0a;
	ndn_msg[ndn_idx + 1] = 4;
	ndn_idx += 2;
	
	srand ((unsigned) time (NULL));
	value32 = (uint32_t) rand ();
	value32 = htonl (value32);
	memcpy (&ndn_msg[ndn_idx], &value32, sizeof (uint32_t));
	ndn_idx += sizeof (uint32_t);
	
	
	face = &(fib_entry->faces);
	
	while (face->next) {
		
		/* Updates the NDN PIT 			*/
		cef_plugin_ndn_pit_entry_update (
					ndn_pit, pm->name, pm->name_len, peer_faceid);
		
		face = face->next;
		sock_entry = (CefT_Ndn_Sock*) cef_hash_tbl_item_get_from_index (
											sock_tbl, ndn_faces[face->faceid].index);
		if (sock_entry == NULL) {
			continue;
		}
		
		sendto (ndn->listen_fd, ndn_msg, ndn_idx
			, 0, sock_entry->ai_addr, sock_entry->ai_addrlen);
	}
	
	return (0);
}

/*--------------------------------------------------------------------------------------
	Callback for incoming Cefore msg process
----------------------------------------------------------------------------------------*/
int
cef_plugin_ndn_cefcob (
	CefT_Plugin_Ndn* 		ndn,					/* NDN Plugin Handle				*/
	unsigned char* 			cef_msg, 
	uint16_t 				cef_msg_len,
	CefT_Parsed_Message* 	pm, 					/* Parsed CEFORE message			*/
	CefT_Parsed_Opheader* 	poh						/* Parsed Option Header				*/
) {
	unsigned char ndn_msg[CefC_Max_Length];
	unsigned char ndn_name[CefC_Max_Length];
	uint16_t ndn_name_len;
	uint16_t value16;
	uint16_t ndn_msg_len 	= 0;
	uint16_t ndn_idx 		= 0;
	uint16_t trg_len 		= 0;
	uint16_t trg_offset 	= 0;
	SHA256_CTX 		ctx;
	unsigned char signe[64];
	CefC_Ndn_Pit_Entry* pit_entry;
	CefC_Ndn_Pit_Face* face;
	CefT_Ndn_Sock* sock_entry;
	
	/* Updates statistics 		*/
	m_stat_cef_rx++;
	
	/*--------------------------------------------------------------
		Checks the NDN PIT 
	----------------------------------------------------------------*/
	
	pit_entry = (CefC_Ndn_Pit_Entry*) 
		cef_hash_tbl_item_remove (ndn_pit, pm->name, pm->name_len);
	
	if (pit_entry == NULL) {
		return (1);
	}
	
	/* Converts the Cefore Name to NDN Name 		*/
	ndn_name_len = cef_plugin_ndn_c2n_name_convert (pm->name, pm->name_len, ndn_name);
	
	if (ndn_name_len == 0) {
		free (pit_entry);
		return (0);
	}
	
	/*--------------------------------------------------------------
		Caluclation the length of NDN Data Packet 
	----------------------------------------------------------------*/
	
	/* Name 			*/
	if (ndn_name_len < 253) {
		/* NameType(1) + NameLen(1) + NameValue		*/
		ndn_msg_len = ndn_name_len + 2;
	} else {
		/* NameType(1) + NameLen(3) + NameValue		*/
		ndn_msg_len = ndn_name_len + 4;
	}
	
	/* Content 			*/
	if (pm->payload_len < 253) {
		/* PayloadType(1) + PayloadLen(1) + Payload		*/
		ndn_msg_len += pm->payload_len + 2;
	} else {
		/* PayloadType(1) + PayloadLen(3) + Payload		*/
		ndn_msg_len += pm->payload_len + 4;
	}
	
	/* SignatureInfo + SignatureValue 		*/
	ndn_msg_len += 39;
	
	/* MetaInfo 							*/
	if (pm->meta_len < 253) {
		/* PayloadType(1) + PayloadLen(1) + Payload		*/
		ndn_msg_len += pm->meta_len + 2;
	} else {
		/* PayloadType(1) + PayloadLen(3) + Payload		*/
		ndn_msg_len += pm->meta_len + 4;
	}
	
	/*--------------------------------------------------------------
		Creates the NDN Data
	----------------------------------------------------------------*/
	
	/* Sets PacketType and PacketLen 	*/
	ndn_msg[ndn_idx] = 0x06;
	ndn_idx++;
	
	if (ndn_msg_len < 253) {
		ndn_msg[ndn_idx] = (unsigned char)(ndn_msg_len);
		ndn_idx++;
		trg_offset = 2;
	} else {
		ndn_msg[ndn_idx] = 0xfd;
		value16 = htons (ndn_msg_len);
		memcpy (&ndn_msg[ndn_idx + 1], &value16, sizeof (uint16_t));
		ndn_idx += 3;
		trg_offset = 4;
	}
	trg_len = ndn_msg_len;
	
	/* Sets Name TLVs 		*/
	ndn_msg[ndn_idx] = 0x07;
	ndn_idx++;
	
	if (ndn_name_len < 253) {
		ndn_msg[ndn_idx] = (unsigned char) ndn_name_len;
		ndn_idx++;
	} else {
		ndn_msg[ndn_idx] = 0xfd;
		value16 = htons (ndn_name_len);
		memcpy (&ndn_msg[ndn_idx + 1], &value16, sizeof (uint16_t));
		ndn_idx += 3;
	}
	memcpy (&ndn_msg[ndn_idx], ndn_name, ndn_name_len);
	ndn_idx += ndn_name_len;
	
	/* Sets MetaInfo 		*/
	ndn_msg[ndn_idx] = 0x14;
	ndn_idx++;
	
	if (pm->meta_len < 253) {
		ndn_msg[ndn_idx] = (unsigned char) pm->meta_len;
		ndn_idx++;
	} else {
		ndn_msg[ndn_idx] = 0xfd;
		value16 = htons (pm->meta_len);
		memcpy (&ndn_msg[ndn_idx + 1], &value16, sizeof (uint16_t));
		ndn_idx += 3;
	}
	if (pm->meta_len > 0) {
		memcpy (&ndn_msg[ndn_idx], &cef_msg[pm->meta_f], pm->meta_len);
		ndn_idx += pm->meta_len;
	}
	
	/* Sets Content TLV 	*/
	ndn_msg[ndn_idx] = 0x15;
	ndn_idx++;
	
	if (pm->payload_len < 253) {
		ndn_msg[ndn_idx] = (unsigned char) pm->payload_len;
		ndn_idx++;
	} else {
		ndn_msg[ndn_idx] = 0xfd;
		value16 = htons (pm->payload_len);
		memcpy (&ndn_msg[ndn_idx + 1], &value16, sizeof (uint16_t));
		ndn_idx += 3;
	}
	if (pm->payload_len > 0) {
		memcpy (&ndn_msg[ndn_idx], pm->payload, pm->payload_len);
		ndn_idx += pm->payload_len;
	}
	
	/* Sets Signature 		*/
	ndn_msg[ndn_idx    ] 	= 0x16;
	ndn_msg[ndn_idx + 1] 	= 0x03;
	ndn_msg[ndn_idx + 2] 	= 0x1b;
	ndn_msg[ndn_idx + 3] 	= 0x01;
	ndn_msg[ndn_idx + 4] 	= 0x00;
	
	ndn_msg[ndn_idx + 5] 	= 0x17;
	ndn_msg[ndn_idx + 6] 	= 0x20;
	
	SHA256_Init (&ctx);
	SHA256_Update (&ctx, &ndn_msg[trg_offset], trg_len);
	SHA256_Final (signe, &ctx);
	memcpy (&ndn_msg[ndn_idx + 7], signe, 32);
	ndn_idx += 39;
	
	/*--------------------------------------------------------------
		Forwards the NDN packet to the downstream NFD
	----------------------------------------------------------------*/
	face = &(pit_entry->faces);
	
	while (face->next) {
		face = face->next;
		sock_entry = (CefT_Ndn_Sock*) cef_hash_tbl_item_get_from_index (
											sock_tbl, ndn_faces[face->faceid].index);
		if (sock_entry == NULL) {
			continue;
		}
		
		sendto (ndn->listen_fd, ndn_msg, ndn_idx
			, 0, sock_entry->ai_addr, sock_entry->ai_addrlen);
	}
	
	free (pit_entry);
	
	return (0);
}

/*--------------------------------------------------------------------------------------
	Callback for post process
----------------------------------------------------------------------------------------*/
void 
cef_plugin_ndn_destroy (
	CefT_Plugin_Ndn* 	ndn 						/* NDN Plugin Handle				*/
) {
	int i;
	
	/* Outputs statistics 		*/
	if (m_stat_output_f) {
		fprintf (stderr, "[NDN STATISTICS]\n");
		fprintf (stderr, " Rx Cefore Message : "FMTU64"\n", m_stat_cef_rx);
		fprintf (stderr, " Rx NDN    Message : "FMTU64"\n", m_stat_ndn_rx);
		fprintf (stderr, " Tx Cefore Message : "FMTU64"\n", m_stat_cef_tx);
		fprintf (stderr, " Tx NDN    Message : "FMTU64"\n", m_stat_ndn_tx);
	}
	
	for (i = 0 ; i < CefC_Ndn_Face_Max ; i++) {
		if (ndn_faces[i].fd != 0) {
			close (ndn_faces[i].fd);
		}
	}
	
	return;
}

/*--------------------------------------------------------------------------------------
	Outputs NDN FIB
----------------------------------------------------------------------------------------*/
void 
cef_plugin_ndn_fib_print (
	char* rsp_msg
) {
	char 	ws[1024];
	FILE*	fp = NULL;
	char 	buff[65600];	/* 65535 (max length of name) + 64 */
	char 	uri[CefC_Max_Length];
	char 	addr[64];
	char 	prot[64];
	int 	res;
	int 	output_num = 0;
	
	if (m_ndn_plugin_f == 0) {
		sprintf (rsp_msg, "%s  NDN Plugin is not running\n", rsp_msg);
		return;
	}
	
	/* Opens FIB file of NDN 		*/
	cef_client_config_dir_get (ws);
	sprintf (ws, "%s/ndn.fib", ws);
	
	fp = fopen (ws, "r");
	if (fp == NULL) {
		fp = fopen (ws, "w");
		if (fp == NULL) {
			fprintf (stderr, "[cefore] cef_plugin_ndn_fib_create (ERROR: Write)\n");
			return;
		}
		fclose (fp);
		fp = fopen (ws, "r");
	}
	
	while (fgets (buff, 65600, fp) != NULL) {
		if (buff[0] == 0x23/* '#' */) {
			continue;
		}
		
		/* parse the read line 		*/
		res = cef_plugin_ndn_trim_line_string (buff, uri, prot, addr);
		if (res < 0) {
			continue;
		}
		sprintf (rsp_msg, "%s  %s\n", rsp_msg, uri);
		sprintf (rsp_msg, "%s    %s:%s\n", rsp_msg, addr, prot);
		output_num++;
	}
	fclose (fp);
	
	if (output_num == 0) {
		sprintf (rsp_msg, "%s  Entry is empty\n", rsp_msg);
	}
	
	return;
}

/* #################################################################################### */
/* #################################################################################### */
/* #################################################################################### */

/*--------------------------------------------------------------------------------------
	Incomming NDN Interest process
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cef_plugin_ndn_interest_process (
	unsigned char* 		msg, 
	uint16_t 			msg_len, 
	uint16_t 			peer_faceid
) {
	
	uint16_t index 			= 0;
	uint16_t value16 		= 0;
	uint32_t nonce 			= 0;
	uint16_t fld_len 		= 0;
	uint16_t name_len 		= 0;
	uint16_t name_offset 	= 0;
	uint16_t nonce_offset 	= 0;
	uint16_t nonce_lne 		= 0;
	CefT_Interest_TLVs params;
	unsigned char buff[CefC_Max_Length];
	int res, i;
	CefT_Fib_Entry* 	fib_entry;
	uint16_t faceids[CefC_Fib_UpFace_Max];
	uint16_t face_num = 0;
	
	/* Parses the received NDN Interest 		*/
	PARSE_LENGTH (&msg[index], fld_len, value16);
	index += fld_len;
	PARSE_LENGTH (&msg[index], fld_len, value16);
	index += fld_len;
	
	while (index < msg_len) {
		if (msg[index] == 0x07) {
			/***** Name 			*****/
			name_offset = index;
			PARSE_LENGTH (&msg[index + 1], fld_len, name_len);
			index += 1 /* Type */ + fld_len + name_len;
		} else if (msg[index] == 0x0a) {
			/***** Nonce			*****/
			PARSE_LENGTH (&msg[index + 1], fld_len, nonce_lne);
			nonce_offset = index;
			index += 1 /* Type */ + fld_len + nonce_lne;
			
			memcpy (&nonce, &msg[index + 2], sizeof (uint32_t));
			nonce = ntohs (nonce);
		} else {
			PARSE_LENGTH (&msg[index], fld_len, value16);
			index += fld_len;
			PARSE_LENGTH (&msg[index], fld_len, value16);
			index += fld_len + value16;
		}
	}
	
	if ((nonce_offset == 0) || (name_offset == 0)) {
		return (-1);
	}
	memset (&params, 0, sizeof (CefT_Interest_TLVs));
	
	/* Converts the Name from NDN format to ICN format 		*/
	params.name_len 
		= cef_plugin_ndn_n2c_name_convert (&msg[name_offset], name_len, params.name);
	
	/* Creates ICN Interest 			*/
	params.hoplimit 		= 32;
	params.opt.lifetime_f 	= 1;
	params.opt.lifetime 	= CefC_Default_LifetimeSec * 1000;
	params.opt.symbolic_f 	= CefC_T_OPT_REGULAR;
	params.nonce_f 			= 1;
	params.nonce 			= cef_client_htonb ((uint64_t) nonce);
	
	res = cef_frame_interest_create (buff, &params);
	
	if (res > 0) {
		
		/* Updates the NDN PIT 			*/
		cef_plugin_ndn_pit_entry_update (
					ndn_pit, params.name, params.name_len, peer_faceid);
		
		/* Search the Cefore FIB 		*/
		fib_entry = cef_fib_entry_search (cef_fib, params.name, params.name_len);
		
		/* Sends the Cefore Interest 	*/
		if (fib_entry) {
			face_num = cef_fib_forward_faceid_get (fib_entry, faceids);
			
			for (i = 0 ; i < face_num ; i++) {
				if (cef_face_check_active (faceids[i]) > 0) {
					cef_face_frame_send_forced (faceids[i], buff, (uint16_t) res);
				}
			}
		}
	}
	
	return (1);
}

/*--------------------------------------------------------------------------------------
	Incomming NDN Data process
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cef_plugin_ndn_data_process (
	unsigned char* 		msg, 
	uint16_t 			msg_len, 
	uint16_t 			peer_faceid
) {
	uint16_t index 				= 0;
	uint16_t value16			= 0;
	uint16_t fld_len 			= 0;
	uint16_t name_len 			= 0;
	uint16_t name_offset 		= 0;
	uint16_t content_len 		= 0;
	uint16_t content_offset 	= 0;
	uint16_t metainfo_len 		= 0;
	uint16_t metainfo_offset 	= 0;
	
	CefT_Object_TLVs params;
	CefC_Ndn_Pit_Entry* pit_entry;
	CefC_Ndn_Pit_Face* face;
	unsigned char buff[CefC_Max_Length];
	int res;
	
	/* Parses the received NDN Data 		*/
	PARSE_LENGTH (&msg[index], fld_len, value16);
	index += fld_len;
	PARSE_LENGTH (&msg[index], fld_len, value16);
	index += fld_len;
	
	while (index < msg_len) {
		
		if (msg[index] == 0x07) {
			/***** Name 			*****/
			name_offset = index;
			PARSE_LENGTH (&msg[index + 1], fld_len, name_len);
			index += 1 /* Type */ + fld_len + name_len;
		} else if (msg[index] == 0x15) {
			/***** Content			*****/
			PARSE_LENGTH (&msg[index + 1], fld_len, content_len);
			content_offset = index + 1 + fld_len;
			index += 1 /* Type */ + fld_len + content_len;
			
		} else if (msg[index] == 0x14) {
			/***** MetaInfo			*****/
			PARSE_LENGTH (&msg[index + 1], fld_len, metainfo_len);
			metainfo_offset = index + 1 + fld_len;
			index += 1 /* Type */ + fld_len + metainfo_len;
			
		} else {
			PARSE_LENGTH (&msg[index], fld_len, value16);
			index += fld_len;
			PARSE_LENGTH (&msg[index], fld_len, value16);
			index += fld_len + value16;
		}
	}
	
	if ((name_offset == 0) || (content_offset == 0)) {
		return (-1);
	}
	memset (&params, 0, sizeof (CefT_Object_TLVs));
	
	/* Searches the Name from the NDN PIT 		*/
	params.name_len = 
		cef_plugin_ndn_n2c_name_convert (&msg[name_offset], name_len, params.name);
	
	pit_entry = (CefC_Ndn_Pit_Entry*) 
		cef_hash_tbl_item_remove (ndn_pit, params.name, params.name_len);
	
	if (pit_entry == NULL) {
		return (1);
	}
	
	/* Creates ICN Data 			*/
	if (content_len > 0) {
		memcpy (params.payload, &msg[content_offset], content_len);
		params.payload_len = content_len;
	}
	
	if (metainfo_len > 0) {
		memcpy (params.meta, &msg[metainfo_offset], metainfo_len);
		params.meta_len = metainfo_len;
	}
	
	res = cef_frame_object_create (buff, &params);
	
	if (res > 0) {
		
		face = &(pit_entry->faces);
		
		while (face->next) {
			face = face->next;
			cef_face_frame_send_forced (face->faceid, buff, (uint16_t) res);
		}
	}
	free (pit_entry);
	
	return (1);
}

/*--------------------------------------------------------------------------------------
	Looks up and creates a PIT entry matching the specified Name
----------------------------------------------------------------------------------------*/
static CefC_Ndn_Pit_Entry* 					/* a PIT entry								*/
cef_plugin_ndn_pit_entry_update (
	CefT_Hash_Handle pit,					/* PIT										*/
	unsigned char* name, 
	uint16_t name_len, 
	uint16_t faceid
) {
	CefC_Ndn_Pit_Entry* entry;
	CefC_Ndn_Pit_Face* face;
	
	/* Searches a PIT entry 	*/
	entry = (CefC_Ndn_Pit_Entry*) cef_hash_tbl_item_get (pit, name, name_len);
	
	/* Creates a new PIT entry, if it dose not match 	*/
	if (entry == NULL) {
		entry = (CefC_Ndn_Pit_Entry*) malloc (sizeof (CefC_Ndn_Pit_Entry));
		memset (entry, 0, sizeof (CefC_Ndn_Pit_Entry));
		entry->key = (unsigned char*) malloc (name_len);
		entry->klen = name_len;
		memcpy (entry->key, name, name_len);
		cef_hash_tbl_item_set (pit, name, name_len, entry);
	}
	
	face = &(entry->faces);
	
	while (face->next) {
		face = face->next;
		if (face->faceid == faceid) {
			return (entry);
		}
	}
	face->next = (CefC_Ndn_Pit_Face*) malloc (sizeof (CefC_Ndn_Pit_Face));
	memset (face->next, 0, sizeof (CefC_Ndn_Pit_Face));
	face->next->faceid = faceid;
	
	return (entry);
}

/*--------------------------------------------------------------------------------------
	Converts the name from NDN to Cefore
----------------------------------------------------------------------------------------*/
static uint16_t								/* length of Cefore Name 					*/
cef_plugin_ndn_n2c_name_convert (
	unsigned char* 		ndn_name, 
	uint16_t 			ndn_name_len, 
	unsigned char* 		cef_name
) {
	
	uint16_t cef_idx = 0;
	uint16_t ndn_idx = 0;
	uint16_t seg_len;
	struct tlv_hdr tlv_fld;
	uint16_t value16;
	uint32_t value32;
	
	while (ndn_idx < ndn_name_len) {
		if (ndn_name[ndn_idx] == 0x08/* NameComponent */) {
			if (ndn_name[ndn_idx + 1] == 253) {
				memcpy (&value16, &ndn_name[ndn_idx + 1], sizeof (uint16_t));
				seg_len = ntohs (value16);
				ndn_idx += 4;
			} else if (ndn_name[1] == 254) {
				memcpy (&value32, &ndn_name[ndn_idx + 1], sizeof (uint32_t));
				seg_len = (uint32_t) ntohl (value32);
				ndn_idx += 6;
			} else {
				seg_len = (uint32_t) ndn_name[ndn_idx + 1];
				ndn_idx += 2;
			}
			
			tlv_fld.type   = ftvn_nameseg;
			tlv_fld.length = htons (seg_len);
			
			memcpy (&cef_name[cef_idx], &tlv_fld, sizeof (struct tlv_hdr));
			memcpy (&cef_name[cef_idx + CefC_O_Value], &ndn_name[ndn_idx], seg_len);
			
			cef_idx += CefC_S_TLF + seg_len;
			ndn_idx += seg_len;
		} else {
			ndn_idx++;
		}
	}
	
	return (cef_idx);
}

/*--------------------------------------------------------------------------------------
	Converts the name from Cefore to NDN
----------------------------------------------------------------------------------------*/
static uint16_t								/* length of NDN Name 						*/
cef_plugin_ndn_c2n_name_convert (
	unsigned char* 		cef_name, 
	uint16_t 			cef_name_len, 
	unsigned char* 		ndn_name
) {
	
	uint16_t cef_idx = 0;
	uint16_t ndn_idx = 0;
	struct tlv_hdr* tlvp;
	
	uint16_t type;
	uint16_t length;
	
	while (cef_idx < cef_name_len) {
		tlvp = (struct tlv_hdr*)(&cef_name[cef_idx]);
		type   = ntohs (tlvp->type);
		length = ntohs (tlvp->length);
		
		if ((type != CefC_T_NAMESEGMENT) && (type != CefC_T_CHUNK)) {
			return (0);
		}
		
		ndn_name[ndn_idx] = 0x08;
		ndn_idx++;
		
		if (length < 253) {
			ndn_name[ndn_idx] = (unsigned char) length;
			ndn_idx++;
		} else {
			ndn_name[ndn_idx] = 0xfd;
			memcpy (&ndn_name[ndn_idx + 1], &tlvp->length, sizeof (uint16_t));
			ndn_idx += 3;
		}
		memcpy (&ndn_name[ndn_idx], &cef_name[cef_idx + CefC_S_TLF], length);
		ndn_idx += length;
		cef_idx += CefC_S_TLF + length;
	}
	
	return (ndn_idx);
}

/*--------------------------------------------------------------------------------------
	Seeks the top of the frame from the receive buffer
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cef_plugin_ndn_messege_head_seek (
	void
) {
	uint16_t move_len;
	unsigned char* wp;
	unsigned char* ep;
	unsigned char buff[CefC_Max_Length];
	uint16_t index = 0;
	static uint16_t short_step = 0;
	uint8_t pkt_type = 0;
	uint32_t value32;
	uint16_t value16;
	uint32_t pkt_len = 0;
	
	while (buff_len > 7) {
		pkt_type = recv_buff[index];
		
		if ((pkt_type != 0x05) && (pkt_type != 0x06) && (pkt_type != 0x64)) {
			wp = &recv_buff[index];
			ep = recv_buff + index + buff_len;
			move_len = 0;
			
			while (wp < ep) {
				if ((*wp != 0x05) && (*wp != 0x06) && (*wp != 0x64)) {
					wp++;
				} else {
					move_len = ep - wp;
					memcpy (buff, wp, move_len);
					memcpy (recv_buff, buff, move_len);
					buff_len -= wp - recv_buff;
					pkt_type = recv_buff[0];
					index = 0;
					
					break;
				}
			}
			if (move_len == 0) {
				buff_len = 0;
				return (-1);
			}
		}
		
		if (recv_buff[1] == 253) {
			memcpy (&value16, &recv_buff[2], sizeof (uint16_t));
			pkt_len = (uint32_t) ntohs (value16) + 4;
		} else if (recv_buff[1] == 254) {
			memcpy (&value32, &recv_buff[2], sizeof (uint32_t));
			pkt_len = (uint32_t) ntohl (value32) + 6;
		} else {
			pkt_len = (uint32_t) recv_buff[1] + 2;
		}
		
		if ((pkt_type != 0x05) && (pkt_type != 0x06) && (pkt_type != 0x64)) {
			buff_len--;
			index++;
			continue;
		}
		
		/* Obtains values of Header Length and Payload Length 	*/
		if (buff_len < pkt_len) {
			short_step++;
			if (short_step > 2) {
				short_step = 0;
				buff_len--;
				index++;
				continue;
			}
			return (-1);
		}
		
		if (index > 0) {
			memmove (recv_buff, recv_buff + index, buff_len);
		}
		short_step = 0;
		return ((int) pkt_len);
	}
	
	return (-1);
}

/*--------------------------------------------------------------------------------------
	Callback for post process
----------------------------------------------------------------------------------------*/
static void 
cef_plugin_ndn_fib_create (
	void 
) {
	char 	ws[1024];
	FILE*	fp = NULL;
	char 	buff[65600];	/* 65535 (max length of name) + 64 */
	char 	uri[CefC_Max_Length];
	char 	addr[64];
	char 	prot[64];
	int 	res;
	int 	faceid;
	unsigned char name[CefC_Max_Length];
	CefC_Ndn_Fib_Entry* entry;
	CefC_Ndn_Fib_Face* face;
	
	/* Opens FIB file of NDN 		*/
	cef_client_config_dir_get (ws);
	sprintf (ws, "%s/ndn.fib", ws);
	
	fp = fopen (ws, "r");
	if (fp == NULL) {
		fp = fopen (ws, "w");
		if (fp == NULL) {
			fprintf (stderr, "[cefore] cef_plugin_ndn_fib_create (ERROR: Write)\n");
			return;
		}
		fclose (fp);
		fp = fopen (ws, "r");
	}
	
	while (fgets (buff, 65600, fp) != NULL) {
		if (buff[0] == 0x23/* '#' */) {
			continue;
		}
		
		/* parse the read line 		*/
		res = cef_plugin_ndn_trim_line_string (buff, uri, prot, addr);
		if (res < 0) {
			continue;
		}
		
		/* lookup Face-ID */
		faceid = cef_plugin_ndn_lookup_faceid_from_addrstr (addr, "udp");
		if (faceid < 0) {
			continue;
		}
		
		/* translation the string uri to Name TLV */
		res = cef_frame_conversion_uri_to_name (uri, name);
		if ((res < 0) || (res > CefC_Max_Length)){
			continue;
		}
		
		/* search this name from FIB */
		entry = (CefC_Ndn_Fib_Entry*) cef_hash_tbl_item_get (ndn_fib, name, res);
		if (entry == NULL) {
			entry = (CefC_Ndn_Fib_Entry*) malloc (sizeof (CefC_Ndn_Fib_Entry));
			entry->key = (unsigned char*) malloc (sizeof (char) * res + 1);
			memcpy (entry->key, name, res);
			entry->klen = res;
			entry->faces.faceid = -1;
			entry->faces.next = NULL;
			
			cef_hash_tbl_item_set (ndn_fib, name, res, entry);
		}
		
		face = &(entry->faces);
		
		while (face->next) {
			face = face->next;
			if (face->faceid == faceid) {
				break;
			}
		}
		if (face->next == 0) {
			face->next = (CefC_Ndn_Fib_Face*) malloc (sizeof (CefC_Ndn_Fib_Face));
			face->next->faceid 	= faceid;
			face->next->next 	= NULL;
		}
	}
	
	fclose (fp);
	
	return;
}

/*--------------------------------------------------------------------------------------
	Searches FIB entry matching the specified Key
----------------------------------------------------------------------------------------*/
static CefC_Ndn_Fib_Entry* 					/* FIB entry 								*/
cef_plugin_ndn_fib_entry_search (
	unsigned char* name, 					/* Key of the FIB entry						*/
	uint16_t name_len						/* Length of Key							*/
) {
	CefC_Ndn_Fib_Entry* entry;
	unsigned char* msp;
	unsigned char* mep;
	uint16_t len = name_len;
	uint16_t length;
	
	while (len > 0) {
		entry = (CefC_Ndn_Fib_Entry*) cef_hash_tbl_item_get (ndn_fib, name, len);
		
		if (entry != NULL) {
			return (entry);
		}
		
		msp = name;
		mep = name + len - 1;
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
	
	return (NULL);
}

/*--------------------------------------------------------------------------------------
	Looks up and creates the Face from the specified string of destination address
----------------------------------------------------------------------------------------*/
static int									/* Face-ID									*/
cef_plugin_ndn_lookup_faceid_from_addrstr (
	const char* destination,				/* String of destination address 			*/
	const char* protocol					/* protoco (udp,tcp,local) 					*/
) {
	int faceid;
	int prot_index = CefC_Ndn_Face_Type_Invalid;
	
	if (strcmp (protocol, "udp") == 0) {
		prot_index = CefC_Ndn_Face_Type_Udp;
	}
	if (strcmp (protocol, "tcp") == 0) {
		prot_index = CefC_Ndn_Face_Type_Tcp;
	}
	
	faceid = cef_plugin_ndn_lookup_faceid (destination, prot_index);
	
	
	return (faceid);
}

/*--------------------------------------------------------------------------------------
	Looks up and creates the peer Face
----------------------------------------------------------------------------------------*/
static int									/* Peer Face-ID 							*/
cef_plugin_ndn_lookup_peer_faceid (
	struct addrinfo* sas, 					/* sockaddr_storage structure				*/
	socklen_t sas_len						/* length of sockaddr_storage				*/
) {
	char 	srvs[NI_MAXSERV];
	char 	name[NI_MAXHOST];
	int 	result;
	CefT_Ndn_Sock* entry;
	int 	faceid;
	
	/* Obtains the source node's information 	*/
	result = getnameinfo ((struct sockaddr*) sas, sas_len, name, sizeof (name),
				srvs, sizeof (srvs), NI_NUMERICHOST | NI_NUMERICSERV);
	
	if (result != 0) {
		return (-1);
	}
	
	/* Looks up the source node's information from the source table 	*/
	entry = (CefT_Ndn_Sock*) cef_hash_tbl_item_get (
									sock_tbl,
									(const unsigned char*) name, strlen (name));
	if (entry) {
		return (entry->faceid);
	}
	
	faceid = cef_plugin_ndn_lookup_faceid (name, CefC_Ndn_Face_Type_Udp);
	
	return (faceid);
}

/*--------------------------------------------------------------------------------------
	Looks up and creates the specified Face
----------------------------------------------------------------------------------------*/
static int									/* Face-ID									*/
cef_plugin_ndn_lookup_faceid (
	const char* destination, 				/* String of the destination address 		*/
	int protocol							/* protoco (udp,tcp,local) 					*/
) {
	struct addrinfo hints;
	struct addrinfo* res;
	struct addrinfo* cres;
	int err;
	char port_str[32];
	int sock;
	CefT_Ndn_Sock* entry;
	int faceid;
	int index;
	int flag;
	int val;
	fd_set readfds;
	struct timeval timeout;
	int ret;
	
	memset (&hints, 0, sizeof (hints));
	hints.ai_family = AF_UNSPEC;
	if (protocol != CefC_Ndn_Face_Type_Tcp) {
		hints.ai_socktype = SOCK_DGRAM;
	} else {
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_NUMERICSERV;
	}
	
	sprintf (port_str, "%d", ndn_port_num);
	
	if ((err = getaddrinfo (destination, port_str, &hints, &res)) != 0) {
		return (-1);
	}
	
	for (cres = res ; cres != NULL ; cres = res) {
		res = cres->ai_next;
		entry = (CefT_Ndn_Sock*) cef_hash_tbl_item_get (
				sock_tbl, (const unsigned char*) destination, strlen (destination));
		
		if (entry == NULL) {
			if (protocol != CefC_Ndn_Face_Type_Tcp) {
				sock = socket (cres->ai_family, cres->ai_socktype, 0);
			} else {
				sock = socket (cres->ai_family, cres->ai_socktype, cres->ai_protocol);
			}
			if (sock < 0) {
				cef_plugin_ndn_addrinfo_free (cres);
				continue;
			}
			if (protocol != CefC_Ndn_Face_Type_Udp) {
				flag = fcntl (sock, F_GETFL, 0);
				if (flag < 0) {
					close (sock);
					cef_plugin_ndn_addrinfo_free (cres);
					continue;
				}
				if (fcntl (sock, F_SETFL, flag | O_NONBLOCK) < 0) {
					close (sock);
					cef_plugin_ndn_addrinfo_free (cres);
					continue;
				}
				if (connect (sock, cres->ai_addr, cres->ai_addrlen) < 0) {
					/* NOP */;
				}
				val = 1;
				ioctl (sock, FIONBIO, &val);
				FD_ZERO (&readfds);
				FD_SET (sock, &readfds);
				timeout.tv_sec = 5;
				timeout.tv_usec = 0;
				usleep (5000);
				ret = select (sock + 1, &readfds, NULL, NULL, &timeout);
				if (ret == 0) {
					close (sock);
					cef_plugin_ndn_addrinfo_free (cres);
					continue;
				} else {
					if (FD_ISSET (sock, &readfds)) {
						ret = recv (sock, port_str, 0, 0);
						if (ret == -1) {
							close (sock);
							cef_plugin_ndn_addrinfo_free (cres);
							continue;
						} else {
							/* NOP */;
						}
					}
				}
			}
			faceid = cef_plugin_ndn_faceid_search ();
			if (faceid < 0) {
				close (sock);
				cef_plugin_ndn_addrinfo_free (cres);
				continue;
			}
			cres->ai_next = NULL;
			entry = cef_plugin_ndn_sock_entry_create (
							sock, cres->ai_addr, cres->ai_addrlen);
			entry->faceid = faceid;
			entry->protocol = (uint8_t) protocol;
			
			index = cef_hash_tbl_item_set (
				sock_tbl, (const unsigned char*)destination, strlen (destination), entry);
			
			if (index < 0) {
				close (sock);
				cef_plugin_ndn_sock_entry_destroy (entry);
				continue;
			}
			ndn_faces[faceid].index = index;
			ndn_faces[faceid].fd 	= entry->sock;
			
			if (m_stat_output_f) {
				fprintf (stderr, "Open Face ID:%d FD:%d [Peer=%s] : NDN\n" 
						, entry->faceid, ndn_faces[entry->faceid].fd, destination);
			}
		}
		freeaddrinfo (res);
		
		return (entry->faceid);
	}

	return (-1);
}

/*--------------------------------------------------------------------------------------
	Creates a new entry of Socket Table
----------------------------------------------------------------------------------------*/
static CefT_Ndn_Sock*							/* the created new entry				*/
cef_plugin_ndn_sock_entry_create (
	int sock, 									/* file descriptor to register			*/
	struct sockaddr* ai_addr,
	socklen_t ai_addrlen
) {
	CefT_Ndn_Sock* entry;
	
	entry = (CefT_Ndn_Sock*) malloc (sizeof (CefT_Ndn_Sock));
	entry->ai_addr = ai_addr;
	entry->ai_addrlen = ai_addrlen;
	entry->sock = sock;
	entry->faceid = -1;
	
	return (entry);
}

/*--------------------------------------------------------------------------------------
	Looks up Face-ID that is not used
----------------------------------------------------------------------------------------*/
static int										/* Face-ID that is not used				*/
cef_plugin_ndn_faceid_search (
	void
) {
	int i;
	
	for (i = assigned_faceid ; i < CefC_Ndn_Face_Max ; i++) {
		if (ndn_faces[i].fd != 0) {
			continue;
		}
		assigned_faceid = i + 1;
		return (i);
	}
	
	for (i = 0 ; i < assigned_faceid ; i++) {
		if (ndn_faces[i].fd != 0) {
			continue;
		}
		assigned_faceid = i + 1;
		return (i);
	}
	assigned_faceid = 0;
	
	return (-1);
}
/*--------------------------------------------------------------------------------------
	Destroy the specified entry of Socket Table
----------------------------------------------------------------------------------------*/
static void
cef_plugin_ndn_sock_entry_destroy (
	CefT_Ndn_Sock* entry						/* the entry to destroy					*/
) {
	if (entry->ai_addr) {
		free (entry->ai_addr);
	}
	free (entry);
}

/*--------------------------------------------------------------------------------------
	Deallocates the specified addrinfo
----------------------------------------------------------------------------------------*/
static void
cef_plugin_ndn_addrinfo_free (
	struct addrinfo* ai							/* addrinfo to free 					*/
) {
	if (ai) {
		free (ai);
	}
}

/*--------------------------------------------------------------------------------------
	Triming a line read from a file
----------------------------------------------------------------------------------------*/
static int
cef_plugin_ndn_trim_line_string (
	const char* p, 								/* target string for trimming 			*/
	char* name,									/* name string after trimming			*/
	char* prot,									/* protocol string after trimming		*/
	char* addr									/* address string after trimming		*/
) {
	int parame = CefC_Ndn_Fib_Param_Name;
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
			case CefC_Ndn_Fib_Param_Name: {
				*name = *p;
				name++;
				break;
			}
			case CefC_Ndn_Fib_Param_Prot: {
				*prot = *p;
				prot++;
				break;
			}
			case CefC_Ndn_Fib_Param_Addr: {
				*addr = *p;
				addr++;
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
	*addr = 0x00;
	*prot = 0x00;
	*name = 0x00;
	
	if (parame >= CefC_Ndn_Fib_Param_Num) {
		delm_f = -1;
	}
	
	return (delm_f);
}

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
 * cef_conpub.h
 */

#ifndef __CEF_CONPUB_HEADER__
#define __CEF_CONPUB_HEADER__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdint.h>
#include <sys/stat.h>

#include <cefore/cef_plugin.h>
#include <cefore/cef_rngque.h>
#include <cefore/cef_hash.h>
#include <cefore/cef_pit.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/


#define CefC_Cefnetd_Buff_Max			512000

/*------------------------------------------------------------------*/
/* Default cache status												*/
/*------------------------------------------------------------------*/
#define CefC_CnpbDefault_Tcp_Prot			9799	/* Port num between cefnetd and 	*/
													/* conpubd 							*/
#define CefC_CnpbDefault_Local_Sock_Id		"0"		/* Socket ID used by conpubd and 	*/
													/* cefnetd							*/
#define CefC_Cnpb_memory_Cache_Type			"memory"/* Plugin name (string) used		*/
													/* by conpubd						*/
#define CefC_Cnpb_filesystem_Cache_Type		"filesystem"
													/* Plugin name (string) used		*/
													/* by conpubd						*/
#define CefC_Cnpb_db_Cache_Type		"db"			/* Plugin name (string) used		*/
													/* by conpubd						*/
#define CefC_CnpbDefault_Purge_Interval		60		/* Interval (seconds) at which 		*/
													/* conpubd checks 					*/
													/* for expired content				*/
#define CefC_CnpbDefault_Cache_Default_Rct	600		/* RTC(seconds) to set for Cob 		*/
													/* to send							*/
#define CefC_CnpbDefault_Valid_Alg			"NONE"	/* Specify the Validation Algorithm	*/
													/* to be added to Content Object	*/
#define CefC_CnpbDefault_Contents_num		1024	/* Total content					*/
#define CefC_CnpbDefault_Contents_Capacity	4294967296
													/* Total content capacity 			*/
#define CefC_CnpbDefault_Block_Size			1024	/* Specify the maximum payload 		*/
													/* length (bytes) of Content Object	*/
#define CefC_CnpbDefault_Node_Path			"127.0.0.1"
#define CefC_CnpbDefault_Cefnetd_Port		CefC_Default_PortNum

/*------------------------------------------------------------------*/
/* Macros for conpub													*/
/*------------------------------------------------------------------*/
#define CefC_Conpub_File_Path_Length	1024		/* Max length of file path			*/
#define CefC_Conpub_Conf_Name			"conpubd.conf"
													/* conpubd Config file name			*/
#define CefC_Conpub_ContDef_Name		"conpubcont.def"
													/* conpubd contnts definition 		*/
													/* file name						*/
#define CefC_Conpub_Max_Table_Num		65535		/* Max size of table				*/
#define CefC_Conpub_Max_Table_Margin	10000		/* Margin size of table				*/
#define CefC_Conpub_Max_Send_Num		16
#define CefC_Conpub_Max_Wait_Response	1000		/* Wait time(msec)					*/
#define CefC_Default_Cache_Send_Rate	512			/* default send rate for mem cache	*/

#define CefC_Conpub_Cmd_MaxLen			1024
#define CefC_Conpub_Cmd_ConnOK			"CMD://ConpubdConnOK"

/*------------------------------------------------------------------*/
/* type of queue entry												*/
/*------------------------------------------------------------------*/
#define CefC_Cs_Tx_Elem_Type_Invalid	0x00		/* Type Invalid						*/
#define CefC_Cs_Tx_Elem_Type_Cob 		0x01		/* Type Content Object				*/

/*------------------------------------------------------------------*/
/* type of conpub message											*/
/*------------------------------------------------------------------*/
#define CefC_Conpub_Msg_Type_Invalid	0x00		/* Type Invalid						*/
#define CefC_Conpub_Msg_Type_Interest	0x01		/* Type Interest					*/
#define CefC_Conpub_Msg_Type_Cob		0x02		/* Type Content Object				*/
#define CefC_Conpub_Msg_Type_UpReq		0x03		/* Type Upload Request				*/
#define CefC_Conpub_Msg_Type_Increment	0x04		/* Type Increment Access Count		*/
#define CefC_Conpub_Msg_Type_Echo		0x05		/* Type Echo						*/
#define CefC_Conpub_Msg_Type_Status		0x06		/* Type Get Status					*/
#define CefC_Conpub_Msg_Type_Ccninfo	0x08		/* Type Ccninfo message			*/
#define CefC_Conpub_Msg_Type_Cefping	0x09		/* Type Cefping						*/
#define CefC_Conpub_Msg_Type_Bulk_Cob	0x0a		/* Type Content Object (Bulk)		*/
#define CefC_Conpub_Msg_Type_Kill		0x0b		/* Type Kill command				*/
#define CefC_Conpub_Msg_Type_RCap		0x0c		/* Type Retrieve cache capacity		*/
#define CefC_Conpub_Msg_Type_SCap		0x0d		/* Type Set cache capacity			*/
#define CefC_Conpub_Msg_Type_RCLT		0x0e		/* Type Retrieve Content Life Time	*/
#define CefC_Conpub_Msg_Type_SCLT		0x0f		/* Type Set Content Life Time		*/
#define CefC_Conpub_Msg_Type_Num		0x10

#define CefC_Conpub_Cob_Exist			0x00		/* Type Content is exist			*/
#define CefC_Conpub_Cob_NotExist		0x01		/* Type Content is not exist		*/

#define CefC_Conpub_Stat_Msg_Type_Invalid	0x00	/* Type Invalid						*/
#define CefC_Conpub_Stat_Msg_Type_Status	0x01	/* Type Status						*/
#define CefC_Conpub_Stat_Msg_Type_Cache		0x02	/* Type Cache Information			*/

#define CefC_Conpub_Msg_HeaderLen		4

/*------------------------------------------------------------------*/
/* type of CefC_Conpub_Msg_Type_Interest								*/
/*------------------------------------------------------------------*/
#define CefC_Conpub_Interest_Type_Invalid	0x00	/* Type Invalid						*/
#define CefC_Conpub_Interest_Type_Normal	0x01	/* Type Interest					*/
#define CefC_Conpub_Interest_Type_Num		0x02

#define CefC_Conpub_Interest_ChunkNum_NotExist	0	/* Chunk Num Flag off				*/
#define CefC_Conpub_Interest_ChunkNum_Exist		1	/* Chunk Num Flag on				*/

/*------------------------------------------------------------------*/
/* Macros for get conpubd status										*/
/*------------------------------------------------------------------*/
#define CefC_Conpub_Stat_MaxUri			128
#define CefC_Conpub_Stat_Mtu			65535

/*------------------------------------------------------------------*/
/* Macros for Massage Buffer										*/
/*------------------------------------------------------------------*/
#define CefC_Conpub_Buff_Max 			100000000


/*------------------------------------------------------------------*/
/* status type														*/
/*------------------------------------------------------------------*/
typedef enum {
	CefC_Conpub_Stat_Type_Invalid 		= 0x00,		/* Invalid 							*/
	CefC_Conpub_Stat_Type_Cache 		= 0x01,		/* Cache							*/
	CefC_Conpub_Stat_Type_Unavailable 	= 0xFF		/* Unavailable 						*/
} CefC_Conpub_Stat_Type;


/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/


typedef struct {
	/********** Content Store Information	***********/
	uint8_t			cache_type;					/* Cache Type							*/
												/* 0 : None								*/
												/* 1 : Excache							*/
	uint32_t		def_rct;					/* default RCT 							*/
	
	/********** Memory Cache Information	***********/
	uint32_t		cache_cap;					/* Cache Capacity						*/
	
	/********** TCP connection 		***********/
	uint16_t 		tcp_port_num;
	char 			peer_id_str[NI_MAXHOST];
	int 			tcp_sock;
	unsigned char	rcv_buff[CefC_Max_Length];
	uint16_t 		rcv_len;
	
	/********** Local connection 	***********/
	int 			local_sock;
	char 			local_sock_name[1024];
	
} CefT_CPCs_Stat;

typedef struct {

	/********** Content Object Information			***********/
	unsigned char	msg[CefC_Max_Msg_Size];		/* Receive message						*/
	uint16_t		msg_len;					/* Length of message 					*/
	uint32_t		chunk_num;					/* Chunk Num							*/
	uint64_t		expiry;
	
} CefT_CPCob_Entry;

/***** Insert to data of CefT_CPCs_Tx_Elem_Cob	*****/
typedef struct {

	CefT_CPCob_Entry		cob;				/* Content Object						*/
	int					faceid;					/* Interest arrived face id				*/

} CefT_CPCs_Tx_Elem_Cob;

/***** Content information	*****/
typedef struct {
	unsigned char	msg[CefC_Max_Msg_Size];
	uint16_t		msg_len;
	unsigned char	name[CefC_Max_Msg_Size];
	uint16_t		name_len;
	uint16_t		pay_len;
	uint32_t		chunk_num;
	uint64_t		cache_time;
	uint64_t		expiry;
} CefT_Conpubd_Content_Info;

/***** Tx Queue Element 	*****/
typedef struct {

	int 					type;				/* Type of the element 				*/
	void* 					data;				/* Information 						*/

} CefT_CPCs_Tx_Elem;

struct CefT_Conpub_Status_Hdr {
	
	uint16_t 		node_num;
	uint32_t 		con_num;
	
} __attribute__((__packed__));

struct CefT_Conpub_Status_Rep {
	
	uint64_t 		con_size;
	uint64_t 		access;
	uint64_t 		freshness;
	uint64_t 		elapsed_time;
	uint16_t 		name_len;
	
} __attribute__((__packed__));


#endif // __CEF_CONPUB_HEADER__


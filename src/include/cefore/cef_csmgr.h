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
 * cef_csmgr.h
 */

#ifndef __CEF_CSMGR_HEADER__
#define __CEF_CSMGR_HEADER__

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
/* Cefore cache mode												*/
/*------------------------------------------------------------------*/
#define CefC_Cache_Type_None			0			/* Mode None						*/
#define CefC_Cache_Type_Localcache		1			/* Mode Local cache					*/
#define CefC_Cache_Type_Excache			2			/* Mode Excache (csmgrd)			*/
#define CefC_Cache_Type_ExConpub		3			/* Mode Excache (conpubd)			*/
/*------------------------------------------------------------------*/
/* Default cache status												*/
/*------------------------------------------------------------------*/
#define CefC_Default_Cache_Type			0			/* Default None						*/
#define CefC_Default_Cache_Capacity		30000		/* Default 30000 entries			*/
#define CefC_Default_Int_Check_Cache	10000		/* Default 10 secs					*/
#define CefC_Default_Def_Rct			600000		/* Default 10 minits				*/
#define CefC_Default_Tcp_Prot			9799		/* port num between cefnetd and 	*/
													/* csmgrd 							*/
#define CefC_Default_Node_Path			"127.0.0.1"

/*------------------------------------------------------------------*/
/* Macros for csmgr													*/
/*------------------------------------------------------------------*/
#define CefC_Csmgr_File_Path_Length		1024		/* Max length of file path			*/
#define CefC_Conpubd_File_Path_Length	1024		/* Max length of file path			*/
#define CefC_Csmgrd_Conf_Name			"csmgrd.conf"
													/* csmrd Config file name			*/
#define CefC_Conpubd_Conf_Name			"conpubd.conf"
													/* conpubd Config file name			*/
#define CefC_Csmgr_Max_Table_Num		65535		/* Max size of table				*/
#define CefC_Csmgr_Max_Table_Margin		10000		/* Margin size of table				*/
#define CefC_Csmgr_Max_Send_Num			16
#if 0
#define CefC_Csmgr_Max_Wait_Response	2000		/* Wait time(msec)					*/
#else
#define CefC_Csmgr_Max_Wait_Response	5000		/* Wait time(msec)					*/
#endif
#define CefC_Default_Cache_Send_Rate	512			/* default send rate for mem cache	*/

#define CefC_Csmgr_Cmd_MaxLen			1024
#define CefC_Csmgr_Cmd_ConnOK			"CMD://CsmgrConnOK"

/*------------------------------------------------------------------*/
/* type of queue entry												*/
/*------------------------------------------------------------------*/
#define CefC_Cs_Tx_Elem_Type_Invalid	0x00		/* Type Invalid						*/
#define CefC_Cs_Tx_Elem_Type_Cob 		0x01		/* Type Content Object				*/

/*------------------------------------------------------------------*/
/* type of csmgr message											*/
/*------------------------------------------------------------------*/
#define CefC_Csmgr_Msg_Type_Invalid		0x00		/* Type Invalid						*/
#define CefC_Csmgr_Msg_Type_Interest	0x01		/* Type Interest					*/
#define CefC_Csmgr_Msg_Type_Cob			0x02		/* Type Content Object				*/
#define CefC_Csmgr_Msg_Type_UpReq		0x03		/* Type Upload Request				*/
#define CefC_Csmgr_Msg_Type_Increment	0x04		/* Type Increment Access Count		*/
#define CefC_Csmgr_Msg_Type_Echo		0x05		/* Type Echo						*/
#define CefC_Csmgr_Msg_Type_Status		0x06		/* Type Get Status					*/
#define CefC_Csmgr_Msg_Type_Ccninfo		0x08		/* Type Ccninfo message			*/
#define CefC_Csmgr_Msg_Type_Cefping		0x09		/* Type Cefping						*/
#define CefC_Csmgr_Msg_Type_Bulk_Cob	0x0a		/* Type Content Object (Bulk)		*/
#define CefC_Csmgr_Msg_Type_Kill		0x0b		/* Type Kill command				*/
#define CefC_Csmgr_Msg_Type_RCap		0x0c		/* Type Retrieve cache capacity		*/
#define CefC_Csmgr_Msg_Type_SCap		0x0d		/* Type Set cache capacity			*/
#define CefC_Csmgr_Msg_Type_RCLT		0x0e		/* Type Retrieve Content Life Time	*/
#define CefC_Csmgr_Msg_Type_SCLT		0x0f		/* Type Set Content Life Time		*/
#define CefC_Csmgr_Msg_Type_CnpbStatus	0x10		/* Type Get Conpub Status			*/
#define CefC_Csmgr_Msg_Type_CnpbRload	0x11		/* Type Reload Conpub Contents		*/
#define CefC_Csmgr_Msg_Type_RCCH		0x12		/* Type Retrieve cache chunk		*/
#define CefC_Csmgr_Msg_Type_SCDL		0x13		/* Type Delete cache				*/
#define CefC_Csmgr_Msg_Type_PreCcninfo	0x14		/* Type Prepare Ccninfo message		*/
#define CefC_Csmgr_Msg_Type_ContInfo	0x15		/* Type Get Contents Information	*/
#define CefC_Csmgr_Msg_Type_Num			0x16
//#define CefC_Csmgr_Msg_Type_Num			0x15

#define CefC_Csmgr_Cob_Exist			0x00		/* Type Content is exist			*/
#define CefC_Csmgr_Cob_NotExist			0x01		/* Type Content is not exist		*/

#define CefC_Csmgr_Stat_Msg_Type_Invalid	0x00	/* Type Invalid						*/
#define CefC_Csmgr_Stat_Msg_Type_Status		0x01	/* Type Status						*/
#define CefC_Csmgr_Stat_Msg_Type_Cache		0x02	/* Type Cache Information			*/

#define CefC_Csmgr_Msg_HeaderLen		4
#define CefC_Csmgr_User_Len				256

/*------------------------------------------------------------------*/
/* type of CefC_Csmgr_Msg_Type_Interest								*/
/*------------------------------------------------------------------*/
#define CefC_Csmgr_Interest_Type_Invalid	0x00	/* Type Invalid						*/
#define CefC_Csmgr_Interest_Type_Normal		0x01	/* Type Interest					*/
#define CefC_Csmgr_Interest_Type_Num		0x02

#define CefC_Csmgr_Interest_ChunkNum_NotExist	0	/* Chunk Num Flag off				*/
#define CefC_Csmgr_Interest_ChunkNum_Exist		1	/* Chunk Num Flag on				*/

/*------------------------------------------------------------------*/
/* Macros for get csmgr status										*/
/*------------------------------------------------------------------*/
#define CefC_Csmgr_Stat_MaxUri			128
#define CefC_Csmgr_Stat_Mtu				65535

/*------------------------------------------------------------------*/
/* Macros for csmgr status option									*/
/*------------------------------------------------------------------*/
#define CefC_Csmgr_Stat_Opt_None		0x00
#define CefC_Csmgr_Stat_Opt_Clear		0x01

/*------------------------------------------------------------------*/
/* Macros for Massage Buffer										*/
/*------------------------------------------------------------------*/
#define CefC_Csmgr_Buff_Max 			100000000


/*------------------------------------------------------------------*/
/* status type														*/
/*------------------------------------------------------------------*/
typedef enum {
	CefC_Csmgr_Stat_Type_Invalid 		= 0x00,		/* Invalid 							*/
	CefC_Csmgr_Stat_Type_Cache 			= 0x01,		/* Cache							*/
	CefC_Csmgr_Stat_Type_Unavailable 	= 0xFF		/* Unavailable 						*/
} CefC_Csmgr_Stat_Type;

/*------------------------------------------------------------------*/
/* Macros for get Conpub Status										*/
/*------------------------------------------------------------------*/
#define CefC_CnpbStatus_Name				0x0001
#define CefC_CnpbStatus_Path				0x0002
#define CefC_CnpbStatus_Date				0x0003
#define CefC_CnpbStatus_Expiry				0x0004
#define CefC_CnpbStatus_Interest			0x0005
//#define CefC_CnpbStatus_Hash				0x0006
#define CefC_CnpbStatus_Version				0x0006
#define CefC_CnpbStatus_ValidAlg			0x0007

/*------------------------------------------------------------------*/
/* Macros for compare version										*/
/*------------------------------------------------------------------*/
#define CefC_CV_Inconsistent				-1000
#define CefC_CV_Same						0
#define CefC_CV_Newest_1stArg				1
#define CefC_CV_Newest_2ndArg				-1


/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/

typedef struct {

	/********** Content Store Information	***********/
	uint8_t			cache_type;					/* CS mode								*/
												/* 0 : None								*/
												/* 1 : Local cache						*/
												/* 2 : Excache(csmgrd)					*/
												/* 3 : Excache(Conpubd)					*/
	uint32_t		def_rct;					/* default RCT 							*/
	
	/********** CSMGR_ACCESS **********/
	int				csmgr_access;				/* 0:ReadWrite 1:ReadOnly				*/
	/********** BUFFER_CHACHE_TIME **********/
	uint32_t		buffer_cache_time;			/* msec									*/
	
	/********** Memory Cache Information	***********/
	uint32_t		cache_cap;					/* Cache Capacity						*/
	
	/********** Content Object Table		***********/
	CefT_Hash_Handle	cob_table;				/* Content Object Table					*/

	/********** Tx Message Queue		***********/
	CefT_Mp_Handle		tx_cob_mp;				/* for CefT_Cs_Tx_Elem_Cob 				*/
	CefT_Mp_Handle 		tx_que_mp;				/* for CefT_Cs_Tx_Elem 					*/
	CefT_Rngque* 		tx_que;					/* TX ring buffer 						*/

	/********** CS memory pool 		***********/
	CefT_Mp_Handle	cs_cob_entry_mp;		/* for cob entry							*/
	
	/********** TCP connection 		***********/
	uint16_t 		tcp_port_num;
	char 			peer_id_str[NI_MAXHOST];
	int 			tcp_sock;
	unsigned char	rcv_buff[CefC_Max_Length];
	uint16_t 		rcv_len;
	
	/********** Local connection 	***********/
	int 			local_sock;
//	char 			local_sock_name[1024];
	char 			local_sock_name[2048];

	/********** local Cache Information ***********/
	uint32_t		local_cache_capacity;			/* Cache Capacity						*/
	uint32_t		local_cache_interval;			/* Expired check cycle (sec)			*/
	int 			pipe_fd[2];						/* socket of cefnetd->Local cache		*/
													/*  0: for cefnetd						*/
													/*  1: for Local cache				*/
	int				to_csmgrd_pipe_fd[2];

	
} CefT_Cs_Stat;

typedef struct {

	/********** Content Object Information			***********/
//20210824	unsigned char	msg[CefC_Max_Msg_Size];		/* Receive message						*/
/*0.8.3c*/	unsigned char*	msg;			/* Receive message						*/
	uint16_t		msg_len;				/* Length of message 					*/
	uint32_t		chunk_num;				/* Chunk Num							*/
	uint64_t		expiry;
	uint64_t		cache_time;
	unsigned char*	version;				/* Version								*/
	uint16_t		ver_len;				/* Length of Version					*/
} CefT_Cob_Entry;

/***** Insert to data of CefT_Cs_Tx_Elem_Cob	*****/
typedef struct {

	CefT_Cob_Entry		cob;					/* Content Object						*/
	int					faceid;					/* Interest arrived face id				*/

} CefT_Cs_Tx_Elem_Cob;

/***** Content information	*****/
typedef struct {
	unsigned char	msg[CefC_Max_Msg_Size];
	uint16_t		msg_len;
	unsigned char	name[CefC_Max_Msg_Size];
	uint16_t		name_len;
	uint16_t		pay_len;
	uint32_t		chnk_num;
	uint64_t		cache_time;
	uint64_t		expiry;
} CefT_Csmgrd_Content_Info; 

/*------------------------------------------------------------------*/
/* for cache information field										*/
/*------------------------------------------------------------------*/

/***** Tx Queue Element 	*****/
typedef struct {

	int 					type;					/* Type of the element 				*/
	void* 					data;					/* Information 						*/

} CefT_Cs_Tx_Elem;

struct CefT_Csmgr_Status_Hdr {
	
	uint16_t 		node_num;
	uint32_t 		con_num;
	
} __attribute__((__packed__));

struct CefT_Csmgr_Status_Rep {
	
	uint64_t 		con_size;
	uint64_t 		access;
	uint64_t 		req_count;
	uint64_t 		freshness;
	uint64_t 		elapsed_time;
	uint16_t 		name_len;
	uint16_t 		ver_len;
	
} __attribute__((__packed__));

struct CefT_Csmgr_CnpbStatus_TL {
	uint16_t 	type;
	uint16_t 	length;
} __attribute__((__packed__));


/****************************************************************************************
 Function Declarations
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Create Content Store Manager Status
----------------------------------------------------------------------------------------*/
CefT_Cs_Stat*						/* The return value is null if an error occurs		*/
cef_csmgr_stat_create (
	uint8_t cs_mode
);
/*--------------------------------------------------------------------------------------
	Destroy Content Store Manager Status
----------------------------------------------------------------------------------------*/
void
cef_csmgr_stat_destroy (
	CefT_Cs_Stat** cs_stat					/* Content Store Status						*/
);
/*--------------------------------------------------------------------------------------
	Reads the config file
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_csmgr_config_read (
	CefT_Cs_Stat* cs_stat					/* Content Store Status						*/
);

/*--------------------------------------------------------------------------------------
	Reads the config file for conpub
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_csmgr_config_read_for_conpub (
	CefT_Cs_Stat* cs_stat					/* Content Store Status						*/
);
/*--------------------------------------------------------------------------------------
	Search and replies the Cob from the temporary cache
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_csmgr_cache_lookup (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	int faceid,								/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	CefT_Parsed_Message* pm,				/* Parsed CEFORE message					*/
	CefT_Parsed_Opheader* poh,				/* Parsed Option Header						*/
	CefT_Pit_Entry* pe,						/* PIT entry								*/
	unsigned char** cob
);

/*--------------------------------------------------------------------------------------
	Check reply flag. Don't forward interest if reply flag is on.
----------------------------------------------------------------------------------------*/
int									/* The return value is 0 if an error occurs			*/
cef_csmgr_rep_f_check (
	CefT_Pit_Entry* pe, 					/* PIT entry								*/
	int faceid								/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
);
/*--------------------------------------------------------------------------------------
	Insert the Cob into the temporary cache
----------------------------------------------------------------------------------------*/
void 
cef_csmgr_cache_insert (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t msg_len,						/* length of received message				*/
	CefT_Parsed_Message* pm,				/* Parsed CEFORE message					*/
	CefT_Parsed_Opheader* poh				/* Parsed Option Header						*/
);
/*--------------------------------------------------------------------------------------
	Send message from csmgr to cefnetd
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_csmgr_send_msg (
	int fd,									/* socket fd								*/
	unsigned char* msg,						/* send message								*/
	uint16_t msg_len						/* message length							*/
);
/*--------------------------------------------------------------------------------------
	Put Content Object to excache
----------------------------------------------------------------------------------------*/
void
cef_csmgr_excache_item_put (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t msg_len,						/* length of received message				*/
	int faceid,								/* Arrived face id							*/
	CefT_Parsed_Message* pm,				/* Parsed CEFORE message					*/
	CefT_Parsed_Opheader* poh				/* Parsed Option header						*/
);
void
cef_csmgr_excache_item_push (
	CefT_Cs_Stat* cs_stat					/* Content Store status						*/
);
/*--------------------------------------------------------------------------------------
	Search and queue entry
----------------------------------------------------------------------------------------*/
void 
cef_csmgr_excache_lookup (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	int faceid,								/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	CefT_Parsed_Message* pm,				/* Parsed CEFORE message					*/
	CefT_Parsed_Opheader* poh,				/* Parsed Option Header						*/
	CefT_Pit_Entry* pe						/* PIT entry								*/
);
/*--------------------------------------------------------------------------------------
	Get frame from received message
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
csmgr_frame_get (
	unsigned char* buff,					/* receive message							*/
	int buff_len,							/* message length							*/
	unsigned char* msg,						/* frame of csmgr message					*/
	int* frame_size,						/* frame length								*/
	uint8_t* type							/* message type								*/
);
/*--------------------------------------------------------------------------------------
	Forwarding content object
----------------------------------------------------------------------------------------*/
int
csmgr_cob_forward (
	int faceid,									/* Face-ID to reply to the origin of 	*/
	unsigned char* msg,							/* Receive message						*/
	uint16_t msg_len,							/* Length of message					*/
	uint32_t chnk_num							/* Chunk Number of content				*/
);
/*--------------------------------------------------------------------------------------
	parse cob name
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_csmgr_cob_name_parse (
	unsigned char* buff,						/* receive message						*/
	int buff_len,								/* receive message length				*/
	uint16_t* index,							/* index of message						*/
	unsigned char* name,						/* cob name								*/
	uint16_t* name_len							/* cob name length						*/
);
/*--------------------------------------------------------------------------------------
	print hex dump
----------------------------------------------------------------------------------------*/
void
cef_csmgr_hex_print (
	unsigned char* text,					/* Text										*/
	int text_len							/* Text length								*/
);
/*--------------------------------------------------------------------------------------
	close socket
----------------------------------------------------------------------------------------*/
void
csmgr_sock_close (
	CefT_Cs_Stat* cs_stat					/* Content Store status						*/
);
/*--------------------------------------------------------------------------------------
	Change str to value
----------------------------------------------------------------------------------------*/
int64_t								/* The return value is negative if an error occurs	*/
cef_csmgr_config_get_value (
	char* option,							/* csmgr option								*/
	char* value								/* String									*/
);
/*--------------------------------------------------------------------------------------
	Incoming cefping message
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_csmgr_excache_item_check (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	unsigned char* name,					/* Content URI								*/
	uint16_t name_len						/* Length of Content URI					*/
);
/*--------------------------------------------------------------------------------------
	Incoming pre-Ccninfo message
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_csmgr_excache_item_check_for_ccninfo (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	unsigned char* name,					/* Content URI								*/
	uint16_t name_len						/* Length of Content URI					*/
);
/*--------------------------------------------------------------------------------------
	Incoming Ccninfo message
----------------------------------------------------------------------------------------*/
int											/* length of Cache Information				*/
cef_csmgr_excache_info_get (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	unsigned char* name,					/* Content URI								*/
	uint16_t name_len,						/* Length of Content URI					*/
	unsigned char* info,					/* cache information from csmgr 			*/
	uint16_t ccninfo_flag					/* Ccninfo Trace Flag						*/
);
/*--------------------------------------------------------------------------------------
	Incoming Ccninfo message for cefnetd local cache
----------------------------------------------------------------------------------------*/
int											/* length of Cache Information				*/
cef_csmgr_locache_info_get (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	unsigned char* name,					/* Content URI								*/
	uint16_t name_len,						/* Length of Content URI					*/
	unsigned char* info,					/* cache information from csmgr 			*/
	uint16_t ccninfo_flag					/* Ccninfo Trace Flag 						*/
);
/*--------------------------------------------------------------------------------------
	Connect csmgr with TCP socket
----------------------------------------------------------------------------------------*/
int											/* created socket							*/
cef_csmgr_connect_tcp_to_csmgr (
	const char* dest, 
	const char* port
);
/*--------------------------------------------------------------------------------------
	Create the work buffer for csmgr
----------------------------------------------------------------------------------------*/
unsigned char* 
cef_csmgr_buffer_init (
	void 
);
/*--------------------------------------------------------------------------------------
	Destroy the work buffer for csmgr
----------------------------------------------------------------------------------------*/
void 
cef_csmgr_buffer_destroy (
	void 
);


#ifdef CefC_Ccore
/*--------------------------------------------------------------------------------------
	Retrieve cache capacity
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_csmgr_capacity_retrieve (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	uint64_t* cap							/* Capacity									*/
);
/*--------------------------------------------------------------------------------------
	Update cache capacity
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_csmgr_capacity_update (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	uint64_t cap							/* Capacity									*/
);
/*--------------------------------------------------------------------------------------
	Retrieve content Lifetime
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_csmgr_con_lifetime_retrieve (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	char* name,								/* Content name								*/
	uint16_t name_len,						/* Name length								*/
	uint64_t* lifetime						/* Lifetime									*/
);
/*--------------------------------------------------------------------------------------
	Set content Lifetime
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_csmgr_con_lifetime_set (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	char* name,								/* Content name								*/
	uint16_t name_len,						/* Name length								*/
	uint64_t lifetime						/* Lifetime									*/
);
/*--------------------------------------------------------------------------------------
	Retrieve Cache Chunk
----------------------------------------------------------------------------------------*/
int
cef_csmgr_con_chunk_retrieve (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	char* name,								/* Content name								*/
	uint16_t name_len,						/* Name length								*/
	char* range,							/* Cache Range								*/
	uint16_t range_len,						/* Range length								*/
	char* info								/* cache information						*/
);
/*--------------------------------------------------------------------------------------
	Delete Cache Chunk
----------------------------------------------------------------------------------------*/
int
cef_csmgr_con_chunk_delete (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	char* name,								/* Content name								*/
	uint16_t name_len,						/* Name length								*/
	char* range,							/* Cache Range								*/
	uint16_t range_len						/* Range length								*/
);
#endif // CefC_Ccore
#ifdef CefC_Dtc
/*--------------------------------------------------------------------------------------
	Create Content Store Manager Status
----------------------------------------------------------------------------------------*/
CefT_Cs_Stat*						/* The return value is null if an error occurs		*/
cef_csmgr_dtc_stat_create (
	void
);
/*--------------------------------------------------------------------------------------
	Destroy Content Store Status
----------------------------------------------------------------------------------------*/
void
cef_csmgr_dtc_stat_destroy (
	CefT_Cs_Stat** cs_stat					/* Content Store Status						*/
);
/*--------------------------------------------------------------------------------------
	Puts Content Object to Cefore-DTC temp cache
----------------------------------------------------------------------------------------*/
void
cef_csmgr_dtc_item_put (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t msg_len,						/* length of received message				*/
	CefT_Parsed_Message* pm,				/* Parsed CEFORE message					*/
	CefT_Parsed_Opheader* poh				/* Parsed Option header						*/
);
#endif // CefC_Dtc


void *
cef_csmgr_send_to_csmgrd_thread (
	void *p
);

/*--------------------------------------------------------------------------------------
	Incoming ContInfo Check Request message
----------------------------------------------------------------------------------------*/
int
cef_csmgr_content_info_get (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	char* name,								/* Content name								*/
	uint16_t name_len,						/* Name length								*/
	char* range,							/* Cache Range								*/
	uint16_t range_len,						/* Range length								*/
	char** info
);

/*--------------------------------------------------------------------------------------
	Compare ver1 and ver2
----------------------------------------------------------------------------------------*/
int
cef_csmgr_cache_version_compare (
	unsigned char* ver1,
	uint16_t vlen1,
	unsigned char* ver2,
	uint16_t vlen2
);

#endif // __CEF_CSMGR_HEADER__

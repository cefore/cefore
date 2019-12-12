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
 * cef_fib.c
 */

#define __CEF_FIB_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>

#include <cefore/cef_frame.h>
#include <cefore/cef_fib.h>
#include <cefore/cef_face.h>
#include <cefore/cef_log.h>
#include <cefore/cef_client.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

#define CefC_Fib_Param_Num		3
#define CefC_Fib_Param_Name		0
#define CefC_Fib_Param_Prot		1
#define CefC_Fib_Param_Addr		2

#define CefC_Fib_Default_Len	4

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/
/****** Entry of Socket Table 			*****/
typedef struct {
	struct addrinfo* ai;						/* addrinfo of this entry 				*/
	int 	sock;								/* File descriptor 						*/
	int 	faceid;								/* Assigned Face-ID 					*/
} CefT_Sock;

/****************************************************************************************
 State Variables
 ****************************************************************************************/
static CefT_Fib_Entry* default_entry = NULL;
static char prot_str[3][16] = {"invalid", "tcp", "udp"};

#ifdef CefC_Debug
static char 	fib_dbg_msg[2048];
#endif // CefC_Debug

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Reads the FIB configuration file
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cef_fib_config_file_read (
	CefT_Hash_Handle fib					/* FIB										*/
);
static int
cef_fib_trim_line_string (
	const char* p, 								/* target string for trimming 			*/
	char* name,									/* name string after trimming			*/
	char* prot,									/* protocol string after trimming		*/
	char* addr									/* address string after trimming		*/
);
static CefT_Fib_Entry*
cef_fib_entry_create (
	const unsigned char* name,					/* name for hash key					*/
	unsigned int name_len
);
static void
cef_fib_set_faceid_to_entry (
	CefT_Fib_Entry* entry,
	int faceid
);
static int
cef_fib_route_add (
	CefT_Hash_Handle fib,					/* FIB										*/
	uint8_t prot,							/* Protocol									*/
	char* host,								/* Host Address								*/
	char* uri								/* URI										*/
);
/*--------------------------------------------------------------------------------------
	Delete route in FIB
----------------------------------------------------------------------------------------*/
static int
cef_fib_route_del (
	CefT_Hash_Handle fib,					/* FIB										*/
	uint8_t prot,							/* Protocol									*/
	char* host,								/* Host Address								*/
	char* uri								/* URI										*/
);
static void
cef_fib_remove_faceid_from_entry (
	CefT_Fib_Entry* entry,
	int faceid
);

/****************************************************************************************
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Initialize FIB module
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cef_fib_init (
	CefT_Hash_Handle fib					/* FIB										*/
){
	/* Reads the FIB configuration file 	*/
	cef_fib_config_file_read (fib);
	return (0);
}
/*--------------------------------------------------------------------------------------
	Searches FIB entry matching the specified Key
----------------------------------------------------------------------------------------*/
CefT_Fib_Entry* 							/* FIB entry 								*/
cef_fib_entry_search (
	CefT_Hash_Handle fib,					/* FIB										*/
	unsigned char* name, 					/* Key of the FIB entry						*/
	uint16_t name_len						/* Length of Key							*/
) {
	CefT_Fib_Entry* entry;
	unsigned char* msp;
	unsigned char* mep;
	uint16_t len = name_len;
	uint16_t length;

	while (len > 0) {
		entry = (CefT_Fib_Entry*) cef_hash_tbl_item_get (fib, name, len);

		if (entry != NULL) {
#ifdef CefC_Debug
			{
				int dbg_x;
				
				sprintf (fib_dbg_msg, "[fib] matched to the entry [");
				for (dbg_x = 0 ; dbg_x < entry->klen ; dbg_x++) {
					sprintf (fib_dbg_msg, "%s %02X", fib_dbg_msg, entry->key[dbg_x]);
				}
				cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", fib_dbg_msg);
			}
#endif // CefC_Debug
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

	return (default_entry);
}
/*--------------------------------------------------------------------------------------
	Obtains Face-ID(s) to forward the Interest matching the specified FIB entry
----------------------------------------------------------------------------------------*/
int 										/* the number of Face-ID to forward			*/
cef_fib_forward_faceid_get (
	CefT_Fib_Entry* entry, 					/* FIB entry								*/
	uint16_t faceids[]						/* set Face-ID to forward the Interest		*/
) {
	int i = 0;
	CefT_Fib_Face* face = &(entry->faces);

	while (face->next) {
		face = face->next;
		faceids[i] = face->faceid;
		i++;
	}
#ifdef CefC_Debug
	{
		int dbg_x;
		
		for (dbg_x = 0 ; dbg_x < i ; dbg_x++) {
			sprintf (fib_dbg_msg, "%s %d", fib_dbg_msg, faceids[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s\n", fib_dbg_msg);
	}
#endif // CefC_Debug
	return (i);
}
/*--------------------------------------------------------------------------------------
	Obtains Face-ID(s) to forward the Interest matching the specified FIB entry
----------------------------------------------------------------------------------------*/
int 										/* the number of Face-ID to forward			*/
cef_fib_forward_faceid_select (
	CefT_Fib_Entry* entry, 					/* FIB entry								*/
	uint16_t incoming_faceid, 				/* FaceID at which the Interest arived 		*/
	uint16_t faceids[]						/* set Face-ID to forward the Interest		*/
) {
	int i = 0;
	CefT_Fib_Face* face = &(entry->faces);
	int incoming_face_type;
	int face_type;
	
	incoming_face_type = cef_face_type_get (incoming_faceid);
	
	while (face->next) {
		face = face->next;
		face_type = cef_face_type_get (face->faceid);
		if (incoming_face_type == face_type) {
			faceids[i] = face->faceid;
			i++;
		}
	}
	
	if (i == 0) {
		face = &(entry->faces);
		while (face->next) {
			face = face->next;
			faceids[i] = face->faceid;
			i++;
		}
	}
#ifdef CefC_Debug
	{
		int dbg_x;
		
		sprintf (fib_dbg_msg, "[fib] Select Faces:");
		
		for (dbg_x = 0 ; dbg_x < i ; dbg_x++) {
			sprintf (fib_dbg_msg, "%s %d", fib_dbg_msg, faceids[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s\n", fib_dbg_msg);
	}
#endif // CefC_Debug
	
	return (i);
}
/*--------------------------------------------------------------------------------------
	Removes the specified Faceid from the specified FIB entry
----------------------------------------------------------------------------------------*/
int  										/* the number of Face-ID to forward			*/
cef_fib_faceid_remove (
	CefT_Hash_Handle fib,					/* FIB										*/
	CefT_Fib_Entry* entry, 					/* FIB entry								*/
	uint16_t faceid							/* set Face-ID to forward the Interest		*/
) {
	CefT_Fib_Face* face = &(entry->faces);
	CefT_Fib_Face* prev = face;
	int remove_f = 0;
#ifdef CefC_Debug
	{
		int dbg_x;
		
		sprintf (fib_dbg_msg, "[fib] Remove Face#%d from [", faceid);
		
		for (dbg_x = 0 ; dbg_x < entry->klen ; dbg_x++) {
			sprintf (fib_dbg_msg, "%s %02X", fib_dbg_msg, entry->key[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", fib_dbg_msg);
	}
#endif // CefC_Debug
	
	while (face->next) {
		face = face->next;
		if (face->faceid == faceid) {
			prev->next = face->next;
			free (face);
			remove_f = 1;
			break;
		}
		prev = face;
	}
	
	/* check fib entry */
	if (entry->faces.next == NULL) {
		entry = (CefT_Fib_Entry*) cef_hash_tbl_item_remove (fib, entry->key, entry->klen);
		if (entry->klen == CefC_Fib_Default_Len) {
			default_entry = NULL;
		}
		free (entry->key);
		free (entry);
		entry = NULL;
	}
	
	return (remove_f);
}
/*--------------------------------------------------------------------------------------
	Inserts the specified Faceid to the specified FIB entry
----------------------------------------------------------------------------------------*/
int 										/* if successful, more than 0				*/
cef_fib_faceid_insert (
	CefT_Fib_Entry* entry, 					/* FIB entry								*/
	uint16_t faceid							/* set Face-ID to forward the Interest		*/
) {
	CefT_Fib_Face* face = &(entry->faces);
	
#ifdef CefC_Debug
	{
		int dbg_x;
		
		sprintf (fib_dbg_msg, "[fib] Insert Face#%d to [", faceid);
		
		for (dbg_x = 0 ; dbg_x < entry->klen ; dbg_x++) {
			sprintf (fib_dbg_msg, "%s %02X", fib_dbg_msg, entry->key[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", fib_dbg_msg);
	}
#endif // CefC_Debug
	
	while (face->next) {
		face = face->next;
		if (face->faceid == faceid) {
			return (0);
		}
	}
	
	face->next = (CefT_Fib_Face*) malloc (sizeof (CefT_Fib_Face));
	face->next->faceid = faceid;
	face->next->next = NULL;

	return (1);
}
/*--------------------------------------------------------------------------------------
	Lookups FIB entry exact-matching the specified Key
----------------------------------------------------------------------------------------*/
CefT_Fib_Entry* 							/* FIB entry 								*/
cef_fib_entry_lookup (
	CefT_Hash_Handle fib,					/* FIB										*/
	unsigned char* name, 					/* Key of the FIB entry						*/
	uint16_t name_len						/* Length of Key							*/
) {
	CefT_Fib_Entry* entry;
	
	entry = (CefT_Fib_Entry*) cef_hash_tbl_item_get (fib, name, name_len);
	
	if (entry == NULL) {
		entry = cef_fib_entry_create (name, name_len);
		cef_hash_tbl_item_set (fib, name, name_len, entry);
		
		if (name_len == CefC_Fib_Default_Len) {
			default_entry = entry;
		}
	}
	
	return (entry);
}
/*--------------------------------------------------------------------------------------
	Clean FaceID from FIB
----------------------------------------------------------------------------------------*/
void
cef_fib_faceid_cleanup (
	CefT_Hash_Handle fib,					/* FIB										*/
	uint16_t faceid
) {
	CefT_Fib_Entry* entry;
	CefT_Fib_Entry* work;
	uint32_t index = 0;
	CefT_Fib_Face* face;
	CefT_Fib_Face* prev;
	
	cef_log_write (CefC_Log_Info, "Remove Face#%d from FIB\n", faceid);
	
	do {
		entry = (CefT_Fib_Entry*) cef_hash_tbl_item_check_from_index (fib, &index);
		
		if (entry) {
			face = &(entry->faces);
			prev = face;
			
			while (face->next) {
				face = face->next;
				if (face->faceid == faceid) {
					prev->next = face->next;
					free (face);
					break;
				}
				prev = face;
			}
			
			if (entry->faces.next == NULL) {
				work = (CefT_Fib_Entry*) cef_hash_tbl_item_remove_from_index (fib, index);
				
				if (work->klen == CefC_Fib_Default_Len) {
					default_entry = NULL;
				}
				free (work->key);
				free (work);
			}
		}
		index++;
	} while (entry);
	
	return;
}
/*--------------------------------------------------------------------------------------
	Reads the FIB configuration file
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
cef_fib_config_file_read (
	CefT_Hash_Handle fib					/* FIB										*/
) {
	char 	ws[1024];
	FILE*	fp = NULL;
	char 	buff[65600];	/* 65535(max length of name) + 64 */
	char 	uri[CefC_Max_Length];
	unsigned char name[CefC_Max_Length];
	char 	addr[64];
	char 	prot[64];
	int 	res;
	int 	faceid;
	CefT_Fib_Entry* entry;

#ifndef CefC_Android
	cef_client_config_dir_get (ws);
#else // CefC_Android
	/* Android local cache storage is data/data/package_name/	*/
	sprintf (ws, "data/data/org.app.cefore/.cefore/cefnetd.fib");
#endif // CefC_Android
	
	sprintf (ws, "%s/cefnetd.fib", ws);
	
	fp = fopen (ws, "r");
	if (fp == NULL) {
		fp = fopen (ws, "w");
		if (fp == NULL) {
			cef_log_write (CefC_Log_Error, "Failed to open the FIB File (%s)\n", ws);
			return (-1);
		}
		fclose (fp);
		fp = fopen (ws, "r");
	}

	while (fgets (buff, 65600, fp) != NULL) {
		buff[2048] = 0;

		if (buff[0] == 0x23/* '#' */) {
			continue;
		}

		/* parse the read line 		*/
		res = cef_fib_trim_line_string (buff, uri, prot, addr);
		if (res < 0) {
			cef_log_write (CefC_Log_Warn, "[cefnetd.fib] Invalid line:%s\n", buff);
			continue;
		}

		/* lookup Face-ID */
		faceid = cef_face_lookup_faceid_from_addrstr (addr, prot);
		if (faceid < 0) {
			cef_log_write (CefC_Log_Warn, "[cefnetd.fib] Failed to create Face\n");
			continue;
		}

		/* translation the string uri to Name TLV */
		res = cef_frame_conversion_uri_to_name (uri, name);
		if ((res < 0) || (res > CefC_Max_Length)){
			cef_log_write (CefC_Log_Warn, "[cefnetd.fib] Invalid URI:%s\n", uri);
			continue;
		}

		/* search this name from FIB */
		entry = (CefT_Fib_Entry*) cef_hash_tbl_item_get (fib, name, res);
		if (entry == NULL) {
			entry = cef_fib_entry_create (name, res);
			cef_hash_tbl_item_set (fib, name, res, entry);
		}
		cef_log_write (CefC_Log_Info, 
			"Creation the FIB entry: URI=%s, Prot=%s, Next=%s, Face=%d\n", 
			uri, prot, addr, faceid);
		
		cef_fib_set_faceid_to_entry (entry, faceid);
		
		if (res == CefC_Fib_Default_Len) {
			default_entry = entry;
		}
	}

	fclose (fp);

	return (1);
}

/*--------------------------------------------------------------------------------------
	Remove a FIB entory from FIB
----------------------------------------------------------------------------------------*/
int
cef_fib_entry_destroy (
	CefT_Hash_Handle fib,					/* FIB										*/
	unsigned char* name, 					/* Key of the FIB entry						*/
	uint16_t name_len						/* Length of Key							*/
) {
	CefT_Fib_Entry* entry;
	CefT_Fib_Face* face;
	CefT_Fib_Face* work;
	
	entry = (CefT_Fib_Entry*) cef_hash_tbl_item_remove (fib, name, name_len);
	
	if (entry == NULL) {
		return (0);
	}
	
	face = entry->faces.next;
	
	while (face) {
		work = face;
		face = work->next;
		free (work);
	}
	
	free (entry->key);
	free (entry);
	
	return (1);
}

static void
cef_fib_set_faceid_to_entry (
	CefT_Fib_Entry* entry,
	int faceid
) {
	CefT_Fib_Face* face = &(entry->faces);

	while (face->next) {
		face = face->next;
		if (face->faceid == faceid) {
			return;
		}
	}

	face->next = (CefT_Fib_Face*) malloc (sizeof (CefT_Fib_Face));
	face->next->faceid = faceid;
	face->next->next = NULL;

	return;
}

static void
cef_fib_remove_faceid_from_entry (
	CefT_Fib_Entry* entry,
	int faceid
) {
	CefT_Fib_Face* face = &(entry->faces);
	CefT_Fib_Face* prev = face;
	
	while (face->next) {
		face = face->next;
		if (face->faceid == faceid) {
			prev->next = face->next;
			free (face);
			return;
		}
		prev = face;
	}

	return;
}

static CefT_Fib_Entry*
cef_fib_entry_create (
	const unsigned char* name,					/* name for hash key					*/
	unsigned int name_len
) {
	CefT_Fib_Entry* entry;

	entry = (CefT_Fib_Entry*) malloc (sizeof (CefT_Fib_Entry));
	entry->key = (unsigned char*) malloc (sizeof (char) * name_len + 1);
	memcpy (entry->key, name, name_len);
	entry->klen = name_len;
	entry->faces.faceid = -1;
	entry->faces.next = NULL;

	return (entry);
}

static int
cef_fib_trim_line_string (
	const char* p, 								/* target string for trimming 			*/
	char* name,									/* name string after trimming			*/
	char* prot,									/* protocol string after trimming		*/
	char* addr									/* address string after trimming		*/
) {
	int parame = CefC_Fib_Param_Name;
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
			case CefC_Fib_Param_Name: {
				*name = *p;
				name++;
				break;
			}
			case CefC_Fib_Param_Prot: {
				*prot = *p;
				prot++;
				break;
			}
			case CefC_Fib_Param_Addr: {
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

	if (parame >= CefC_Fib_Param_Num) {
		delm_f = -1;
	}

	return (delm_f);
}

/*--------------------------------------------------------------------------------------
	Receive the FIB route message
----------------------------------------------------------------------------------------*/
void
cef_fib_route_msg_read (
	CefT_Hash_Handle fib,					/* FIB										*/
	unsigned char* msg, 					/* the received message(s)					*/
	int msg_size							/* size of received message(s)				*/
) {
	uint8_t op;
	uint8_t prot;
	uint8_t host_len;
	char host[64] = {0};
	int index = 0;
	char uri[CefC_Max_Length];
	int uri_len;

	/* get operation */
	if ((msg_size - index) < sizeof (op)) {
		/* message is too short */
		return;
	}
	op = msg[index];
	index += sizeof (op);

	/* get protocol */
	if ((msg_size - index) < sizeof (prot)) {
		/* message is too short */
		return;
	}
	prot = msg[index];
	index += sizeof (prot);
	
	/* get host */
	if ((msg_size - index) < sizeof (host_len)) {
		/* message is too short */
		return;
	}
	host_len = msg[index];
	index += sizeof (host_len);
	if ((msg_size - index - host_len) < 0) {
		/* message is too short */
		return;
	}
	memcpy (host, &msg[index], host_len);
	host[host_len] = 0x00;
	index += host_len;

	/* get uri */
	uri_len = msg_size - index;
	if (uri_len <= 0) {
		/* message is too short */
		return;
	}
	memcpy (uri, &msg[index], uri_len);
	uri[uri_len] = 0x00;
	
	if (op == CefC_Fib_Route_Ope_Add) {
		cef_fib_route_add (fib, prot, host, uri);
	} else if (op == CefC_Fib_Route_Ope_Del) {
		cef_fib_route_del (fib, prot, host, uri);
	}
	
	return;
}
/*--------------------------------------------------------------------------------------
	Add route in FIB
----------------------------------------------------------------------------------------*/
static int
cef_fib_route_add (
	CefT_Hash_Handle fib,					/* FIB										*/
	uint8_t prot,							/* Protocol									*/
	char* host,								/* Host Address								*/
	char* uri								/* URI										*/
) {
	int faceid;
	int res;
	unsigned char name[CefC_Max_Length];
	CefT_Fib_Entry* entry;

	/* lookup Face-ID */
	faceid = cef_face_lookup_faceid_from_addrstr (host, prot_str[prot]);
	if (faceid < 0) {
		cef_log_write (CefC_Log_Warn, 
			"Failed to create Face:ID=%s, Prot=%s\n", host, prot_str[prot]);
		return (-1);
	}

	/* translation the string uri to Name TLV */
	res = cef_frame_conversion_uri_to_name ((const char*)uri, name);
	if ((res < 0) || (res > CefC_Max_Length)) {
		cef_log_write (CefC_Log_Warn, "Invalid URI\n", uri);
		return (-1);
	}
	
	/* search this name from FIB */
	entry = (CefT_Fib_Entry*) cef_hash_tbl_item_get (fib, name, res);
	if (entry == NULL) {
		/* create new entry */
		entry = cef_fib_entry_create (name, res);
		cef_hash_tbl_item_set (fib, name, res, entry);
	}
	cef_log_write (CefC_Log_Info, 
		"Insert the FIB entry: URI=%s, Prot=%s, Next=%s, Face=%d\n", 
		uri, prot_str[prot], host, faceid);
	
	cef_fib_set_faceid_to_entry (entry, faceid);

	if (res == CefC_Fib_Default_Len) {
		default_entry = entry;
	}
	
	return (0);
}
/*--------------------------------------------------------------------------------------
	Delete route in FIB
----------------------------------------------------------------------------------------*/
static int
cef_fib_route_del (
	CefT_Hash_Handle fib,					/* FIB										*/
	uint8_t prot,							/* Protocol									*/
	char* host,								/* Host Address								*/
	char* uri								/* URI										*/
) {
	CefT_Fib_Entry* fib_entry;
	int faceid;
	
	unsigned char name[CefC_Max_Length];
	int res;
	int not_remove_f = 1;
	
	/* translation the string uri to Name TLV */
	res = cef_frame_conversion_uri_to_name ((const char*)uri, name);
	
	if ((res < 0) || (res > CefC_Max_Length)) {
		cef_log_write (CefC_Log_Warn, "Invalid URI\n", uri);
		return (-1);
	}
	
	/* search this name from FIB */
	fib_entry = (CefT_Fib_Entry*) cef_hash_tbl_item_get (fib, name, res);
	if (fib_entry == NULL) {
		/* URI not found */
		cef_log_write (CefC_Log_Warn, "%s is not registered in FIB\n", uri);
		return (-1);
	}

	/* remove faceid from fib entry */
	if (fib_entry->faces.next != NULL) {
		/* lookup Face-ID */
		faceid = cef_face_search_faceid (host, prot_str[prot]);
		if (faceid > 0) {
			cef_log_write (CefC_Log_Info, 
				"Remove the FIB entry: URI=%s, Prot=%s, Next=%s, Face=%d\n", 
				uri, prot_str[prot], host, faceid);
			cef_fib_remove_faceid_from_entry (fib_entry, faceid);
			not_remove_f = 0;
		}
		if (not_remove_f) {
			cef_log_write (CefC_Log_Warn, 
				"%s:%s is not registered in FIB entry [ %s ]\n", 
				host, prot_str[prot], uri);
		}
	}
	
	/* check fib entry */
	if (fib_entry->faces.next == NULL) {
		cef_log_write (CefC_Log_Info, "Delete the FIB entry: URI=%s\n", uri);
		
		/* fib entry is empty */
		fib_entry = (CefT_Fib_Entry*) cef_hash_tbl_item_remove (fib, name, res);
		free (fib_entry->key);
		fib_entry->key = NULL;
		free (fib_entry);
		fib_entry = NULL;
	}
	return (0);
}

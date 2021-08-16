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
 * cef_fib.c
 */

#define __CEF_FIB_SOURECE__

//#define	__FIB_DEV__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include <cefore/cef_frame.h>
#include <cefore/cef_fib.h>
#include <cefore/cef_face.h>
#include <cefore/cef_log.h>
#include <cefore/cef_client.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

#define CefC_Fib_Param_Num		34				/* name + port + addr (max is 32) 		*/
#define CefC_Fib_Param_Name		0
#define CefC_Fib_Param_Prot		1
#define CefC_Fib_Param_Addr		2

#define CefC_Fib_Default_Len	4
#ifndef CefC_Android
#define CefC_Fib_Addr_Max		32
#else // CefC_Android
#define CefC_Fib_Addr_Max		3
#endif // CefC_Android


/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

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
	char* p, 									/* target string for trimming 			*/
	char* name,									/* name string after trimming			*/
	char* prot,									/* protocol string after trimming		*/
	char addr[CefC_Fib_Addr_Max][CefC_Max_Length]
);
static CefT_Fib_Entry*
cef_fib_entry_create (
	const unsigned char* name,					/* name for hash key					*/
	unsigned int name_len
);
static void
cef_fib_set_faceid_to_entry (
	CefT_Fib_Entry* entry,
	int faceid, 
	uint8_t type
);
static int
cef_fib_route_add (
	CefT_Hash_Handle fib,					/* FIB										*/
	uint8_t prot,							/* Protocol									*/
	char* host,								/* Host Address								*/
	char* uri,								/* URI										*/
	uint8_t type							/* CefC_Fib_Entry_XXX						*/
);
/*--------------------------------------------------------------------------------------
	Delete route in FIB
----------------------------------------------------------------------------------------*/
static int
cef_fib_route_del (
	CefT_Hash_Handle fib,					/* FIB										*/
	uint8_t prot,							/* Protocol									*/
	char* host,								/* Host Address								*/
	char* uri,								/* URI										*/
	uint8_t type							/* CefC_Fib_Entry_XXX						*/
);
static int 
cef_fib_remove_faceid_from_entry (
	CefT_Fib_Entry* entry,
	int faceid, 
	uint8_t type
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
	cef_fib_faceid_cleanup (fib);
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
#if 0
			{
				int dbg_x;
				
				sprintf (fib_dbg_msg, "[fib] matched to the entry [");
				for (dbg_x = 0 ; dbg_x < entry->klen ; dbg_x++) {
					sprintf (fib_dbg_msg, "%s %02X", fib_dbg_msg, entry->key[dbg_x]);
				}
				cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", fib_dbg_msg);
			}
#else
			{
				int dbg_x;
				int len = 0;
				
				len = sprintf (fib_dbg_msg, "[fib] matched to the entry [");
				for (dbg_x = 0 ; dbg_x < entry->klen ; dbg_x++) {
					len = len + sprintf (fib_dbg_msg + len, " %02X", entry->key[dbg_x]);
				}
				cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", fib_dbg_msg);
			}
#endif
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
#if 0
	{
		int dbg_x;
		
		for (dbg_x = 0 ; dbg_x < i ; dbg_x++) {
			sprintf (fib_dbg_msg, "%s %d", fib_dbg_msg, faceids[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s\n", fib_dbg_msg);
	}
#else
	{
		int dbg_x;
		int len = 0;
		
		for (dbg_x = 0 ; dbg_x < i ; dbg_x++) {
			len = len + sprintf (fib_dbg_msg + len, " %d", faceids[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s\n", fib_dbg_msg);
	}

#endif
#endif // CefC_Debug
	return (i);
}
/*--------------------------------------------------------------------------------------
	Obtains Face-ID(s) to forward the Interest matching the specified FIB entry
----------------------------------------------------------------------------------------*/
int 										/* the number of Face-ID to forward			*/
cef_fib_forward_faceid_select (
	CefT_Fib_Entry* entry, 					/* FIB entry								*/
	uint16_t incoming_faceid, 				/* FaceID at which the Interest arrived 	*/
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
#if 0
	{
		int dbg_x;
		
		sprintf (fib_dbg_msg, "[fib] Select Faces:");
		
		for (dbg_x = 0 ; dbg_x < i ; dbg_x++) {
			sprintf (fib_dbg_msg, "%s %d", fib_dbg_msg, faceids[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s\n", fib_dbg_msg);
	}
#else
	{
		int dbg_x;
		int len = 0;
		
		len = sprintf (fib_dbg_msg, "[fib] Select Faces:");
		for (dbg_x = 0 ; dbg_x < i ; dbg_x++) {
			len = len + sprintf (fib_dbg_msg + len, " %d", faceids[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s\n", fib_dbg_msg);
	}
#endif
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
#if 0
	{
		int dbg_x;
		
		sprintf (fib_dbg_msg, "[fib] Remove Face#%d from [", faceid);
		
		for (dbg_x = 0 ; dbg_x < entry->klen ; dbg_x++) {
			sprintf (fib_dbg_msg, "%s %02X", fib_dbg_msg, entry->key[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", fib_dbg_msg);
	}
#else
	{
		int dbg_x;
		int len = 0;
		
		len = sprintf (fib_dbg_msg, "[fib] Remove Face#%d from [", faceid);
		for (dbg_x = 0 ; dbg_x < entry->klen ; dbg_x++) {
			len = len + sprintf (fib_dbg_msg + len, " %02X", entry->key[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", fib_dbg_msg);
	}
#endif
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
#if 0
	{
		int dbg_x;
		
		sprintf (fib_dbg_msg, "[fib] Insert Face#%d to [", faceid);
		
		for (dbg_x = 0 ; dbg_x < entry->klen ; dbg_x++) {
			sprintf (fib_dbg_msg, "%s %02X", fib_dbg_msg, entry->key[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", fib_dbg_msg);
	}
#else 
	{
		int dbg_x;
		int len = 0;
		
		len = sprintf (fib_dbg_msg, "[fib] Insert Face#%d to [", faceid);
		for (dbg_x = 0 ; dbg_x < entry->klen ; dbg_x++) {
			len = len + sprintf (fib_dbg_msg + len, " %02X", entry->key[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", fib_dbg_msg);
	}

#endif
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
		if(cef_hash_tbl_item_num_get(fib) == cef_hash_tbl_def_max_get(fib)) {
			cef_log_write (CefC_Log_Warn, 
				"FIB table is full(FIB_SIZE = %d)\n", cef_hash_tbl_def_max_get(fib));
			return (NULL);
		}
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
	CefT_Hash_Handle fib
) {
	CefT_Fib_Entry* entry;
	CefT_Fib_Entry* work;
	uint32_t index = 0;
	CefT_Fib_Face* face;
	CefT_Fib_Face* prev;
	
	do {
		entry = (CefT_Fib_Entry*) cef_hash_tbl_item_check_from_index (fib, &index);
		
		if (entry) {
			face = &(entry->faces);
			prev = face;
			
			while (face->next) {
				face = face->next;
				if (cef_face_check_close (face->faceid)) {
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
//	char 	ws[1024];
	char 	ws[2048];
	char 	ws_w[1024];
	FILE*	fp = NULL;
	char 	buff[65600];	/* 65535(max length of name) + 64 */
	char 	uri[CefC_Max_Length];
	unsigned char name[CefC_Max_Length];
	char 	addr[CefC_Fib_Addr_Max][CefC_Max_Length];
	char 	prot[CefC_Max_Length];
	int 	res;
	int 	faceid;
	CefT_Fib_Entry* entry;
	int 	i, addr_num;
	
//	cef_client_config_dir_get (ws);
	
//	sprintf (ws, "%s/cefnetd.fib", ws);
	cef_client_config_dir_get (ws_w);
	
	sprintf (ws, "%s/cefnetd.fib", ws_w);
	
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
		buff[65599] = 0;
		
		if (strlen (buff) >= CefC_Max_Length) {
			cef_log_write (CefC_Log_Warn, 
				"[cefnetd.fib] Detected the too long line:%s\n", buff);
			continue;
		}
		
		if (buff[0] == 0x23/* '#' */) {
			continue;
		}
		if (isspace(buff[0])) {
			continue;
		}
		
		/* parse the read line 		*/
		addr_num = cef_fib_trim_line_string (buff, uri, prot, addr);
		if (addr_num < 1) {
			cef_log_write (CefC_Log_Warn, "[cefnetd.fib] Invalid line:%s\n", buff);
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
			if(cef_face_num_get () >= CefC_Fib_Addr_Max) {
				cef_log_write (CefC_Log_Warn, "[cefnetd.fib] The maximum number(%d) of faces has been exceeded.\n", CefC_Fib_Addr_Max);
				break;
			}
			if(cef_hash_tbl_item_num_get(fib) == cef_hash_tbl_def_max_get(fib)) {
				cef_log_write (CefC_Log_Warn, 
					"FIB table is full(FIB_SIZE = %d)\n", cef_hash_tbl_def_max_get(fib));
				break;
			}
			entry = cef_fib_entry_create (name, res);
			cef_hash_tbl_item_set (fib, name, res, entry);
		}
		
		if (res == CefC_Fib_Default_Len) {
			default_entry = entry;
		}
		
		for (i = 0 ; i < addr_num ; i++) {
			
			/* lookup Face-ID */
			faceid = cef_face_lookup_faceid_from_addrstr (addr[i], prot);
			if (faceid < 0) {
				cef_log_write (CefC_Log_Warn, "[cefnetd.fib] Failed to create Face\n");
				continue;
			}
			
			cef_log_write (CefC_Log_Info, 
				"Creation the FIB entry: URI=%s, Prot=%s, Next=%s, Face=%d\n", 
				uri, prot, addr[i], faceid);

#ifdef __FIB_DEV__
			fprintf( stderr, "[%s] Creation the FIB entry: URI=%s, Prot=%s, Next=%s, Face=%d\n",
				__func__, uri, prot, addr[i], faceid);
#endif
			
			cef_fib_set_faceid_to_entry (entry, faceid, CefC_Fib_Entry_Static);
		}
	}

	fclose (fp);

	return (1);
}

/*--------------------------------------------------------------------------------------
	Check FIB ip address
----------------------------------------------------------------------------------------*/
int
cef_fib_check_addr(const char *addr) {
	int rc = 1;	// correct:1 error:0
	int error_status = 0; // 0:general 1: interface name
	int i, cnt;
	int is_link_local;
	int percent_pos;
	char *char_ptr;
	char *percent_ptr;
	int bracket_pos;
	char *bracket_ptr;
	static char link_addr_head[7] = "fe80::";
	int link_addr_num = 6;
	if (addr[0] == '[') {
		if (strchr(&addr[1],'[')) {
			cef_log_write (CefC_Log_Error, 
				"Invalid ip address format:%s\n", addr);
			return 0;
		}
		cnt = 0;
		char_ptr = strchr(&addr[0],':');
		if (char_ptr) {
			cnt++;
			char_ptr = strchr(++char_ptr,':');
			if (char_ptr) {
				cnt++;
			}
		}
		if (cnt < 2) {
			cef_log_write (CefC_Log_Error, 
				"Invalid ip address format:%s\n", addr);
			return 0;			
		}
		/* ipv6 */
		percent_ptr = strchr(&addr[0],'%');
		if (percent_ptr) {
			percent_pos = percent_ptr - addr + 1;
			bracket_ptr = strchr(&addr[percent_pos],']');
			if (bracket_ptr) {
				bracket_pos = bracket_ptr - percent_ptr + percent_pos -1;
				// check invalid charactor 
				for (i = percent_pos ; i < bracket_pos; i++) {
					if (!isprint(addr[i]) || isspace(addr[i])) {
						rc = 0;
						break;
					}
				}
				if (rc) {
					// check double bracket(])
					if (strchr((bracket_ptr + 1),']'))
					{
						rc = 0;
					}
				}
			}
			else {
				rc = 0;
			}
		}
		else {
			is_link_local = 1;
			for (i = 0; i < link_addr_num ; i++) {
				if (link_addr_head[i] != tolower(addr[i + 1])) {
					is_link_local = 0;
					break;
				}
			}
			if (is_link_local) {
				error_status = 1;
				rc = 0;
			}
			if (rc) {
				bracket_ptr = strchr(&addr[0],']');
				if (!bracket_ptr) {
					rc = 0;
				}
				else {
					char_ptr = strchr(bracket_ptr + 1, ']');
					if (char_ptr) {
						rc = 0;
					}
				}
			}
		}
		if (rc) {
			++bracket_ptr;
			if (*bracket_ptr != '\0' && *bracket_ptr != ':')
			{
				rc = 0;
			}
		}
	}
	else {
		if (strchr(&addr[0],']')) {
			rc = 0;
		}
	}
	if (!rc)
	{
		if (!error_status)
		{
			cef_log_write (CefC_Log_Error, 
				"Invalid ip address format:%s\n", addr);
		}
		else
		{
			cef_log_write (CefC_Log_Error, 
				"Interface name is not specified in link local IPv6:%s\n", addr);
		}
	}
	return rc;
}
	
/*--------------------------------------------------------------------------------------
	Remove a FIB entry from FIB
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
	int faceid, 
	uint8_t type
) {
	CefT_Fib_Face* face = &(entry->faces);

	while (face->next) {
		face = face->next;
		if (face->faceid == faceid) {
			face->type |= type;
			return;
		}
	}
	
	face->next = (CefT_Fib_Face*) malloc (sizeof (CefT_Fib_Face));
	face->next->faceid = faceid;
	face->next->type = type;
	face->next->next = NULL;

	return;
}

static int 
cef_fib_remove_faceid_from_entry (
	CefT_Fib_Entry* entry,
	int faceid, 
	uint8_t type
) {
	CefT_Fib_Face* face = &(entry->faces);
	CefT_Fib_Face* prev = face;
	
	while (face->next) {
		face = face->next;
		if (face->faceid == faceid) {
			face->type &= ~type;
			
			if (type > face->type) {
				prev->next = face->next;
				free (face);
			}
			return (1);
		}
		prev = face;
	}

	return (-1);
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
	char* p, 									/* target string for trimming 			*/
	char* name,									/* name string after trimming			*/
	char* prot,									/* protocol string after trimming		*/
	char addr[CefC_Fib_Addr_Max][CefC_Max_Length]
) {
	int addr_num = 0;
	char* wp;
	
	
	if ((*p == 0x23) || (*p == 0x0D) || (*p == 0x0A)|| (*p == 0x00)) {
		return (0);
	}
	
	wp = p;
	while (*wp) {
		if ((*wp == 0x0D) || (*wp == 0x0A)) {
			*wp = 0x00;
		}
		wp++;
	}
	
	/* URI 				*/
	wp = strtok (p," \t");
	if (wp) {
		strcpy (name, wp);
	} else {
		return (0);
	}
	
	/* protocol			*/
	wp = strtok (NULL, " \t");
	if (wp) {
		strcpy (prot, wp);
		if (strcmp(prot, "tcp") != 0 && strcmp(prot, "udp") != 0) {
			return (0);
		}
	} else {
		return (0);
	}
	
	/* addresses		*/
	while (wp != NULL) {
		
		wp = strtok (NULL, " \t");
		
		if (wp) {
			if (cef_fib_check_addr(wp)) {
				strcpy (addr[addr_num], wp);
				addr_num++;
			}
		}
		
		if (addr_num == CefC_Fib_Addr_Max) {
			break;
		}
	}
	
	return (addr_num);
}

/*--------------------------------------------------------------------------------------
	Receive the FIB route message
----------------------------------------------------------------------------------------*/
int 
cef_fib_route_msg_read (
	CefT_Hash_Handle fib,					/* FIB										*/
	unsigned char* msg, 					/* the received message(s)					*/
	int msg_size,							/* size of received message(s)				*/
	uint8_t type,							/* CefC_Fib_Entry_XXX						*/
	int* rc 								/* 0x01=New Entry, 0x02=Free Entry 			*/
) {
	uint8_t op;
	uint8_t prot;
	uint8_t host_len;
	char host[64] = {0};
	int index = 0;
	char uri[CefC_Max_Length];
	uint16_t uri_len;
	int res = -1;
	unsigned char name[CefC_Max_Length];
	int name_len;
	CefT_Fib_Entry* bentry;
	CefT_Fib_Entry* aentry;
	//
	CefT_Fib_Face* faces = NULL;
	int			b_type_c = 0;
	int			b_type_s = 0;
	int			a_type_c = 0;
	int			a_type_s = 0;
	//
	
	/* Inits the return code 		*/
	*rc = 0x00;
	
	/* get operation */
	if ((msg_size - index) < sizeof (op)) {
		/* message is too short */
		return (-1);
	}
	op = msg[index];
	index += sizeof (op);
	
	/* get protocol */
	if ((msg_size - index) < sizeof (prot)) {
		/* message is too short */
		return (-1);
	}
	prot = msg[index];
	index += sizeof (prot);
	
	/* get uri */
	memcpy (&uri_len, &msg[index], sizeof (uint16_t));
	index += sizeof (uint16_t);
	if (uri_len <= 0) {
		/* message is too short */
		return (-1);
	}
	if ((msg_size - index) < uri_len) {
		/* message is too short */
		return (-1);
	}
	memcpy (uri, &msg[index], uri_len);
	uri[uri_len] = 0x00;
	index += uri_len;
	
	name_len = cef_frame_conversion_uri_to_name ((const char*) uri, name);
	if ((name_len < 0) || (name_len > CefC_Max_Length)) {
		cef_log_write (CefC_Log_Warn, "Invalid URI\n", uri);
		return (-1);
	}
	bentry = cef_hash_tbl_item_get(fib, name, name_len);
	//FaceInfo
	if ( bentry != NULL ) {
		faces = bentry->faces.next;
		while (faces != NULL) {
			
			if ( (faces->type >> 2) & 0x01 ) {
				b_type_c = 1;
			}
			if ( (faces->type >> 1) & 0x01 ) {
				b_type_s = 1;
			}
			faces = faces->next;
		}
	}
	
	while (index < msg_size) {
		/* get host */
		if ((msg_size - index) < sizeof (host_len)) {
			/* message is too short */
			return (-1);
		}
		host_len = msg[index];
		index += sizeof (host_len);
		if ((msg_size - index) < host_len) {
			/* message is too short */
			return (-1);
		}
		memcpy (host, &msg[index], host_len);
		host[host_len] = 0x00;
		index += host_len;
		
		if (!cef_fib_check_addr(host)) {
			continue;
		}
		if (op == CefC_Fib_Route_Ope_Add) {
			res = cef_fib_route_add (fib, prot, host, uri, type);
		} else if (op == CefC_Fib_Route_Ope_Del) {
			res = cef_fib_route_del (fib, prot, host, uri, type);
		}
	}
	aentry = cef_hash_tbl_item_get(fib, name, name_len);
	//FaceInfo
	if ( aentry != NULL ) {
		faces = aentry->faces.next;
		while (faces != NULL) {
			
			if ( (faces->type >> 2) & 0x01 ) {
				a_type_c = 1;
			}
			if ( (faces->type >> 1) & 0x01 ) {
				a_type_s = 1;
			}
			faces = faces->next;
		}
	}

	if (bentry) {
		if (aentry == NULL) {
			*rc = 0x02;
		}
	} else {
		if (aentry) {
			*rc = 0x01;
		}
	}
	//Face Modify Check
	if ( (bentry != NULL) && (aentry != NULL) ) {
		if ( (b_type_c == 0) && (b_type_s == 0) ) {
			if ( (a_type_c == 1) || (a_type_s == 1) ) {
				*rc = 0x01;
			}
		} else if ( (b_type_c == 1) || (b_type_s == 1) ) {
			if ( (a_type_c == 0) && (a_type_s == 0) ) {
				*rc = 0x02;
			}
		} else {
			*rc = 0x00;
		}
	}
	
	return (res);
}
/*--------------------------------------------------------------------------------------
	Obtain the Name from the received route message
----------------------------------------------------------------------------------------*/
int 
cef_fib_name_get_from_route_msg (
	unsigned char* msg, 					/* the received message(s)					*/
	int msg_size, 
	unsigned char* name
) {
	int index = 0;
	char uri[CefC_Max_Length];
	uint16_t uri_len;
	int name_len;
	
	if ((msg_size - index) < sizeof (uint8_t)) {
		return (-1);
	}
	index += sizeof (uint8_t);
	
	if ((msg_size - index) < sizeof (uint8_t)) {
		return (-1);
	}
	index += sizeof (uint8_t);
	
	memcpy (&uri_len, &msg[index], sizeof (uint16_t));
	index += sizeof (uint16_t);
	if (uri_len <= 0) {
		return (-1);
	}
	if ((msg_size - index) < uri_len) {
		return (-1);
	}
	memcpy (uri, &msg[index], uri_len);
	uri[uri_len] = 0x00;
	index += uri_len;
	
	name_len = cef_frame_conversion_uri_to_name ((const char*) uri, name);
	if ((name_len < 0) || (name_len > CefC_Max_Length)) {
		cef_log_write (CefC_Log_Warn, "Invalid URI\n", uri);
		return (-1);
	}
	
	return (name_len);
}
/*--------------------------------------------------------------------------------------
	Add route in FIB
----------------------------------------------------------------------------------------*/
static int
cef_fib_route_add (
	CefT_Hash_Handle fib,					/* FIB										*/
	uint8_t prot,							/* Protocol									*/
	char* host,								/* Host Address								*/
	char* uri,								/* URI										*/
	uint8_t type							/* CefC_Fib_Entry_XXX						*/
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
		if(cef_hash_tbl_item_num_get(fib) == cef_hash_tbl_def_max_get(fib)) {
			cef_log_write (CefC_Log_Warn, 
				"FIB table is full(FIB_SIZE = %d)\n", cef_hash_tbl_def_max_get(fib));
			return (-1);
		}

		/* create new entry */
		entry = cef_fib_entry_create (name, res);
		cef_hash_tbl_item_set (fib, name, res, entry);
	}
	cef_log_write (CefC_Log_Info, 
		"Insert the FIB entry: URI=%s, Prot=%s, Next=%s, Face=%d\n", 
		uri, prot_str[prot], host, faceid);
	
	cef_fib_set_faceid_to_entry (entry, faceid, type);

	if (res == CefC_Fib_Default_Len) {
		default_entry = entry;
	}
	
	return (1);
}
/*--------------------------------------------------------------------------------------
	Delete route in FIB
----------------------------------------------------------------------------------------*/
static int
cef_fib_route_del (
	CefT_Hash_Handle fib,					/* FIB										*/
	uint8_t prot,							/* Protocol									*/
	char* host,								/* Host Address								*/
	char* uri,								/* URI										*/
	uint8_t type							/* CefC_Fib_Entry_XXX						*/
) {
	CefT_Fib_Entry* fib_entry;
	int faceid;
	
	unsigned char name[CefC_Max_Length];
	int res, name_len;
	
	/* translation the string uri to Name TLV */
	name_len = cef_frame_conversion_uri_to_name ((const char*)uri, name);
	
	if ((name_len < 0) || (name_len > CefC_Max_Length)) {
		cef_log_write (CefC_Log_Warn, "Invalid URI\n", uri);
		return (-1);
	}
	
	/* search this name from FIB */
	fib_entry = (CefT_Fib_Entry*) cef_hash_tbl_item_get (fib, name, name_len);
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
			res = cef_fib_remove_faceid_from_entry (fib_entry, faceid, type);
			
			if (res > 0) {
				cef_log_write (CefC_Log_Info, 
					"Remove the FIB entry: URI=%s, Prot=%s, Next=%s, Face=%d\n", 
					uri, prot_str[prot], host, faceid);
			} else {
				cef_log_write (CefC_Log_Warn, 
					"%s (%s) is not registered in FIB entry [ %s ]\n", 
					host, prot_str[prot], uri);
			}
		} else {
			cef_log_write (CefC_Log_Warn, 
				"%s (%s) is not registered in the Face Table\n", 
				host, prot_str[prot]);
		}
{		
		uint32_t index = 0;
		CefT_Fib_Entry* check_fib_entry;
		CefT_Fib_Face* current;
		int	 existed_face = 0;
		
		do {
			check_fib_entry = (CefT_Fib_Entry*) cef_hash_tbl_item_check_from_index (fib, &index);
			if (check_fib_entry != NULL && fib_entry != check_fib_entry) {
				current = &(check_fib_entry->faces);
				while (current->next) {
					current = current->next;
					if(faceid == current->faceid) {
						existed_face = 1;
						break;
					}
				}
				if (existed_face) {
					break;
				}
			}
			index++;
		} while (check_fib_entry);
		
		if (!existed_face) {
			cef_face_close (faceid);
		}
}
	}
	
	/* check fib entry */
	if (fib_entry->faces.next == NULL) {
		cef_log_write (CefC_Log_Info, "Delete the FIB entry: URI=%s\n", uri);
		
		/* fib entry is empty */
		fib_entry = (CefT_Fib_Entry*) cef_hash_tbl_item_remove (fib, name, name_len);
		free (fib_entry->key);
		fib_entry->key = NULL;
		free (fib_entry);
		fib_entry = NULL;
	}
	
	return (1);
}
/*--------------------------------------------------------------------------------------
	Obtains the FIB information
----------------------------------------------------------------------------------------*/
int 
cef_fib_info_get (
	CefT_Hash_Handle* fib, 
	char* info_buff, 
	const unsigned char* name, 
	int name_len, 
	int partial_match_f
) {
	CefT_Fib_Entry* entry;
	uint32_t index;
	int table_num;
	int i;
//	char uri[CefC_Max_Length];
	char uri[8192];
	CefT_Fib_Face* fib_face;
	int res;
	int cmp_len;
//	char face_info[CefC_Max_Length];
	char face_info[8192];
	uint8_t def_name_f = 0;
	char work_buff[CefC_Max_Length];
	
	index = 0;
	
	/* get table num		*/
	table_num = cef_hash_tbl_item_num_get (*fib);
	if (table_num == 0) {
		return (0);
	}
	
	/* output table		*/
	for (i = 0; i < table_num; i++) {
		entry = (CefT_Fib_Entry*) cef_hash_tbl_elem_get (*fib, &index);
		if (entry == NULL) {
			break;
		}
		if (partial_match_f) {
			cmp_len = name_len;
			if (name_len == 4) {
				/* Name is default name. and partial match */
				/* Get All FIB entry                       */
				def_name_f = 1;
			}
		} else {
			if (name_len != entry->klen) {
				index++;
				continue;
			}
			cmp_len = name_len;
		}
		if (!def_name_f && (memcmp (name, entry->key, cmp_len) != 0)) {
			index++;
			continue;
		}
		
		memset (uri, 0, sizeof (uri));
		res = cef_frame_conversion_name_to_uri (entry->key, entry->klen, uri);
		if (res < 0) {
			index++;
			continue;
		}
		/* output faces	*/
		fib_face = entry->faces.next;
		
		while (fib_face != NULL) {
			res = cef_face_info_get (face_info, fib_face->faceid);
			
			if (res > 0) {
				snprintf (work_buff, CefC_Max_Length, "%sFIB: %s %s\n", info_buff, uri, face_info);
				memcpy (info_buff, work_buff, strlen(work_buff));
				if (strlen(info_buff) >= ((CefC_Max_Length)-1)){
					goto endfunc;
				}
			}
			fib_face = fib_face->next;
		}
		index++;
	}
endfunc:;
	return (strlen (info_buff));
}

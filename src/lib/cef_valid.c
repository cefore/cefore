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
 * cef_valid.c
 */

#define __CEF_VALID_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/

#include <string.h>
#include <limits.h>
#include <arpa/inet.h>

#include <cefore/cef_define.h>
#include <cefore/cef_log.h>
#include <cefore/cef_client.h>
#include <cefore/cef_frame.h>
#include <cefore/cef_valid.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/


/****************************************************************************************
 State Variables
 ****************************************************************************************/


/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/
static int
cef_valid_trim_line_string (
	const char* p1, 							/* target string for trimming 			*/
	char* p2,									/* name string after trimming			*/
	char* p3									/* value string after trimming			*/
);


/****************************************************************************************
 ****************************************************************************************/

int
cef_valid_read_pubkey (
	const char* conf_path, 
	unsigned char* key
) {
#ifndef CefC_Android
	char*	wp;
	FILE* 	fp;
	char 	file_path[PATH_MAX];
	char	buff[1024];
	char 	ws[1024];
	char 	pname[1024];
	int 	res;
	unsigned char key_buff[CefC_Max_Length + 1];
	
	
	if ((conf_path != NULL) && (conf_path[0] != 0x00)) {
		sprintf (file_path, "%s/cefnetd.conf", conf_path);
	} else {
		wp = getenv (CefC_CEFORE_DIR);
		if (wp != NULL && wp[0] != 0) {
			sprintf (file_path, "%s/cefore/cefnetd.conf", wp);
		} else {
			sprintf (file_path, "%s/cefnetd.conf", CefC_CEFORE_DIR_DEF);
		}
	}
	
	fp = fopen (file_path, "r");
	if (fp == NULL) {
		cef_log_write (CefC_Log_Error, "[valid] Failed to open config: %s\n", file_path);
		return (-1);
	}
	
	/* Reads and records written values in the cefnetd's config file. */
	file_path[0] = 0x00;
	while (fgets (buff, 1023, fp) != NULL) {
		buff[1023] = 0;
		
		if (buff[0] == 0x23/* '#' */) {
			continue;
		}
		res = cef_valid_trim_line_string (buff, pname, ws);
		if (res < 0) {
			continue;
		}
		if (strcmp (pname, CefC_ParamName_PubKey) == 0) {
			strcpy (file_path, ws);
			break;
		}
	}
	fclose (fp);
	if (file_path[0] == 0x00) {
		return (0);
	}
	fp = fopen (file_path, "rb");
	if (fp == NULL) {
		cef_log_write (CefC_Log_Error, "[valid] Failed to open key: %s\n", file_path);
		return (0);
	}
	
	res = fread (key_buff, sizeof (unsigned char), CefC_Max_Length + 1, fp);
	fclose (fp);
	
	if ((res < 0) || (res > CefC_Max_Length)) {
		return (0);
	}
	memcpy (key, key_buff, res);
	
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, 
		"Read the public key (%s: %d bytes)\n", file_path, res);
	cef_dbg_buff_write (CefC_Dbg_Finest, key, res);
#endif // CefC_Debug
	
	return (res);
#else // CefC_Android
	// TODO
	return (0);
#endif // CefC_Android
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
	
	/* Obtains Validation Algorithm TLV size 		*/
	if (pkt_len - index < CefC_S_TLF) {
		return (0);
	}
	tlv_ptr = (struct tlv_hdr*) &msg[index];
	val_len = ntohs (tlv_ptr->length);
	if (index + CefC_S_TLF + val_len < pkt_len) {
		return (0);
	}
	index   += CefC_S_TLF;
	val_len -= CefC_S_TLF;
	
	/* Obtains the public key 		*/
	memcpy (key, &msg[index + CefC_S_TLF], val_len);
	
#ifndef CefC_Android
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, "Get the public key (%d bytes)\n", val_len);
	cef_dbg_buff_write (CefC_Dbg_Finest, key, val_len);
#endif // CefC_Debug
#endif // CefC_Android
	
	return ((int) val_len);
}

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

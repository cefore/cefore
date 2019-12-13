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
 * csmgrd_plugin.c
 */

#define __CSMGRD_PLUGIN_SOURCE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <limits.h>

#include <cefore/cef_client.h>
#include <csmgrd/csmgrd_plugin.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/



/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/



/****************************************************************************************
 State Variables
 ****************************************************************************************/
static char log_porc[256] = {0};
static int 	log_lv = 0;
static char log_lv_str[4][16] = {"INFO", "WARNING", "ERROR", "CRITICAL"};

#ifdef CefC_Debug
static char dbg_proc[256] = {0};
static int 	dbg_lv = CefC_Dbg_None;
#endif // CefC_Debug

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

#ifdef CefC_Debug
static int
csmgrd_dbg_trim_line_string (
	const char* p1, 							/* target string for trimming 			*/
	char* p2,									/* name string after trimming			*/
	char* p3									/* value string after trimming			*/
);
#endif // CefC_Debug

/****************************************************************************************
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Function to Create Cob message
----------------------------------------------------------------------------------------*/
void
csmgrd_plugin_cob_msg_create (
	unsigned char* buff,						/* created message						*/
	uint16_t* buff_len,							/* Length of message					*/
	unsigned char* msg,							/* Content Object						*/
	uint16_t msg_len,							/* Length of Content Object				*/
	uint32_t chnk_num,							/* Chunk number							*/
	int faceid									/* faceid								*/
) {
	uint16_t index = 0;
	/* set header */
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_Bulk_Cob;
	index += CefC_Csmgr_Msg_HeaderLen;

	/* set cob message */
	memcpy (buff + index, &(msg_len), CefC_S_Length);
	memcpy (buff + index + CefC_S_Length, msg, msg_len);
	index += CefC_S_Length + msg_len;

	/* set chunk num */
	memcpy (buff + index, &(chnk_num), CefC_S_ChunkNum);
	index += CefC_S_ChunkNum;

	/* set faceid */
	memcpy (buff + index, &faceid, sizeof (faceid));
	index += sizeof (faceid);

	/* set Length */
	memcpy (buff + CefC_O_Length, &index, CefC_S_Length);

	*buff_len = index;
	return;
}
/*--------------------------------------------------------------------------------------
	Function to Send Cob message
----------------------------------------------------------------------------------------*/
int
csmgrd_plugin_cob_msg_send (
	int fd,									/* socket fd								*/
	unsigned char* msg,						/* send message								*/
	uint16_t msg_len						/* message length							*/
) {
	struct pollfd fds[1];
	fds[0].fd  = fd;
	fds[0].events = POLLOUT | POLLERR;
	if (poll (fds, 1, 100) < 1) {
		/* poll error */
		return (-1);
	}
	/* send Cob message */
	if (send (fds[0].fd, msg, msg_len, 0) < 1) {
		/* send error */
		if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
			return (-1);
		}
	}
	return (0);
}

/*--------------------------------------------------------------------------------------
	Sets APIs for cache algorithm library
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
csmgrd_lib_api_get (
	const char* algo_lib_name,
	void** 	algo_lib,
	CsmgrdT_Lib_Interface* algo_apis
) {
	/* Opens the library 		*/
	*algo_lib = dlopen (algo_lib_name, RTLD_LAZY);
	if (*algo_lib == NULL) {
		return (-1);
	}

	/* Loads APIs 		*/
	algo_apis->init = dlsym (*algo_lib, "init");
	algo_apis->destroy = dlsym (*algo_lib, "destroy");
	algo_apis->insert = dlsym (*algo_lib, "insert");
	algo_apis->erase = dlsym (*algo_lib, "erase");
	algo_apis->hit = dlsym (*algo_lib, "hit");
	algo_apis->miss = dlsym (*algo_lib, "miss");
	algo_apis->status = dlsym (*algo_lib, "status");


	return (1);
}
/*--------------------------------------------------------------------------------------
	Creates tye key from name and chunk number
----------------------------------------------------------------------------------------*/
int												/* length of the created key 			*/
csmgrd_key_create (
	CsmgrdT_Content_Entry* entry,
	unsigned char* key
) {
	uint32_t chnk_num;

	memcpy (&key[0], entry->name, entry->name_len);
	key[entry->name_len] 		= 0x00;
	key[entry->name_len + 1] 	= 0x10;
	key[entry->name_len + 2] 	= 0x00;
	key[entry->name_len + 3] 	= 0x04;
	chnk_num = htonl (entry->chnk_num);
	memcpy (&key[entry->name_len + 4], &chnk_num, sizeof (uint32_t));

	return (entry->name_len + 4 + sizeof (uint32_t));
}

/*--------------------------------------------------------------------------------------
	Concatenates name and chunk number
----------------------------------------------------------------------------------------*/
int												/* length of the created key 			*/
csmgrd_name_chunknum_concatenate (
	const unsigned char* name,
	uint16_t name_len,
	uint32_t chunknum,
	unsigned char* key
) {
	uint32_t no_chunknum;

	memcpy (&key[0], name, name_len);
	key[name_len] 		= 0x00;
	key[name_len + 1] 	= 0x10;
	key[name_len + 2] 	= 0x00;
	key[name_len + 3] 	= 0x04;
	no_chunknum = htonl (chunknum);
	memcpy (&key[name_len + 4], &no_chunknum, sizeof (uint32_t));

	return (name_len + 4 + sizeof (uint32_t));
}

/*--------------------------------------------------------------------------------------
	Creates the content entry
----------------------------------------------------------------------------------------*/
int 
cef_csmgr_con_entry_create (
	unsigned char* buff,						/* receive message						*/
	int buff_len,								/* message length						*/
	CsmgrdT_Content_Entry* entry
) {
	uint16_t index, len;
	uint16_t value16;
	uint32_t value32;
	uint64_t value64;
	
	/* check message size */
	if (buff_len <= CefC_Csmgr_Msg_HeaderLen) {
		return (-1);
	}
	
	/* check header */
	if ((buff[CefC_O_Fix_Ver]  != CefC_Version) ||
		(buff[CefC_O_Fix_Type] >= CefC_Csmgr_Msg_Type_Num) ||
		(buff[CefC_O_Fix_Type] == CefC_Csmgr_Msg_Type_Invalid)) {
		return (-1);
	}
	memcpy (&value16, &buff[CefC_O_Length], CefC_S_Length);
	len = ntohs (value16);
	
	/* check message length */
	if ((len <= CefC_Csmgr_Msg_HeaderLen) || 
		(len > CefC_Max_Msg_Size * 2) || 
		(len > buff_len)) {
		return (-1);
	}
	index = CefC_Csmgr_Msg_HeaderLen;
	
	/* Get payload length */
	memcpy (&value16, &buff[index], CefC_S_Length);
	entry->pay_len = ntohs (value16);

	if(entry->pay_len > len){
		return(-1);
	}
	index += CefC_S_Length;
	
	/* Get cob message */
	memcpy (&value16, &buff[index], CefC_S_Length);
	entry->msg_len = ntohs (value16);
	if(entry->pay_len > entry->msg_len){
		return(-1);
	}
	if(entry->msg_len > len){
		return(-1);
	}
	index += CefC_S_Length;
	memcpy (entry->msg, &buff[index], entry->msg_len);
	index += entry->msg_len;
	
	/* Get cob name */
	memcpy (&value16, &buff[index], CefC_S_Length);
	entry->name_len = ntohs (value16);
	if(entry->name_len > entry->msg_len){
		return(-1);
	}
	index += CefC_S_Length;
	memcpy (entry->name, &buff[index], entry->name_len);
	index += entry->name_len;
	
	/* Get chunk num */
	memcpy (&value32, &buff[index], CefC_S_ChunkNum);
	entry->chnk_num = ntohl (value32);
	index += CefC_S_ChunkNum;
	
	/* Get cache time */
	memcpy (&value64, &buff[index], CefC_S_Cachetime);
	entry->cache_time = cef_client_ntohb (value64);
	index += CefC_S_Cachetime;
	
	/* get expiry */
	memcpy (&value64, &buff[index], CefC_S_Expiry);
	entry->expiry = cef_client_ntohb (value64);
	index += CefC_S_Expiry;
	
	/* get address */
	memcpy (&entry->node, &buff[index], sizeof (struct in_addr));
	index += sizeof (struct in_addr);
	
	return ((int) index);
}
void
csmgrd_log_init (
	const char* proc_name
) {
	char* wp;

	assert (proc_name != NULL);

	strcpy (log_porc, proc_name);
	wp = getenv ("CEF_LOG");
	if (wp == NULL) {
		log_lv = -1;
		return;
	}
	log_lv = atoi (wp);
	if (log_lv == 0) {
		log_lv = CefC_Log_Critical;
	} else {
		log_lv = -1;
	}

}

void
csmgrd_log_write (
	int level, 										/* logging level 					*/
	const char* fmt, 								/* output format					*/
	...												/* parameters						*/
) {
	va_list arg;
	char 		time_str[64];
	struct tm* 	timeptr;
	time_t 		timer;
	struct timeval t;
	
	assert (level <= CefC_Log_Critical);
	assert (log_porc[0] != 0x00);
	
	if (level > log_lv) {
		va_start (arg, fmt);
		
		timer 	= time (NULL);
		timeptr = localtime (&timer);
		strftime (time_str, 64, "%Y-%m-%d %H:%M:%S", timeptr);
		gettimeofday (&t, NULL);
		
		fprintf (stdout, "%s."FMTLINT" [%s] %s: "
			, time_str, t.tv_usec / 1000, log_porc, log_lv_str[level]);
		vfprintf (stdout, fmt, arg);
		
		va_end (arg);
	}
}

#ifdef CefC_Debug

void
csmgrd_dbg_init (
	const char* proc_name,
	const char* config_file_dir
) {
	char 	file_path[PATH_MAX];
	FILE* 	fp;
	char	buff[1024];
	char 	ws[1024];
	char 	pname[1024];
	int 	res;
	
	assert (proc_name != NULL);
	strcpy (dbg_proc, proc_name);
	
	/* Records the debug level 			*/
	if (config_file_dir[0] != 0x00) {
		sprintf (file_path, "%s/csmgrd.conf", config_file_dir);
	} else {
		sprintf (file_path, "%s/csmgrd.conf", CefC_CEFORE_DIR_DEF);
	}
	
	fp = fopen (file_path, "r");
	if (fp == NULL) {
		return;
	}
	
	/* Reads and records written values in the cefnetd's config file. */
	while (fgets (buff, 1023, fp) != NULL) {
		buff[1023] = 0;
		
		if (buff[0] == 0x23/* '#' */) {
			continue;
		}
		res = csmgrd_dbg_trim_line_string (buff, pname, ws);
		if (res < 0) {
			continue;
		}
		
		if (strcmp (pname, "LOG_LEVEL") == 0) {
			dbg_lv = atoi (ws);
		}
	}
	fclose (fp);
	
	if (dbg_lv > CefC_Dbg_Finest) {
		dbg_lv = CefC_Dbg_Finest;
	}
	if (dbg_lv < CefC_Dbg_None) {
		dbg_lv = CefC_Dbg_None;
	}
	dbg_lv++;
}

void
csmgrd_dbg_write (
	int level, 										/* debug level 						*/
	const char* fmt, 								/* output format					*/
	...												/* parameters						*/
) {
	va_list arg;
	char 		time_str[64];
	struct tm* 	timeptr;
	time_t 		timer;
	struct timeval t;
	
	assert (level >= CefC_Dbg_Fine && level <= CefC_Dbg_Finest);
	assert (dbg_proc[0] != 0x00);
	
	if (level < dbg_lv) {
		va_start (arg, fmt);
		
		timer 	= time (NULL);
		timeptr = localtime (&timer);
		strftime (time_str, 64, "%Y-%m-%d %H:%M:%S", timeptr);
		gettimeofday (&t, NULL);
		
		fprintf (stdout, 
			"%s."FMTLINT" [%s] DEBUG: ", time_str, t.tv_usec / 1000, dbg_proc);
		vfprintf (stdout, fmt, arg);
		
		va_end (arg);
	}
}

void
csmgrd_dbg_buff_write (
	int level, 										/* debug level 						*/
	const unsigned char* buff,
	int len
) {
	int i;
	int n = 0;
	int s = 0;

	if (level < dbg_lv) {

		fprintf (stderr, "------------------------------------------------------\n");
		fprintf (stderr, "      0  1  2  3  4  5  6  7    8  9  0  1  2  3  4  5\n");
		for (i = 0 ; i < len ; i++) {
			if (n == 0) {
				fprintf (stderr, "%3d: ", s);
				s++;
			}
			fprintf (stderr, "%02X ", buff[i]);

			if (n == 7) {
				fprintf (stderr, "  ");
			}
			n++;
			if (n > 15) {
				n = 0;
				fprintf (stderr, "\n");
			}
		}
		fprintf (stderr, "\n------------------------------------------------------\n");
	}
}
static int
csmgrd_dbg_trim_line_string (
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

#endif // CefC_Debug
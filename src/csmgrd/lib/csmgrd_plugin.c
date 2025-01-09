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
 * csmgrd_plugin.c
 */

#define __CSMGRD_PLUGIN_SOURCE__

#define		CSMGRD_PLUGIN_SEND_USLEEP	100000
#define		CSMGRD_PLUGIN_SEND_TIMEOUT	10000

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
#include <cefore/cef_frame.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/
#define ALGO_MAX_MEM_USAGE				55

#define	SEND_RETRY_LIMIT		10

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

/****************************************************************************************
 State Variables
 ****************************************************************************************/
static char log_proc[256] = {0};
static int 	log_lv = 0;
static char log_lv_str[4][16] = {"INFO", "WARNING", "ERROR", "CRITICAL"};

#ifdef CefC_Debug
static char dbg_proc[256] = {0};
static int 	dbg_lv = CefC_Dbg_None;
#endif // CefC_Debug

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

static int
csmgrd_log_trim_line_string (
	const char* p1, 							/* target string for trimming 			*/
	char* p2,									/* name string after trimming			*/
	char* p3									/* value string after trimming			*/
);

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
	Function to Send Cob message
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an EBADF occurs	*/
csmgrd_plugin_cob_msg_send (
	int fd,									/* socket fd								*/
	unsigned char* msg,						/* send message								*/
	uint16_t msg_len						/* message length							*/
) {
	unsigned char* p = msg;
	int len = msg_len;
	int res = 0;
	int send_count = 0;

	if ( len <= 0 ) {
		return (0);
	}

	errno = 0;
	res = send (fd, p, len,  MSG_DONTWAIT);
	if ( res <= 0 ) {
#ifdef CefC_Debug
		csmgrd_dbg_write (CefC_Dbg_Finer, "[%s](%d): ########### send_count:%d len:%d res:%d %s\n",
							__FUNCTION__, __LINE__, send_count, len, res, strerror (errno));
#endif // CefC_Debug
		return (errno == EBADF ? -1 : 0);
	}
	if ( 0 < res ){
		len -= res;
		p += res;
	}

	/**************************************************************
		If it fails to send even 1 byte, it doesn't send at all,
		otherwise it retry the rest.
	 **************************************************************/

	for ( send_count = 1;
		0 < len && errno != EBADF && send_count <= SEND_RETRY_LIMIT;
			send_count++ ){

#ifdef CefC_Debug
		csmgrd_dbg_write (CefC_Dbg_Finer, "[%s](%d): usleep(CSMGRD_PLUGIN_SEND_USLEEP);\n", __FUNCTION__, __LINE__);
#endif // CefC_Debug
		usleep(CSMGRD_PLUGIN_SEND_USLEEP);

		errno = 0;
		res = send (fd, p, len,  MSG_DONTWAIT);
		if ( res == len ) {
			return (0);
		} else if ( 0 < res ) {
			len -= res;
			p += res;
		}

#ifdef CefC_Debug
		csmgrd_dbg_write (CefC_Dbg_Finer, "[%s](%d): ########### send_count:%d len:%d res:%d %s\n",
							__FUNCTION__, __LINE__, send_count, len, res, strerror (errno));
#endif // CefC_Debug
	}

	return (errno == EBADF ? -1 : 0);
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
	Creates key from name and chunk number
----------------------------------------------------------------------------------------*/
int												/* length of the created key 			*/
csmgrd_key_create (
	CsmgrdT_Content_Entry* entry,
	unsigned char* key
) {
	uint32_t chunk_num;

	memcpy (&key[0], entry->name, entry->name_len);
	key[entry->name_len] 		= 0x00;
	key[entry->name_len + 1] 	= 0x10;
	key[entry->name_len + 2] 	= 0x00;
	key[entry->name_len + 3] 	= 0x04;
	chunk_num = htonl (entry->chunk_num);
	memcpy (&key[entry->name_len + 4], &chunk_num, sizeof (uint32_t));

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
	struct timeval tv;

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
		(len > buff_len)) {
		return (-1);
	}
	index = CefC_Csmgr_Msg_HeaderLen;

	/* Get payload length */
	memcpy (&value16, &buff[index], CefC_S_Length);
	entry->pay_len = ntohs (value16);

	if (entry->pay_len > len) {
		return (-1);
	}
	index += CefC_S_Length;

	/* Get cob message */
	memcpy (&value16, &buff[index], CefC_S_Length);
	entry->msg_len = ntohs (value16);
	if (entry->pay_len > entry->msg_len) {
		return (-1);
	}
	if (entry->msg_len > len) {
		return (-1);
	}
	index += CefC_S_Length;
	entry->msg = calloc (1 , entry->msg_len);
	if (entry->msg == NULL) {
		csmgrd_log_write (CefC_Log_Info, "%s(%d): Could not get memory information.\n", __FUNCTION__, __LINE__);
		return (-1);
	}
	memcpy (entry->msg, &buff[index], entry->msg_len);
	index += entry->msg_len;

{
	unsigned char* ucp;
	uint16_t pkt_len = 0;
	uint16_t hdr_len = 0;
	CefT_CcnMsg_MsgBdy 	pm = { 0 };
	CefT_CcnMsg_OptHdr 	poh = { 0 };
	int res;

/*                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +---------------+---------------+---------------+---------------+
     |    version    |      type     |            pkt_len            |
     +---------------+---------------+---------------+---------------+
     |   hoplimit    |   reserve1    |   reserve2    |     hdr_len   |
     +---------------+---------------+---------------+---------------+
*/

	ucp = (unsigned char*) entry->msg;
	memcpy (&value16, &ucp[2], CefC_S_Length);	/* 2=version+type */
	pkt_len = ntohs (value16);
	hdr_len = ucp[7];	/* 7=version+type+pkt_len+hoplimit+reserve1+reserve2 */

	res = cef_frame_message_parse (
					entry->msg, (pkt_len - hdr_len), hdr_len, &poh, &pm, CefC_PT_OBJECT);
	if (res < 0) {
		free (entry->msg);
		return (-1);
	}
	if (pm.org.version_f) {
		entry->ver_len = pm.org.version_len;
		if (pm.org.version_len) {
			entry->version = (unsigned char*) malloc (pm.org.version_len);
			memcpy (entry->version, pm.org.version_val, pm.org.version_len);
		} else {
			entry->version = NULL;
		}
	} else {
		entry->ver_len = 0;
		entry->version = NULL;
	}
}

	/* Get cob name */
	memcpy (&value16, &buff[index], CefC_S_Length);
	entry->name_len = ntohs (value16);
	if (entry->name_len > entry->msg_len) {
		free (entry->msg);
		if (entry->version != NULL) {
			free (entry->version);
		}
		return (-1);
	}
	index += CefC_S_Length;
	if (!(buff[index] == 0x00 && buff[index+1] == 0x01)) {
		free (entry->msg);
		if (entry->version != NULL) {
			free (entry->version);
		}
		return (-1);
	}
	entry->name = calloc (1 , entry->name_len);
	if (entry->name == NULL) {
		free (entry->msg);
		if (entry->version != NULL) {
			free (entry->version);
		}
		return (-1);
	}
	memcpy (entry->name, &buff[index], entry->name_len);
	index += entry->name_len;

	/* Get chunk num */
	memcpy (&value32, &buff[index], CefC_S_ChunkNum);
	entry->chunk_num = ntohl (value32);
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

	/* get insert time */
	gettimeofday (&tv, NULL);
	entry->ins_time = tv.tv_sec * 1000000llu + tv.tv_usec;

	return ((int) index+3/* for MAGIC */);
}
/*--------------------------------------------------------------------------------------
	Check for excessive or insufficient memory resources for cache algorithm library
----------------------------------------------------------------------------------------*/
int
csmgrd_cache_algo_availability_check (
	uint64_t	capacity,
	char*		algo,
	int			name_size,
	int			cob_size,
	char*		cs_type
) {
	uint64_t total_kiro = 0;
	uint64_t free_kiro = 0;
	uint64_t est_resource;

	char buf[64] = {0};

	int ret = 0;
	char* wp = NULL;

	/* get total and free memory size */
	FILE *fp = popen(CefC_GET_MEMORY_INFO_SH, "r");
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, "fp:%p\n", fp);
#endif // CefC_Debug
	if (fp == NULL) {
		cef_log_write (CefC_Log_Critical, "%s(%d): Could not get memory information.\n", __FUNCTION__, __LINE__);
	} else {
		wp = fgets (buf, sizeof (buf), fp);
		while ( wp ) {
			ret = atoi (buf);
			if (ret != -1) {
				char* token = NULL;
				char* saveptr = NULL;
				token = strtok_r (buf, ",", &saveptr);
				if (token == NULL) {
					break;
				}
				ret = atoi (token);
				if (ret != -1) {
					total_kiro = ret;
#ifdef CefC_Debug
					cef_dbg_write (CefC_Dbg_Finest, "total_kiro:%ld\n", total_kiro);
#endif // CefC_Debug
				}

				token = strtok_r (NULL, ",", &saveptr);
				if (token == NULL) {
					break;
				}
				ret = atoi (token);
				if (ret != -1) {
					free_kiro = ret;
#ifdef CefC_Debug
					cef_dbg_write (CefC_Dbg_Finest, "free_kiro:%ld\n", free_kiro);
#endif // CefC_Debug
				}
			}
			break;
		}
		pclose(fp);
	}

	if (total_kiro == 0 || free_kiro == 0) {
		cef_log_write (CefC_Log_Critical, "%s(%d): Could not find keyword to get memory information\n",
						__FUNCTION__, __LINE__);
		return (-1);
	}

	/* Cache Strategy Management Resource Estimate */
	est_resource  = capacity * (uint64_t)(24+4+name_size);

	/* Cache Strategy Related (loopkup) Resource Estimates */
	est_resource += capacity * (uint64_t)(8+32+name_size);

	if (strcmp (cs_type, "memory") == 0) {
		/* Cache Resource Estimate */
		est_resource += capacity * (uint64_t)(8+40+name_size+cob_size);
	} else {
		est_resource += free_kiro * 1024 * 0.3;
	}

	if (free_kiro * 1024 * ALGO_MAX_MEM_USAGE / 100 < est_resource) {
		char* conf = "csmgrd";
		csmgrd_log_write (CefC_Log_Error,
		    "Unable to use %s cache with specified algorithm due to lack of memory"
    		"resource. Unset algorithm, i.e., CACHE_ALGORITHM=None, in %s.conf.\n"
			"	(Detected Memory Size="FMTU64"\n"
			"	 Estimated available memory size="FMTU64"\n"
			"	 Memory size that the algorithm is expected to use="FMTU64")\n",
			cs_type, conf,
			free_kiro * 1024,
			free_kiro * 1024 * ALGO_MAX_MEM_USAGE / 100,
			est_resource);
		return (-1);
	}

	return (0);
}
void
csmgrd_log_init (
	const char* proc_name,
	int			level
) {

	assert (proc_name != NULL);

	strcpy (log_proc, proc_name);
	log_lv = level;
}
void
csmgrd_log_init2 (
	const char* config_file_dir
) {

	char* 	wp;
	char 	file_path[PATH_MAX];
	FILE* 	fp;
	char	buff[1024];
	char 	ws[1024];
	char 	pname[1024];
	int 	res;

	/* Update the log level information 	*/
	if (config_file_dir[0] != 0x00) {
		sprintf (file_path, "%s/csmgrd.conf", config_file_dir);
	} else {
		wp = getenv (CefC_CEFORE_DIR);
		if (wp != NULL && wp[0] != 0) {
			sprintf (file_path, "%s/cefore/csmgrd.conf", wp);
		} else {
			sprintf (file_path, "%s/csmgrd.conf", CefC_CEFORE_DIR_DEF);
		}
	}

	fp = fopen (file_path, "r");
	if (fp == NULL) {
		return;
	}

	log_lv = 0;
	/* Reads and records written values in the cefnetd's config file. */
	while (fgets (buff, 1023, fp) != NULL) {
		buff[1023] = 0;

		if (buff[0] == 0x23/* '#' */) {
			continue;
		}
		res = csmgrd_log_trim_line_string (buff, pname, ws);
		if (res < 0) {
			continue;
		}

		if (strcmp (pname, "CEF_LOG_LEVEL") == 0) {
			log_lv = atoi (ws);
			if (!(0<=log_lv && log_lv <= 2)) {
				log_lv = 0;
			}
		}
	}
	fclose (fp);
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
	int		use_log_level;


	assert (level <= CefC_Log_Critical);
	assert (log_proc[0] != 0x00);

    if (log_lv == 0) {
		use_log_level = CefC_Log_Error;
	} else if (log_lv == 1) {
		use_log_level = CefC_Log_Warn;
	} else {
		use_log_level = -1;
	}

	if (level >= use_log_level) {
		char	buff[1024];
		int		buff_len = 0;

		va_start (arg, fmt);

		timer 	= time (NULL);
		timeptr = localtime (&timer);
		strftime (time_str, 64, "%Y-%m-%d %H:%M:%S", timeptr);
		gettimeofday (&t, NULL);

		buff_len = sprintf(buff, "%s."FMTLINT" [%s] %s: "
				, time_str, t.tv_usec / 1000, log_proc, log_lv_str[level]);
		vsprintf(&buff[buff_len], fmt, arg);
		cef_log_fprintf("%s", buff);

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
	char*	wp;

	assert (proc_name != NULL);
	strcpy (dbg_proc, proc_name);

	/* Records the debug level 			*/
	if (config_file_dir[0] != 0x00) {
		sprintf (file_path, "%s/csmgrd.conf", config_file_dir);
	} else {
		wp = getenv (CefC_CEFORE_DIR);
		if (wp != NULL && wp[0] != 0) {
			sprintf (file_path, "%s/cefore/csmgrd.conf", wp);
		} else {
			sprintf (file_path, "%s/csmgrd.conf", CefC_CEFORE_DIR_DEF);
		}
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

		if (strcmp (pname, "CEF_DEBUG_LEVEL") == 0) {
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
static int
csmgrd_log_trim_line_string (
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

/*--------------------------------------------------------------------------------------
	Set pending timer
----------------------------------------------------------------------------------------*/
int							/* The return value is negative if an error occurs	*/
csmgrd_cache_set_pending_timer (
	CsmgrT_Stat_Handle hdl,
	unsigned char* name,						/* Content name							*/
	uint16_t name_len,							/* Content name length					*/
	uint64_t pending_timer						/* Content Pending Timer				*/
) {
	uint64_t nowt;
	struct timeval tv;
	uint64_t new_pending_timer;

	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;
	new_pending_timer = nowt + pending_timer * 1000000llu;

	/* Updtes the content information */
	csmgrd_stat_content_pending_timer_update (hdl, name, name_len, new_pending_timer);

	return (0);
}

/*--------------------------------------------------------------------------------------
	Update content publisher expiry
----------------------------------------------------------------------------------------*/
int							/* The return value is negative if an error occurs	*/
csmgrd_cache_update_publisher_expiry (
	CsmgrT_Stat_Handle hdl,
	unsigned char* name,						/* Content name							*/
	uint16_t name_len,							/* Content name length					*/
	int expiry_f,								/* Offset of expires					*/
	uint64_t expiry								/* expires								*/
) {
	uint64_t new_publisher_expiry;

	if (expiry_f) {
		new_publisher_expiry = expiry;
	} else {
		new_publisher_expiry = UINT64_MAX;
	}

	/* Updtes the content information */
	csmgrd_stat_content_publisher_expiry_update (hdl, name, name_len, new_publisher_expiry);

	return (0);
}

/*--------------------------------------------------------------------------------------
	Update expiry
----------------------------------------------------------------------------------------*/
int							/* The return value is negative if an error occurs	*/
csmgrd_cache_update_expiry (
	CsmgrT_Stat_Handle hdl,
	unsigned char* name,						/* Content name							*/
	uint16_t name_len,							/* Content name length					*/
	CsmgrT_Stat* rcd,
	uint64_t extend_lifetime
) {
	uint64_t new_expiry;

	if (rcd->expiry >= rcd->publisher_expiry) {
		return (0);
	}

	new_expiry = rcd->expiry + extend_lifetime;
	if (new_expiry > rcd->publisher_expiry) {
		new_expiry = rcd->publisher_expiry;
	}

	/* Updtes the content information */
	csmgrd_stat_content_lifetime_update (hdl, name, name_len, new_expiry);

	return (0);
}

/*--------------------------------------------------------------------------------------
	Verification for UCINC
----------------------------------------------------------------------------------------*/
int
csmgrd_cob_verify_ucinc (
	CsmgrT_Stat_Handle hdl,
	const unsigned char* name,
	uint16_t name_len,
	unsigned char* plain_val,
	uint16_t plain_len,
	unsigned char* signature_val,
	uint16_t signature_len,
	uint64_t *plaint
) {
	uint64_t nowt;
	uint64_t nowt_min;
	uint64_t nowt_max;
	struct timeval tv;
	int ret = -1;
	unsigned char wk_plain[8] = {0};

	if (plain_len == 0 || signature_len == 0) {
		csmgrd_log_write (CefC_Log_Error, "plain_len:%d. signature_len:%d\n", plain_len, signature_len);
		return ret;
	}

	for (int cnt = 0 ; cnt < plain_len ; cnt++) {
		wk_plain[cnt] = plain_val[plain_len-1-cnt];
	}
	memcpy (plain_val, wk_plain, plain_len);

	ret = csmgrd_stat_cob_verify_ucinc (hdl, name, name_len, signature_val, signature_len, plain_val, plain_len);
	if (!ret) {
		memcpy (plaint, plain_val, plain_len);

		gettimeofday (&tv, NULL);
		nowt = tv.tv_sec * 1000000llu + tv.tv_usec;
		nowt_min = nowt - 2000000llu;
		nowt_max = nowt + 2000000llu;
		if (*plaint < nowt_min || nowt_max < *plaint) {
			ret = -2;
		}
	}

	return ret;
}


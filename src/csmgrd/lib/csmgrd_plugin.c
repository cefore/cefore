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
 * csmgrd_plugin.c
 */

#define __CSMGRD_PLUGIN_SOURCE__

//#define	__CSMGRD_PLUGIN_SEND_ERROR__

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

/****************************************************************************************
 Macros
 ****************************************************************************************/
#define ALGO_MAX_MEM_USAGE				55

#define	DEMO_RETRY_NUM	10

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
int
csmgrd_plugin_cob_msg_send (
	int fd,									/* socket fd								*/
	unsigned char* msg,						/* send message								*/
	uint16_t msg_len						/* message length							*/
) {

   	unsigned char* p = msg;
   	int len = msg_len;
	fd_set fds, writefds;
	int n;
	struct timeval timeout;
	int res = 0;
	int send_count = 0;


   	res = send (fd, p, len,  MSG_DONTWAIT);
	if ( res <= 0 ) {
#ifdef	__CSMGRD_PLUGIN_SEND_ERROR__
		fprintf(stderr, "[%s](res <=0): ########### ERROR=%s send_count:%d\n", __FUNCTION__, strerror (errno), send_count);
#endif
		return( 0 );
	}
	len -= res;  
	p += res;
	send_count++;

	while( len > 0 ) {
		timeout.tv_sec  = 0;
		timeout.tv_usec = CSMGRD_PLUGIN_SEND_TIMEOUT;
		FD_ZERO (&writefds);
		FD_SET (fd, &writefds);
		memcpy (&fds, &writefds, sizeof (fds));
		n = select (fd+1, NULL, &fds, NULL, &timeout);
		if (n > 0) {
			if (FD_ISSET (fd, &fds)) {
			   	res = send (fd, p, len,  MSG_DONTWAIT);
			   	if ( res > 0 ) {
					len -= res;  
					p += res;
				} else {
#ifdef	__CSMGRD_PLUGIN_SEND_ERROR__
					fprintf(stderr, "[%s](res <=0): ########### ERROR=%s send_count:%d\n", __FUNCTION__, strerror (errno), send_count);
#endif
					if ( errno == EAGAIN ) {
						usleep(CSMGRD_PLUGIN_SEND_USLEEP);
					}
				}
				send_count++;
			}
		} else {
			if ( send_count == 0 ) {
#ifdef	__CSMGRD_PLUGIN_SEND_ERROR__
				fprintf(stderr, "[%s](%d): ########### n:%d   send_count:%d   len:%d   %s\n", 
										__FUNCTION__, __LINE__, n, send_count, len, strerror (errno));
#endif
				break;
			} else if ( send_count > DEMO_RETRY_NUM ) {
#ifdef	__CSMGRD_PLUGIN_SEND_ERROR__
				fprintf(stderr, "[%s](%d): ########### n:%d   send_count:%d   len:%d   %s\n", 
										__FUNCTION__, __LINE__, n, send_count, len, strerror (errno));
#endif
				break;
			}
			send_count++;
			if ( errno == EAGAIN ) {
				usleep(CSMGRD_PLUGIN_SEND_USLEEP);
			}
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
	struct timeval tv;
	
	/* check message size */
	if (buff_len <= CefC_Csmgr_Msg_HeaderLen) {
		return (-1);
	}
	
	/* check header */
	if ((buff[CefC_O_Fix_Ver]  != CefC_Version) ||
		(buff[CefC_O_Fix_Type] >= CefC_Csmgr_Msg_Type_Num) ||
		(buff[CefC_O_Fix_Type] == CefC_Csmgr_Msg_Type_Invalid)) {
//@@@@@fprintf(stderr, "[%s]: ------ retern(%d) -----\n", __FUNCTION__, __LINE__);
		return (-1);
	}
	memcpy (&value16, &buff[CefC_O_Length], CefC_S_Length);
	len = ntohs (value16);
	
	/* check message length */
	if ((len <= CefC_Csmgr_Msg_HeaderLen) || 
		(len > buff_len)) {
//@@@@@fprintf(stderr, "[%s]: ------ retern(%d) -----\n", __FUNCTION__, __LINE__);
		return (-1);
	}
	index = CefC_Csmgr_Msg_HeaderLen;
	
	/* Get payload length */
	memcpy (&value16, &buff[index], CefC_S_Length);
	entry->pay_len = ntohs (value16);

	if (entry->pay_len > len) {
//@@@@fprintf(stderr, "[%s]: ------ retern(%d) -----\n", __FUNCTION__, __LINE__);
		return (-1);
	}
	index += CefC_S_Length;
	
	/* Get cob message */
	memcpy (&value16, &buff[index], CefC_S_Length);
	entry->msg_len = ntohs (value16);
	if (entry->pay_len > entry->msg_len) {
//@@@@fprintf(stderr, "[%s]: ------ retern(%d) -----\n", __FUNCTION__, __LINE__);
		return (-1);
	}
	if (entry->msg_len > len) {
//@@@@fprintf(stderr, "[%s]: ------ retern(%d) -----\n", __FUNCTION__, __LINE__);
		return (-1);
	}
	index += CefC_S_Length;
	entry->msg = calloc (1 , entry->msg_len);
	if (entry->msg == NULL) {
//@@@@fprintf(stderr, "[%s]: ------ retern(%d) -----\n", __FUNCTION__, __LINE__);
		return (-1);
	}
	memcpy (entry->msg, &buff[index], entry->msg_len);
	index += entry->msg_len;
	
	/* Get cob name */
	memcpy (&value16, &buff[index], CefC_S_Length);
	entry->name_len = ntohs (value16);
	if (entry->name_len > entry->msg_len) {
		free (entry->msg);
//@@@@fprintf(stderr, "[%s]: ------ retern(%d) -----\n", __FUNCTION__, __LINE__);
		return (-1);
	}
	index += CefC_S_Length;
	if (!(buff[index] == 0x00 && buff[index+1] == 0x01)) { 
		free (entry->msg);
//@@@@fprintf(stderr, "[%s]: ------ retern(%d) -----\n", __FUNCTION__, __LINE__);
		return (-1);
	}
	entry->name = calloc (1 , entry->name_len);
	if (entry->name == NULL) {
		free (entry->msg);
		return (-1);
	}
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
	
	/* get insert time */
	gettimeofday (&tv, NULL);
	entry->ins_time = tv.tv_sec * 1000000llu + tv.tv_usec;
	
//@@@@@fprintf(stderr, "[%s]: ------ reternOK(%d) -----\n", __FUNCTION__, __LINE__);
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
	FILE* fp;
	uint64_t total_mega = 0;
	uint64_t free_mega = 0;
	uint64_t est_resource;

	/* get total and free memory size */
#ifndef CefC_MACOS
	/************************************************************************************/
	/* [/proc/meminfo format]															*/
	/*		MemTotal:        8167616 kB													*/
	/*		MemFree:         7130204 kB													*/
	/*		MemAvailable:    7717896 kB													*/
	/*		...																			*/
	/************************************************************************************/
	char buf[1024];
	char* key_total = "MemTotal:";
	char* key_free = "MemFree:";
	char* meminfo = "/proc/meminfo";
	int val;
	if ((fp = fopen (meminfo, "r")) == NULL) {
		cef_log_write (CefC_Log_Critical, "%s(%d): Could not open %s to get memory information.\n", __FUNCTION__, meminfo);
		return (-1);
	}
	while (fgets (buf, sizeof (buf), fp) != NULL) {
		if (strncmp (buf, key_total, strlen (key_total)) == 0) {
			sscanf (&buf[strlen (key_total)], "%d", &val);
			total_mega = val / 1024;
		}
		if (strncmp (buf, key_free, strlen (key_free)) == 0) {
			sscanf (&buf[strlen (key_free)], "%d", &val);
			free_mega = val / 1024;
		}
	}
	if (total_mega == 0) {
		cef_log_write (CefC_Log_Critical, "%s(%d): Could not find keyword(%s) to get memory information\n", 
						__FUNCTION__, key_total);
		fclose (fp);
		return (-1);
	}
	if (free_mega == 0) {
		cef_log_write (CefC_Log_Critical, "%s(%d): Could not find keyword(%s) to get memory information\n", 
						__FUNCTION__, key_free);
		fclose (fp);
		return (-1);
	}
	fclose (fp);
#else // CefC_MACOS
	/************************************************************************************/
	/* ["top -l 1 | grep PhysMem:" format]												*/
	/*		PhysMem: 7080M used (1078M wired), 1109M unused.							*/
	/************************************************************************************/
	char buf[1024];
	char* cmd = "top -l 1 | grep PhysMem:";
	char* tag = "PhysMem:"; 
	int	 used = 0, unused = 0;
	if ((fp = popen (cmd, "r")) != NULL) {
		while (fgets (buf, sizeof (buf), fp) != NULL) {
			if (strstr (buf, tag) != NULL) {
				char* pos = strchr (buf, ' ');
				sscanf (pos, "%d", &used);
				pos = strchr (pos, ',');
				sscanf (pos+1, "%d", &unused);
			} 
		}
		pclose (fp);
	} else {
		cef_log_write (CefC_Log_Critical, "%s(%d): Could not get memory information.\n", __FUNCTION__, __LINE__);
		return (-1);
	}		
	if (unused == 0 || used == 0) {
		cef_log_write (CefC_Log_Critical, "%s(%d): Could not find keyword(%s) to get memory information\n", 
					__FUNCTION__, tag);
		return (-1);
	}
	total_mega = used + unused;
	free_mega = unused;
#endif // CefC_MACOS

	/* Cache Strategy Management Resource Estimate */
	est_resource  = capacity * (uint64_t)(24+4+name_size);

	/* Cache Strategy Related (loopkup) Resource Estimates */
	est_resource += capacity * (uint64_t)(8+32+name_size);
	
	if (strcmp (cs_type, "memory") == 0) {
		/* Cache Resource Estimate */
		est_resource += capacity * (uint64_t)(8+40+name_size+cob_size);
	} else {
		est_resource += free_mega * 1024000 * 0.3;
	}
	
	if (free_mega * 1024000 * ALGO_MAX_MEM_USAGE / 100 < est_resource) {
		char* conf;
		if (strcmp (cs_type, "memory") == 0) {
			conf = "csmgrd";
		} else 
		if (strcmp (cs_type, "filesystem") == 0) {
			conf = "csmgrd";
		} else {
			conf = "dbcache";
		}
		csmgrd_log_write (CefC_Log_Error, 
		    "Unable to use %s cache with specified algorithm due to lack of memory"
    		"resource. Unset algorithm, i.e., CACHE_ALGORITHM=None, in %s.conf.\n"
			"	(Detected Memory Size="FMTU64"\n"
			"	 Estimated available memory size="FMTU64"\n"
			"	 Memory size that the algorithm is expected to use="FMTU64")\n",
			cs_type, conf, 
			free_mega * 1024000,
			free_mega * 1024000 * ALGO_MAX_MEM_USAGE / 100,
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
	
	strcpy (log_porc, proc_name);
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
	assert (log_porc[0] != 0x00);
	
    if (log_lv == 0) {
		use_log_level = CefC_Log_Error;
	} else if (log_lv == 1) {
		use_log_level = CefC_Log_Warn;
	} else {
		use_log_level = -1;
	}
	
	if (level >= use_log_level) {
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


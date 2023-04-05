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
 * conpubd_plugin.c
 */

//#define __CONPUBD_PLUGIN_SOURCE__

//#define	__CONPUBD_PLUGIN_SEND_ERROR__

#define		CONPUBD_PLUGIN_SEND_USLEEP	100000
#define		CONPUBD_PLUGIN_SEND_TIMEOUT	10000

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
#include <conpubd/conpubd_plugin.h>

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

static int
conpubd_log_trim_line_string (
	const char* p1, 							/* target string for trimming 			*/
	char* p2,									/* name string after trimming			*/
	char* p3									/* value string after trimming			*/
);

#ifdef CefC_Debug
static int
conpubd_dbg_trim_line_string (
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
conpubd_plugin_cob_msg_send (
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

	while( len > 0 ) {
		timeout.tv_sec  = 0;
		timeout.tv_usec = CONPUBD_PLUGIN_SEND_TIMEOUT;
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
#ifdef	__CONPUBD_PLUGIN_SEND_ERROR__
					fprintf(stderr, "[%s](res <=0): ########### ERROR=%s \n", __FUNCTION__, strerror (errno));
#endif
					if ( errno == EAGAIN ) {
						usleep(CONPUBD_PLUGIN_SEND_USLEEP);
					}
				}
				send_count++;
				if ( send_count > 10 ) {
					break;
				}
			}
		} else {
			if ( send_count == 0 ) {
#ifdef	__CONPUBD_PLUGIN_SEND_ERROR__
				fprintf(stderr, "[%s](%d): ########### n:%d   send_count:%d   len:%d   %s\n", 
										__FUNCTION__, __LINE__, n, send_count, len, strerror (errno));
#endif
				break;
			} else if ( send_count > 10 ) {
#ifdef	__CONPUBD_PLUGIN_SEND_ERROR__
				fprintf(stderr, "[%s](%d): ########### n:%d   send_count:%d   len:%d   %s\n", 
										__FUNCTION__, __LINE__, n, send_count, len, strerror (errno));
#endif
				break;
			}
			send_count++;
			if ( errno == EAGAIN ) {
				usleep(CONPUBD_PLUGIN_SEND_USLEEP);
			}
		}
	}
	return (0);

}


/*--------------------------------------------------------------------------------------
	Creates tye key from name and chunk number
----------------------------------------------------------------------------------------*/
int												/* length of the created key 			*/
conpubd_key_create (
	ConpubdT_Content_Entry* entry,
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
conpubd_name_chunknum_concatenate (
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

void
conpubd_log_init (
	const char*	proc_name,
	int			level
) {

	assert (proc_name != NULL);

	strcpy (log_porc, proc_name);
	log_lv = level;
}
void
conpubd_log_init2 (
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
		sprintf (file_path, "%s/conpubd.conf", config_file_dir);
	} else {
		wp = getenv (CefC_CEFORE_DIR);
		if (wp != NULL && wp[0] != 0) {
			sprintf (file_path, "%s/cefore/conpubd.conf", wp);
		} else {
			sprintf (file_path, "%s/conpubd.conf", CefC_CEFORE_DIR_DEF);
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
		res = conpubd_log_trim_line_string (buff, pname, ws);
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
conpubd_log_write (
	int level, 										/* logging level 					*/
	const char* fmt, 								/* output format					*/
	...												/* parameters						*/
) {
	va_list arg;
	int		use_log_level;
	char 		time_str[64];
	struct tm* 	timeptr;
	time_t 		timer;
	struct timeval t;
	
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
conpubd_dbg_init (
	const char* proc_name,
	const char* config_file_dir
) {
	char 	file_path[PATH_MAX];
	FILE* 	fp;
	char	buff[1024];
	char 	ws[1024];
	char 	pname[1024];
	int 	res;
	char* 	wp;

	assert (proc_name != NULL);
	strcpy (dbg_proc, proc_name);
	
	/* Records the debug level 			*/
	if (config_file_dir[0] != 0x00) {
		sprintf (file_path, "%s/conpubd.conf", config_file_dir);
	} else {
		wp = getenv (CefC_CEFORE_DIR);
		if (wp != NULL && wp[0] != 0) {
			sprintf (file_path, "%s/cefore/conpubd.conf", wp);
		} else {
			sprintf (file_path, "%s/conpubd.conf", CefC_CEFORE_DIR_DEF);
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
		res = conpubd_dbg_trim_line_string (buff, pname, ws);
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
conpubd_dbg_write (
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
conpubd_dbg_buff_write (
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
conpubd_dbg_trim_line_string (
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
conpubd_log_trim_line_string (
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

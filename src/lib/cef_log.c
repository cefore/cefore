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
 * cef_log.c
 */

#define __CEF_LOG_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <stdarg.h>
#include <assert.h>
#include <sys/time.h>

#include <cefore/cef_define.h>
#include <cefore/cef_log.h>

#ifdef CefC_Android
#include <android/log.h>
#endif // CefC_Android

/****************************************************************************************
 Macros
 ****************************************************************************************/

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/


/****************************************************************************************
 State Variables
 ****************************************************************************************/

static char log_porc[256] = {"unknown"};
static int 	log_lv = 0;
static char log_lv_str[4][16] = {"INFO", "WARNING", "ERROR", "CRITICAL"};

#ifdef CefC_Debug
static char dbg_proc[256] = {"unknown"};
static int 	dbg_lv = CefC_Dbg_None;
#endif // CefC_Debug

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

static int
cef_log_trim_line_string (
	const char* p1, 							/* target string for trimming 			*/
	char* p2,									/* name string after trimming			*/
	char* p3									/* value string after trimming			*/
);

#ifdef CefC_Debug
static int
cef_dbg_trim_line_string (
	const char* p1, 							/* target string for trimming 			*/
	char* p2,									/* name string after trimming			*/
	char* p3									/* value string after trimming			*/
);
#endif // CefC_Debug

/****************************************************************************************
 ****************************************************************************************/

void
cef_log_init (
	const char*	proc_name,
	int			level
) {

	assert (proc_name != NULL);
	
	strcpy (log_porc, proc_name);
	log_lv = level;	
}
void
cef_log_init2 (
	const char* config_file_dir, 
	int cefnetd_f
) {
	char* 	wp;
	char 	file_path[PATH_MAX*2];
	FILE* 	fp;
	char	buff[1024];
	char 	ws[1024];
	char 	pname[1024];
	int 	res;

	/* Update the log level information 	*/
	if (config_file_dir[0] != 0x00) {
		if (cefnetd_f==1) {
			sprintf (file_path, "%s/cefnetd.conf", config_file_dir);
		} else if (cefnetd_f==2) {
			sprintf (file_path, "%s/conpubd.conf", config_file_dir);
		} else {
			sprintf (file_path, "%s/csmgrd.conf", config_file_dir);
		}
		
	} else {
		wp = getenv (CefC_CEFORE_DIR);
		if (wp != NULL && wp[0] != 0) {
			if (cefnetd_f==1) {
				sprintf (file_path, "%s/cefore/cefnetd.conf", wp);
			} else if (cefnetd_f==2) {
				sprintf (file_path, "%s/cefore/conpubd.conf", wp);
			} else {
				sprintf (file_path, "%s/cefore/csmgrd.conf", wp);
			}
		} else {
			if (cefnetd_f==1) {
				sprintf (file_path, "%s/cefnetd.conf", CefC_CEFORE_DIR_DEF);
			} else if (cefnetd_f==2) {
				sprintf (file_path, "%s/conpubd.conf", CefC_CEFORE_DIR_DEF);
			} else {
				sprintf (file_path, "%s/csmgrd.conf", CefC_CEFORE_DIR_DEF);
			}
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
		res = cef_log_trim_line_string (buff, pname, ws);
		if (res < 0) {
			continue;
		}
		
		if (strcmp (pname, "CEF_LOG_LEVEL") == 0) {
			log_lv = atoi (ws);
			if (!(0<=log_lv && log_lv <= 2)){
				log_lv = 0;
			}
		}
	}
	fclose (fp);
	
}

void
cef_log_write (
	int level, 										/* logging level 					*/
	const char* fmt, 								/* output format					*/
	...												/* parameters						*/
) {
	va_list arg;
	int		use_log_level;
#ifndef CefC_Android
	char 		time_str[64];
	struct tm* 	timeptr;
	time_t 		timer;
	struct timeval t;
#endif // CefC_Android
	
	
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
#ifdef CefC_Android
		__android_log_vprint(
			level + ANDROID_LOG_INFO - CefC_Log_Info, log_porc, fmt, arg);
#else // CefC_Android
		timer 	= time (NULL);
		timeptr = localtime (&timer);
		strftime (time_str, 64, "%Y-%m-%d %H:%M:%S", timeptr);
		gettimeofday (&t, NULL);
		
		fprintf (stdout, "%s."FMTLINT" [%s] %s: "
			, time_str, t.tv_usec / 1000, log_porc, log_lv_str[level]);
		vfprintf (stdout, fmt, arg);
#endif // CefC_Android
		va_end (arg);
	}
}

#ifdef CefC_Debug

void
cef_dbg_init (
	const char* proc_name,
	const char* config_file_dir, 
	int cefnetd_f
) {
	char* 	wp;
	char 	file_path[PATH_MAX];
	FILE* 	fp;
	char	buff[1024];
	char 	ws[1024];
	char 	pname[1024];
	int 	res;
	
	/* Records the process name 		*/
	assert (proc_name != NULL);
	strcpy (dbg_proc, proc_name);
	
	/* Records the debug level information 			*/
	if (config_file_dir[0] != 0x00) {
		if (cefnetd_f==1) {
			sprintf (file_path, "%s/cefnetd.conf", config_file_dir);
		} else if (cefnetd_f==2) {
			sprintf (file_path, "%s/conpubd.conf", config_file_dir);
		} else {
			sprintf (file_path, "%s/csmgrd.conf", config_file_dir);
		}
		
	} else {
		wp = getenv (CefC_CEFORE_DIR);
		if (wp != NULL && wp[0] != 0) {
			if (cefnetd_f==1) {
				sprintf (file_path, "%s/cefore/cefnetd.conf", wp);
			} else if (cefnetd_f==2) {
				sprintf (file_path, "%s/cefore/conpubd.conf", wp);
			} else {
				sprintf (file_path, "%s/cefore/csmgrd.conf", wp);
			}
		} else {
			if (cefnetd_f==1) {
				sprintf (file_path, "%s/cefnetd.conf", CefC_CEFORE_DIR_DEF);
			} else if (cefnetd_f==2) {
				sprintf (file_path, "%s/conpubd.conf", CefC_CEFORE_DIR_DEF);
			} else {
				sprintf (file_path, "%s/csmgrd.conf", CefC_CEFORE_DIR_DEF);
			}
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
		res = cef_dbg_trim_line_string (buff, pname, ws);
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
cef_dbg_write (
	int level, 										/* debug level 						*/
	const char* fmt, 								/* output format					*/
	...												/* parameters						*/
) {
	va_list arg;
#ifndef CefC_Android
	char 		time_str[64];
	struct tm* 	timeptr;
	time_t 		timer;
	struct timeval t;
#endif // CefC_Android
	assert (level >= CefC_Dbg_Fine && level <= CefC_Dbg_Finest);
	assert (dbg_proc[0] != 0x00);
	
	if (level < dbg_lv) {
		va_start (arg, fmt);
#ifdef CefC_Android
		__android_log_vprint(ANDROID_LOG_DEBUG, dbg_proc, fmt, arg);
#else // CefC_Android
		timer 	= time (NULL);
		timeptr = localtime (&timer);
		strftime (time_str, 64, "%Y-%m-%d %H:%M:%S", timeptr);
		gettimeofday (&t, NULL);
		
		fprintf (stdout, 
			"%s."FMTLINT" [%s] DEBUG: ", time_str, t.tv_usec / 1000, dbg_proc);
		vfprintf (stdout, fmt, arg);
#endif // CefC_Android
		va_end (arg);
	}
}

void
cef_dbg_buff_write (
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
cef_dbg_trim_line_string (
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
cef_log_trim_line_string (
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



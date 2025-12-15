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
#include <cefore/cef_frame.h>
#include <cefore/cef_client.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/
#define	BUFSIZ_TIMESTR	BUFSIZ_64

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/


/****************************************************************************************
 State Variables
 ****************************************************************************************/

static char log_proc[256] = {"unknown"};
static int 	log_lv = 0;
static char log_lv_str[4][16] = {"INFO", "WARNING", "ERROR", "CRITICAL"};
static FILE *cef_log_fp = NULL;
static char log_local_sock_id[CefC_LOCAL_SOCK_ID_SIZ+1] = { "0" };

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

	strcpy (log_proc, proc_name);
	log_lv = level;
	cef_log_fp = stdout;
}

void
cef_log_init2 (
	const char* config_file_dir,
	int cefnetd_f
) {
	char* 	wp;
	char 	file_path[PATH_MAX*2];
	FILE* 	fp;
	char	buff[BUFSIZ_1K];
	char 	ws[BUFSIZ_1K];
	char 	pname[BUFSIZ_1K];
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
			if ( log_lv < 1 ){
				log_lv = 0;
			}
		}
		else if (strcmp (pname, CefC_ParamName_LocalSockId) == 0) {
			if (strlen (ws) > CefC_LOCAL_SOCK_ID_SIZ) {
				cef_log_write (CefC_Log_Warn,
					"%s must be less than or equal to %d.\n",
						CefC_ParamName_LocalSockId, CefC_LOCAL_SOCK_ID_SIZ);
				continue;
			}
			strcpy (log_local_sock_id, ws);
		}
	}
	fclose (fp);
}


void
cef_log_fopen (
	int port_num
) {
	char 	path_logfile[PATH_MAX];

	if (port_num == CefC_Unset_Port) {
		port_num = CefC_Default_PortNum;
	}
	sprintf(path_logfile, "/tmp/%s_%d_%s.log", log_proc, port_num, log_local_sock_id);
	if ( cef_log_fp && cef_log_fp != stdout ){
		fclose(cef_log_fp);
	}
	cef_log_fp = fopen (path_logfile, "a+");
	if ( cef_log_fp ){
		fclose (cef_log_fp);
		chmod(path_logfile, 0666);	/* all:RW */
		cef_log_fp = fopen (path_logfile, "a+");
	} else
		cef_log_fp = stdout;
}

void
cef_log_flush (void)
{
	if ( cef_log_fp )
		fflush (cef_log_fp);
}

void
cef_log_fprintf (
	const char* fmt, 								/* output format					*/
	...												/* parameters						*/
) {
	va_list arg;

	if ( !cef_log_fp )
		cef_log_fp = stdout;

	va_start (arg, fmt);
	vfprintf (cef_log_fp, fmt, arg);
	va_end (arg);
}

void
cef_log_write (
	int level, 										/* logging level 					*/
	const char* fmt, 								/* output format					*/
	...												/* parameters						*/
) {
	va_list arg;
	int		use_log_level;
	char 		time_str[BUFSIZ_TIMESTR];
	struct tm* 	timeptr;
	time_t 		timer;
	struct timeval t;

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
		va_start (arg, fmt);
		timer 	= time (NULL);
		timeptr = localtime (&timer);
		strftime (time_str, BUFSIZ_TIMESTR, "%Y-%m-%d %H:%M:%S", timeptr);
		gettimeofday (&t, NULL);

		fprintf (cef_log_fp, "%s."FMTLINT" [%s] %s: "
			, time_str, t.tv_usec / 1000, log_proc, log_lv_str[level]);
		vfprintf (cef_log_fp, fmt, arg);
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
	char	buff[BUFSIZ_1K];
	char 	ws[BUFSIZ_1K];
	char 	pname[BUFSIZ_1K];
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
#ifdef	cef_dbg_write
cef_dbg_write_origin (
#else	//	cef_dbg_write
cef_dbg_write (
#endif	//	cef_dbg_write
	int level, 										/* debug level 						*/
	const char* fmt, 								/* output format					*/
	...												/* parameters						*/
) {
	va_list arg;
	char 		time_str[BUFSIZ_TIMESTR];
	struct tm* 	timeptr;
	time_t 		timer;
	struct timeval t;
	assert (level >= CefC_Dbg_Fine && level <= CefC_Dbg_Finest);
	assert (dbg_proc[0] != 0x00);

	if (level < dbg_lv) {
		va_start (arg, fmt);
		timer 	= time (NULL);
		timeptr = localtime (&timer);
		strftime (time_str, BUFSIZ_TIMESTR, "%Y-%m-%d %H:%M:%S", timeptr);
		gettimeofday (&t, NULL);

		fprintf (stdout,
			"%s."FMTLINT" [%s] DEBUG: ", time_str, t.tv_usec / 1000, dbg_proc);
		vfprintf (stdout, fmt, arg);
		va_end (arg);
	}
}

void
cef_dbg_write_with_line (
	const char* func, 								/* function name					*/
	const int   lineno, 							/* line number						*/
	int level, 										/* debug level 						*/
	const char* usrfmt,								/* output format					*/
	...												/* parameters						*/
) {
	va_list arg;
	char 		time_str[BUFSIZ_TIMESTR], fmtbuf[BUFSIZ_1K];
	struct tm* 	timeptr;
	time_t 		timer;
	struct timeval t;
	assert (level >= CefC_Dbg_Fine && level <= CefC_Dbg_Finest);
	assert (dbg_proc[0] != 0x00);

	if (level < dbg_lv) {
		va_start (arg, usrfmt);
		timer 	= time (NULL);
		timeptr = localtime (&timer);
		strftime (time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeptr);
		gettimeofday (&t, NULL);

		snprintf(fmtbuf, sizeof(fmtbuf), "%s." FMTLINT " [%s] DEBUG: %s(%u) %s",
			time_str, t.tv_usec / 1000, dbg_proc, func, lineno, usrfmt);
		vfprintf (stdout, fmtbuf, arg);
		va_end (arg);
	}
}

void
cef_dbg_buff_write_with_line(
	const char* func, 								/* function name					*/
	const int   lineno, 							/* line number						*/
	int level, 										/* debug level 						*/
	const unsigned char* buff,						/* buffer							*/
	const size_t buff_size							/* buffer size						*/
) {
	char 		time_str[BUFSIZ_TIMESTR], fmtbuf[BUFSIZ_1K];
	struct tm* 	timeptr;
	time_t 		timer;
	struct timeval t;
	assert (level >= CefC_Dbg_Fine && level <= CefC_Dbg_Finest);
	assert (dbg_proc[0] != 0x00);

	if (level < dbg_lv) {
		timer 	= time (NULL);
		timeptr = localtime (&timer);
		strftime (time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeptr);
		gettimeofday (&t, NULL);

		fprintf (stdout, "%s." FMTLINT " [%s] DEBUG: %s(%u) -- 8< ---- 8< ---- 8< ---- 8< --\n",
					time_str, t.tv_usec / 1000, dbg_proc, func, lineno);
		fprintf (stdout, "%s." FMTLINT " [%s] DEBUG:        0  1  2  3  4  5  6  7    8  9  0  1  2  3  4  5\n",
					time_str, t.tv_usec / 1000, dbg_proc);

		for (int i = 0 ; i < buff_size ; i++) {
			char	wkbuf[8];
			const int	j = (0 < i && !(i % 16));
			if ( j ){
				fprintf (stdout, "%s\n", fmtbuf);
			}
			if ( !(i % 16) ){
				snprintf(fmtbuf, sizeof(fmtbuf), "%s." FMTLINT " [%s] DEBUG: %04X:",
					time_str, t.tv_usec / 1000, dbg_proc, i);
			} else if ( (i % 16) == 8 ){
				strcat(fmtbuf, "  ");
			}
			snprintf (wkbuf, sizeof(wkbuf), " %02X", buff[i]);
			strcat(fmtbuf, wkbuf);
		}
		fprintf (stdout, "%s\n", fmtbuf);
	}
}

void
#ifndef	cef_dbg_buff_write_name
cef_dbg_buff_write_name (
#else	//	cef_dbg_buff_write_name
cef_dbg_buff_write_name_with_line (
	const char* func, 								/* function name					*/
	const int   lineno, 							/* line number						*/
#endif	//	cef_dbg_buff_write_name
	int level, 										/* debug level 						*/
	const unsigned char* hdr_buff,
	int hdr_len,
	const unsigned char* buff,
	int len,
	const unsigned char* ftr_buff,
	int ftr_len
) {
	if (level < dbg_lv) {
		char workstr[CefC_Max_Length];
		char* wkp = workstr;

		if (hdr_len + len + ftr_len > CefC_Max_Length)
			return;

		memset (wkp, 0, sizeof (workstr));

		/* header */
		if (hdr_buff != NULL && hdr_len > 0) {
			memcpy (wkp, hdr_buff, hdr_len);
			wkp += hdr_len;
		}

		/* main */
		if ((dbg_lv-1) == CefC_Dbg_Finer) {
			if (buff != NULL && len > 0) {
				char xstr[CefC_Max_Length/2];
				int xlen = 0;
				xlen = cef_frame_conversion_name_to_uri ((unsigned char*)buff, len, xstr);
				strcat (wkp, xstr);
				wkp += xlen;
			}
		} else if ((dbg_lv-1) == CefC_Dbg_Finest){
			if (buff != NULL && len > 0) {
				char xstr[16];
				int dbg_x;
				int xlen = 0;
				for (dbg_x = 0; dbg_x < len; dbg_x++) {
					xlen += sprintf (xstr, " %02X", buff[dbg_x]);
					strcat (wkp, xstr);
				}
				wkp += xlen;
			}
		}

		/* footer */
		if (ftr_buff != NULL && ftr_len > 0) {
			memcpy (wkp, ftr_buff, ftr_len);
			wkp += ftr_len;
		}

#ifdef	cef_dbg_write
		cef_dbg_write_with_line (func, lineno, level, "%s", workstr);
#else	//	cef_dbg_write
		cef_dbg_write (level, "%s", workstr);
#endif	//	cef_dbg_write
	}
}


void
cef_dbg_dump_with_line(
	const char* func, 								/* function name					*/
	const int   lineno, 							/* line number						*/
	int level, 										/* debug level 						*/
	const unsigned char* buff,						/* buffer							*/
	const size_t buff_size,							/* buffer size						*/
	const char* usrfmt,								/* output format					*/
	...												/* parameters						*/
) {
	va_list arg;
	char 		time_str[BUFSIZ_TIMESTR], fmtbuf[BUFSIZ_1K];
	struct tm* 	timeptr;
	time_t 		timer;
	struct timeval t;
	assert (level >= CefC_Dbg_Fine && level <= CefC_Dbg_Finest);
	assert (dbg_proc[0] != 0x00);

	if (level < dbg_lv) {
		va_start (arg, usrfmt);
		timer 	= time (NULL);
		timeptr = localtime (&timer);
		strftime (time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeptr);
		gettimeofday (&t, NULL);

		snprintf(fmtbuf, sizeof(fmtbuf), "%s." FMTLINT " [%s] DEBUG: %s(%u) %s",
			time_str, t.tv_usec / 1000, dbg_proc, func, lineno, usrfmt);
		vfprintf (stdout, fmtbuf, arg);
		va_end (arg);

		for (int i = 0 ; i < buff_size ; i++) {
			char	wkbuf[8];
			const int	j = (0 < i && !(i % 16));
			if ( j ){
				fprintf (stdout, "%s\n", fmtbuf);
			}
			if ( !(i % 16) ){
				snprintf(fmtbuf, sizeof(fmtbuf), "%s." FMTLINT " [%s] DEBUG: %s(%u) %04X:",
					time_str, t.tv_usec / 1000, dbg_proc, func, lineno, i);
			} else if ( (i % 16) == 8 ){
				strcat(fmtbuf, " ");
			}
			snprintf (wkbuf, sizeof(wkbuf), " %02X", buff[i]);
			strcat(fmtbuf, wkbuf);
		}
		fprintf (stdout, "%s\n", fmtbuf);
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


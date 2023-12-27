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
 * cefput_verify.c
 */
 

#define __CEF_PUTVERIFYE_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>
#include <sys/time.h>
#include <time.h>
#include <sys/stat.h>

#include <cefore/cef_define.h>
#include <cefore/cef_frame.h>
#include <cefore/cef_client.h>
#include <cefore/cef_valid.h>
#include <cefore/cef_log.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/
#define CefC_BlockSize_Byte                 1024            /* option[-b] default */
#define CefC_Rate_Mbps                      5.0             /* option[-r] default */
#define CefC_RateMbps_Min                   0.001           /* option[-r] min    (1Kbps) */
#define CefC_RateMbps_Max                   1000.0		    /* option[-r] max    (1000Mbps) */
#define CefC_WaitCsmgrd_Sec                 1               /* option[-w] default */
#define CefC_WaitCsmgrd_Max                 3600            /* option[-w] max    (sec) */
#define CefC_WaitCsmgrd_Retry               0               /* option[-c] default */
#define CefC_WaitCsmgrd_Retry_Max           10              /* option[-c] max */
#define CefC_PutCsmgrd_Vercnt               3               /* option[-n] default */
#define CefC_PutCsmgrd_Limit                50              /* option[-n] max */
//#define CefC_PutCsmgrd_Limit              -1              /* Never give up */

#define CefC_Putfile_Max                    512000
#define CefC_UnixTime_Max                   2147483647      /* 32bit signed int */
                                                            /* 2038-1-19 3:14:7 (UTC) */

//#define TO_CSMGRD // Enable to connect directly to Csmgrd

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/
#ifdef CefC_Develop
typedef struct _CefT_loss_chunk  CefT_loss_chunk;
struct _CefT_loss_chunk {
	int s_chunk_num;
	int e_chunk_num;
	CefT_loss_chunk *next;
};
#endif // CefC_Develop


/****************************************************************************************
 State Variables
 ****************************************************************************************/

static int				app_running_f = 0;
static int				sig_catch_f = 0;
CefT_Client_Handle		fhdl;
#ifdef TO_CSMGRD
CefT_Client_Handle		cefnetd_fhdl;
#endif
static struct timeval	start_t;
static struct timeval	end_t;
static uint64_t			stat_send_frames = 0;
static uint64_t			stat_send_bytes = 0;
static struct timeval	check_end_t;
static uint64_t			stat_resend_frames = 0;
static uint64_t			stat_resend_bytes = 0;
static char*			ng_seq = NULL;
#ifdef CefC_Develop
static CefT_loss_chunk*	head_lc_p = NULL;
static int				loss_chunk_no = -1;
static uint64_t			stat_drop_frames = 0;
char					dbg_file_name[CefC_Max_Length];
#endif // CefC_Develop
static int				verify_only_f = 0;

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

static void
post_process (
	int retry_num,
	int put_limit_count
);
static void
sigcatch (
	int sig
);
static void
print_usage (
	void
);
static int
cefputv_check_chunk (
	unsigned char*		name,
	uint16_t			name_len,
	uint64_t			start_seq, 
	uint64_t			end_seq
);
static int
cefputv_parse_response (
	unsigned char*		res_seqnum, 
	uint64_t			start_seq, 
	uint64_t			end_seq
);
static int
cefputv_put_chunk (
	long				interval_us,
	int					block_size,
	long				sending_time_us,
	char*				filename,
	CefT_CcnMsg_MsgBdy	params
);
static void
cefputv_send_fibreg (
	unsigned char*		name,
	uint16_t			name_len
);

#ifdef CefC_Develop
static int
cefputv_read_debug_file (
	char* any_fname
);

static int
cefputv_trim_line_string (
	const char*			p1, 				/* target string for trimming 			*/
	char*				p2,					/* 1st value string after trimming		*/
	char*				p3					/* 2nd value string after trimming		*/
);

static void
cefputv_set_next_chunk_no (
	void
);
#endif // CefC_Develop

/****************************************************************************************
 ****************************************************************************************/
int main (
	int argc,
	char** argv
) {
	int res;
	unsigned char			buff[CefC_Max_Length];
	CefT_CcnMsg_OptHdr	opt;
	CefT_CcnMsg_MsgBdy		params;
	uint64_t				seqnum = 0;
	char					uri[1024];
	struct stat				statBuf;
	
	char					filename[1024];
	FILE*					fp;
	double					interval;
	long					interval_us;
	static struct timeval	now_t;
	uint64_t				next_tus;
	uint64_t				now_tus;
	uint64_t				now_tus2;
	uint64_t				now_ms;
	char*					work_arg;
	int						i;
	
	char					conf_path[PATH_MAX] = {0};
	int						port_num = CefC_Unset_Port;
	
	unsigned char*			work_buff = NULL;
	uint32_t				work_buff_idx = 0;
	int						cob_len;
	unsigned char			cob_buff[CefC_Max_Length*2];
	unsigned char			wbuff[CefC_Max_Length*2];
	
	long int				int_rate;
	long					sending_time_us;
	uint64_t				now_s;
	int						retry_num = 1;
	uint64_t				s_seqnum = 0;
	uint64_t				e_seqnum = 0;
	int						put_limit_count = 1;
	uint64_t				param_s_seqnum = UINT64_MAX;
	
	/***** flags 		*****/
	int						uri_f 		= 0;
	int						file_f 		= 0;
	int						rate_f 		= 0;
	int						blocks_f 	= 0;
	int						expiry_f 	= 0;
	int						cachet_f 	= 0;
	int						dir_path_f 	= 0;
	int						port_num_f 	= 0;
	int						wait_time_f	= 0;
	int						retry_cnt_f	= 0;
	int						verify_cnt_f	= 0;
	
	/***** parameters 	*****/
	uint64_t				cache_time	= CefC_UnixTime_Max;
	uint64_t				expiry		= CefC_UnixTime_Max;
	double					rate		= CefC_Rate_Mbps;
	int						block_size	= CefC_BlockSize_Byte;
	uint32_t				wait_time	= CefC_WaitCsmgrd_Sec;
	int						retry_cnt	= CefC_WaitCsmgrd_Retry;
	int						verify_cnt	= CefC_PutCsmgrd_Vercnt;
	
#ifdef CefC_Develop
	int						dbg_file_f	= 0;
#endif // CefC_Develop
	
	/*------------------------------------------
		Checks specified options
	--------------------------------------------*/
	uri[0] 			= 0;
	
	fprintf (stdout, "[cefput_verify] Start\n");
	fprintf (stdout, "[cefput_verify] Parsing parameters ... ");
	
	/* Inits logging 		*/
	cef_log_init ("cefput_verify", 1);
	
	/* Obtains options 		*/
	for (i = 1 ; i < argc ; i++) {
		
		work_arg = argv[i];
		if (work_arg == NULL || work_arg[0] == 0) {
			break;
		}
		if (strcmp (work_arg, "-f") == 0) {
			if (file_f) {
				fprintf (stdout, "ERROR: [-f] is duplicated.");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stdout, "ERROR: [-f] has no parameter.\n");
				print_usage ();
				return (-1);
			}
			work_arg = argv[i + 1];
			strcpy (filename, work_arg);
			file_f++;
			i++;
		} else if (strcmp (work_arg, "-r") == 0) {
			if (rate_f) {
				fprintf (stdout, "ERROR: [-r] is duplicated.");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stdout, "ERROR: [-r] has no parameter.\n");
				print_usage ();
				return (-1);
			}
			work_arg = argv[i + 1];
			rate = atof (work_arg);
			if (rate < CefC_RateMbps_Min) {
				rate = CefC_RateMbps_Min;
			}
			if (rate > CefC_RateMbps_Max) {
				rate = CefC_RateMbps_Max;
			}
			
			int_rate = (long int)(rate * 1000.0);
			rate = (double)int_rate / 1000.0;
			
			rate_f++;
			i++;
		} else if (strcmp (work_arg, "-b") == 0) {
			if (blocks_f) {
				fprintf (stdout, "ERROR: [-b] is duplicated.");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stdout, "ERROR: [-b] has no parameter.\n");
				print_usage ();
				return (-1);
			}
			work_arg = argv[i + 1];
			block_size = atoi (work_arg);
			
			if (block_size < 1) {
				block_size = 1;
			}
			if (block_size > 65000) {
				block_size = 65000;
			}
			blocks_f++;
			i++;
		} else if (strcmp (work_arg, "-e") == 0) {
			if (expiry_f) {
				fprintf (stdout, "ERROR: [-e] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stdout, "ERROR: [-e] has no parameter.\n");
				print_usage ();
				return (-1);
			}
			work_arg = argv[i + 1];
			expiry = atoi (work_arg);
			
			if ((expiry < 1) || (expiry > CefC_UnixTime_Max)) {
				fprintf (stdout, "ERROR: [-e] is 1 or more and less than %d.\n", CefC_UnixTime_Max);
				print_usage ();
				return (-1);
			}
			expiry_f++;
			i++;
		} else if (strcmp (work_arg, "-t") == 0) {
			if (cachet_f) {
				fprintf (stdout, "ERROR: [-t] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stdout, "ERROR: [-t] has no parameter.\n");
				print_usage ();
				return (-1);
			}
			work_arg = argv[i + 1];
			cache_time = atoi (work_arg);
			
			if ((cache_time < 0) || (cache_time > CefC_UnixTime_Max)) {
				fprintf (stdout, "ERROR: [-t] is 1 or more and less than %d.\n", CefC_UnixTime_Max);
				print_usage ();
				return (-1);
			}
			cachet_f++;
			i++;
		} else if (strcmp (work_arg, "-h") == 0) {
			print_usage ();
			exit (1);
		} else if (strcmp (work_arg, "-d") == 0) {
			if (dir_path_f) {
				fprintf (stderr, "ERROR: [-d] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stderr, "ERROR: [-d] has no parameter.\n");
				print_usage ();
				return (-1);
			}
			if (strlen(argv[i + 1]) > PATH_MAX) {
				fprintf (stderr, "ERROR: [-d] parameter is too long.\n");
				print_usage ();
				return (-1);
			}
			work_arg = argv[i + 1];
			strcpy (conf_path, work_arg);
			dir_path_f++;
			i++;
		} else if (strcmp (work_arg, "-p") == 0) {
			if (port_num_f) {
				fprintf (stderr, "ERROR: [-p] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stderr, "ERROR: [-p] has no parameter.\n");
				print_usage ();
				return (-1);
			}
			work_arg = argv[i + 1];
			port_num = atoi (work_arg);
			port_num_f++;
			i++;
		} else if (strcmp (work_arg, "-w") == 0) {
			if (wait_time_f) {
				fprintf (stdout, "ERROR: [-w] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stdout, "ERROR: [-w] has no parameter.\n");
				print_usage ();
				return (-1);
			}
			work_arg = argv[i + 1];
			wait_time = atoi (work_arg);
			
			if ((wait_time < 0) || (wait_time > CefC_WaitCsmgrd_Max)) {
				fprintf (stdout, "ERROR: [-w] is 0 or more and less than %d.\n", CefC_WaitCsmgrd_Max);
				print_usage ();
				return (-1);
			}
			wait_time_f++;
			i++;
		} else if (strcmp (work_arg, "-c") == 0) {
			if (retry_cnt_f) {
				fprintf (stdout, "ERROR: [-c] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stdout, "ERROR: [-c] has no parameter.\n");
				print_usage ();
				return (-1);
			}
			work_arg = argv[i + 1];
			retry_cnt = atoi (work_arg);
			
			if ((retry_cnt < 0) || (retry_cnt > CefC_WaitCsmgrd_Retry_Max)) {
				fprintf (stdout, "ERROR: [-c] is 1 or more and less than %d.\n", CefC_WaitCsmgrd_Retry_Max);
				print_usage ();
				return (-1);
			}
			retry_cnt_f++;
			i++;
		} else if (strcmp (work_arg, "-n") == 0) {
			if (verify_cnt_f) {
				fprintf (stdout, "ERROR: [-n] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stdout, "ERROR: [-n] has no parameter.\n");
				print_usage ();
				return (-1);
			}
			work_arg = argv[i + 1];
			verify_cnt = atoi (work_arg);
			
			if (CefC_PutCsmgrd_Limit != -1 && 
				((verify_cnt < 0) || (verify_cnt > CefC_PutCsmgrd_Limit))) {
				fprintf (stdout, "ERROR: [-n] is 1 or more and less than %d.\n", CefC_PutCsmgrd_Limit);
				print_usage ();
				return (-1);
			}
			verify_cnt_f++;
			i++;
		} else if (strcmp (work_arg, "-v") == 0) {
			if (verify_only_f) {
				fprintf (stdout, "ERROR: [-v] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			
			work_arg = argv[i + 1];
			if (work_arg != NULL && work_arg[0] != 0x2d) {	/* - */
				param_s_seqnum = strtoul (work_arg, NULL, 10);
				i++;
			}
			verify_only_f++;
#ifdef CefC_Develop
		} else if (strcmp (work_arg, "-dbg") == 0) {
			if (dbg_file_f) {
				fprintf (stdout, "ERROR: [-dbg] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stdout, "ERROR: [-dbg] has no parameter.\n");
				print_usage ();
				return (-1);
			}
			work_arg = argv[i + 1];
			strcpy (dbg_file_name, work_arg);
			
			dbg_file_f++;
			i++;
#endif // CefC_Develop
		} else {
			
			work_arg = argv[i];
			
			if (work_arg[0] == '-') {
				fprintf (stdout, 
					"ERROR: unknown option (%s) is specified.\n", work_arg);
				print_usage ();
				return (-1);
			}
			
			if (uri_f) {
				fprintf (stdout, "ERROR: uri is duplicated.\n");
				print_usage ();
				return (-1);
			}
			res = strlen (work_arg);
			
			if (res >= 1024) {
				fprintf (stdout, "ERROR: uri is too long.\n");
				print_usage ();
				return (-1);
			}
			strcpy (uri, work_arg);
			uri_f++;
		}
	}
	
	if (uri_f == 0) {
		fprintf (stdout, "ERROR: uri is not specified.\n");
		print_usage ();
		exit (1);
	}
	if (file_f == 0 && verify_only_f == 0) {
		fprintf (stdout, "ERROR: File name is not specified.\n");
		print_usage ();
		return (-1);
	}
	
	fprintf (stdout, "OK\n");
	cef_log_init2 (conf_path, 1/* for CEFNETD */);
#ifdef CefC_Debug
	cef_dbg_init ("cefput_verify", conf_path, 1);
#endif // CefC_Debug
	
	if (verify_only_f) {
		goto VO_NAME;
	}
	
#ifdef CefC_Develop
	/*------------------------------------------
		Check debug file
	--------------------------------------------*/
	if (dbg_file_f) {
		if(cefputv_read_debug_file (dbg_file_name) < 0) {
			exit (1);
		}
	} else {
		dbg_file_name[0] = 0x00;
	}
#endif // CefC_Develop
	
VO_NAME:
	/*------------------------------------------
		Creates the name from URI
	--------------------------------------------*/
	memset (&opt, 0, sizeof (CefT_CcnMsg_OptHdr));
	memset (&params, 0, sizeof (CefT_CcnMsg_MsgBdy));
	cef_frame_init ();
	res = cef_client_init (port_num, conf_path);
	if (res < 0) {
		fprintf (stdout, "ERROR: Failed to init the client package.\n");
		exit (1);
	}
	fprintf (stdout, "[cefput_verify] Init Cefore Client package ... OK\n");
	fprintf (stdout, "[cefput_verify] Conversion from URI into Name ... ");
	res = cef_frame_conversion_uri_to_name (uri, params.name);
	if (res < 0) {
		fprintf (stdout, "ERROR: Invalid URI is specified.\n");
		exit (1);
	}
	fprintf (stdout, "OK\n");
	
	params.name_len 	= res;
	params.chunk_num_f 	= 1;
	
	if (verify_only_f) {
		goto VO_CONN;
	}
	/*------------------------------------------
		Sets Expiry Time and RCT
	--------------------------------------------*/
	gettimeofday (&now_t, NULL);
	now_ms = now_t.tv_sec * 1000llu + now_t.tv_usec / 1000llu;
	
	now_s = now_t.tv_sec + 1;
	if (now_s + cache_time > CefC_UnixTime_Max) {
		cache_time = CefC_UnixTime_Max - now_s;
	}
	if (now_s + expiry > CefC_UnixTime_Max) {
		expiry = CefC_UnixTime_Max - now_s;
	}
	
	opt.cachetime_f 	= 1;
	opt.cachetime 	= now_ms + cache_time * 1000;
	
	if (expiry) {
		params.expiry = now_ms + expiry * 1000;
	} else {
		params.expiry = now_ms + 3600000;
	}
	
	/*------------------------------------------
		Checks the input file
	--------------------------------------------*/
	if (stat(filename, &statBuf) == 0) {
	} else {
		fprintf (stdout, "ERROR: the specified input file stat can not get.\n");
		exit (1);
	}
	fp = fopen (filename, "rb");
	fprintf (stdout, "[cefput_verify] Checking the input file ... ");
	if (fp == NULL) {
		fprintf (stdout, "ERROR: the specified input file can not be opened.\n");
		exit (1);
	}
	fprintf (stdout, "OK\n");
	
VO_CONN:
	/*------------------------------------------
		Connects to CEFORE
	--------------------------------------------*/
#ifndef TO_CSMGRD
	fprintf (stdout, "[cefput_verify] Connect to cefnetd ... ");
	fhdl = cef_client_connect ();
	if (fhdl < 1) {
		fprintf (stdout, "ERROR: cefnetd is not running.\n");
		exit (1);
	}
#else
	fprintf (stdout, "[cefput_verify] Connect to csmgrd ... ");
	fhdl = cef_client_connect_to_csmgrd ();
	if (fhdl < 1) {
		fprintf (stdout, "ERROR: csmgrd is not running.\n");
		exit (1);
	}
	fprintf (stdout, "OK\n");
	fprintf (stdout, "[cefput_verify] Connect to cefnetd ... ");
	cefnetd_fhdl = cef_client_connect ();
	if (cefnetd_fhdl < 1) {
		fprintf (stdout, "ERROR: cefnetd is not running.\n");
		exit (1);
	}
#endif
	fprintf (stdout, "OK\n");
	
	app_running_f = 1;
	fprintf (stdout, "[cefput_verify] URI            = %s\n", uri);
	if (!verify_only_f) {
		fprintf (stdout, "[cefput_verify] File           = %s\n", filename);
		fprintf (stdout, "[cefput_verify] Rate           = %.3f Mbps\n", rate);
		fprintf (stdout, "[cefput_verify] Block Size     = %d Bytes\n", block_size);
		fprintf (stdout, "[cefput_verify] Cache Time     = "FMTU64" sec\n", cache_time);
		fprintf (stdout, "[cefput_verify] Expiration     = "FMTU64" sec\n", expiry);
		fprintf (stdout, "[cefput_verify] Wait Time      = %d sec\n", wait_time);
		fprintf (stdout, "[cefput_verify] Retry (Verify) = %d time\n", verify_cnt);
		fprintf (stdout, "[cefput_verify] Retry (Csmgrd) = %d time\n", retry_cnt);
#ifdef CefC_Develop
		if (dbg_file_f) {
			fprintf (stdout, "[cefput_verify] Debug File     = %s\n", dbg_file_name);
		}
#endif // CefC_Develop
	} else {
		wait_time = 0;
		retry_cnt = 0;
		if (param_s_seqnum != UINT64_MAX) {
			if (param_s_seqnum > UINT32_MAX) {
				s_seqnum = 0;
			} else {
				s_seqnum = (uint32_t)param_s_seqnum;
			}
		} else {
			s_seqnum = 0;
		}
		e_seqnum = UINT32_MAX;
		goto VO_VERIFY;
	}
	
	/*------------------------------------------
		Calculates the interval
	--------------------------------------------*/
	interval = (rate * 1000000.0) / (double)(block_size * 8);
	interval_us = (long)((1.0 / interval) * 1000000.0);
	sending_time_us = (long)(((double)(block_size * 8) / (rate * 1000000.0)) * 1000000.0);
	
	/*------------------------------------------
		Main Loop
	--------------------------------------------*/
	gettimeofday (&start_t, NULL);
	next_tus = start_t.tv_sec * 1000000llu + start_t.tv_usec + interval_us;
	work_buff = (unsigned char*) malloc (sizeof (unsigned char) * CefC_Putfile_Max);
	
	fprintf (stdout, "[cefput_verify] Start creating Content Objects\n");
	
	while (app_running_f) {
		if (SIG_ERR == signal (SIGINT, sigcatch)) {
			break;
		}
		cob_len = 0;
		
		while (work_buff_idx < 1) {
			res = fread (buff, sizeof (unsigned char), block_size, fp);
			if(seqnum > UINT32_MAX){
				res = 0;
			}
			cob_len = 0;
			
			if (res > 0) {
#ifdef CefC_Develop
				if (loss_chunk_no != -1 &&
					loss_chunk_no == seqnum) {
					cefputv_set_next_chunk_no();
					seqnum++;
					stat_drop_frames++;
					continue;
				}
#endif // CefC_Develop
				
				memcpy (params.payload, buff, res);
				params.payload_len = (uint16_t) res;
				params.chunk_num = (uint32_t)seqnum;
				
				if ( (stat_send_bytes + res) == statBuf.st_size ) {
					params.end_chunk_num_f = 1;
					params.end_chunk_num = seqnum;
				}
#ifndef TO_CSMGRD
				cob_len = cef_frame_object_create (cob_buff, &opt, &params);
#else	//TO_CSMGRD
				cob_len = cef_frame_object_create_for_csmgrd (wbuff, &opt, &params);
				{
					uint16_t index = 0;
					uint16_t value16;
					uint32_t value32;
					uint64_t value64;
					int chunk_field_len = CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum;
					uint16_t value16_namelen;
					struct in_addr node;
					
					/* Creates Upload Request message 		*/
					/* set header */
					cob_buff[CefC_O_Fix_Ver]  = CefC_Version;
					cob_buff[CefC_O_Fix_Type] = 0x03/*** CefC_Csmgr_Msg_Type_UpReq ***/;
					index += 4 /*** CefC_Csmgr_Msg_HeaderLen ***/;
						
					/* set payload length */
					value16 = htons (params.payload_len);
					memcpy (cob_buff + index, &value16, CefC_S_Length);
					index += CefC_S_Length;
						
					/* set cob message */
					value16 = htons (cob_len);
					memcpy (cob_buff + index, &value16, CefC_S_Length);
					memcpy (cob_buff + index + CefC_S_Length, wbuff, cob_len);
					index += CefC_S_Length + cob_len;
						
					/* set cob name */
					value16_namelen = params.name_len;
					value16 = htons (value16_namelen);
					memcpy (cob_buff + index, &value16, CefC_S_Length);
					memcpy (cob_buff + index + CefC_S_Length, params.name, value16_namelen);
					index += CefC_S_Length + value16_namelen;
						
					/* set chunk num */
					value32 = htonl (params.chunk_num);
					memcpy (cob_buff + index, &value32, CefC_S_ChunkNum);
					index += CefC_S_ChunkNum;
						
					/* set cache time */
					value64 = cef_client_htonb (opt.cachetime*1000);
					memcpy (cob_buff + index, &value64, CefC_S_Cachetime);
					index += CefC_S_Cachetime;
						
					/* set expiry */
					value64 = cef_client_htonb (params.expiry*1000);
					memcpy (cob_buff + index, &value64, CefC_S_Expiry);
					index += CefC_S_Expiry;
					
					/* get address */
					/* check local face flag */
					node.s_addr = 0;
					/* set address */
					memcpy (cob_buff + index, &node, sizeof (struct in_addr));
					index += sizeof (struct in_addr);
					
					/* set Length */
					value16 = htons (index);
					memcpy (cob_buff + CefC_O_Length, &value16, CefC_S_Length);
					
					/* ADD MAGIC */
					value16 = htons (index+3);
					memcpy (cob_buff + CefC_O_Length, &value16, CefC_S_Length);
					cob_buff[index]   = 0x63;
					cob_buff[index+1] = 0x6f;
					cob_buff[index+2] = 0x62;
					index += 3;
					
					cob_len = index;
				}
#endif	//TO_CSMGRD
				if ( cob_len < 0 ) {
					fprintf (stdout, "ERROR: Content Object frame size over(%d).\n", cob_len*(-1));
					fprintf (stdout, "       Try shortening the block size specification.\n");
					exit (1);
				}
				
				if (work_buff_idx + cob_len <= CefC_Putfile_Max) {
					memcpy (&work_buff[work_buff_idx], cob_buff, cob_len);
					work_buff_idx += cob_len;
					cob_len = 0;
					
					stat_send_frames++;
					stat_send_bytes += res;
					
					seqnum++;
				} else {
					break;
				}
			} else {
				app_running_f = 0;
				break;
			}
		}
		gettimeofday (&now_t, NULL);
		now_tus = now_t.tv_sec * 1000000llu + now_t.tv_usec;
		
		if (next_tus > now_tus) {
			usleep ((useconds_t)(next_tus - now_tus));
		}
		gettimeofday (&now_t, NULL);
		now_tus2 = now_t.tv_sec * 1000000llu + now_t.tv_usec;
		
		next_tus = now_tus + interval_us + sending_time_us + (next_tus - now_tus2);
		
		if (work_buff_idx > 0) {
#ifndef TO_CSMGRD
			cef_client_message_input (fhdl, work_buff, work_buff_idx);
#else
			cef_client_message_input (fhdl, work_buff, work_buff_idx);
#endif
			work_buff_idx = 0;
		} else {
			break;
		}
		
		if (cob_len > 0) {
			memcpy (&work_buff[work_buff_idx], cob_buff, cob_len);
			work_buff_idx += cob_len;
			
			stat_send_frames++;
			stat_send_bytes += res;
			
			seqnum++;
		}
	}
	gettimeofday (&end_t, NULL);
	
	fclose (fp);
	
	if (work_buff) {
		free (work_buff);
	}
	
	if (sig_catch_f) {
		post_process (retry_num, put_limit_count);
		exit (0);
	}
	
	e_seqnum = seqnum - 1;
	
	do {
		fprintf (stdout, "[cefput_verify]   wait %d sec...\n", wait_time);
		sleep(wait_time);
		
		if (sig_catch_f) {
			post_process (retry_num, put_limit_count);
			exit (0);
		}
		
VO_VERIFY:
		if (s_seqnum == e_seqnum)
			fprintf (stdout, "[cefput_verify] Start verify ("FMTU64")\n", s_seqnum);
		else {
			if (e_seqnum < UINT32_MAX)
				fprintf (stdout, "[cefput_verify] Start verify ("FMTU64"-"FMTU64")\n", s_seqnum, e_seqnum);
			else
				fprintf (stdout, "[cefput_verify] Start verify ("FMTU64"- )\n", s_seqnum);
		}
		
		res = cefputv_check_chunk (params.name, params.name_len, s_seqnum, e_seqnum);
		if (verify_only_f) {
			goto VO_END;
		}
		
		if (res < 0) {
			fprintf (stdout, "[cefput_verify] Put chunk...(%d)\n", put_limit_count);
			cefputv_put_chunk (interval_us, block_size, sending_time_us, filename, params);
			free (ng_seq);
			ng_seq = NULL;
		} else if (res == 0) {
			/* retry */
			if (retry_num <= retry_cnt) {
				fprintf (stdout, "[cefput_verify] Retry...(%d/%d)\n", retry_num, retry_cnt);
				res = -1;
				retry_num++;
			} else {
				fprintf (stdout, "[cefput_verify] Retry Over...\n");
				res = -1;
				retry_num++;
				break;
			}
		}
		
		if (res > 0) {
			break;
		}
		put_limit_count++;
		if (verify_cnt >= 0 &&
			put_limit_count >= (verify_cnt+1)) {
			fprintf (stdout, "[cefput_verify] Give up to verify...(%d times put)\n", put_limit_count);
			res = 0;
			break;
		}
	} while (res < 0);
	
	gettimeofday (&check_end_t, NULL);
	
	if (res > 0) {
		cefputv_send_fibreg (params.name, params.name_len);
	}
	
VO_END:
	post_process (retry_num, put_limit_count);
	exit (0);
}


static void
print_usage (
	void
) {
	
	fprintf (stdout, "\nUsage: cefput_verify\n");
	fprintf (stdout, "  cefput_verify uri -f path [-b block_size] [-r rate] [-e expiry] "
					 "[-t cache_time] [-d config_file_dir] [-p port_num] "
					 "[-w wait_time] [-c retry_count] [-n verify_count] [-v (start)] \n\n");
	fprintf (stderr, "  uri              Specify the URI.\n");
	fprintf (stdout, "  path             Specify the file path of output. \n");
	fprintf (stdout, "  block_size       Specifies the max payload length (bytes) of the Content Object.\n");
	fprintf (stdout, "  rate             Transfer rate to cefnetd (Mbps)\n");
	fprintf (stdout, "  expiry           Specifies the lifetime (seconds) of the Content Object.\n");
	fprintf (stdout, "  cache_time       Specifies the period (seconds) after which Content Objects are cached before they are deleted.\n");
	fprintf (stderr, "  config_file_dir  Configure file directory\n");
	fprintf (stderr, "  port_num         Port Number\n");
	fprintf (stderr, "  wait_time        Specify the time (seconds) to wait before checking cache storage after the first put.\n");
	fprintf (stderr, "  retry_count      Specify the number of times to retry when there is no response when inquiring missing Cob to csmgrd.\n");
	fprintf (stderr, "  verify_count     Specify the number of times to verify and sending missing chunk(s).\n");
	fprintf (stderr, "  -v (start)       Missing check only. Specify the starting position for (start).\n");
	fprintf (stdout, "  valid_algo       Specify the validation algorithm (crc32 or sha256)\n");

#ifndef CefC_Develop
	fprintf (stdout, "\n\n");
#else
	fprintf (stdout, "[-dbg debug_fname]\n\n");
#endif // CefC_Develop
}

static void
post_process (
	int retry_num,
	int put_limit_count
) {
	uint64_t	diff_t;
	double		diff_t_dbl = 0.0;
	double		thrpt = 0.0;
	uint64_t	send_bits;
	uint64_t	vdiff_t;
	double		vdiff_t_dbl = 0.0;
	uint64_t	WaitCsmgrdSec, WaitCsmgrdUSec;
	struct timeval diff_tval;
	struct timeval vdiff_tval;
	
	if (verify_only_f) {
		usleep (1000000);
#ifndef TO_CSMGRD
		fprintf (stdout, "[cefput_verify] Unconnect to cefnetd ... ");
#else
		fprintf (stdout, "[cefput_verify] Unconnect to cefnetd ... ");
		cef_client_close (cefnetd_fhdl);
		fprintf (stdout, "OK\n");
		fprintf (stdout, "[cefput_verify] Unconnect to csmgrd ... ");
#endif
		cef_client_close (fhdl);
		fprintf (stdout, "OK\n");
		
		fprintf (stdout, "[cefput_verify] Terminate\n");
		exit (0);
	}
	
	if (stat_send_frames) {
//		diff_t = ((end_t.tv_sec - start_t.tv_sec) * 1000000llu
//							+ (end_t.tv_usec - start_t.tv_usec));
		timersub( &end_t, &start_t, &diff_tval );
		diff_t = diff_tval.tv_sec * 1000000llu + diff_tval.tv_usec;
		WaitCsmgrdSec = CefC_WaitCsmgrd_Sec;
		WaitCsmgrdUSec = (CefC_WaitCsmgrd_Sec * 1000000) % 1000000;
//		vdiff_t = ((check_end_t.tv_sec - end_t.tv_sec - WaitCsmgrdSec) * 1000000llu
//							+ (check_end_t.tv_usec - end_t.tv_usec - WaitCsmgrdUSec));
		timersub( &check_end_t, &end_t, &vdiff_tval );
		vdiff_t = ((vdiff_tval.tv_sec - WaitCsmgrdSec) * 1000000llu) 
							+ (vdiff_tval.tv_usec - WaitCsmgrdUSec);
	} else {
		diff_t = 0;
		vdiff_t = 0;
	}
	usleep (1000000);
#ifndef TO_CSMGRD
	fprintf (stdout, "[cefput_verify] Unconnect to cefnetd ... ");
#else
	fprintf (stdout, "[cefput_verify] Unconnect to cefnetd ... ");
	cef_client_close (cefnetd_fhdl);
	fprintf (stdout, "OK\n");
	fprintf (stdout, "[cefput_verify] Unconnect to csmgrd ... ");
#endif
	cef_client_close (fhdl);
	fprintf (stdout, "OK\n");
	
	fprintf (stdout, "[cefput_verify] Terminate\n");
	fprintf (stdout, "[cefput_verify] Tx Frames   = "FMTU64"\n", stat_send_frames);
	fprintf (stdout, "[cefput_verify] Tx Bytes    = "FMTU64"\n", stat_send_bytes);
#ifdef CefC_Develop
	if (dbg_file_name[0] != 0x00) {
		fprintf (stdout, "[cefput_verify] Drop Frames = "FMTU64"\n", stat_drop_frames);
	}
#endif // CefC_Develop
	if (diff_t > 0) {
		diff_t_dbl = (double)diff_t / 1000000.0;
		fprintf (stdout, "[cefput_verify] Duration    = %.3f sec\n", diff_t_dbl + 0.0009);
		send_bits = stat_send_bytes * 8;
		thrpt = (double)(send_bits) / diff_t_dbl;
#ifndef TO_CSMGRD
		fprintf (stdout, "[cefput_verify] Throughput  = %lu bps\n", (unsigned long)thrpt);
#else
		fprintf (stdout, "[cefput_verify] Throughput  = %lu bps\n", (unsigned long)thrpt);
#endif
		fprintf (stdout, "[cefput_verify] Verify      = %d\n", (put_limit_count - 1));
		fprintf (stdout, "[cefput_verify]  Tx Frames  = "FMTU64"\n", stat_resend_frames);
		fprintf (stdout, "[cefput_verify]  Tx Bytes   = "FMTU64"\n", stat_resend_bytes);
		fprintf (stdout, "[cefput_verify] Retry       = %d\n", (retry_num - 1));
		if (sig_catch_f) {
			fprintf (stdout, "[cefput_verify] Verify Time = 0.000 sec\n");
		} else {
			vdiff_t_dbl = (double)vdiff_t / 1000000.0;
			fprintf (stdout, "[cefput_verify] Verify Time = %.3f sec\n", vdiff_t_dbl + 0.0009);
		}
	} else {
		fprintf (stdout, "[cefput_verify] Duration    = 0.000 sec\n");
		fprintf (stdout, "[cefput_verify] Verify Time = 0.000 sec\n");
	}
	
	exit (0);
}

static void
sigcatch (
	int			sig
) {
	if (sig == SIGINT) {
		fprintf (stdout, "[cefput_verify] Catch the signal\n");
		app_running_f = 0;
		sig_catch_f = 1;
	}
}

static int					/* Returns -1 if missing chunk */
cefputv_check_chunk (
	unsigned char*		name,
	uint16_t			name_len,
	uint64_t			start_seq, 
	uint64_t			end_seq
) {

	CefT_Ccninfo_TLVs		tlvs;
	int						check_running_f;
	int						res;
	unsigned char			buff[CefC_Max_Length];
	unsigned char			msg[CefC_Max_Length];
	struct timeval			t;
	uint64_t				now_time;
	uint64_t				end_time;
	int						index = 0;
	uint16_t				res_len;
	uint16_t				pkt_len;
	struct fixed_hdr*		fixhdr;
	CefT_Parsed_Ccninfo*	p_pci;
	CefT_Reply_SubBlk*		rep_p;
	
	/* Send Contents Information Request Message */
	memset (&tlvs, 0, sizeof (CefT_Ccninfo_TLVs));
	tlvs.hoplimit		= (uint8_t) 1;
	tlvs.name_len		= name_len;
	memcpy (tlvs.name, name, tlvs.name_len);
	srand ((unsigned) time (NULL));
	tlvs.opt.req_id	= (uint16_t)(rand () % 65535);
	tlvs.opt.req_id	|= 0x8080;
	tlvs.opt.putverify_f			= 1;
	tlvs.opt.putverify_msgtype	= CefC_CpvOp_ContInfoMsg;
	tlvs.opt.putverify_sseq		= (uint32_t)start_seq;
	tlvs.opt.putverify_eseq		= (uint32_t)end_seq;
	
#ifndef TO_CSMGRD
	res = cef_client_ccninfo_input (fhdl, &tlvs);
#else
	res = cef_client_ccninfo_input (cefnetd_fhdl, &tlvs);
#endif
	if (res < 0){
		exit (-1);
	}
	
	check_running_f = 1;
	
	gettimeofday (&t, NULL);
	end_time = (t.tv_sec + 10) * 1000000llu + t.tv_usec;
	
	while (check_running_f) {
		if (SIG_ERR == signal (SIGINT, sigcatch)) {
			break;
		}
		/* Obtains UNIX time 			*/
		gettimeofday (&t, NULL);
		now_time = t.tv_sec * 1000000llu + t.tv_usec;
		
		if (now_time > end_time) {
			/* failed */
			fprintf (stdout, "[cefput_verify] No response to Contents Information Request\n");
			check_running_f = 0;
			return (0);
		}
		
		/* Reads the message from cefnetd			*/
#ifndef TO_CSMGRD
		res = cef_client_read (fhdl, &buff[index], CefC_Max_Length - index);
#else
		res = cef_client_read (cefnetd_fhdl, &buff[index], CefC_Max_Length - index);
#endif
		
		if (res > 0) {
			res += index;
			
			do {
				fixhdr = (struct fixed_hdr*) buff;
				pkt_len = ntohs (fixhdr->pkt_len);
				
				if (res >= pkt_len) {
					//memset (&p_pci, 0x00, sizeof (CefT_Parsed_Ccninfo));
					
					/* Parses the received Ccninfo Replay 	*/
					p_pci = cef_frame_ccninfo_parse (buff);
					if (p_pci == NULL) {
						goto PKTLEN;
					}
					
					/* Check Reply */
					if (p_pci->pkt_type != CefC_PT_REPLY) {
						cef_frame_ccninfo_parsed_free (p_pci);
						goto PKTLEN;
					}
					
					if (p_pci->putverify_f &&
						p_pci->putverify_msgtype == CefC_CpvOp_ContInfoMsg) {
						/* Response to Contents Information Request */
						rep_p = p_pci->rep_blk;
						if (rep_p->rep_name_len == name_len &&
							memcmp (rep_p->rep_name, name, name_len) == 0) {
							goto CHECK_CONTENTS;
						} else {
							cef_frame_ccninfo_parsed_free (p_pci);
							goto PKTLEN;
						}
					} else {
						cef_frame_ccninfo_parsed_free (p_pci);
						goto PKTLEN;
					}
PKTLEN:;
					if (res - pkt_len > 0) {
						memcpy (msg, &buff[pkt_len], res - pkt_len);
						memcpy (buff, msg, res - pkt_len);
						index = res - pkt_len;
					} else {
						index = 0;
					}
					res -= pkt_len;
				} else {
					index = res;
					break;
				}
			} while (res > 0);
		}
	}
CHECK_CONTENTS:;
	
	/* check information */
	res = cefputv_parse_response (rep_p->rep_range, start_seq, end_seq);
	cef_frame_ccninfo_parsed_free (p_pci);
	
	return (res);
}

static int					/* Returns -1 if missing chunk */
cefputv_parse_response (
	unsigned char*		res_seqnum, 
	uint64_t			start_seq, 
	uint64_t			end_seq
) {
	int			s_find_f, e_find_f;
	char*		p;
	int			s_pos, e_pos;
	int			next_s_pos;
	int			prev_e_pos;
	int			s_val;
	char		wk_buff[CefC_Max_Length];
	char*		wk_buff_p;
	char*		wk_buff_end_p;
	int			wk_buff_len;
	char		tmp_buff[CefC_Max_Length];
	int			tmp_buff_len;
	
	s_find_f = 0;	/* If you find a start value, set it to 1. */
	e_find_f = 0;	/* If you find a end value, set it to 1. */
	s_val = start_seq;
	next_s_pos = -1;
	prev_e_pos = -1;
	
	memset (tmp_buff, 0x00, CefC_Max_Length);
	memset (wk_buff, 0x00, CefC_Max_Length);
	wk_buff_p = wk_buff;
	wk_buff_end_p = &wk_buff[CefC_Max_Length-1];
	
	/*-------------------------------------------------------------------------*/
	/* The value returned from csmgrd is always included in the request range. */
	/* [ start_seq <= res_seqnum <= end_seq ]                                  */
	/*-------------------------------------------------------------------------*/
	if (res_seqnum == NULL) {
		if (start_seq == end_seq) {
			wk_buff_len = sprintf (wk_buff, FMTU64", ", start_seq);
		} else {
			wk_buff_len = sprintf (wk_buff, FMTU64":"FMTU64", ", start_seq, end_seq);
		}
		ng_seq = (char*)malloc (wk_buff_len + 1);
		memcpy (ng_seq, wk_buff, wk_buff_len);
		ng_seq[wk_buff_len] = 0x00;
		fprintf (stdout, "[cefput_verify]   Missed: %s\n", ng_seq);
		return (-1);
	}
	
	p = strtok ((char*)res_seqnum, ",");
	while (p != NULL) {
		char*	colon_p;
		memset (tmp_buff, 0, CefC_Max_Length);
		
		colon_p = strstr (p, ":");
		if (colon_p != NULL) {
			int tmp_val_s, tmp_val_e;
			
			strncpy (tmp_buff, p, (colon_p - p));
			tmp_val_s = atoi (tmp_buff);
			strcpy (tmp_buff, (colon_p + 1));
			tmp_val_e = atoi (tmp_buff);
			prev_e_pos = tmp_val_e;
			
			if (!s_find_f) {
				/* The starting position has not been decided yet. */
				if (tmp_val_s == s_val) {
					s_pos = tmp_val_e + 1;
					s_find_f = 1;
					if (s_pos >= end_seq) {
						/* Reached the end of the check range. */
						e_pos = s_pos;
						e_find_f = 1;
						break;
					}
				} else {
					/* case: tmp_val_s > s_val */
					s_pos = s_val;
					s_find_f = 1;
					e_pos = tmp_val_s - 1;
					e_find_f = 1;
					next_s_pos = tmp_val_e + 1;
				}
			} else {
				/* Since the start position is fixed, decide the end position. */
				if (!e_find_f) {
					e_pos = tmp_val_s - 1;
					e_find_f = 1;
					next_s_pos = tmp_val_e + 1;
				} else {
					/* The end position has already been decided. */
					;
				}
			}
		} else {
			int tmp_val;
			tmp_val = atoi (p);
			prev_e_pos = tmp_val;
			
			if (!s_find_f) {
				/* The starting position has not been decided yet. */
				if (tmp_val == s_val) {
					s_pos = tmp_val + 1;
					s_find_f = 1;
					if (s_pos >= end_seq) {
						/* Reached the end of the check range. */
						e_pos = end_seq;
						e_find_f = 1;
						break;
					}
				} else {
					/* case: tmp_val > s_val */
					s_pos = s_val;
					s_find_f = 1;
					e_pos = tmp_val - 1;
					e_find_f = 1;
					next_s_pos = tmp_val + 1;
				}
			} else {
				/* Since the start position is fixed, decide the end position. */
				if (!e_find_f) {
					e_pos = tmp_val - 1;
					e_find_f = 1;
					next_s_pos = tmp_val + 1;
				} else {
					/* The end position has already been decided. */
					;
				}
			}
		}
		
		if (s_find_f && e_find_f) {
			if (s_pos > end_seq) {
				/* out of range */
				s_find_f = 0;
				e_find_f = 0;
				break;
			}
			if (s_pos == e_pos) {
				tmp_buff_len = sprintf (tmp_buff, "%d,", s_pos);
			} else if (s_pos < e_pos) {
				tmp_buff_len = sprintf (tmp_buff, "%d:%d,", s_pos, e_pos);
			}
			s_find_f = 0;
			e_find_f = 0;
			s_val = e_pos + 1;
			if ((wk_buff_p + tmp_buff_len) < wk_buff_end_p) {
				memcpy (wk_buff_p, tmp_buff, tmp_buff_len);
				wk_buff_p += tmp_buff_len;
			} else {
				/* can't write to buff anymore */
				break;
			}
			if (next_s_pos != -1) {
				s_pos = next_s_pos;
				s_find_f = 1;
				next_s_pos = -1;
			}
		}
		
		/* next seq */
		p = strtok (NULL, ",");
	}
	
	if (s_find_f && !e_find_f) {
		if (prev_e_pos < end_seq)
			e_pos = end_seq;
		else
			e_pos = s_pos;
		e_find_f = 1;
	}
	if (s_find_f && e_find_f) {
		if (s_pos > end_seq) {
			/* out of range */
			goto NOTADD;
		} else if (s_pos == e_pos) {
			tmp_buff_len = sprintf (tmp_buff, "%d,", s_pos);
		} else if (s_pos < e_pos) {
			tmp_buff_len = sprintf (tmp_buff, "%d:%d,", s_pos, e_pos);
		} else {
			goto NOTADD;
		}
		if ((wk_buff_p + tmp_buff_len) < wk_buff_end_p) {
			memcpy (wk_buff_p, tmp_buff, tmp_buff_len);
			wk_buff_p += tmp_buff_len;
		} else {
			/* can't write to buff anymore */
		}
	}
NOTADD:;
	
	wk_buff_len = strlen (wk_buff);
	if (wk_buff_len > 0) {
		if (ng_seq != NULL) {
			free (ng_seq);
		}
		ng_seq = (char*)malloc (wk_buff_len + 1);
		memcpy (ng_seq, wk_buff, wk_buff_len);
		ng_seq[wk_buff_len] = 0x00;
		fprintf (stdout, "[cefput_verify]   Missed: %s\n", ng_seq);
		return (-1);
	}
	if (verify_only_f) {
		fprintf (stdout, "[cefput_verify]   Inserted: %s\n", res_seqnum);
	} else {
		fprintf (stdout, "[cefput_verify]   ...all OK\n");
	}
	return (1);
}

static int
cefputv_put_chunk (
	long				interval_us,
	int					block_size,
	long				sending_time_us,
	char*				filename,
	CefT_CcnMsg_MsgBdy	params
) {
	struct timeval		retx_start_t;
	unsigned char*		work_buff = NULL;
	uint32_t			work_buff_idx = 0;
	int					cob_len;
	int					res;
	unsigned char		buff[CefC_Max_Length];
	uint64_t			seqnum = 0;
	unsigned char		cob_buff[CefC_Max_Length*2];
	unsigned char		wbuff[CefC_Max_Length*2];
	static struct		timeval now_t;
	uint64_t			next_tus;
	uint64_t			now_tus;
	uint64_t			now_tus2;
	uint64_t			now_ms;
	int					s_pos = 0;
	int					e_pos = 0;
	char*				p;
	char*				colon_p;
	char				tmp_buff[CefC_Max_Length];
	FILE*				fp;
	struct stat 		statBuf;
	char				copy_ng_seq[CefC_Max_Length];
	CefT_CcnMsg_OptHdr opt;
	
	gettimeofday (&retx_start_t, NULL);
	next_tus = retx_start_t.tv_sec * 1000000llu + retx_start_t.tv_usec + interval_us;
	work_buff = (unsigned char*) malloc (sizeof (unsigned char) * CefC_Putfile_Max);
	
	app_running_f = 1;
	
	if (stat(filename, &statBuf) == 0) {
	} else {
		fprintf (stdout, "ERROR: the specified input file stat can not get(2).\n");
		exit (1);
	}
	fp = fopen (filename, "rb");
	if (fp == NULL) {
		fprintf (stdout, "ERROR: the specified input file can not be opened(2).\n");
		exit (1);
	}
	
	memset (&opt, 0, sizeof (CefT_CcnMsg_OptHdr));
	memset (copy_ng_seq, 0x00, CefC_Max_Length);
	memcpy (copy_ng_seq, ng_seq, strlen (ng_seq));
	p = strtok (copy_ng_seq, ",");
	if (p == NULL) {
		fprintf (stdout, "ERROR: Invalid response from csmgrd.\n");
		exit (1);
	}
	colon_p = strstr (p, ":");
	if (colon_p != NULL) {
		strncpy (tmp_buff, p, (colon_p - p));
		s_pos = atoi (tmp_buff);
		strcpy (tmp_buff, (colon_p + 1));
		e_pos = atoi (tmp_buff);
	} else {
		s_pos = atoi (p);
		e_pos = s_pos;
	}
	
	while (app_running_f) {
		if (SIG_ERR == signal (SIGINT, sigcatch)) {
			break;
		}
		cob_len = 0;
		
		while (work_buff_idx < 1) {
			res = fread (buff, sizeof (unsigned char), block_size, fp);
			
			if (seqnum > e_pos) {
				p = strtok (NULL, ",");
				if (p == NULL) {
					app_running_f = 0;
					break;
				}
				colon_p = strstr (p, ":");
				if (colon_p != NULL) {
					strncpy (tmp_buff, p, (colon_p - p));
					s_pos = atoi (tmp_buff);
					strcpy (tmp_buff, (colon_p + 1));
					e_pos = atoi (tmp_buff);
				} else {
					s_pos = atoi (p);
					e_pos = s_pos;
				}
			}
			if (seqnum < s_pos) {
				seqnum++;
				continue;
			}
			
			if(seqnum > UINT32_MAX){
				res = 0;
			}
			cob_len = 0;
			
			if (res > 0) {
				memcpy (params.payload, buff, res);
				params.payload_len = (uint16_t) res;
				params.chunk_num = (uint32_t)seqnum;
				
				if ( (stat_resend_bytes + res) == statBuf.st_size ) {
					params.end_chunk_num_f = 1;
					params.end_chunk_num = seqnum;
				}
#ifndef TO_CSMGRD
				cob_len = cef_frame_object_create (cob_buff, &opt, &params);
#else	//TO_CSMGRD
				cob_len = cef_frame_object_create_for_csmgrd (wbuff, &opt, &params);
				{
					uint16_t index = 0;
					uint16_t value16;
					uint32_t value32;
					uint64_t value64;
					int chunk_field_len = CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum;
					uint16_t value16_namelen;
					struct in_addr node;
					
					/* Creates Upload Request message 		*/
					/* set header */
					cob_buff[CefC_O_Fix_Ver]  = CefC_Version;
					cob_buff[CefC_O_Fix_Type] = 0x03/*** CefC_Csmgr_Msg_Type_UpReq ***/;
					index += 4 /*** CefC_Csmgr_Msg_HeaderLen ***/;
						
					/* set payload length */
					value16 = htons (params.payload_len);
					memcpy (cob_buff + index, &value16, CefC_S_Length);
					index += CefC_S_Length;
						
					/* set cob message */
					value16 = htons (cob_len);
					memcpy (cob_buff + index, &value16, CefC_S_Length);
					memcpy (cob_buff + index + CefC_S_Length, wbuff, cob_len);
					index += CefC_S_Length + cob_len;
						
					/* set cob name */
					value16_namelen = params.name_len;
					value16 = htons (value16_namelen);
					memcpy (cob_buff + index, &value16, CefC_S_Length);
					memcpy (cob_buff + index + CefC_S_Length, params.name, value16_namelen);
					index += CefC_S_Length + value16_namelen;
					
					/* set chunk num */
					value32 = htonl (params.chunk_num);
					memcpy (cob_buff + index, &value32, CefC_S_ChunkNum);
					index += CefC_S_ChunkNum;
						
					/* set cache time */
					value64 = cef_client_htonb (opt.cachetime*1000);
					memcpy (cob_buff + index, &value64, CefC_S_Cachetime);
					index += CefC_S_Cachetime;
						
					/* set expiry */
					value64 = cef_client_htonb (params.expiry*1000);
					memcpy (cob_buff + index, &value64, CefC_S_Expiry);
					index += CefC_S_Expiry;
					/* get address */
					/* check local face flag */
					node.s_addr = 0;
					/* set address */
					memcpy (cob_buff + index, &node, sizeof (struct in_addr));
					index += sizeof (struct in_addr);
					
					/* set Length */
					value16 = htons (index);
					memcpy (cob_buff + CefC_O_Length, &value16, CefC_S_Length);
					
					/* ADD MAGIC */
					value16 = htons (index+3);
					memcpy (cob_buff + CefC_O_Length, &value16, CefC_S_Length);
					cob_buff[index]   = 0x63;
					cob_buff[index+1] = 0x6f;
					cob_buff[index+2] = 0x62;
					index += 3;
					
					cob_len = index;
				}
#endif	//TO_CSMGRD
				if ( cob_len < 0 ) {
					fprintf (stdout, "ERROR: Content Object frame size over(%d).\n", cob_len*(-1));
					fprintf (stdout, "       Try shortening the block size specification.\n");
					exit (1);
				}
				
				if (work_buff_idx + cob_len <= CefC_Putfile_Max) {
					memcpy (&work_buff[work_buff_idx], cob_buff, cob_len);
					work_buff_idx += cob_len;
					cob_len = 0;
					
					stat_resend_frames++;
					stat_resend_bytes += res;
					
					seqnum++;
				} else {
					break;
				}
			} else {
				app_running_f = 0;
				break;
			}
		}
		gettimeofday (&now_t, NULL);
		now_tus = now_t.tv_sec * 1000000llu + now_t.tv_usec;
		
		if (next_tus > now_tus) {
			usleep ((useconds_t)(next_tus - now_tus));
		}
		gettimeofday (&now_t, NULL);
		now_tus2 = now_t.tv_sec * 1000000llu + now_t.tv_usec;
		
		next_tus = now_tus + interval_us + sending_time_us + (next_tus - now_tus2);
		
		if (work_buff_idx > 0) {
			cef_client_message_input (fhdl, work_buff, work_buff_idx);
			work_buff_idx = 0;
		} else {
			break;
		}
		
		if (cob_len > 0) {
			memcpy (&work_buff[work_buff_idx], cob_buff, cob_len);
			work_buff_idx += cob_len;
			
			stat_resend_frames++;
			stat_resend_bytes += res;
			
			seqnum++;
		}
	}
	
	return (1);
}

static void
cefputv_send_fibreg (
	unsigned char*		name,
	uint16_t			name_len
) {
	CefT_CcnMsg_OptHdr opt;
	CefT_CcnMsg_MsgBdy		params;
	
	/* Send FIB registration request Message */
	memset (&opt, 0, sizeof (CefT_CcnMsg_OptHdr));
	memset (&params, 0, sizeof (CefT_CcnMsg_MsgBdy));
	params.hoplimit 		= 1;
	opt.lifetime_f 	= 1;
	opt.lifetime 	= CefC_Default_LifetimeSec * 1000;
	memcpy (params.name, name, name_len);
	params.name_len = name_len;
	params.org.putverify_f	= 1;
	params.org.putverify_msgtype = CefC_CpvOp_FibRegMsg;
	
	fprintf (stdout, "[cefput_verify] Send FIB registration request\n");
#ifndef TO_CSMGRD
	cef_client_interest_input (fhdl, &opt, &params);
#else
	cef_client_interest_input (cefnetd_fhdl, &opt, &params);
#endif
	
	return;
}

#ifdef CefC_Develop
static int
cefputv_read_debug_file (
	char*				any_fname
) {
	FILE*				fp;
	int 				res = 0;
	char 				st[1024];
	char 				ed[1024];
	CefT_loss_chunk*	wlc_p = NULL;
	int					lcnt = 0;
	char				buff[1024];
	
	head_lc_p = NULL;
	loss_chunk_no = 0;
	
	fp = fopen (any_fname, "r");
	fprintf (stdout, "[cefput_verify] Checking debug file ... ");
	if (fp == NULL) {
		fprintf (stdout, "ERROR: debug file can not be opened.\n");
		exit (1);
	}
	
	while (fgets (buff, 1023, fp) != NULL) {
		buff[1023] = 0;
		
		if (buff[0] == '#')
			continue;
		res = cefputv_trim_line_string (buff, st, ed);
		if (res < 0)
			continue;
		
		if (lcnt != 0) {
			wlc_p->next = (CefT_loss_chunk*)malloc (sizeof(CefT_loss_chunk));
			wlc_p = wlc_p->next;
		} else {
			wlc_p = (CefT_loss_chunk*)malloc (sizeof(CefT_loss_chunk));
			head_lc_p = wlc_p;
		}
		lcnt++;
		wlc_p->s_chunk_num = atoi (st);
		if (wlc_p->s_chunk_num < 0) {
			res = -1;
			goto LCP_FREE;
		}
		if (ed[0] != 0x00)
			wlc_p->e_chunk_num = atoi (ed);
		else
			wlc_p->e_chunk_num = wlc_p->s_chunk_num;
		if (wlc_p->e_chunk_num < 0) {
			res = -1;
			goto LCP_FREE;
		}
	}
	if (wlc_p != NULL)
		wlc_p->next = NULL;
	fclose (fp);
	
	res = 0;
	/* check value */
	wlc_p = head_lc_p;
	while (wlc_p != NULL) {
		if (wlc_p->s_chunk_num != wlc_p->e_chunk_num ) {
			if (wlc_p->s_chunk_num > wlc_p->e_chunk_num) {
				fprintf (stdout, "ERROR: %d-%d (start>end)[0x01]\n", wlc_p->s_chunk_num, wlc_p->e_chunk_num);
				res = -1;
				goto LCP_FREE;
			} else if (wlc_p->next != NULL &&
						wlc_p->e_chunk_num > wlc_p->next->s_chunk_num){
				fprintf (stdout, "ERROR: %d-%d (end>next start(%d))[0x02]\n", wlc_p->s_chunk_num, wlc_p->e_chunk_num, wlc_p->next->s_chunk_num);
				res = -1;
				goto LCP_FREE;
			}
		} else {
			if (wlc_p->next != NULL &&
				wlc_p->e_chunk_num > wlc_p->next->s_chunk_num){
				fprintf (stdout, "ERROR: %d-%d (end>next start(%d))[0x03]\n", wlc_p->s_chunk_num, wlc_p->e_chunk_num, wlc_p->next->s_chunk_num);
				res = -1;
				goto LCP_FREE;
			}
		}
		wlc_p = wlc_p->next;
	}
LCP_FREE:
	if (res < 0) {
		CefT_loss_chunk *tlc_p;
		
		wlc_p = head_lc_p;
		if (wlc_p != NULL) {
			tlc_p = wlc_p->next;
			free (wlc_p);
			wlc_p = tlc_p;
		}
		fprintf (stdout, "ERROR: invalid value.\n");
		exit (1);
	}
	if (0) {
		wlc_p = head_lc_p;
		fprintf(stderr, "Target chunks that are not put...\n");
		while (wlc_p != NULL) {
			fprintf(stderr, "    %d", wlc_p->s_chunk_num);
			if(wlc_p->e_chunk_num != wlc_p->s_chunk_num)
				fprintf(stderr, ":%d\n", wlc_p->e_chunk_num);
			else
				fprintf(stderr, "\n");
			wlc_p = wlc_p->next;
		}
	}
	
	if (head_lc_p != NULL) {
		loss_chunk_no = head_lc_p->s_chunk_num;
		fprintf (stdout, "OK\n");
	} else {
		res = -1;
		fprintf (stdout, "NG\n");
	}
		
	return (res);
}

static int
cefputv_trim_line_string (
	const char* p1, 							/* target string for trimming 			*/
	char* p2,									/* 1st value string after trimming		*/
	char* p3									/* 2nd value string after trimming		*/
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
		if (*wp == 0x3a /* ':' */) {
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
	
	if (equal_f < 0)
		*p3 = 0x00;
	if (*p2 != 0x00)
		equal_f = 1;
	return (equal_f);
}

static void
cefputv_set_next_chunk_no (
	void
) {
	CefT_loss_chunk *wlc_p;
	if (loss_chunk_no >= head_lc_p->s_chunk_num) {
		loss_chunk_no++;
	}
	if (loss_chunk_no > head_lc_p->e_chunk_num) {
		wlc_p = head_lc_p;
		head_lc_p = head_lc_p->next;
		if (head_lc_p == NULL)
			loss_chunk_no = -1;
		else
			loss_chunk_no = head_lc_p->s_chunk_num;
		free (wlc_p);
	}
	return;
}
#endif // CefC_Develop

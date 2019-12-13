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
 * cefputfile.c
 */
 

#define __CEF_PUTFILE_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>
#include <sys/time.h>

#include <cefore/cef_define.h>
#include <cefore/cef_frame.h>
#include <cefore/cef_client.h>
#include <cefore/cef_valid.h>
#include <cefore/cef_log.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

#define CefC_Putfile_Max 					512000
#define CefC_RateMbps_Max				 	32.0
#define CefC_RateMbps_Min				 	0.001	/* 1Kbps */


/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/


/****************************************************************************************
 State Variables
 ****************************************************************************************/

static int app_running_f = 0;
CefT_Client_Handle fhdl;
static struct timeval start_t;
static struct timeval end_t;
static uint64_t stat_send_frames = 0;
static uint64_t stat_send_bytes = 0;

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

static void
post_process (
	void
);
static void
sigcatch (
	int sig
);
static void
print_usage (
	void
);

/****************************************************************************************
 ****************************************************************************************/
int main (
	int argc,
	char** argv
) {
	int res;
	unsigned char buff[CefC_Max_Length];
	CefT_Object_TLVs params;
	int seqnum = 0;
	char uri[1024];
	
	char filename[1024];
	double interval;
	long interval_us;
	static struct timeval now_t;
	uint64_t next_tus;
	uint64_t now_tus;
	uint64_t now_tus2;
	uint64_t now_ms;
	char*	work_arg;
	int 	i;
	
	char 	conf_path[PATH_MAX] = {0};
	int 	port_num = CefC_Unset_Port;
	char 	valid_type[1024];
	
	unsigned char* 	work_buff = NULL;
	uint32_t 		work_buff_idx = 0;
	int 			cob_len;
	unsigned char 	cob_buff[CefC_Max_Length];
	
	int int_rate;
	long sending_time_us;
	
	/***** flags 		*****/
	int uri_f 		= 0;
	int file_f 		= 0;
	int rate_f 		= 0;
	int blocks_f 	= 0;
	int expiry_f 	= 0;
	int cachet_f 	= 0;
	int nsg_f 		= 0;
	int dir_path_f 	= 0;
	int port_num_f 	= 0;
	int valid_f 	= 0;
	
	/***** parameters 	*****/
	uint16_t cache_time 	= 300;
	uint64_t expiry 		= 3600;
	double rate 			= 5.0;
	int block_size 			= 1024;
	
	/*------------------------------------------
		Checks specified options
	--------------------------------------------*/
	uri[0] 			= 0;
	valid_type[0] 	= 0;
	
	fprintf (stdout, "[cefputfile] Start\n");
	fprintf (stdout, "[cefputfile] Parsing parameters ... ");
	
	/* Inits logging 		*/
	cef_log_init ("cefputfile");
	
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
			
			int_rate = (int)(rate * 1000.0);
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
			
			if (block_size < 60) {
				block_size = 60;
			}
			if (block_size > 1460) {
				block_size = 1460;
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
			
			if ((expiry < 1) || (expiry > 86400)) {
				expiry = 0;
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
			
			if ((cache_time < 0) || (cache_time > 65535)) {
				cache_time = 10;
			}
			cachet_f++;
			i++;
		} else if (strcmp (work_arg, "-z") == 0) {
			if (nsg_f) {
				fprintf (stdout, "ERROR: [-z] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stdout, "ERROR: [-z] has no parameter.\n");
				print_usage ();
				return (-1);
			}
			work_arg = argv[i + 1];
			if (strcmp (work_arg, "sg")) {
				fprintf (stdout, "ERROR: [-z] has the invalid parameter.\n");
				print_usage ();
				return (-1);
			}
			nsg_f++;
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
		} else if (strcmp (work_arg, "-v") == 0) {
			if (valid_f) {
				fprintf (stderr, "ERROR: [-v] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stderr, "ERROR: [-v] has no parameter.\n");
				print_usage ();
				return (-1);
			}
			work_arg = argv[i + 1];
			strcpy (valid_type, work_arg);
			valid_f++;
			i++;
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
			
			if (res >= 1204) {
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
	if (file_f == 0) {
		/* Use the last string in the URL */
		res = strlen (uri);
		if (res >= 1204) {
			fprintf (stdout, "ERROR: uri is too long.\n");
			print_usage ();
			return (-1);
		}
		if (uri[res - 1] == '/') {
			/* Ignore last '/' */
			res -= 2;
		}
		while (res > 0) {
			res--;
			if (uri[res] == '/') {
				res++;
				break;
			}
		}
		if (res <= 0) {
			fprintf (stdout, "ERROR: File name is not specified.\n");
			print_usage ();
			return (-1);
		}
		i = 0;
		while (1) {
			if ((uri[res + i] == '\0') || (uri[res + i] == '/')) {
				break;
			}
			i++;
		}
		strncpy (filename, uri + res, i);
		filename[i] = '\0';
	}
	if (nsg_f == 1) {
		cache_time 	= 0;
		expiry 		= 10;
	}
	fprintf (stdout, "OK\n");
#ifdef CefC_Debug
	cef_dbg_init ("cefputfile", conf_path, 1);
#endif // CefC_Debug
	
	/*------------------------------------------
		Creates the name from URI
	--------------------------------------------*/
	memset (&params, 0, sizeof (CefT_Object_TLVs));
	cef_frame_init ();
	res = cef_client_init (port_num, conf_path);
	if (res < 0) {
		fprintf (stdout, "ERROR: Failed to init the client package.\n");
		exit (1);
	}
	fprintf (stdout, "[cefputfile] Init Cefore Client package ... OK\n");
	fprintf (stdout, "[cefputfile] Conversion from URI into Name ... ");
	res = cef_frame_conversion_uri_to_name (uri, params.name);
	if (res < 0) {
		fprintf (stdout, "ERROR: Invalid URI is specified.\n");
		exit (1);
	}
	fprintf (stdout, "OK\n");
	
	params.name_len 	= res;
	params.chnk_num_f 	= 1;
	
	/*------------------------------------------
		Sets Expiry Time and RCT
	--------------------------------------------*/
	gettimeofday (&now_t, NULL);
	now_ms = now_t.tv_sec * 1000 + now_t.tv_usec / 1000;
	
	params.opt.cachetime_f 	= 1;
	params.opt.cachetime 	= now_ms + cache_time * 1000;
	
	if (expiry) {
		params.expiry = now_ms + expiry * 1000;
	} else {
		params.expiry = now_ms + 3600000;
	}
	
	/*------------------------------------------
		Checks the input file
	--------------------------------------------*/
	FILE* fp = fopen (filename, "rb");
	fprintf (stdout, "[cefputfile] Checking the input file ... ");
	if (fp == NULL) {
		fprintf (stdout, "ERROR: the specified input file can not be opened.\n");
		exit (1);
	}
	fprintf (stdout, "OK\n");
	
	/*------------------------------------------
		Set Validation Alglithm
	--------------------------------------------*/
	if (valid_f == 1) {
		cef_valid_init (conf_path);
		params.alg.valid_type = (uint16_t) cef_valid_type_get (valid_type);
		
		if (params.alg.valid_type == CefC_T_ALG_INVALID) {
			fprintf (stdout, "ERROR: -v has the invalid parameter %s\n", valid_type);
			exit (1);
		}
	}
	
	/*------------------------------------------
		Connects to CEFORE
	--------------------------------------------*/
	fprintf (stdout, "[cefputfile] Connect to cefnetd ... ");
	fhdl = cef_client_connect ();
	if (fhdl < 1) {
		fprintf (stdout, "ERROR: cefnetd is not running.\n");
		exit (1);
	}
	fprintf (stdout, "OK\n");
	
	app_running_f = 1;
	fprintf (stdout, "[cefputfile] URI         = %s\n", uri);
	fprintf (stdout, "[cefputfile] File        = %s\n", filename);
	fprintf (stdout, "[cefputfile] Rate        = %.3f Mbps\n", rate);
	fprintf (stdout, "[cefputfile] Block Size  = %d Bytes\n", block_size);
	fprintf (stdout, "[cefputfile] Cache Time  = %d sec\n", cache_time);
	fprintf (stdout, "[cefputfile] Expiration  = "FMTU64" sec\n", expiry);
	
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
	
	fprintf (stdout, "[cefputfile] Start creating Content Objects\n");
	
	while (app_running_f) {
		if (SIG_ERR == signal (SIGINT, sigcatch)) {
			break;
		}
		cob_len = 0;
		
		while (work_buff_idx < 1) {
			
			res = fread (buff, sizeof (unsigned char), block_size, fp);
			cob_len = 0;
			
			if (res > 0) {
				memcpy (params.payload, buff, res);
				params.payload_len = (uint16_t) res;
				params.chnk_num = seqnum;
				
				cob_len = cef_frame_object_create (cob_buff, &params);
				
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
			cef_client_message_input (fhdl, work_buff, work_buff_idx);
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
	
	post_process ();
	exit (0);
}

static void
print_usage (
	void
) {
	
	fprintf (stdout, "\nUsage: \n");
	fprintf (stdout, "  cefputfile uri -f path [-r rate] [-b block_size] [-e expiry] "
					 "[-t cache_time] [-v valid_algo] [-d config_file_dir] [-p port_num] \n\n");
	fprintf (stdout, 
		" valid_algo   Specify the validation algorithm (crc32 or sha256)\n\n");
}

static void
post_process (
	void
) {
	uint64_t diff_t;
	double diff_t_dbl = 0.0;
	double thrpt = 0.0;
	uint64_t send_bits;
	
	if (stat_send_frames) {
		diff_t = ((end_t.tv_sec - start_t.tv_sec) * 1000000llu
							+ (end_t.tv_usec - start_t.tv_usec));
	} else {
		diff_t = 0;
	}
	usleep (1000000);
	fprintf (stdout, "[cefputfile] Unconnect to cefnetd ... ");
	cef_client_close (fhdl);
	fprintf (stdout, "OK\n");
	
	fprintf (stdout, "[cefputfile] Terminate\n");
	fprintf (stdout, "[cefputfile] Tx Frames = "FMTU64"\n", stat_send_frames);
	fprintf (stdout, "[cefputfile] Tx Bytes  = "FMTU64"\n", stat_send_bytes);
	if (diff_t > 0) {
		diff_t_dbl = (double)diff_t / 1000000.0;
		fprintf (stdout, "[cefgetfile] Duration  = %.3f sec\n", diff_t_dbl + 0.0009);
		send_bits = stat_send_bytes * 8;
		thrpt = (double)(send_bits) / diff_t_dbl;
		fprintf (stdout, "[cefputfile] Thorghput = %d bps\n", (int)thrpt);
	} else {
		fprintf (stdout, "[cefgetfile] Duration  = 0.000 sec\n");
	}
	
	exit (0);
}

static void
sigcatch (
	int sig
) {
	if (sig == SIGINT) {
		fprintf (stdout, "[cefputfile] Catch the signal\n");
		app_running_f = 0;
	}
}

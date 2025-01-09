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
 * cefputstream.c
 */

#define __CEF_PUTSTREAM_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
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
#define CefC_RateMbps_Min				 	0.001	/* 1Kbps */

#define	T_USEC				(1000000)		/* 1(sec) = 1000000(usec)	*/

#define USAGE                print_usage(CefFp_Usage)
#define printerr(...)        fprintf(stderr,"[cefputstream] ERROR: " __VA_ARGS__)

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

static uint64_t stat_jitter_sum = 0;
static uint64_t stat_jitter_sq_sum = 0;
static uint64_t stat_jitter_max = 0;


/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

static void
post_process (
    FILE* ofp
);
static void
sigcatch (
	int sig
);
static void
print_usage (
    FILE* ofp
);

/****************************************************************************************
 ****************************************************************************************/
int main (
	int argc,
	char** argv
) {
	int res;
	unsigned char buff[CefC_Max_Length];
	CefT_CcnMsg_OptHdr opt;
	CefT_CcnMsg_MsgBdy params;
	uint64_t seqnum = 0;
	char uri[1024];
	size_t uri_len;

	double interval;
	long interval_us;
	static struct timeval now_t;
	uint64_t next_tus;
	uint64_t now_tus;
	uint64_t now_ms;
	uint64_t jitter;
	char*	work_arg;
	int 	i;
	int		input_res;

	char 	conf_path[PATH_MAX] = {0};
	int 	port_num = CefC_Unset_Port;

	char valid_type[1024];

	/***** flags 		*****/
	int uri_f 		= 0;
	int rate_f 		= 0;
	int blocks_f 	= 0;
	int expiry_f 	= 0;
	int cachet_f 	= 0;
	int dir_path_f 	= 0;
	int port_num_f 	= 0;
	int valid_f 	= 0;

	/***** parameters 	*****/
	uint64_t cache_time 	= 0;
	uint64_t expiry 		= 0;
	double rate 			= 5.0;
	int block_size 			= 1024;

	/*------------------------------------------
		Checks specified options
	--------------------------------------------*/
	uri[0] 			= 0;
	valid_type[0] 	= 0;

	printf ("[cefputstream] Start\n");

	/* Inits logging 		*/
	cef_log_init ("cefputstream", 1);

	/* Obtains options 		*/
	for (i = 1 ; i < argc ; i++) {

		work_arg = argv[i];
		if (work_arg == NULL || work_arg[0] == 0) {
			break;
		}

		if (strcmp (work_arg, "-r") == 0) {
			if (rate_f) {
				printerr("[-r] is duplicated.\n");
				USAGE;
				return (-1);
			}
			if (i + 1 == argc) {
				printerr("[-r] has no parameter.\n");
				USAGE;
				return (-1);
			}
			work_arg = argv[i + 1];
			rate = atof (work_arg);
			if ((rate < CefC_RateMbps_Min)) {
				rate = CefC_RateMbps_Min;
			}
			rate_f++;
			i++;
		} else if (strcmp (work_arg, "-b") == 0) {
			if (blocks_f) {
				printerr("[-b] is duplicated.\n");
				USAGE;
				return (-1);
			}
			if (i + 1 == argc) {
				printerr("[-b] has no parameter.\n");
				USAGE;
				return (-1);
			}
			work_arg = argv[i + 1];
			block_size = atoi (work_arg);

			if (block_size < 60) {
				block_size = 60;
			}
			if (block_size > CefC_Max_Block) {
				block_size = CefC_Max_Block;
			}
			blocks_f++;
			i++;
		} else if (strcmp (work_arg, "-e") == 0) {
			if (expiry_f) {
				printerr("[-e] is duplicated.\n");
				USAGE;
				return (-1);
			}
			if (i + 1 == argc) {
				printerr("[-e] has no parameter.\n");
				USAGE;
				return (-1);
			}
			work_arg = argv[i + 1];
			expiry = atoi (work_arg);

			if (expiry > 86400) {
				expiry = 86400;
			}
			expiry_f++;
			i++;
		} else if (strcmp (work_arg, "-t") == 0) {
			if (cachet_f) {
				printerr("[-t] is duplicated.\n");
				USAGE;
				return (-1);
			}
			if (i + 1 == argc) {
				printerr("[-t] has no parameter.\n");
				USAGE;
				return (-1);
			}
			work_arg = argv[i + 1];
			cache_time = atoi (work_arg);

			if ((cache_time < 0) || (cache_time > 65535)) {
				cache_time = 10;
			}
			cachet_f++;
			i++;
		} else if (strcmp (work_arg, "-v") == 0) {
			if (valid_f) {
				printerr("[-v] is duplicated.\n");
				USAGE;
				return (-1);
			}
			if (i + 1 == argc) {
				printerr("[-v] has no parameter.\n");
				USAGE;
				return (-1);
			}
			work_arg = argv[i + 1];
			strcpy (valid_type, work_arg);
			valid_f++;
			i++;
		} else if (strcmp (work_arg, "-h") == 0) {
			USAGE;
			exit (1);
		} else if (strcmp (work_arg, "-d") == 0) {
			if (dir_path_f) {
				printerr("[-d] is duplicated.\n");
				USAGE;
				return (-1);
			}
			if (i + 1 == argc) {
				printerr("[-d] has no parameter.\n");
				USAGE;
				return (-1);
			}
			//202108
			if (strlen(argv[i + 1]) > PATH_MAX) {
				printerr("[-d] parameter is too long.\n");
				USAGE;
				return (-1);
			}
			work_arg = argv[i + 1];
			strcpy (conf_path, work_arg);
			dir_path_f++;
			i++;
		} else if (strcmp (work_arg, "-p") == 0) {
			if (port_num_f) {
				printerr("[-p] is duplicated.\n");
				USAGE;
				return (-1);
			}
			if (i + 1 == argc) {
				printerr("[-p] has no parameter.\n");
				USAGE;
				return (-1);
			}
			work_arg = argv[i + 1];
			port_num = atoi (work_arg);
			port_num_f++;
			i++;
		} else {

			work_arg = argv[i];

			if (work_arg[0] == '-') {
				printerr("unknown option is specified.\n");
				USAGE;
				return (-1);
			}

			if (uri_f) {
				printerr("uri is duplicated.\n");
				USAGE;
				return (-1);
			}
			res = strlen (work_arg);

			if (res >= 1024) {
				printerr("uri is too long.\n");
				USAGE;
				return (-1);
			}
			strcpy (uri, work_arg);
			uri_f++;
		}
	}

	if (uri_f == 0) {
		printerr("URI is not specified.\n");
		USAGE;
		exit (1);
	}
	printf ("[cefputstream] Parsing parameters ... OK\n");
	cef_log_init2 (conf_path, 1 /* for CEFNETD */);
#ifdef CefC_Debug
	cef_dbg_init ("cefputstream", conf_path, 1);
#endif // CefC_Debug

	/*------------------------------------------
		Creates the name from URI
	--------------------------------------------*/
	memset (&opt, 0, sizeof (CefT_CcnMsg_OptHdr));
	memset (&params, 0, sizeof (CefT_CcnMsg_MsgBdy));
	cef_frame_init ();
	res = cef_client_init (port_num, conf_path);
	if (res < 0) {
		printerr("Failed to init the client package.\n");
		exit (1);
	}
	printf ("[cefputstream] Init Cefore Client package ... OK\n");
	res = cef_frame_conversion_uri_to_name (uri, params.name);
	if (res < 0) {
		printerr("Invalid URI is specified.\n");
		exit (1);
	}
	uri_len = strlen (uri);
	if (uri_len && (uri[uri_len-1]=='/')) {
		printerr("Invalid URI specified. It is illegal for a URI to end with /.\n");
		exit (1);
	}
	params.name_len 	= res;
	params.chunk_num_f 	= 1;
	printf ("[cefputstream] Conversion from URI into Name ... OK\n");

	/*------------------------------------------
		Sets Expiry Time and RCT
	--------------------------------------------*/
	gettimeofday (&now_t, NULL);
//#382	now_ms = now_t.tv_sec * 1000 + now_t.tv_usec / 1000;
	now_ms = now_t.tv_sec * 1000llu + now_t.tv_usec / 1000llu;	//#382

	if (cache_time > 0) {
		opt.cachetime_f 	= 1;
		opt.cachetime 	= now_ms + cache_time * 1000;
	} else {
		opt.cachetime_f 	= 1;
		opt.cachetime 	= now_ms;
	}

	if (expiry > 0) {
		params.expiry = now_ms + expiry * 1000;
	} else {
		params.expiry = 0;
	}

	/*------------------------------------------
		Set Validation Alglithm
	--------------------------------------------*/
	if (valid_f == 1) {
		cef_valid_init (conf_path);
		params.alg.valid_type = (uint16_t) cef_valid_type_get (valid_type);

		if (params.alg.valid_type == CefC_T_ALG_INVALID) {
			printerr("-v has the invalid parameter %s\n", valid_type);
			exit (1);
		}
	}

	/*------------------------------------------
		Connects to CEFORE
	--------------------------------------------*/
	fhdl = cef_client_connect ();
	if (fhdl < 1) {
		printerr("cefnetd is not running.\n");
		exit (1);
	}
	app_running_f = 1;
	printf ("[cefputstream] Connect to cefnetd ... OK\n");

	/*------------------------------------------
		Calculates the interval
	--------------------------------------------*/
	interval = (double)((double) rate * T_USEC) / (double)(block_size * 8);
	interval_us = (long)((1.0 / interval) * T_USEC);

	/*------------------------------------------
		Main Loop
	--------------------------------------------*/
	printf ("[cefputstream] URI         = %s\n", uri);
	printf ("[cefputstream] Rate        = %f Mbps\n", rate);
	printf ("[cefputstream] Block Size  = %d Bytes\n", block_size);
	printf ("[cefputstream] Cache Time  = "FMTU64" sec\n", cache_time);
	printf ("[cefputstream] Expiration  = "FMTU64" sec\n", expiry);
	printf ("[cefputstream] Interval    = %lu us\n", interval_us);

	memset (buff, 1, CefC_Max_Length);
	gettimeofday (&start_t, NULL);
	next_tus = start_t.tv_sec * T_USEC + start_t.tv_usec;

	if (signal(SIGINT, sigcatch) == SIG_ERR){
		printerr("signal(SIGINT)");
	}
	if (signal(SIGTERM, sigcatch) == SIG_ERR){
		printerr("signal(SIGTERM)");
	}
	if (signal(SIGPIPE, sigcatch) == SIG_ERR){
		printerr("signal(SIGPIPE)");
	}
	printf ("[cefputstream] Start creating Content Objects\n");

	while (app_running_f) {
		gettimeofday (&now_t, NULL);
		now_tus = now_t.tv_sec * T_USEC + now_t.tv_usec;

		if (now_tus > next_tus) {

			if (stat_send_frames > 0) {
				jitter = (now_t.tv_sec - end_t.tv_sec) * T_USEC
								+ (now_t.tv_usec - end_t.tv_usec);

				stat_jitter_sum    += jitter;
				stat_jitter_sq_sum += jitter * jitter;
				if (jitter > stat_jitter_max) {
					stat_jitter_max = jitter;
				}
			}

			res = read (0, buff, block_size);
			if(seqnum > UINT32_MAX){
				res = 0;
			}

			if (res > 0) {
				memcpy (params.payload, buff, res);
				params.payload_len = (uint16_t) res;
				params.chunk_num = seqnum;
				//0.8.3
				input_res = cef_client_object_input (fhdl, &opt, &params);
				if ( input_res < 0 ) {
					printerr ("Content Object frame size over(%d).\n", input_res*(-1));
					printerr ("       Try shortening the block size specification.\n");
					exit (1);
				}
				stat_send_frames++;
				stat_send_bytes += res;
				seqnum++;

				gettimeofday (&end_t, NULL);
			} else {
				break;
			}
			next_tus = now_tus + interval_us;
		}
	}
	post_process (stdout);
	exit (0);
}

static void
print_usage (
	FILE* ofp
) {

	fprintf (ofp, "\nUsage: cefputstream\n");
	fprintf (ofp, "  cefputstream uri [-r rate] [-b block_size] [-e expiry] "
						  "[-t cache_time] [-v valid_algo] [-d config_file_dir] [-p port_num]\n\n");
	fprintf (ofp, "  uri              Specify the URI.\n");
	fprintf (ofp, "  rate             Transfer rate to cefnetd (Mbps)\n");
	fprintf (ofp, "  block_size       Specifies the max payload length (bytes) of the Content Object.\n");
	fprintf (ofp, "  expiry           Specifies the lifetime (seconds) of the Content Object.\n");
	fprintf (ofp, "  cache_time       Specifies the period (seconds) after which Content Objects are cached before they are deleted.\n");
	fprintf (ofp, "  valid_algo       Specify the validation algorithm (" CefC_ValidTypeStr_CRC32C " or " CefC_ValidTypeStr_RSA256 ")\n");
	fprintf (ofp, "  config_file_dir  Configure file directory\n");
	fprintf (ofp, "  port_num         Port Number\n\n");
}

static void
post_process (
	FILE* ofp
) {
	uint64_t diff_t;
	double diff_t_dbl = 0.0;
	double thrpt = 0.0;
	uint64_t send_bits;
	uint64_t jitter_ave;
	struct timeval diff_tval;

	if (stat_send_frames) {
		timersub( &end_t, &start_t, &diff_tval );
		diff_t = diff_tval.tv_sec * 1000000llu + diff_tval.tv_usec;
	} else {
		diff_t = 0;
	}
	usleep (T_USEC);
	cef_client_close (fhdl);
	fprintf (ofp, "[cefputstream] Unconnect to cefnetd ... OK\n");

	fprintf (ofp, "[cefputstream] Stop\n");
	fprintf (ofp, "[cefputstream] Tx Frames  = "FMTU64"\n", stat_send_frames);
	fprintf (ofp, "[cefputstream] Tx Bytes   = "FMTU64"\n", stat_send_bytes);
	if (diff_t > 0) {
		diff_t_dbl = (double)diff_t / 1000000.0;
		fprintf (ofp, "[cefputstream] Duration   = %.3f sec\n", diff_t_dbl + 0.0009);
		send_bits = stat_send_bytes * 8;
		thrpt = (double)(send_bits) / diff_t_dbl;
		fprintf (ofp, "[cefputstream] Throughput = %d bps\n", (int)thrpt);
	} else {
		fprintf (ofp, "[cefputstream] Duration   = 0.000 sec\n");
	}
	if (stat_send_frames > 0) {
		jitter_ave = stat_jitter_sum / stat_send_frames;

		fprintf (ofp, "[cefputstream] Jitter (Ave) = "FMTU64" us\n", jitter_ave);
		fprintf (ofp, "[cefputstream] Jitter (Max) = "FMTU64" us\n", stat_jitter_max);
		fprintf (ofp, "[cefputstream] Jitter (Var) = "FMTU64" us\n"
			, (stat_jitter_sq_sum / stat_send_frames) - (jitter_ave * jitter_ave));
	}
	exit (0);
}

static void
sigcatch (
	int sig
) {
	printf ("[cefputstream] Catch the signal\n");
	switch ( sig ){
	case SIGINT:
	case SIGTERM:
	case SIGPIPE:
		app_running_f = 0;
		break;
	}
}

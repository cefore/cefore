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
	CefT_Object_TLVs prames;
	int seqnum = 0;
	char uri[1024];
	char filename[1024];
	double interval;
	long interval_us;
	static struct timeval now_t;
	uint64_t next_tus;
	uint64_t now_tus;
	uint64_t now_ms;
	uint64_t jitter;
	char*	work_arg;
	int 	i;
	
	char 	conf_path[PATH_MAX] = {0};
	int 	port_num = CefC_Unset_Port;
	
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
	int key_path_f 	= 0;
	
	/***** parameters 	*****/
	uint16_t cache_time 	= 300;
	uint64_t expiry 		= 3600;
	int rate 				= 5;
	int block_size 			= 1024;
	
	/*------------------------------------------
		Checks specified options
	--------------------------------------------*/
	uri[0] = 0;
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
			rate = atoi (work_arg);
			if ((rate < 1) || (rate > 200)) {
				rate = 1;
			}
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
		} else if (strcmp (work_arg, "-k") == 0) {
			if (key_path_f) {
				fprintf (stderr, "ERROR: [-k] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			key_path_f++;
		} else {
			
			work_arg = argv[i];
			
			if (work_arg[0] == '-') {
				fprintf (stdout, "ERROR: unknown option is specified.\n");
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
		fprintf (stdout, "ERROR: [-f] is not specified.\n");
		exit (1);
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
	memset (&prames, 0, sizeof (CefT_Object_TLVs));
	cef_frame_init ();
	res = cef_client_init (port_num, conf_path);
	if (res < 0) {
		fprintf (stdout, "ERROR: Failed to init the client package.\n");
		exit (1);
	}
	fprintf (stdout, "[cefputfile] Init Cefore Client package ... OK\n");
	fprintf (stdout, "[cefputfile] Conversion from URI into Name ... ");
	res = cef_frame_conversion_uri_to_name (uri, prames.name);
	if (res < 0) {
		fprintf (stdout, "ERROR: Invalid URI is specified.\n");
		exit (1);
	}
	fprintf (stdout, "OK\n");
	
	prames.name_len 	= res;
	prames.chnk_num_f 	= 1;
	
	/*------------------------------------------
		Sets Expiry Time and RCT
	--------------------------------------------*/
	gettimeofday (&now_t, NULL);
	now_ms = now_t.tv_sec * 1000 + now_t.tv_usec / 1000;
	
	prames.opt.cachetime_f 	= 1;
	prames.opt.cachetime 	= now_ms + cache_time * 1000;
	
	if (expiry) {
		prames.expiry = now_ms + expiry * 1000;
	} else {
		prames.expiry = now_ms + 3600000;
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
		Checks Validation 
	--------------------------------------------*/
	if (key_path_f) {
		prames.alg.pubkey_len = cef_valid_read_pubkey (conf_path, prames.alg.pubkey);
		
		if (prames.alg.pubkey_len > 0) {
			fprintf (stdout, "[cefputfile] Read the public key ... OK\n");
		} else {
			fprintf (stdout, "[cefputfile] Read the public key ... NG\n");
			fclose (fp);
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
	fprintf (stdout, "[cefputfile] Rate        = %d Mbps\n", rate);
	fprintf (stdout, "[cefputfile] Block Size  = %d Bytes\n", block_size);
	fprintf (stdout, "[cefputfile] Cache Time  = %d sec\n", cache_time);
	fprintf (stdout, "[cefputfile] Expiration  = "FMTU64" sec\n", expiry);
	
	/*------------------------------------------
		Calculates the interval
	--------------------------------------------*/
	interval = (double)((double) rate * 1000000.0) / (double)(block_size * 8);
	interval_us = (long)((1.0 / interval) * 1000000.0);

	/*------------------------------------------
		Main Loop
	--------------------------------------------*/
	cef_client_name_reg (fhdl, CefC_App_Reg, prames.name, prames.name_len);
	
	gettimeofday (&start_t, NULL);
	next_tus = start_t.tv_sec * 1000000 + start_t.tv_usec;
	
	fprintf (stdout, "[cefputfile] Start creating Content Objects\n");
	
	while (app_running_f) {
		if (SIG_ERR == signal (SIGINT, sigcatch)) {
			break;
		}
		gettimeofday (&now_t, NULL);
		now_tus = now_t.tv_sec * 1000000 + now_t.tv_usec;
		
		if (now_tus > next_tus) {
			
			if (stat_send_frames > 0) {
				jitter = (now_t.tv_sec - end_t.tv_sec) * 1000000
								+ (now_t.tv_usec - end_t.tv_usec);
				
				stat_jitter_sum    += jitter;
				stat_jitter_sq_sum += jitter * jitter;
				if (jitter > stat_jitter_max) {
					stat_jitter_max = jitter;
				}
			}
			
			res = fread (buff, sizeof (unsigned char), block_size, fp);
			
			if (res > 0) {
				memcpy (prames.payload, buff, res);
				prames.payload_len = (uint16_t) res;
				prames.chnk_num = seqnum;
				cef_client_object_input (fhdl, &prames);
				stat_send_frames++;
				stat_send_bytes += res;
				seqnum++;

				gettimeofday (&end_t, NULL);
			} else {
				break;
			}
			next_tus = now_tus + interval_us;
		}
		usleep ((useconds_t) interval_us);
	}
	fclose (fp);
	
	post_process ();
	exit (0);
}

static void
print_usage (
	void
) {
	
	fprintf (stdout, "\nUsage: \n");
	fprintf (stdout, "  cefputfile uri -f path [-r rate] [-b block_size] [-e expiry] "
					 "[-t cache_time]\n\n");
	
}

static void
post_process (
	void
) {
	uint64_t diff_t;
	uint64_t send_bits;
	uint64_t jitter_ave;
	
	if (stat_send_frames) {
		diff_t = ((end_t.tv_sec - start_t.tv_sec) * 1000000
							+ (end_t.tv_usec - start_t.tv_usec)) / 1000000;
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
	fprintf (stdout, "[cefputfile] Duration  = "FMTU64"\n", diff_t);
	if (diff_t > 0) {
		send_bits = stat_send_bytes * 8;
		fprintf (stdout, "[cefputfile] Thorghput = "FMTU64"\n", send_bits / diff_t);
	}
	if (stat_send_frames > 0) {
		jitter_ave = stat_jitter_sum / stat_send_frames;

		fprintf (stdout, "[cefputfile] Jitter (Ave) = "FMTU64" us\n", jitter_ave);
		fprintf (stdout, "[cefputfile] Jitter (Max) = "FMTU64" us\n", stat_jitter_max);
		fprintf (stdout, "[cefputfile] Jitter (Var) = "FMTU64" us\n"
			, (stat_jitter_sq_sum / stat_send_frames) - (jitter_ave * jitter_ave));
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

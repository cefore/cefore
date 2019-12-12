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
 * cefgetstream.c
 */

#define __CEF_GETSTREAM_SOURECE__

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
#define	DEFAULT_LIFETIME	4				/* 4.0 Sec	*/
#define	T_USEC				(1000000)		/* 1(sec) = 1000000(usec)	*/
#define	SESSION_LIFETIME	(10*T_USEC)		/* 10.0 Sec	*/

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/


/****************************************************************************************
 State Variables
 ****************************************************************************************/

static int app_running_f = 0;

static uint64_t stat_recv_frames = 0;
static uint64_t stat_recv_bytes = 0;
static uint64_t stat_jitter_sum = 0;
static uint64_t stat_jitter_sq_sum = 0;
static uint64_t stat_jitter_max = 0;
static struct timeval start_t;
static struct timeval end_t;
CefT_Client_Handle fhdl;

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
	int frame_size;
	int index = 0;
	char uri[1024];
	unsigned char buff[CefC_Max_Length];
	unsigned char frame[CefC_Max_Length];
	CefT_Interest_TLVs params;
	struct timeval t;
	uint64_t dif_time;
	uint64_t nxt_time;
	uint64_t now_time;
	uint64_t end_time;
	uint64_t jitter;
	uint32_t recv_num 	= 0;
	uint32_t chnk_num 	= 0;
	int pipeline 		= 4;
	int send_cnt 		= 0;
	char*	work_arg;
	int 	i;
	
	char 	conf_path[PATH_MAX] = {0};
	int 	port_num = CefC_Unset_Port;
	
	/***** flags 		*****/
	int uri_f 			= 0;
	int nsg_flag 		= 0;
	int dir_path_f 		= 0;
	int port_num_f 		= 0;
	int pipeline_f 		= 0;
	int key_path_f 		= 0;
	
	memset (&params, 0, sizeof (CefT_Interest_TLVs));
	
	fprintf (stderr, "[cefgetstream] Start\n");
	fprintf (stderr, "[cefgetstream] Parsing parameters ... ");
	
	/* Inits logging 		*/
	cef_log_init ("cefgetstream");
	
	/* Obtains options 		*/
	for (i = 1 ; i < argc ; i++) {
		
		work_arg = argv[i];
		if (work_arg == NULL || work_arg[0] == 0) {
			break;
		}
		
		if (strcmp (work_arg, "-z") == 0) {
			if (nsg_flag) {
				fprintf (stderr, "ERROR: [-z] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stderr, "ERROR: [-z] has no parameter.\n");
				return (-1);
			}
			work_arg = argv[i + 1];
			if (strcmp (work_arg, "sg")) {
				fprintf (stderr, "ERROR: [-z] has the invalid parameter.\n");
				print_usage ();
				return (-1);
			}
			nsg_flag++;
			i++;
		} else if (strcmp (work_arg, "-s") == 0) {
			if (pipeline_f) {
				fprintf (stderr, "ERROR: [-s] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stderr, "ERROR: [-s] has no parameter.\n");
				print_usage ();
				return (-1);
			}
			work_arg = argv[i + 1];
			pipeline = atoi (work_arg);
			if (pipeline > 32) {
				pipeline = 32;
			}
			if (pipeline < 1) {
				pipeline = 1;
			}
			pipeline_f++;
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
		} else if (strcmp (work_arg, "-k") == 0) {
			if (key_path_f) {
				fprintf (stderr, "ERROR: [-k] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			key_path_f++;
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
		} else {
			
			work_arg = argv[i];
			
			if (work_arg[0] == '-') {
				fprintf (stderr, "ERROR: unknown option is specified.\n");
				print_usage ();
				return (-1);
			}
			
			if (uri_f) {
				fprintf (stderr, "ERROR: uri is duplicated.\n");
				print_usage ();
				return (-1);
			}
			res = strlen (work_arg);
			
			if (res >= 1204) {
				fprintf (stderr, "ERROR: uri is too long.\n");
				print_usage ();
				return (-1);
			}
			strcpy (uri, work_arg);
			uri_f++;
		}
	}
	
	/* Checks errors 			*/
	if (uri_f == 0) {
		fprintf (stderr, "ERROR: uri is not specified.\n");
		print_usage ();
		exit (1);
	}
	fprintf (stderr, "OK\n");
#ifdef CefC_Debug
	cef_dbg_init ("cefgetstream", conf_path, 1);
#endif // CefC_Debug
	
	cef_frame_init ();
	res = cef_client_init (port_num, conf_path);
	if (res < 0) {
		fprintf (stderr, "ERROR: Failed to init the client package.\n");
		exit (1);
	}
	fprintf (stderr, "[cefgetstream] Init Cefore Client package ... OK\n");
	fprintf (stderr, "[cefgetstream] Conversion from URI into Name ... ");
	res = cef_frame_conversion_uri_to_name (uri, params.name);
	if (res < 0) {
		fprintf (stderr, "ERROR: Invalid URI is specified.\n");
		print_usage ();
		exit (1);
	}
	params.name_len = res;
	fprintf (stderr, "OK\n");
	fprintf (stderr, "[cefgetstream] Connect to cefnetd ... ");
	fhdl = cef_client_connect ();
	if (fhdl < 1) {
		fprintf (stderr, "ERROR: cefnetd is not running.\n");
		exit (1);
	}
	fprintf (stderr, "OK\n");
	
	/*------------------------------------------
		Checks Validation 
	--------------------------------------------*/
	if (key_path_f) {
		params.alg.pubkey_len = cef_valid_read_pubkey (conf_path, params.alg.pubkey);
		
		if (params.alg.pubkey_len > 0) {
			fprintf (stderr, 
				"[cefgetstream] Read the public key ... OK\n");
		} else {
			fprintf (stderr, 
				"[cefgetstream] Read the public key ... NG\n");
			exit (1);
		}
	}
	
	/* Sets Interest parameters 			*/
	params.hoplimit 			= 32;
	params.opt.lifetime_f 		= 1;
	params.opt.lifetime 		= DEFAULT_LIFETIME * 1000;
	
	if (nsg_flag) {
		params.opt.symbolic_f	= CefC_T_OPT_LONGLIFE;
		params.chunk_num_f 		= 0;
	} else {
		params.opt.symbolic_f	= CefC_T_OPT_REGULAR;
		params.chunk_num_f 		= 1;
		params.chunk_num		= 0;
	}

	gettimeofday (&t, NULL);
	now_time = cef_client_covert_timeval_to_us (t);
	if (nsg_flag) {
		dif_time = (uint64_t)((double) params.opt.lifetime * 0.8) * 1000;
		nxt_time = 0;
		end_time = now_time + 10000000;
	} else {
		dif_time = (uint64_t)((double) params.opt.lifetime * 0.3) * 1000;
		nxt_time = now_time + 10000000;
	}

	if (nsg_flag) {
		cef_client_interest_input (fhdl, &params);
		fprintf (stderr, "[cefgetstream] Start sending Long Life Interests\n");
	} else {
		fprintf (stderr, "[cefgetstream] Start sending Interests\n");
		
		/* Sends Initerest(s) 		*/
		for (i = 0 ; i < pipeline ; i++) {
			cef_client_interest_input (fhdl, &params);
			params.chunk_num++;
			usleep (10000);
		}
		end_t.tv_sec = t.tv_sec;
	}
	
	app_running_f = 1;
	fprintf (stderr, "[cefgetstream] Start sending Interests\n");
	cef_client_interest_input (fhdl, &params);
	fprintf (stderr, 
		"[cefgetstream] Send the Interest (ChunkNum=%u)\n", params.chunk_num);
	
	if (signal(SIGINT, sigcatch) == SIG_ERR){
		fprintf (stderr, "[cefgetstream] ERROR: signal(SIGINT)");
	}
	if (signal(SIGTERM, sigcatch) == SIG_ERR){
		fprintf (stderr, "[cefgetstream] ERROR: signal(SIGTERM)");
	}
	if (signal(SIGPIPE, sigcatch) == SIG_ERR){
		fprintf (stderr, "[cefgetstream] ERROR: signal(SIGPIPE)");
	}
	
	while (app_running_f) {
		gettimeofday (&t, NULL);
		now_time = cef_client_covert_timeval_to_us (t);

		if (nsg_flag) {
			if (now_time > end_time) {
				break;
			}
		}

		res = cef_client_read (fhdl, &buff[index], CefC_Max_Length - index);

		if (res > 0) {
			res += index;

			if (stat_recv_frames < 1) {
				start_t.tv_sec  = t.tv_sec;
				start_t.tv_usec = t.tv_usec;
			} else {
				jitter = (t.tv_sec - end_t.tv_sec) * T_USEC
								+ (t.tv_usec - end_t.tv_usec);

				stat_jitter_sum    += jitter;
				stat_jitter_sq_sum += jitter * jitter;
				if (jitter > stat_jitter_max) {
					stat_jitter_max = jitter;
				}
			}
			end_t.tv_sec  = t.tv_sec;
			end_t.tv_usec = t.tv_usec;
			if (nsg_flag) {
				end_time = now_time + SESSION_LIFETIME;
			}

			do {
				if (nsg_flag) {
					res = cef_client_payload_get (buff, res, frame, &frame_size);
				} else {
					res = cef_client_payload_get_with_chnk_num (
									buff, res, frame, &frame_size, &chnk_num);
				}

				if (frame_size > 0) {
					if (nsg_flag) {
						fwrite (frame, sizeof (unsigned char), frame_size, stdout);
					} else {
						params.chunk_num = chnk_num + 1;
						recv_num++;
						fwrite (frame, sizeof (unsigned char), frame_size, stdout);
						cef_client_interest_input (fhdl, &params);
						nxt_time = now_time + 4000000;
					}
					stat_recv_frames++;
					stat_recv_bytes += frame_size;
				}
			} while ((frame_size > 0) && (res > 0));

			if (res > 0) {
				index = res;
			} else {
				index = 0;
			}
		}

		/* Sends Interest with Symbolic flag to CEFORE 		*/
		if (now_time > nxt_time) {
			if (nsg_flag) {
				cef_client_interest_input (fhdl, &params);
				nxt_time = now_time + dif_time;
			} else {
				fprintf (stderr, 
					"[cefgetstream] Break (ChunkNum=%u)\n", params.chunk_num);
				break;
			}
		}
	}

	if (nsg_flag) {
		if (index > 0) {
			fwrite (buff, index, 1, stdout);
		}
	}

	params.opt.lifetime = 0;
	cef_client_interest_input (fhdl, &params);

	post_process ();

	exit (0);
}

static void
print_usage (
	void
) {
	
	fprintf (stderr, "\nUsage: \n");
	fprintf (stderr, "  cefgetstream uri\n\n");
}

static void
post_process (
	void
) {
	uint64_t diff_t;
	uint64_t recv_bits;
	uint64_t jitter_ave;
	
	if (stat_recv_frames) {
		diff_t = (uint64_t)(((end_t.tv_sec - start_t.tv_sec) * 1000000
							+ (end_t.tv_usec - start_t.tv_usec)) / 1000000);
	} else {
		diff_t = 0;
	}
	usleep (1000000);

	fprintf (stderr, "[cefgetstream] Unconnect to cefnetd ... ");
	cef_client_close (fhdl);
	fprintf (stderr, "OK\n");

	fprintf (stderr, "[cefgetstream] Terminate\n");
	fprintf (stderr, "[cefgetstream] Rx Frames = "FMTU64"\n", stat_recv_frames);
	fprintf (stderr, "[cefgetstream] Rx Bytes  = "FMTU64"\n", stat_recv_bytes);
	fprintf (stderr, "[cefgetstream] Duration  = "FMTU64" sec\n", diff_t);
	if (diff_t > 0) {
		recv_bits = stat_recv_bytes * 8;
		fprintf (stderr, "[cefgetstream] Throghput = "FMTU64" bps\n", recv_bits / diff_t);
	}
	if (stat_recv_frames > 0) {
		jitter_ave = stat_jitter_sum / stat_recv_frames;

		fprintf (stderr, "[cefgetstream] Jitter (Ave) = "FMTU64" us\n", jitter_ave);
		fprintf (stderr, "[cefgetstream] Jitter (Max) = "FMTU64" us\n", stat_jitter_max);
		fprintf (stderr, "[cefgetstream] Jitter (Var) = "FMTU64" us\n"
			, (stat_jitter_sq_sum / stat_recv_frames) - (jitter_ave * jitter_ave));
	}
}
static void
sigcatch (
	int sig
) {
	fprintf (stderr, "[cefgetstream] Catch the signal\n");
	switch (sig){
	case SIGINT:
	case SIGTERM:
	case SIGPIPE:
		app_running_f = 0;
		break;
	}
}

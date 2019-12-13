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

#define __CEF_GETFILE_SOURECE__

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

#define CefC_Max_PileLine 		16

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

typedef struct _Ceft_RxWnd {
	
	uint32_t 				seq;
	uint8_t 				flag;
	unsigned char 			buff[CefC_Max_Length];
	int 					frame_size;
	struct _Ceft_RxWnd* 	next;
	
} Ceft_RxWnd;

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
	int pipeline = 4;
	int index = 0;
	char uri[1024];
	CefT_Interest_TLVs params;
	struct timeval t;
	uint64_t dif_time;
	uint64_t nxt_time;
	uint64_t now_time;
	uint64_t end_time;
	uint64_t val;
	uint32_t diff_seq;
	int send_cnt = 0;
	int i;
	char*	work_arg;
	
	char 	conf_path[PATH_MAX] = {0};
	int 	port_num = CefC_Unset_Port;
	
	char valid_type[1024];
	
	struct cef_app_frame app_frame;
	unsigned char* buff;
	
	Ceft_RxWnd* 	rxwnd;
	Ceft_RxWnd* 	rxwnd_prev;
	Ceft_RxWnd* 	rxwnd_head;
	Ceft_RxWnd* 	rxwnd_tail;
	
	/***** flags 		*****/
	int pipeline_f 		= 0;
	int max_seq_f 		= 0;
	int uri_f 			= 0;
	int nsg_flag 		= 0;
	int from_pub_f 		= 0;
	int dir_path_f 		= 0;
	int port_num_f 		= 0;
	int valid_f 		= 0;
	
	/***** state variavles 	*****/
	uint32_t 	sv_max_seq 		= UINT_MAX - 1;
	
	memset (&params, 0, sizeof (CefT_Interest_TLVs));
	
	
	/*---------------------------------------------------------------------------
		Obtains parameters
	-----------------------------------------------------------------------------*/
	uri[0] 			= 0;
	valid_type[0] 	= 0;
	
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
		
		if (strcmp (work_arg, "-s") == 0) {
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
			if ((pipeline < 1) || (pipeline > CefC_Max_PileLine)) {
				pipeline = 1;
			}
			pipeline_f++;
			i++;
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
		} else if (strcmp (work_arg, "-m") == 0) {
			if (max_seq_f) {
				fprintf (stderr, "ERROR: [-m] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stderr, "ERROR: [-m] has no parameter.\n");
				print_usage ();
				return (-1);
			}
			work_arg = argv[i + 1];
			sv_max_seq = (uint32_t) atoi (work_arg);
			
			if (sv_max_seq < 1) {
				sv_max_seq = 1;
			}
			sv_max_seq--;
			max_seq_f++;
			i++;
		} else if (strcmp (work_arg, "-z") == 0) {
			if (nsg_flag) {
				fprintf (stderr, "ERROR: [-z] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stderr, "ERROR: [-z] has no parameter.\n");
				print_usage ();
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
		} else if (strcmp (work_arg, "-o") == 0) {
			if (from_pub_f) {
				fprintf (stderr, "ERROR: [-o] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			from_pub_f++;
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
		} else if (strcmp (work_arg, "-h") == 0) {
			print_usage ();
			exit (1);
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
	if (pipeline > sv_max_seq + 1) {
		pipeline = sv_max_seq + 1;
	}
	fprintf (stderr, "OK\n");
#ifdef CefC_Debug
	cef_dbg_init ("cefgetstream", conf_path, 1);
#endif // CefC_Debug
	
	/*---------------------------------------------------------------------------
		Inits the Cefore APIs
	-----------------------------------------------------------------------------*/
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
	fprintf (stderr, "OK\n");
	fprintf (stderr, "[cefgetstream] Checking the output file ... ");
	params.name_len = res;
	fprintf (stderr, "OK\n");
	
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
	fprintf (stderr, "[cefgetstream] Connect to cefnetd ... ");
	fhdl = cef_client_connect ();
	if (fhdl < 1) {
		fprintf (stderr, "ERROR: cefnetd is not running.\n");
		exit (1);
	}
	fprintf (stderr, "OK\n");
	buff = (unsigned char*) malloc (sizeof (unsigned char) * CefC_AppBuff_Size);
	memset (&app_frame, 0, sizeof (struct cef_app_frame));
	
	/*---------------------------------------------------------------------------
		Sets Interest parameters
	-----------------------------------------------------------------------------*/
	params.hoplimit 				= 32;
	params.opt.lifetime_f 			= 1;
	
	if (nsg_flag) {
		params.opt.symbolic_f		= CefC_T_OPT_LONGLIFE;
		params.opt.lifetime 		= 10000;
	} else {
		params.opt.symbolic_f		= CefC_T_OPT_REGULAR;
		params.opt.lifetime 		= 4000;
		params.chunk_num			= 0;
		params.chunk_num_f			= 1;
	}
	
	if (from_pub_f) {
		params.app_comp 			= CefC_T_APP_FROM_PUB;
	}
	
	gettimeofday (&t, NULL);
	now_time = cef_client_covert_timeval_to_us (t);
	if (nsg_flag) {
		dif_time = (uint64_t)((double) params.opt.lifetime * 0.8) * 1000;
		nxt_time = 0;
		end_time = now_time + 10000000;
	} else {
		dif_time = (uint64_t)((double) params.opt.lifetime * 0.3) * 1000;
		nxt_time = now_time + dif_time;
	}
	
	/*---------------------------------------------------------------------------
		Sends first Interest(s)
	-----------------------------------------------------------------------------*/
	app_running_f = 1;
	fprintf (stderr, "[cefgetstream] URI=%s\n", uri);
	if (nsg_flag) {
		cef_client_interest_input (fhdl, &params);
		fprintf (stderr, "[cefgetstream] Start sending Long Life Interests\n");
	} else {
		fprintf (stderr, "[cefgetstream] Start sending Interests\n");
		
		/* Sends Initerest(s) 		*/
		for (i = 0 ; i < pipeline ; i++) {
			cef_client_interest_input (fhdl, &params);
			params.chunk_num++;
			
			usleep (100000);
		}
		
		/* Creates the rx window 	*/
		rxwnd = (Ceft_RxWnd*) malloc (sizeof (Ceft_RxWnd));
		memset (rxwnd, 0, sizeof (Ceft_RxWnd));
		rxwnd->next = rxwnd;
		rxwnd->seq 	= 0;
		rxwnd_prev = rxwnd;
		rxwnd_head = rxwnd;
		rxwnd_tail = rxwnd;
		
		for (i = 1 ; i < pipeline ; i++) {
			rxwnd = (Ceft_RxWnd*) malloc (sizeof (Ceft_RxWnd));
			memset (rxwnd, 0, sizeof (Ceft_RxWnd));
			rxwnd->seq 	= (uint32_t) i;
			rxwnd_prev->next = rxwnd;
			rxwnd_tail = rxwnd;
			rxwnd_prev = rxwnd;
		}
		end_t.tv_sec = t.tv_sec;
	}
	
	/*---------------------------------------------------------------------------
		Main loop
	-----------------------------------------------------------------------------*/
	while (app_running_f) {
		if (SIG_ERR == signal (SIGINT, sigcatch)) {
			break;
		}
		
		/* Obtains UNIX time 			*/
		gettimeofday (&t, NULL);
		now_time = cef_client_covert_timeval_to_us (t);
		
		if (nsg_flag) {
			if (now_time > end_time) {
				break;
			}
		}
		
		/* Reads the message from cefnetd			*/
		res = cef_client_read (fhdl, &buff[index], CefC_AppBuff_Size - index);
		
		if (res > 0) {
			res += index;
			
			/* Updates the jitter 		*/
			if (stat_recv_frames < 1) {
				start_t.tv_sec  = t.tv_sec;
				start_t.tv_usec = t.tv_usec;
			} else {
				val = (t.tv_sec - end_t.tv_sec) * 1000000 + (t.tv_usec - end_t.tv_usec);
				
				stat_jitter_sum    += val;
				stat_jitter_sq_sum += val * val;
				
				if (val > stat_jitter_max) {
					stat_jitter_max = val;
				}
			}
			end_t.tv_sec  = t.tv_sec;
			end_t.tv_usec = t.tv_usec;
			
			if (nsg_flag) {
				end_time = now_time + 1000000;
			}
			
			/* Incomming message process 		*/
			do {
				res = cef_client_payload_get_with_info (buff, res, &app_frame);
				
				if (app_frame.version == CefC_App_Version) {
					
					if (nsg_flag) {
						stat_recv_frames++;
						stat_recv_bytes += app_frame.payload_len;
						fwrite (app_frame.payload, 
							sizeof (unsigned char), app_frame.payload_len, stdout);
					} else {
						
						/* Inserts the received frame to the buffer 	*/
						if ((app_frame.chunk_num < rxwnd_head->seq) || 
							(app_frame.chunk_num > rxwnd_tail->seq)) {
							continue;
						}
						
						diff_seq = app_frame.chunk_num - rxwnd_head->seq;
						rxwnd = rxwnd_head;
						
						for (i = 0 ; i < diff_seq ; i++) {
							rxwnd = rxwnd->next;
						}
						
						if (rxwnd->flag != 1) {
							memcpy (
								rxwnd->buff, app_frame.payload, app_frame.payload_len);
							rxwnd->frame_size = app_frame.payload_len;
							rxwnd->flag = 1;
						}
						
						rxwnd = rxwnd_head;
						
						for (i = 0 ; i < diff_seq + 1 ; i++) {
							
							if (rxwnd->flag == 0) {
								params.chunk_num = rxwnd->seq;
								cef_client_interest_input (fhdl, &params);
								break;
							}
							stat_recv_frames++;
							stat_recv_bytes += app_frame.payload_len;
							
							fwrite (rxwnd->buff, 
								sizeof (unsigned char), rxwnd->frame_size, stdout);
							
							if (rxwnd->seq == sv_max_seq) {
								fprintf (stderr, 
									"[cefgetstream] "
									"Received the specified number of chunk\n");
								app_running_f = 0;
							}
							
							/* Updates head and tail pointers		*/
							rxwnd_head->seq 			= rxwnd_tail->seq + 1;
							rxwnd_head->flag 			= 0;
							rxwnd_head->frame_size 		= 0;
							
							rxwnd_tail->next = rxwnd_head;
							rxwnd_tail = rxwnd_head;
							
							rxwnd_head = rxwnd_tail->next;
							rxwnd_tail->next 	= NULL;
							
							rxwnd = rxwnd_head;
							
							/* Sends an interest with the next chunk number 	*/
							params.chunk_num = rxwnd_tail->seq;
							if (params.chunk_num <= sv_max_seq) {
								cef_client_interest_input (fhdl, &params);
							}
						}
					}
				} else {
					break;
				}
			} while (res > 0);
			
			if (res > 0) {
				index = res;
			} else {
				index = 0;
			}
		}
		
		/* Sends Interest with Symbolic flag to CEFORE 		*/
		if (nsg_flag) {
			if (now_time > nxt_time) {
				cef_client_interest_input (fhdl, &params);
				fprintf (stderr, "[cefgetstream] Send Long Life Interest\n");
				nxt_time = now_time + dif_time;
			}
		} else {
			if (t.tv_sec - end_t.tv_sec > 2) {
				break;
			}
		}
	}
	
	if (nsg_flag) {
		if (index > 0) {
			fwrite (buff, index, 1, stdout);
		}
		params.opt.lifetime = 0;
		cef_client_interest_input (fhdl, &params);
	}
	
	post_process ();
	
	exit (0);
}

static void
print_usage (
	void
) {
	
	fprintf (stderr, "\nUsage: cefgetstream\n\n");
	fprintf (stderr, "  cefgetstream uri [-o] [-m chunks] [-v valid_algo]\n\n");
	fprintf (stderr, "  uri     Specify the URI.\n");
	fprintf (stderr, "  -o      Specify this option, if you require the content\n"
	                 "          that the owner is caching\n");
	fprintf (stdout, " chunks   Specify the number of chunk that you want to obtain\n");
	fprintf (stdout, 
		" valid_algo   Specify the validation algorithm (crc32 or sha256)\n\n");}

static void
post_process (
	void
) {
	uint64_t diff_t;
	uint64_t recv_bits;
	uint64_t jitter_ave;
	
	if (stat_recv_frames) {
		diff_t = ((end_t.tv_sec - start_t.tv_sec) * 1000000
								+ (end_t.tv_usec - start_t.tv_usec)) / 1000000;
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
	if (sig == SIGINT) {
		fprintf (stderr, "[cefgetstream] Catch the signal\n");
		app_running_f = 0;
	}
}

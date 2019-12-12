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
 * cefgetfile.c
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
FILE* fp = NULL;

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
	int pipeline = 4;
	int index = 0;
	char uri[1024];
	char fpath[1024];
	unsigned char buff[CefC_Max_Length];
	unsigned char frame[CefC_Max_Length];
	CefT_Interest_TLVs params;
	struct timeval t;
	uint64_t dif_time;
	uint64_t nxt_time;
	uint64_t now_time;
	uint64_t end_time;
	uint64_t val;
	uint32_t chnk_num = 0;
	uint32_t diff_seq;
	int send_cnt = 0;
	int i;
	char*	work_arg;
	
	char 	conf_path[PATH_MAX] = {0};
	int 	port_num = CefC_Unset_Port;
	
	Ceft_RxWnd* 	rxwnd;
	Ceft_RxWnd* 	rxwnd_prev;
	Ceft_RxWnd* 	rxwnd_head;
	Ceft_RxWnd* 	rxwnd_tail;
	
	/***** flags 		*****/
	int pipeline_f 		= 0;
	int max_seq_f 		= 0;
	int uri_f 			= 0;
	int file_f 			= 0;
	int nsg_flag 		= 0;
	int from_pub_f 		= 0;
	int dir_path_f 		= 0;
	int port_num_f 		= 0;
	int key_path_f 		= 0;
	
	/***** state variavles 	*****/
	uint32_t 	sv_max_seq 		= UINT_MAX - 1;
	
	memset (&params, 0, sizeof (CefT_Interest_TLVs));
	
	
	/*---------------------------------------------------------------------------
		Obtains parameters
	-----------------------------------------------------------------------------*/
	fprintf (stdout, "[cefgetfile] Start\n");
	fprintf (stdout, "[cefgetfile] Parsing parameters ... ");
	
	/* Inits logging 		*/
	cef_log_init ("cefgetfile");
	
	/* Obtains options 		*/
	for (i = 1 ; i < argc ; i++) {
		
		work_arg = argv[i];
		if (work_arg == NULL || work_arg[0] == 0) {
			break;
		}
		
		if (strcmp (work_arg, "-f") == 0) {
			if (file_f) {
				fprintf (stdout, "ERROR: [-f] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stdout, "ERROR: [-f] has no parameter.\n");
				print_usage ();
				return (-1);
			}
			work_arg = argv[i + 1];
			strcpy (fpath, work_arg);
			file_f++;
			i++;
		} else if (strcmp (work_arg, "-s") == 0) {
			if (pipeline_f) {
				fprintf (stdout, "ERROR: [-s] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stdout, "ERROR: [-s] has no parameter.\n");
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
				fprintf (stdout, "ERROR: [-m] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stdout, "ERROR: [-m] has no parameter.\n");
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
		} else if (strcmp (work_arg, "-k") == 0) {
			if (key_path_f) {
				fprintf (stderr, "ERROR: [-k] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			key_path_f++;
		} else if (strcmp (work_arg, "-z") == 0) {
			if (nsg_flag) {
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
			nsg_flag++;
			i++;
		} else if (strcmp (work_arg, "-o") == 0) {
			if (from_pub_f) {
				fprintf (stdout, "ERROR: [-o] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			from_pub_f++;
		} else if (strcmp (work_arg, "-h") == 0) {
			print_usage ();
			exit (1);
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
	
	/* Checks errors 			*/
	if (uri_f == 0) {
		fprintf (stdout, "ERROR: uri is not specified.\n");
		print_usage ();
		exit (1);
	}
	if (file_f == 0) {
		fprintf (stdout, "ERROR: [-f] is not specified.\n");
		print_usage ();
		exit (1);
	}
	if (pipeline > sv_max_seq + 1) {
		pipeline = sv_max_seq + 1;
	}
	fprintf (stdout, "OK\n");
#ifdef CefC_Debug
	cef_dbg_init ("cefgetfile", conf_path, 1);
#endif // CefC_Debug
	
	/*---------------------------------------------------------------------------
		Inits the Cefore APIs
	-----------------------------------------------------------------------------*/
	cef_frame_init ();
	res = cef_client_init (port_num, conf_path);
	if (res < 0) {
		fprintf (stdout, "ERROR: Failed to init the client package.\n");
		exit (1);
	}
	fprintf (stdout, "[cefgetfile] Init Cefore Client package ... OK\n");
	fprintf (stdout, "[cefgetfile] Conversion from URI into Name ... ");
	res = cef_frame_conversion_uri_to_name (uri, params.name);
	if (res < 0) {
		fprintf (stdout, "ERROR: Invalid URI is specified.\n");
		print_usage ();
		exit (1);
	}
	fprintf (stdout, "OK\n");
	fprintf (stdout, "[cefgetfile] Checking the output file ... ");
	fp = fopen (fpath, "wb");
	if (fp == NULL) {
		fprintf (stdout, "ERROR: Specified output file can not be opend.\n");
		exit (1);
	}
	params.name_len = res;
	fprintf (stdout, "OK\n");
	fprintf (stdout, "[cefgetfile] Connect to cefnetd ... ");
	fhdl = cef_client_connect ();
	if (fhdl < 1) {
		fprintf (stdout, "ERROR: cefnetd is not running.\n");
		exit (1);
	}
	fprintf (stdout, "OK\n");
	
	/*------------------------------------------
		Checks Validation 
	--------------------------------------------*/
	if (key_path_f) {
		params.alg.pubkey_len = cef_valid_read_pubkey (conf_path, params.alg.pubkey);
		
		if (params.alg.pubkey_len > 0) {
			fprintf (stdout, "[cefgetfile] Read the public key ... OK\n");
		} else {
			fprintf (stdout, "[cefgetfile] Read the public key ... NG\n");
			fclose (fp);
			exit (1);
		}
	}
	
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
	fprintf (stdout, "[cefgetfile] URI=%s\n", uri);
	if (nsg_flag) {
		cef_client_interest_input (fhdl, &params);
		fprintf (stdout, "[cefgetfile] Start sending Long Life Interests\n");
	} else {
		fprintf (stdout, "[cefgetfile] Start sending Interests\n");
		
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
		res = cef_client_read (fhdl, &buff[index], CefC_Max_Length - index);
		
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
				if (nsg_flag) {
					res = cef_client_payload_get (buff, res, frame, &frame_size);
				} else {
					res = cef_client_payload_get_with_chnk_num (
									buff, res, frame, &frame_size, &chnk_num);
				}
				
				if (frame_size > 0) {
					
					if (nsg_flag) {
						stat_recv_frames++;
						stat_recv_bytes += frame_size;
						fwrite (frame, sizeof (unsigned char), frame_size, fp);
					} else {
						
						/* Inserts the received frame to the buffer 	*/
						if ((chnk_num < rxwnd_head->seq) || 
							(chnk_num > rxwnd_tail->seq)) {
							continue;
						}
						
						diff_seq = chnk_num - rxwnd_head->seq;
						rxwnd = rxwnd_head;
						
						for (i = 0 ; i < diff_seq ; i++) {
							rxwnd = rxwnd->next;
						}
						
						if (rxwnd->flag != 1) {
							memcpy (rxwnd->buff, frame, frame_size);
							rxwnd->frame_size = frame_size;
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
							stat_recv_bytes += frame_size;
							
							fwrite (rxwnd->buff, 
								sizeof (unsigned char), rxwnd->frame_size, fp);
							
							if (rxwnd->seq == sv_max_seq) {
								fprintf (stdout, 
									"[cefgetfile] "
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
				}
			} while ((frame_size > 0) && (res > 0));
			
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
				fprintf (stdout, "[cefgetfile] Send Long Life Interest\n");
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
			fwrite (buff, index, 1, fp);
		}
		params.opt.lifetime = 0;
		cef_client_interest_input (fhdl, &params);
	}
	
	fclose (fp);
	post_process ();
	
	exit (0);
}

static void
print_usage (
	void
) {
	
	fprintf (stdout, "\nUsage: cefgetfile\n\n");
	fprintf (stdout, "  cefgetfile uri -f file [-o] [-m chunks]\n\n");
	fprintf (stdout, "  uri     Specify the URI.\n");
	fprintf (stdout, "  file    Specify the file name of output. \n");
	fprintf (stdout, "  -o      Specify this option, if you require the content\n"
	                 "          that the owner is caching\n");
	fprintf (stdout, " chunks   Specify the number of chunk that you want to obtain\n\n");
}

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
	fprintf (stdout, "[cefgetfile] Unconnect to cefnetd ... ");
	cef_client_close (fhdl);
	fprintf (stdout, "OK\n");
	
	fprintf (stdout, "[cefgetfile] Terminate\n");
	fprintf (stdout, "[cefgetfile] Rx Frames = "FMTU64"\n", stat_recv_frames);
	fprintf (stdout, "[cefgetfile] Rx Bytes  = "FMTU64"\n", stat_recv_bytes);
	fprintf (stdout, "[cefgetfile] Duration  = "FMTU64" sec\n", diff_t);
	if (diff_t > 0) {
		recv_bits = stat_recv_bytes * 8;
		fprintf (stdout, "[cefgetfile] Throghput = "FMTU64" bps\n", recv_bits / diff_t);
	}
	if (stat_recv_frames > 0) {
		jitter_ave = stat_jitter_sum / stat_recv_frames;

		fprintf (stdout, "[cefgetfile] Jitter (Ave) = "FMTU64" us\n", jitter_ave);
		fprintf (stdout, "[cefgetfile] Jitter (Max) = "FMTU64" us\n", stat_jitter_max);
		fprintf (stdout, "[cefgetfile] Jitter (Var) = "FMTU64" us\n"
			, (stat_jitter_sq_sum / stat_recv_frames) - (jitter_ave * jitter_ave));
	}
}
static void
sigcatch (
	int sig
) {
	if (sig == SIGINT) {
		fprintf (stdout, "[cefgetfile] Catch the signal\n");
		app_running_f = 0;
	}
}

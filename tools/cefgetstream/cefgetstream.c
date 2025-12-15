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
#include <stdarg.h>

#include <cefore/cef_define.h>
#include <cefore/cef_frame.h>
#include <cefore/cef_client.h>
#include <cefore/cef_valid.h>
#include <cefore/cef_log.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

#define CefC_Max_PipeLine 		1024	/* MAX Pipeline */
#define CefC_Def_PipeLine 		8		/* Default Pipeline */

#define USAGE					print_usage(CefFp_Usage)
#define printerr(...)			fprintf(stderr,"[cefgetstream] ERROR: " __VA_ARGS__)

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

typedef struct _Ceft_RxWnd {
	
	uint64_t 				seq;
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
	int pipeline = CefC_Def_PipeLine;
	int index = 0;
	char uri[1024];
	CefT_CcnMsg_OptHdr opt;
	CefT_CcnMsg_MsgBdy params;
	struct timeval t;
	uint64_t dif_time;
	uint64_t nxt_time;
	uint64_t now_time;
	uint64_t end_time;
	uint64_t val;
	uint64_t diff_seq;
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
	
	int backup_fd;
	
	/***** flags 		*****/
	int pipeline_f 		= 0;
	int max_seq_f 		= 0;
	int uri_f 			= 0;
	int nsg_flag 		= 0;
	int from_pub_f 		= 0;
	int dir_path_f 		= 0;
	int port_num_f 		= 0;
	int valid_f 		= 0;
	//0.8.3
	int blk_mode_f		= 0;
	int blk_mode_val	= 0;	//BLOCK
	
	/***** state variavles 	*****/
	uint32_t 	sv_max_seq 		= UINT_MAX - 1;
	int			sg_lifetime		= 4;
	
	memset (&opt, 0, sizeof (CefT_CcnMsg_OptHdr));
	memset (&params, 0, sizeof (CefT_CcnMsg_MsgBdy));
	
	
	/*---------------------------------------------------------------------------
		Obtains parameters
	-----------------------------------------------------------------------------*/
	uri[0] 			= 0;
	valid_type[0] 	= 0;
	
	printf ("[cefgetstream] Start\n");
	
	/* Inits logging 		*/
	cef_log_init ("cefgetstream", 1);
	
	/* Obtains options 		*/
	for (i = 1 ; i < argc ; i++) {
		
		work_arg = argv[i];
		if (work_arg == NULL || work_arg[0] == 0) {
			break;
		}
		
		if (strcmp (work_arg, "-s") == 0) {
			if (pipeline_f) {
				printerr("[-s] is duplicated.\n");
				USAGE;
				return (-1);
			}
			if (i + 1 == argc) {
				printerr("[-s] has no parameter.\n");
				USAGE;
				return (-1);
			}
			work_arg = argv[i + 1];
			pipeline = atoi (work_arg);
//			if ((pipeline < 1) || (pipeline > CefC_Max_PileLine)) {
//				pipeline = 1;
//			}
			if ( pipeline < 1 ) {
				pipeline = CefC_Def_PipeLine;
			} else if ( pipeline > CefC_Max_PipeLine ) {
				pipeline = CefC_Max_PipeLine;
			}
			pipeline_f++;
			i++;
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
		//0.8.3
		} else if (strcmp (work_arg, "-l") == 0) {
			if (port_num_f) {
				printerr("[-l] is duplicated.\n");
				USAGE;
				return (-1);
			}
			if (i + 1 == argc) {
				printerr("[-l] has no parameter.\n");
				USAGE;
				return (-1);
			}
			work_arg = argv[i + 1];
			blk_mode_val = atoi (work_arg);
			if ( (blk_mode_val == 0) || (blk_mode_val == 1) ) {
				/* OK */
			} else {
				printerr("block_mode is 0 or 1.\n");
				USAGE;
				return (-1);
			}
			blk_mode_f++;
			i++;
		} else if (strcmp (work_arg, "-m") == 0) {
			if (max_seq_f) {
				printerr("[-m] is duplicated.\n");
				USAGE;
				return (-1);
			}
			if (i + 1 == argc) {
				printerr("[-m] has no parameter.\n");
				USAGE;
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
				printerr("[-z] is duplicated.\n");
				USAGE;
				return (-1);
			}
			if (i + 1 == argc) {
				
			} else {
				work_arg = argv[i + 1];
				sg_lifetime = atoi (work_arg);
				if ( sg_lifetime < 0 ) {
					printerr("[-z] has the invalid parameter.(Lifetime > 0)\n");
					USAGE;
					return(-1);
				}
			}
			nsg_flag++;
			i++;
		} else if (strcmp (work_arg, "-o") == 0) {
			if (from_pub_f) {
				printerr("[-o] is duplicated.\n");
				USAGE;
				return (-1);
			}
			from_pub_f++;
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
			
			if (res >= CefC_NAME_MAXLEN) {
				printerr("uri is too long.\n");
				USAGE;
				return (-1);
			}
			strcpy (uri, work_arg);
			uri_f++;
		}
	}
	
	/* Checks errors 			*/
	if (uri_f == 0) {
		printerr("uri is not specified.\n");
		USAGE;
		exit (1);
	}
	if (pipeline > sv_max_seq + 1) {
		pipeline = sv_max_seq + 1;
	}
	printf ("[cefgetstream] Parsing parameters ... OK\n");
	cef_log_init2 (conf_path, 1 /* for CEFNETD */);
#ifdef CefC_Debug
	cef_dbg_init ("cefgetstream", conf_path, 1);
#endif // CefC_Debug
	
	/*---------------------------------------------------------------------------
		Inits the Cefore APIs
	-----------------------------------------------------------------------------*/
	backup_fd = dup (1);
	dup2(2, 1);
	
	cef_frame_init ();
	res = cef_client_init (port_num, conf_path);
	if (res < 0) {
		printerr("Failed to init the client package.\n");
		exit (1);
	}
	printf ("[cefgetstream] Init Cefore Client package ... OK\n");
	res = cef_frame_conversion_uri_to_name (uri, params.name);
	if (res < 0) {
		printerr("Invalid URI is specified.\n");
		USAGE;
		exit (1);
	}
	printf ("[cefgetstream] Conversion from URI into Name ... OK\n");
	params.name_len = res;
	printf ("[cefgetstream] Checking the output file ... OK\n");
	
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
	printf ("[cefgetstream] Connect to cefnetd ... OK\n");
	buff = (unsigned char*) malloc (sizeof (unsigned char) * CefC_AppBuff_Size);
	memset (&app_frame, 0, sizeof (struct cef_app_frame));
	
	/*---------------------------------------------------------------------------
		Sets Interest parameters
	-----------------------------------------------------------------------------*/
	params.hoplimit 				= 32;
	opt.lifetime_f 			= 1;
	
	if (nsg_flag) {
		Cef_Int_Symbolic(params);
		opt.lifetime 		= sg_lifetime * 1000;	//0.8.3
	} else {
		Cef_Int_Regular(params);
		opt.lifetime 		= CefC_Default_LifetimeSec * 1000;
		params.chunk_num			= 0;
		params.chunk_num_f			= 1;
	}
	
	if (from_pub_f) {
		params.org.from_pub_f			= CefC_T_FROM_PUB;
	}
	
	gettimeofday (&t, NULL);
	now_time = cef_client_covert_timeval_to_us (t);
	if (nsg_flag) {
		dif_time = (uint64_t)((double) opt.lifetime * 0.8) * 1000;
		nxt_time = 0;
		end_time = now_time + 10000000;
	} else {
		dif_time = (uint64_t)((double) opt.lifetime * 0.3) * 1000;
		nxt_time = now_time + dif_time;
	}
	
	/*---------------------------------------------------------------------------
		Sends first Interest(s)
	-----------------------------------------------------------------------------*/
	app_running_f = 1;
	printf ("[cefgetstream] URI=%s\n", uri);
	if (nsg_flag) {
		cef_client_interest_input (fhdl, &opt, &params);
		printf ("[cefgetstream] Start sending Long Life Interests\n");
	} else {
		printf ("[cefgetstream] Start sending Interests\n");
		
		/* Sends Initerest(s) 		*/
		for (i = 0 ; i < pipeline ; i++) {
			cef_client_interest_input (fhdl, &opt, &params);
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
	dup2(backup_fd, 1);
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
				val = (t.tv_sec - end_t.tv_sec) * 1000000llu + (t.tv_usec - end_t.tv_usec);
				
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

					/* InterestReturn */
					if ( (uint8_t)app_frame.type == CefC_PT_INTRETURN ) {
						printf ("[cefgetstream] Incomplete\n");
						printf ("[cefgetstream] "
								"Received Interest Return(Type:%02x)\n", app_frame.returncode);
						app_running_f = 0;
						goto IR_RCV;
					}

					
					if (nsg_flag) {
						stat_recv_frames++;
						stat_recv_bytes += app_frame.payload_len;
						if ( blk_mode_val == 1 ) {	//NONBLOCK
							int val;
							if (stat_recv_frames == 1) {
								if ((val = fcntl(1, F_GETFL, 0)) < 0) {
									printerr("fcntl F_GETFL error");
									exit(1);
								}
								if (fcntl(1, F_SETFL, val | O_NONBLOCK) < 0) {
									printerr("fcntl F_SETFL error");
									exit(1);
								}
							}
							write (1, app_frame.payload, app_frame.payload_len);
						} else {	//BLOCK
							fwrite (app_frame.payload, 
								sizeof (unsigned char), app_frame.payload_len, stdout);
							gettimeofday (&t, NULL);
							now_time = cef_client_covert_timeval_to_us (t);
							end_time = now_time + 1000000;
						}
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
						
						for (i = 0 ; i < pipeline; i++) {
							
							if (rxwnd->flag == 0) {
								params.chunk_num = rxwnd->seq;
								cef_client_interest_input (fhdl, &opt, &params);
								break;
							}
							stat_recv_frames++;
							stat_recv_bytes += app_frame.payload_len;
							
							fwrite (rxwnd->buff, 
								sizeof (unsigned char), rxwnd->frame_size, stdout);
							
							if (rxwnd->seq == UINT32_MAX) {
								printf ("[cefgetstream] Received the specified number of chunk\n");
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
							if (params.chunk_num <= UINT32_MAX) {
								cef_client_interest_input (fhdl, &opt, &params);
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
				cef_client_interest_input (fhdl, &opt, &params);
				printf ("[cefgetstream] Send Long Life Interest\n");
				nxt_time = now_time + dif_time;
			}
		} else {
			if (t.tv_sec - end_t.tv_sec > 2) {
				break;
			}
		}
IR_RCV:;
	}
	
	if (nsg_flag) {
		if (index > 0) {
			fwrite (buff, index, 1, stdout);
		}
		opt.lifetime = 0;
		cef_client_interest_input (fhdl, &opt, &params);
	}
	
	post_process (stdout);
	
	exit (0);
}

static void
print_usage (
	FILE* ofp
) {
	
	fprintf (ofp, "\nUsage: cefgetstream\n\n");
	fprintf (ofp, "  cefgetstream uri [-o] [-m chunks] [-s pipeline] [-v valid_algo] [-d config_file_dir] [-p port_num] [-z Lifetime] [-l block_mode]\n\n");
	fprintf (ofp, "  uri              Specify the URI.\n");
	fprintf (ofp, "  -o               Specify this option if content must be retrieved directly from content owner and not from intermediate cache\n");
	fprintf (ofp, "  chunks           Specify the number of chunk that you want to obtain\n");
	fprintf (ofp, "  pipeline         Number of pipeline\n");
	fprintf (ofp, "  valid_algo       Specify the validation algorithm (" CefC_ValidTypeStr_CRC32C " or " CefC_ValidTypeStr_RSA256 ")\n");
	fprintf (ofp, "  config_file_dir  Configure file directory\n");
	fprintf (ofp, "  port_num         Port Number\n");
	fprintf (ofp, "  Lifetime         Send Long Life Intereset Lifetime\n");
	fprintf (ofp, "  block_mode       0:BLOCK    1:NONBLOCK\n\n");
}

static void
post_process (
	FILE* ofp
) {
	uint64_t diff_t;
	double diff_t_dbl = 0.0;
	double thrpt = 0.0;
	uint64_t recv_bits;
	uint64_t jitter_ave;
	struct timeval diff_tval;
	int	invalid_end = 0;
	
	if (stat_recv_frames) {
		if ( !timercmp( &start_t, &end_t, != ) == 0 ) {
			if ( timercmp( &start_t, &end_t, < ) == 0 ) {
				// Invalid end time
				fprintf (ofp, "[cefgetstream] Invalid end time. No time statistics reported.\n");
				diff_t = 0;
				invalid_end = 1;
			} else {
				timersub( &end_t, &start_t, &diff_tval );
				diff_t = diff_tval.tv_sec * 1000000llu + diff_tval.tv_usec;
			}
		} else {
			//Same Time
			diff_t = 0;
		}
	} else {
		diff_t = 0;
	}
	usleep (1000000);
	fprintf (ofp, "[cefgetstream] Unconnect to cefnetd ... ");
	cef_client_close (fhdl);
	fprintf (ofp, "OK\n");
	
	fprintf (ofp, "[cefgetstream] Terminate\n");
	fprintf (ofp, "[cefgetstream] Rx Frames = "FMTU64"\n", stat_recv_frames);
	fprintf (ofp, "[cefgetstream] Rx Bytes  = "FMTU64"\n", stat_recv_bytes);
	if (diff_t > 0) {
		diff_t_dbl = (double)diff_t / 1000000.0;
		fprintf (ofp, "[cefgetstream] Duration  = %.3f sec\n", diff_t_dbl + 0.0009);
		recv_bits = stat_recv_bytes * 8;
		thrpt = (double)(recv_bits) / diff_t_dbl;
		fprintf (ofp, "[cefgetstream] Throughput = %d bps\n", (int)thrpt);
	} else {
		fprintf (ofp, "[cefgetstream] Duration  = 0.000 sec\n");
	}
	if ((stat_recv_frames > 0) && (invalid_end == 0)) {
		jitter_ave = stat_jitter_sum / stat_recv_frames;

		fprintf (ofp, "[cefgetstream] Jitter (Ave) = "FMTU64" us\n", jitter_ave);
		fprintf (ofp, "[cefgetstream] Jitter (Max) = "FMTU64" us\n", stat_jitter_max);
		fprintf (ofp, "[cefgetstream] Jitter (Var) = "FMTU64" us\n"
			, (stat_jitter_sq_sum / stat_recv_frames) - (jitter_ave * jitter_ave));
	}
}
static void
sigcatch (
	int sig
) {
	if (sig == SIGINT) {
		printf ("[cefgetstream] Catch the signal\n");
		app_running_f = 0;
	}
}

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
 * cefgetfile_sec.c
 */

#define __CEF_GETFILE_SEC_SOURECE__

//#define	__DEB_GET__
//#define	__DEB_GET_KEY__
//#define		__DEV_COBH__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
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

#define CefC_Max_PipeLine 		1024	/* MAX Pipeline */
#define CefC_Def_PipeLine 		8		/* Default Pipeline */

#define CefC_Resend_Interval	10000		/* 10 ms 		*/
#define CefC_Max_Retry 			5

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

typedef struct _Ceft_RxWnd {
	
	uint64_t 				seq;
	uint8_t 				flag;
	unsigned char 			buff[CefC_Max_Length];
	int 					frame_size;
	uint8_t 				CobHash_f;
	unsigned char			cob_hash[32];
	struct _Ceft_RxWnd* 	next;
	
} Ceft_RxWnd;

typedef	struct	man_rec_t {
	uint32_t		chunk;
	unsigned char	cob_hash[32];
}	MAN_REC_T;

/****************************************************************************************
 State Variables
 ****************************************************************************************/

static int app_running_f = 0;

static uint64_t stat_recv_frames = 0;
static uint64_t man_stat_recv_frames = 0;
static uint64_t stat_recv_bytes = 0;
static uint64_t stat_all_recv_frames = 0;	//20230522
static uint64_t stat_all_recv_bytes = 0;	//20230522
static uint64_t stat_jitter_sum = 0;
static uint64_t stat_jitter_sq_sum = 0;
static uint64_t stat_jitter_max = 0;
static struct timeval start_t;
static struct timeval end_t;
CefT_Client_Handle fhdl;
FILE* fp = NULL;
int rcv_ng_f = 0;
FILE* man_fp = NULL;


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
	int pipeline = CefC_Def_PipeLine;
	int index = 0;
	char uri[1024] = {0};
	char fpath[1024] = {0};
	char man_uri[1048] = {0};
	char man_fpath[1024] = {0};
	CefT_CcnMsg_OptHdr opt;
	CefT_CcnMsg_OptHdr man_opt;	
	CefT_CcnMsg_MsgBdy params;
	CefT_CcnMsg_MsgBdy man_params;
	struct timeval t;
	uint64_t dif_time;
	uint64_t nxt_time;
	uint64_t now_time;
	uint64_t end_time;
	uint64_t val;
	uint32_t chunk_num = 0;
	uint32_t diff_seq;
	int send_cnt = 0;
	int i;
	char*	work_arg;
	int64_t	end_chunk_num		= -1;
	int64_t	man_end_chunk_num	= -1;
	
	char 	conf_path[PATH_MAX] = {0};
	int 	port_num = CefC_Unset_Port;
	
	char valid_type[1024];
	
	Ceft_RxWnd* 	rxwnd;
	Ceft_RxWnd* 	rxwnd_prev;
	Ceft_RxWnd* 	rxwnd_head;
	Ceft_RxWnd* 	rxwnd_tail;
	
	struct cef_app_frame app_frame;
	unsigned char* buff;
	
	int retry_cnt = 0;
	uint64_t retry_int = CefC_Resend_Interval;

	int				man_rec_num = 0;
	int				man_rec_ctr = 0;
	MAN_REC_T		man_rec;
	int				man_rec_size = sizeof(man_rec);
	int				man_buff_size = 4 + (man_rec_size*CefC_MANIFEST_REC_MAX);
	uint32_t		man_content_total_chunk = 0;
	unsigned char	man_buff[man_buff_size];
	int				man_buff_idx = 0;
	Ceft_RxWnd* 	man_rxwnd;
	Ceft_RxWnd* 	man_rxwnd_prev;
	Ceft_RxWnd* 	man_rxwnd_head;
	Ceft_RxWnd* 	man_rxwnd_tail;
	
	/***** flags 		*****/
	int pipeline_f 		= 0;
	int max_seq_f 		= 0;
	int uri_f 			= 0;
	int file_f 			= 0;
	int dir_path_f 		= 0;
	int port_num_f 		= 0;
	int mode_f 			= 0;
	int	mode_val		= 0;
	int man_fail_f = 0;
	int man_res;
	/***** state variavles 	*****/
	uint32_t 	sv_max_seq 		= UINT_MAX - 1;

	memset (&opt, 0, sizeof (CefT_CcnMsg_OptHdr));	
	memset (&man_opt, 0, sizeof (CefT_CcnMsg_OptHdr));	
	memset (&params, 0, sizeof (CefT_CcnMsg_MsgBdy));
	memset (&man_params, 0, sizeof (CefT_CcnMsg_MsgBdy));
	
	
	/*---------------------------------------------------------------------------
		Obtains parameters
	-----------------------------------------------------------------------------*/
	uri[0] 			= 0;
	valid_type[0] 	= 0;
	
	fprintf (stdout, "[cefgetfile_sec] Start\n");
	fprintf (stdout, "[cefgetfile_sec] Parsing parameters ... ");
	
	/* Inits logging 		*/
	cef_log_init ("cefgetfile_sec", 1);
	
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
			if ( pipeline < 1 ) {
				pipeline = CefC_Def_PipeLine;
			} else if ( pipeline > CefC_Max_PipeLine ) {
				pipeline = CefC_Max_PipeLine;
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
			//202108
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
		} else if (strcmp (work_arg, "-m") == 0) {
			if (mode_f) {
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
			mode_val = atoi (work_arg);
			if ( (mode_val < 0) && (mode_val > 2) ) {
				fprintf (stderr, "ERROR: [-m] parameter is 0 or 1 or 2.\n");
			}
			mode_f++;
			i++;
		} else if (strcmp (work_arg, "-h") == 0) {
			print_usage ();
			exit (1);
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
	
	/* Checks errors 			*/
	if (uri_f == 0) {
		fprintf (stdout, "ERROR: uri is not specified.\n");
		print_usage ();
		exit (1);
	}
	if (file_f == 0) {
		/* Use the last string in the URL */
		res = strlen (uri);
		if (res >= 1024) {
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
			exit (1);
		}
		i = 0;
		while (1) {
			if ((uri[res + i] == '\0') || (uri[res + i] == '/')) {
				break;
			}
			i++;
		}
		strncpy (fpath, uri + res, i);
		fpath[i] = '\0';
	}
	if (pipeline > sv_max_seq + 1) {
		pipeline = sv_max_seq + 1;
	}
	fprintf (stdout, "OK\n");
	cef_log_init2 (conf_path, 1/* for CEFNETD */);
#ifdef CefC_Debug
	cef_dbg_init ("cefgetfile_sec", conf_path, 1);
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
	fprintf (stdout, "[cefgetfile_sec] Init Cefore Client package ... OK\n");
	fprintf (stdout, "[cefgetfile_sec] Conversion from URI into Name ... ");
	strcpy( man_uri, uri );
	strcat( man_uri, CefC_MANIFEST_NAME );
	
	res = cef_frame_conversion_uri_to_name (uri, params.name);
	if (res < 0) {
		fprintf (stdout, "ERROR: Invalid URI is specified.\n");
		print_usage ();
		exit (1);
	}
	fprintf (stdout, "OK\n");
	fprintf (stdout, "[cefgetfile_sec] Checking the output file ... ");
	fp = fopen (fpath, "wb");
	if (fp == NULL) {
		fprintf (stdout, "ERROR: Specified output file can not be opend.\n");
		exit (1);
	}
	params.name_len = res;
	fprintf (stdout, "OK\n");
	
	/*------------------------------------------
		Connects to CEFORE
	--------------------------------------------*/
	fprintf (stdout, "[cefgetfile_sec] Connect to cefnetd ... ");
	fhdl = cef_client_connect ();
	if (fhdl < 1) {
		fprintf (stdout, "ERROR: cefnetd is not running.\n");
		exit (1);
	}
	fprintf (stdout, "OK\n");
	
	/*---------------------------------------------------------------------------
		Sets Interest parameters
	-----------------------------------------------------------------------------*/
	params.hoplimit 			= 32;
	opt.lifetime_f 		= 1;
	Cef_Int_Regular(params);
	opt.lifetime 		= CefC_Default_LifetimeSec * 1000;
	params.chunk_num			= 0;
	params.chunk_num_f			= 1;


	/*---------------------------------------------------------------------------
		Get	Manifest
	-----------------------------------------------------------------------------*/
	if ( (mode_val == 1) || (mode_val == 2) ) {
		srand((unsigned)time(NULL));
		uint32_t rand_n = rand();
		sprintf( man_fpath, "%s/manifest_%d", getenv("HOME"), rand_n );
#ifdef __DEB_GET__
printf( "Manifest:%s\n", man_fpath );
#endif
		man_fp = fopen (man_fpath, "wb");
		if (man_fp == NULL) {
			fprintf (stdout, "ERROR: Manifest output file can not be opend.\n");
			exit (1);
		}
#ifdef __DEB_GET__
printf ("Manifest URI=%s\n", man_uri);
#endif
		res = cef_frame_conversion_uri_to_name (man_uri, man_params.name);
		if (res < 0) {
			fprintf (stdout, "ERROR: Invalid URI is specified.\n");
			print_usage ();
			exit (1);
		}

		man_params.name_len = res;

		man_params.hoplimit 			= 32;
		man_opt.lifetime_f 		= 1;
		Cef_Int_Regular(params);
		man_opt.lifetime 		= CefC_Default_LifetimeSec * 1000;
		man_params.chunk_num			= 0;
		man_params.chunk_num_f			= 1;
		
		/*---------------------------------------------------------------------------
			Sends first Interest(s)
		-----------------------------------------------------------------------------*/
		app_running_f = 1;
		fprintf (stdout, "[cefgetfile_sec] Manifest URI=%s\n", man_uri);

		fprintf (stdout, "[cefgetfile_sec] Start sending Interests\n");
		
		/* Sends Initerest(s) 		*/
		for (i = 0 ; i < pipeline ; i++) {
			cef_client_interest_input (fhdl, &opt, &man_params);
			man_params.chunk_num++;
			
			usleep (100000);
		}
		
		/* Creates the rx window 	*/
		man_rxwnd = (Ceft_RxWnd*) malloc (sizeof (Ceft_RxWnd));
		memset (man_rxwnd, 0, sizeof (Ceft_RxWnd));
		man_rxwnd->next = man_rxwnd;
		man_rxwnd->seq 	= 0;
		man_rxwnd_prev = man_rxwnd;
		man_rxwnd_head = man_rxwnd;
		man_rxwnd_tail = man_rxwnd;
		
		for (i = 1 ; i < pipeline ; i++) {
			man_rxwnd = (Ceft_RxWnd*) malloc (sizeof (Ceft_RxWnd));
			memset (man_rxwnd, 0, sizeof (Ceft_RxWnd));
			man_rxwnd->seq = (uint32_t) i;
			man_rxwnd_prev->next = man_rxwnd;
			man_rxwnd_tail = man_rxwnd;
			man_rxwnd_prev = man_rxwnd;
		}
		end_t.tv_sec = t.tv_sec;

		memset (&app_frame, 0, sizeof (struct cef_app_frame));
		buff = (unsigned char*) malloc (sizeof (unsigned char) * CefC_AppBuff_Size);
	
		gettimeofday (&t, NULL);
		now_time = cef_client_covert_timeval_to_us (t);

		dif_time = (uint64_t)((double) opt.lifetime * 0.3) * 1000;
		nxt_time = now_time + dif_time;
		end_time = now_time;

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
			
			/* Reads the message from cefnetd			*/
			res = cef_client_read (fhdl, &buff[index], CefC_AppBuff_Size - index);
			
			if (res > 0) {

				res += index;
			
				/* Incomming message process 		*/
				do {
					res = cef_client_payload_get_with_info (buff, res, &app_frame);

					/* InterestReturn */
					if ( (uint8_t)app_frame.type == CefC_PT_INTRETURN ) {
						fprintf (stdout, "[cefgetfile_sec] Incomplete\n");
										fprintf (stdout, 
											"[cefgetfile_sec] "
											"Received Interest Return(Type:%02x)\n", app_frame.returncode);
						app_running_f = 0;
						man_fail_f = -1;
						goto MAN_IR_RCV;
					}

					if ( app_frame.end_chunk_num >= 0 ) {
						man_end_chunk_num = app_frame.end_chunk_num;
						man_end_chunk_num++;	/* 0 Origin */
#ifdef __DEB_GET__
printf( "Manifest man_end_chunk_num+1:%ld\n", man_end_chunk_num );
#endif
					}
				
					if (app_frame.version == CefC_App_Version) {
						/* Inserts the received frame to the buffer 	*/
						if ((app_frame.chunk_num < man_rxwnd_head->seq) || 
							(app_frame.chunk_num > man_rxwnd_tail->seq)) {
						continue;
						}
						
						diff_seq = app_frame.chunk_num - man_rxwnd_head->seq;
						man_rxwnd = man_rxwnd_head;
						
						for (i = 0 ; i < diff_seq ; i++) {
							man_rxwnd = man_rxwnd->next;
						}
						
						if (man_rxwnd->flag != 1) {
							memcpy (man_rxwnd->buff, 
								app_frame.payload, app_frame.payload_len);
							man_rxwnd->frame_size = app_frame.payload_len;
							man_rxwnd->flag = 1;
							
							retry_cnt = 0;
							end_time = now_time;
							retry_int = CefC_Resend_Interval;
						}
						
						man_rxwnd = man_rxwnd_head;
							
						for (i = 0 ; i < pipeline; i++) {
								
							if (man_rxwnd->flag == 0) {
								break;
							}
#ifdef __DEB_GET__
printf( "Manifest app_frame.payload_len:%d\n", app_frame.payload_len );
#endif
							//
							memcpy( &man_rec_num, man_rxwnd->buff, 4 );
							man_content_total_chunk += man_rec_num;
#ifdef __DEB_GET__
printf( "man_rec_num:%d   man_content_total_chunk:%u\n", man_rec_num, man_content_total_chunk );
#endif
							man_stat_recv_frames++;
							fwrite (man_rxwnd->buff, 
								sizeof (unsigned char), man_rxwnd->frame_size, man_fp);

							if ( man_stat_recv_frames == man_end_chunk_num ) {
#ifdef __DEB_GET__
printf( "Manifest man_stat_recv_frames:%ld   man_end_chunk_num+1:%ld\n", man_stat_recv_frames, man_end_chunk_num );
#endif
								fprintf (stdout, "[cefgetfile_sec] Manifest Completed to get all the chunks.\n");
								app_running_f = 0;
								goto MAN_IR_RCV;
							}
						
							if (man_rxwnd->seq == UINT32_MAX) {
								fprintf (stdout, 
								"[cefgetfile_sec] "
								"Received the specified number of chunk\n");
									app_running_f = 0;
									man_fail_f = -1;
							}
							
							/* Updates head and tail pointers		*/
							man_rxwnd_head->seq 		= man_rxwnd_tail->seq + 1;
							man_rxwnd_head->flag 		= 0;
							man_rxwnd_head->frame_size 	= 0;
							
							man_rxwnd_tail->next = man_rxwnd_head;
							man_rxwnd_tail = man_rxwnd_head;
							
							man_rxwnd_head = man_rxwnd_tail->next;
							man_rxwnd_tail->next 	= NULL;
							
							man_rxwnd = man_rxwnd_head;
							
							/* Sends an interest with the next chunk number 	*/
							man_params.chunk_num = man_rxwnd_tail->seq;
							if (man_params.chunk_num <= UINT32_MAX) {
								cef_client_interest_input (fhdl, &opt, &man_params);
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
		
			if (now_time - end_time > retry_int) {
				
				if (retry_cnt == CefC_Max_Retry) {
					man_rxwnd = man_rxwnd_head;
					for (i = 0 ; i < pipeline ; i++) {
						if (man_rxwnd->flag != 0) {
							break;
						}
					}
					fprintf (stdout, "[cefgetfile_sec] Manifest Suspended to retrieve the content because the number of Interest retransmission has reached its limit, 5.\n");
					man_fail_f = -1;
					break;
				}
				
				man_rxwnd = man_rxwnd_head;
				send_cnt = 0;
				
				for (i = 0 ; i < pipeline ; i++) {
					if ((man_rxwnd->seq <= sv_max_seq) && 
						(man_rxwnd->flag == 0)) {
						man_params.chunk_num = man_rxwnd->seq;
						cef_client_interest_input (fhdl, &opt, &params);
						send_cnt++;
					}
					man_rxwnd = man_rxwnd->next;
				}
				if (send_cnt > 0) {
					retry_int += CefC_Resend_Interval;
					retry_cnt++;
				}
				end_time = now_time;
			}
		}
MAN_IR_RCV:;
	}
	if ( man_fp != NULL ) {
		fclose( man_fp );
		if (man_fail_f < 0) {
			remove(man_fpath);
			goto SKIP_CONTENT;
		}
	}

	/*---------------------------------------------------------------------------
		Sends first Interest(s)
	-----------------------------------------------------------------------------*/
	man_rec_num = 0;
#ifdef __DEV_COBH__
printf( "man_rec_num:%d\n", man_rec_num );
#endif
	// KeyIdRestriction
	if ( (mode_val == 0) || (mode_val == 2) ) {
		unsigned char keyid[32];
		uint16_t 		pubkey_len;
		unsigned char 	pubkey[CefC_Max_Length];
		
		cef_valid_init (conf_path);
		pubkey_len = (uint16_t)cef_valid_keyid_create( params.name, params.name_len, pubkey, keyid );
		
		params.KeyIdRester_f = 1;
		memcpy( params.KeyIdRester_val, keyid, 32 );
#ifdef __DEB_GET_KEY__
		{
			int dbg_x;
			fprintf (stderr, "KeyId [ ");
			for (dbg_x = 0 ; dbg_x < 32 ; dbg_x++) {
				fprintf (stderr, "%02x ", keyid[dbg_x]);
			}
			fprintf (stderr, "]\n");
		}
#endif
	} else {
		params.KeyIdRester_f = 0;
	}

	if ( (mode_val == 1) || (mode_val == 2) ) {
		/* Read Manifest */
#ifdef __DEV_COBH__
printf( "Manifest:%s\n", man_fpath );
#endif
		man_fp = fopen (man_fpath, "rb");
		if (man_fp == NULL) {
			fprintf (stdout, "ERROR: Manifest input file can not be opend.\n");
			exit (1);
		}
#ifdef __DEV_COBH__
printf( "man_buff_size:%d\n", man_buff_size );
#endif
		man_res = fread (man_buff, sizeof (unsigned char), man_buff_size, man_fp);
		if ( man_res > 0 ) {
			memcpy( &man_rec_num, man_buff, 4 );
#ifdef __DEV_COBH__
printf( "man_res:%d   man_rec_num:%d   man_buff_idx:%d\n", man_res, man_rec_num, man_buff_idx );
#endif
			man_buff_idx = 4;
			man_rec_ctr = 0;
			memcpy( &man_rec, &man_buff[man_buff_idx], man_rec_size );
			man_rec_ctr++;
			man_buff_idx += man_rec_size;
#ifdef __DEV_COBH__
printf( "man_rec.chunk:%d   man_buff_idx:%d   man_rec_ctr:%d\n", man_rec.chunk, man_buff_idx, man_rec_ctr );
#endif
		} else {
			fprintf (stdout, "ERROR: Manifest input file can not be read.\n");
			exit (1);
		}
	}


	app_running_f = 1;
	send_cnt = 0;
	fprintf (stdout, "[cefgetfile_sec] URI=%s\n", uri);

	fprintf (stdout, "[cefgetfile_sec] Start sending Interests\n");

	/* Sends Initerest(s) 		*/
	for (i = 0 ; i < pipeline ; i++) {
		if ( i == 0 ) {
			/* Creates the rx window 	*/
			rxwnd = (Ceft_RxWnd*) malloc (sizeof (Ceft_RxWnd));
			memset (rxwnd, 0, sizeof (Ceft_RxWnd));
			rxwnd->next = rxwnd;
			rxwnd->seq 	= params.chunk_num;
			rxwnd_prev = rxwnd;
			rxwnd_head = rxwnd;
			rxwnd_tail = rxwnd;
			if ( (mode_val == 1) || (mode_val == 2) ) {
				if ( params.chunk_num == man_rec.chunk ) {
#ifdef __DEV_COBH__
printf( "CKP-000 params.chunk_num:%u   man_rec.chunk:%u\n", params.chunk_num, man_rec.chunk );
#endif
#ifdef	__DEB_GET__
if ( (mode_val == 1) || ( mode_val == 2) ) {
	if ( params.chunk_num == man_rec.chunk ) {
		int hidx;
		char	hash_dbg[1024];
		sprintf (hash_dbg, "CobHash [");
		
		for (hidx = 0 ; hidx < 32 ; hidx++) {
			sprintf (hash_dbg, "%s %02X", hash_dbg, man_rec.cob_hash[hidx]);
		}
		sprintf (hash_dbg, "%s ]\n", hash_dbg);
		printf( "%s", hash_dbg );
	}
}
#endif
					params.ObjHash_f= 1;
					memcpy( params.ObjHash_val, man_rec.cob_hash, 32 );
					man_rec_ctr++;
					if ( man_rec_ctr > man_rec_num ) {
						man_res = fread (man_buff, sizeof (unsigned char), man_buff_size, man_fp);
#ifdef __DEV_COBH__
printf( "CKP-001 man_res:%d   man_rec_num:%d   man_buff_idx:%d\n", man_res, man_rec_num, man_buff_idx );
#endif
						if ( man_res > 0 ) {
							memcpy( &man_rec_num, man_buff, 4 );
							man_buff_idx = 4;
							man_rec_ctr = 0;
						} else {
							man_rec_num = 0;
						}
					}
					if ( man_rec_num > 0 ) {
#ifdef __DEV_COBH__
printf( "CKP-002 man_rec_num:%d   man_buff_idx:%d\n", man_rec_num, man_buff_idx );
#endif
						/* Next man_rec */
						memcpy( &man_rec, &man_buff[man_buff_idx], man_rec_size );
						rxwnd->CobHash_f = 1;
						memcpy( rxwnd->cob_hash, &man_buff[man_buff_idx], man_rec_size );
						man_buff_idx += man_rec_size;
//						man_rec_ctr++;
#ifdef __DEV_COBH__
printf( "CKP-003 man_rec_num:%d   man_buff_idx:%d\n", man_rec_num, man_buff_idx );
#endif
					}
				}
#ifdef __DEV_COBH__
printf( "CKP-004 man_rec.chunk:%d   man_buff_idx:%d   man_rec_ctr:%d\n", man_rec.chunk, man_buff_idx, man_rec_ctr );
#endif
			}
		} else {
			rxwnd = (Ceft_RxWnd*) malloc (sizeof (Ceft_RxWnd));
			memset (rxwnd, 0, sizeof (Ceft_RxWnd));
			rxwnd->seq = params.chunk_num;
			rxwnd_prev->next = rxwnd;
			rxwnd_tail = rxwnd;
			rxwnd_prev = rxwnd;
			if ( (mode_val == 1) || (mode_val == 2) ) {
#ifdef __DEV_COBH__
printf( "CKP-005 params.chunk_num:%u   man_rec.chunk:%u\n", params.chunk_num, man_rec.chunk );
#endif
#ifdef	__DEV_GET__
if ( (mode_val == 1) || ( mode_val == 2) ) {
	if ( params.chunk_num == man_rec.chunk ) {
		int hidx;
		char	hash_dbg[1024];
		sprintf (hash_dbg, "CobHash [");
		
		for (hidx = 0 ; hidx < 32 ; hidx++) {
			sprintf (hash_dbg, "%s %02X", hash_dbg, man_rec.cob_hash[hidx]);
		}
		sprintf (hash_dbg, "%s ]\n", hash_dbg);
		printf( "%s", hash_dbg );
	}
}
#endif
				if ( params.chunk_num == man_rec.chunk ) {
#ifdef __DEV_COBH__
printf( "CKP-006 params.chunk_num:%d   man_rec.chunk:%d\n", params.chunk_num, man_rec.chunk );
#endif
					params.ObjHash_f= 1;
					memcpy( params.ObjHash_val, man_rec.cob_hash, 32 );
					man_rec_ctr++;
					if ( man_rec_ctr > man_rec_num ) {
						man_res = fread (man_buff, sizeof (unsigned char), man_buff_size, man_fp);
#ifdef __DEV_COBH__
printf( "CKP-007 man_res:%d   man_rec_num:%d   man_buff_idx:%d\n", man_res, man_rec_num, man_buff_idx );
#endif
						if ( man_res > 0 ) {
							memcpy( &man_rec_num, man_buff, 4 );
							man_buff_idx = 4;
							man_rec_ctr = 0;
						} else {
							man_rec_num = 0;
						}
					}
					if ( man_rec_num > 0 ) {
#ifdef __DEV_COBH__
printf( "CKP-008 man_rec_num:%d   man_buff_idx:%d\n", man_rec_num, man_buff_idx );
#endif
						/* Next man_rec */
						memcpy( &man_rec, &man_buff[man_buff_idx], man_rec_size );
						rxwnd->CobHash_f = 1;
						memcpy( rxwnd->cob_hash, &man_buff[man_buff_idx], man_rec_size );
						man_buff_idx += man_rec_size;
#ifdef __DEV_COBH__
printf( "CKP-009 man_rec_num:%d   man_buff_idx:%d\n", man_rec_num, man_buff_idx );
#endif
					}
				}
#ifdef __DEV_COBH__
printf( "CKP-010 man_rec.chunk:%d   man_buff_idx:%d   man_rec_ctr:%d\n", man_rec.chunk, man_buff_idx, man_rec_ctr );
#endif
			}
		}
		cef_client_interest_input (fhdl, &opt, &params);
		params.chunk_num++;

		usleep (100000);
		
	}

	end_t.tv_sec = t.tv_sec;

	memset (&app_frame, 0, sizeof (struct cef_app_frame));

	if ( mode_val == 0 ) {
	buff = (unsigned char*) malloc (sizeof (unsigned char) * CefC_AppBuff_Size);
	}
	
	gettimeofday (&t, NULL);
	now_time = cef_client_covert_timeval_to_us (t);

	dif_time = (uint64_t)((double) opt.lifetime * 0.3) * 1000;
	nxt_time = now_time + dif_time;
	end_time = now_time;

	
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
			
			/* Incomming message process 		*/
			do {
				res = cef_client_payload_get_with_info (buff, res, &app_frame);
				
				if (app_frame.version == CefC_App_Version) {

					/* InterestReturn */
					if ( (uint8_t)app_frame.type == CefC_PT_INTRETURN ) {
						fprintf (stdout, "[cefgetfile_sec] Incomplete\n");
										fprintf (stdout, 
											"[cefgetfile_sec] "
											"Received Interest Return(Type:%02x)\n", app_frame.returncode);
						app_running_f = 0;
						rcv_ng_f = 1;
						goto IR_RCV;
					}

					if ( app_frame.end_chunk_num >= 0 ) {
						end_chunk_num = app_frame.end_chunk_num;
						end_chunk_num++;	/* 0 Origin */
#ifdef __DEV_COBH__
printf( "arxwnd_head->seq:%ld  rxwnd_tail->seq:%ld\n", rxwnd_head->seq, rxwnd_tail->seq );
printf( "app_frame.end_chunk_num:%ld  end_chunk_num+1:%ld\n", app_frame.end_chunk_num, end_chunk_num );
#endif
					}
					stat_all_recv_frames++;								//20230522
					stat_all_recv_bytes += app_frame.name_len			//20230522
										 + app_frame.ver_len			//20230522
										 + app_frame.hdr_org_len		//20230522
										 + app_frame.msg_org_len		//20230522
										 + app_frame.payload_len;		//20230522

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
						memcpy (rxwnd->buff, 
							app_frame.payload, app_frame.payload_len);
						rxwnd->frame_size = app_frame.payload_len;
						rxwnd->flag = 1;
							
						retry_cnt = 0;
						end_time = now_time;
						retry_int = CefC_Resend_Interval;
					}
						
					rxwnd = rxwnd_head;
					
					for (i = 0 ; i < pipeline; i++) {
						
						if (rxwnd->flag == 0) {
							break;
						}
						stat_recv_frames++;
						stat_recv_bytes += app_frame.payload_len;
							
						fwrite (rxwnd->buff, 
							sizeof (unsigned char), rxwnd->frame_size, fp);
							
						if ( stat_recv_frames == end_chunk_num ) {
#ifdef __DEV_COBH__
printf( "Content stat_recv_frames:%ld   end_chunk_num+1:%ld\n", stat_recv_frames, end_chunk_num );
#endif
							fprintf (stdout, "[cefgetfile_sec] Completed to get all the chunks.\n");
							app_running_f = 0;
							goto IR_RCV;
						}

						if (rxwnd->seq == UINT32_MAX) {
							fprintf (stdout, 
								"[cefgetfile_sec] "
								"Received the specified number of chunk\n");
							rcv_ng_f = 1;
							app_running_f = 0;
						}
							
						/* Updates head and tail pointers		*/
						rxwnd_head->seq 		= rxwnd_tail->seq + 1;
						rxwnd_head->flag 		= 0;
						rxwnd_head->frame_size 	= 0;
						rxwnd_head->CobHash_f	= 0;
							
						rxwnd_tail->next = rxwnd_head;
						rxwnd_tail = rxwnd_head;
						
						rxwnd_head = rxwnd_tail->next;
						rxwnd_tail->next 	= NULL;
						
						rxwnd = rxwnd_head;
						
						/* Sends an interest with the next chunk number 	*/
						params.chunk_num = rxwnd_tail->seq;
						if (params.chunk_num <= UINT32_MAX) {
							if ( (mode_val == 1) || (mode_val == 2) ) {
#ifdef __DEV_COBH__
printf( "CKP-100 params.chunk_num:%u   man_rec.chunk:%u\n", params.chunk_num, man_rec.chunk );
#endif
#ifdef __DEB_GET__
if ( (mode_val == 1) || ( mode_val == 2) ) {
	if ( params.chunk_num == man_rec.chunk ) {
		int hidx;
		char	hash_dbg[1024];
		sprintf (hash_dbg, "CobHash [");
		
		for (hidx = 0 ; hidx < 32 ; hidx++) {
			sprintf (hash_dbg, "%s %02X", hash_dbg, man_rec.cob_hash[hidx]);
		}
		sprintf (hash_dbg, "%s ]\n", hash_dbg);
		printf( "%s", hash_dbg );
	}
}
#endif
								if ( params.chunk_num == man_rec.chunk ) {
#ifdef __DEV_COBH__
printf( "CKP-101 params.chunk_num:%u   man_rec.chunk:%u\n", params.chunk_num, man_rec.chunk );
#endif
									params.ObjHash_f= 1;
									memcpy( params.ObjHash_val, man_rec.cob_hash, 32 );
									man_rec_ctr++;
									if ( man_rec_ctr > man_rec_num ) {
										man_res = fread (man_buff, sizeof (unsigned char), man_buff_size, man_fp);
#ifdef __DEV_COBH__
printf( "CKP-102 man_res:%d   man_rec_num:%d   man_buff_idx:%d\n", man_res, man_rec_num, man_buff_idx );
#endif
										if ( man_res > 0 ) {
											memcpy( &man_rec_num, man_buff, 4 );
											man_buff_idx = 4;
											man_rec_ctr = 1;
										} else {
											man_rec_num = 0;
										}
									}
									if ( man_rec_num > 0 ) {
										/* Next man_rec */
#ifdef __DEV_COBH__
printf( "CKP-103 man_rec_num:%d   man_buff_idx:%d\n", man_rec_num, man_buff_idx );
#endif
										memcpy( &man_rec, &man_buff[man_buff_idx], man_rec_size );
										rxwnd_tail->CobHash_f = 1;
										memcpy( rxwnd_tail->cob_hash, &man_buff[man_buff_idx], man_rec_size );
										man_buff_idx += man_rec_size;
#ifdef __DEV_COBH__
printf( "CKP-104 man_rec_num:%d   man_buff_idx:%d\n", man_rec_num, man_buff_idx );
#endif
									}
#ifdef __DEV_COBH__
printf( "CKP-105 man_rec.chunk:%u   man_buff_idx:%d   man_rec_ctr:%d\n", man_rec.chunk, man_buff_idx, man_rec_ctr );
#endif
								}
							}
							cef_client_interest_input (fhdl, &opt, &params);
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
		
		if (now_time - end_time > retry_int) {
			
			if (retry_cnt == CefC_Max_Retry) {
				rxwnd = rxwnd_head;
				for (i = 0 ; i < pipeline ; i++) {
					if (rxwnd->flag != 0) {
						break;
					}
				}
				fprintf (stdout, "[cefgetfile_sec] Suspended to retrieve the content because the number of Interest retransmission has reached its limit, 5.\n");
				rcv_ng_f = 1;
				break;
			}
				
			rxwnd = rxwnd_head;
			send_cnt = 0;
				
			for (i = 0 ; i < pipeline ; i++) {
				if ((rxwnd->seq <= sv_max_seq) && 
					(rxwnd->flag == 0)) {
					params.chunk_num = rxwnd->seq;
#ifdef __DEV_COBH__
printf( "CKP-200 params.chunk_num:%u\n", params.chunk_num );
#endif
#ifdef	__DEV_GET__
if ( (mode_val == 1) || ( mode_val == 2) ) {
	if (rxwnd_head->CobHash_f == 1) {
		int hidx;
		char	hash_dbg[1024];
		sprintf (hash_dbg, "CobHash [");
		
		for (hidx = 0 ; hidx < 32 ; hidx++) {
			sprintf (hash_dbg, "%s %02X", hash_dbg, rxwnd->cob_hash[hidx]);
		}
		sprintf (hash_dbg, "%s ]\n", hash_dbg);
		printf( "%s", hash_dbg );
	}
}
#endif
					if ( (mode_val == 1) || (mode_val == 2) ) {
						if (rxwnd_head->CobHash_f == 1) {
							params.ObjHash_f= 1;
							memcpy( params.ObjHash_val, rxwnd->cob_hash, 32 );
						}
					}
					cef_client_interest_input (fhdl, &opt, &params);
					send_cnt++;
				}
				rxwnd = rxwnd->next;
			}
			if (send_cnt > 0) {
				retry_int += CefC_Resend_Interval;
				retry_cnt++;
			}
			end_time = now_time;
		}
IR_RCV:;	
	}
	
	fclose (fp);
	remove(man_fpath);
	if (rcv_ng_f) {
		remove(fpath);
	}

SKIP_CONTENT:;
	post_process ();
	
	exit (0);
}

static void
print_usage (
	void
) {
	
	fprintf (stdout, "\nUsage: cefgetfile_sec\n\n");
	fprintf (stdout, "  cefgetfile_sec uri -f file [-m mode] [-s pipeline] [-d config_file_dir] [-p port_num]\n\n");
	fprintf (stdout, "  uri              Specify the URI.\n");
	fprintf (stdout, "  file             Specify the file name of output. \n");
	fprintf (stdout, "  mode             0: Send Interest with KeyIdRestriction TLV set.\n"
	                 "                   1: Send Interest requesting Manifest, and send Interest with a CobHash value set.\n"
	                 "                   2: Send Interest requesting Manifest, and send Interest with KeyIdRestriction TLV and CobHash value set.\n");
	fprintf (stdout, "  pipeline         Number of pipeline\n");
	fprintf (stderr, "  config_file_dir  Configure file directory\n");
	fprintf (stderr, "  port_num         Port Number\n\n");
}

static void
post_process (
	void
) {
	uint64_t diff_t;
	double diff_t_dbl = 0.0;
	double thrpt = 0.0;
	double goodpt = 0.0;	//20230522
	uint64_t recv_bits;
	uint64_t all_recv_bits;	//20230522
	uint64_t jitter_ave;
	struct timeval diff_tval;
	int	invalid_end = 0;
	
	if (stat_recv_frames) {
		if ( timercmp( &start_t, &end_t, < ) == 0 ) {
			// Invalid end time
			fprintf (stdout, "[cefgetfile_sec] Invalid end time. No time statistics reported.\n");
			diff_t = 0;
			invalid_end = 1;
		} else {
			timersub( &end_t, &start_t, &diff_tval );
			diff_t = diff_tval.tv_sec * 1000000llu + diff_tval.tv_usec;
		}
	} else {
		diff_t = 0;
	}
	usleep (1000000);
	fprintf (stdout, "[cefgetfile_sec] Unconnect to cefnetd ... ");
	cef_client_close (fhdl);
	fprintf (stdout, "OK\n");
	
	fprintf (stdout, "[cefgetfile_sec] Terminate\n");
	fprintf (stdout, "[cefgetfile_sec] Rx Frames (All)           = "FMTU64"\n", stat_all_recv_frames);			//20230522
	fprintf (stdout, "[cefgetfile_sec] Rx Frames (ContentObject) = "FMTU64"\n", stat_recv_frames);				//20230522
	if (rcv_ng_f) {
		fprintf (stdout, "[cefgetfile_sec] Received frame ... NG\n");
		fprintf (stdout, "[cefgetfile_sec] Could not receive anything\n");
	} else {
		fprintf (stdout, "[cefgetfile_sec] Rx Bytes (All)           = "FMTU64"\n", stat_all_recv_bytes);		//20230522
		fprintf (stdout, "[cefgetfile_sec] Rx Bytes (ContentObject) = "FMTU64"\n", stat_recv_bytes);			//20230522
		if (diff_t > 0) {
			diff_t_dbl = (double)diff_t / 1000000.0;
			fprintf (stdout, "[cefgetfile_sec] Duration                 = %.3f sec\n", diff_t_dbl + 0.0009);
			recv_bits = stat_recv_bytes * 8;
			all_recv_bits = stat_all_recv_bytes * 8;															//20230522
			thrpt = (double)(all_recv_bits) / diff_t_dbl;														//20230522
			goodpt = (double)(recv_bits) / diff_t_dbl;															//20230522
			fprintf (stdout, "[cefgetfile_sec] Throughput               = "FMTU64" bps\n", (uint64_t)thrpt);	//20230522
			fprintf (stdout, "[cefgetfile_sec] Goodput                  = "FMTU64" bps\n", (uint64_t)goodpt);	//20230522
		} else {
//			fprintf (stdout, "[cefgetfile_sec] Duration                 = 0.000 sec\n");
		}
		if ((stat_recv_frames > 0) && (invalid_end == 0)) {
			jitter_ave = stat_jitter_sum / stat_recv_frames;
	
			fprintf (stdout, "[cefgetfile_sec] Jitter (Ave)             = "FMTU64" us\n", jitter_ave);
			fprintf (stdout, "[cefgetfile_sec] Jitter (Max)             = "FMTU64" us\n", stat_jitter_max);
			fprintf (stdout, "[cefgetfile_sec] Jitter (Var)             = "FMTU64" us\n"
				, (stat_jitter_sq_sum / stat_recv_frames) - (jitter_ave * jitter_ave));
		}
	}
}
static void
sigcatch (
	int sig
) {
	if (sig == SIGINT) {
		fprintf (stdout, "[cefgetfile_sec] Catch the signal\n");
		app_running_f = 0;
	}
}

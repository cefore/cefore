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
 * cefgetcontent.c
 */

#define __CEF_CONTENTGET_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdio.h>
#include <stdlib.h>

#include <sys/stat.h>
#include <sys/mman.h>
#include <openssl/sha.h>
#include <limits.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/wait.h>

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
	struct _Ceft_RxWnd* 	next;
	
} Ceft_RxWnd;

struct sign_tlv {
	
	uint16_t 		type;
	uint16_t 		length;
	unsigned char 	hash[SHA256_DIGEST_LENGTH];
	
} __attribute__((__packed__));

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
int rcv_ng_f = 0;



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
	char uri[1024];
	char fpath[1024];
	unsigned char req_version[CefC_Max_Length];
	uint16_t req_ver_len = 0;
	unsigned char rcvd_version[CefC_Max_Length];
	uint16_t rcvd_ver_len = 0;
	unsigned char name[CefC_Max_Length];
	int name_len;
	CefT_CcnMsg_OptHdr opt;
	CefT_CcnMsg_MsgBdy params;
	struct timeval t;
	uint64_t now_time;
	uint64_t end_time;
	uint64_t val;
	uint32_t diff_seq;
	int send_cnt = 0;
	int i;
	char*	work_arg;
	uint16_t valid_alg = 0;
	
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
	
	/***** flags 		*****/
	int pipeline_f 		= 0;
	int uri_f 			= 0;
	int file_f 			= 0;
	int get_sign_f 		= 0;
	int dir_path_f 		= 0;
	int port_num_f 		= 0;
	int valid_f 		= 0;
	int get_ver_f 		= 0;
	
	/***** state variavles 	*****/
	uint32_t 	sv_max_seq 		= UINT32_MAX - 1;
	
#ifdef CefC_Develop
	/***** debug 	*****/
	int version_f = 0;
	char version[65535];
	int vlen = 0;
#endif // CefC_Develop
	
	memset (&opt, 0, sizeof (CefT_CcnMsg_OptHdr));
	memset (&params, 0, sizeof (CefT_CcnMsg_MsgBdy));
	
	
	/*---------------------------------------------------------------------------
		Obtains parameters
	-----------------------------------------------------------------------------*/
	/* Inits logging 		*/
	cef_log_init ("cefgetcontent", 1);
	
	/* Parses parameters 		*/
	for (i = 1 ; i < argc ; i++) {
		
		work_arg = argv[i];
		if (work_arg == NULL || work_arg[0] == 0) {
			break;
		}
		
		if (strcmp (work_arg, "-f") == 0) {
			if (file_f) {
				fprintf (stderr, "[cefgetcontent] ERROR: file is duplicated.");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stderr, "[cefgetcontent] ERROR: file is not specified.");
				print_usage ();
				return (-1);
			}
			work_arg = argv[i + 1];
			
			if (strlen (work_arg) >= CefC_Max_Length) {
				fprintf (stderr, "[cefgetcontent] ERROR: file is too long.");
				print_usage ();
				return (-1);
			}
			file_f++;
			strcpy (fpath, work_arg);
			i++;
		} else if (strcmp (work_arg, "-s") == 0) {
			if (pipeline_f) {
				fprintf (stderr, "[cefgetcontent] ERROR: pipeline is duplicated.");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stderr, "[cefgetcontent] ERROR: pipeline is not specified.");
				print_usage ();
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
		} else if (strcmp (work_arg, "-h") == 0) {
			print_usage ();
			exit (1);
		} else if (strcmp (work_arg, "-d") == 0) {
			if (dir_path_f) {
				fprintf (stderr, "[cefgetcontent] ERROR: [-d] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stderr, "[cefgetcontent] ERROR: [-d] has no parameter.\n");
				return (-1);
			}
			//202108
			if (strlen(argv[i + 1]) > PATH_MAX) {
				fprintf (stderr, "[cefgetcontent] ERROR: [-d] parameter is too long.\n");
				return (-1);
			}
			work_arg = argv[i + 1];
			strcpy (conf_path, work_arg);
			dir_path_f++;
			i++;
		} else if (strcmp (work_arg, "-p") == 0) {
			if (port_num_f) {
				fprintf (stderr, "[cefgetcontent] ERROR: [-p] is duplicated.\n");
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stderr, "[cefgetcontent] ERROR: [-p] has no parameter.\n");
				return (-1);
			}
			work_arg = argv[i + 1];
			port_num = atoi (work_arg);
			port_num_f++;
			i++;
#ifdef CefC_Develop
		} else if (strcmp (work_arg, "-vsn") == 0) {
			if (version_f) {
				fprintf (stderr, "[cefgetcontent] ERROR: [-vsn] is duplicated.\n");
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stderr, "[cefgetcontent] ERROR: [-vsn] is not specified.\n");
				return (-1);
			}
			work_arg = argv[i + 1];
			vlen = strlen (work_arg);
			memcpy (version, work_arg, vlen);
			version[vlen] = 0x00;
			version_f++;
			i++;
#endif // CefC_Develop
		} else if (strcmp (work_arg, "-v") == 0) {
			if (valid_f) {
				fprintf (stderr, "[cefgetcontent] ERROR: [-v] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stderr, "[cefgetcontent] ERROR: [-v] has no parameter.\n");
				print_usage ();
				return (-1);
			}
			work_arg = argv[i + 1];
			strcpy (valid_type, work_arg);
			valid_f++;
			i++;
		} else if (strcmp (work_arg, "-gv") == 0) {
			if (get_ver_f) {
				fprintf (stderr, "[cefgetcontent] ERROR: [-gv] is duplicated.\n");
				print_usage ();
				return (-1);
			}
			get_ver_f++;
		} else {
			
			work_arg = argv[i];
			
			if (work_arg[0] == '-') {
				fprintf (stderr, "[cefgetcontent] ERROR: unknown option is specified.");
				print_usage ();
				return (-1);
			}
			
			if (uri_f) {
				fprintf (stderr, "[cefgetcontent] ERROR: uri is duplicated.");
				print_usage ();
				return (-1);
			}
			res = strlen (work_arg);
			
			if (res >= 1204) {
				fprintf (stderr, "[cefgetcontent] ERROR: uri is too long.");
				print_usage ();
				return (-1);
			}
			strcpy (uri, work_arg);
			uri_f++;
		}
	}
	
	/* Checks errors 			*/
	if (uri_f == 0) {
		fprintf (stderr, "[cefgetcontent] ERROR: uri is not specified.\n");
		print_usage ();
		exit (1);
	}
	if (get_ver_f == 0 && file_f == 0) {
		fprintf (stderr, "[cefgetcontent] ERROR: file is not specified.\n");
		print_usage ();
		exit (1);
	}
	cef_log_init2 (conf_path, 2 /* for CONPUBD */);
#ifdef CefC_Debug
	cef_dbg_init ("cefgetcontent", conf_path, 2);
#endif // CefC_Debug

	/*---------------------------------------------------------------------------
		Inits the Cefore APIs
	-----------------------------------------------------------------------------*/
	cef_frame_init ();
	res = cef_client_init (port_num, conf_path);
	if (res < 0) {
		fprintf (stderr, "[cefgetcontent] ERROR: Failed to init the client package.\n");
		exit (1);
	}
	res = cef_frame_conversion_uri_to_name (uri, name);
	if (res < 0) {
		fprintf (stderr, "[cefgetcontent] ERROR: Invalid URI is specified.\n");
		print_usage ();
		exit (1);
	}
	name_len = res;
	
	if (get_ver_f == 0) {
		fp = fopen (fpath, "wb");
		if (fp == NULL) {
			fprintf (stderr, "[cefgetcontent] ERROR: Specified file can not be opend.\n");
			exit (1);
		}
	}
	
	if (valid_f == 1) {
		cef_valid_init (conf_path);
		valid_alg = (uint16_t) cef_valid_type_get (valid_type);
		
		if (valid_alg == CefC_T_ALG_INVALID) {
			fprintf (stdout, 
				"[cefgetcontent] ERROR: -v has the invalid parameter %s\n", valid_type);
			exit (1);
		}
	}
	
	fhdl = cef_client_connect ();
	if (fhdl < 1) {
		fprintf (stderr, "[cefgetcontent] ERROR: cefnetd is not running.\n");
		exit (1);
	}
#ifdef CefC_Develop
	if (version_f) {
		goto GETCONTENT;
	}
#endif // CefC_Develop
	/*---------------------------------------------------------------------------
		Gets Version
	-----------------------------------------------------------------------------*/
	memset (&params, 0, sizeof (CefT_CcnMsg_MsgBdy));
	params.hoplimit 		= 32;
	opt.lifetime_f 	= 1;
	opt.lifetime 	= CefC_Default_LifetimeSec * 1000;
	memcpy (params.name, name, name_len);
	params.name_len = name_len;
	params.alg.valid_type = valid_alg;
	/* Version Request */
	params.org.version_f = 1;
	params.org.version_len  = 0;
	
	cef_client_interest_input (fhdl, &opt, &params);
	app_running_f = 1;
	gettimeofday (&t, NULL);
	end_time = (t.tv_sec + 4) * 1000000llu + t.tv_usec;
	buff = (unsigned char*) malloc (sizeof (unsigned char) * CefC_AppBuff_Size);
	memset (&app_frame, 0, sizeof (struct cef_app_frame));
	
	while (app_running_f) {
		if (SIG_ERR == signal (SIGINT, sigcatch)) {
			break;
		}
		/* Obtains UNIX time 			*/
		gettimeofday (&t, NULL);
		now_time = t.tv_sec * 1000000llu + t.tv_usec;
		
		if (now_time > end_time) {
			break;
		}
		
		/* Reads the message from cefnetd			*/
		res = cef_client_read (fhdl, &buff[index], CefC_AppBuff_Size - index);
		
		if (res > 0) {
			res += index;
			
			do {
				res = cef_client_payload_get_with_info (buff, res, &app_frame);
				
				if (app_frame.version == CefC_App_Version) {

					/* InterestReturn */
					if ( (uint8_t)app_frame.type == CefC_PT_INTRETURN ) {
						fprintf (stdout, "[cefgetcontent] Incomplete\n");
						fprintf (stdout, "[cefgetcontent] "
											"Received Interest Return(Type:%02x)\n", app_frame.returncode);
						app_running_f = 0;
						goto IR_RCV;
					}
					
					if (app_frame.version_f) {
						if (app_frame.ver_len == 0) {
							/* Response to Version Request */
							req_ver_len = app_frame.payload_len;
							if (req_ver_len) {
								memcpy (req_version, app_frame.payload, req_ver_len);
								fprintf (stdout, "[cefgetcontent] Responded version is \"%s\"\n", app_frame.payload);
							} else {
								req_version[0] = 0x00;
								fprintf (stdout, "[cefgetcontent] Responded version is \"None\"\n");
							}
							goto CONTENTGET_KEY;
						} else {
							break;
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
IR_RCV:;	
	}
	
	if (get_sign_f == 0) {
		fprintf (stderr, "[cefgetcontent] Failed to receive Version\n");
		rcv_ng_f = 1;
		if (get_ver_f) {
			fprintf (stderr, "[cefgetcontent] Stop\n");
			exit (0);
		}
		goto CONTENTGET_POST;
	}
	
CONTENTGET_KEY:
	fprintf (stderr, "[cefgetcontent] Success in getting Version\n");
	if (get_ver_f) {
		fprintf (stderr, "[cefgetcontent] Stop\n");
		exit (0);
	}
	fprintf (stderr, "[cefgetcontent] Initialization ...\n");
//	sleep (5);
	
#ifdef CefC_Develop
GETCONTENT:;
#endif // CefC_Develop
	/*---------------------------------------------------------------------------
		Sets Interest parameters
	-----------------------------------------------------------------------------*/
	memset (&opt, 0, sizeof (CefT_CcnMsg_OptHdr));
	memset (&params, 0, sizeof (CefT_CcnMsg_MsgBdy));
	
	/* Creates the name with Version	*/
	memcpy (params.name, name, name_len);
	params.name_len = name_len;
	/* Sets Version */
#ifdef CefC_Develop
	if (!version_f) {
#endif // CefC_Develop
	params.org.version_len= req_ver_len;
	if (req_ver_len) {
		/* Versioned Contents */
		params.org.version_f = 1;
		memcpy (&params.org.version_val, req_version, params.org.version_len);
	} else {
		/* Unversioned Contents */
		params.org.version_f = 0;
		params.org.version_val[0] = 0x00;
	}
#ifdef CefC_Develop
	} else {
		if (vlen == 4 && strncmp (version, "None", vlen) == 0) {
			params.org.version_f = 0;
			params.org.version_val[0] = 0x00;
		} else {
			params.org.version_f = 1;
			params.org.version_len = vlen;
			memcpy (&params.org.version_val, version, params.org.version_len);
			req_ver_len = vlen;
			memcpy (req_version, version, req_ver_len);
		}
	}
#endif // CefC_Develop
	
	params.hoplimit 		= 32;
	opt.lifetime_f 	= 1;
	opt.lifetime 	= CefC_Default_LifetimeSec * 1000;
	Cef_Int_Regular(params);	
	params.chunk_num		= 0;
	params.chunk_num_f		= 1;
	
	params.alg.valid_type = valid_alg;
	
	gettimeofday (&t, NULL);
	now_time = cef_client_covert_timeval_to_us (t);
	
	/*---------------------------------------------------------------------------
		Sends first Interest(s)
	-----------------------------------------------------------------------------*/
	app_running_f = 1;
	index = 0;
	fprintf (stderr, "[cefgetcontent] Start\n");
	fprintf (stderr, "[cefgetcontent] Running ...\n");
		
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
		rxwnd->seq = (uint32_t) i;
		rxwnd_prev->next = rxwnd;
		rxwnd_tail = rxwnd;
		rxwnd_prev = rxwnd;
	}
	end_t.tv_sec = t.tv_sec;
	memset (&app_frame, 0, sizeof (struct cef_app_frame));
	buff = (unsigned char*) malloc (sizeof (unsigned char) * CefC_AppBuff_Size);
	
	gettimeofday (&t, NULL);
	now_time = cef_client_covert_timeval_to_us (t);
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
						fprintf (stdout, "[cefgetcontent] Incomplete\n");
						fprintf (stdout, "[cefgetcontent] "
											"Received Interest Return(Type:%02x)\n", app_frame.returncode);
						app_running_f = 0;
						rcv_ng_f = 1;
						goto IR_RCV2;
					}
					
					/* Check Version */
					if (req_ver_len) {
						if (app_frame.ver_len == req_ver_len &&
							memcmp (app_frame.ver_value, req_version, req_ver_len) == 0) {
							; /* Contents that matches request */
						} else {
							/* Version different from the requested version */
							break;
						}
					} else {
						if (stat_recv_frames < 1) {
							/* Record the first received version */
							if (app_frame.ver_len) {
								memcpy (rcvd_version, app_frame.ver_value, app_frame.ver_len);
								fprintf (stdout, "[cefgetcontent] Received version is \"%s\"\n", rcvd_version);
							} else {
								rcvd_version[0] = 0x00;
								fprintf (stdout, "[cefgetcontent] Received version is \"None\"\n");
							}
							rcvd_ver_len = app_frame.ver_len;
						} else {
							if (rcvd_ver_len) {
								if (app_frame.ver_len == rcvd_ver_len &&
									memcmp (app_frame.ver_value, rcvd_version, rcvd_ver_len) == 0) {
									;/* Contents that matches first received */
								} else {
									/* Version different from the first received version */
									break;
								}
							} else {
								if (app_frame.ver_len) {
									/* The first cob was unversioned,   */
									/* but next cob was versioned ...   */
									break;
								}
							}
						}
					}
					
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
						memcpy (rxwnd->buff, app_frame.payload, app_frame.payload_len);
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
						
						if (rxwnd->seq == UINT32_MAX /*sv_max_seq*/) {
							fprintf (stdout, 
								"[cefgetcontent] "
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
						if (params.chunk_num <=  UINT32_MAX/* sv_max_seq+1 */) {
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
		
		/* Sends Interest with Symbolic flag to CEFORE 		*/
		if (now_time - end_time > retry_int) {
			
			if (retry_cnt == CefC_Max_Retry) {
				rxwnd = rxwnd_head;
				for (i = 0 ; i < pipeline ; i++) {
					if (rxwnd->flag != 0) {
						break;
					}
				}
				if (i != pipeline) {
					fprintf (stdout, "[cefgetcontent] Incomplete\n");
					rcv_ng_f = 1;
				} else {
					if (stat_recv_frames) {
						fprintf (stdout, "[cefgetcontent] Complete\n");
					} else {
						fprintf (stdout, "[cefgetcontent] Incomplete\n");
						rcv_ng_f = 1;
					}
				}
				break;
			}
	
			rxwnd = rxwnd_head;
			send_cnt = 0;
			
			for (i = 0 ; i < pipeline ; i++) {
				if ((rxwnd->seq <= sv_max_seq) && 
					(rxwnd->flag == 0)) {
					params.chunk_num = rxwnd->seq;
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
IR_RCV2:;	
	}
	
CONTENTGET_POST:;
	fclose(fp);
	if (rcv_ng_f) {
		remove(fpath);
	}
	post_process ();
	
	exit (0);
}

static void
print_usage (
	void
) {
	
	fprintf (stderr, "\nUsage: cefgetcontent\n");
	fprintf (stderr, "  cefgetcontent uri -f file [-s pipeline] [-d config_file_dir] [-p port_num] [-v valid_alg] [-gv]\n\n");
	fprintf (stderr, "  uri              URI of the content that you want to get\n");
	fprintf (stderr, "  file             File name that you save\n");
	fprintf (stderr, "  pipeline         Number of pipeline\n");
	fprintf (stderr, "  config_file_dir  Configure file directory\n");
	fprintf (stderr, "  port_num         Port Number\n");
	fprintf (stderr, "  valid_alg        Validation Algorithm\n");
	fprintf (stderr, "  -gv              Just get the version of the content indicated by URI\n\n");
}

static void
post_process (
	void
) {
	uint64_t diff_t;
	double diff_t_dbl = 0.0;
	double thrpt = 0.0;
	uint64_t recv_bits;
	uint64_t jitter_ave;

	if (stat_recv_frames) {
		diff_t = (end_t.tv_sec - start_t.tv_sec) * 1000000llu
								+ (end_t.tv_usec - start_t.tv_usec);
	} else {
		diff_t = 0;
	}

	usleep (1000000);

	cef_client_close (fhdl);

	fprintf (stderr, "[cefgetcontent] Stop\n");
	fprintf (stderr, "[cefgetcontent] Rx Frames = "FMTU64"\n", stat_recv_frames);
	fprintf (stderr, "[cefgetcontent] Rx Bytes  = "FMTU64"\n", stat_recv_bytes);
	if (diff_t > 0) {
		diff_t_dbl = (double)diff_t / 1000000.0;
		fprintf (stdout, "[cefgetcontent] Duration  = %.3f sec\n", diff_t_dbl + 0.0009);
		recv_bits = stat_recv_bytes * 8;
		thrpt = (double)(recv_bits) / diff_t_dbl;
		fprintf (stderr, "[cefgetcontent] Throughput = %d bps\n", (int)thrpt);
	} else {
		fprintf (stdout, "[cefgetcontent] Duration  = 0.000 sec\n");
	}
	if (stat_recv_frames > 0) {
		jitter_ave = stat_jitter_sum / stat_recv_frames;

		fprintf (stderr, "[cefgetcontent] Jitter (Ave) = "FMTU64" us\n", jitter_ave);
		fprintf (stderr, "[cefgetcontent] Jitter (Max) = "FMTU64" us\n", stat_jitter_max);
		fprintf (stderr, "[cefgetcontent] Jitter (Var) = "FMTU64" us\n"
			, (stat_jitter_sq_sum / stat_recv_frames) - (jitter_ave * jitter_ave));
	}
}
static void
sigcatch (
	int sig
) {
	if (sig == SIGINT) {
		app_running_f = 0;
	}
}

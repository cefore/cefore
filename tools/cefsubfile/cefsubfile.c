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
 * cefsubfile.c
 */

#define __CEF_SUBFILE_SOURECE__
/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>
#include <time.h>
#include <sys/time.h>
#include <stdarg.h>

#include <cefore/cef_define.h>
#include <cefore/cef_frame.h>
#include <cefore/cef_client.h>
#include <cefore/cef_valid.h>
#include <cefore/cef_log.h>

#ifdef REFLEXIVE_FORWARDING
/****************************************************************************************
 Macros
 ****************************************************************************************/
#define CefC_Max_Str_Len			1024	/* MAX length of string */
#define CefC_Max_PipeLine			10000	/* MAX Pipeline */
#define CefC_Def_PipeLine			8		/* Default Pipeline */
#define CefC_Lifetime_Max			64000	/* 64sec */
#define CefC_Lifetime_Min			1000	/* 1sec */
#define CefC_Resend_Interval		300000	/* 300 ms		*/
#define CefC_Max_Retry				5
#define CefC_Session_Limit			8		/* MAX Session */

#define USAGE					print_usage(CefFp_Usage);
#define CefC_BASIC_LOG_OUTPUT	stderr
#define printlog(...)			fprintf(CefC_BASIC_LOG_OUTPUT, "[cefsubfile] " __VA_ARGS__)
#define printerr(...)			fprintf(stderr, "[cefsubfile] ERROR: " __VA_ARGS__)

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/
typedef enum {
	CefC_Ref_RGI = 0,
	CefC_Ref_SMI
} IntType;

typedef enum {
	CefC_Output_File = 0,
	CefC_Output_File_Spec,
	CefC_Output_Stdout
} OutputType;

typedef enum	{
	RxSts_Null,
	RxSts_Request,
	RxSts_Receive,
}	Rx_Status;

typedef struct _Ceft_RxWnd {

	uint64_t 				seq;
	int		 				status;
	int		 				retry_count;
	uint64_t				req_time;
	uint64_t				retry_time;
	unsigned char 			buff[CefC_Max_Length];
	int 					frame_size;
	struct _Ceft_RxWnd* 	next;

} Ceft_RxWnd;

typedef struct _CefT_RxSession {
	unsigned char			rnp[CefC_NAME_MAXLEN];
	uint16_t				rnp_len;
	int64_t					end_chunk_num;
	uint8_t					symbolic_f;
	
	Ceft_RxWnd*				rxwnd_head;
	Ceft_RxWnd* 			rxwnd_tail;

	uint64_t 				nxt_time;
	uint64_t 				end_time;
	char					fpath[PATH_MAX];
	FILE*					fp;

	struct _CefT_RxSession*	next_session;

	uint64_t				recv_frames;
	uint64_t 				stat_recv_bytes;
	uint64_t 				stat_all_recv_frames;
	uint64_t 				stat_all_recv_bytes;
	uint64_t 				stat_jitter_sum;
	uint64_t 				stat_jitter_sq_sum;
	uint64_t 				stat_jitter_max;
	struct timeval 			start_t;
	struct timeval 			end_t;

} CefT_RxSession;

#define	RxWnd_NotRequest(r)	(RxSts_Request > (r)->status)
#define	RxWnd_IsRequest(r)	(RxSts_Request <= (r)->status)
#define	RxWnd_IsInflight(r)	(RxSts_Request == (r)->status)
#define	RxWnd_IsReceived(r)	(RxSts_Request < (r)->status)

#define	CefC_RxWndSize	CefC_Max_PipeLine
#define	T_RETRY_INTERVAL(n)	(n * 1000 * 3 / 4)

/****************************************************************************************
 State Variables
 ****************************************************************************************/
static int app_running_f = 0;
CefT_Client_Handle fhdl;
#ifdef CefC_Debug
char dbg_msg[CefC_Max_Str_Len];
#endif // CefC_Debug

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/
static void
print_usage (
	FILE* ofp						/* File pointer to output */
);
static void
output_payload (
	CefT_RxSession* rxsession,		/* rxsession to output */
	OutputType file_f
);
int
set_rnp_to_name (
	unsigned char* name,			/* name */
	unsigned int name_len,			/* length of name */
	unsigned char* rnp,				/* rnp */
	unsigned int rnp_len			/* length of rnp */
);
int
send_trigger_data (
	CefT_RxSession* rxsession,		/* rxsession */
	CefT_CcnMsg_OptHdr* poh_TD,		/* Option Header for Trg.Data */
	CefT_CcnMsg_MsgBdy* pm_TD,		/* CEFORE message for Trg.Data */
	char* uri						/* URI for conversion to Name */
);
static void
send_reflexive_interest (
	CefT_RxSession* rxsession,		/* rxsession */
	CefT_CcnMsg_OptHdr* poh_RI,		/* Option Header for Ref.Int */
	CefT_CcnMsg_MsgBdy* pm_RI,		/* CEFORE message for Ref.Int */
	uint64_t lifetime,				/* lifetime to set Ref.Int  */
	int int_type					/* Packet type. RGI:0, SMI:1 */
);
static void
sigcatch (
	int sig
);
#endif // REFLEXIVE_FORWARDING

/****************************************************************************************
 ****************************************************************************************/
int main (
	int argc,	
	char** argv
) {	
#ifdef REFLEXIVE_FORWARDING
	int res;
	int res_ref;
	int i, j;
	int index = 0;

	char* work_arg;
	char uri[CefC_Max_Str_Len];
	char fpath_base[CefC_Max_Str_Len] = {0};
	unsigned char reg_fib_name[CefC_Max_Str_Len];
	int reg_fib_name_len;

	char valid_type_RI[CefC_Max_Str_Len];
	char valid_type_TD[CefC_Max_Str_Len];

	char conf_path[PATH_MAX] = {0};
	int port_num = CefC_Unset_Port;
	int pipeline = CefC_Def_PipeLine;
	uint64_t lifetime = CefC_Default_LifetimeSec * 1000;
	uint64_t lifetime_smi = 4000;

	unsigned char* buff = NULL;
	CefT_CcnMsg_MsgBdy pm_RI;
	CefT_CcnMsg_MsgBdy pm_TD;
	CefT_CcnMsg_MsgBdy pm_rx;
	CefT_CcnMsg_OptHdr poh_RI;
	CefT_CcnMsg_OptHdr poh_TD;
	CefT_CcnMsg_OptHdr poh_rx;
	Ceft_RxWnd* rxwnd;
	Ceft_RxWnd* rxwnd_prev;
	CefT_RxSession* rxsession = NULL;
	CefT_RxSession* rxsession_head = NULL;
	CefT_RxSession* rxsession_prev = NULL;

	struct timeval t;
	uint64_t val;
	uint64_t now_time;
	uint64_t diff_seq;
	unsigned char rnp_tmp[CefC_Max_Str_Len];

	/***** flags 		*****/
	int pipeline_f = 0;
	int uri_f = 0;
	int dir_path_f = 0;
	int port_num_f = 0;
	int valid_RI_f = 0;
	int valid_TD_f = 0;
	int lifetime_f = 0;
	int session_f = 0;
	int no_resend_f = 0;
	OutputType file_f = CefC_Output_File;

	/*---------------------------------------------------------------------------
	  Obtains parameters
  	-----------------------------------------------------------------------------*/
	uri[0] = 0;
	valid_type_RI[0] = 0;
	valid_type_TD[0] = 0;
	
	printlog("Start\n");

	/* Inits logging 		*/
	cef_log_init ("cefsubfile", 1);
#ifdef CefC_Debug
	cef_dbg_init ("cefsubfile", conf_path, 1);
#endif // CefC_Debug

	/* Obtains options 		*/
	for (i = 1 ; i < argc ; i++) {

		work_arg = argv[i];
		if (work_arg == NULL || work_arg[0] == 0) {
			break;
		}

		if (strcmp (work_arg, "-d") == 0) {
			if (dir_path_f) {
				printerr("[-d] is duplicated.\n");
				USAGE;
				exit (1);
			}
			if (i + 1 == argc) {
				printerr("[-d] has no parameter.\n");
				USAGE;
				exit (1);
			}
			if (strlen(argv[i + 1]) > PATH_MAX) {
				printerr("[-d] parameter is too long.\n");
				USAGE;
				exit (1);
			}

			work_arg = argv[i + 1];
			strcpy (conf_path, work_arg);
			dir_path_f++;
			i++;

		} else if (strcmp (work_arg, "-s") == 0) {
			if (pipeline_f) {
				printerr("[-s] is duplicated.\n");
				USAGE;
				exit (1);
			}
			if (i + 1 == argc) {
				printerr("[-s] has no parameter.\n");
				USAGE;
				exit (1);
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
	
		} else if (strcmp (work_arg, "-p") == 0) {
			if (port_num_f) {
				printerr("[-p] is duplicated.\n");
				USAGE;
				exit (1);
			}
	
			if (i + 1 == argc) {
				printerr("[-p] has no parameter.\n");
				USAGE;
				exit (1);
			}

			work_arg = argv[i + 1];
			port_num = atoi (work_arg);
			port_num_f++;
			i++;

		} else if (strcmp (work_arg, "-v_RI") == 0) {
			if (valid_RI_f) {
				printerr("[-v_RI] is duplicated.\n");
				USAGE;
				exit (1);
			}
			if (i + 1 == argc) {
				printerr("[-v_RI] has no parameter.\n");
				USAGE;
				exit (1);
			}
			work_arg = argv[i + 1];
			strcpy (valid_type_RI, work_arg);
			valid_RI_f++;
			i++;

		} else if (strcmp (work_arg, "-v_TD") == 0) {
			if (valid_TD_f) {
				printerr("[-v_TD] is duplicated.\n");
				USAGE;
				exit (1);
			}
			if (i + 1 == argc) {
				printerr("[-v_TD] has no parameter.\n");
				USAGE;
				exit (1);
			}
			work_arg = argv[i + 1];
			strcpy (valid_type_TD, work_arg);
			valid_TD_f++;
			i++;

		} else if (strcmp (work_arg, "-f") == 0) {
			if (file_f) {
				printerr("[-f] is duplicated.\n");
				USAGE;
				exit (1);
			}
			if (i + 1 == argc) {
				printerr("[-f] has no parameter.\n");
				USAGE;
				exit (1);
			}
	
			work_arg = argv[i + 1];
			if (strcmp(work_arg, "-") == 0) {
				file_f = CefC_Output_Stdout;
			} else {
				strcpy (fpath_base, work_arg);
				snprintf(fpath_base + strlen(fpath_base), 
						sizeof(fpath_base) - strlen(fpath_base), "%s", "/");
				file_f = CefC_Output_File_Spec;
			}
			i++;

#ifdef CefC_Develop
		} else if (strcmp (work_arg, "-l") == 0) {
			if (lifetime_f) {
				printerr("[-l] is duplicated.\n");
				USAGE;
				exit (1);
			}

			if (i + 1 == argc) {
				printerr("[-l] has no parameter.\n");
				USAGE;
				exit (1);
			}

			work_arg = argv[i + 1];
			lifetime = atoi (work_arg) * 1000;
			if (lifetime > CefC_Lifetime_Max) {
				lifetime = CefC_Lifetime_Max;
			} else if (lifetime < CefC_Lifetime_Min) {
				lifetime = CefC_Lifetime_Min;
			}
			lifetime_f++;
			i++;

		} else if (strcmp (work_arg, "-r") == 0) {
			if (no_resend_f > 1) {
				printerr("[-r] is duplicated.\n");
				USAGE;
				exit (1);
			}
			no_resend_f++;

#endif // CefC_Develop
		} else {
			work_arg = argv[i];
			if (work_arg[0] == '-') {
				USAGE;
				exit (1);
			}

			if (uri_f) {
				printerr("uri is duplicated.\n");
				USAGE;
				exit (1);
			}
			res = strlen (work_arg);

			if (res >= CefC_Max_Str_Len) {
				printerr("uri is too long.\n");
				USAGE;
				exit (1);
			}
			strcpy (uri, work_arg);
			uri_f++;
		}
	}

	/* Checks errors */
	if (uri_f == 0) {
		printerr("uri is not specified.\n");
		USAGE;
		exit (1);
	}
	if (file_f == CefC_Output_File_Spec) {
		struct stat st;
		if (stat(fpath_base, &st) != 0 || !S_ISDIR(st.st_mode)) {
			printerr("The specified output directory does not exist..\n");
			USAGE;
			exit (1);
		}
	}

	snprintf(fpath_base + strlen(fpath_base), 
			sizeof(fpath_base) - strlen(fpath_base), "%s", "RNP0x");

	cef_log_init2 (conf_path, 1/* for CEFNETD */);
	printlog("Parsing parameters ...OK\n");
	
	/*--------------------------------------------------------------------------
  	  Inits the Cefore APIs
  	-----------------------------------------------------------------------------*/
	cef_frame_init ();
	res = cef_client_init (port_num, conf_path);
	if (res < 0) {
		printerr("Failed to init the client package.\n");
		exit (1);
	}
	printlog("Init Cefore Client package ... OK\n");

	/*------------------------------------------
  	  Connects to CEFORE
  	--------------------------------------------*/
	fhdl = cef_client_connect ();
	if (fhdl < 1) {
		printerr("cefnetd is not running.\n");
		exit (1);
	}
	printlog("Connect to cefnetd ... OK\n");

	/* register fib entry to cefnetd */
	res = cef_frame_conversion_uri_to_name (uri, reg_fib_name);
	if (res < 0) {
		printerr("Invalid URI is specified.\n");
		USAGE;
		exit (1);
	}
	reg_fib_name_len = res;
	cef_client_name_reg(fhdl, CefC_T_OPT_APP_REG, reg_fib_name, reg_fib_name_len);
	printlog("Register fib entry to cefnetd ... OK (URI=%s)\n", uri);

	/*------------------------------------------
  	  Initialize variavles
  	--------------------------------------------*/
	app_running_f = 1;
	memset (&poh_RI, 0, sizeof (CefT_CcnMsg_OptHdr));	
	memset (&poh_TD, 0, sizeof (CefT_CcnMsg_OptHdr));
	memset (&pm_RI, 0, sizeof (CefT_CcnMsg_MsgBdy));
	memset (&pm_TD, 0, sizeof (CefT_CcnMsg_MsgBdy));

	buff = (unsigned char*) malloc (sizeof (unsigned char) * CefC_AppBuff_Size);
	memset (buff, 0, sizeof (unsigned char) * CefC_AppBuff_Size);

	rxsession_head = (CefT_RxSession*) malloc (sizeof (CefT_RxSession));
	memset (rxsession_head, 0, sizeof (CefT_RxSession));
	
	gettimeofday (&t, NULL);

	/*---------------------------------------------------------------------------
  	  Sets Interest/Data parameters
  	-----------------------------------------------------------------------------*/
	pm_RI.hoplimit = 32;
	poh_RI.lifetime_f = 1;

	if ((valid_RI_f == 1) || (valid_TD_f == 1)) {
		cef_valid_init (conf_path);
	}

	if (valid_RI_f) {
		pm_RI.alg.valid_type = (uint16_t) cef_valid_type_get (valid_type_RI);
		if (pm_RI.alg.valid_type == CefC_T_ALG_INVALID) {
			printerr("-v_int has the invalid parameter %s\n", valid_type_RI);
			exit (1);
		}
	}

	if (valid_TD_f) {
		pm_TD.alg.valid_type = (uint16_t) cef_valid_type_get (valid_type_TD);
		if (pm_TD.alg.valid_type == CefC_T_ALG_INVALID) {
			printerr("-v_data has the invalid parameter %s\n", valid_type_TD);
			exit (1);
		}
	}

	pm_TD.org.symbolic_f = 0;
	pm_TD.org.longlife_f = 0;
	pm_TD.hoplimit = 32;
	pm_TD.chunk_num_f = 0;
	pm_TD.expiry_f = 1;
	pm_TD.expiry = 0;

	poh_TD.lifetime_f = 1;
	poh_TD.lifetime = 0;
	poh_TD.cachetime_f = 1;
	poh_TD.cachetime = 0;

	/*---------------------------------------------------------------------------
  	  Main loop (Recv msg and respond to Trigget Interest or Reflexive Data )
  	-----------------------------------------------------------------------------*/
	while (app_running_f > 0) {
		if (SIG_ERR == signal (SIGINT, sigcatch)) {
			break;
		}

		/* Obtains UNIX time */
		gettimeofday (&t, NULL);
		now_time = cef_client_covert_timeval_to_us (t);

		/* Reads the message from cefnetd */
		res = cef_client_read_core (fhdl, &buff[index], CefC_AppBuff_Size - index, CefC_Resend_Interval/1000);

		if (res > 0) {
			res += index;

			do {
				unsigned char msg_buff[CefC_Max_Msg_Size] = {0};
				int msg_len = 0, hdr_len = 0, msg_type = -1, frame_type = -1;
				int ref_type = 0;
				struct fixed_hdr* fix_hdr;

				/* Get frame type of msg */
				i = 0;
				if ((buff[index] != CefC_Version) ||
						(buff[index + 1] > CefC_PT_MAX)) {
					while (i < res) {
						if ((buff[index +i] != CefC_Version) ||
								(buff[index + i + 1] != CefC_PT_OBJECT)) {
							i += 2;
						} else {
							break;
						}
					}
				}
				if ((i < res) && ((res - i) >= 8)) {
					fix_hdr = (struct fixed_hdr*)(&buff[index + i]);
					frame_type = fix_hdr->type;
					hdr_len = fix_hdr->hdr_len;
				} else {
					break;
				}

				/* Parse msg */
				res = cef_client_rawdata_get(&buff[index], res, msg_buff, &msg_len, &msg_type);

				memset (&poh_rx, 0, sizeof (CefT_CcnMsg_OptHdr));
				memset (&pm_rx, 0, sizeof (CefT_CcnMsg_MsgBdy));
				cef_frame_message_parse (msg_buff, msg_len - hdr_len, hdr_len, &poh_rx, &pm_rx, msg_type);

				/* Get whether name type is Trigger, Reflexive or Normal */
				if (pm_rx.rnp_pos == 0) {
					ref_type = CefC_Reflexive_Msg;
				} else if (pm_rx.rnp_pos > 0) {
					ref_type = CefC_Trigger_Msg;
				} else {
#ifdef CefC_Debug
					cef_dbg_write (CefC_Dbg_Finest, "Receive invalid msg.\n");
#endif // CefC_Debug
					continue;
				}

				/* Get RNP info from name of msg */
				memset(rnp_tmp, 0, CefC_Max_Str_Len);
				res_ref = cef_frame_conversion_name_to_reflexivename (pm_rx.name, pm_rx.name_len, rnp_tmp, 0, pm_rx.rnp_pos);

				/* Check if relavant sessoin already exists */
				session_f = 0;
				i = 0;
				rxsession = rxsession_head;
				rxsession_prev = NULL;
				while (rxsession->next_session != NULL ) {
					rxsession_prev = rxsession;
					rxsession = rxsession->next_session;

					if (memcmp (rxsession->rnp, rnp_tmp, res_ref) == 0) {
						session_f = 1;
						break;
					}
					i++;
				}

				/* Processing based on msg type of reflexive forwarding */
				if ( (frame_type == CefC_PT_INTEREST) && (ref_type == CefC_Trigger_Msg) ) {
#ifdef CefC_Debug
					char tmp[CefC_Max_Str_Len];
					cef_frame_conversion_name_to_uri (pm_rx.name, pm_rx.name_len , tmp);
					cef_dbg_write (CefC_Dbg_Fine, "Receive Trigger Interest. (%s)\n", tmp);
#endif // CefC_Debug
				   	if (!session_f) {
						if (pm_rx.chunk_num_f) {
							continue;
						}
#ifdef CefC_Debug
						cef_dbg_write (CefC_Dbg_Finer,
								"This RNP is new, so create new session.\n");
#endif // CefC_Debug

						if (i >= CefC_Session_Limit) {
							printerr("Session limit has been reached. Skip create new srssion\n");
							continue;
						}

						/* Create new session */
						rxsession->next_session = (CefT_RxSession*) malloc (sizeof(CefT_RxSession));
						if (rxsession->next_session == NULL) {
							printerr("Malloc of session if failed.\n");
							exit(1);
						}
						memset (rxsession->next_session, 0, sizeof (CefT_RxSession));
						rxsession = rxsession->next_session;

						/* Set RNP info of this session */
						memcpy(rxsession->rnp, rnp_tmp, res_ref);
						rxsession->rnp_len = res_ref;
						rxsession->end_chunk_num = -1;

						memcpy (rxsession->fpath, fpath_base, sizeof (fpath_base));
						int path_len = strlen(rxsession->fpath);

						for (int q = CefC_S_TLF; q < rxsession->rnp_len; q++) {
							char wk_tmp[3];
							sprintf (wk_tmp, "%02x", rxsession->rnp[q]);
							strcpy (&rxsession->fpath[path_len], wk_tmp);
							path_len += strlen (wk_tmp);
						}
						sprintf (&rxsession->fpath[path_len],".out");
						rxsession->fp = fopen (rxsession->fpath, "wb");
						if (rxsession->fp == NULL) {
							printerr("Specified output file can not be opend.\n");
							exit (1);
						}

						if (pm_rx.org.reflexive_smi_f == 0) {
							rxsession->symbolic_f = 0;

							/* Create rx window of this session */
							rxwnd = (Ceft_RxWnd*) malloc (sizeof (Ceft_RxWnd));
							memset (rxwnd, 0, sizeof (Ceft_RxWnd));
							rxwnd->next = rxwnd;
							rxwnd->seq = 0;
							rxwnd->status = RxSts_Request;
							rxwnd_prev = rxwnd;
							rxsession->rxwnd_head = rxwnd;
							rxsession->rxwnd_tail = rxwnd;

							for (i = 1 ; i < CefC_RxWndSize ; i++) {
								rxwnd = (Ceft_RxWnd*) malloc (sizeof (Ceft_RxWnd));
								memset (rxwnd, 0, sizeof (Ceft_RxWnd));
								rxwnd->seq = (uint32_t) i;
								rxwnd_prev->next = rxwnd;
								rxsession->rxwnd_tail = rxwnd;
								rxwnd_prev = rxwnd;
							}

							/*  Sends Reflexive Interest(s) */
							rxwnd = rxsession->rxwnd_head;
							for (i = 0 ; i < pipeline && rxwnd != NULL; i++) {
								pm_RI.chunk_num = rxwnd->seq;
								send_reflexive_interest (rxsession, &poh_RI, &pm_RI, lifetime, CefC_Ref_RGI);

								rxwnd->status = RxSts_Request;
								rxwnd->req_time = now_time;
								rxwnd->retry_time = now_time + T_RETRY_INTERVAL(lifetime);
								rxwnd = rxwnd->next;
							}
						} else {
							rxsession->symbolic_f = 1;
							rxsession->end_time = now_time + 10000000;
							rxsession->rxwnd_head = NULL;
							rxsession->rxwnd_tail = NULL;

							/* Sends Initerest(s) */
							send_reflexive_interest (rxsession, &poh_RI, &pm_RI, lifetime_smi, CefC_Ref_SMI);
							rxsession->nxt_time = now_time + (uint64_t)((double) lifetime_smi * 0.8) * 1000;;
						}

					} else {
						if (pm_rx.chunk_num_f) {
							/* Send Trigger Data respond to Trigger Interest */
							pm_TD.chunk_num_f = 1;
							pm_TD.chunk_num = pm_rx.chunk_num;
							pm_TD.end_chunk_num_f = 1;
							pm_TD.end_chunk_num = pm_rx.end_chunk_num;

							send_trigger_data (rxsession, &poh_TD, &pm_TD, uri);
#ifdef CefC_Debug
						} else {
							cef_dbg_write (CefC_Dbg_Finest,
								"The Trigger Interest with this RNP is already in progress.\n");
#endif // CefC_Debug
						}
					}
				} else if ( (frame_type == CefC_PT_OBJECT) && 
						(ref_type == CefC_Reflexive_Msg) && (session_f == 1) ) {
#ifdef CefC_Debug
					char tmp[CefC_Max_Str_Len];
					cef_frame_conversion_name_to_uri (pm_rx.name, pm_rx.name_len , tmp);
					cef_dbg_write (CefC_Dbg_Finer, "Receive Reflexive Data. (%s, chunk="FMT64")\n", tmp, (int64_t)pm_rx.chunk_num);
#endif // CefC_Debug
					/* Check end_chunk of Reflexive Data */
					if ( pm_rx.end_chunk_num_f > 0 ) {
						rxsession->end_chunk_num = pm_rx.end_chunk_num; 
					}

					/* Update stats info */
					if (rxsession->recv_frames < 1) {
						rxsession->start_t.tv_sec  = t.tv_sec;
						rxsession->start_t.tv_usec = t.tv_usec;
					} else {
						val = (t.tv_sec - rxsession->end_t.tv_sec) * 1000000llu
								+ (t.tv_usec - rxsession->end_t.tv_usec);
						rxsession->stat_jitter_sum    += val;
						rxsession->stat_jitter_sq_sum += val * val;

						if (val > rxsession->stat_jitter_max) {
							rxsession->stat_jitter_max = val;
						}
					}
					rxsession->end_t.tv_sec  = t.tv_sec;
					rxsession->end_t.tv_usec = t.tv_usec;
					rxsession->stat_all_recv_frames++;
					rxsession->stat_all_recv_bytes += msg_len - hdr_len;

					if (rxsession->symbolic_f == 1) {
						/* buffer received payload to rxwindow */
						fwrite (pm_rx.payload, sizeof (unsigned char), pm_rx.payload_len, rxsession->fp);
						rxsession->recv_frames++;
						rxsession->stat_recv_bytes += pm_rx.payload_len;

						/* Upadate end_time of this session */
						rxsession->end_time = now_time + 1000000;

					} else {
						rxwnd = rxsession->rxwnd_head;
			
						/* Check invalid chunk_num */
						if ((pm_rx.chunk_num < rxwnd->seq) || 
								(pm_rx.chunk_num > rxsession->rxwnd_tail->seq)) {
#ifdef CefC_Debug
							cef_dbg_write (CefC_Dbg_Finest, "This CoB's chunk_num("FMT64") is invalid.\n", (int64_t)pm_rx.chunk_num);
#endif // CefC_Debug
							continue;
						}

						diff_seq = pm_rx.chunk_num - rxwnd->seq;
						for (i = 0 ; i < diff_seq ; i++) {
							rxwnd = rxwnd->next;
						}

						/* buffer received payload to rxwindow */
						if (!RxWnd_IsReceived(rxwnd)) {
							memcpy (rxwnd->buff, pm_rx.payload, pm_rx.payload_len);
							rxwnd->frame_size = pm_rx.payload_len;
							rxwnd->status = RxSts_Receive;

						} else {
#ifdef CefC_Debug
							cef_dbg_write (CefC_Dbg_Finest, "This Cob has already been received.\n");
#endif // CefC_Debug
							continue;
						}

						/* Advance the receive window (remove the received section)	*/
						rxwnd = rxsession->rxwnd_head;
						for (i = 0 ; i < CefC_RxWndSize; i++) {

							if (!RxWnd_IsReceived(rxwnd)) {
								break;
							}
							rxsession->recv_frames++;
							rxsession->stat_recv_bytes += pm_rx.payload_len;

							fwrite (rxwnd->buff,
								sizeof (unsigned char), rxwnd->frame_size, rxsession->fp);

							if ( rxsession->recv_frames > rxsession->end_chunk_num ) {
								/* Completed to get all the chunks */
								break;
							}

							/* Check whether reaching max number of reception  */
							if (rxsession->rxwnd_tail->seq == UINT32_MAX /*sv_max_seq*/) {
								rxwnd_prev = rxwnd;
								rxwnd = rxwnd->next;
								rxsession->rxwnd_head = rxwnd;
								free(rxwnd_prev);
								continue;
							}

							/* Updates head and tail pointers		*/
							rxsession->rxwnd_head->seq 		= rxsession->rxwnd_tail->seq + 1;
							rxsession->rxwnd_head->status		= RxSts_Null;
							rxsession->rxwnd_head->retry_count	= 0;
							rxsession->rxwnd_head->frame_size 	= 0;
							rxsession->rxwnd_head->req_time 	= 0;
							rxsession->rxwnd_head->retry_time 	= 0;

							rxsession->rxwnd_tail->next = rxsession->rxwnd_head;
							rxsession->rxwnd_tail = rxsession->rxwnd_head;

							rxsession->rxwnd_head = rxsession->rxwnd_tail->next;
							rxsession->rxwnd_tail->next 	= NULL;

							rxwnd = rxsession->rxwnd_head;
						}
					}
						
					/* Check if Completed to get all the chunks */
					if ((rxsession->end_chunk_num >= 0) &&
							( (rxsession->symbolic_f && pm_rx.chunk_num == rxsession->end_chunk_num )
							 || (rxsession->recv_frames == (rxsession->end_chunk_num + 1)))) {

						if (rxsession->symbolic_f == 0) {
							printlog("Completed to get all the chunks.\n");
						} else {
							printlog("Completed. Get end chunk.\n");

							/* Send cleanup Reflexive Interest to delete SMI pit*/
							send_reflexive_interest (rxsession, &poh_RI, &pm_RI, 0, CefC_Ref_SMI);
						}

						/* Send Trigger Data respond to Trigger Interest */
						pm_TD.chunk_num_f = 0;
						pm_TD.end_chunk_num_f = 0;
						res_ref = send_trigger_data (rxsession, &poh_TD, &pm_TD, uri);
#ifdef CefC_Debug
						if (res_ref < 0) {
							cef_dbg_write (CefC_Dbg_Finest, "Failed to send Trigger Data.%s\n", dbg_msg);
						}
#endif // CefC_Debug

						/* Output received payload of each rxwindow to stdout */
						fclose (rxsession->fp);
						output_payload (rxsession, file_f);

						/* Delete this rxsession and rxwindow */
						rxwnd = rxsession->rxwnd_head;

						while (rxwnd != NULL) {
							rxwnd_prev = rxwnd;
							rxwnd = rxwnd->next;
							free (rxwnd_prev);
						}
						rxsession_prev->next_session = rxsession->next_session;
						free(rxsession);
					}
				}
			} while (res > 0);

			if (res > 0) {
				index = res;
			} else {
				index = 0;
			}
		}

		gettimeofday (&t, NULL);
		now_time = cef_client_covert_timeval_to_us (t);

		rxsession = rxsession_head;
		rxsession_prev = NULL;
		while (rxsession->next_session != NULL ) {
			int output_f = 0;
			rxsession_prev = rxsession;
			rxsession = rxsession->next_session;

			/* Sends Interest with Symbolic flag to CEFORE 		*/
			rxwnd = rxsession->rxwnd_head;
			if (rxsession->symbolic_f == 1) {
				/* Sends Initerest(s) */
				if (now_time > rxsession->end_time) {
					output_f = 1;

				} else if (now_time > rxsession->nxt_time) {
					send_reflexive_interest (rxsession, &poh_RI, &pm_RI, lifetime_smi, CefC_Ref_SMI);
#ifdef CefC_Debug
					cef_dbg_write (CefC_Dbg_Finer, "ResendRI(SMI)\n");
#endif // CefC_Debug
					rxsession->nxt_time = now_time + (uint64_t)((double) lifetime_smi * 0.8) * 1000;;
				}

			} else {
				for (i = j = 0; i < CefC_RxWndSize && j < pipeline && rxwnd != NULL; i++) {
					if ( 0 <= rxsession->end_chunk_num && rxsession->end_chunk_num < rxwnd->seq )
						break;
#ifdef CefC_Debug
if (RxWnd_IsInflight(rxwnd)) {
	cef_dbg_write (CefC_Dbg_Finest, "RxWnd_IsInflight:Chunk="FMT64", retry=%d, req_time="FMTU64", retry_time="FMTU64"\n",
	(int64_t)rxwnd->seq, rxwnd->retry_count, rxwnd->req_time, rxwnd->retry_time);
}
#endif // CefC_Debug

					if ( !RxWnd_IsRequest(rxwnd)		/* Sends an interest with the next chunk number 	*/
						|| RxWnd_IsInflight(rxwnd)		/* ReSends an interest */
					) {
						j++;

						if (rxwnd->retry_time < now_time){
							if (RxWnd_IsInflight(rxwnd)) {
								if ( CefC_Max_Retry <= rxwnd->retry_count ){
									output_f = 1;
									printerr ("Timeout (The number of RI retransmission has reached its limit, %d.)\n" , CefC_Max_Retry);
									break;
								}
								rxwnd->retry_count++;
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, "ResendRI:Chunk="FMT64", retry=%d, req_time="FMTU64", retry_time="FMTU64"\n",
	(int64_t)rxwnd->seq, rxwnd->retry_count, rxwnd->req_time, rxwnd->retry_time);
}else{
	cef_dbg_write (CefC_Dbg_Finest, "SendRI:Chunk="FMT64", req_time="FMTU64", retry_time="FMTU64"\n",
	(int64_t)pm_RI.chunk_num, rxwnd->req_time, rxwnd->retry_time);
#endif // CefC_Debug
							}

							pm_RI.chunk_num = rxwnd->seq;
							if (pm_RI.chunk_num <=  UINT32_MAX /* sv_max_seq+1 */) {
								if (!RxWnd_IsRequest(rxwnd) || (no_resend_f == 0)) {
									send_reflexive_interest (rxsession, &poh_RI, &pm_RI, lifetime, CefC_Ref_RGI);
								}
								rxwnd->status = RxSts_Request;
								rxwnd->req_time = now_time;
								rxwnd->retry_time = now_time + T_RETRY_INTERVAL(lifetime);
							}
						}
					}
					rxwnd = rxwnd->next;
				}
			}

			if (output_f) {
				/* Output received payload of each rxwindow to stdout */
				fclose (rxsession->fp);
				output_payload (rxsession, file_f);

				/* Delete this rxsession and rxwindow */
				rxwnd = rxsession->rxwnd_head;
				while (rxwnd != NULL) {
					rxwnd_prev = rxwnd;
					rxwnd = rxwnd->next;
					free (rxwnd_prev);
				}
				rxsession_prev->next_session = rxsession->next_session;
				free(rxsession);
			}
		}
	}

	/* Delete session and rxwindow */
	rxsession = rxsession_head;
	while(rxsession->next_session != NULL) {
		rxsession_prev = rxsession;
		rxsession = rxsession->next_session;

		fclose (rxsession->fp);
		output_payload (rxsession, file_f);

		if (rxsession->symbolic_f == 1) {
			/* Send Reflexive Interest with lifetime=0 to delete related SMI pit*/
			send_reflexive_interest (rxsession, &poh_RI, &pm_RI, 0, CefC_Ref_SMI);

		}

		rxwnd = rxsession->rxwnd_head;
		while (rxwnd != NULL) {
			rxwnd_prev = rxwnd;
			rxwnd = rxwnd->next;
			free (rxwnd_prev);
		}
		free(rxsession_prev);
	}
	free(rxsession);
	free (buff);

	/* Deregister fib entry from cefnetd */
	cef_client_name_reg(fhdl, CefC_T_OPT_APP_DEREG, reg_fib_name, reg_fib_name_len);
	printlog("Deregister fib entry from cefnetd ... OK (URI=%s)\n", uri);
	usleep (100000);

	/* Disconnects to CEFORE */
	cef_client_close (fhdl);
	printlog("Unconnect to cefnetd ... OK\n");
	printlog("Terminate\n");

	exit (0);

#else // REFLEXIVE_FORWARDING
	printf ("PUSH function has been disabled.\n");
#endif // REFLEXIVE_FORWARDING
}

#ifdef REFLEXIVE_FORWARDING
static void
print_usage (
	FILE* ofp						/* File pointer to output */
) {
	fprintf (ofp, "\nUsage: cefsubfile\n\n");
	fprintf (ofp, 
		"  cefsubfile uri [-f output_path] [-s pipeline] "
		"[-v_RI valid_algo] [-v_TD valid_algo] [-d config_file_dir] [-p port_num]");
	fprintf (ofp, "\n\n");

	fprintf (ofp, "  uri                  Specify the URI.\n");
	fprintf (ofp, "  -f output_path       Specify directory path to output content\n"
				  "                       (When \"-\" is specified, output to stdout)\n");
	fprintf (ofp, "  -s pipeline          Number of pipeline\n");
	fprintf (ofp, "  -v_RI valid_algo     Specify the validation algorithm for Reflexive Interest (" CefC_ValidTypeStr_CRC32C " | " CefC_ValidTypeStr_RSA256 ")\n");
	fprintf (ofp, "  -v_TD valid_algo     Specify the validation algorithm for Trgger Data (" CefC_ValidTypeStr_CRC32C " | " CefC_ValidTypeStr_RSA256 ")\n");
	fprintf (ofp, "  -d config_file_dir   Configure file directory\n");
	fprintf (ofp, "  -p port_num          Port Number\n");
	fprintf (ofp, "\n");
}

static void
output_payload (
	CefT_RxSession* rxsession,		/* rxsession to output */
	OutputType file_f
) {
	FILE *fp = NULL;
	unsigned char buf[4096];
    size_t file_size;

	uint64_t diff_t;
	double diff_t_dbl = 0.0;
	double thrpt = 0.0;
	double goodpt = 0.0;
	uint64_t recv_bits;
	uint64_t all_recv_bits;
	uint64_t jitter_ave;
	struct timeval diff_tval;
	int invalid_end = 0;


	char log_msg[256];
	int pos = 0;
	pos = snprintf(log_msg, sizeof(log_msg), "RNP=0x");
	for (int x = CefC_S_TLF; x < rxsession->rnp_len; x++) {
		pos += snprintf(log_msg + pos, sizeof(log_msg) - pos, "%02x", rxsession->rnp[x]);
		if (pos >= sizeof(log_msg))
			break;
	}
	printlog("%s\n", log_msg);
	if (file_f != CefC_Output_Stdout) {
		printlog("Outputfile: %s\n", rxsession->fpath);
	}

	/* Output stats */
	if (rxsession->recv_frames) {
		if ( !timercmp( &rxsession->start_t, &rxsession->end_t, != ) == 0 ) {
			if ( timercmp( &rxsession->start_t, &rxsession->end_t, < ) == 0 ) {
				// Invalid end time
				printlog ("Invalid end time. No time statistics reported.\n");
				diff_t = 0;
				invalid_end = 1;
			} else {
				timersub( &rxsession->end_t, &rxsession->start_t, &diff_tval );
				diff_t = diff_tval.tv_sec * 1000000llu + diff_tval.tv_usec;
			}
		} else {
			//Same Time
			diff_t = 0;
		}
	} else {
		diff_t = 0;
	}

	printlog("Rx Frames (All)           = "FMTU64"\n", rxsession->stat_all_recv_frames);
	printlog("Rx Frames (ContentObject) = "FMTU64"\n", rxsession->recv_frames);
	if (rxsession->recv_frames > 0) {
		printlog("Rx Bytes (All)            = "FMTU64"\n", rxsession->stat_all_recv_bytes);
		printlog("Rx Bytes (ContentObject)  = "FMTU64"\n", rxsession->stat_recv_bytes);
		if (diff_t > 0) {
			diff_t_dbl = (double)diff_t / 1000000.0;
			printlog("Duration                  = %.3f sec\n", diff_t_dbl + 0.0009);
			recv_bits = rxsession->stat_recv_bytes * 8;
			all_recv_bits = rxsession->stat_all_recv_bytes * 8;
			thrpt = (double)(all_recv_bits) / diff_t_dbl;
			goodpt = (double)(recv_bits) / diff_t_dbl;
			printlog("Throughput                = "FMTU64" bps\n", (uint64_t)thrpt);
			printlog("Goodput                   = "FMTU64" bps\n", (uint64_t)goodpt);
		} else {
			printlog("Duration                  = 0.000 sec\n");
		}
		if ((rxsession->recv_frames > 0) && (invalid_end == 0)) {
			jitter_ave = rxsession->stat_jitter_sum / rxsession->recv_frames;
			printlog("Jitter (Ave)              = "FMTU64" us\n", jitter_ave);
			printlog("Jitter (Max)              = "FMTU64" us\n", rxsession->stat_jitter_max);
			printlog("Jitter (Var)              = "FMTU64" us\n",
				(rxsession->stat_jitter_sq_sum / rxsession->recv_frames)
				- (jitter_ave * jitter_ave));
		}
	}


	/* Output received payload of each rxwindow to stdout */
	if (file_f == CefC_Output_Stdout) {
		fp = fopen(rxsession->fpath, "rb");
		if (!fp) {
			printerr("Can't output the data.\n");
			return;
		}
		printlog("Output the data:\n");
		while ((file_size = fread(buf, 1, sizeof(buf), fp)) > 0) {
			fwrite(buf, 1, file_size, stdout);
		}
		fclose(fp);

		remove(rxsession->fpath);
		fprintf(CefC_BASIC_LOG_OUTPUT, "\n");
	}
	fprintf(CefC_BASIC_LOG_OUTPUT, "\n");

	return;
}

int
set_rnp_to_name (
	unsigned char* name,			/* name */
	unsigned int name_len,			/* length of name */
	unsigned char* rnp,				/* rnp */
	unsigned int rnp_len			/* length of rnp */
) {
	int x = 0;
	struct tlv_hdr* tlv_hdr;
	uint16_t sub_type;
	uint16_t sub_len;
	uint16_t rnp_len_n;
	uint16_t ftvn_rnp;

	if (name_len <= CefC_S_TLF) {
		return (0);
	}

	/* Check if sub-TLV of input name is only T_NAMESEGMENT */
	while (x < name_len) {
		tlv_hdr = (struct tlv_hdr*) &name[x];
		sub_type = ntohs (tlv_hdr->type);
		sub_len = ntohs (tlv_hdr->length);

		if ( sub_type != CefC_T_NAMESEGMENT ) {
			printf("Input Name is invalid.\n");
			return (-1);
		}
		x += CefC_S_TLF + sub_len;
	}

	/* Add RNP TLV to tail of NAME TLV */
	ftvn_rnp = htons (CefC_T_REFLEXIVE_NAME);
	memcpy (&name[x], &ftvn_rnp, CefC_S_Type);
	x += CefC_S_Type;
	rnp_len_n = htons (rnp_len);
	memcpy (&name[x], &rnp_len_n, CefC_S_Length);
	x += CefC_S_Length;
	memcpy (&name[x], rnp, rnp_len);
	x += rnp_len;

	return (x);
}

int
send_trigger_data (
	CefT_RxSession* rxsession,		/* rxsession */
	CefT_CcnMsg_OptHdr* poh_TD,		/* Option Header for Trg.Data */
	CefT_CcnMsg_MsgBdy* pm_TD,		/* CEFORE message for Trg.Data */
	char* uri						/* URI for conversion to Name */
) {
	int res_ref;

	/* Get name from uri and rnp */
	res_ref = cef_frame_conversion_uri_to_name(uri, pm_TD->name);
	if (res_ref < 0) {
		printerr("Invalid URI is specified.\n");
		return (-1);
	}

	res_ref = set_rnp_to_name(pm_TD->name, res_ref, 
			&rxsession->rnp[CefC_S_TLF], rxsession->rnp_len - CefC_S_TLF);
	if (res_ref < 0) {
		printerr("Name or RNP is invalid in set_rnp_to_name function.\n");
		return (-1);
	}

	pm_TD->name_len = res_ref;

	/* Send Trigger Data respond to Trigger Interest */
	res_ref = cef_client_object_input (fhdl, poh_TD, pm_TD);
	if (res_ref <= 0 ) {
		printerr("Frame size of Trigger Interest exceeds limit.\n");
		return (-1);
	}

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finer,
			"Send Trigger Data.\n");
#endif // CefC_Debug
	return (0);
}

static void
send_reflexive_interest (
	CefT_RxSession* rxsession,		/* rxsession */
	CefT_CcnMsg_OptHdr* poh_RI,		/* Option Header for Ref.Int */
	CefT_CcnMsg_MsgBdy* pm_RI,		/* CEFORE message for Ref.Int */
	uint64_t lifetime,					/* lifetime to set Ref.Int  */
	int int_type					/* Packet type. RGI:0, SMI:1 */
) {

	/* Send Reflexive Interest */
	memset(pm_RI->name, 0, pm_RI->name_len);
	memcpy(pm_RI->name, rxsession->rnp, rxsession->rnp_len);
	pm_RI->name_len = rxsession->rnp_len;
	poh_RI->lifetime = lifetime;

	memset (pm_RI->org_val, 0, CefC_Max_Length);
	pm_RI->org_len = 0;
	if (int_type == CefC_Ref_RGI) {
		pm_RI->org.symbolic_f = 0;
		pm_RI->org.longlife_f = 0;
		pm_RI->chunk_num_f = 1;
	} else if (int_type == CefC_Ref_SMI) {
		pm_RI->org.symbolic_f = 1;
		pm_RI->org.longlife_f = 1;
		pm_RI->chunk_num_f = 0;
	} else {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest,
				"  Invalid PacketType in send_reflexive_interest function.\n");
#endif // CefC_Debug
		return;
	}

	cef_client_interest_input (fhdl, poh_RI, pm_RI);
#ifdef CefC_Debug
	if (pm_RI->chunk_num_f) {
		cef_dbg_write (CefC_Dbg_Finer,
				"  Send Reflexive Interest(Chunk="FMT64").\n",
				(int64_t)pm_RI->chunk_num);

	} else {
		cef_dbg_write (CefC_Dbg_Finer,
				"  Send Reflexive Interests (lifetime="FMTU64"ms).\n", lifetime);
	}
#endif // CefC_Debug

	return;
}

static void
sigcatch (
	int sig
) {
	if (sig == SIGINT) {
		printlog("Catch the signal\n");
		app_running_f = 0;
	}
}
#endif // REFLEXIVE_FORWARDING

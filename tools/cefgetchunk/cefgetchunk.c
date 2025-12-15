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
 * cefgetchunk.c
 */

#define __CEF_GETCHUNK_SOURECE__

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

#define USAGE					print_usage(CefFp_Usage)
#define printerr(...)			fprintf(stderr,"[cefgetchunk] ERROR: " __VA_ARGS__)
/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/


/****************************************************************************************
 State Variables
 ****************************************************************************************/

static int app_running_f = 0;
CefT_Client_Handle fhdl;

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

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
	int index = 0;
	char uri[1024];
	CefT_CcnMsg_OptHdr opt;	
	CefT_CcnMsg_MsgBdy params;
	struct timeval t;
	uint64_t now_time;
	uint64_t end_time;
	uint32_t chunk_num = 0;
	int i;
	char*	work_arg;
	
	char 	conf_path[PATH_MAX] = {0};
	int 	port_num = CefC_Unset_Port;
	
	struct cef_app_frame app_frame;
	unsigned char* buff;
	
	/***** flags 		*****/
	int uri_f 			= 0;
	int chunk_num_f 	= 0;
	int time_out_f 		= 1;
	int dir_path_f 		= 0;
	int port_num_f 		= 0;
	
	memset (&opt, 0, sizeof (CefT_CcnMsg_OptHdr));	
	memset (&params, 0, sizeof (CefT_CcnMsg_MsgBdy));
	
	printf ("[cefgetchunk] Start\n");
	
	/* Inits logging 		*/
	cef_log_init ("cefgetchunk", 1);
	
	/* Parses parameters 		*/
	for (i = 1 ; i < argc ; i++) {
		
		work_arg = argv[i];
		if (work_arg == NULL || work_arg[0] == 0) {
			break;
		}
		
		if (strcmp (work_arg, "-c") == 0) {
			if (chunk_num_f) {
				printerr("[-c] is duplicated.\n");
				USAGE;
				return (-1);
			}
			if (i + 1 == argc) {
				printerr("[-c] has no parameter.\n");
				USAGE;
				return (-1);
			}
			work_arg = argv[i + 1];
			chunk_num = (uint32_t) atoi (work_arg);
			chunk_num_f++;
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
	if (chunk_num_f == 0) {
		printerr( 
			"[-c] is not specified.\n");
		USAGE;
		exit (1);
	}
	printf ("[cefgetchunk] Parsing parameters ... OK\n");
	cef_log_init2 (conf_path, 1 /* for CEFNETD */);
#ifdef CefC_Debug
	cef_dbg_init ("cefgetchunk", conf_path, 1);
#endif // CefC_Debug
	
	cef_frame_init ();
	res = cef_client_init (port_num, conf_path);
	if (res < 0) {
		printerr("Failed to init the client package.\n");
		exit (1);
	}
	printf ("[cefgetchunk] Init Cefore Client package ... OK\n");
	res = cef_frame_conversion_uri_to_name (uri, params.name);
	if (res < 0) {
		printerr("Invalid URI is specified.\n");
		USAGE;
		exit (1);
	}
	params.name_len = res;
	printf ("[cefgetchunk] Conversion from URI into Name ... OK\n");
	fhdl = cef_client_connect ();
	if (fhdl < 1) {
		printerr("cefnetd is not running.\n");
		exit (1);
	}
	printf ("[cefgetchunk] Connect to cefnetd ... OK\n");
	buff = (unsigned char*) malloc (sizeof (unsigned char) * CefC_AppBuff_Size);
	memset (&app_frame, 0, sizeof (struct cef_app_frame));
	
	/* Sets Interest parameters 			*/
	params.hoplimit 			= 32;
	opt.lifetime_f 		= 1;
	opt.lifetime 		= 10000;
	
	Cef_Int_Regular(params);
	params.chunk_num_f 		= 1;
	params.chunk_num		= chunk_num;
	
	gettimeofday (&t, NULL);
	now_time = cef_client_covert_timeval_to_us (t);
	end_time = now_time + 3000000;
	
	app_running_f = 1;
	cef_client_interest_input (fhdl, &opt, &params);
	printf ("[cefgetchunk] Send an Interest\n");
	
	while (app_running_f) {
		if (SIG_ERR == signal (SIGINT, sigcatch)) {
			break;
		}
		
		gettimeofday (&t, NULL);
		now_time = cef_client_covert_timeval_to_us (t);
		
		if (now_time > end_time) {
			break;
		}
		
		res = cef_client_read (fhdl, &buff[index], CefC_AppBuff_Size - index);
		
		if (res > 0) {
			res += index;
			
			do {
				res = cef_client_payload_get_with_info (buff, res, &app_frame);
				
				if (app_frame.version == CefC_App_Version) {

					/* InterestReturn */
					if ( (uint8_t)app_frame.type == CefC_PT_INTRETURN ) {
						printf ("[cefgetfile] Incomplete\n");
						printf ("[cefgetfile] "
								"Received Interest Return(Type:%02x)\n", app_frame.returncode);
						app_running_f = 0;
						goto IR_RCV;				
					}

					if (app_frame.chunk_num == params.chunk_num) {
						printf ("[cefgetchunk] Get a requested Cob #%u\n",app_frame.chunk_num); 
						fwrite (app_frame.payload, 
							sizeof (unsigned char), app_frame.payload_len, stdout);
					} else {
						printf ("[cefgetchunk] Get a Cob #u that you did not request.\n");
					}
					time_out_f 		= 0;
					app_running_f 	= 0;
				}
				break;
				
			} while (res > 0);
			
			if (res > 0) {
				index = res;
			} else {
				index = 0;
			}
		}
IR_RCV:;	
	}
	
	if (time_out_f) {
		printf ("[cefgetchunk] Timeout.\n");
	}
	cef_client_close (fhdl);
	
	exit (0);
}

static void
print_usage (
	FILE* ofp
) {
	fprintf (ofp, "\nUsage: cefgetchunk\n\n");
	fprintf (ofp, "  cefgetchunk uri -c chunk_num [-d config_file_dir] [-p port_num]\n\n");
	fprintf (ofp, "  uri              Specify the URI.\n");
	fprintf (ofp, "  chunk_num        Specify the chunk number.\n");
	fprintf (ofp, "  config_file_dir  Configure file directory\n");
	fprintf (ofp, "  port_num         Port Number\n\n");
}

static void
sigcatch (
	int sig
) {
	if (sig == SIGINT) {
		printf ("[cefgetchunk] Catch the signal\n");
		app_running_f = 0;
	}
}

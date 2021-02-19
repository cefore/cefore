/*
 * Copyright (c) 2016-2020, National Institute of Information and Communications
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
 * cefping.c
 */

#define __CEF_CEFPING_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <limits.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <cefore/cef_define.h>
#include <cefore/cef_frame.h>
#include <cefore/cef_client.h>
#include <cefore/cef_log.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

#define CefC_Cp_Str_Max 		256
#define CefC_Cp_Str_Buff 		257
#define CefC_Max_Buff 			64

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

typedef struct {
	
	char 			prefix[CefC_Cp_Str_Buff];
	unsigned char 	name[CefC_Max_Length];
	int 			name_len;
	int 			count;
	int 			wait_time;
	int 			hop_limit;
	char 			responder[CefC_Max_Buff];
	int 			responder_len;
	unsigned char	responder_id[16];
	int 			responder_id_len;
	
} CefT_Cp_Parms;

/****************************************************************************************
 State Variables
 ****************************************************************************************/

static char 	conf_path[PATH_MAX] = {0};
static int 		port_num = CefC_Unset_Port;
static uint8_t	output_f = 0;

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

static CefT_Cp_Parms params;
static int cp_running_f;
CefT_Client_Handle fhdl;

/*--------------------------------------------------------------------------------------
	Outputs usage
----------------------------------------------------------------------------------------*/
static void
cp_usage_output (
	const char* msg									/* Supplementary information 		*/
);
/*--------------------------------------------------------------------------------------
	Parses parameters
----------------------------------------------------------------------------------------*/
static int											/* error occurs, return negative	*/
cp_parse_parameters (
	int 	argc, 									/* same as main function 			*/
	char*	argv[]									/* same as main function 			*/
);
/*--------------------------------------------------------------------------------------
	Catch the signal
----------------------------------------------------------------------------------------*/
static void
cp_sigcatch (
	int sig
);
/*--------------------------------------------------------------------------------------
	Outputs the results
----------------------------------------------------------------------------------------*/
static void
cp_results_output (
	unsigned char* msg,
	uint16_t packet_len, 
	uint16_t header_len, 
	uint64_t rtt_us
);

/****************************************************************************************
 ****************************************************************************************/

int main (
	int argc,
	char** argv
) {
	struct timeval tv;
	uint64_t end_us_t;
	uint64_t start_us_t;
	uint64_t now_us_t;
	CefT_Ping_TLVs tlvs;
	unsigned char buff[CefC_Max_Length];
	int res;
	uint16_t packet_len;
	uint16_t header_len;
	
	/*----------------------------------------------------------------
		Init variables
	------------------------------------------------------------------*/
	/* Inits logging 		*/
	cef_log_init ("cefping", 1);
	
	cef_frame_init ();
	memset (&params, 0, sizeof (CefT_Cp_Parms));
	memset (&tlvs, 0, sizeof (CefT_Ping_TLVs));
	params.count 		= 1;
	params.wait_time 	= 3;
	params.hop_limit 	= 32;
	cp_running_f 		= 0;
	
	/*----------------------------------------------------------------
		Parses parameters
	------------------------------------------------------------------*/
	if (cp_parse_parameters (argc, argv) < 0) {
		exit (0);
	}
	cef_log_init2 (conf_path, 1 /* for CEFNETD */);
#ifdef CefC_Debug
	cef_dbg_init ("cefping", conf_path, 1);
#endif // CefC_Debug
	
	/*----------------------------------------------------------------
		Connects to cefnetd
	------------------------------------------------------------------*/
	res = cef_client_init (port_num, conf_path);
	if (res < 0) {
		fprintf (stdout, "[cefping] ERROR: Failed to init the client package.\n");
		exit (1);
	}
	
	fhdl = cef_client_connect ();
	if (fhdl < 1) {
		fprintf (stdout, "[cefping] ERROR: fail to connect cefnetd\n");
		exit (0);
	}
	
	/*----------------------------------------------------------------
		Creates and puts a cefping
	------------------------------------------------------------------*/
	tlvs.hoplimit = params.hop_limit;
	tlvs.name_len = params.name_len;
	memcpy (tlvs.name, params.name, tlvs.name_len);
	
	if (params.responder_len > 0) {
		tlvs.opt.responder_f = params.responder_len;
		memcpy (tlvs.opt.responder_id, params.responder, params.responder_len);
	}
	tlvs.opt.responder_f = params.responder_id_len;
	memcpy (tlvs.opt.responder_id, params.responder_id, tlvs.opt.responder_f);
	
	cef_client_cefping_input (fhdl, &tlvs);
	params.count--;
	
	/*----------------------------------------------------------------
		Main loop
	------------------------------------------------------------------*/
	gettimeofday (&tv, NULL);
	start_us_t = cef_client_covert_timeval_to_us (tv);
	end_us_t = start_us_t + (uint64_t)(params.wait_time * 1000000);
	cp_running_f = 1;
	
	while (cp_running_f) {
		if (SIG_ERR == signal (SIGINT, cp_sigcatch)) {
			break;
		}
		
		/* Obtains the current time in usec 		*/
		gettimeofday (&tv, NULL);
		now_us_t = cef_client_covert_timeval_to_us (tv);
		
		/* Obtains the replay from cefnetd 			*/
		res = cef_client_read (fhdl, buff, CefC_Max_Length);
		
		if (res > 0) {
			
			memcpy (&packet_len, &buff[CefC_O_Fix_PacketLength], CefC_S_Length);
			packet_len = ntohs (packet_len);
			header_len = buff[CefC_O_Fix_HeaderLength];
			
			if (packet_len == res) {
				cp_results_output (buff, packet_len, header_len, now_us_t - start_us_t);
				
				if (params.count > 0) {
					cef_client_cefping_input (fhdl, &tlvs);
					end_us_t = now_us_t + (uint64_t)(params.wait_time * 1000000);
					params.count--;
				}
			}
		}
		
		/* Checks the waiting time 		*/
		if (now_us_t > end_us_t) {
			if (params.count > 0) {
				cef_client_cefping_input (fhdl, &tlvs);
				end_us_t = now_us_t + (uint64_t)(params.wait_time * 1000000);
				params.count--;
			} else {
				break;
			}
		}
	}
	if (!output_f) {
		fprintf (stdout, "timeout\n");
	}
	output_f = 0;
	cef_client_close (fhdl);
	exit (0);
}
/*--------------------------------------------------------------------------------------
	Outputs the results
----------------------------------------------------------------------------------------*/
static void
cp_results_output (
	unsigned char* msg, 
	uint16_t packet_len, 
	uint16_t header_len, 
	uint64_t rtt_us
) {
	CefT_Parsed_Message 	pm;
	CefT_Parsed_Opheader 	poh;
	int res;
	char addrstr[256];
	
	/* Parses the received Cefping Replay 	*/
	res = cef_frame_message_parse (
					msg, packet_len, header_len, &poh, &pm, CefC_PT_PING_REP);
	if ( pm.AppComp_num > 0 ) {
		/* Free AppComp */
		cef_frame_app_components_free ( pm.AppComp_num, pm.AppComp );
	}
	
	if (res < 0) {
		return;
	}
	
	/* Outputs header message 			*/
	fprintf (stdout, "response from ");
	
	/* Outputs the responder			*/
	if (pm.payload_len == 4) {
		inet_ntop (AF_INET, pm.payload, addrstr, sizeof (addrstr));
		fprintf (stdout, "%s: ", addrstr);
	} else if (pm.payload_len == 16) {
		inet_ntop (AF_INET6, pm.payload, addrstr, sizeof (addrstr));
		fprintf (stdout, "%s: ", addrstr);
	} else {
		for (res = 0 ; res < pm.payload_len ; res++) {
			fprintf (stdout, "%02X", pm.payload[res]);
		}
		fprintf (stdout, ": ");
	}
	
	/* Checks Return Code 			*/
	switch (pm.ping_retcode) {
		case CefC_CpRc_Cache: {
			fprintf (stdout, "cache    ");
			break;
		}
		case CefC_CpRc_NoCache: {
			fprintf (stdout, "no cache ");
			break;
		}
		case CefC_CpRc_NoRoute: {
			fprintf (stdout, "no route ");
			break;
		}
		case CefC_CpRc_AdProhibit: {
			fprintf (stdout, "prohibit ");
			break;
		}
		default: {
			fprintf (stdout, "unknown  ");
			break;
		}
	}
	
	/* Outputs RTT[ms]					*/
	fprintf (stdout, "time=%f ms\n", (double)((double) rtt_us / 1000.0));
	output_f = 1;
	
	return;
}

/*--------------------------------------------------------------------------------------
	Outputs usage
----------------------------------------------------------------------------------------*/
static void
cp_usage_output (
	const char* msg									/* Supplementary information 		*/
) {
	if (msg) {
		fprintf (stdout, "%s\n\n", msg);
	}
	
	fprintf (stdout, 	"Usage: cefping prefix [-r responder]"
						"[-h hop_limit][-w wait_time][-d config_file_dir][-p port_num]\n");
	
	return;
}

/*--------------------------------------------------------------------------------------
	Parses parameters
----------------------------------------------------------------------------------------*/
static int											/* error occurs, return negative	*/
cp_parse_parameters (
	int 	argc, 									/* same as main function 			*/
	char*	argv[]									/* same as main function 			*/
) {
	int 	i, n;
	char*	work_arg;
	int 	res;
	
	int 	num_opt_r 		= 0;
	int 	num_opt_w 		= 0;
	int 	num_opt_h 		= 0;
	int 	num_opt_prefix 	= 0;
	int 	dir_path_f 		= 0;
	int 	port_num_f 		= 0;
	
	/* Parses parameters 		*/
	for (i = 1 ; i < argc ; i++) {
		
		work_arg = argv[i];
		if (work_arg == NULL || work_arg[0] == 0) {
			break;
		}
		
		if (strcmp (work_arg, "-r") == 0) {
			if (num_opt_r) {
				cp_usage_output ("error: responder is duplicated.");
				return (-1);
			}
			if (i + 1 == argc) {
				cp_usage_output ("error: responder is not specified.");
				return (-1);
			}
			work_arg = argv[i + 1];
			
			if (strlen (work_arg) >= CefC_Max_Buff) {
				cp_usage_output ("error: responder is too long.");
				return (-1);
			}
			params.responder_len = strlen (work_arg);
			strcpy (params.responder, work_arg);
			
			res = inet_pton (AF_INET, params.responder, &params.responder_id);
			
			if (res == 0) {
				res = inet_pton (AF_INET6, params.responder, &params.responder_id);
				
				if (res == 0) {
					cp_usage_output ("error: responder is invalid.");
					return (-1);
				}
				params.responder_id_len = 16;
			} else {
				params.responder_id_len = 4;
			}
			
			num_opt_r++;
			i++;
		} else if (strcmp (work_arg, "-w") == 0) {
			if (num_opt_w) {
				cp_usage_output ("error: wait_time is duplicated.");
				return (-1);
			}
			if (i + 1 == argc) {
				cp_usage_output ("error: wait_time is not specified.");
				return (-1);
			}
			work_arg = argv[i + 1];
			for (n = 0 ; work_arg[n] ; n++) {
				if (isdigit (work_arg[n]) == 0) {
					cp_usage_output ("error: wait_time is invalid.");
					return (-1);
				}
			}
			params.wait_time = atoi (work_arg);
			
			if (params.wait_time < 1) {
				cp_usage_output ("error: wait_time is smaller than 1.");
				return (-1);
			}
			num_opt_w++;
			i++;
		} else if (strcmp (work_arg, "-h") == 0) {
			if (num_opt_h) {
				cp_usage_output ("error: hop_limit is duplicated.");
				return (-1);
			}
			if (i + 1 == argc) {
				cp_usage_output ("error: hop_limit is not specified.");
				return (-1);
			}
			work_arg = argv[i + 1];
			for (n = 0 ; work_arg[n] ; n++) {
				if (isdigit (work_arg[n]) == 0) {
					cp_usage_output ("error: hop_limit is invalid.");
					return (-1);
				}
			}
			params.hop_limit = atoi (work_arg);
			
			if (params.hop_limit < 1) {
				cp_usage_output ("error: hop_limit is smaller than 1.");
				return (-1);
			}
			num_opt_h++;
			i++;
		} else if (strcmp (work_arg, "-d") == 0) {
			if (dir_path_f) {
				cp_usage_output ("error: [-d] is duplicated.\n");
				return (-1);
			}
			if (i + 1 == argc) {
				cp_usage_output ("error: [-d] has no parameter.\n");
				return (-1);
			}
			work_arg = argv[i + 1];
			strcpy (conf_path, work_arg);
			dir_path_f++;
			i++;
		} else if (strcmp (work_arg, "-p") == 0) {
			if (port_num_f) {
				cp_usage_output ("error: [-p] is duplicated.\n");
				return (-1);
			}
			if (i + 1 == argc) {
				cp_usage_output ("error: [-p] has no parameter.\n");
				return (-1);
			}
			work_arg = argv[i + 1];
			port_num = atoi (work_arg);
			port_num_f++;
			i++;
		} else {
			
			work_arg = argv[i];
			
			if (work_arg[0] == '-') {
				cp_usage_output ("error: unknown option is specified.");
				return (-1);
			}
			
			if (num_opt_prefix) {
				cp_usage_output ("error: prefix is duplicated.");
				return (-1);
			}
			res = strlen (work_arg);
			
			if (res >= CefC_Cp_Str_Max) {
				cp_usage_output ("error: prefix is too long.");
				return (-1);
			}
			
			res = cef_frame_conversion_uri_to_name (work_arg, params.name);
			
			if (res < 0) {
				cp_usage_output ("error: prefix is invalid.");
				return (-1);
			}
			if (res < 5/* require longer than Type + Length */) {
				cp_usage_output ("error: prefix MUST NOT be ccn:/");
				return (-1);
			}
			params.name_len = res;
			
			strcpy (params.prefix, work_arg);
			
			num_opt_prefix++;
		}
	}
	
	/* Checks option error */
	if (num_opt_prefix != 1) {
		cp_usage_output ("error: prefix is not specified.");
		return (-1);
	}
	
	return (1);
}
/*--------------------------------------------------------------------------------------
	Catch the signal
----------------------------------------------------------------------------------------*/
static void
cp_sigcatch (
	int sig
) {
	if (sig == SIGINT) {
		cp_running_f = 0;
	}
}


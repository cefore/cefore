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
 * ccninfo.c
 */

#define __CCNINFO_SOURECE__

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
#include <cefore/cef_cefinfo.h>
#include <cefore/cef_log.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

#define CefC_Ct_Str_Max 		256
#define CefC_Ct_Str_Buff 		257
#define CefC_Max_Buff 			64

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

typedef struct {
	
	char 			prefix[CefC_Ct_Str_Buff];
	unsigned char 	name[CefC_Max_Length];
	int 			name_len;
	int 			wait_time;
	int 			hop_limit;
	int 			skip_hop;
	uint8_t 		flag;
	
} CefT_Ct_Parms;

/****************************************************************************************
 State Variables
 ****************************************************************************************/

static char 	protocol[CefC_Ct_Str_Max];
static char 	conf_path[PATH_MAX] = {0};
static int 		port_num = CefC_Unset_Port;

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

static CefT_Ct_Parms params;
static int ct_running_f;
CefT_Client_Handle fhdl;

/*--------------------------------------------------------------------------------------
	Outputs usage
----------------------------------------------------------------------------------------*/
static void
ct_usage_output (
	const char* msg									/* Supplementary information 		*/
);
/*--------------------------------------------------------------------------------------
	Parses parameters
----------------------------------------------------------------------------------------*/
static int											/* error occurs, return negative	*/
ct_parse_parameters (
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
	Obtains the protocol name
----------------------------------------------------------------------------------------*/
static void
cp_protocol_get (
	const char* name,
	char* protocol
);
/*--------------------------------------------------------------------------------------
	Outputs the results
----------------------------------------------------------------------------------------*/
static void
ct_results_output (
	unsigned char* msg,
	uint16_t packet_len, 
	uint16_t header_len, 
	uint64_t start_us, 
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
	CefT_Trace_TLVs tlvs;
	unsigned char buff[CefC_Max_Length];
	unsigned char msg[CefC_Max_Length];
	int res;
	uint16_t pkt_len;
	uint16_t index = 0;
	struct fixed_hdr* fixhdr;
	
	/*----------------------------------------------------------------
		Init variables
	------------------------------------------------------------------*/
	/* Inits logging 		*/
	cef_log_init ("cefinfo");
	
	cef_frame_init ();
	memset (&params, 0, sizeof (CefT_Ct_Parms));
	memset (&tlvs, 0, sizeof (CefT_Trace_TLVs));
	ct_running_f = 0;
	
	/* Sets default values that are not zero to parameters		*/
	params.wait_time = CefC_Default_LifetimeSec;
	params.hop_limit = 32;
	
	/*----------------------------------------------------------------
		Parses parameters
	------------------------------------------------------------------*/
	if (ct_parse_parameters (argc, argv) < 0) {
		exit (0);
	}
	if (params.skip_hop >= params.hop_limit) {
		ct_usage_output ("error: [-s hop_count] is greater than [-r hop_count]");
		exit (0);
	}
	if ((params.flag & CefC_CtOp_Publisher) &&
		(params.name_len == 4/* Default Name (cef:/)*/)) {
		ct_usage_output ("error: Default Name is specified with [-o].");
		exit (0);
	}
#ifdef CefC_Debug
	cef_dbg_init ("cefinfo", conf_path, 1);
#endif // CefC_Debug
	
	/*----------------------------------------------------------------
		Connects to cefnetd
	------------------------------------------------------------------*/
	res = cef_client_init (port_num, conf_path);
	if (res < 0) {
		fprintf (stdout, "[cefinfo] ERROR: Failed to init the client package.\n");
		exit (0);
	}
	
	fhdl = cef_client_connect ();
	if (fhdl < 1) {
		fprintf (stderr, "[cefinfo] ERROR: fail to connect cefnetd\n");
		exit (0);
	}
	
	/*----------------------------------------------------------------
		Creates and puts a cefinfo request
	------------------------------------------------------------------*/
	tlvs.hoplimit = (uint8_t) params.hop_limit;
	tlvs.name_len = params.name_len;
	tlvs.opt.timeout = params.wait_time;
	memcpy (tlvs.name, params.name, tlvs.name_len);
	cp_protocol_get (params.prefix, protocol);
	
	tlvs.opt.trace_flag = params.flag;
	if (params.skip_hop > 0) {
		tlvs.opt.skip_hop = (uint8_t) params.skip_hop;
	}
	
	srand ((unsigned) time (NULL));
	tlvs.opt.req_id = (uint16_t)(rand () % 65535);
	
	fprintf (stderr, "cefinfo to %s with "	, params.prefix);
	fprintf (stderr, "HopLimit=%d, "		, params.hop_limit);
	fprintf (stderr, "SkipHopCount=%d, "	, params.skip_hop);
	fprintf (stderr, "Flag=0x%04X and "		, params.flag);
	fprintf (stderr, "Request ID=%u\n"		, tlvs.opt.req_id);
	
	cef_client_cefinfo_input (fhdl, &tlvs);
	
	/*----------------------------------------------------------------
		Main loop
	------------------------------------------------------------------*/
	gettimeofday (&tv, NULL);
	start_us_t = cef_client_covert_timeval_to_us (tv);
	end_us_t = start_us_t + (uint64_t)(params.wait_time * 1000000);
	ct_running_f = 1;
	
	while (ct_running_f) {
		if (SIG_ERR == signal (SIGINT, cp_sigcatch)) {
			break;
		}
		
		/* Obtains the current time in usec 		*/
		gettimeofday (&tv, NULL);
		now_us_t = cef_client_covert_timeval_to_us (tv);
		
		/* Obtains the replay from cefnetd 			*/
		res = cef_client_read (fhdl, &buff[index], CefC_Max_Length - index);
		
		if (res > 0) {
			res += index;
			
			gettimeofday (&tv, NULL);
			now_us_t = cef_client_covert_timeval_to_us (tv);
			
			do {
				fixhdr = (struct fixed_hdr*) buff;
				pkt_len = ntohs (fixhdr->pkt_len);
				
				if (res >= pkt_len) {
					ct_results_output (buff, pkt_len, 
							fixhdr->hdr_len, start_us_t, now_us_t - start_us_t);
					
					if (res - pkt_len > 0) {
						memcpy (msg, &buff[pkt_len], res - pkt_len);
						memcpy (buff, msg, res - pkt_len);
						index = res - pkt_len;
					} else {
						index = 0;
					}
					res -= pkt_len;
				} else {
					index = res;
					break;
				}
			} while (res > 0);
		}
		
		/* Checks the waiting time 		*/
		if (now_us_t > end_us_t) {
			break;
		}
	}
	cef_client_close (fhdl);
	exit (0);
}
/*--------------------------------------------------------------------------------------
	Outputs the results
----------------------------------------------------------------------------------------*/
static void
ct_results_output (
	unsigned char* msg, 
	uint16_t packet_len, 
	uint16_t header_len, 
	uint64_t start_us,
	uint64_t rtt_us
) {
	CefT_Parsed_Message 	pm;
	CefT_Parsed_Opheader 	poh;
	int res, i, n, x;
	uint16_t 	ret_code;
	uint16_t 	index;
	uint16_t 	end_pld;
	uint16_t 	offset;
	uint16_t 	fd_type, fd_len, rp_type, cs_type, seg_len;
	uint16_t 	id_len;
	uint16_t 	gw_cnt;
	
	unsigned char name[2048];
	char 		gw_ids[32][256];
	uint16_t	gw_len[32];
	uint64_t	gw_stp[32];
	char 		addrstr[256];
	double 		diff_us;
	struct tlv_hdr* tlv_hdr;
	struct trace_rep_block* trbp;
	struct trace_rep_block rep_blk;
	struct hostent* host;
	char con_type[5] = {"xcpdf"};
	char cache_type[2] = {" '"};
	
	/* Parses the received Cefinfo Replay 	*/
	res = cef_frame_message_parse (
					msg, packet_len, header_len, &poh, &pm, CefC_PT_TRACE_REP);
	
	if (res < 0) {
		return;
	}
	
	/* Parses the Report Blocks 			*/
	index = CefC_S_Fix_Header;
	gw_cnt = 0;
	
	while (index < header_len) {
		
		tlv_hdr = (struct tlv_hdr*) &msg[index];
		fd_type = ntohs (tlv_hdr->type);
		fd_len  = ntohs (tlv_hdr->length);
		
		if (fd_type == CefC_T_OPT_TRACE_RPT) {
			
			offset = index + CefC_S_TLF;
			id_len = fd_len - 8;
			
			memcpy (&gw_stp[gw_cnt], &msg[offset], sizeof (uint64_t));
			gw_stp[gw_cnt] = cef_client_ntohb (gw_stp[gw_cnt]);
			
			memcpy (&gw_ids[gw_cnt][0], &msg[offset + sizeof (uint64_t)], id_len);
			gw_ids[gw_cnt][id_len] = 0x00;
			gw_len[gw_cnt] = id_len;
			
			gw_cnt++;
		}
		index += CefC_S_TLF + fd_len;
	}
	if (gw_cnt == 0) {
		return;
	}
	
	/* Outputs header message 			*/
	fprintf (stderr, "\nresponse from ");
	
	/* Outputs the responder			*/
	if (gw_len[gw_cnt - 1] == 4) {
		host = gethostbyaddr ((const char*)&(gw_ids[gw_cnt - 1][0]), 4, AF_INET);
		if (host != NULL) {
			fprintf (stderr, "%s: ", host->h_name);
		} else {
			inet_ntop (AF_INET, &gw_ids[gw_cnt - 1][0], addrstr, sizeof (addrstr));
			fprintf (stderr, "%s: ", addrstr);
		}
	} else if (gw_len[gw_cnt - 1] == 16) {
		host = gethostbyaddr ((const char*)&(gw_ids[gw_cnt - 1][0]), 16, AF_INET6);
		if (host != NULL) {
			fprintf (stderr, "%s: ", host->h_name);
		} else {
			inet_ntop (AF_INET6, &gw_ids[gw_cnt - 1][0], addrstr, sizeof (addrstr));
			fprintf (stderr, "%s: ", addrstr);
		}
	} else {
		for (res = 0 ; res < gw_len[gw_cnt - 1] ; res++) {
			fprintf (stderr, "%02X", gw_ids[gw_cnt - 1][res]);
		}
		fprintf (stderr, ": ");
	}
	
	/* Checks Return Code 			*/
	ret_code = msg[CefC_O_Fix_Trace_RetCode];
	
	switch (ret_code) {
		case CefC_CtRc_NoError: {
			fprintf (stderr, "no error");
			break;
		}
		case CefC_CtRc_NoRoute: {
			fprintf (stderr, "no route");
			break;
		}
		case CefC_CtRc_AdProhibit: {
			fprintf (stderr, "prohibit");
			break;
		}
		case CefC_CtRc_NoSpace: {
			fprintf (stderr, "no space");
			break;
		}
		case CefC_CtRc_NoInfo: {
			fprintf (stderr, "no info");
			break;
		}
		case CefC_CtRc_NoMoreHop: {
			fprintf (stderr, "hoplimit");
			break;
		}
		default: {
			fprintf (stderr, "unknown");
			break;
		}
	}
	
	/* Outputs RTT[ms]					*/
	fprintf (stderr, ", time=%f ms\n\n", (double)((double) rtt_us / 1000.0));
	
	/* Outputs Route 					*/
	fprintf (stderr, "route information:\n");
	for (i = 0 ; i < gw_cnt ; i++) {
		
		fprintf (stderr, "%2d ", i + 1);
		
		if (gw_len[i] == 4) {
			host = gethostbyaddr ((const char*)&(gw_ids[i][0]), 4, AF_INET);
			if (host != NULL) {
				fprintf (stderr, "%s\t\t\t", host->h_name);
			} else {
				inet_ntop (AF_INET, &gw_ids[i][0], addrstr, sizeof (addrstr));
				fprintf (stderr, "%s\t\t\t", addrstr);
			}
		} else if (gw_len[i] == 16) {
			host = gethostbyaddr ((const char*)&(gw_ids[i][0]), 16, AF_INET6);
			if (host != NULL) {
				fprintf (stderr, "%s\t\t\t", host->h_name);
			} else {
				inet_ntop (AF_INET6, &gw_ids[i][0], addrstr, sizeof (addrstr));
				fprintf (stderr, "%s\t\t\t", addrstr);
			}
		} else {
			for (res = 0 ; res < gw_len[i] ; res++) {
				fprintf (stderr, "%02X", gw_ids[i][res]);
			}
			fprintf (stderr, "\t\t\t");
		}
		
		if (i) {
			diff_us = (double)((double) gw_stp[i] - (double) gw_stp[i - 1]);
		} else {
			diff_us = (double)((double) gw_stp[i] - (double) start_us);
		}
		
		fprintf (stderr, "%.3f ms\n", diff_us / 1000.0);
	}
	fprintf (stderr, "\n");
	
	/* Outputs Cache Status 				*/
	if (pm.payload_len == 0) {
		return;
	}
	index = pm.payload_f + CefC_S_Type + CefC_S_Length;
	end_pld = index + pm.payload_len;
	i = 1;
	
	fprintf (stderr, "cache information:"
		"   prefix    size    cobs    interests   start-end    lifetime    expire\n");
	while (index < end_pld) {
		
		/* Obtains Type and Length 		*/
		tlv_hdr = (struct tlv_hdr*) &msg[index];
		rp_type = ntohs (tlv_hdr->type);
		if (rp_type & CefC_T_TRACE_ON_CSMGRD) {
			cs_type = 1;
		} else {
			cs_type = 0;
		}
		rp_type = rp_type & 0x7FFF;
		
		fd_len  = ntohs (tlv_hdr->length);
		index += CefC_S_TLF;
		
		if ((rp_type < CefC_T_TRACE_CONTENT) || (rp_type > CefC_T_TRACE_FUNCTION)) {
			fprintf (stderr, "Invalid Reply Block!!!\n");
			break;
		}
		
		/* Obtains values with fixed length 	*/
		trbp = (struct trace_rep_block*) &msg[index];
		
		rep_blk.cont_size 	= ntohl (trbp->cont_size);
		rep_blk.cont_cnt 	= ntohl (trbp->cont_cnt);
		rep_blk.rcv_int 	= ntohl (trbp->rcv_int);
		rep_blk.first_seq 	= ntohl (trbp->first_seq);
		rep_blk.last_seq 	= ntohl (trbp->last_seq);
		rep_blk.cache_time 	= cef_client_ntohb (trbp->cache_time);
		rep_blk.remain_time = cef_client_ntohb (trbp->remain_time);
		index += sizeof (struct trace_rep_block);
		
		/* Obtains Name 						*/
		tlv_hdr = (struct tlv_hdr*) &msg[index];
		fd_type = ntohs (tlv_hdr->type);
		fd_len  = ntohs (tlv_hdr->length);
		index += CefC_S_TLF;
		
		if (fd_type != CefC_T_NAME) {
			fprintf (stderr, "Invalid Reply Block!!!\n");
			break;
		}
		memcpy (name, &msg[index], fd_len);
		
		fprintf (stderr, "%2d %c%c "
			, i, con_type[rp_type], cache_type[cs_type]);
		
		fprintf (stderr, "%s:/", protocol);
		n = 0;
		
		while (n < fd_len) {
			tlv_hdr = (struct tlv_hdr*) &name[n];
			seg_len = ntohs (tlv_hdr->length);
			n += CefC_S_TLF;
			
			for (x = 0 ; x < seg_len ; x++) {
				if (name[n + x] == 0x2d) {
					fprintf (stderr, "%c", name[n + x]);
				}else if ((name[n + x] < 0x30) || (name[n + x] > 0x7E)) {
					fprintf (stderr, "%02X", name[n + x]);
				} else {
					fprintf (stderr, "%c", name[n + x]);
				}
			}
			fprintf (stderr, "/");
			n += seg_len;
		}
		
		fprintf (stderr, "\t%7u KB %7u %5u   "
			, rep_blk.cont_size, rep_blk.cont_cnt, rep_blk.rcv_int);
		
		fprintf (stderr, "%u-%u   ", rep_blk.first_seq, rep_blk.last_seq);
		
		fprintf (stderr, FMTU64" secs   "FMTU64" secs\n"
			, rep_blk.remain_time, rep_blk.cache_time);
		
		i++;
		index += fd_len;
	}
	
	fprintf (stderr, "\n");
	
	return;
}

/*--------------------------------------------------------------------------------------
	Outputs usage
----------------------------------------------------------------------------------------*/
static void
ct_usage_output (
	const char* msg									/* Supplementary information 		*/
) {
	fprintf (stderr, 	"Usage:cefinfo name_prefix [-P] [-n] [-o] [-r hop_count]"
						" [-s skip_hop] [-w wait_time]\n");
	
	if (msg) {
		fprintf (stderr, "%s\n", msg);
	}
	
	return;
}

/*--------------------------------------------------------------------------------------
	Parses parameters
----------------------------------------------------------------------------------------*/
static int											/* error occurs, return negative	*/
ct_parse_parameters (
	int 	argc, 									/* same as main function 			*/
	char*	argv[]									/* same as main function 			*/
) {
	int 	i, n;
	char*	work_arg;
	int 	res;
	
	/* counters of each parameter 	*/
	int 	num_opt_p 		= 0;
	int 	num_opt_r 		= 0;
	int 	num_opt_s 		= 0;
	int 	num_opt_prefix 	= 0;
	int 	num_opt_n 		= 0;
	int 	num_opt_o 		= 0;
	int 	dir_path_f 		= 0;
	int 	port_num_f 		= 0;
	
	/* Parses parameters 		*/
	for (i = 1 ; i < argc ; i++) {
		
		work_arg = argv[i];
		if (work_arg == NULL || work_arg[0] == 0) {
			break;
		}
		
		/*-----------------------------------------------------------------------*/
		/****** -P (requires the partial match) 							******/
		/*-----------------------------------------------------------------------*/
		if (strcmp (work_arg, "-P") == 0) {
			/* Checks whether [-p] is not specified more than twice. 	*/
			if (num_opt_p) {
				ct_usage_output ("error: [-P] is duplicated.");
				return (-1);
			}
			params.flag |= CefC_CtOp_ReqPartial;
			num_opt_p++;
		/*-----------------------------------------------------------------------*/
		/****** -n 															******/
		/*-----------------------------------------------------------------------*/
		} else if (strcmp (work_arg, "-n") == 0) {
			/* Checks whether [-n] is not specified more than twice. 	*/
			if (num_opt_n) {
				ct_usage_output ("error: [-n] is duplicated.");
				return (-1);
			}
			
			params.flag |= CefC_CtOp_NoCache;
			num_opt_n++;
		/*-----------------------------------------------------------------------*/
		/****** -o 															******/
		/*-----------------------------------------------------------------------*/
		} else if (strcmp (work_arg, "-o") == 0) {
			/* Checks whether [-o] is not specified more than twice. 	*/
			if (num_opt_o) {
				ct_usage_output ("error: [-o] is duplicated.");
				return (-1);
			}
			params.flag |= CefC_CtOp_Publisher;
			num_opt_o++;
		/*-----------------------------------------------------------------------*/
		/****** -r 															******/
		/*-----------------------------------------------------------------------*/
		} else if (strcmp (work_arg, "-r") == 0) {
			/* Checks whether [-r] is not specified more than twice. 	*/
			if (num_opt_r) {
				ct_usage_output ("error: [-r hop_count] is duplicated.");
				return (-1);
			}
			if (i + 1 == argc) {
				ct_usage_output ("error: [-r hop_count] is invalid.");
				return (-1);
			}
			
			/* Checks whethre the specified value is valid or not.	*/
			work_arg = argv[i + 1];
			for (n = 0 ; work_arg[n] ; n++) {
				if (isdigit (work_arg[n]) == 0) {
					ct_usage_output ("error: [-r hop_count] is invalid.");
					return (-1);
				}
			}
			params.hop_limit = atoi (work_arg);
			
			if (params.hop_limit < 1) {
				ct_usage_output ("error: [-r hop_count] is smaller than 1.");
				return (-1);
			}
			if (params.hop_limit > 255) {
				params.hop_limit = 255;
			}
			num_opt_r++;
			i++;
		/*-----------------------------------------------------------------------*/
		/****** -s 															******/
		/*-----------------------------------------------------------------------*/
		} else if (strcmp (work_arg, "-s") == 0) {
			/* Checks whether [-s] is not specified more than twice. 	*/
			if (num_opt_s) {
				ct_usage_output ("error: [-s hop_count] is duplicated.");
				return (-1);
			}
			if (i + 1 == argc) {
				ct_usage_output ("error: [-s hop_count] is invalid.");
				return (-1);
			}
			
			/* Checks whethre the specified value is valid or not.	*/
			work_arg = argv[i + 1];
			for (n = 0 ; work_arg[n] ; n++) {
				if (isdigit (work_arg[n]) == 0) {
					ct_usage_output ("error: [-s hop_count] is invalid.");
					return (-1);
				}
			}
			params.skip_hop = atoi (work_arg);
			
			if (params.skip_hop < 1) {
				ct_usage_output ("error: [-s hop_count] is smaller than 1.");
				return (-1);
			}
			if (params.skip_hop > 255) {
				params.skip_hop = 255;
			}
			num_opt_s++;
			i++;
		/*-----------------------------------------------------------------------*/
		/****** -d 															******/
		/*-----------------------------------------------------------------------*/
		} else if (strcmp (work_arg, "-d") == 0) {
			if (dir_path_f) {
				ct_usage_output ("error: [-d] is duplicated.\n");
				return (-1);
			}
			if (i + 1 == argc) {
				ct_usage_output ("error: [-d] has no parameter.\n");
				return (-1);
			}
			work_arg = argv[i + 1];
			strcpy (conf_path, work_arg);
			dir_path_f++;
			i++;
		/*-----------------------------------------------------------------------*/
		/****** -p 															******/
		/*-----------------------------------------------------------------------*/
		} else if (strcmp (work_arg, "-p") == 0) {
			if (port_num_f) {
				ct_usage_output ("error: [-p] is duplicated.\n");
				return (-1);
			}
			if (i + 1 == argc) {
				ct_usage_output ("error: [-p] has no parameter.\n");
				return (-1);
			}
			work_arg = argv[i + 1];
			port_num = atoi (work_arg);
			port_num_f++;
			i++;
		/*-----------------------------------------------------------------------*/
		/****** name_prefix 												******/
		/*-----------------------------------------------------------------------*/
		} else {
			/* Error to the invalid option. 		*/
			work_arg = argv[i];
			if (work_arg[0] == '-') {
				ct_usage_output ("error: unknown option is specified.");
				return (-1);
			}
			
			/* Checks whether name_prefix is not specified more than twice. 	*/
			if (num_opt_prefix) {
				ct_usage_output ("error: name_prefix is duplicated.");
				return (-1);
			}
			res = strlen (work_arg);
			
			if (res >= CefC_Ct_Str_Max) {
				ct_usage_output ("error: name_prefix is too long.");
				return (-1);
			}
			
			/* Converts the URI to Name. 			*/
			res = cef_frame_conversion_uri_to_name (work_arg, params.name);
			
			if (res < 0) {
				ct_usage_output ("error: prefix is invalid.");
				return (-1);
			}
			if (res < 5) {
				ct_usage_output ("error: prefix MUST NOT be ccn:/.");
				return (-1);
			}
			params.name_len = res;
			strcpy (params.prefix, work_arg);
			
			num_opt_prefix++;
		}
	}
	if (num_opt_prefix == 0) {
		ct_usage_output ("error: prefix is not specified.");
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
		ct_running_f = 0;
	}
}
/*--------------------------------------------------------------------------------------
	Obtains the protocol name
----------------------------------------------------------------------------------------*/
static void
cp_protocol_get (
	const char* name,
	char* protocol
) {
	const char* wp = name;
	uint16_t prot_len, n;
	int name_len;
	
	name_len = strlen (name);
	prot_len = 0;
	
	if (name_len >= CefC_Ct_Str_Max) {
		strcpy (protocol, "invalid");
		return;
	}
	
	for (n = 0 ; n < name_len ; n++) {
		if (wp[n] != ':') {
			protocol[prot_len] = wp[n];
			prot_len++;
		} else {
			protocol[prot_len] = 0x00;
			break;
		}
	}
	if (n == name_len) {
		strcpy (protocol, "cef");
	}
}

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
 * cefputfile.c
 */
 

#define __CEF_PUTFILE_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>
#include <sys/time.h>
#include <time.h>
#include <sys/stat.h>

#include <cefore/cef_define.h>
#include <cefore/cef_frame.h>
#include <cefore/cef_client.h>
#include <cefore/cef_valid.h>
#include <cefore/cef_log.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

#define CefC_Putfile_Max 					512000
//#define CefC_RateMbps_Max				 	32.0
#define CefC_RateMbps_Max				 	100000000.0
#define CefC_RateMbps_Min				 	0.001	/* 1Kbps */

//#define TO_CSMGRD // Enable to connect directly to Csmgrd

#define USAGE                               print_usage(CefFp_Usage)
#define printerr(...)                       fprintf(stderr,"[cefputfile] ERROR: " __VA_ARGS__)

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/


/****************************************************************************************
 State Variables
 ****************************************************************************************/

static int app_running_f = 0;
CefT_Client_Handle fhdl;
static struct timeval start_t;
static struct timeval end_t;
static uint64_t stat_send_frames = 0;
static uint64_t stat_send_bytes = 0;

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

int bnum = 0;
#if 1 //+++++@@@@@ DUMMY FILE
	int dummy_f 		= 0;
	uint32_t dummy_sum	= 0;
#endif //-----@@@@@ DUMMY FILE
/****************************************************************************************
 ****************************************************************************************/
int main (
	int argc,
	char** argv
) {
	int res;
	unsigned char buff[CefC_Max_Length];
	CefT_CcnMsg_OptHdr opt;	
	CefT_CcnMsg_MsgBdy params;
	uint64_t seqnum = 0;
	char uri[1024];
	size_t uri_len;
	struct stat statBuf;
	
	char filename[1024];
	FILE* fp;
	double interval;
	long interval_us;
	static struct timeval now_t;
	uint64_t next_tus;
	uint64_t now_tus;
	uint64_t now_tus2;
	uint64_t now_ms;
	char*	work_arg;
	int 	i;
	
	char 	conf_path[PATH_MAX] = {0};
	int 	port_num = CefC_Unset_Port;
	char 	valid_type[1024];
	
	unsigned char* 	work_buff = NULL;
	uint32_t 		work_buff_idx = 0;
	int 			cob_len;
	unsigned char 	cob_buff[CefC_Max_Length*2];
	unsigned char   wbuff[CefC_Max_Length*2];
	
	long int int_rate;
	long sending_time_us;
	
	/***** flags 		*****/
	int uri_f 		= 0;
	int file_f 		= 0;
	int rate_f 		= 0;
	int blocks_f 	= 0;
	int expiry_f 	= 0;
	int cachet_f 	= 0;
	int nsg_f 		= 0;
	int dir_path_f 	= 0;
	int port_num_f 	= 0;
	int valid_f 	= 0;
	
	/***** parameters 	*****/
	uint64_t cache_time 	= 300;
	uint64_t expiry 		= 3600;
	double rate 			= 5.0;
	int block_size 			= 1024;
#if 1 //+++++@@@@@ DUMMY FILE
	uint64_t dummy_para;			/* dummy file size (KByte) */
	uint64_t dummy_size;
	uint64_t dummy_sent_size	= 0;
#endif //-----@@@@@ DUMMY FILE
	
	/*------------------------------------------
		Checks specified options
	--------------------------------------------*/
	uri[0] 			= 0;
	valid_type[0] 	= 0;
	
	printf ("[cefputfile] Start\n");
	
	/* Inits logging 		*/
	cef_log_init ("cefputfile", 1);
	
	/* Obtains options 		*/
	for (i = 1 ; i < argc ; i++) {
		
		work_arg = argv[i];
		if (work_arg == NULL || work_arg[0] == 0) {
			break;
		}
#if 1 //+++++@@@@@ DUMMY FILE		
		if (strcmp (work_arg, "-D") == 0) {
			if (file_f) {
				printerr("[-D] is duplicated.");
				USAGE;
				return (-1);
			}
			if (i + 1 == argc) {
				printerr("[-D] has no parameter.\n");
				USAGE;
				return (-1);
			}
			work_arg = argv[i + 1];
			dummy_para = (uint64_t)strtoull (work_arg, NULL, 10);
			printf ("[cefputfile] dummy_para   = "FMTU64"\n", dummy_para);
			dummy_size = dummy_para;
			dummy_size = dummy_size * 1024;
			printf ("[cefputfile] dummy_size   = "FMTU64"\n", dummy_size);
			dummy_f++;
			i++;
		} else 
#endif //-----@@@@@ DUMMY FILE		
		if (strcmp (work_arg, "-f") == 0) {
			if (file_f) {
				printerr("[-f] is duplicated.");
				USAGE;
				return (-1);
			}
			if (i + 1 == argc) {
				printerr("[-f] has no parameter.\n");
				USAGE;
				return (-1);
			}
			work_arg = argv[i + 1];
			strcpy (filename, work_arg);
			file_f++;
			i++;
		} else if (strcmp (work_arg, "-r") == 0) {
			if (rate_f) {
				printerr("[-r] is duplicated.");
				USAGE;
				return (-1);
			}
			if (i + 1 == argc) {
				printerr("[-r] has no parameter.\n");
				USAGE;
				return (-1);
			}
			work_arg = argv[i + 1];
			rate = atof (work_arg);
			if (rate < CefC_RateMbps_Min) {
				rate = CefC_RateMbps_Min;
			}
			if (rate > CefC_RateMbps_Max) {
				rate = CefC_RateMbps_Max;
			}
			
			int_rate = (long int)(rate * 1000.0);
			rate = (double)int_rate / 1000.0;
			
			rate_f++;
			i++;
		} else if (strcmp (work_arg, "-b") == 0) {
			if (blocks_f) {
				printerr("[-b] is duplicated.");
				USAGE;
				return (-1);
			}
			if (i + 1 == argc) {
				printerr("[-b] has no parameter.\n");
				USAGE;
				return (-1);
			}
			work_arg = argv[i + 1];
			block_size = atoi (work_arg);
			
#if 0 //+++++@@@@@@ VALIABLE MSGLEN
			if (block_size < 60) {
				block_size = 60;
			}
			if (block_size > 1460) {
				block_size = 1460;
			}
#else
			if (block_size < 1) {
				block_size = 1;
			}
			if (block_size > 65000) {
				block_size = 65000;
			}
#endif  //-----@@@@@@ VALIABLE MSGLEN
			blocks_f++;
			i++;
		} else if (strcmp (work_arg, "-e") == 0) {
			if (expiry_f) {
				printerr("[-e] is duplicated.\n");
				USAGE;
				return (-1);
			}
			if (i + 1 == argc) {
				printerr("[-e] has no parameter.\n");
				USAGE;
				return (-1);
			}
			work_arg = argv[i + 1];
			expiry = atoi (work_arg);
			
			if ((expiry < 1) || (expiry > 31536000)) {
				expiry = 0;
			}
			expiry_f++;
			i++;
		} else if (strcmp (work_arg, "-t") == 0) {
			if (cachet_f) {
				printerr("[-t] is duplicated.\n");
				USAGE;
				return (-1);
			}
			if (i + 1 == argc) {
				printerr("[-t] has no parameter.\n");
				USAGE;
				return (-1);
			}
			work_arg = argv[i + 1];
			cache_time = atoi (work_arg);
			
			if ((cache_time < 0) || (cache_time > 31536000)) {
				cache_time = 10;
			}
			cachet_f++;
			i++;
		} else if (strcmp (work_arg, "-z") == 0) {
			if (nsg_f) {
				printerr("[-z] is duplicated.\n");
				USAGE;
				return (-1);
			}
			if (i + 1 == argc) {
				printerr("[-z] has no parameter.\n");
				USAGE;
				return (-1);
			}
			work_arg = argv[i + 1];
			if (strcmp (work_arg, "sg")) {
				printerr("[-z] has the invalid parameter.\n");
				USAGE;
				return (-1);
			}
			nsg_f++;
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
		} else {
			
			work_arg = argv[i];
			
			if (work_arg[0] == '-') {
				printerr("unknown option (%s) is specified.\n", work_arg);
				USAGE;
				return (-1);
			}
			
			if (uri_f) {
				printerr("uri is duplicated.\n");
				USAGE;
				return (-1);
			}
			res = strlen (work_arg);
			
			if (res >= 1024) {
				printerr("uri is too long.\n");
				USAGE;
				return (-1);
			}
			strcpy (uri, work_arg);
			uri_f++;
		}
	}
	
	if (uri_f == 0) {
		printerr("uri is not specified.\n");
		USAGE;
		exit (1);
	}
	if (file_f == 0) {
		/* Use the last string in the URL */
		res = strlen (uri);
		if (res >= 1204) {
			printerr("uri is too long.\n");
			USAGE;
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
			printerr("File name is not specified.\n");
			USAGE;
			return (-1);
		}
		i = 0;
		while (1) {
			if ((uri[res + i] == '\0') || (uri[res + i] == '/')) {
				break;
			}
			i++;
		}
		strncpy (filename, uri + res, i);
		filename[i] = '\0';
	}
	if (dummy_f == 1) {
		if (cachet_f == 0) {
			cache_time 	= 31536000;
		}
		if (expiry_f == 0) {
			expiry 		= 31536000;
		}
	}
	if (nsg_f == 1) {
		cache_time 	= 0;
		expiry 		= 10;
	}
	printf ("[cefputfile] Parsing parameters ... OK\n");
	cef_log_init2 (conf_path, 1/* for CEFNETD */);
#ifdef CefC_Debug
	cef_dbg_init ("cefputfile", conf_path, 1);
#endif // CefC_Debug
	
	/*------------------------------------------
		Creates the name from URI
	--------------------------------------------*/
	memset (&opt, 0, sizeof (CefT_CcnMsg_OptHdr));	
	memset (&params, 0, sizeof (CefT_CcnMsg_MsgBdy));
	cef_frame_init ();
	res = cef_client_init (port_num, conf_path);
	if (res < 0) {
		printerr("Failed to init the client package.\n");
		exit (1);
	}
	printf ("[cefputfile] Init Cefore Client package ... OK\n");
	res = cef_frame_conversion_uri_to_name (uri, params.name);
	if (res < 0) {
		printerr("Invalid URI is specified.\n");
		exit (1);
	}
	uri_len = strlen (uri);
	if (uri_len && (uri[uri_len-1]=='/')) {
		printerr("Invalid URI specified. It is illegal for a URI to end with /.\n");
		exit (1);
	}
	printf ("[cefputfile] Conversion from URI into Name ... OK\n");
	
	params.name_len 	= res;
	params.chunk_num_f 	= 1;
	
	/*------------------------------------------
		Sets Expiry Time and RCT
	--------------------------------------------*/
	gettimeofday (&now_t, NULL);
//#832	now_ms = now_t.tv_sec * 1000 + now_t.tv_usec / 1000;
	now_ms = now_t.tv_sec * 1000llu + now_t.tv_usec / 1000llu;	//#832
	
	opt.cachetime_f 	= 1;
	opt.cachetime 	= now_ms + cache_time * 1000;
	
	if (expiry) {
		params.expiry = now_ms + expiry * 1000;
	} else {
		params.expiry = now_ms + 3600000;
	}
	
	/*------------------------------------------
		Checks the input file
	--------------------------------------------*/
	if (dummy_f == 0) {
		if (stat(filename, &statBuf) == 0) {
		} else {
			printerr("the specified input file stat can not get.\n");
			exit (1);
		}
		fp = fopen (filename, "rb");
		if (fp == NULL) {
			printerr("the specified input file can not be opened.\n");
			exit (1);
		}
		printf ("[cefputfile] Checking the input file ... OK\n");
	} else {
		unsigned int seed;
		seed = dummy_para;
		for (int i=0; i<strlen (uri); i++) {
			seed += (unsigned int)uri[i];
		}
		srand((unsigned int) seed); 
		statBuf.st_size = dummy_size;
	}
	
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
#ifndef TO_CSMGRD
	fhdl = cef_client_connect ();
#else
	fhdl = cef_client_connect_to_csmgrd ();
#endif
	if (fhdl < 1) {
		printerr("cefnetd is not running.\n");
		exit (1);
	}
	printf ("[cefputfile] Connect to cefnetd ... OK\n");
	
	app_running_f = 1;
	printf ("[cefputfile] URI         = %s\n", uri);
	if (dummy_f == 1) {
		printf ("[cefputfile] Dummy File  = "FMTU64" KByte\n", dummy_para);
	} else {		
		printf ("[cefputfile] File        = %s\n", filename);
	}
	printf ("[cefputfile] Rate        = %.3f Mbps\n", rate);
	printf ("[cefputfile] Block Size  = %d Bytes\n", block_size);
	printf ("[cefputfile] Cache Time  = "FMTU64" sec\n", cache_time);
	printf ("[cefputfile] Expiration  = "FMTU64" sec\n", expiry);
	
	/*------------------------------------------
		Calculates the interval
	--------------------------------------------*/
	interval = (rate * 1000000.0) / (double)(block_size * 8);
	interval_us = (long)((1.0 / interval) * 1000000.0);
	sending_time_us = (long)(((double)(block_size * 8) / (rate * 1000000.0)) * 1000000.0);
	
	/*------------------------------------------
		Main Loop
	--------------------------------------------*/
	gettimeofday (&start_t, NULL);
	next_tus = start_t.tv_sec * 1000000llu + start_t.tv_usec + interval_us;
	work_buff = (unsigned char*) malloc (sizeof (unsigned char) * CefC_Putfile_Max);
	
	printf ("[cefputfile] Start creating Content Objects\n");
	
	while (app_running_f) {
		if (SIG_ERR == signal (SIGINT, sigcatch)) {
			break;
		}
		cob_len = 0;
		
		while (work_buff_idx < 1) {
			if(dummy_f == 0){
				res = fread (buff, sizeof (unsigned char), block_size, fp);
				if(seqnum > UINT32_MAX){
					res = 0;
				}
		
			} else {

				if ((dummy_size - dummy_sent_size) >= block_size){
			        res = block_size; 
				} else if ((dummy_size - dummy_sent_size) < block_size) {
		    	    res = dummy_size - dummy_sent_size;
				} else {
			        res = 0; 
				}
				if(seqnum > UINT32_MAX){
					res = 0;
				}
				dummy_sent_size += res;
				unsigned char rv;
				for(int i=0; i<res; i++){
					rv = (unsigned char)rand() % 255;
					buff[i] = rv;
					dummy_sum += (unsigned char)rv;
				}	
			}
			cob_len = 0;
			
			if (res > 0) {
				memcpy (params.payload, buff, res);
				params.payload_len = (uint16_t) res;
				params.chunk_num = (uint32_t)seqnum;
				
				if ( (stat_send_bytes + res) == statBuf.st_size ) {
					params.end_chunk_num_f = 1;
					params.end_chunk_num = seqnum;
				}
#ifndef TO_CSMGRD
				cob_len = cef_frame_object_create (cob_buff, &opt, &params);
#else
				cob_len = cef_frame_object_create_for_csmgrd (wbuff, &params);
{
	uint16_t	payload_len;
	uint16_t	header_len;
	uint16_t	pkt_len;
	uint16_t	hdr_len;
	int res;
	CefT_CcnMsg_MsgBdy pm;
	CefT_CcnMsg_OptHdr poh;
	uint16_t index = 0;
	uint16_t value16;
	uint32_t value32;
	uint64_t value64;
	int chunk_field_len = CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum;
	uint16_t value16_namelen;
	struct in_addr node;
	uint64_t nowt = cef_client_present_timeus_get ();

{	
	struct cef_hdr {
		uint8_t 	version;
		uint8_t 	type;
		uint16_t 	pkt_len;
		uint8_t		hoplimit;
		uint8_t		reserve1;
		uint8_t		reserve2;
		uint8_t 	hdr_len;
	} __attribute__((__packed__));
	struct		cef_hdr* chp;
	chp = (struct cef_hdr*) wbuff;
	pkt_len = ntohs (chp->pkt_len);
	hdr_len = chp->hdr_len;
}
	payload_len = pkt_len - hdr_len;
	header_len 	= hdr_len;

	/* Creates Upload Request message 		*/
	/* set header */
	cob_buff[CefC_O_Fix_Ver]  = CefC_Version;
	cob_buff[CefC_O_Fix_Type] = 0x03/*** CefC_Csmgr_Msg_Type_UpReq ***/;
	index += 4 /*** CefC_Csmgr_Msg_HeaderLen ***/;
		
	/* set payload length */
	value16 = htons (params.payload_len);
	memcpy (cob_buff + index, &value16, CefC_S_Length);
	index += CefC_S_Length;
		
	/* set cob message */
	value16 = htons (cob_len);
	memcpy (cob_buff + index, &value16, CefC_S_Length);
	memcpy (cob_buff + index + CefC_S_Length, wbuff, cob_len);
	index += CefC_S_Length + cob_len;
		
	/* set cob name */
		value16_namelen = params.name_len;
		value16 = htons (value16_namelen);
		memcpy (cob_buff + index, &value16, CefC_S_Length);
		memcpy (cob_buff + index + CefC_S_Length, params.name, value16_namelen);
		index += CefC_S_Length + value16_namelen;
		
	/* set chunk num */
	value32 = htonl (params.chunk_num);
	memcpy (cob_buff + index, &value32, CefC_S_ChunkNum);
	index += CefC_S_ChunkNum;
		
	/* set cache time */
	value64 = cef_client_htonb (opt.cachetime*1000);
	memcpy (cob_buff + index, &value64, CefC_S_Cachetime);
	index += CefC_S_Cachetime;
		
	/* set expiry */
	value64 = cef_client_htonb (params.expiry*1000);
	memcpy (cob_buff + index, &value64, CefC_S_Expiry);
	index += CefC_S_Expiry;
	/* get address */
	/* check local face flag */
	node.s_addr = 0;
	/* set address */
	memcpy (cob_buff + index, &node, sizeof (struct in_addr));
	index += sizeof (struct in_addr);
	
	/* set Length */
	value16 = htons (index);
	memcpy (cob_buff + CefC_O_Length, &value16, CefC_S_Length);

	/* ADD MAGIC */
	value16 = htons (index+3);
	memcpy (cob_buff + CefC_O_Length, &value16, CefC_S_Length);
	cob_buff[index]   = 0x63;
	cob_buff[index+1] = 0x6f;
	cob_buff[index+2] = 0x62;
	index += 3;

	cob_len = index;

}
#endif
				//0.8.3
				if ( cob_len < 0 ) {
					printerr ("Content Object frame size over(%d).\n", cob_len*(-1));
					printerr ("       Try shortening the block size specification.\n");
					exit (1);
				}
				
				if (work_buff_idx + cob_len <= CefC_Putfile_Max) {
					memcpy (&work_buff[work_buff_idx], cob_buff, cob_len);
					work_buff_idx += cob_len;
					cob_len = 0;
					
					stat_send_frames++;
					stat_send_bytes += res;
					
					seqnum++;
				} else {
					break;
				}
			} else {
				app_running_f = 0;
				break;
			}
		}
		gettimeofday (&now_t, NULL);
		now_tus = now_t.tv_sec * 1000000llu + now_t.tv_usec;
		
		if (next_tus > now_tus) {
			usleep ((useconds_t)(next_tus - now_tus));
		}
		gettimeofday (&now_t, NULL);
		now_tus2 = now_t.tv_sec * 1000000llu + now_t.tv_usec;
		
		next_tus = now_tus + interval_us + sending_time_us + (next_tus - now_tus2);
		
		if (work_buff_idx > 0) {
#ifndef TO_CSMGRD
			cef_client_message_input (fhdl, work_buff, work_buff_idx);
#else
/*//@@@@@@@@@*/			cef_client_message_input (fhdl, work_buff, work_buff_idx);
#endif
			work_buff_idx = 0;
		} else {
			break;
		}
		
		if (cob_len > 0) {
			memcpy (&work_buff[work_buff_idx], cob_buff, cob_len);
			work_buff_idx += cob_len;
			
			stat_send_frames++;
			stat_send_bytes += res;
			
			seqnum++;
		}
	}
	gettimeofday (&end_t, NULL);
	if (dummy_f == 0) {
		fclose (fp);
	}
	if (work_buff) {
		free (work_buff);
	}

	post_process (stdout);
	exit (0);
}

static void
print_usage (
	FILE* ofp
) {
	
	fprintf (ofp, "\nUsage: cefputfile\n");
	fprintf (ofp, "  cefputfile uri -f path [-r rate] [-b block_size] [-e expiry] "
						  "[-t cache_time] [-v valid_algo] [-d config_file_dir] [-p port_num] \n\n");
	fprintf (ofp, "  uri              Specify the URI.\n");
	fprintf (ofp, "  path             Specify the file path of output. \n");
	fprintf (ofp, "  rate             Transfer rate to cefnetd (Mbps)\n");
	fprintf (ofp, "  block_size       Specifies the max payload length (bytes) of the Content Object.\n");
	fprintf (ofp, "  expiry           Specifies the lifetime (seconds) of the Content Object.\n");
	fprintf (ofp, "  cache_time       Specifies the period (seconds) after which Content Objects are cached before they are deleted.\n");
	fprintf (ofp, "  valid_algo       Specify the validation algorithm (" CefC_ValidTypeStr_CRC32C " or " CefC_ValidTypeStr_RSA256 ")\n");
	fprintf (ofp, "  config_file_dir  Configure file directory\n");
	fprintf (ofp, "  port_num         Port Number\n\n");
}

static void
post_process (
    FILE* ofp
) {
	uint64_t diff_t;
	double diff_t_dbl = 0.0;
	double thrpt = 0.0;
	uint64_t send_bits;
	struct timeval diff_tval;
	
	if (stat_send_frames) {
		timersub( &end_t, &start_t, &diff_tval );
		diff_t = diff_tval.tv_sec * 1000000llu + diff_tval.tv_usec;
	} else {
		diff_t = 0;
	}
	usleep (1000000);
	cef_client_close (fhdl);
	fprintf (ofp, "[cefputfile] Unconnect to cefnetd ... OK\n");
	
	fprintf (ofp, "[cefputfile] Terminate\n");
	fprintf (ofp, "[cefputfile] Tx Frames  = "FMTU64"\n", stat_send_frames);
	fprintf (ofp, "[cefputfile] Tx Bytes   = "FMTU64"\n", stat_send_bytes);
	if (diff_t > 0) {
		diff_t_dbl = (double)diff_t / 1000000.0;
		fprintf (ofp, "[cefputfile] Duration   = %.3f sec\n", diff_t_dbl + 0.0009);
		send_bits = stat_send_bytes * 8;
		thrpt = (double)(send_bits) / diff_t_dbl;
#ifndef TO_CSMGRD
//		fprintf (ofp, "[cefputfile] Throughput = %d bps\n", (int)thrpt);
		fprintf (ofp, "[cefputfile] Throughput = %lu bps\n", (unsigned long)thrpt);
#else
		fprintf (ofp, "[cefputfile] Throughput = %lu bps\n", (unsigned long)thrpt);
#endif
	} else {
		fprintf (ofp, "[cefputfile] Duration   = 0.000 sec\n");
	}
if(dummy_f == 1){
		fprintf (ofp, "[cefputfile] Dummy Sum  = %u\n", dummy_sum);
}
	
	exit (0);
}

static void
sigcatch (
	int sig
) {
	if (sig == SIGINT) {
		printf ("[cefputfile] Catch the signal\n");
		app_running_f = 0;
	}
}

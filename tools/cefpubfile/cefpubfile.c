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
 * cefpubfile.c
 */
 

#define __CEF_PUBFILE_SOURECE__

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
#define CefC_Max_Str_Len		1024			/* MAX length of string */
#define CefC_Putfile_Max 		512000			/* Max file fize */
#define CefC_RateMbps_Max		100000000.0
#define CefC_RateMbps_Min		0.001
#define CefC_TI_Retry_Max		65535
#define CefC_Lifetime_Max		64000			/* 64sec */
#define CefC_Lifetime_Min		1000			/* 1sec */
#define CefC_Def_Lifetime		3000			/* 3sec */
#define CefC_Resend_AdjustTime	1000			/* 1sec */
#define CefC_Def_CacheTime		10				/* 10sec */
#define CefC_Def_Exipiry		10				/* 10sec */
#define CefC_Def_Rate			50.0			/* 50Mbps */
#define CefC_Def_BlockSize		1024			/* 1024Byte */

#define USAGE					print_usage(CefFp_Usage)
#define printerr(...)			fprintf(stderr,"[cefpubfile] ERROR: " __VA_ARGS__)

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/
typedef enum {
	CefC_SRC_STA_IN_PROC = 0,	/* source status flag: in progress */
	CefC_SRC_STA_COMPLETE		/* source status flag: completed */
} TI_Status;

/****************************************************************************************
 State Variables
 ****************************************************************************************/
static int app_running_f = 0;
CefT_Client_Handle fhdl;

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/
int
generate_rnp_by_rand (
	unsigned char* rnp,	/* Pointer of buffer to set generated RNP */
	int seed_f,
	int seed
);
int
set_rnp_to_name (
	unsigned char* name,	/* Name TLV to add RNP TLV */
	unsigned int name_len,	/* Length of Origin Name TLV*/
	unsigned char* rnp,		/* RNP TLV to set Name TLV */
	unsigned int rnp_len	/* Length of RNP TLV */
);
static void
print_usage (
	FILE* ofp
);
static void
send_reflexive_data (
	CefT_Client_Handle fhdl,			/* client handle */
	FILE* fp,						/* data file pointer */
	CefT_CcnMsg_OptHdr* poh_RD,		/* parameters to Option Header(s) */
	CefT_CcnMsg_MsgBdy* pm_RD,	/* parameters to create the interest */
	int block_size,					/* block size of Cob */
	double rate,					/* send bitrate */
	uint64_t st_size				/* data file size */
);
static void
output_push_data (
	FILE* ofp,				/* File pointer to output */
	FILE* fp_push,			/* File pointer to PUSH data */
	unsigned char* rnp,		/* RNP TLV */
	unsigned int rnp_len,	/* Length of RNP TLV */
	int show_f
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
	int index = 0;
	int i;

	unsigned char buff_tmp[CefC_Max_Str_Len];
	unsigned char*  buff_recv = NULL;
	CefT_CcnMsg_OptHdr  poh;
	CefT_CcnMsg_MsgBdy  pm;
	CefT_CcnMsg_OptHdr poh_RD;
	CefT_CcnMsg_MsgBdy pm_RD;
	CefT_CcnMsg_OptHdr poh_TI;
	CefT_CcnMsg_MsgBdy pm_TI;
	int rnp_len;
	int seed = 0;

	static struct timeval now_t;
	uint64_t now_ms;
	uint64_t now_time;
	uint64_t resend_time;
	int retry_cnt = 0;

	char* work_arg;
	char conf_path[PATH_MAX] = {0};
	int port_num = CefC_Unset_Port;
	long int int_rate;
	char valid_type_TI[CefC_Max_Str_Len];
	char valid_type_RD[CefC_Max_Str_Len];
	char uri[CefC_Max_Str_Len];

	char filename[CefC_Max_Str_Len];
	FILE* fp = NULL;
	struct stat statBuf;

	/***** flags *****/
	int dir_path_f = 0;
	int port_num_f = 0;
	int show_f = 0;
	int retry_limit_f = 0;
	int seed_f = 0;

	/***** flags for Reflexive Data *****/
	int file_f = 0;
	int rate_f = 0;
	int blocks_f = 0;
	int expiry_f = 0;
	int cachet_f = 0;
	int valid_RD_f = 0;

	/***** flags for Trigger Interest *****/
	int uri_f = 0;
	int lifetime_f = 0;
	int nsg_Trg_flag = 0;
	int nsg_Ref_flag = 0;
	int valid_TI_f = 0;
	int from_pub_f = 0;
	int no_resend_f = 0;

	/***** parameters for Reflexive Data *****/
	uint64_t cache_time = CefC_Def_CacheTime;
	uint64_t expiry = CefC_Def_Exipiry;
	double rate = CefC_Def_Rate;
	int block_size = CefC_Def_BlockSize;

	/***** parameters for Trigger Interest *****/
	uint64_t lifetime = CefC_Def_Lifetime;
	int64_t	end_chunk_num = -1;

	

	/*------------------------------------------
	  Checks specified options
	--------------------------------------------*/
	uri[0] = 0;
	valid_type_TI[0] = 0;
	valid_type_RD[0] = 0;

	printf ("[cefpubfile] Start\n");

	/* Inits logging */
	cef_log_init ("cefpubfile", 1);

	/* Obtains options */
	for (i = 1 ; i < argc ; i++) {
		work_arg = argv[i];

		if (work_arg == NULL || work_arg[0] == 0) {
			break;
		}

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

			if (block_size < 1) {
				block_size = 1;
			}
			if (block_size > 65000) {
				block_size = 65000;
			}
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

		} else if (strcmp (work_arg, "-l") == 0) {
			if (lifetime_f) {
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
			lifetime = atoi (work_arg) * 1000;
			if (lifetime > CefC_Lifetime_Max) {
				lifetime = CefC_Lifetime_Max;
			} else if (lifetime < CefC_Lifetime_Min) {
				lifetime = CefC_Lifetime_Min;
			}
			lifetime_f++;
			i++;

		} else if (strcmp (work_arg, "-z") == 0) {
			if ((nsg_Trg_flag == 1) || (nsg_Ref_flag == 1)) {
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
			if (strcmp (work_arg, "both") == 0) {
				nsg_Trg_flag++;
				nsg_Ref_flag++;
			} else if (strcmp (work_arg, "ref") == 0) {
				nsg_Ref_flag++;
			} else if (strcmp (work_arg, "trg") == 0) {
				nsg_Trg_flag++;
			} else {
				printerr("[-z] has the invalid parameter.\n");
				USAGE;
				return (-1);
			}
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

		} else if (strcmp (work_arg, "-v_TI") == 0) {
			if (valid_TI_f) {
				printerr("[-v_TI] is duplicated.\n");
				USAGE;
				return (-1);
			}
			if (i + 1 == argc) {
				printerr("[-v_TI] has no parameter.\n");
				USAGE;
				return (-1);
			}

			work_arg = argv[i + 1];
			strcpy (valid_type_TI, work_arg);
			valid_TI_f++;
			i++;

		} else if (strcmp (work_arg, "-v_RD") == 0) {
			if (valid_RD_f) {
				printerr("[-v_RD] is duplicated.\n");
				USAGE;
				return (-1);
			}
			if (i + 1 == argc) {
				printerr("[-v_RD] has no parameter.\n");
				USAGE;
				return (-1);
			}

			work_arg = argv[i + 1];
			strcpy (valid_type_RD, work_arg);
			valid_RD_f++;
			i++;

		} else if (strcmp (work_arg, "-m") == 0) {
			if (retry_limit_f) {
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
			retry_cnt = atoi (work_arg);
			if (retry_cnt > CefC_TI_Retry_Max) {
				retry_cnt = CefC_TI_Retry_Max;
			}
			retry_limit_f++;
			i++;

#ifdef CefC_Develop
		} else if (strcmp (work_arg, "-o") == 0) {
			if (show_f) {
				printerr("[-o] is duplicated.\n");
				USAGE;
				return (-1);
			}
			show_f++;

		} else if (strcmp (work_arg, "-s") == 0) {
			if (seed_f) {
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
			seed = atoi (work_arg);
			seed_f++;
			i++;

		} else if (strcmp (work_arg, "-no_resend") == 0) {
			if (no_resend_f) {
				printerr("[--no_resend] is duplicated.\n");
				USAGE;
				return (-1);
			}
			no_resend_f++;

#endif // CefC_Develop
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

	/* Checks errors */
	if (uri_f == 0) {
		printerr("uri is not specified.\n");
		USAGE;
		exit (1);
	}

	if (file_f == 0) {
		/* Use the last string in the URL */
		res = strlen (uri);
		if (res >= CefC_Max_Str_Len) {
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

	cef_log_init2 (conf_path, 1/* for CEFNETD */);

#ifdef CefC_Debug
	cef_dbg_init ("cefpubfile", conf_path, 1);
#endif // CefC_Debug

	/* Init Validation Alglithm */
	if ((valid_TI_f == 1) || (valid_RD_f == 1)) {
		cef_valid_init (conf_path);
	}

	printf ("[cefpubfile] Parsing parameters ... OK\n");
	printf ("[cefpubfile] URI         = %s\n", uri);
	printf ("[cefpubfile] File        = %s\n", filename);
	printf ("[cefpubfile] Rate        = %.3f Mbps\n", rate);
	printf ("[cefpubfile] Block Size  = %d Bytes\n", block_size);
	printf ("[cefpubfile] Cache Time  = "FMTU64" sec\n", cache_time);
	printf ("[cefpubfile] Expiration  = "FMTU64" sec\n", expiry);

	/*---------------------------------------------------------------------------
	  Inits the Cefore APIs
	-----------------------------------------------------------------------------*/
	cef_frame_init ();
	res = cef_client_init (port_num, conf_path);
	if (res < 0) {
		printerr("Failed to init the client package.\n");
		exit (1);
	}
	printf ("[cefpubfile] Init Cefore Client package ... OK\n");

	/*---------------------------------------------------------------------------
	  Connects to CEFORE
	-----------------------------------------------------------------------------*/
	fhdl = cef_client_connect ();
	if (fhdl < 1) {
		printerr("cefnetd is not running.\n");
		exit (1);
	}
	printf ("[cefpubfile] Connect to cefnetd ... OK\n");

	/*---------------------------------------------------------------------------
	  Initialize variavles
	-----------------------------------------------------------------------------*/
	app_running_f = 1;
	memset (&poh_RD, 0, sizeof (CefT_CcnMsg_OptHdr));
	memset (&poh_TI, 0, sizeof (CefT_CcnMsg_OptHdr));
	memset (&pm_RD, 0, sizeof (CefT_CcnMsg_MsgBdy));
	memset (&pm_TI, 0, sizeof (CefT_CcnMsg_MsgBdy));

	/*---------------------------------------------------------------------------
	  Sets parameters to Trigger Interest
	-----------------------------------------------------------------------------*/
	pm_TI.hoplimit = 32;
	poh_TI.lifetime_f = 1;
	poh_TI.lifetime = lifetime;

	if (from_pub_f) {
		pm_TI.org.from_pub_f = CefC_T_FROM_PUB;
	}

	/* Set Validation Alglithm */
	if (valid_TI_f) {
		pm_TI.alg.valid_type = (uint16_t) cef_valid_type_get (valid_type_TI);

		if (pm_TI.alg.valid_type == CefC_T_ALG_INVALID) {
			printerr("-v_TI has the invalid parameter %s\n", valid_type_TI);
			exit (1);
		}
	}

	/* Set chunk_num */
	pm_TI.chunk_num_f = 0;

	if (nsg_Trg_flag == 1) {
		Cef_Int_Symbolic(pm_TI);
	} else {
		Cef_Int_Regular(pm_TI);
	}

	if (nsg_Ref_flag == 1) {
		pm_TI.org.reflexive_smi_f = 1;
	}

	/* Creates the name from URI and RNP */
	res = cef_frame_conversion_uri_to_name (uri, pm_TI.name);
	if (res < 0) {
		printerr("Invalid URI is specified.\n");
		exit (1);
	}

	/* Set Name adding RNP */
	memset (buff_tmp, 0, CefC_Max_Str_Len);
	rnp_len = generate_rnp_by_rand (buff_tmp, seed_f, seed);
	res = set_rnp_to_name (pm_TI.name, res, buff_tmp, rnp_len);
	if (res < 0) {
		printerr("Invalid URI is specified.\n");
		exit (1);
	}
	pm_TI.name_len = res;

	/*---------------------------------------------------------------------------
	  Sets parameters to Reflexive Data 
	-----------------------------------------------------------------------------*/

	/* Set RNP to Name */
	res = cef_frame_conversion_name_to_reflexivename (pm_TI.name, pm_TI.name_len, pm_RD.name, 0, -1);
	if (res <= 0) {
		printerr("Mistake to convert name to reflexivename.\n");
		exit (1);
	}
	pm_RD.name_len = res;

	/* Set chunk_num */
	pm_RD.chunk_num_f = 1;

	/* Set Validation Alglithm */
	if (valid_RD_f == 1) {
		pm_RD.alg.valid_type = (uint16_t) cef_valid_type_get (valid_type_RD);
		if (pm_RD.alg.valid_type == CefC_T_ALG_INVALID) {
			printerr("-v_RD has the invalid parameter %s\n", valid_type_RD);
			exit (1);
		}
	}

	poh_RD.cachetime_f = 1;

	/*---------------------------------------------------------------------------
	  Checks the input file
	-----------------------------------------------------------------------------*/

	if (stat(filename, &statBuf) != 0) {
		printerr("the specified input file stat can not get.\n");
		exit (1);
	}
	fp = fopen (filename, "rb");
	if (fp == NULL) {
		printerr("the specified input file can not be opened.\n");
		exit (1);
	}
	printf ("[cefpubfile] Checking the input file ... OK\n");

	/* Output PUSH data and RNP */
	output_push_data (stdout, fp, pm_RD.name, pm_RD.name_len, show_f);

	/*---------------------------------------------------------------------------
	  Send Reflexive Data for localcache
	-----------------------------------------------------------------------------*/
	/* Set Expiry Time and RCT */
	gettimeofday (&now_t, NULL);
	now_ms = now_t.tv_sec * 1000llu + now_t.tv_usec / 1000llu;
	if (expiry) {
		pm_RD.expiry = now_ms + expiry * 1000;
	} else {
		pm_RD.expiry = now_ms + 3600000;
	}
	poh_RD.cachetime = now_ms + cache_time * 1000;

	/* Send Reflexive Data */
	send_reflexive_data (fhdl, fp, &poh_RD, &pm_RD, block_size, rate, statBuf.st_size);
	printf ("[cefpubfile] Upload push data to cefnetd ... OK\n");

	/*---------------------------------------------------------------------------
	  Sends Trigger Interest
	-----------------------------------------------------------------------------*/
	if(app_running_f > 0) {
		printf ("[cefpubfile] Send Trigger Interest.\n");
		cef_client_interest_input (fhdl, &poh_TI, &pm_TI);
	}

	/* set chunk_num for Resending Trigger Interest */
	if (nsg_Trg_flag != 1) {
		pm_TI.chunk_num_f = 1;
		pm_TI.chunk_num = 0;
	}

	/*---------------------------------------------------------------------------
	  Main loop (wait to Recv Symbolic Reflexive Interest)
	-----------------------------------------------------------------------------*/
	gettimeofday (&now_t, NULL);
	now_time = cef_client_covert_timeval_to_us (now_t);
	resend_time = now_time + lifetime * 1000 - CefC_Resend_AdjustTime * 1000;
	buff_recv = (unsigned char*) malloc (sizeof (unsigned char) * CefC_AppBuff_Size);
	memset (buff_recv, 0, sizeof (unsigned char) * CefC_AppBuff_Size);

	while (app_running_f) {
		if (SIG_ERR == signal (SIGINT, sigcatch)) {
			break;
		}

		/* Check timeout */
		gettimeofday (&now_t, NULL);
		now_time = cef_client_covert_timeval_to_us (now_t);

		/* Resend Trigger Interest */
		if (now_time > resend_time) {
			if ((retry_limit_f == 0) || (retry_cnt > 0)) {
				printf ("[cefpubfile] Resend Trigger Interest.\n");

				/* Update chunk_num of Trigger Interest*/
				if (nsg_Trg_flag != 1) {
					if (end_chunk_num > pm_TI.chunk_num) {
						pm_TI.chunk_num++;
					} else {
						pm_TI.chunk_num = 0;
					}
				}

				if (!no_resend_f) {
					cef_client_interest_input (fhdl, &poh_TI, &pm_TI);
				}

				retry_cnt--;
				resend_time = now_time + lifetime * 1000 - CefC_Resend_AdjustTime * 1000;

			} else {
				printerr ("Timeout. (the number of Trigger Interest retransmission has reached its limit.)\n");
				app_running_f = 0;
				break;
			}
		}

		/* Reads the message from cefnetd */
		res = cef_client_read_core (fhdl, &buff_recv[index], CefC_AppBuff_Size - index, 300);

		if (res > 0) {

			res += index;

			/* Incomming message process */
			do {
				unsigned char msg_buff[CefC_Max_Msg_Size] = {0};
				int msg_len = 0, hdr_len = 0, msg_type = -1, frame_type = -1;
				int ref_type = 0;
				struct fixed_hdr* fix_hdr;

				/* Get frame type of msg */
				i = 0;
				if ((buff_recv[index] != CefC_Version) ||
						(buff_recv[index + 1] > CefC_PT_MAX)) {
					while (i < res) {
						if ((buff_recv[index +i] != CefC_Version) ||
								(buff_recv[index + i + 1] != CefC_PT_OBJECT)) {
							i += 2;
						} else {
							break;
						}
					}
				}
				if ((i < res) && ((res - i) >= 8)) {
					fix_hdr = (struct fixed_hdr*)(&buff_recv[index + i]);
					frame_type = fix_hdr->type;
					hdr_len = fix_hdr->hdr_len;
				} else {
					break;
				}


				/* Parse msg */
				res = cef_client_rawdata_get(&buff_recv[index], res, msg_buff, &msg_len, &msg_type);
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Finest, "msg_len=%d, hdr_len=%d, msg_type=%d\n", msg_len, hdr_len, msg_type);
#endif // CefC_Debug

				memset(&pm, 0x00, sizeof(pm));
				memset(&poh, 0x00, sizeof(poh));
				cef_frame_message_parse (msg_buff, msg_len - hdr_len, hdr_len, &poh, &pm, msg_type);

				/* Check reflexive type (Trigger or Reflexive) */
				if (pm.rnp_pos == 0) {
					ref_type = CefC_Reflexive_Msg;
				} else if (pm.rnp_pos > 0) {
					ref_type = CefC_Trigger_Msg;
				}

				/* Processing based on msg type of reflexive forwarding */
				if ( (frame_type == CefC_PT_INTEREST) && (ref_type == CefC_Reflexive_Msg)) {
#ifdef CefC_Debug
					cef_dbg_write (CefC_Dbg_Finest,"[cefpubfile] Receive Reflexive Interest.\n");
#endif // CefC_Debug

					/* Check if this Interest is SMI */
					if (pm.org.symbolic_f != 1) {
						continue;
					}

					/* Check if this Interest is cleanup SMI of FastRecovery */
					if (poh.lifetime == 0) {
						continue;
					}

					/* Check whether own and recv RNPs are same */
					if ( !( pm_RD.name_len == pm.name_len
								&&  memcmp (&pm_RD.name[0], &pm.name[0], pm_RD.name_len) == 0 ) ) {
						continue;
					}

					/* Send Reflexive Data */
					pm_RD.expiry = 0;
					poh_RD.cachetime = 0;
					send_reflexive_data (fhdl, fp, &poh_RD, &pm_RD, block_size, rate,statBuf.st_size);

				} else if ( (frame_type == CefC_PT_OBJECT) && (ref_type == CefC_Trigger_Msg)) {

					/* Check whether own and recv Names are same */
					int org_name_len = pm_TI.name_len;
					int rcv_name_len = pm.name_len;
					if (pm.chunk_num_f) {
						rcv_name_len -= (CefC_S_TLF + CefC_S_ChunkNum);
					}
					if ( !( org_name_len == rcv_name_len)
								&& ( memcmp (pm_TI.name, pm.name, org_name_len) == 0 ) ) {
						continue;
					}

					if ( pm.chunk_num_f <= 0) {
						printf("[cefpubfile] Receive Trigger Data, finish application.\n");
						app_running_f = 0;
						break;
					} else {
						end_chunk_num = pm.end_chunk_num;
#ifdef CefC_Debug
						cef_dbg_write (CefC_Dbg_Finest,"[cefpubfile] Receive Trigger Data with chunk (Chunk="FMT64", EndChunkNum="FMT64").\n",
								(int64_t)pm.chunk_num, (int64_t)pm.end_chunk_num);
#endif // CefC_Debug
					}
				}
			} while (res > 0);

			if (res > 0) {
				index = res;
			} else {
				index = 0;
			}
		}
	}

	/* Close output file  */
	fclose (fp);

	/* Free the buffer */
	free (buff_recv);

	/* Disconnects to CEFORE */
	cef_client_close (fhdl);

	exit (0);
#else // REFLEXIVE_FORWARDING
	printf ("PUSH function has been disabled.\n");
#endif // REFLEXIVE_FORWARDING
}

#ifdef REFLEXIVE_FORWARDING
static void
print_usage (
	FILE* ofp
) {
	fprintf (ofp, "\nUsage: cefpubfile\n");
	fprintf (ofp, "  cefpubfile uri -f path [-r rate] [-b block_size] [-e expiry] [-t cache_time] "
		"[-l lifetime] [-m retry_limit] [-z target] [-v_TI valid_algo] [-v_RD valid_algo] "
		"[-d config_file_dir] [-p port_num] ");
	fprintf (ofp, "\n\n");

	fprintf (ofp, "  uri                  Specify the URI.\n");
	fprintf (ofp, "  -f path              Specify the file path of output. \n");
	fprintf (ofp, "  -r rate              Transfer rate to cefnetd (Mbps)\n");
	fprintf (ofp, "  -b block_size        Specifies the max payload length (bytes) of the Content Object.\n");
	fprintf (ofp, "  -e expiry            Specifies the lifetime (seconds) of the Content Object.\n");
	fprintf (ofp, "  -t cache_time        Specifies the period (seconds) after which Content Objects are cached before they are deleted.\n");
	fprintf (ofp, "  -l lifetime          Specify the Lifetime of Trigger Interest\n");
	fprintf (ofp, "  -m retry_limit       Specify the retry limit of Trigger Interest\n");
	fprintf (ofp, "  -z target            Use Long Life Interest for Trigger Interest or/and Reflexive Interest ( trg | ref | both )\n");
	fprintf (ofp, "  -v_TI valid_algo     Specify the validation algorithm for Trigger Interest (" CefC_ValidTypeStr_CRC32C " | " CefC_ValidTypeStr_RSA256 ")\n");
	fprintf (ofp, "  -v_RD valid_algo     Specify the validation algorithm for Reflexive Data (" CefC_ValidTypeStr_CRC32C " | " CefC_ValidTypeStr_RSA256 ")\n");
	fprintf (ofp, "  -d config_file_dir   Configure file directory\n");
	fprintf (ofp, "  -p port_num          Port Number\n");
	fprintf (ofp, "\n");
}

int
generate_rnp_by_rand (
	unsigned char* rnp,	/* Pointer of buffer to set generated RNP */
	int seed_f,
	int seed
) {
	int rnp_len;
	int rand_val;
	static struct timeval now_t;

	if (seed_f != 1) {
		gettimeofday (&now_t, NULL);
		seed = cef_client_covert_timeval_to_us (now_t);
	}

	srand(seed);
	for (rnp_len = 0; rnp_len < CefC_RNP_Len; rnp_len++) {
		rand_val = 0 + rand() % 256;
		rnp[rnp_len] = (char)rand_val;
	}

	return rnp_len;
}

int
set_rnp_to_name (
	unsigned char* name,		/* Name TLV to add RNP TLV */
	unsigned int name_len,		/* Length of Origin Name TLV*/
	unsigned char* rnp,		/* RNP TLV to set Name TLV */
	unsigned int rnp_len		/* Length of RNP TLV */
) {
	int x = 0;
	struct tlv_hdr* tlv_hdr;
	uint16_t sub_type;
	uint16_t sub_len;
	uint16_t rnp_t_n;
	uint16_t rnp_len_n;

	/* Check default name */
	if ((name_len == 0) || (name_len == 4)) {
		printerr("Default name is invalid.\n");
		return (x);
	}

	/* Check if sub-TLV of input name is T_NAMESEGMENT only */
	while (x < name_len) {
		tlv_hdr = (struct tlv_hdr*) &name[x];
		sub_type = ntohs (tlv_hdr->type);
		sub_len = ntohs (tlv_hdr->length);

		if ( sub_type != CefC_T_NAMESEGMENT ) {
			printerr("Input Name is invalid.\n");
			return (-1);
		}

		x += CefC_S_TLF + sub_len;
	}

	/* Add RNP TLV to NAME TLV */
	rnp_t_n = htons (CefC_T_REFLEXIVE_NAME);
	rnp_len_n = htons (rnp_len);

	memcpy (&name[x], &rnp_t_n, CefC_S_Type);
	x += CefC_S_Type;
	memcpy (&name[x], &rnp_len_n, CefC_S_Length);
	x += CefC_S_Length;
	memcpy (&name[x], rnp, rnp_len);
	x += rnp_len;

	return (x);
}

static void
output_push_data (
	FILE* ofp,				/* File pointer to output */
	FILE* fp_push,			/* File pointer to PUSH data */
	unsigned char* rnp,		/* RNP TLV */
	unsigned int rnp_len,	/* Length of RNP TLV */
	int show_f
) {
	int i;
	rewind (fp_push); 

	/* Output received payload of each rxwindow to stdout */
	fprintf (ofp,"[RNP=0x");
	for (i = CefC_S_TLF; i < rnp_len; i++) {
		fprintf (ofp,"%02x", rnp[i]);
	}
	fprintf (ofp,"]\n");

	if (show_f) {
		while (1) {
			char buff[CefC_Max_Length];
			size_t read_count = fread(buff, sizeof (unsigned char), CefC_Max_Length, fp_push);
			fwrite (buff, sizeof (unsigned char), read_count, ofp);
			if (read_count < CefC_Max_Length) {
				break;
			}
		}

		fprintf (ofp, "\n");

	}

	return;
}

static void
send_reflexive_data (
	CefT_Client_Handle fhdl,		/* client handle */
	FILE* fp,						/* data file pointer */
	CefT_CcnMsg_OptHdr* poh_RD,		/* parameters to Option Header(s) */
	CefT_CcnMsg_MsgBdy* pm_RD,		/* parameters to create the interest */
	int block_size,					/* block size of Cob */
	double rate,					/* send bitrate */
	uint64_t st_size				/* data file size */
) {
	int res;
	uint32_t work_buff_idx = 0;
	int cob_len;
	uint64_t seqnum = 0;
	uint64_t stat_send_bytes = 0;
	static struct timeval now_t;
	uint64_t next_tus;
	uint64_t now_tus;
	uint64_t now_tus2;
	unsigned char* work_buff = NULL;
	unsigned char buff[CefC_Max_Length];
	unsigned char cob_buff[CefC_Max_Length*2];

	double interval;
	long interval_us;

	/* initialize parameter */
	pm_RD->end_chunk_num_f = 0;
	pm_RD->end_chunk_num   = -1;
	work_buff = (unsigned char*) malloc (sizeof (unsigned char) * CefC_Putfile_Max);   
	rewind (fp); 

	/* Calculates the interval */
	interval = (rate * 1000000.0) / (double)(block_size * 8);
	interval_us = (long)((1.0 / interval) * 1000000.0);

	gettimeofday (&now_t, NULL);
	next_tus = cef_client_covert_timeval_to_us(now_t) + interval_us;

	while (app_running_f) {
		if (SIG_ERR == signal (SIGINT, sigcatch)) {
			break;
		}
		cob_len = 0;

		/* Calculate and set the EndChunkNumber */
		pm_RD->end_chunk_num_f = 1;
		pm_RD->end_chunk_num = (uint32_t)(st_size / block_size);
		if ((st_size % block_size) == 0) {
			pm_RD->end_chunk_num--;
		}

		/* Create a CoB */
		while (work_buff_idx < 1) {
			/* Read 1 block of data from file  */
			res = fread (buff, sizeof (unsigned char), block_size, fp);
			if(seqnum > UINT32_MAX){
				res = 0;
			}
			cob_len = 0;

			if (res > 0) {
				/* set payload and chunk_num to frame  */
				memcpy (pm_RD->payload, buff, res);
				pm_RD->payload_len = (uint16_t) res;
				pm_RD->chunk_num = (uint32_t) seqnum;

				/* Create CoB from set params */
				cob_len = cef_frame_object_create (cob_buff, poh_RD, pm_RD);

				if ( cob_len < 0 ) {
					printerr ("Content Object frame size over(%d).\n", cob_len*(-1));
					printerr ("       Try shortening the block size specification.\n");
					app_running_f = 0;
					work_buff_idx = -1;
					break;
				}

				if (work_buff_idx + cob_len <= CefC_Putfile_Max) {
					memcpy (&work_buff[work_buff_idx], cob_buff, cob_len);
					work_buff_idx += cob_len;
					cob_len = 0;

					stat_send_bytes += res;

					seqnum++;
				} else {
					printerr ("Total Content Object size over(%d).\n", CefC_Putfile_Max);
					app_running_f = 0;
					break;
				}
			} else {
				break;
			}
		}

		/* Get now time and wait until next time */
		gettimeofday (&now_t, NULL);
		now_tus = cef_client_covert_timeval_to_us(now_t);

		if (next_tus > now_tus) {
			usleep ((useconds_t)(next_tus - now_tus));
		}

		/* Set next time */
		gettimeofday (&now_t, NULL);
		now_tus2 = cef_client_covert_timeval_to_us(now_t);
		next_tus = now_tus + interval_us + (next_tus - now_tus2);

		/* Input Cob to cefnetd */
		if (work_buff_idx > 0) {
			cef_client_message_input (fhdl, work_buff, work_buff_idx);
			work_buff_idx = 0;
		} else {
			break;
		}

		if (cob_len > 0) {
			memcpy (&work_buff[work_buff_idx], cob_buff, cob_len);
			work_buff_idx += cob_len;
			stat_send_bytes += res;
			seqnum++;
		}
	}

	free (work_buff);

	return;
}

static void
sigcatch (
	int sig
) {
	if (sig == SIGINT) {
		printf ("[cefpubfile] Catch the signal\n");
		app_running_f = 0;
	}
}
#endif // REFLEXIVE_FORWARDING

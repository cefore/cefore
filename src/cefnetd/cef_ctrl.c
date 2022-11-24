/*
 * Copyright (c) 2016-2021, National Institute of Information and Communications
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
 * cef_ctrl.c
 */

#define __CEF_CTRL_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>

#include "cef_netd.h"
#include "version.h"
#include <cefore/cef_define.h>
#include <cefore/cef_frame.h>
#include <cefore/cef_client.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

#define CefC_Arg_Kill				"kill"
#define CefC_Arg_Status				"status"
#define CefC_Arg_Route				"route"
#define CefC_Arg_Route_Ope_Add		"add"
#define CefC_Arg_Route_Ope_Del		"del"
#define CefC_Arg_Route_Ope_Enable	"enable"
#define CefC_Arg_Route_Pro_TCP		"tcp"
#define CefC_Arg_Route_Pro_UDP		"udp"
#ifdef CefC_Ser_Log
#define CefC_Arg_Ser_Log			"serlog"
#endif // CefC_Ser_Log
#ifndef CefC_Nwproc
#define CefC_StatusRspWait			200000		/* usec */
#else // CefC_Nwproc
#define CefC_StatusRspWait			2000000
#endif // CefC_Nwproc

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/


/****************************************************************************************
 State Variables
 ****************************************************************************************/


/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/
static int
cef_ctrl_create_route_msg (
	unsigned char* buff,
	int argc,
	char** argv, 
	char* user_name
);


/****************************************************************************************
 ****************************************************************************************/
int main (
	int argc,
	char** argv
) {
	CefT_Client_Handle fhdl;
	unsigned char buff[1024];
	int len;
	int res;
	int i;
	int dir_path_f 		= 0;
	int port_num_f 		= 0;
	int pit_f			= 0;
	uint16_t output_opt_f = 0;
	char*	work_arg;
	char 	file_path[PATH_MAX] = {0};
	int 	port_num = CefC_Unset_Port;
	unsigned char rsp_msg[CefC_Max_Length];
	
	char*	wp;
	char launched_user_name[CefC_Ctrl_User_Len];
	
	/* Inits logging 		*/
	cef_log_init ("cefctrl", 1);
	
	if (argc < 2) {
		cef_log_write (CefC_Log_Error, "Parameters are not specified.\n");
		exit (1);
	}
	if (argc > 10) {
		cef_log_write (CefC_Log_Error, "Parameters are too many.\n");
		exit (1);
	}
	
	/* Obtains options 		*/
	for (i = 1 ; i < argc ; i++) {
		
		work_arg = argv[i];
		if (work_arg == NULL || work_arg[0] == 0) {
			break;
		}
		
		if (strcmp (work_arg, "-d") == 0) {
			if (i + 1 == argc) {
				cef_log_write (CefC_Log_Error, "[-d] has no parameter.\n");
				exit (1);
			}
			//202108
			if ( strlen(argv[i + 1]) >= PATH_MAX) {
				cef_log_write (CefC_Log_Error, "[-d] parameter is too long.\n");
				exit (1);
			}
			
			strcpy (file_path, argv[i + 1]);
			dir_path_f++;
			i++;
		} else if (strcmp (work_arg, "--pit") == 0) {
			if (strcmp (argv[1], CefC_Arg_Status) == 0) {
				pit_f++;
				i++;
			} else {
				cef_log_write (CefC_Log_Error, "[--pit] has no parameter.\n");
				exit (1);
			}
		} else if (strcmp (work_arg, "-s") == 0) {
			if (strcmp (argv[1], CefC_Arg_Status) == 0) {
				output_opt_f |= CefC_Ctrl_StatusOpt_Stat;
			} else {
				cef_log_write (CefC_Log_Error, "[-s] has no parameter.\n");
				exit (1);
			}
		} else if (strcmp (work_arg, "-m") == 0) {			//Secret option
			if (strcmp (argv[1], CefC_Arg_Status) == 0) {
				output_opt_f |= CefC_Ctrl_StatusOpt_Metric;
			} else {
				cef_log_write (CefC_Log_Error, "[-m] has no parameter.\n");
				exit (1);
			}
#if ((defined CefC_CefnetdCache) && (defined CefC_Develop))
		} else if (strcmp (work_arg, "-lc") == 0) {			//Secret option
			if (strcmp (argv[1], CefC_Arg_Status) == 0) {
				output_opt_f |= CefC_Ctrl_StatusOpt_LCache;
			} else {
				cef_log_write (CefC_Log_Error, "[-lc] has no parameter.\n");
				exit (1);
			}
#endif //((defined CefC_CefnetdCache) && (defined CefC_Develop))
		} else if (strcmp (work_arg, "-p") == 0) {
			if (i + 1 == argc) {
				cef_log_write (CefC_Log_Error, "[-p] has no parameter.\n");
				exit (1);
			}
			port_num = atoi (argv[i + 1]);
			port_num_f++;
			i++;
		} else if ( (strcmp (work_arg, "-v") == 0) || 
					(strcmp (work_arg, "--version") == 0)) {
			
			fprintf (stdout, "%s\n", CEFORE_VERSION);
			exit (1);
		} else {
			if (work_arg[0] == '-') {
				cef_log_write (CefC_Log_Error, "unknown option is specified.\n");
				exit (1);
			}
		}
	}
	
	if (dir_path_f > 1) {
		cef_log_write (CefC_Log_Error, "[-d] is specified more than once\n");
		exit (1);
	}
	if (port_num_f > 1) {
		cef_log_write (CefC_Log_Error, "[-p] is specified more than once\n");
		exit (1);
	}
	cef_log_init2 (file_path, 1 /* for CEFNETD */);
#ifdef CefC_Debug
	cef_dbg_init ("cefctrl", file_path, 1);
	cef_dbg_write (CefC_Dbg_Fine, "operation is %s\n", argv[1]);
#endif // CefC_Debug
	
	res = cef_client_init (port_num, file_path);
	if (res < 0) {
		cef_log_write (CefC_Log_Error, "Failed to init client package.\n");
		exit (1);
	}
	
	fhdl = cef_client_connect ();
	if (fhdl < 1) {
		cef_log_write (CefC_Log_Error, "Failed to connect to cefnetd.\n");
		exit (1);
	}
	
	/* Records the user which launched cefnetd 		*/
	wp = getenv ("USER");
	if (wp == NULL) {
		cef_log_write (CefC_Log_Error, 
			"Failed to obtain $USER launched cefctrl\n");
		exit (1);
	}
	memset (launched_user_name, 0, CefC_Ctrl_User_Len);
	strcpy (launched_user_name, wp);
	
	if (strcmp (argv[1], CefC_Arg_Kill) == 0) {
		sprintf ((char*) buff, "%s%s", CefC_Ctrl, CefC_Ctrl_Kill);
		memcpy (&buff[CefC_Ctrl_Len + CefC_Ctrl_Kill_Len], 
						launched_user_name, CefC_Ctrl_User_Len);
		cef_client_message_input (fhdl, buff, 
			CefC_Ctrl_Len + CefC_Ctrl_Kill_Len + CefC_Ctrl_User_Len);
	} else if (pit_f && strcmp (argv[1], CefC_Arg_Status) == 0) {
		sprintf ((char*) buff, "%s%s", CefC_Ctrl, CefC_Ctrl_StatusPit);
		memcpy (&buff[CefC_Ctrl_Len + CefC_Ctrl_StatusPit_Len], 
						launched_user_name, CefC_Ctrl_User_Len);
		cef_client_message_input (fhdl, buff, 
			CefC_Ctrl_Len + CefC_Ctrl_StatusPit_Len + CefC_Ctrl_User_Len);
	} else if (strcmp (argv[1], CefC_Arg_Status) == 0) {
		if (output_opt_f) {
			sprintf ((char*) buff, "%s%s", CefC_Ctrl, CefC_Ctrl_StatusStat);
			memcpy (&buff[CefC_Ctrl_Len + CefC_Ctrl_StatusStat_Len], 
						&output_opt_f, sizeof (uint16_t));
			memcpy (&buff[CefC_Ctrl_Len + CefC_Ctrl_StatusStat_Len + sizeof (uint16_t)], 
						launched_user_name, CefC_Ctrl_User_Len);
			cef_client_message_input (fhdl, buff, 
				CefC_Ctrl_Len + CefC_Ctrl_StatusStat_Len + sizeof (uint16_t) + CefC_Ctrl_User_Len);
		} else {
			sprintf ((char*) buff, "%s%s", CefC_Ctrl, CefC_Ctrl_Status);
			memcpy (&buff[CefC_Ctrl_Len + CefC_Ctrl_Status_Len], 
						launched_user_name, CefC_Ctrl_User_Len);
			cef_client_message_input (fhdl, buff, 
				CefC_Ctrl_Len + CefC_Ctrl_Status_Len + CefC_Ctrl_User_Len);
		}
		
		usleep (CefC_StatusRspWait);
		int ff = 1;
		int resped = 0;

		while (1) {
			if (ff == 1) {
				ff = 0;

//				for (int i=0; i < 30000000/CefC_StatusRspWait; i++) {
				for (int i=0; i < 1200000000/CefC_StatusRspWait; i++) {	//600sec
					res = cef_client_read (fhdl, rsp_msg, CefC_Max_Length);
					if (res > 0){
						break;
					}
					usleep (CefC_StatusRspWait);
				}
			} else {
				res = cef_client_read (fhdl, rsp_msg, CefC_Max_Length);
			}
			if (res > 0) {
				resped = 1;
				rsp_msg[res] = 0x00;
				fprintf (stdout, "%s", (char*) rsp_msg);
			} else {
				if (resped == 0){
					cef_log_write (CefC_Log_Error
						, "cefnetd does not send responce.\n");
				}
				break;
			}
		}
	} else if (strcmp (argv[1], CefC_Arg_Route) == 0) {
		sprintf ((char*) buff, "%s%s", CefC_Ctrl, CefC_Ctrl_Route);
		len = cef_ctrl_create_route_msg (
			buff + CefC_Ctrl_Len + CefC_Ctrl_Route_Len, 
				argc - (dir_path_f * 2 + port_num_f * 2), argv, launched_user_name);
		if (len > 0) {
			cef_client_message_input (
				fhdl, buff, 
				CefC_Ctrl_Len + CefC_Ctrl_Route_Len + len);
		}
#ifdef CefC_Ser_Log
	} else if (strcmp (argv[1], CefC_Arg_Ser_Log) == 0) {
		sprintf ((char*) buff, "%s%s", CefC_Ctrl, CefC_Ctrl_Ser_Log);
		memcpy (&buff[CefC_Ctrl_Len + CefC_Ctrl_Ser_Log_Len], 
						launched_user_name, CefC_Ctrl_User_Len);
		cef_client_message_input (fhdl, buff, 
			CefC_Ctrl_Len + CefC_Ctrl_Ser_Log_Len + CefC_Ctrl_User_Len);
#endif // CefC_Ser_Log
	}
	usleep (100000);
	cef_client_close (fhdl);

	exit (0);
}

static int
cef_ctrl_create_route_msg (
	unsigned char* buff,
	int argc,
	char** argv, 
	char* user_name
) {
	uint8_t host_len;
	uint8_t op;
	uint8_t prot;
	int index = 0;
	uint16_t uri_len;
	int i;
	
	/* check the number of parameters 		*/
	if (argc > 37) {
		cef_log_write (CefC_Log_Error, "Invalid parameter(s) is(are) specified.\n");
		return (-1);
	}
	if (argc < 6) {
		cef_log_write (CefC_Log_Error, 
			"Required parameter(s) is(are) not specified.\n");
		return (-1);
	}
	
	/* check operation */
	if (strcmp (argv[2], CefC_Arg_Route_Ope_Add) == 0) {
		/* operation is add route */
		op = CefC_Fib_Route_Ope_Add;
	} else if (strcmp (argv[2], CefC_Arg_Route_Ope_Del) == 0) {
		/* operation is delete route */
		op = CefC_Fib_Route_Ope_Del;
	} else if (strcmp (argv[2], CefC_Arg_Route_Ope_Enable) == 0) {
		/* operation is delete route */
		op = CefC_Fib_Route_Ope_Add;
	} else {
		cef_log_write (CefC_Log_Error, 
			"Option that is neither add nor del for cefroute is specified.\n");
		return (-1);
	}
	
	/* check protocol */
	if (strcmp (argv[4], CefC_Arg_Route_Pro_TCP) == 0) {
		prot = CefC_Fib_Route_Pro_TCP;
	} else if (strcmp (argv[4], CefC_Arg_Route_Pro_UDP) == 0) {
		/* protocol is UDP */
		prot = CefC_Fib_Route_Pro_UDP;
	} else {
		cef_log_write (CefC_Log_Error, 
			"Protocol that is neither udp nor tcp for cefroute is specified.\n");
		return (-1);
	}
	
	/* set user name 	*/
	memcpy (buff + index, user_name, CefC_Ctrl_User_Len);
	index += CefC_Ctrl_User_Len;
	
	/* set operation 	*/
	memcpy (buff + index, &op, sizeof (op));
	index += sizeof (op);
	
	/* set protocol 	*/
	memcpy (buff + index, &prot, sizeof (prot));
	index += sizeof (prot);
	
	/* set URI */
	uri_len = (uint16_t) strlen (argv[3]);
	memcpy (buff + index, &uri_len, sizeof (uint16_t));
	index += sizeof (uint16_t);
	memcpy (buff + index, argv[3], uri_len);
	index += uri_len;
	
	for (i = 5 ; i < argc ; i++) {
		/* set host IPaddress */
		host_len = strlen (argv[i]);
		memcpy (buff + index, &host_len, sizeof (host_len));
		index += sizeof (host_len);
		memcpy (buff + index, argv[i], host_len);
		index += host_len;
	}
	
	return (index);
}

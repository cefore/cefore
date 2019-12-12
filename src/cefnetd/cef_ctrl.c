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
#define CefC_Arg_Route_Ope_del		"del"
#define CefC_Arg_Route_Pro_TCP		"tcp"
#define CefC_Arg_Route_Pro_UDP		"udp"

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
	
	char*	work_arg;
	char 	file_path[PATH_MAX] = {0};
	int 	port_num = CefC_Unset_Port;
	unsigned char rsp_msg[CefC_Max_Length];
	
#ifndef CefC_Android
	char*	wp;
#endif // CefC_Android
	char launched_user_name[CefC_Ctrl_User_Len];
	
	/* Inits logging 		*/
	cef_log_init ("cefctrl");
	
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
			strcpy (file_path, argv[i + 1]);
			dir_path_f++;
			i++;
		} else if (strcmp (work_arg, "-p") == 0) {
			if (i + 1 == argc) {
				cef_log_write (CefC_Log_Error, "[-p] has no parameter.\n");
				exit (1);
			}
			port_num = atoi (argv[i + 1]);
			port_num_f++;
			i++;
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
#ifdef CefC_Debug
	cef_dbg_init ("cefctrl", file_path, 1);
	cef_dbg_write (CefC_Dbg_Fine, "operation is %s\n", argv[1]);
#endif // CefC_Debug
	
	res = cef_client_init (port_num, file_path);
	if (res < 0) {
		cef_log_write (CefC_Log_Error, "Faild to init cliet package.\n");
		exit (1);
	}
	
	fhdl = cef_client_connect ();
	if (fhdl < 1) {
		cef_log_write (CefC_Log_Error, "Faild to connect to cefnetd.\n");
		exit (1);
	}
	
#ifndef CefC_Android
	/* Records the user which launched cefnetd 		*/
	wp = getenv ("USER");
	if (wp == NULL) {
		cef_log_write (CefC_Log_Error, 
			"Failed to obtain $USER launched cefctrl\n");
		exit (1);
	}
	memset (launched_user_name, 0, CefC_Ctrl_User_Len);
	strcpy (launched_user_name, wp);
#else // CefC_Android
	memset (launched_user_name, 0, CefC_Ctrl_User_Len);
	strcpy (launched_user_name, "root");
#endif // CefC_Android
	
	if (strcmp (argv[1], CefC_Arg_Kill) == 0) {
		sprintf ((char*) buff, "%s%s", CefC_Ctrl, CefC_Ctrl_Kill);
		memcpy (&buff[CefC_Ctrl_Len + CefC_Ctrl_Kill_Len], 
						launched_user_name, CefC_Ctrl_User_Len);
		cef_client_message_input (fhdl, buff, 
			CefC_Ctrl_Len + CefC_Ctrl_Kill_Len + CefC_Ctrl_User_Len);
	} else if (strcmp (argv[1], CefC_Arg_Status) == 0) {
		sprintf ((char*) buff, "%s%s", CefC_Ctrl, CefC_Ctrl_Status);
		memcpy (&buff[CefC_Ctrl_Len + CefC_Ctrl_Status_Len], 
						launched_user_name, CefC_Ctrl_User_Len);
		cef_client_message_input (fhdl, buff, 
			CefC_Ctrl_Len + CefC_Ctrl_Status_Len + CefC_Ctrl_User_Len);
		
		usleep (200000);
		while (1) {
			res = cef_client_read (fhdl, rsp_msg, CefC_Max_Length);
			if (res > 0) {
				rsp_msg[res] = 0x00;
				fprintf (stdout, "%s", (char*) rsp_msg);
			} else {
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
				CefC_Ctrl_Len + CefC_Ctrl_Route_Len + CefC_Ctrl_User_Len + len);
		}
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
	int uri_len;
	
	/* check the number of parameters 		*/
	if (argc > 6) {
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
	} else if (strcmp (argv[2], CefC_Arg_Route_Ope_del) == 0) {
		/* operation is delete route */
		op = CefC_Fib_Route_Ope_Del;
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
	
	/* set host IPaddress */
	host_len = strlen (argv[5]);
	memcpy (buff + index, &host_len, sizeof (host_len));
	index += sizeof (host_len);
	memcpy (buff + index, argv[5], host_len);
	index += host_len;
	
	/* set URI */
	uri_len = strlen (argv[3]);
	memcpy (buff + index, argv[3], uri_len);
	index += uri_len;

	return (index);
}

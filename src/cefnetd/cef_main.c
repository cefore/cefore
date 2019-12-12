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
 * cef_main.c
 */

#define __CEF_MAIN_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include "cef_netd.h"

/****************************************************************************************
 Macros
 ****************************************************************************************/

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/


/****************************************************************************************
 State Variables
 ****************************************************************************************/


/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/


/****************************************************************************************
 ****************************************************************************************/
int main (
	int argc,
	char** argv
) {
	int res;
	int dir_path_f 		= 0;
	int port_num_f 		= 0;
	int i;
	char*	work_arg;
	char 	file_path[PATH_MAX] = {0};
	int 	port_num = CefC_Unset_Port;
	
	/* Inits logging 		*/
	cef_log_init ("cefnetd");
	
	/* Parses the options 	*/
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
			cef_log_write (CefC_Log_Error, "Unknown option is specified.\n");
			exit (1);
		}
	}
	
	if (dir_path_f > 1) {
		cef_log_write (CefC_Log_Error, "[-d] options is specified duplicately.\n");
		exit (1);
	}
	if (port_num_f > 1) {
		cef_log_write (CefC_Log_Error, "[-p] options is specified duplicately.\n");
		exit (1);
	}
#ifdef CefC_Debug
	cef_dbg_init ("cefnetd", file_path, 1);
#endif // CefC_Debug
	
	/* Creation the local socket name 	*/
	res = cef_client_init (port_num, file_path);
	if (res < 0) {
		cef_log_write (CefC_Log_Error, "Failed to init the client package.\n");
		exit (1);
	}
	
	/* Launches cefnetd 			*/
	cef_node_run ();
	
	exit (1);
}

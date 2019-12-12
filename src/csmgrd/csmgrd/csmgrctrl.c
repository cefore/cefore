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
 * csmgrctrl.c
 */

#define __CSMGR_CTRL_SOURCE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cefore/cef_csmgr.h>
#include <cefore/cef_client.h>
#include <cefore/cef_log.h>



/****************************************************************************************
 Macros
 ****************************************************************************************/

#define CefC_Unset_Tcp_Port 		-1

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/



/****************************************************************************************
 State Variables
 ****************************************************************************************/



/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/
int
main (
	int argc,
	char** argv
);

/*--------------------------------------------------------------------------------------
	Selects TCP port
----------------------------------------------------------------------------------------*/
static int 
csctrl_select_port (
	int port_num, 
	const char* config_file_dir
);
/*--------------------------------------------------------------------------------------
	Trims the string buffer read from the config file
----------------------------------------------------------------------------------------*/
static int
csctrl_trim_line_string (
	const char* p1, 							/* target string for trimming 			*/
	char* p2,									/* name string after trimming			*/
	char* p3									/* value string after trimming			*/
);

/****************************************************************************************
 ****************************************************************************************/
int
main (
	int argc,
	char** argv
) {
	uint8_t 	port_f 			= 0;
	int 		dir_path_f 		= 0;
	
	int 	port_num 			= CefC_Unset_Tcp_Port;
	char 	port_str[32] 		= {0};
	char 	file_path[PATH_MAX] = {0};
	char 	launched_user_name[CefC_Csmgr_User_Len];
	
	int tcp_sock;
	int res;
	int i;
	char* work_arg;
	unsigned char buff[CefC_Csmgr_Stat_Mtu] = {0};
	uint16_t index = 0;
	uint16_t value16;
	
	/* Inits logging 		*/
	cef_log_init ("csmgrctrl");
	
	/* Obtains options 		*/
	for (i = 1 ; i < argc ; i++) {
		
		work_arg = argv[i];
		if (work_arg == NULL || work_arg[0] == 0) {
			break;
		}
		
		if (strcmp (work_arg, "-p") == 0) {
			if (port_f) {
				cef_log_write (CefC_Log_Error, "[-p] is specified more than once\n");
				return (-1);
			}
			if (i + 1 == argc) {
				cef_log_write (CefC_Log_Error, "[-p] has no parameter.\n");
				return (-1);
			}
			port_num = atoi (argv[i + 1]);
			port_f++;
			i++;
		} else if (strcmp (work_arg, "-d") == 0) {
			if (dir_path_f) {
				cef_log_write (CefC_Log_Error, "[-d] is specified more than once\n");
			}
			if (i + 1 == argc) {
				cef_log_write (CefC_Log_Error, "[-d] has no parameter.\n");
				return (-1);
			}
			strcpy (file_path, argv[i + 1]);
			dir_path_f++;
			i++;
		} else {
			cef_log_write (CefC_Log_Error, "unknown option is specified.\n");
			return (-1);
		}
	}
	
	/* Records the user which launched cefnetd 		*/
	work_arg = getenv ("USER");
	if (work_arg == NULL) {
		cef_log_write (CefC_Log_Error, 
			"Failed to obtain $USER launched cefctrl\n");
		exit (1);
	}
	memset (launched_user_name, 0, CefC_Csmgr_User_Len);
	strcpy (launched_user_name, work_arg);
	
	/* Selects TCP port 	*/
	port_num = csctrl_select_port (port_num, file_path);
	if (port_num < 0) {
		fprintf (stderr, "ERROR : Invalid PORT_NUM\n");
		return (0);
	}
	sprintf (port_str, "%d", port_num);
	tcp_sock = cef_csmgr_connect_tcp_to_csmgrd ("127.0.0.1", port_str);
	if (tcp_sock < 1) {
		fprintf (stderr, "ERROR : connect to csmgrd\n");
		return (0);
	}
	
	/* Create Kill message	*/
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_Kill;
	index += CefC_Csmgr_Msg_HeaderLen;
	
	memcpy (&buff[CefC_Csmgr_Msg_HeaderLen], launched_user_name, CefC_Csmgr_User_Len);
	index += CefC_Csmgr_User_Len;
	
	value16 = htons (index);
	memcpy (&buff[CefC_O_Length], &value16, CefC_S_Length);
	
	/* send message	*/
	res = cef_csmgr_send_msg (tcp_sock, buff, index);
	if (res < 0) {
		fprintf (stderr, "ERROR : Send message (%s)\n", strerror (errno));
		close (tcp_sock);
		return (-1);
	}
	
	/* post process 	*/
	usleep (100000);
	close (tcp_sock);
	
	return (0);
}

/*--------------------------------------------------------------------------------------
	Selects TCP port
----------------------------------------------------------------------------------------*/
static int 
csctrl_select_port (
	int port_num, 
	const char* config_file_dir
) {
	char*	wp;
	FILE* 	fp;
	char 	file_path[PATH_MAX];
	char	buff[1024];
	char 	ws[1024];
	char 	pname[1024];
	int 	res;
	
	if (port_num != CefC_Unset_Tcp_Port) {
		return (port_num);
	}
	if (config_file_dir[0] != 0x00) {
		sprintf (file_path, "%s/csmgrd.conf", config_file_dir);
	} else {
		wp = getenv (CefC_CEFORE_DIR);
		if (wp != NULL && wp[0] != 0) {
			sprintf (file_path, "%s/cefore/csmgrd.conf", wp);
		} else {
			sprintf (file_path, "%s/csmgrd.conf", CefC_CEFORE_DIR_DEF);
		}
	}
	fp = fopen (file_path, "r");
	if (fp == NULL) {
		cef_log_write (CefC_Log_Error, "Failed to open %s\n", file_path);
		return (-1);
	}
	/* Reads and records written values in the cefnetd's config file. */
	while (fgets (buff, 1023, fp) != NULL) {
		buff[1023] = 0;
		if (buff[0] == 0x23/* '#' */) {
			continue;
		}
		res = csctrl_trim_line_string (buff, pname, ws);
		if (res < 0) {
			continue;
		}
		if (strcmp (pname, "PORT_NUM") == 0) {
			res = atoi (ws);
			if ((res < 1025) || (res > 65535)) {
				fclose (fp);
				return (-1);
			}
			port_num = res;
		}
	}
	fclose (fp);
	
	if (port_num == CefC_Unset_Tcp_Port) {
		port_num = CefC_Default_Tcp_Prot;
	}
	return (port_num);
}

/*--------------------------------------------------------------------------------------
	Trims the string buffer read from the config file
----------------------------------------------------------------------------------------*/
static int
csctrl_trim_line_string (
	const char* p1, 							/* target string for trimming 			*/
	char* p2,									/* name string after trimming			*/
	char* p3									/* value string after trimming			*/
) {
	char ws[1024];
	char* wp = ws;
	char* rp = p2;
	int equal_f = -1;

	while (*p1) {
		if ((*p1 == 0x0D) || (*p1 == 0x0A)) {
			break;
		}

		if ((*p1 == 0x20) || (*p1 == 0x09)) {
			p1++;
			continue;
		} else {
			*wp = *p1;
		}

		p1++;
		wp++;
	}
	*wp = 0x00;
	wp = ws;

	while (*wp) {
		if (*wp == 0x3d /* '=' */) {
			if (equal_f > 0) {
				return (-1);
			}
			equal_f = 1;
			*rp = 0x00;
			rp = p3;
		} else {
			*rp = *wp;
			rp++;
		}
		wp++;
	}
	*rp = 0x00;

	return (equal_f);
}

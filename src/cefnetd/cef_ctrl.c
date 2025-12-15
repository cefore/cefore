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

#define	printerr(...)	fprintf(stderr,"[cef_ctrl] ERROR: " __VA_ARGS__)

#define CefC_Arg_Kill				"kill"
#define CefC_Arg_Status				"status"
#define CefC_Arg_Route				"route"
#define CefC_Arg_Route_Ope_Add		"add"
#define CefC_Arg_Route_Ope_Del		"del"
#define CefC_Arg_Route_Ope_Enable	"enable"
#define CefC_Arg_Route_Pro_TCP		"tcp"
#define CefC_Arg_Route_Pro_UDP		"udp"
#define CefC_StatusRspWait			200000		/* usec */

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
	unsigned char buff[CefC_Max_Length];
	int len;
	int res;
	int i;
	int dir_path_f 		= 0;
	int port_num_f 		= 0;
	int pit_f			= 0;
	int16_t numofpit_i	= 0;
	uint16_t numofpit	= 0;
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
		printerr("Parameters are not specified.\n");
		exit (1);
	}
	if (argc > 10) {
		printerr("Parameters are too many.\n");
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
				printerr("[-d] has no parameter.\n");
				exit (1);
			}
			//202108
			if ( strlen(argv[i + 1]) >= PATH_MAX) {
				printerr("[-d] parameter is too long.\n");
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
				printerr("[--pit] has no parameter.\n");
				exit (1);
			}
		} else if (strcmp (work_arg, "-s") == 0) {
			if (strcmp (argv[1], CefC_Arg_Status) == 0) {
				output_opt_f |= CefC_Ctrl_StatusOpt_Stat;
			} else {
				printerr("[-s] has no parameter.\n");
				exit (1);
			}
		} else if (strcmp (work_arg, "-m") == 0) {			//Secret option
			if (strcmp (argv[1], CefC_Arg_Status) == 0) {
				output_opt_f |= CefC_Ctrl_StatusOpt_Metric;
			} else {
				printerr("[-m] has no parameter.\n");
				exit (1);
			}
		} else if (strcmp (work_arg, "-n") == 0) {			//Number of PIT
			if (strcmp (argv[1], CefC_Arg_Status) == 0) {
				if ( i + 1 == argc ) {
					printerr("[-n] has no parameter.\n");
					exit (1);
				}
				output_opt_f |= CefC_Ctrl_StatusOpt_Numofpit;
				numofpit_i = atoi (argv[i + 1]);
				if ( numofpit_i <= 0 ) {
					printerr("[-n] parameter is invalid value(%d).\n", numofpit_i);
					exit (1);
				}
				numofpit = numofpit_i;
				i++;
			} else {
				printerr("[-n] has no parameter.\n");
				exit (1);
			}
#if ((defined CefC_CefnetdCache) && (defined CefC_Develop))
		} else if (strcmp (work_arg, "-lc") == 0) {			//Secret option
			if (strcmp (argv[1], CefC_Arg_Status) == 0) {
				output_opt_f |= CefC_Ctrl_StatusOpt_LCache;
			} else {
				printerr("[-lc] has no parameter.\n");
				exit (1);
			}
#endif //((defined CefC_CefnetdCache) && (defined CefC_Develop))
#if ((defined CefC_Develop))
		} else if (strcmp (work_arg, "--fib-only") == 0) {			//Secret option
			if (strcmp (argv[1], CefC_Arg_Status) == 0) {
				output_opt_f |= CefC_Ctrl_StatusOpt_FibOnly;
			} else {
				printerr("[--fib-only] has no parameter.\n");
				exit (1);
			}
		} else if (strcmp (work_arg, "--fibinet-only") == 0) {			//Secret option
			if (strcmp (argv[1], CefC_Arg_Status) == 0) {
				output_opt_f |= CefC_Ctrl_StatusOpt_FibOnly;
				output_opt_f |= CefC_Ctrl_StatusOpt_FibInetOnly;
			} else {
				printerr("[--fibinet-only] has no parameter.\n");
				exit (1);
			}
		} else if (strcmp (work_arg, "--fibv4udp-only") == 0) {			//Secret option
			if (strcmp (argv[1], CefC_Arg_Status) == 0) {
				output_opt_f |= CefC_Ctrl_StatusOpt_FibOnly;
				output_opt_f |= CefC_Ctrl_StatusOpt_FibV4UdpOnly;
			} else {
				printerr("[--fibv4udp-only] has no parameter.\n");
				exit (1);
			}
#endif //((defined CefC_Develop))
		} else if (strcmp (work_arg, "-p") == 0) {
			if (i + 1 == argc) {
				printerr("[-p] has no parameter.\n");
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
				printerr("unknown option is specified.\n");
				exit (1);
			}
		}
	}

	if (dir_path_f > 1) {
		printerr("[-d] is specified more than once\n");
		exit (1);
	}
	if (port_num_f > 1) {
		printerr("[-p] is specified more than once\n");
		exit (1);
	}
	cef_log_init2 (file_path, 1 /* for CEFNETD */);
#ifdef CefC_Debug
	cef_dbg_init ("cefctrl", file_path, 1);
	cef_dbg_write (CefC_Dbg_Finer, "operation is %s\n", argv[1]);
#endif // CefC_Debug

	res = cef_client_init (port_num, file_path);
	if (res < 0) {
		printerr("Failed to init client package.\n");
		exit (1);
	}

	fhdl = cef_client_connect ();
	if (fhdl < 1) {
		printerr("Failed to connect to cefnetd.\n");
		exit (1);
	}

	/* Records the user which launched cefnetd 		*/
	wp = getenv ("USER");
	if (wp == NULL) {
		printerr("Failed to obtain $USER launched cefctrl\n");
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
			if ( output_opt_f & CefC_Ctrl_StatusOpt_Numofpit ) {
				memcpy( &buff[CefC_Ctrl_Len + CefC_Ctrl_StatusStat_Len + sizeof (uint16_t)],
						&numofpit, sizeof (uint16_t));
				memcpy (&buff[CefC_Ctrl_Len + CefC_Ctrl_StatusStat_Len + sizeof (uint16_t) + sizeof (uint16_t)],
							launched_user_name, CefC_Ctrl_User_Len);
				cef_client_message_input (fhdl, buff,
					CefC_Ctrl_Len + CefC_Ctrl_StatusStat_Len + sizeof (uint16_t) + sizeof (uint16_t) + CefC_Ctrl_User_Len);
			} else {
				memcpy (&buff[CefC_Ctrl_Len + CefC_Ctrl_StatusStat_Len + sizeof (uint16_t)],
							launched_user_name, CefC_Ctrl_User_Len);
				cef_client_message_input (fhdl, buff,
					CefC_Ctrl_Len + CefC_Ctrl_StatusStat_Len + sizeof (uint16_t) + CefC_Ctrl_User_Len);
			}
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
					if (res != 0){
						break;
					}
					usleep (CefC_StatusRspWait);
				}
			} else {
				res = cef_client_read_core (fhdl, rsp_msg, CefC_Max_Length, 10);	// timeout=10ms
			}
			if (res > 0) {
				resped = 1;
				rsp_msg[res] = 0x00;
				fprintf (stdout, "%s", (char*) rsp_msg);
			} else {
				if (resped == 0){
					printerr("cefnetd does not send response.\n");
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
		res = cef_client_read (fhdl, rsp_msg, CefC_Max_Length);
		if (res > 0) {
			rsp_msg[res] = 0x00;
			fprintf (stdout, "%s", (char*) rsp_msg);
		} else {
			printerr("cefnetd does not send response.\n");
		}
	}
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
	int cost = 0;
	int rtcost_f = 0;
	int keyid_f = 0;

	/* check the number of parameters 		*/
	if (argc > 37) {
		printerr("Invalid parameter(s) is(are) specified.\n");
		return (-1);
	}
	if (argc < 6) {
		printerr("Required parameter(s) is(are) not specified.\n");
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
		printerr("Option that is neither add nor del for cefroute is specified.\n");
		return (-1);
	}

	/* check rtcost */
	if (strncmp (argv[4], CefC_Fib_RtCost_Identifier, strlen(CefC_Fib_RtCost_Identifier)) == 0) {
		char *endptr;
		const char *value_str = argv[4] + strlen(CefC_Fib_RtCost_Identifier);
		long cost_l = strtol(value_str, &endptr, 10);

		if ((cost_l == LONG_MIN || cost_l == LONG_MAX) && errno != 0) {
			printerr("RtCost is invalid value.\n");
			return (-1);
		} else if ((cost_l > INT_MAX) || (cost_l < INT_MIN)) {
			printerr("RtCost (%ld) is invalid value.( %d < RtCost < %d )\n", cost_l, INT_MIN, INT_MAX);
			return (-1);
		} else if ((endptr == value_str) || ('\0' != *endptr)) {
			printerr("RtCost is invalid value.\n");
			return (-1);
		}

		cost = (int)cost_l;
		rtcost_f = 4;
		i = 5;
	} else {
		i = 4;
	}

	/* check keyid */
	if (strncmp (argv[i], CefC_Fib_Keyid_Identifier, strlen(CefC_Fib_Keyid_Identifier)) == 0) {
		if (strlen (argv[i]) != strlen(CefC_Fib_Keyid_Identifier) + CefC_Fib_Keyid_Len * 2) {
			printerr("KeyID is invalid length, cefore support only %d bytes KeyID.\n", CefC_Fib_Keyid_Len);
			return (-1);
		}
		keyid_f = i;
		i++;
	}

	/* check protocol */
	if (strcmp (argv[i], CefC_Arg_Route_Pro_TCP) == 0) {
		//prot = CefC_Fib_Route_Pro_TCP;
		prot = CefC_Face_Type_Tcp;
	} else if (strcmp (argv[i], CefC_Arg_Route_Pro_UDP) == 0) {
		/* protocol is UDP */
		//prot = CefC_Fib_Route_Pro_UDP;
		prot = CefC_Face_Type_Udp;
	} else {
		printerr("Protocol that is neither udp nor tcp for cefroute is specified.\n");
		return (-1);
	}
	i++;

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
	if ( CefC_NAME_MAXLEN < uri_len ){
		printerr("URL is too long (%d bytes), cefore does not support T_NAMEs longer than %u bytes.\n",
					uri_len, CefC_NAME_MAXLEN);
		return (-1);
	}
	memcpy (buff + index, &uri_len, sizeof (uint16_t));
	index += sizeof (uint16_t);
	memcpy (buff + index, argv[3], uri_len);
	index += uri_len;

	/* set rtcost */
	if (rtcost_f > 0) {
		memcpy (buff + index, CefC_Fib_RtCost_Identifier, strlen(CefC_Fib_RtCost_Identifier));
		index += strlen(CefC_Fib_RtCost_Identifier);
		memcpy (buff + index, &cost, sizeof(int));
		index += sizeof(int);
	}

	/* set keyid */
	if (keyid_f > 0) {
		memcpy (buff + index, CefC_Fib_Keyid_Identifier, strlen(CefC_Fib_Keyid_Identifier));
		index += strlen(CefC_Fib_Keyid_Identifier);
		for (int j = 0; j < CefC_Fib_Keyid_Len; j++) {
			unsigned int x;
			sscanf((char *)&argv[keyid_f][strlen(CefC_Fib_Keyid_Identifier) + j * 2], "%02x", &x);
			buff[index] = x;
			index++;
		}
	}

	for (; i < argc ; i++) {
		/* set host IPaddress */
		struct addrinfo hints;
		struct addrinfo* gai_res;
		struct addrinfo* gai_cres;
		char host[CefC_NAME_BUFSIZ] = {0};
		char addr_str[INET6_ADDRSTRLEN];
		char port_str[INET6_ADDRSTRLEN], *port_ptr = NULL;
		char ifname[INET6_ADDRSTRLEN], *ifname_ptr = NULL;
		char *IPv6_endmark = NULL;
		int	 err;

		memset (&hints, 0, sizeof (hints));
		memset (addr_str, 0, sizeof (addr_str));
		memset (port_str, 0, sizeof (port_str));
		memset (ifname, 0, sizeof (ifname));

		strcpy(host, argv[i]);
		IPv6_endmark = strchr(host, ']');	/* Rules for enclosing IPv6 strings in [] */

		if ( host[0] != '[' ){			/* not IPv6 */
			if ( (port_ptr = strchr(host, ':')) != NULL ){
				strcpy(port_str, port_ptr);
				*port_ptr++ = '\0';
			}
		} else if ( IPv6_endmark ) {	/* IPv6 */
			*IPv6_endmark++ = '\0';
			if ( (port_ptr = strchr(IPv6_endmark, ':')) != NULL ){
				strcpy(port_str, port_ptr);
				*port_ptr++ = '\0';
			}
			strcpy(host, &host[1]);
			/*-----------------------------------------------------------*
				When specifying the next hop with a link-local address,
				you must also specify the interface name with the IFNAME
			 *-----------------------------------------------------------*/
			ifname_ptr = strchr(host, '%');
			if ( ifname_ptr ){
				strcpy(ifname, ifname_ptr);
			}
		}
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "host=%s, port=%s, ifname=%s\n", host, port_str, ifname);
#endif // CefC_Debug

		hints.ai_family = AF_UNSPEC;
		if (prot != CefC_Face_Type_Tcp) {
			hints.ai_socktype = SOCK_DGRAM;
		} else {
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_flags = AI_NUMERICSERV;
		}

		if ((err = getaddrinfo (host, port_ptr, &hints, &gai_res)) != 0) {
			printerr ("getaddrinfo(%s)=%s\n", host, gai_strerror(err));
			return (-1);
		}
		for (gai_cres = gai_res ; gai_cres != NULL && !addr_str[0]; gai_cres = gai_cres->ai_next) {
			struct sockaddr_in *ai = (struct sockaddr_in *)(gai_cres->ai_addr);
			struct sockaddr_in6 *ai6 = (struct sockaddr_in6 *)(gai_cres->ai_addr);

			switch ( ai->sin_family ){
			case AF_INET:
				inet_ntop(ai->sin_family, &(ai->sin_addr), addr_str, sizeof(addr_str));
				snprintf(host, sizeof(host), "%s", addr_str);
				break;
			case AF_INET6:
				inet_ntop(ai6->sin6_family, &(ai6->sin6_addr), addr_str, sizeof(addr_str));
				if ( ifname[0] ){
					snprintf(host, sizeof(host), "[%s%s]", addr_str, ifname);
				} else {
					snprintf(host, sizeof(host), "[%s]", addr_str);
				}
				break;
			default:
				continue;
			}
		}
		freeaddrinfo (gai_res);
		if ( port_str[0] ){
			strcat(host, port_str);
		}

#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "host=%s, addr=%s\n", host, addr_str);
#endif // CefC_Debug
		host_len = strlen(host);
		buff[index++] = host_len;
		memcpy(&buff[index], host, host_len);
		index += host_len;
	}

	return (index);
}

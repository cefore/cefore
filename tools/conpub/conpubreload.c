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
 * conpubreload.c
 */

#define __CONPUB_RELOAD_SOURCE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cefore/cef_csmgr.h>
#include <cefore/cef_client.h>



/****************************************************************************************
 Macros
 ****************************************************************************************/
#define	USAGE			print_usage(CefFp_Usage)
#define	printerr(...)	fprintf(stderr,"[conpubreload] ERROR: " __VA_ARGS__)


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
	Output Result
----------------------------------------------------------------------------------------*/
static void
output_result (
	FILE *ofp,
	unsigned char* frame,
	int frame_size
);
/*--------------------------------------------------------------------------------------
	Output Usage
----------------------------------------------------------------------------------------*/
static void
print_usage (
	FILE *ofp
);


/****************************************************************************************
 ****************************************************************************************/
int
main (
	int argc,
	char** argv
) {
	int tcp_sock;
	int len;
	int res;
	int frame_size;
	unsigned char buff[CefC_Csmgr_Stat_Mtu] = {0};
	uint16_t value16;
	struct pollfd fds[1];
	unsigned char frame[CefC_Csmgr_Stat_Mtu] = {0};
	char dst[64] = {0};
	char port_str[32] = {0};
	int i;
	char*	work_arg;

	/***** flags 		*****/
	int host_f 			= 0;
	int port_f 			= 0;

	/***** state variavles 	*****/
	uint8_t type 		= 0;
	uint16_t index 		= 0;

	/* Obtains options 		*/
	for (i = 1 ; i < argc ; i++) {

		work_arg = argv[i];
		if (work_arg == NULL || work_arg[0] == 0) {
			break;
		}

		if (strcmp (work_arg, "-h") == 0) {
			if (host_f) {
				printerr("host is duplicated.");
				USAGE;
				return (-1);
			}
			if (i + 1 == argc) {
				printerr("host is not specified.");
				USAGE;
				return (-1);
			}
			work_arg = argv[i + 1];
			strcpy (dst, work_arg);
			host_f++;
			i++;
		} else if (strcmp (work_arg, "-p") == 0) {
			if (port_f) {
				printerr("port is duplicated.");
				USAGE;
				return (-1);
			}
			if (i + 1 == argc) {
				printerr("port is not specified.");
				USAGE;
				return (-1);
			}
			work_arg = argv[i + 1];
			strcpy (port_str, work_arg);
			port_f++;
			i++;
		} else {

			work_arg = argv[i];

			if (work_arg[0] == '-') {
				printerr("unknown option is specified.");
				USAGE;
				return (-1);
			}
		}
	}

	/* check port flag */
	if (port_f == 0) {
		sprintf (port_str, "%d", CefC_Default_Tcp_Prot);
	}

	/* check dst flag */
	if (host_f == 0) {
		strcpy (dst, "127.0.0.1");
	}
	printf ("\nconpubreload: Connect to %s:%s\n", dst, port_str);
	tcp_sock = cef_csmgr_connect_tcp_to_csmgr (dst, port_str);

	if (tcp_sock < 1) {
		printerr("connect to conpubd\n");
		return (0);
	}
	cef_frame_init ();

	/* Create Upload Request message	*/
	/* set header	*/
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	/* Request Reload 	*/
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_CnpbRload;
	index += CefC_Csmgr_Msg_HeaderLen;

	/* set Length	*/
	value16 = htons (index);
	memcpy (buff + CefC_O_Length, &value16, CefC_S_Length);

	/* send message	*/
	res = cef_csmgr_send_msg (tcp_sock, buff, index);
	if (res < 0) {
		printerr("Send message\n");
		close (tcp_sock);
		return (-1);
	}

	/* receive message	*/
	fds[0].fd = tcp_sock;
	fds[0].events = POLLIN | POLLERR;
	memset (buff, 0, sizeof (buff));
	/* poll	*/
	res = poll (fds, 1, 1000);
	if (res < 0) {
		/* poll error	*/
		printerr("poll error (%s)\n", strerror (errno));
		close (tcp_sock);
		return (-1);
	} else 	if (res == 0) {
		/* timeout	*/
		printerr("timeout\n");
		close (tcp_sock);
		return (-1);
	}

	if (fds[0].revents & (POLLERR | POLLNVAL | POLLHUP)) {
		/* events error.	*/
		if (fds[0].revents & POLLERR) {
			printerr("Poll event is POLLERR\n");
		} else if (fds[0].revents & POLLNVAL) {
			printerr("Poll event is POLLNVAL\n");
		} else {
			printerr("Poll event is POLLHUP\n");
		}
		close (tcp_sock);
		return (-1);
	}

	len = recv (fds[0].fd, buff, CefC_Csmgr_Stat_Mtu, 0);
	if (len > 0) {
		cef_csmgr_buffer_init ();

		/* receive message	*/
		len = csmgr_frame_get (buff, len, frame, &frame_size, &type);
		if (frame_size > 0) {
			if (type != CefC_Csmgr_Msg_Type_CnpbRload) {
				printerr("Response type is not conpubreload\n");
				close (tcp_sock);
				cef_csmgr_buffer_destroy ();
				return (-1);
			}
			output_result (stdout, frame, frame_size);
		} else {
			printerr("Response message is Invalid\n");
			cef_csmgr_buffer_destroy ();
			close (tcp_sock);
			return (-1);
		}
	} else {
		/* closed socket	*/
		printerr("Receive message error (%s)\n", strerror (errno));
		cef_csmgr_buffer_destroy ();
		close (tcp_sock);
		return (-1);
	}
	cef_csmgr_buffer_destroy ();
	close (tcp_sock);

	return (0);
}
/*--------------------------------------------------------------------------------------
	Output Result
----------------------------------------------------------------------------------------*/
static void
output_result (
	FILE *ofp,
	unsigned char* frame,
	int frame_size
) {

	fprintf (ofp, "\nconpubreload: %s\n\n", frame);

	return;
}
/*--------------------------------------------------------------------------------------
	Output Usage
----------------------------------------------------------------------------------------*/
static void
print_usage (
	FILE *ofp
) {
	fprintf (ofp,
		"\n\nUsage: conpubreload\n\n"
		"  conpubreload [-h host] [-p port]\n\n"
		"  host   Specify the host identifier (e.g., IP address) on which csmgrd \n"
		"         is running. The default value is localhost (i.e., 127.0.0.1).\n"
		"  port   Port number to connect csmgrd. The default value is 9799.\n\n"
	);
	return;
}

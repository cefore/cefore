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
 * csmgrecho.c
 */

#define __CSMGR_ECHO_SOURCE__

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
#include <cefore/cef_log.h>



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
int
main (
	int argc,
	char** argv
);
/*--------------------------------------------------------------------------------------
	Output Usage
----------------------------------------------------------------------------------------*/
static void
usage (
	void
);



/****************************************************************************************
 ****************************************************************************************/
int
main (
	int argc,
	char** argv
) {
	uint8_t 	port_f 			= 0;
	uint8_t 	dst_f 			= 0;
	char 		port_str[32] 	= {0};
	char 		dst[64] 		= {0};
	int tcp_sock;
	int res;
	int i;
	char* work_arg;
	unsigned char buff[CefC_Csmgr_Stat_Mtu] = {0};
	uint16_t index = 0;
	struct pollfd fds[1];
	uint8_t type = 0;
	unsigned char frame[CefC_Csmgr_Stat_Mtu] = {0};
	int frame_size;
	int len;
	uint16_t value16;
	
	/* Inits logging 		*/
	cef_log_init ("csmgrecho");
	
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
			strcpy (port_str, argv[i + 1]);
			port_f++;
			i++;
		} else if (strcmp (work_arg, "-h") == 0) {
			if (dst_f) {
				cef_log_write (CefC_Log_Error, "[-h] is specified more than once\n");
				return (-1);
			}
			if (i + 1 == argc) {
				cef_log_write (CefC_Log_Error, "[-h] has no parameter.\n");
				return (-1);
			}
			strcpy (dst, argv[i + 1]);
			dst_f++;
			i++;
		} else {
			cef_log_write (CefC_Log_Error, "unknown option is specified.\n");
			usage ();
			return (-1);
		}
	}
//#ifdef CefC_Debug
//	cef_dbg_init ("csmgrecho", file_path, 0);
//#endif // CefC_Debug
	
	/* check port flag */
	if (port_f == 0) {
		sprintf (port_str, "%d", CefC_Default_Tcp_Prot);
	}

	/* check dst flag */
	if (dst_f == 0) {
		strcpy (dst, "127.0.0.1");
	}
	fprintf (stderr, "\nConnect to %s:%s\n", dst, port_str);
	tcp_sock = cef_csmgr_connect_tcp_to_csmgrd (dst, port_str);
	
	if (tcp_sock < 1) {
		fprintf (stderr, "ERROR : connect to csmgrd\n");
		return (0);
	}

	/* Create Echo message	*/
	/* set header	*/
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	/* Get Status	*/
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_Echo;
	index += CefC_Csmgr_Msg_HeaderLen;

	memcpy (buff + index, "hello", strlen ("hello"));
	index += strlen ("hello");

	/* set Length	*/
	value16 = htons (index);
	memcpy (buff + CefC_O_Length, &value16, CefC_S_Length);

	/* send message	*/
	res = cef_csmgr_send_msg (tcp_sock, buff, index);
	if (res < 0) {
		fprintf (stderr, "ERROR : Send message (%s)\n", strerror(errno));
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
		fprintf (stderr, "ERROR : poll error (%s)\n", strerror (errno));
		close (tcp_sock);
		return (-1);
	} else 	if (res == 0) {
		/* timeout	*/
		fprintf (stderr, "ERROR : timeout\n");
		close (tcp_sock);
		return (-1);
	}

	if (fds[0].revents & (POLLERR | POLLNVAL | POLLHUP)) {
		/* events error.	*/
		if (fds[0].revents & POLLERR) {
			fprintf (stderr, "ERROR : poll events POLLERR\n");
		} else if (fds[0].revents & POLLNVAL) {
			fprintf (stderr, "ERROR : poll events POLLNVAL\n");
		} else {
			fprintf (stderr, "ERROR : poll events POLLHUP\n");
		}
		close (tcp_sock);
		return (-1);
	}

	len = recv (fds[0].fd, buff, CefC_Csmgr_Stat_Mtu, 0);
	if (len > 0) {
		/* receive message	*/
		cef_csmgr_buffer_init ();
		
		len = csmgr_frame_get (buff, len, frame, &frame_size, &type);
		if (frame_size > 0) {
			if (type != CefC_Csmgr_Msg_Type_Echo) {
				fprintf (stderr, "ERROR : Response type is not echo\n");
				close (tcp_sock);
				return (-1);
			}
			if (strcmp ((const char*)frame, "hello") == 0) {
				/* receive echo message */
				fprintf (stderr, "SUCCESS : Received return message\n\n");
			} else {
				/* error */
				fprintf (stderr, "FAILED : Can't receive echo message\n\n");
			}
		} else {
			fprintf (stderr, "ERROR : Response message is Invalid\n");
			close (tcp_sock);
			return (-1);
		}
	} else {
		/* closed socket	*/
		fprintf (stderr, "ERROR : Receive message error (%s)\n", strerror (errno));
		close (tcp_sock);
		return (-1);
	}

	/* post process */
	close (tcp_sock);

	return (0);
}
/*--------------------------------------------------------------------------------------
	Output Usage
----------------------------------------------------------------------------------------*/
static void
usage (
	void
) {
	fprintf (stderr,
		"Usage : csmgrecho [-h host] [-p port]\n");
	return;
}

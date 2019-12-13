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
 * csmgrstatus.c
 */

#define __CSMGR_STATUS_SOURCE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cefore/cef_csmgr.h>
#include <cefore/cef_client.h>



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
	Output Result
----------------------------------------------------------------------------------------*/
static void
output_result (
	unsigned char* frame,
	int frame_size
);
/*--------------------------------------------------------------------------------------
	Output Usage
----------------------------------------------------------------------------------------*/
static void
print_usage (
	void
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
	int name_len;
	struct pollfd fds[1];
	unsigned char frame[CefC_Csmgr_Stat_Mtu] = {0};
	char uri[1024] = {0};
	char dst[64] = {0};
	char port_str[32] = {0};
	unsigned char tmp_name[512];
	int i;
	char*	work_arg;

	/***** flags 		*****/
	int host_f 			= 0;
	int port_f 			= 0;
	int uri_f 			= 0;

	/***** state variavles 	*****/
	uint8_t type 		= 0;
	uint16_t index 		= 0;
	uint8_t uri_value 	= 0;

	/* Obtains options 		*/
	for (i = 1 ; i < argc ; i++) {

		work_arg = argv[i];
		if (work_arg == NULL || work_arg[0] == 0) {
			break;
		}

		if (strcmp (work_arg, "-h") == 0) {
			if (host_f) {
				fprintf (stderr, "csmgrstatus: [ERROR] host is duplicated.");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stderr, "csmgrstatus: [ERROR] host is not specified.");
				print_usage ();
				return (-1);
			}
			work_arg = argv[i + 1];
			strcpy (dst, work_arg);
			host_f++;
			i++;
		} else if (strcmp (work_arg, "-p") == 0) {
			if (port_f) {
				fprintf (stderr, "csmgrstatus: [ERROR] port is duplicated.");
				print_usage ();
				return (-1);
			}
			if (i + 1 == argc) {
				fprintf (stderr, "csmgrstatus: [ERROR] port is not specified.");
				print_usage ();
				return (-1);
			}
			work_arg = argv[i + 1];
			strcpy (port_str, work_arg);
			port_f++;
			i++;
		} else {

			work_arg = argv[i];

			if (work_arg[0] == '-') {
				fprintf (stderr, "csmgrstatus: [ERROR] unknown option is specified.");
				print_usage ();
				return (-1);
			}

			if (uri_f) {
				fprintf (stderr, "csmgrstatus: [ERROR] uri is duplicated.");
				print_usage ();
				return (-1);
			}
			res = strlen (work_arg);

			if (res >= 1204) {
				fprintf (stderr, "csmgrstatus: [ERROR] uri is too long.");
				print_usage ();
				return (-1);
			}
			strcpy (uri, work_arg);
			uri_value = 1;
			uri_f++;
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
	fprintf (stderr, "\nConnect to %s:%s\n", dst, port_str);
	tcp_sock = cef_csmgr_connect_tcp_to_csmgrd (dst, port_str);

	if (tcp_sock < 1) {
		fprintf (stderr, "ERROR : connect to csmgrd\n");
		return (0);
	}
	cef_frame_init ();
	
	/* Create Upload Request message	*/
	/* set header	*/
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	/* Get Status	*/
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_Status;
	index += CefC_Csmgr_Msg_HeaderLen;

	/* set uri flag	*/
	memcpy (buff + index, &uri_value, sizeof (uint8_t));
	index += sizeof (uint8_t);
	if (uri_value) {
		name_len = cef_frame_conversion_uri_to_name (uri, tmp_name);
		if (name_len < 0) {
			fprintf (stderr, "ERROR : URI is Invalid (%s)\n", uri);
		}
		if (name_len == 4) { /* uri is ccn:/ */
			name_len = 0;
		}
	} else {
		name_len = 0;
	}
	
	if (name_len > 0) {
		memcpy (buff + index, &tmp_name, name_len);
		index += (uint16_t) name_len;
	}
	
	/* set Length	*/
	value16 = htons (index);
	memcpy (buff + CefC_O_Length, &value16, CefC_S_Length);
	
	/* send message	*/
	res = cef_csmgr_send_msg (tcp_sock, buff, index);
	if (res < 0) {
		fprintf (stderr, "ERROR : Send message\n");
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
			fprintf (stderr, "ERROR : Poll event is POLLERR\n");
		} else if (fds[0].revents & POLLNVAL) {
			fprintf (stderr, "ERROR : Poll event is POLLNVAL\n");
		} else {
			fprintf (stderr, "ERROR : Poll event is POLLHUP\n");
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
			if (type != CefC_Csmgr_Msg_Type_Status) {
				fprintf (stderr, "ERROR : Response type is not status\n");
				close (tcp_sock);
				cef_csmgr_buffer_destroy ();
				return (-1);
			}
			output_result (frame, frame_size);
		} else {
			fprintf (stderr, "ERROR : Response message is Invalid\n");
			cef_csmgr_buffer_destroy ();
			close (tcp_sock);
			return (-1);
		}
	} else {
		/* closed socket	*/
		fprintf (stderr, "ERROR : Receive message error (%s)\n", strerror (errno));
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
	unsigned char* frame,
	int frame_size
) {
	struct CefT_Csmgr_Status_Hdr stat_hdr;
	struct CefT_Csmgr_Status_Rep stat_rep;
	unsigned char name[65535];
	char get_uri[65535];
	uint16_t index = 0;
	int con_no = 0;
	
	if (frame_size < sizeof (struct CefT_Csmgr_Status_Hdr)) {
		fprintf (stderr, "Received the invalid response\n");
	}
	memcpy (&stat_hdr, &frame[0], sizeof (struct CefT_Csmgr_Status_Hdr));
	stat_hdr.node_num 	= ntohs (stat_hdr.node_num);
	stat_hdr.con_num 	= ntohs (stat_hdr.con_num);
	
	fprintf (stderr, "*****   Connection Status Report   *****\n");
	fprintf (stderr, "All Connection Num             : %d\n\n", stat_hdr.node_num);
	
	fprintf (stderr, "*****   Cache Status Report        *****\n");
	fprintf (stderr, "Number of Cached Contents      : %d\n\n", stat_hdr.con_num);
	index += sizeof (struct CefT_Csmgr_Status_Hdr);
	
	while (index < frame_size) {
		if (frame_size - index < sizeof (struct CefT_Csmgr_Status_Rep)) {
			break;
		}
		memcpy (&stat_rep, &frame[index], sizeof (struct CefT_Csmgr_Status_Rep));
		stat_rep.con_size 		= cef_client_ntohb (stat_rep.con_size);
		stat_rep.access 		= cef_client_ntohb (stat_rep.access);
		stat_rep.freshness 		= cef_client_ntohb (stat_rep.freshness);
		stat_rep.elapsed_time 	= cef_client_ntohb (stat_rep.elapsed_time);
		stat_rep.name_len 		= ntohs (stat_rep.name_len);
		index += sizeof (struct CefT_Csmgr_Status_Rep);
		
		if (frame_size - index < stat_rep.name_len) {
			break;
		}
		memcpy (name, &frame[index], stat_rep.name_len);
		index += stat_rep.name_len;
		
		if (stat_rep.name_len > 0) {
			cef_frame_conversion_name_to_uri (name, stat_rep.name_len, get_uri);
			fprintf (stderr, "[%d]\n", con_no);
			fprintf (stderr, "  Content Name : %s\n", get_uri);
			fprintf (stderr, "  Content Size : "FMTU64" Bytes\n", stat_rep.con_size);
			fprintf (stderr, "  Access Count : "FMTU64"\n", stat_rep.access);
			if (stat_rep.freshness) {
				fprintf (stderr, "  Freshness    : "FMTU64" Sec\n", stat_rep.freshness);
			} else {
				fprintf (stderr, "  Freshness    : Permanent\n");
			}
			fprintf (stderr, "  Elapsed Time : "FMTU64" Sec\n", stat_rep.elapsed_time);
			fprintf (stderr, "\n");
			con_no++;
		}
	}
	
	return;
}
/*--------------------------------------------------------------------------------------
	Output Usage
----------------------------------------------------------------------------------------*/
static void
print_usage (
	void
) {
	fprintf (stderr,
		"\nUsage: csmgrstatus\n\n"
		"  csmgrstatus [uri] [-h host] [-p port]\n\n"
		"  uri    Name prefix of the content to output.\n"
		"  host   Specify the host identifier (e.g., IP address) on which csmgrd \n"
		"         is running. The default value is localhost (i.e., 127.0.0.1).\n"
		"  port   Port number to connect csmgrd. The default value is 9799.\n\n"
	);
	return;
}

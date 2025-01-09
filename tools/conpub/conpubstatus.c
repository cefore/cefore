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
 * conpubstatus.c
 */

#define __CONPUB_STATUS_SOURCE__

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
#define	printerr(...)	fprintf(stderr,"[conpubstatus] ERROR: " __VA_ARGS__)

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/
struct conpub_rsp_value64 {
	uint16_t 	type;
	uint16_t 	length;
	uint64_t 	value;

} __attribute__((__packed__));

struct conpub_rsp_value32 {
	uint16_t 	type;
	uint16_t 	length;
	uint32_t 	value;

} __attribute__((__packed__));

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
	FILE* ofp,
	unsigned char* frame,
	int frame_size
);
/*--------------------------------------------------------------------------------------
	Output Usage
----------------------------------------------------------------------------------------*/
static void
print_usage (
	FILE* ofp
);


/****************************************************************************************
 ****************************************************************************************/
int
main (
	int argc,
	char** argv
) {
	int tcp_sock;
	int res;
	int frame_size;
	unsigned char buff[CefC_Csmgr_Stat_Mtu] = {0};
	uint16_t value16;
	struct pollfd fds[1];
	unsigned char *frame;
	char dst[64] = {0};
	char port_str[32] = {0};
	int i;
	char*	work_arg;
	uint32_t msg_len, rcvd_size;
	int rc;
	int blocks;

	/***** flags 		*****/
	int host_f 			= 0;
	int port_f 			= 0;

	/***** state variavles 	*****/
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
	tcp_sock = cef_csmgr_connect_tcp_to_csmgr (dst, port_str);

	if (tcp_sock < 1) {
		printerr("Connection failed to %s:%s\n", dst, port_str);
		return (0);
	}
	cef_frame_init ();

	/* Create Upload Request message	*/
	/* set header	*/
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	/* Get Status	*/
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_CnpbStatus;
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
	rcvd_size = 0;
	frame_size = 0;
	msg_len = 0;
	frame = calloc (1, CefC_Csmgr_Stat_Mtu);
	if (frame == NULL) {
		printerr("Frame buffer allocation (alloc) error\n");
		close (tcp_sock);
		cef_csmgr_buffer_destroy ();
		return (-1);
	}

RERECV:;
	fds[0].fd = tcp_sock;
	fds[0].events = POLLIN | POLLERR;
	res = poll(fds, 1, 60000);
	if (res < 0) {
		/* poll error	*/
		printerr("poll error (%s)\n", strerror (errno));
		close (tcp_sock);
		cef_csmgr_buffer_destroy ();
		free (frame);
		return (-1);
	} else 	if (res == 0) {
		/* timeout	*/
		printerr("timeout\n");
		close (tcp_sock);
		cef_csmgr_buffer_destroy ();
		free (frame);
		return (-1);
	}
	if (fds[0].revents & POLLIN) {
		rc = recv (tcp_sock, frame+rcvd_size , CefC_Csmgr_Stat_Mtu, 0);
		if (rc < 0) {
			printerr("Receive message error (%s)\n", strerror (errno));
			close (tcp_sock);
			cef_csmgr_buffer_destroy ();
			free (frame);
			return (-1);
		}
	} else {
		if (fds[0].revents & POLLERR) {
			printerr("Poll event is POLLERR\n");
		} else if (fds[0].revents & POLLNVAL) {
			printerr("Poll event is POLLNVAL\n");
		} else {
			printerr("Poll event is POLLHUP\n");
		}
		close (tcp_sock);
		cef_csmgr_buffer_destroy ();
		free (frame);
		return (-1);
	}
	rcvd_size += rc;
	if (rcvd_size == rc) {
		if ((rc < 6/* Ver(1)+Type(1)+Length(4) */)
			|| (frame[CefC_O_Fix_Ver] != CefC_Version)
			|| (frame[CefC_O_Fix_Type] != CefC_Csmgr_Msg_Type_CnpbStatus) ){
			printerr("Response type is not status\n");
			close (tcp_sock);
			cef_csmgr_buffer_destroy ();
			free (frame);
			return (-1);
		}

		memcpy (&msg_len, &frame[2], sizeof (uint32_t));
		msg_len = ntohl (msg_len);
		blocks = (msg_len) / CefC_Csmgr_Stat_Mtu;
		if (((msg_len) % CefC_Csmgr_Stat_Mtu) != 0){
			blocks += 1;
		}
		if (blocks > 1) {
			void *new = realloc(frame, blocks * CefC_Csmgr_Stat_Mtu);
			if (new == NULL) {
				printerr("Frame buffer allocation (realloc) error\n");
				close (tcp_sock);
				cef_csmgr_buffer_destroy ();
				free (frame);
				return (-1);
			}
			frame = new;
		}
	}
	if (rcvd_size < msg_len){
		goto RERECV;
	}
	frame_size = msg_len;
	output_result (stdout, &frame[6/* Ver(1)+Type(1)+Length(4) */], frame_size-6/* Ver(1)+Type(1)+Length(4) */);
	cef_csmgr_buffer_destroy ();
	close (tcp_sock);
	free (frame);
	return (0);
}
/*--------------------------------------------------------------------------------------
	Output Result
----------------------------------------------------------------------------------------*/
static void
output_result (
	FILE* ofp,
	unsigned char* frame,
	int frame_size
) {
	struct CefT_Csmgr_CnpbStatus_TL* rsp_hdr;
	struct conpub_rsp_value64* cmd_64_tlv;
	uint16_t type;
	uint16_t length;
	uint32_t index = 0;
	time_t 			date;
	time_t 			expiry;
	time_t 			pending;
	uint64_t 		interests;
	unsigned char ver[2048];
	unsigned char name[2048];
	unsigned char path[2048];
	char uri[2048];
	struct tm* timeptr;
	char date_str[64] = {'\0'};
	char expiry_str[64] = {'\0'};
	char pending_str[64] = {'\0'};
	int rec_idx = 1;

	fprintf (ofp,
		"\nindex   name   version   file   date   expiry   interests   pending\n");
	if (memcmp (frame, "NONE", strlen("NONE")) == 0) {
		frame_size = 0;
	}

	while (index < frame_size) {

		/* Obtains Name 			*/
		rsp_hdr = (struct CefT_Csmgr_CnpbStatus_TL*) &frame[index];
		type   = ntohs (rsp_hdr->type);
		length = ntohs (rsp_hdr->length);
		index += sizeof (struct CefT_Csmgr_CnpbStatus_TL);
		if (type != CefC_CnpbStatus_Name) {
			return;
		}
		memcpy (name, &frame[index], length);
		cef_frame_conversion_name_to_string (name, length, uri, "ccn");
		index += length;

		/* Obtains Version */
		rsp_hdr = (struct CefT_Csmgr_CnpbStatus_TL*) &frame[index];
		type   = ntohs (rsp_hdr->type);
		length = ntohs (rsp_hdr->length);
		index += sizeof (struct CefT_Csmgr_CnpbStatus_TL);
		if (type != CefC_CnpbStatus_Version) {
			return;
		}
		memcpy (ver, &frame[index], length);
		ver[length] = 0x00;
		index += length;

		/* Obtains Path 			*/
		rsp_hdr = (struct CefT_Csmgr_CnpbStatus_TL*) &frame[index];
		type   = ntohs (rsp_hdr->type);
		length = ntohs (rsp_hdr->length);
		index += sizeof (struct CefT_Csmgr_CnpbStatus_TL);
		if (type != CefC_CnpbStatus_Path) {
			return;
		}
		memcpy (path, &frame[index], length);
		path[length] = 0x00;
		index += length;

		/* Obtains Date 			*/
		cmd_64_tlv = (struct conpub_rsp_value64*) &frame[index];
		type   = ntohs (cmd_64_tlv->type);
		length = ntohs (cmd_64_tlv->length);
		index += sizeof (struct conpub_rsp_value64);
		if (type != CefC_CnpbStatus_Date) {
			return;
		}
		date = cef_client_ntohb (cmd_64_tlv->value);
		timeptr = localtime (&date);
		strftime (date_str, 64, "%Y-%m-%d %H:%M", timeptr);

		/* Obtains Expiry 			*/
		cmd_64_tlv = (struct conpub_rsp_value64*) &frame[index];
		type   = ntohs (cmd_64_tlv->type);
		length = ntohs (cmd_64_tlv->length);
		index += sizeof (struct conpub_rsp_value64);
		if (type != CefC_CnpbStatus_Expiry) {
			return;
		}
		expiry = cef_client_ntohb (cmd_64_tlv->value);
		timeptr = localtime (&expiry);
		strftime (expiry_str, 64, "%Y-%m-%d %H:%M", timeptr);

		/* Obtains Pending timer 			*/
		cmd_64_tlv = (struct conpub_rsp_value64*) &frame[index];
		type   = ntohs (cmd_64_tlv->type);
		length = ntohs (cmd_64_tlv->length);
		index += sizeof (struct conpub_rsp_value64);
		if (type != CefC_CnpbStatus_Pending) {
			return;
		}
		pending = cef_client_ntohb (cmd_64_tlv->value);
		if (pending) {
			sprintf(pending_str, "%lu Sec", pending);
		} else {
			sprintf(pending_str, "%s", "-");
		}

		/* Obtains Interests 			*/
		cmd_64_tlv = (struct conpub_rsp_value64*) &frame[index];
		type   = ntohs (cmd_64_tlv->type);
		length = ntohs (cmd_64_tlv->length);
		index += sizeof (struct conpub_rsp_value64);
		if (type != CefC_CnpbStatus_Interest) {
			return;
		}
		interests = cef_client_ntohb (cmd_64_tlv->value);

		/* Outputs a record 			*/
		fprintf (ofp, "%d  %s\t%s\t%s\t%s\t%s\t"
			, rec_idx, uri, ver, path, date_str, expiry_str);

		fprintf (ofp, "   "FMTU64"\t", interests);
		fprintf (ofp, "\t%s\n", pending_str);
		rec_idx++;
	}
	fprintf (ofp, "\n");

}
/*--------------------------------------------------------------------------------------
	Output Usage
----------------------------------------------------------------------------------------*/
static void
print_usage (
	FILE* ofp
) {
	fprintf (ofp,
		"\n\nUsage: conpubstatus\n\n"
		"  conpubstatus [-h host] [-p port]\n\n"
		"  host   Specify the host identifier (e.g., IP address) on which csmgrd \n"
		"         is running. The default value is localhost (i.e., 127.0.0.1).\n"
		"  port   Port number to connect csmgrd. The default value is 9799.\n\n"
	);
	return;
}

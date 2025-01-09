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
 * csmgrstatus.c
 */

#define __CSMGR_STATUS_SOURCE__

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
#define	printerr(...)	fprintf(stderr,"[csmgrstatus] ERROR: " __VA_ARGS__)

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
	FILE* ofp,
	unsigned char* frame,
	int frame_size,
	int32_t stt_num
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
	int name_len;
	struct pollfd fds[1];
	unsigned char *frame;
	char uri[CefC_Max_Length] = {0};
	char dst[64] = {0};
	char port_str[32] = {0};
	unsigned char tmp_name[512];
	int i;
	char*	work_arg;
	uint32_t msg_len, rcvd_size;
	int rc;
	int blocks;
	uint8_t option = CefC_Csmgr_Stat_Opt_None;

	/***** flags 		*****/
	int host_f 			= 0;
	int port_f 			= 0;
	int uri_f 			= 0;
	int clear_f 		= 0;
	int stt_f			= 0;
	int	num_f			= 0;

	int32_t	stt_num		= -1;	//Default
	int32_t	out_num		= 100;	//Default
	int32_t disp_stt;

	/***** state variavles 	*****/
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
		} else if (strcmp (work_arg, "-c") == 0) {
			if (clear_f) {
				printerr("clear option is duplicated.");
				USAGE;
				return (-1);
			}
			clear_f++;
			i++;
		} else if (strcmp (work_arg, "-s") == 0) {
			if (stt_f) {
				printerr("Range option(s) is duplicated.");
				USAGE;
				return (-1);
			}
			if (i + 1 == argc) {
				printerr("Range option start is not specified.");
				USAGE;
				return (-1);
			}
			work_arg = argv[i + 1];
			stt_num = atoi(work_arg);
			if (stt_num <= 0) {
				printerr("Range option start less than or equal to 0.");
				USAGE;
				return (-1);
			}
			stt_f++;
			i++;
		} else if (strcmp (work_arg, "-n") == 0) {
			if (num_f) {
				printerr("Range option(n) is duplicated.");
				USAGE;
				return (-1);
			}
			if (i + 1 == argc) {
				printerr("Range option(n) is not specified.");
				USAGE;
				return (-1);
			}
			work_arg = argv[i + 1];
			out_num = atoi(work_arg);
			if (out_num <= 0) {
				printerr("Range option num less than or equal to 0.");
				USAGE;
				return (-1);
			}
			num_f++;
			i++;
		} else {

			work_arg = argv[i];

			if (work_arg[0] == '-') {
				printerr("unknown option is specified.");
				USAGE;
				return (-1);
			}

			if (uri_f) {
				printerr("uri is duplicated.");
				USAGE;
				return (-1);
			}
			res = strlen (work_arg);

			if (res >= 1204) {
				printerr("uri is too long.");
				USAGE;
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
	tcp_sock = cef_csmgr_connect_tcp_to_csmgr (dst, port_str);

	if (tcp_sock < 1) {
		printerr("Connection failed to %s:%s\n", dst, port_str);
		return (0);
	}
	if (clear_f != 0 && uri_f == 0) {
		printerr("uri to be cleared is not specified.");
		USAGE;
		return (0);
	}
	cef_frame_init ();

/* =====================================================================
                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +---------------+---------------+---------------+---------------+
     |    Version    |  PacketType   |         PacketLength          |
     +---------------+---------------+---------------+---------------+
     |     Option    |                   Name(URI)                   /
     +---------------+---------------+---------------+---------------+
   ===================================================================== */
	/* Create Upload Request message	*/
	/* set header	*/
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	/* Get Status	*/
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_Status;
	index += CefC_Csmgr_Msg_HeaderLen;

	/* set option */
	if (clear_f) {
		option |= CefC_Csmgr_Stat_Opt_Clear;
	}
	if (stt_f) {
		option |= CefC_Csmgr_Stat_Opt_Range;
	}
	buff[index] = option;
	index++;
	if (stt_f) {
		memcpy(buff + index, &stt_num, sizeof(int32_t) );
		index += sizeof(int32_t);
		memcpy(buff + index, &out_num, sizeof(int32_t) );
		index += sizeof(int32_t);
	} else {
		memcpy(buff + index, &stt_num, sizeof(int32_t) );
		index += sizeof(int32_t);
		memcpy(buff + index, &out_num, sizeof(int32_t) );
		index += sizeof(int32_t);
	}

	/* set uri flag	*/
	memcpy (buff + index, &uri_value, sizeof (uint8_t));
	index += sizeof (uint8_t);
	if (uri_value) {
		name_len = cef_frame_conversion_uri_to_name (uri, tmp_name);
		if (name_len < 0) {
			printerr("URI is Invalid (%s)\n", uri);
			return (0);
		}
		if (name_len == 4) { /* uri is ccnx:/ */
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
	res = poll(fds, 1, 10000);
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
			|| (frame[CefC_O_Fix_Type] != CefC_Csmgr_Msg_Type_Status) ){
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
	if (stt_num == -1) {
		disp_stt = 1;
	} else {
		disp_stt = stt_num;
	}

	output_result (stdout, &frame[6/* Ver(1)+Type(1)+Length(4) */], frame_size-6/* Ver(1)+Type(1)+Length(4) */, disp_stt);
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
	FILE *ofp,
	unsigned char* frame,
	int frame_size,
	int32_t	disp_stt
) {
	struct CefT_Csmgr_Status_Hdr stat_hdr;
	struct CefT_Csmgr_Status_Rep stat_rep;
	unsigned char name[CefC_Max_Length];
	char get_uri[CefC_Max_Length];
	uint32_t index = 0;
	int con_no = disp_stt;
	unsigned char version[CefC_Max_Length];

	if (frame_size < sizeof (struct CefT_Csmgr_Status_Hdr)) {
		fprintf (ofp, "Received the invalid response\n");
	}
	memcpy (&stat_hdr, &frame[0], sizeof (struct CefT_Csmgr_Status_Hdr));
	stat_hdr.node_num 	= ntohs (stat_hdr.node_num);
	stat_hdr.con_num 	= ntohl (stat_hdr.con_num);

	fprintf (ofp, "*****   Connection Status Report   *****\n");
	fprintf (ofp, "All Connection Num             : %d\n\n", stat_hdr.node_num);

	fprintf (ofp, "*****   Cache Status Report        *****\n");
	fprintf (ofp, "Number of Cached Contents      : %d\n\n", stat_hdr.con_num);
	index += sizeof (struct CefT_Csmgr_Status_Hdr);

	while (index < frame_size) {
		if (frame_size - index < sizeof (struct CefT_Csmgr_Status_Rep)) {
			break;
		}
		memcpy (&stat_rep, &frame[index], sizeof (struct CefT_Csmgr_Status_Rep));
		stat_rep.con_size 		= cef_client_ntohb (stat_rep.con_size);
		stat_rep.access 		= cef_client_ntohb (stat_rep.access);
		stat_rep.req_count 		= cef_client_ntohb (stat_rep.req_count);
		stat_rep.freshness 		= cef_client_ntohb (stat_rep.freshness);
		stat_rep.elapsed_time 	= cef_client_ntohb (stat_rep.elapsed_time);
		stat_rep.pending_time 	= cef_client_ntohb (stat_rep.pending_time);
		stat_rep.ucinc_f 		= ntohs (stat_rep.ucinc_f);
		stat_rep.validation_result 	= ntohs (stat_rep.validation_result);
		stat_rep.name_len 		= ntohs (stat_rep.name_len);
		stat_rep.ver_len 		= ntohs (stat_rep.ver_len);
		index += sizeof (struct CefT_Csmgr_Status_Rep);

		if (frame_size - index < stat_rep.name_len) {
			break;
		}
		memcpy (name, &frame[index], stat_rep.name_len);
		index += stat_rep.name_len;
		if (stat_rep.ver_len) {
			memcpy (version, &frame[index], stat_rep.ver_len);
			index += stat_rep.ver_len;
		}

		if (stat_rep.name_len > 0) {
			cef_frame_conversion_name_to_uri (name, stat_rep.name_len, get_uri);
			fprintf (ofp, "[%d]\n", con_no);
			fprintf (ofp, "  Content Name  : %s\n", get_uri);
			if (stat_rep.ver_len) {
				fprintf (ofp, "  Version       : ");
				for (int i = 0; i < stat_rep.ver_len; i++) {
					if (isprint (version[i])) fprintf (ofp, "%c", version[i]);
					else fprintf (ofp, "%02x", version[i]);
				}
				fprintf (ofp, "\n");
			} else {
				fprintf (ofp, "  Version       : None\n");
			}
			fprintf (ofp, "  Content Size  : %llu Bytes\n", (unsigned long long)stat_rep.con_size);
			fprintf (ofp, "  Cache Hit     : %llu\n", (unsigned long long)stat_rep.access);
			fprintf (ofp, "  Request Count : %llu\n", (unsigned long long)stat_rep.req_count);
			if (stat_rep.freshness) {
				fprintf (ofp, "  Freshness     : %llu Sec\n", (unsigned long long)stat_rep.freshness);
			} else {
				fprintf (ofp, "  Freshness     : Permanent\n");
			}
			fprintf (ofp, "  Elapsed Time  : %llu Sec\n", (unsigned long long)stat_rep.elapsed_time);
			if (stat_rep.ucinc_f) {
				if (stat_rep.validation_result) {
					fprintf (ofp, "  CS Act.       : Active\n");
				} else {
					fprintf (ofp, "  CS Act.       : Pending (time left %llu ms)\n", (unsigned long long)stat_rep.pending_time);
				}
			}
			fprintf (ofp, "\n");
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
	FILE* ofp
) {
	fprintf (ofp,
		"\n\nUsage: csmgrstatus\n\n"
		"  csmgrstatus [uri] [-h host] [-p port] [-c] [-s start] [-n num]\n\n"
		"  uri    Name prefix of the content to output.\n"
		"  host   Specify the host identifier (e.g., IP address) on which csmgrd \n"
		"         is running. The default value is localhost (i.e., 127.0.0.1).\n"
		"  port   Port number to connect csmgrd. The default value is 9799.\n"
		"  start  Top of content to display.\n"
		"  num    Number of pieces of content to display.\n\n"
	);
	return;
}

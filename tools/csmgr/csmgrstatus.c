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
	int frame_size,
	uint8_t uri_f,
	char* uri
);
/*--------------------------------------------------------------------------------------
	Output Cache information
----------------------------------------------------------------------------------------*/
static void
output_cache_result (
	unsigned char* frame,
	int frame_size,
	char* uri
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
		if (cef_frame_conversion_uri_to_name (uri, tmp_name) < 0) {
			/* header is not cef:/	*/
			fprintf (stderr, "ERROR : URI is Invalid (%s)\n", uri);
		}
		res = strlen (uri);
		if (uri[res - 1] != '/') {
			strcat (uri, "/");
		}
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
		/* receive message	*/
		len = csmgr_frame_get (buff, len, frame, &frame_size, &type);
		if (frame_size > 0) {
			if (type != CefC_Csmgr_Msg_Type_Status) {
				fprintf (stderr, "ERROR : Response type is not status\n");
				close (tcp_sock);
				return (-1);
			}
			output_result (frame, frame_size, uri_value, uri);
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

	close (tcp_sock);

	return (0);
}
/*--------------------------------------------------------------------------------------
	Output Result
----------------------------------------------------------------------------------------*/
static void
output_result (
	unsigned char* frame,
	int frame_size,
	uint8_t uri_f,
	char* uri
) {
	// struct CefT_Cs_Mgrd_Stat mgr_stat;
	char stat[CefC_Max_Length] = {0};
	char rply[CefC_Max_Length] = {0};
	uint16_t stat_len = 0;
	uint16_t rply_len = 0;
	uint16_t cache_len = 0;
	uint8_t type;
	uint16_t index = 0;
	uint16_t value16;

	/* get status */
	type = frame[index];
	if (type != CefC_Csmgr_Stat_Msg_Type_Status) {
		fprintf (stderr, "Receive invalid type (%d)\n", type);
		return;
	}
	index++;
	memcpy (&value16, frame + index, sizeof (uint16_t));
	rply_len = ntohs (value16);
	index += sizeof (uint16_t);
	memcpy (rply, frame + index, rply_len);
	index += rply_len;

	fprintf (stderr, "\n");
	fprintf (stderr, "%s\n", rply);

	/* get status */
	type = frame[index];
	if (type != CefC_Csmgr_Stat_Msg_Type_Status) {
		fprintf (stderr, "Receive invalid type (%d)\n", type);
		return;
	}
	index++;
	memcpy (&value16, frame + index, sizeof (uint16_t));
	stat_len = ntohs (value16);
	index += sizeof (uint16_t);
	memcpy (stat, frame + index, stat_len);
	index += stat_len;

	/* output status */
	fprintf (stderr, "\n");
	fprintf (stderr, "%s\n", stat);

	if (uri_f) {
		if ((frame_size - index) > 0) {
			/* get cache information */
			type = frame[index];
			if (type != CefC_Csmgr_Stat_Msg_Type_Cache) {
				fprintf (stderr, "Receive invalid type\n");
				return;
			}
			index++;
			memcpy (&value16, frame + index, sizeof (uint16_t));
			cache_len = ntohs (value16);
			index += sizeof (cache_len);
			output_cache_result (frame + index, cache_len, uri);
			index += cache_len;
		}
	}

	return;
}
/*--------------------------------------------------------------------------------------
	Output Cache information
----------------------------------------------------------------------------------------*/
static void
output_cache_result (
	unsigned char* frame,
	int frame_size,
	char* uri
) {
	CefT_Csmgrd_Stat_Cache cinfo;

	uint8_t fld_type;
	uint16_t fld_length;
	uint8_t name_length;
	uint32_t name_num;
	char name[265];
	char uri_prot[1024] = {0};
	int uri_prot_len = 0;
	char name_prot[1024] = {0};
	int name_prot_len = 0;
	int i, j;
	int opt_name_len;
	int index = 1;
	uint16_t value16;
	uint32_t value32;
	uint64_t value64;

	size_t fst 	= sizeof (fld_type);
	size_t fsl	= sizeof (fld_length);
	size_t fstl = fst + fsl;
	size_t fsn	= sizeof (uint8_t);
	unsigned char* pread = frame;

	/* check field type 	*/
	memcpy (&fld_type, pread, fst);
	if (fld_type != CefC_Csmgr_Stat_Type_Cache) {
#ifdef CTD_DEBUG
		fprintf (stderr, "[debug] fld_type error(%d)\n", fld_type);/* debug */
#endif // CTD_DEBUG
		return;
	}

	/* search for the cache status that a title fits name_prefix option */

	memcpy (&value16, pread + fst, fsl);
	fld_length = ntohs (value16);
	memcpy (&value32, pread + fstl, sizeof (uint32_t));
	name_num = ntohl (value32);
#ifdef CTD_DEBUG
	fprintf (stderr, "[debug]    length=%d, cache num=%u\n", fld_length, name_num);
#endif // CTD_DEBUG
	if (fld_length != frame_size) {
		return;
	}

	/* get uri and uri length */
	opt_name_len = (int) strlen (uri);
	/* get protocol */
	for (i = 0; i < opt_name_len - 1; i++) {
		if ((uri[i] == ':') && uri[i + 1] == '/') {
			memcpy (uri_prot, uri, i + 2);
			break;
		}
	}
	uri_prot_len = (int)strlen (uri_prot);
	pread = frame + fstl + sizeof (uint32_t);
	for (i = 0 ; i < name_num ; i++) {
		memcpy (&value64, pread, sizeof (uint64_t));
		cinfo.size = cef_client_ntohb (value64);
		pread += sizeof (uint64_t);

		memcpy (&value32, pread, sizeof (uint32_t));
		cinfo.freshness_sec = (int) ntohl (value32);
		pread += sizeof (uint32_t);

		memcpy (&value32, pread, sizeof (uint32_t));
		cinfo.access_cnt = ntohl (value32);
		pread += sizeof (uint32_t);

		memcpy (&value32, pread, sizeof (uint32_t));
		cinfo.elapsed_time = ntohl (value32);
		pread += sizeof (uint32_t);

		/* get content name */
		memcpy (&name_length, pread, fsn);
		memcpy (name, pread + fsn, name_length);
		/* get protocol */
		for (j = 0; j < name_length - 1; j++) {
			if ((name[j] == ':') && name[j + 1] == '/') {
				memcpy (name_prot, name, j + 2);
				break;
			}
		}
		name_prot_len = (int) strlen (name_prot);

		pread += fsn + name_length;
		name[name_length] = 0;
		/* check name length */
		if ((opt_name_len - uri_prot_len) > (name_length - name_prot_len)) {
			continue;
		}

		/* check name */
		if (!memcmp (
				&name[name_prot_len], &uri[uri_prot_len], opt_name_len - uri_prot_len)) {
			/* output cache information */
			fprintf (stderr, "[%d]\n", index);
			fprintf (stderr, "  Content Name : %s%s\n", uri_prot, &name[name_prot_len]);
			fprintf (stderr, "  Content Size : "FMTU64"Bytes\n", cinfo.size);
			fprintf (stderr, "  Access Count : %u\n", cinfo.access_cnt);
			if (cinfo.freshness_sec) {
				fprintf (stderr, "  Freshness    : %d Sec\n", cinfo.freshness_sec);
			} else {
				fprintf (stderr, "  Freshness    : Permanent\n");
			}
			fprintf (stderr, "  Elapsed Time : %u Sec\n", cinfo.elapsed_time);
			fprintf (stderr, "\n");
			index++;
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

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
 * conpub_cont_add.c
 */

#define __CONPUB_CONT_ADD_SOURCE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <sys/poll.h>
#include <arpa/inet.h>
#include <limits.h>
#include <cefore/cef_define.h>
#include <cefore/cef_csmgr.h>
#include <cefore/cef_conpub.h>
#include <cefore/cef_client.h>

#define DEFAULT_EXPIRY 86400

static int send_all(int sock, const unsigned char* buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t s = send(sock, buf + sent, len - sent, 0);
        if (s > 0) { sent += s; continue; }
        if (s == 0) { errno = EPIPE; return -1; }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            struct pollfd pfd = { .fd = sock, .events = POLLOUT };
            if (poll(&pfd, 1, 300000) <= 0) { errno = ETIMEDOUT; return -1; }
            continue;
        }
        return -1;
    }
    return 0;
}

static void print_usage(FILE* ofp);
int conpub_cont_add_check_file_path(const char* path);
int conpub_cont_add_parse_date(const char* date_str, const char* time_str, struct tm* date);

int
main(int argc, char** argv) {
	int sock;
	FILE* fp;
	uint64_t fsz;
	size_t n;
	unsigned char hdr[BUFSIZ_1K];
	unsigned char buf[BUFSIZ_8K];
	size_t index;
	uint16_t n16;
	uint64_t expiry;
	char uri[CefC_NAME_MAXLEN] = {0};
	char filepath[PATH_MAX] = {0};
	char exp_date[64] = {0};
	char exp_time[64] = {0};
	char dst[64] = {0};
	char port_str[32] = {0};

	int uri_f = 0;
	int file_f = 0;
	int host_f = 0;
	int port_f = 0;

	if (argc < 4) {
		print_usage(stderr);
		return -1;
	}

	for (int i = 1 ; i < argc ; i++) {

		char* work_arg = argv[i];

		if (strcmp(work_arg, "-f") == 0) {
			if (i + 1 == argc) {
				fprintf(stderr,"-f requires parameter\n");
				return -1;
			}
			strcpy(filepath, argv[++i]);

			if (conpub_cont_add_check_file_path(filepath) < 0) {
				fprintf(stderr,"file open error\n");
				return -1;
			}
			file_f++;
		}
		else if (strcmp(work_arg, "-ed") == 0) {
			if (i + 1 == argc) return -1;
			strcpy(exp_date, argv[++i]);
		}
		else if (strcmp(work_arg, "-et") == 0) {
			if (i + 1 == argc) return -1;
			strcpy(exp_time, argv[++i]);
		}
		else if (strcmp(work_arg, "-h") == 0) {
			if (i + 1 == argc) return -1;
			strcpy(dst, argv[++i]);
			host_f++;
		}
		else if (strcmp(work_arg, "-p") == 0) {
			if (i + 1 == argc) return -1;
			strcpy(port_str, argv[++i]);
			port_f++;
		}
		else {
			strcpy(uri, work_arg);
			uri_f++;
		}
	}
	if (!uri_f || !file_f) {
		print_usage(stderr);
		return -1;
	}

	if (!host_f) strcpy(dst, "127.0.0.1");
	if (!port_f) sprintf(port_str, "%d", CefC_CnpbDefault_Tcp_Prot);

	fp = fopen(filepath, "rb");
	if (!fp) {
		perror("fopen");
		return -1;
	}

	fseeko(fp, 0, SEEK_END);
	fsz = ftello(fp);
	rewind(fp);

	cef_frame_init ();
	sock = cef_csmgr_connect_tcp_to_csmgr(dst, port_str);
	if (sock < 0) {
		perror("connect");
		fclose(fp);
		return -1;
	}

	memset(hdr, 0, sizeof(hdr));
	index = CefC_Csmgr_Msg_HeaderLen;

/* =====================================================================
                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +---------------+---------------+---------------+---------------+
     |    Version    |  PacketType   |         PacketLength          |
     +---------------+---------------+---------------+---------------+
     |           Name Len            |           Name(URI)           /
     +---------------+---------------+---------------+---------------+
     /                                                               |
     +---------------+---------------+---------------+---------------+
  ===================================================================== */

	/* fixed header */
	hdr[CefC_O_Fix_Ver]  = CefC_Version;
	hdr[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_CnpbCntAdd;

	/* Expiry */
	if (exp_date[0] || exp_time[0]) {
		struct tm tm_exp;
		if (conpub_cont_add_parse_date(exp_date, exp_time, &tm_exp) < 0) {
			fprintf(stderr, "Invalid expiry format\n");
			goto ERROR;
		}
		expiry = cef_client_htonb((uint64_t)mktime(&tm_exp));
	} else {
		expiry = cef_client_htonb((uint64_t)time(NULL) + DEFAULT_EXPIRY);
	}

	memcpy(hdr + index, &expiry, sizeof(uint64_t));
	index += sizeof(uint64_t);

	/* Name */
	unsigned char name[CefC_NAME_MAXLEN];
	uint16_t name_len;

	name_len = cef_frame_conversion_uri_to_name(uri, name);
	if (name_len <= 0) {
		fprintf(stderr, "invalid uri\n");
		return -1;
	}
	n16 = htons(name_len);
	memcpy(hdr + index, &n16, sizeof(uint16_t));
	index += sizeof(uint16_t);

	memcpy(hdr + index, name, name_len);
	index += name_len;

	/* FileSize */
	uint64_t fs = cef_client_htonb(fsz);
	memcpy(hdr + index, &fs, sizeof(uint64_t));
	index += sizeof(uint64_t);

	/* PacketLength */
	n16 = htons(index);
	memcpy(hdr + CefC_O_Length, &n16, sizeof(uint16_t));

	/* send header */
	if (send_all(sock, hdr, index) < 0) {
		perror("send header");
		fclose(fp);
		close(sock);
		return -1;
	}

	/* send file body */
	while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
		if (send_all(sock, buf, n) < 0) {
			perror("send_all");
			fclose(fp);
			close(sock);
			return -1;
		}
	}

	fclose(fp);
	close(sock);

	printf("File sent: %s (%" PRIu64 " bytes)\n", filepath, fsz);
	return 0;

ERROR:
	if (sock >= 0)
		close(sock);
	return -1;
}


/*--------------------------------------------------------------------------------------
	Check file path
----------------------------------------------------------------------------------------*/
int
conpub_cont_add_check_file_path(const char* path) {
	FILE* fp = fopen(path, "rb");
	if (!fp) return -1;
	fclose(fp);
	return 1;
}

/*--------------------------------------------------------------------------------------
	Parse expiry date/time
----------------------------------------------------------------------------------------*/
int
conpub_cont_add_parse_date(const char* date_str, const char* time_str, struct tm* date) {
	memset(date, 0, sizeof(struct tm));

	if (date_str && *date_str) {
		int y, m, d;
		if (sscanf(date_str, "%d-%d-%d", &y, &m, &d) != 3) return -1;
		date->tm_year = y - 1900;
		date->tm_mon  = m - 1;
		date->tm_mday = d;
	} else { date->tm_year = 2037 - 1900; date->tm_mon = 12 - 1; date->tm_mday = 31; }

	if (time_str && *time_str) {
		int hh, mm;
		if (sscanf(time_str, "%d:%d", &hh, &mm) != 2) return -1;
		date->tm_hour = hh;
		date->tm_min  = mm;
	} else { date->tm_hour = 23; date->tm_min = 59; }

	date->tm_isdst = -1;
	return 1;
}

/*--------------------------------------------------------------------------------------
	Print usage
----------------------------------------------------------------------------------------*/
static void
print_usage (
	FILE* ofp
) {
	fprintf (ofp,
		"\n\nUsage: conpub_cont_add\n\n"
		"  conpub_cont_add uri -f path [-ed expiry_date] [-et expiry_time] [-h host] [-p port]\n\n"
		"  uri     Specify the URI.\n"
		"  path    Specify the file path of output. \n"
		"  expiry_date  Specifies the expiry_date of the Content.(YYYY-MM-DD)\n"
		"  expiry_time  Specifies the expiry_time of the Content.(hh:mm)\n"
		"  host    Specify the host identifier (e.g., IP address) on which conpubd \n"
		"          is running. The default value is localhost (i.e., 127.0.0.1).\n"
		"  port    Port number to connect conpubd. The default value is %d.\n\n"
		, CefC_CnpbDefault_Tcp_Prot
	);
	return;
}

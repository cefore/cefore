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
 * cef_client.c
 */

#define __CEF_CLIENT_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <poll.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include <cefore/cef_client.h>
#include <cefore/cef_hash.h>
#include <cefore/cef_face.h>
#include <cefore/cef_frame.h>
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

static uint64_t nowtus = 0;
static char cef_lsock_name[256] = {"/tmp/cef_9896.0"};
static char cbd_lsock_name[256] = {"/tmp/cbd_9896.0"};
#ifdef CefC_Android
static size_t cef_lsock_name_len = 0;
static size_t cbd_lsock_name_len = 0;
#endif // CefC_Android
static char cef_conf_dir[PATH_MAX] = {"/usr/local/cefore"};
static int  cef_port_num = CefC_Default_PortNum;
static unsigned char* work_buff = NULL;

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Trims the string buffer read from the config file
----------------------------------------------------------------------------------------*/
static int
cef_client_trim_line_string (
	const char* p1, 							/* target string for trimming 			*/
	char* p2,									/* name string after trimming			*/
	char* p3									/* value string after trimming			*/
);


/****************************************************************************************
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Creats the local socket name 
----------------------------------------------------------------------------------------*/
int 
cef_client_init (
	int port_num, 
	const char* config_file_dir
) {
	char*	wp;
	FILE* 	fp;
	char 	file_path[PATH_MAX];
	char	buff[1024];
	char 	ws[1024];
	char 	pname[1024];
	char 	lsock_id[1024] = {"0"};
	int 	res;
	
	if (config_file_dir[0] != 0x00) {
		sprintf (file_path, "%s/cefnetd.conf", config_file_dir);
		strcpy (cef_conf_dir, config_file_dir);
	} else {
		wp = getenv (CefC_CEFORE_DIR);
		if (wp != NULL && wp[0] != 0) {
			sprintf (file_path, "%s/cefore/cefnetd.conf", wp);
			sprintf (cef_conf_dir, "%s/cefore", wp);
		} else {
			sprintf (file_path, "%s/cefnetd.conf", CefC_CEFORE_DIR_DEF);
			strcpy (cef_conf_dir, CefC_CEFORE_DIR_DEF);
		}
	}
	
	fp = fopen (file_path, "r");
	if (fp == NULL) {
		cef_log_write (CefC_Log_Error, "[client] Failed to open %s\n", file_path);
		return (-1);
	}
	
	/* Reads and records written values in the cefnetd's config file. */
	while (fgets (buff, 1023, fp) != NULL) {
		buff[1023] = 0;
		
		if (buff[0] == 0x23/* '#' */) {
			continue;
		}
		
		res = cef_client_trim_line_string (buff, pname, ws);
		if (res < 0) {
			continue;
		}
		
		if (strcmp (pname, CefC_ParamName_PortNum) == 0) {
			res = atoi (ws);
			if (res < 1025) {
				cef_log_write (CefC_Log_Warn, 
					"[client] PORT_NUM must be higher than 1024.\n");
				fclose (fp);
				return (-1);
			}
			if (res > 65535) {
				cef_log_write (CefC_Log_Warn, 
					"[client] PORT_NUM must be lower than 65536.\n");
				fclose (fp);
				return (-1);
			}
			if (port_num == CefC_Unset_Port) {
				port_num = res;
			}
		} else if (strcmp (pname, CefC_ParamName_LocalSockId) == 0) {
			strcpy (lsock_id, ws);
		}
	}
	if (port_num == CefC_Unset_Port) {
		port_num = CefC_Default_PortNum;
	}
	if (work_buff) {
		free (work_buff);
	}
	work_buff = (unsigned char*) malloc (CefC_AppBuff_Size);
	
#ifdef CefC_Android
	cef_lsock_name[0] = '\0';
	cef_lsock_name_len =
		(size_t)sprintf (cef_lsock_name + 1, "cef_%d.%s", port_num, lsock_id) + 1;
	cbd_lsock_name[0] = '\0';
	cbd_lsock_name_len =
		(size_t)sprintf (cbd_lsock_name + 1, "cbd_%d.%s", port_num, lsock_id) + 1;
	cef_port_num = port_num;
	cef_log_write (CefC_Log_Info, "[client] Config directory is %s\n", cef_conf_dir);
	cef_log_write (CefC_Log_Info, 
		"[client] Local Socket Name is %s\n", cef_lsock_name + 1);
	cef_log_write (CefC_Log_Info, "[client] Listen Port is %d\n", cef_port_num);
#else // CefC_Android
	sprintf (cef_lsock_name, "/tmp/cef_%d.%s", port_num, lsock_id);
	sprintf (cbd_lsock_name, "/tmp/cbd_%d.%s", port_num, lsock_id);
	cef_port_num = port_num;
	cef_log_write (CefC_Log_Info, "[client] Config directory is %s\n", cef_conf_dir);
	cef_log_write (CefC_Log_Info, "[client] Local Socket Name is %s\n", cef_lsock_name);
	cef_log_write (CefC_Log_Info, "[client] Listen Port is %d\n", cef_port_num);
#endif // CefC_Android

	fclose (fp);
	
	return (1);
}
/*--------------------------------------------------------------------------------------
	Gets the local socket name 
----------------------------------------------------------------------------------------*/
int 
cef_client_local_sock_name_get (
	char* local_sock_name
) {
#ifdef CefC_Android
	memcpy (local_sock_name, cef_lsock_name, cef_lsock_name_len);
	return (cef_lsock_name_len);
#else // CefC_Android
	strcpy (local_sock_name, cef_lsock_name);
	return (strlen (cef_lsock_name));
#endif // CefC_Android
}
/*--------------------------------------------------------------------------------------
	Gets the local socket name for cefbabeld
----------------------------------------------------------------------------------------*/
int 
cef_client_babel_sock_name_get (
	char* local_sock_name
) {
#ifdef CefC_Android
	memcpy (local_sock_name, cbd_lsock_name, cbd_lsock_name_len);
	return (cbd_lsock_name_len);
#else // CefC_Android
	strcpy (local_sock_name, cbd_lsock_name);
	return (strlen (cbd_lsock_name));
#endif // CefC_Android
}
/*--------------------------------------------------------------------------------------
	Gets the config file directory
----------------------------------------------------------------------------------------*/
int 
cef_client_config_dir_get (
	char* config_dir
) {
	strcpy (config_dir, cef_conf_dir);
	return (strlen (cef_conf_dir));
}
/*--------------------------------------------------------------------------------------
	Gets the listen port number
----------------------------------------------------------------------------------------*/
int 
cef_client_listen_port_get (
	void 
) {
	return (cef_port_num);
}
/*--------------------------------------------------------------------------------------
	Creats the client handle
----------------------------------------------------------------------------------------*/
CefT_Client_Handle 								/* created client handle 				*/
cef_client_connect (
	void
) {
	CefT_Connect* conn;
	struct sockaddr_un saddr;
	int sock;
	int flag;
	
	if ((sock = socket (AF_UNIX, SOCK_STREAM, 0)) < 0) {
		cef_log_write (CefC_Log_Error, "%s (socket:%s)\n", __func__, strerror(errno));
		return ((CefT_Client_Handle) NULL);
	}

	/* initialize sockaddr_un 		*/
	memset (&saddr, 0, sizeof (saddr));
	saddr.sun_family = AF_UNIX;
#ifdef CefC_Android
	/* Android socket Name starts with \0.	*/
	memcpy (saddr.sun_path, cef_lsock_name, cef_lsock_name_len);
#else // CefC_Android
	strcpy (saddr.sun_path, cef_lsock_name);
#endif // CefC_Android

	/* prepares a source socket 	*/
#ifdef CefC_Android
	/* Android socket Name starts with \0.	*/
	if (connect (sock, (struct sockaddr*) &saddr,
			sizeof (saddr.sun_family) + cef_lsock_name_len) < 0) {
        cef_log_write (CefC_Log_Error, "%s (connect:%s)\n", __func__, strerror(errno));
		close (sock);
		return ((CefT_Client_Handle) NULL);
	}
#else // CefC_Android

#ifdef __APPLE__
	saddr.sun_len = sizeof (saddr);

	if (connect (sock, (struct sockaddr *)&saddr, SUN_LEN (&saddr)) < 0) {
		cef_log_write (CefC_Log_Error, "%s (connect:%s)\n", __func__, strerror(errno));
		close (sock);
		return ((CefT_Client_Handle) NULL);
	}
#else // __APPLE__
	if (connect (sock, (struct sockaddr*) &saddr,
			sizeof (saddr.sun_family) + strlen (cef_lsock_name)) < 0) {
		cef_log_write (CefC_Log_Error, "%s (connect:%s)\n", __func__, strerror(errno));
		close (sock);
		return ((CefT_Client_Handle) NULL);
	}
#endif // __APPLE__

#endif // CefC_Android
	
	flag = fcntl (sock, F_GETFL, 0);
	if (flag < 0) {
		cef_log_write (CefC_Log_Error, "%s (fcntl:%s)\n", __func__, strerror(errno));
		close (sock);
		return ((CefT_Client_Handle) NULL);
	}
	if (fcntl (sock, F_SETFL, flag | O_NONBLOCK) < 0) {
		cef_log_write (CefC_Log_Error, "%s (fcntl:%s)\n", __func__, strerror(errno));
		close (sock);
		return ((CefT_Client_Handle) NULL);
	}

	conn = (CefT_Connect*) malloc (sizeof (CefT_Connect));
	memset (conn, 0, sizeof (CefT_Connect));
	conn->sock = sock;

	return ((CefT_Client_Handle) conn);
}

/*--------------------------------------------------------------------------------------
	Creats the client handle with the specified type of socket
----------------------------------------------------------------------------------------*/
CefT_Client_Handle 								/* created client handle 				*/
cef_client_connect_cli_core (
	int sk_type									/* type of socket 						*/
) {
	CefT_Connect* conn;
	struct sockaddr_un saddr;
	const int sk_domain = AF_UNIX;
	const int sk_protocol = 0;
	int sock;
	int flag;
	
	if ((sock = socket (sk_domain, sk_type, sk_protocol)) < 0) {
		cef_log_write (CefC_Log_Error, "%s (socket:%s)\n", __func__, strerror(errno));
		return ((CefT_Client_Handle) NULL);
	}

	/* initialize sockaddr_un 		*/
	memset (&saddr, 0, sizeof (saddr));
	saddr.sun_family = sk_domain;
#ifdef CefC_Android
	/* Android socket Name starts with \0.	*/
	memcpy(saddr.sun_path, cef_lsock_name, cef_lsock_name_len);
#else // CefC_Android
	strcpy (saddr.sun_path, cef_lsock_name);
#endif // CefC_Android

	/* prepares a source socket 	*/
#ifdef CefC_Android
	/* Android socket Name starts with \0.	*/
	if (connect (sock, (struct sockaddr*) &saddr,
			sizeof (saddr.sun_family) + cef_lsock_name_len) < 0){
        cef_log_write (CefC_Log_Error, "%s (connect:%s)\n", __func__, strerror(errno));
		close (sock);
		return ((CefT_Client_Handle) NULL);
	}

#else // CefC_Android

#ifdef __APPLE__
	saddr.sun_len = sizeof (saddr);

	if (connect (sock, (struct sockaddr *)&saddr, SUN_LEN (&saddr)) < 0) {
		close (sock);
		return ((CefT_Client_Handle) NULL);
	}
#else // __APPLE__
	if (connect (sock, (struct sockaddr*) &saddr,
			sizeof (saddr.sun_family) + strlen (cef_lsock_name)) < 0){
		cef_log_write (CefC_Log_Error, "%s (connect:%s)\n", __func__, strerror(errno));
		close (sock);
		return ((CefT_Client_Handle) NULL);
	}
#endif // __APPLE__

#endif // CefC_Android

	flag = fcntl (sock, F_GETFL, 0);
	if (flag < 0) {
		cef_log_write (CefC_Log_Error, "%s (fcntl:%s)\n", __func__, strerror(errno));
		close (sock);
		return ((CefT_Client_Handle) NULL);
	}
	if (fcntl (sock, F_SETFL, flag | O_NONBLOCK) < 0) {
		cef_log_write (CefC_Log_Error, "%s (fcntl:%s)\n", __func__, strerror(errno));
		close (sock);
		return ((CefT_Client_Handle) NULL);
	}

	conn = (CefT_Connect*) malloc (sizeof (CefT_Connect));
	memset (conn, 0, sizeof (CefT_Connect));
	conn->sock = sock;

	return ((CefT_Client_Handle) conn);
}

/*--------------------------------------------------------------------------------------
	Creats the client handle with the SOCK_STREAM socket
----------------------------------------------------------------------------------------*/
CefT_Client_Handle 								/* created client handle 				*/
cef_client_connect_cli (
	void
) {
	return (cef_client_connect_cli_core (SOCK_STREAM));
}

/*--------------------------------------------------------------------------------------
	Creats the client handle with the SOCK_DGRAM socket
----------------------------------------------------------------------------------------*/
CefT_Client_Handle 								/* created client handle 				*/
cef_client_connect_srv (
	void
) {
	CefT_Connect* conn;
	char destination[] = {"127.0.0.1"};
	struct addrinfo hints;
	struct addrinfo* res;
	struct addrinfo* cres;
	int err;
	char port_str[32];
	int sock;
	int flag;
	
	memset (&hints, 0, sizeof (hints));
	hints.ai_family =  AF_INET;
	hints.ai_socktype = SOCK_DGRAM;

	sprintf (port_str, "%d", cef_port_num);

	if ((err = getaddrinfo (destination, port_str, &hints, &res)) != 0) {
		cef_log_write (CefC_Log_Error, 
			"%s (getaddrinfo:%s)\n", __func__, gai_strerror(err));
		return (-1);
	}

	for (cres = res ; cres != NULL ; cres = res) {
		res = cres->ai_next;

		sock = socket (cres->ai_family, cres->ai_socktype, 0);

		if (sock < 0) {
			cef_log_write (CefC_Log_Error, "%s (socket:%s)\n", __func__, strerror(errno));
			return ((CefT_Client_Handle) NULL);
		}

		flag = fcntl (sock, F_GETFL, 0);
		if (flag < 0) {
			cef_log_write (CefC_Log_Error, "%s (fcntl:%s)\n", __func__, strerror(errno));
			return ((CefT_Client_Handle) NULL);
		}
		if (fcntl (sock, F_SETFL, flag | O_NONBLOCK) < 0) {
			cef_log_write (CefC_Log_Error, "%s (fcntl:%s)\n", __func__, strerror(errno));
			return ((CefT_Client_Handle) NULL);
		}

		cres->ai_next = NULL;

		freeaddrinfo (res);
		conn = (CefT_Connect*) malloc (sizeof (CefT_Connect));
		memset (conn, 0, sizeof (CefT_Connect));
		conn->sock = sock;
		conn->ai = cres;

		freeaddrinfo (res);
		return ((CefT_Client_Handle) conn);
	}
	cef_log_write (CefC_Log_Error, "%s (fatal)\n", __func__);
	
	return ((CefT_Client_Handle) NULL);
}

/*--------------------------------------------------------------------------------------
	Destroys the specified client handle
----------------------------------------------------------------------------------------*/
void
cef_client_close (
	CefT_Client_Handle fhdl 					/* client handle to be destroyed 		*/
) {
	CefT_Connect* conn = (CefT_Connect*) fhdl;

	if (conn->ai) {
		free (conn);
	} else {
		send (conn->sock, CefC_Face_Close, strlen (CefC_Face_Close), 0);
		close (conn->sock);
		free (conn);
	}
	if (work_buff) {
		free (work_buff);
		work_buff = NULL;
	}
	
	return;
}
/*--------------------------------------------------------------------------------------
	Register/Deregister the specified Name of the Application
----------------------------------------------------------------------------------------*/
void
cef_client_name_reg (
	CefT_Client_Handle fhdl, 					/* client handle						*/
	uint16_t func, 								/* CefC_App_Reg/CefC_App_DeReg 			*/
	const unsigned char* name,					/* Name (not URI)						*/
	uint16_t name_len							/* length of the Name					*/
) {
	CefT_Connect* conn = (CefT_Connect*) fhdl;
	CefT_Interest_TLVs tlvs;
	unsigned char buff[CefC_Max_Length];
	int len;
	
	memset (&tlvs, 0, sizeof (CefT_Interest_TLVs));
	
	memcpy (tlvs.name, name, name_len);
	tlvs.name_len = name_len;
	tlvs.hoplimit 		= 1;
	tlvs.opt.lifetime_f = 1;
	tlvs.opt.lifetime 	= 1;
	
	if (func == CefC_App_Reg) {
		tlvs.opt.symbolic_f = CefC_T_OPT_APP_REG;
	} else {
		tlvs.opt.symbolic_f = CefC_T_OPT_APP_DEREG;
	}
	
	len = cef_frame_interest_create (buff, &tlvs);
	if (len > 0) {
		if (conn->ai) {
			sendto (conn->sock, buff, len
					, 0, conn->ai->ai_addr, conn->ai->ai_addrlen);
		} else {
			send (conn->sock, buff, len, 0);
		}
	}
	
	return;
}

/*--------------------------------------------------------------------------------------
	Inputs the unformatted message to the socket
----------------------------------------------------------------------------------------*/
int
cef_client_message_input (
	CefT_Client_Handle fhdl,					/* client handle 						*/
	unsigned char* msg,							/* message 								*/
	size_t len									/* length of message 					*/
) {
	CefT_Connect* conn = (CefT_Connect*) fhdl;
	
	if (len > 0) {
		if (conn->ai) {
			sendto (conn->sock, msg, len
					, 0, conn->ai->ai_addr, conn->ai->ai_addrlen);
		} else {
			send (conn->sock, msg, len, 0);
		}
	}
	
	return (1);
}

/*--------------------------------------------------------------------------------------
	Inputs the interest to the cefnetd
----------------------------------------------------------------------------------------*/
int												/* length of the created interest 		*/
cef_client_interest_input (
	CefT_Client_Handle fhdl,					/* client handle 						*/
	CefT_Interest_TLVs* tlvs					/* parameters to create the interest 	*/
) {
	CefT_Connect* conn = (CefT_Connect*) fhdl;
	unsigned char buff[CefC_Max_Length];
	int len;
	
	len = cef_frame_interest_create (buff, tlvs);
	if (len > 0) {
		if (conn->ai) {
			sendto (conn->sock, buff, len
					, 0, conn->ai->ai_addr, conn->ai->ai_addrlen);
		} else {
			send (conn->sock, buff, len, 0);
		}
	}
	
	return (len);
}

/*--------------------------------------------------------------------------------------
	Inputs the object to the cefnetd
----------------------------------------------------------------------------------------*/
int												/* length of the created object 		*/
cef_client_object_input (
	CefT_Client_Handle fhdl,					/* client handle 						*/
	CefT_Object_TLVs* tlvs						/* parameters to create the object 		*/
) {
	CefT_Connect* conn = (CefT_Connect*) fhdl;
	unsigned char buff[CefC_Max_Length];
	int len;
	
	len = cef_frame_object_create (buff, tlvs);
	
	if (len > 0) {
		conn->seqnum++;
		cef_frame_seqence_update (buff, conn->seqnum);
		
		if (conn->ai) {
			sendto (conn->sock, buff, len
				, 0, conn->ai->ai_addr, conn->ai->ai_addrlen);
		} else {
			send (conn->sock, buff, len, 0);
		}
	}

	return (1);
}

#ifdef CefC_Cefping
/*--------------------------------------------------------------------------------------
	Inputs the cefping to the cefnetd
----------------------------------------------------------------------------------------*/
int												/* length of the created cefping 		*/
cef_client_cefping_input (
	CefT_Client_Handle fhdl,					/* client handle 						*/
	CefT_Ping_TLVs* tlvs						/* parameters to create the cefping		*/
) {
	CefT_Connect* conn = (CefT_Connect*) fhdl;
	unsigned char buff[CefC_Max_Length];
	int len;

	len = cef_frame_cefping_req_create (buff, tlvs);
	if (len > 0) {
		if (conn->ai) {
			sendto (conn->sock, buff, len
				, 0, conn->ai->ai_addr, conn->ai->ai_addrlen);
		} else {
			send (conn->sock, buff, len, 0);
		}
	}

	return (1);
}
#endif // CefC_Cefping

#ifdef CefC_Cefinfo
/*--------------------------------------------------------------------------------------
	Inputs the cefinfo request to the cefnetd
----------------------------------------------------------------------------------------*/
int												/* length of the created cefinfo 		*/
cef_client_cefinfo_input (
	CefT_Client_Handle fhdl,					/* client handle 						*/
	CefT_Trace_TLVs* tlvs						/* parameters to create the cefinfo	*/
) {
	CefT_Connect* conn = (CefT_Connect*) fhdl;
	unsigned char buff[CefC_Max_Length];
	int len;
	
	len = cef_frame_cefinfo_req_create (buff, tlvs);
	if (len > 0) {
		if (conn->ai) {
			sendto (conn->sock, buff, len
				, 0, conn->ai->ai_addr, conn->ai->ai_addrlen);
		} else {
			send (conn->sock, buff, len, 0);
		}
	}
	
	return (1);
}
#endif // CefC_Cefinfo

/*--------------------------------------------------------------------------------------
	Reads the message from the specified connection (socket)
----------------------------------------------------------------------------------------*/
int 											/* length of read buffer 				*/
cef_client_read (
	CefT_Client_Handle fhdl, 					/* client handle 						*/
	unsigned char* buff, 						/* buffer to write the message 			*/
	int len 									/* length of buffer 					*/
) {
	CefT_Connect* conn = (CefT_Connect*) fhdl;
	int recv_len = 0;
	struct pollfd infds[1];
	struct sockaddr_storage sas;
	socklen_t sas_len = (socklen_t) sizeof (struct sockaddr_storage);

	infds[0].fd = conn->sock;
	infds[0].events = POLLIN | POLLERR;

	poll (infds, 1, 1);

	if (infds[0].revents != 0) {
		if (infds[0].revents & (POLLERR | POLLNVAL | POLLHUP)) {
			if (conn->ai) {
				recv_len = recvfrom (
						conn->sock, buff, len, 0, (struct sockaddr*) &sas, &sas_len);
			} else {
				recv_len = recv (conn->sock, buff, len, 0);
			}
			/* TBD: Error Process */
		}
		if (infds[0].revents & POLLIN) {
			if (conn->ai) {
				recv_len = recvfrom (
						conn->sock, buff, len, 0, (struct sockaddr*) &sas, &sas_len);
			} else {
				recv_len = recv (conn->sock, buff, len, 0);
			}
		}
	}

	return (recv_len);
}

/*--------------------------------------------------------------------------------------
	Obtains one message from the buffer
----------------------------------------------------------------------------------------*/
int 											/* remaining length of buffer 			*/
cef_client_payload_get (
	unsigned char* buff, 						/* buffer 								*/
	int buff_len, 								/* length of buffer 					*/
	unsigned char* frame, 						/* variable to write one message 		*/
	int* frame_size 							/* length of one message 				*/
) {
	struct cef_app_frame* app_frame;
	int i = 0;
	int new_len = 0;
	
	if (buff_len < sizeof (struct cef_app_frame)) {
		return (buff_len);
	}
	
	app_frame = (struct cef_app_frame*) &buff[i];
	
	if ((app_frame->version != CefC_App_Version) || 
		(app_frame->type != CefC_App_Type_Internal)) {
		
		while (i < buff_len) {
			i++;
			app_frame = (struct cef_app_frame*) &buff[i];
			
			if ((app_frame->version != CefC_App_Version) ||
				(app_frame->type != CefC_App_Type_Internal)) {
				continue;
			}
			break;
		}
		if  (i == buff_len) {
			return (0);
		}
	}
	
	if (buff_len - i < sizeof (struct cef_app_frame)) {
		new_len = buff_len - i;
	} else {
		new_len = buff_len - sizeof (struct cef_app_frame);
		memcpy (frame, app_frame->payload, app_frame->payload_len);
		i += sizeof (struct cef_app_frame);
	}
	
	if (new_len > 0) {
		memcpy (&work_buff[0], &buff[i], new_len);
		memcpy (&buff[0], &work_buff[0], new_len);
	}
	
	return (new_len);
}

/*--------------------------------------------------------------------------------------
	Obtains one message from the buffer
----------------------------------------------------------------------------------------*/
int 											/* remaining length of buffer 			*/
cef_client_payload_get_with_info (
	unsigned char* buff, 
	int buff_len, 
	struct cef_app_frame* app_frame
) {
	struct cef_app_frame* wrk_frame;
	int i = 0;
	int new_len = 0;
	
	/* Check if the frame is complete 	*/
	memset (app_frame, 0, sizeof (struct cef_app_frame));
	
//	fprintf (stderr, "# [1] %d bytes (%d)\n"
//		, buff_len, (int) sizeof (struct cef_app_frame));
	
	if (buff_len < sizeof (struct cef_app_frame)) {
//		fprintf (stderr, "# [2] %d bytes\n", buff_len);
		return (buff_len);
	}
	
	/* Seek the head of message 		*/
	wrk_frame = (struct cef_app_frame*) &buff[i];
	
	if ((wrk_frame->version != CefC_App_Version) || 
		(wrk_frame->type != CefC_App_Type_Internal)) {
		
		while (i < buff_len) {
			i++;
			wrk_frame = (struct cef_app_frame*) &buff[i];
			
			if ((app_frame->version != CefC_App_Version) ||
				(app_frame->type != CefC_App_Type_Internal)) {
				continue;
			}
			break;
		}
		if  (i == buff_len) {
//			fprintf (stderr, "# [3] 0 bytes\n");
			return (0);
		}
	}
	
	if (buff_len - i < sizeof (struct cef_app_frame)) {
//		fprintf (stderr, "# [4] %d bytes\n", new_len);
		new_len = buff_len - i;
	} else {
		new_len = buff_len - sizeof (struct cef_app_frame);
		memcpy (app_frame, &buff[i], sizeof (struct cef_app_frame));
		i += sizeof (struct cef_app_frame);
//		fprintf (stderr, "# [5] %d bytes\n", new_len);
	}
	
	if (new_len > 0) {
//		fprintf (stderr, "# [6] %d \n", i);
		memcpy (&work_buff[0], &buff[i], new_len);
		memcpy (&buff[0], &work_buff[0], new_len);
	}
	
	return (new_len);
}

uint64_t
cef_client_covert_timeval_to_us (
	struct timeval t
) {
	uint64_t tus;
	tus = t.tv_sec * 1000000 + t.tv_usec;
	return (tus);
}
uint64_t
cef_client_present_timeus_calc (
	void
) {
	struct timeval t;

	gettimeofday (&t, NULL);
	nowtus = t.tv_sec * 1000000 + t.tv_usec;

	return (nowtus);
}
uint64_t
cef_client_present_timeus_get (
	void
) {
	return (nowtus);
}

uint64_t
cef_client_htonb (
	uint64_t x
) {
	int y = 1;
	if (*(char*)&y) {
		/* host is little endian. */
		return ((x & 0xFF00000000000000ull) >> 56) |
			   ((x & 0x00FF000000000000ull) >> 40) |
			   ((x & 0x0000FF0000000000ull) >> 24) |
			   ((x & 0x000000FF00000000ull) >>  8) |
			   ((x & 0x00000000FF000000ull) <<  8) |
			   ((x & 0x0000000000FF0000ull) << 24) |
			   ((x & 0x000000000000FF00ull) << 40) |
			   ((x & 0x00000000000000FFull) << 56);
	} else {
		/* host is Big endian. */
		return (x);
	}
}

uint64_t
cef_client_ntohb (
	uint64_t x
) {
	return (cef_frame_htonb (x));
}

/*--------------------------------------------------------------------------------------
	Trims the string buffer read from the config file
----------------------------------------------------------------------------------------*/
static int
cef_client_trim_line_string (
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


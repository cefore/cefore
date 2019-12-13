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
 * cef_face.c
 */

#define __CEF_FACE_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <cefore/cef_hash.h>
#include <cefore/cef_face.h>
#include <cefore/cef_frame.h>
#include <cefore/cef_log.h>
#include <cefore/cef_client.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

#define CefC_Face_Type_Num			4
#define CefC_Face_Type_Invalid		0x00
#define CefC_Face_Type_Tcp			0x01
#define CefC_Face_Type_Udp			0x02
#define CefC_Face_Type_Local		0x03

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

/****************************************************************************************
 State Variables
 ****************************************************************************************/
static CefT_Hash_Handle sock_tbl;				/* Socket Table							*/
static CefT_Face* face_tbl = NULL;				/* Face Table							*/
static uint16_t max_tbl_size = 0;				/* Maximum size of the Tables			*/
static uint16_t process_port_num = 0;			/* The port number that cefnetd uses	*/
static uint16_t assigned_faceid = CefC_Face_Reserved;
												/* Face-ID to assign next				*/
static int doing_ip_version[2] = { 0, 0 };
												/* Version of IP that cefnetd uses		*/
												/* [0]v4, [1]v6							*/
static char local_sock_path[1024];
static int local_sock_path_len = 0;
static char babel_sock_path[1024];
static int babel_sock_path_len = 0;

static int my_udp_listen_port_num = 0;
static int my_tcp_listen_port_num = 0;

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Deallocates the specified addrinfo
----------------------------------------------------------------------------------------*/
static void
cef_face_addrinfo_free (
	struct addrinfo* ai						/* addrinfo to free 						*/
);
/*--------------------------------------------------------------------------------------
	Creates a new entry of Socket Table
----------------------------------------------------------------------------------------*/
static CefT_Sock*							/* the created new entry					*/
cef_face_sock_entry_create (
	int sock, 								/* file descriptor to register				*/
	struct sockaddr* ai_addr,
	socklen_t ai_addrlen, 
	int ai_family
);
/*--------------------------------------------------------------------------------------
	Destroy the specified entry of Socket Table
----------------------------------------------------------------------------------------*/
static void
cef_face_sock_entry_destroy (
	CefT_Sock* entry						/* the entry to destroy						*/
);
/*--------------------------------------------------------------------------------------
	Creates the peer ID 
----------------------------------------------------------------------------------------*/
static void 
cef_face_peer_id_create (
	const char* destination, 				/* String of the destination address 		*/
	int protocol,							/* protoco (udp,tcp,local) 					*/
	char* peer_id, 
	char* usr_id, 
	char* port_str
);
/*--------------------------------------------------------------------------------------
	Looks up Face-ID that is not used
----------------------------------------------------------------------------------------*/
static int									/* Face-ID that is not used					*/
cef_face_unused_faceid_search (
	void
);
/*--------------------------------------------------------------------------------------
	Looks up and creates the specified Face
----------------------------------------------------------------------------------------*/
static int									/* Face-ID									*/
cef_face_lookup_faceid (
	int protocol,
	char* peer_id, 
	char* usr_id, 
	char* port_str, 
	int* create_f
);
/*--------------------------------------------------------------------------------------
	Set the informations and payload for the applications
----------------------------------------------------------------------------------------*/
static int
cef_face_app_sdu_create (
	struct cef_app_frame* app_frame, 
	unsigned char* name, 
	uint16_t name_len, 
	unsigned char* payload, 
	uint16_t payload_len, 
	uint32_t chnk_num
);

#ifdef CefC_DebugOld
/****************************************************************************************
 For Debug Trace
 ****************************************************************************************/

extern unsigned int CEF_DEBUG;

#endif // CefC_DebugOld

/****************************************************************************************
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Initialize the face module
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cef_face_init (
	uint8_t 	node_type					/* Node Type (Router/Receiver....)			*/
){
	int		i;
	
	/* Creates the Socket Table and Face Table 		*/
	if (face_tbl != NULL) {
		cef_log_write (CefC_Log_Error, "%s (face_tbl)\n", __func__);
		return (-1);
	}
	switch (node_type) {
		case CefC_Node_Type_Receiver: {
			max_tbl_size = CefC_Face_Receiver_Max;
			break;
		}
		case CefC_Node_Type_Publisher: {
			max_tbl_size = CefC_Face_Publisher_Max;
			break;
		}
		case CefC_Node_Type_Router: {
			max_tbl_size = CefC_Face_Router_Max;
			break;
		}
		default: {
			/* NOP */;
			break;
		}
	}
	if (max_tbl_size == 0) {
		cef_log_write (CefC_Log_Error, "%s (max_tbl_size)\n", __func__);
		return (-1);
	}
	
	face_tbl = (CefT_Face*) malloc (sizeof (CefT_Face) * max_tbl_size);
	memset (face_tbl, 0, sizeof (CefT_Face) * max_tbl_size);
	for (i = 0; i < max_tbl_size; i++)
		face_tbl[i].ifindex = -1;
	sock_tbl = cef_hash_tbl_create ((uint16_t) max_tbl_size);
	
	local_sock_path_len = cef_client_local_sock_name_get (local_sock_path);
	babel_sock_path_len = cef_client_babel_sock_name_get (babel_sock_path);
	
	return (1);
}
/*--------------------------------------------------------------------------------------
	Looks up and creates the Face from the specified string of destination address
----------------------------------------------------------------------------------------*/
int											/* Face-ID									*/
cef_face_lookup_faceid_from_addrstr (
	const char* destination,				/* String of destination address 			*/
	const char* protocol					/* protoco (udp,tcp,local) 					*/
) {
	int faceid;
	int create_f = 0;
#ifdef CefC_Neighbour
	int msg_len;
	unsigned char buff[CefC_Max_Length];
#endif
	int prot_index = CefC_Face_Type_Invalid;
	char port_str[32];
	char peer_id[512];
	char usr_id[512];
	
	if (strcmp (protocol, "udp") == 0) {
		prot_index = CefC_Face_Type_Udp;
	}
	if (strcmp (protocol, "tcp") == 0) {
		prot_index = CefC_Face_Type_Tcp;
	}
	port_str[0] = 0x00;
	cef_face_peer_id_create (destination, prot_index, peer_id, usr_id, port_str);
	
	faceid = cef_face_lookup_faceid (prot_index, peer_id, usr_id, port_str, &create_f);
	
	if ((faceid > 0) && (create_f)) {
		
#ifdef CefC_Neighbour
		/* send a link message */
		msg_len = cef_frame_interest_link_msg_create (buff);
		
		if (msg_len > 0) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finer, 
				"Send a Interest Link message to FID#%d\n", faceid);
#endif // CefC_Debug
			cef_face_frame_send_forced (faceid, buff, (size_t) msg_len);
		}
#endif
		
	}
	
	return (faceid);
}
/*--------------------------------------------------------------------------------------
	Searches the specified Face
----------------------------------------------------------------------------------------*/
int											/* Face-ID									*/
cef_face_search_faceid (
	const char* destination, 				/* String of the destination address 		*/
	const char* protocol					/* protoco (udp,tcp,local) 					*/
) {
	int prot_index = CefC_Face_Type_Invalid;
	char port_str[32];
	char peer_id[512];
	char usr_id[512];
	CefT_Sock* entry;
	
	if (strcmp (protocol, "udp") == 0) {
		prot_index = CefC_Face_Type_Udp;
	}
	if (strcmp (protocol, "tcp") == 0) {
		prot_index = CefC_Face_Type_Tcp;
	}
	
	port_str[0] = 0x00;
	cef_face_peer_id_create (destination, prot_index, peer_id, usr_id, port_str);
	
	entry = (CefT_Sock*) cef_hash_tbl_item_get (
				sock_tbl, (const unsigned char*) peer_id, strlen (peer_id));
	if (entry) {
		return (entry->faceid);
	}
	
	return (-1);
}
/*--------------------------------------------------------------------------------------
	Updates the listen faces
----------------------------------------------------------------------------------------*/
int
cef_face_update_listen_faces (
	struct pollfd* inudpfds,
	uint16_t* inudpfaces, 
	uint8_t* inudpfdc, 
	struct pollfd* intcpfds,
	uint16_t* intcpfaces, 
	uint8_t* intcpfdc
) {
	int i;
	int new_inudpfdc = 2;
	int new_intcpfdc = 0;

	for (i = CefC_Face_Reserved ; i < assigned_faceid ; i++) {
		
		if (face_tbl[i].fd > 0) {
			if (face_tbl[i].protocol == CefC_Face_Type_Tcp) {
				intcpfaces[new_intcpfdc] = i;
				intcpfds[new_intcpfdc].fd = face_tbl[i].fd;
				intcpfds[new_intcpfdc].events = POLLIN | POLLERR;
				new_intcpfdc++;
			} else if (face_tbl[i].protocol == CefC_Face_Type_Udp) {
				inudpfaces[new_inudpfdc] = i;
				inudpfds[new_inudpfdc].fd = face_tbl[i].fd;
				inudpfds[new_inudpfdc].events = POLLIN | POLLERR;
				new_inudpfdc++;
			}
		}
	}
	*inudpfdc = new_inudpfdc;
	*intcpfdc = new_intcpfdc;
	
	return (1);
}
/*--------------------------------------------------------------------------------------
	Looks up and creates the peer Face
----------------------------------------------------------------------------------------*/
int											/* Peer Face-ID 							*/
cef_face_lookup_peer_faceid (
	struct addrinfo* sas, 					/* sockaddr_storage structure				*/
	socklen_t sas_len,						/* length of sockaddr_storage				*/
	int protocol
) {
	char 	name[NI_MAXHOST];
	int 	result;
	CefT_Sock* entry;
	int 	faceid;
	char port_str[32];
	char peer_id[512];
	char usr_id[512];
	
	/* Obtains the source node's information 	*/
	result = getnameinfo ((struct sockaddr*) sas, sas_len, 
				name, sizeof (name), port_str, sizeof (port_str), NI_NUMERICHOST | NI_NUMERICSERV);
	if (result != 0) {
		cef_log_write (CefC_Log_Error, "%s (getnameinfo:%s)\n", __func__, gai_strerror(result));
		return (-1);
	}
	
	/* Looks up the source node's information from the source table 	*/
	cef_face_peer_id_create (name, protocol, peer_id, usr_id, port_str);
	entry = (CefT_Sock*) cef_hash_tbl_item_get (
									sock_tbl,
									(const unsigned char*) peer_id, strlen (peer_id));
	if (entry) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest, 
			"[face] Lookup the Face#%d for %s\n", entry->faceid, peer_id);
#endif // CefC_Debug
		return (entry->faceid);
	}
	
	faceid = cef_face_lookup_faceid (protocol, peer_id, usr_id, port_str, NULL);
	
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finer, 
		"[face] Creation the new Face#%d for %s\n", faceid, peer_id);
#endif // CefC_Debug
	
	return (faceid);
}
/*--------------------------------------------------------------------------------------
	Searches and creates the local Face-ID corresponding to the specified FD
----------------------------------------------------------------------------------------*/
int												/* the corresponding Face-ID			*/
cef_face_lookup_local_faceid (
	int fd										/* File descriptor						*/
) {
	char 	name[1024];
	int 	faceid;
	int 	index;
	CefT_Sock* entry;

	/* Creates the name for the local socket 	*/
	sprintf (name, "app-face-%d", fd);

	/* Looks up the source node's information from the source table 	*/
	entry = (CefT_Sock*) cef_hash_tbl_item_get (
									sock_tbl, (const unsigned char*)name, strlen (name));
	if (entry) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finer, 
			"[face] Lookup the Face#%d (FD#%d) for local peer\n", entry->faceid, fd);
#endif // CefC_Debug
		/* Finds and returns an existing entry 	*/
		return (entry->faceid);
	}

	/* Looks up Face-ID that is not used 		*/
	faceid = cef_face_unused_faceid_search ();
	if (faceid < 0) {
		return (-1);
	}

	/* Creates a new entry of Socket Table 		*/
	entry = cef_face_sock_entry_create (fd, NULL, 0, -1);
	entry->faceid = faceid;

	/* Sets the created entry into Socket Table	*/
	index = cef_hash_tbl_item_set (
							sock_tbl, (const unsigned char*)name, strlen (name), entry);

	if (index < 0) {
		cef_face_sock_entry_destroy (entry);
		return (-1);
	}

	/* Registers the created entry into Face Table	*/
	face_tbl[faceid].index = index;
	face_tbl[faceid].fd = entry->sock;
	face_tbl[faceid].local_f = 1;
	
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finer, 
		"[face] Creation the new Face#%d (FD#%d) for local peer\n", entry->faceid, fd);
#endif // CefC_Debug
	
	return (faceid);
}
/*--------------------------------------------------------------------------------------
	Closes the specified Face
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cef_face_close (
	int faceid								/* Face-ID									*/
) {
	CefT_Sock* entry;
	
	entry = (CefT_Sock*) cef_hash_tbl_item_remove_from_index (
										sock_tbl, face_tbl[faceid].index);
	
	if (entry) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finer, 
			"[face] Close the Face#%d (FD#%d)\n", faceid, face_tbl[entry->faceid].fd);
#endif // CefC_Debug
		face_tbl[faceid].index 		= 0;
		face_tbl[faceid].fd 		= 0;
		face_tbl[faceid].protocol 	= CefC_Face_Type_Invalid;
		close (entry->sock);
		free (entry);
	}

	return (1);
}
/*--------------------------------------------------------------------------------------
	Half-closes the specified Face
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cef_face_down (
	int faceid								/* Face-ID									*/
) {
	CefT_Sock* entry;
	
	entry = (CefT_Sock*) cef_hash_tbl_item_get_from_index (
										sock_tbl, face_tbl[faceid].index);
	
	if (entry) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finer, 
			"[face] Down the Face#%d (FD#%d)\n", faceid, face_tbl[entry->faceid].fd);
#endif // CefC_Debug
		face_tbl[faceid].fd = 0;
	}
	
	return (1);
}
/*--------------------------------------------------------------------------------------
	Checks the specified Face is active or not
----------------------------------------------------------------------------------------*/
int										/* Returns the value less than 1 if it fails 	*/
cef_face_check_active (
	int faceid								/* Face-ID									*/
) {
	return (face_tbl[faceid].fd);
}
/*--------------------------------------------------------------------------------------
	Checks the specified Face is close or not
----------------------------------------------------------------------------------------*/
int										/* Returns the value less than 1 if it fails 	*/
cef_face_check_close (
	int faceid								/* Face-ID									*/
) {
	return (face_tbl[faceid].protocol == CefC_Face_Type_Invalid);
}
/*--------------------------------------------------------------------------------------
	Creates the listening UDP socket with the specified port
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cef_face_udp_listen_face_create (
	uint16_t 		port_num,				/* Port Number that cefnetd listens			*/
	int*			res_v4,
	int*			res_v6
) {
	struct addrinfo hints;
	struct addrinfo* res;
	struct addrinfo* cres;
	int err;
	char port_str[32];
	int sock;
	CefT_Sock* entryv4 = NULL;
	CefT_Sock* entryv6 = NULL;
	char ip_str[64];
	char if_str[128];
	int indexv4 = -1;
	int indexv6 = -1;
	int ret_val = 0;

	my_udp_listen_port_num = port_num;
	
	memset (&hints, 0, sizeof (hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	process_port_num = port_num;

	sprintf (port_str, "%d", port_num);

	if ((err = getaddrinfo (NULL, port_str, &hints, &res)) != 0) {
		cef_log_write (CefC_Log_Error, 
			"%s (getaddrinfo:%s)\n", __func__, gai_strerror(err));
		return (-1);
	}

	for (cres = res ; cres != NULL ; cres = res) {
		res = cres->ai_next;

		sock = socket (cres->ai_family, cres->ai_socktype, 0);
		if (sock < 0) {
			continue;
		}

		{
			int reuse_f = 1;
			setsockopt (sock,
				SOL_SOCKET, SO_REUSEADDR, &reuse_f, sizeof (reuse_f));
			setsockopt (sock,
				SOL_SOCKET, SO_REUSEPORT, &reuse_f, sizeof (reuse_f));
		}
		memset (ip_str, 0, 64);
		if (getnameinfo (cres->ai_addr, (int)cres->ai_addrlen
				, ip_str, sizeof (ip_str), 0, 0,  NI_NUMERICHOST) != 0) {
			continue;
		}
		sprintf (if_str, "%s:udp", ip_str);

		switch (cres->ai_family) {
			case AF_INET: {
				if (indexv4 >= 0) {
					cef_face_addrinfo_free (cres);
					close (sock);
				} else {
					cres->ai_next = NULL;
					entryv4 = cef_face_sock_entry_create (
								sock, cres->ai_addr, cres->ai_addrlen, cres->ai_family);
					entryv4->faceid = CefC_Faceid_ListenUdpv4;
					entryv4->protocol = CefC_Face_Type_Udp;
					indexv4 = cef_hash_tbl_item_set (
						sock_tbl, (const unsigned char*)if_str, strlen (if_str), entryv4);
				}
				break;
			}
			case AF_INET6: {
				if (indexv6 >= 0) {
					cef_face_addrinfo_free (cres);
					close (sock);
				} else {
					cres->ai_next = NULL;
					entryv6 = cef_face_sock_entry_create (
								sock, cres->ai_addr, cres->ai_addrlen, cres->ai_family);
					entryv6->faceid = CefC_Faceid_ListenUdpv6;
					entryv6->protocol = CefC_Face_Type_Udp;
					indexv6 = cef_hash_tbl_item_set (
						sock_tbl, (const unsigned char*)if_str, strlen (if_str), entryv6);
				}
				break;
			}
			default: {
				/* NOP */;
				break;
			}
		}
		errno = 0;
		if (indexv4 >= 0) {
			if (bind (entryv4->sock, entryv4->ai_addr, entryv4->ai_addrlen) < 0) {
				close (entryv4->sock);
				face_tbl[CefC_Faceid_ListenUdpv4].index = indexv4;
				face_tbl[CefC_Faceid_ListenUdpv4].fd = 0;
				cef_log_write (CefC_Log_Error, 
					"[face] Failed to create the listen face with UDP (%s)\n", strerror(errno));
				ret_val = -1;
			} else {
				doing_ip_version[0] = AF_INET;
				face_tbl[CefC_Faceid_ListenUdpv4].index = indexv4;
				face_tbl[CefC_Faceid_ListenUdpv4].fd = entryv4->sock;
				face_tbl[CefC_Faceid_ListenUdpv4].protocol = CefC_Face_Type_Udp;
				*res_v4 = CefC_Faceid_ListenUdpv4;
			}
		}
	
		errno = 0;
		if (indexv6 >= 0) {
			if (bind (entryv6->sock, entryv6->ai_addr, entryv6->ai_addrlen) < 0) {
				close (entryv6->sock);
				face_tbl[CefC_Faceid_ListenUdpv6].index = indexv6;
				face_tbl[CefC_Faceid_ListenUdpv6].fd = 0;
				cef_log_write (CefC_Log_Error, 
					"[face] Failed to create the listen face with UDP (%s)\n", strerror(errno));
				ret_val = -1;
			} else {
				doing_ip_version[1] = AF_INET6;
				face_tbl[CefC_Faceid_ListenUdpv6].index = indexv6;
				face_tbl[CefC_Faceid_ListenUdpv6].fd = entryv6->sock;
				face_tbl[CefC_Faceid_ListenUdpv6].protocol = CefC_Face_Type_Udp;
				*res_v6 = CefC_Faceid_ListenUdpv6;
			}
		}
		indexv4 = -1;
		indexv6 = -1;
	}
	return (ret_val);
}
/*--------------------------------------------------------------------------------------
	Creates the listening TCP socket with the specified port
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cef_face_tcp_listen_face_create (
	uint16_t 		port_num,				/* Port Number that cefnetd listens			*/
	int*			res_v4,
	int*			res_v6
) {
	struct addrinfo hints;
	struct addrinfo* res;
	struct addrinfo* cres;
	int err;
	char port_str[32];
	int sock;
	CefT_Sock* entryv4 = NULL;
	CefT_Sock* entryv6 = NULL;
	char ip_str[64];
	char if_str[128];
	int indexv4 = -1;
	int indexv6 = -1;
	int reuse_f = 1;
	int flag;
	int ret_val = 0;

	my_tcp_listen_port_num = port_num;
	
	memset (&hints, 0, sizeof (hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	process_port_num = port_num;

	sprintf (port_str, "%d", port_num);

	if ((err = getaddrinfo (NULL, port_str, &hints, &res)) != 0) {
		cef_log_write (CefC_Log_Error, 
			"%s (getaddrinfo:%s)\n", __func__, gai_strerror(err));
		return (-1);
	}

	for (cres = res ; cres != NULL ; cres = res) {
		res = cres->ai_next;

		sock = socket (cres->ai_family, cres->ai_socktype, 0);
		if (sock < 0) {
			cef_log_write (CefC_Log_Error, "%s (socket:%s)\n", __func__, strerror(errno));
			continue;
		}
		setsockopt (sock,
			SOL_SOCKET, SO_REUSEADDR, &reuse_f, sizeof (reuse_f));
		setsockopt (sock,
			SOL_SOCKET, SO_REUSEPORT, &reuse_f, sizeof (reuse_f));

		memset (ip_str, 0, 64);
		if (getnameinfo (cres->ai_addr, (int)cres->ai_addrlen
				, ip_str, sizeof (ip_str), 0, 0,  NI_NUMERICHOST) != 0) {
			continue;
		}
		sprintf (if_str, "%s:tcp", ip_str);

		switch (cres->ai_family) {
			case AF_INET: {
				if (indexv4 >= 0) {
					cef_face_addrinfo_free (cres);
					close (sock);
				} else {
					cres->ai_next = NULL;
					entryv4 = cef_face_sock_entry_create (
								sock, cres->ai_addr, cres->ai_addrlen, cres->ai_family);
					entryv4->faceid = CefC_Faceid_ListenTcpv4;
					entryv4->protocol = CefC_Face_Type_Tcp;
					indexv4 = cef_hash_tbl_item_set (
						sock_tbl, (const unsigned char*)if_str, strlen (if_str), entryv4);
				}
				break;
			}
			case AF_INET6: {
				if (indexv6 >= 0) {
					cef_face_addrinfo_free (cres);
					close (sock);
				} else {
					cres->ai_next = NULL;
					entryv6 = cef_face_sock_entry_create (
								sock, cres->ai_addr, cres->ai_addrlen, cres->ai_family);
					entryv6->faceid = CefC_Faceid_ListenTcpv6;
					entryv6->protocol = CefC_Face_Type_Tcp;
					indexv6 = cef_hash_tbl_item_set (
						sock_tbl, (const unsigned char*)if_str, strlen (if_str), entryv6);
				}
				break;
			}
			default: {
				/* NOP */;
				break;
			}
		}
		errno = 0;
		if (indexv4 >= 0) {
			if (bind (entryv4->sock, entryv4->ai_addr, entryv4->ai_addrlen) < 0) {
				close (entryv4->sock);
				face_tbl[CefC_Faceid_ListenTcpv4].index = indexv4;
				face_tbl[CefC_Faceid_ListenTcpv4].fd = 0;
				cef_log_write (CefC_Log_Error, 
					"[face] Failed to create the listen face with TCP (%s)\n", strerror(errno));
				ret_val = -1;
			} else {
				if (listen (entryv4->sock, 16) < 0) {
					cef_log_write (CefC_Log_Error, 
						"%s (listen:%s)\n", __func__, strerror(errno));
					return (-1);
				}
				flag = fcntl (entryv4->sock, F_GETFL, 0);
				if (flag < 0) {
					cef_log_write (CefC_Log_Error, 
						"%s (fcntl:%s)\n", __func__, strerror(errno));
					return (-1);
				}
				if (fcntl (entryv4->sock, F_SETFL, flag | O_NONBLOCK) < 0) {
					cef_log_write (CefC_Log_Error, 
						"%s (fcntl:%s)\n", __func__, strerror(errno));
					return (-1);
				}
				doing_ip_version[0] = AF_INET;
				face_tbl[CefC_Faceid_ListenTcpv4].index = indexv4;
				face_tbl[CefC_Faceid_ListenTcpv4].fd = entryv4->sock;
				face_tbl[CefC_Faceid_ListenTcpv4].protocol = CefC_Face_Type_Tcp;
				*res_v4 = CefC_Faceid_ListenTcpv4;
			}
		}
	
		errno = 0;
		if (indexv6 >= 0) {
			if (bind (entryv6->sock, entryv6->ai_addr, entryv6->ai_addrlen) < 0) {
				close (entryv6->sock);
				face_tbl[CefC_Faceid_ListenTcpv6].index = indexv6;
				face_tbl[CefC_Faceid_ListenTcpv6].fd = 0;
				cef_log_write (CefC_Log_Error, 
					"[face] Failed to create the listen face with TCP (%s)\n", strerror(errno));
				ret_val = -1;
			} else {
				if (listen (entryv6->sock, 16) < 0) {
					cef_log_write (CefC_Log_Error, 
						"%s (listen/v6:%s)\n", __func__, strerror(errno));
					return (-1);
				}
				flag = fcntl (entryv6->sock, F_GETFL, 0);
				if (flag < 0) {
					cef_log_write (CefC_Log_Error, 
						"%s (fcntl/v6:%s)\n", __func__, strerror(errno));
					return (-1);
				}
				if (fcntl (entryv6->sock, F_SETFL, flag | O_NONBLOCK) < 0) {
					cef_log_write (CefC_Log_Error, 
						"%s (fcntl/v6:%s)\n", __func__, strerror(errno));
					return (-1);
				}
				doing_ip_version[1] = AF_INET6;
				face_tbl[CefC_Faceid_ListenTcpv6].index = indexv6;
				face_tbl[CefC_Faceid_ListenTcpv6].fd = entryv6->sock;
				face_tbl[CefC_Faceid_ListenTcpv6].protocol = CefC_Face_Type_Tcp;
				*res_v6 = CefC_Faceid_ListenTcpv6;
			}
		}
		indexv4 = -1;
		indexv6 = -1;
	}
	return (ret_val);
}
/*--------------------------------------------------------------------------------------
	Creates the listening UDP socket for NDN with the specified port
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cef_face_ndn_listen_face_create (
	uint16_t 		port_num				/* Port Number that cefnetd listens			*/
) {
	struct addrinfo hints;
	struct addrinfo* res;
	struct addrinfo* cres;
	int err;
	char port_str[32];
	int sock;
	CefT_Sock* entryv4;
	CefT_Sock* entryv6;
	char ip_str[64];
	char if_str[128];
	int indexv4 = -1;
	int indexv6 = -1;

	memset (&hints, 0, sizeof (hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
	
	sprintf (port_str, "%d", port_num);

	if ((err = getaddrinfo (NULL, port_str, &hints, &res)) != 0) {
		cef_log_write (CefC_Log_Error, 
			"%s (getaddrinfo:%s)\n", __func__, gai_strerror(err));
		return (-1);
	}

	for (cres = res ; cres != NULL ; cres = res) {
		res = cres->ai_next;

		sock = socket (cres->ai_family, cres->ai_socktype, 0);
		if (sock < 0) {
			continue;
		}

		memset (ip_str, 0, 64);
		if (getnameinfo (cres->ai_addr, (int)cres->ai_addrlen
				, ip_str, sizeof (ip_str), 0, 0,  NI_NUMERICHOST) != 0) {
			continue;
		}
		sprintf (if_str, "%s:ndn", ip_str);
		
		switch (cres->ai_family) {
			case AF_INET: {
				if (indexv4 >= 0) {
					cef_face_addrinfo_free (cres);
					close (sock);
				} else {
					cres->ai_next = NULL;
					entryv4 = cef_face_sock_entry_create (
								sock, cres->ai_addr, cres->ai_addrlen, cres->ai_family);
					entryv4->faceid = CefC_Faceid_ListenNdnv4;
					entryv4->protocol = CefC_Face_Type_Udp;
					indexv4 = cef_hash_tbl_item_set (
						sock_tbl, (const unsigned char*)if_str, strlen (if_str), entryv4);
				}
				break;
			}
			case AF_INET6: {
				if (indexv6 >= 0) {
					cef_face_addrinfo_free (cres);
					close (sock);
				} else {
					cres->ai_next = NULL;
					entryv6 = cef_face_sock_entry_create (
								sock, cres->ai_addr, cres->ai_addrlen, cres->ai_family);
					entryv6->faceid = CefC_Faceid_ListenNdnv6;
					entryv6->protocol = CefC_Face_Type_Udp;
					indexv6 = cef_hash_tbl_item_set (
						sock_tbl, (const unsigned char*)if_str, strlen (if_str), entryv6);
				}
				break;
			}
			default: {
				/* NOP */;
				break;
			}
		}
	}
	
	errno = 0;
	if (indexv4 >= 0) {
		if (bind (entryv4->sock, entryv4->ai_addr, entryv4->ai_addrlen) < 0) {
			close (entryv4->sock);
			face_tbl[CefC_Faceid_ListenNdnv4].index = indexv4;
			face_tbl[CefC_Faceid_ListenNdnv4].fd = 0;
		} else {
			face_tbl[CefC_Faceid_ListenNdnv4].index = indexv4;
			face_tbl[CefC_Faceid_ListenNdnv4].fd = entryv4->sock;
			face_tbl[CefC_Faceid_ListenNdnv4].protocol = CefC_Face_Type_Udp;
			return (CefC_Faceid_ListenNdnv4);
		}
	}
	
	if (indexv6 >= 0) {
		if (bind (entryv6->sock, entryv6->ai_addr, entryv6->ai_addrlen) < 0) {
			close (entryv6->sock);
			face_tbl[CefC_Faceid_ListenNdnv6].index = indexv6;
			face_tbl[CefC_Faceid_ListenNdnv6].fd = 0;
		} else {
			face_tbl[CefC_Faceid_ListenNdnv6].index = indexv6;
			face_tbl[CefC_Faceid_ListenNdnv6].fd = entryv6->sock;
			face_tbl[CefC_Faceid_ListenNdnv6].protocol = CefC_Face_Type_Udp;
			return (CefC_Faceid_ListenNdnv6);
		}
	}

	cef_log_write (CefC_Log_Error, 
		"[face] Failed to create the listen face for NFD (%s)\n", strerror(errno));

	return (-1);
}
/*--------------------------------------------------------------------------------------
	Accepts the TCP socket
----------------------------------------------------------------------------------------*/
int													/* Face-ID 							*/
cef_face_accept_connect (
	void
) {
	struct sockaddr_storage* sa;
	socklen_t len = sizeof (struct sockaddr_storage);
	int cs;
	int flag;
	CefT_Sock* entry;
	int faceid;
	int index;
	char ip_str[256];
	char port_str[256];
	char peer_str[256];
#ifdef CefC_Neighbour
	int msg_len;
	unsigned char buff[CefC_Max_Length];
#endif
	
	sa = (struct sockaddr_storage*) malloc (sizeof (struct sockaddr_storage));
	memset (sa, 0, sizeof (struct sockaddr_storage));
	cs = accept (face_tbl[CefC_Faceid_ListenTcpv4].fd, (struct sockaddr*) sa, &len);
	if (cs < 0) {
		cs = accept (face_tbl[CefC_Faceid_ListenTcpv6].fd, (struct sockaddr*) sa, &len);
		if (cs < 0) {
			free (sa);
			return (-1);
		}
	}
	
	flag = fcntl (cs, F_GETFL, 0);
	if (flag < 0) {
		goto POST_ACCEPT;
	}
	if (fcntl (cs, F_SETFL, flag | O_NONBLOCK) < 0) {
		goto POST_ACCEPT;
	}

	if (getnameinfo ((struct sockaddr*) sa, len, ip_str, sizeof (ip_str), 
			port_str, sizeof (port_str),  NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
		goto POST_ACCEPT;
	}
	
	/* Looks up the source node's information from the source table 	*/
	sprintf (peer_str, "%s:%d", ip_str, CefC_Face_Type_Tcp);
	entry = (CefT_Sock*) cef_hash_tbl_item_get (
							sock_tbl, (const unsigned char*) peer_str, strlen (peer_str));
	
	if (entry) {
		cef_face_close (entry->faceid);
	}
	faceid = cef_face_unused_faceid_search ();
	if (faceid < 0) {
		goto POST_ACCEPT;
	}
	entry = cef_face_sock_entry_create (cs, (struct sockaddr*) sa, len, sa->ss_family);
	entry->faceid = faceid;
	entry->protocol = CefC_Face_Type_Tcp;
	entry->port_num = process_port_num;
	
	index = cef_hash_tbl_item_set (
		sock_tbl, (const unsigned char*) peer_str, strlen (peer_str), entry);

	if (index < 0) {
		cef_face_sock_entry_destroy (entry);
		sa = NULL;
		goto POST_ACCEPT;
	}
	face_tbl[faceid].index = index;
	face_tbl[faceid].fd = entry->sock;
	face_tbl[faceid].protocol = CefC_Face_Type_Tcp;

#ifdef CefC_Neighbour
	
	/* send a link message */
	msg_len = cef_frame_interest_link_msg_create (buff);
	if (msg_len > 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finer, 
			"Send a Interest Link message to FID#%d\n", entry->faceid);
#endif // CefC_Debug
		cef_face_frame_send_forced (entry->faceid, buff, (size_t) msg_len);
	}
#endif
	return (faceid);

POST_ACCEPT:
	close (cs);
	if (sa) {
		free (sa);
	}

	return (-1);
}
/*--------------------------------------------------------------------------------------
	Creates the local face that uses UNIX domain socket
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cef_face_local_face_create (
	int sk_type
) {
	struct sockaddr_un saddr;
	int flag;
	int sock;
	int index;
	CefT_Sock* entry;
	
	if ((sock = socket (AF_UNIX, sk_type, 0)) < 0) {
		cef_log_write (CefC_Log_Error, "%s (sock:%s)\n", __func__, strerror(errno));
		return (-1);
	}
	
	/* Initialize a sockaddr_un 	*/
	memset (&saddr, 0, sizeof (saddr));
	saddr.sun_family = AF_UNIX;
#ifdef CefC_Android
	/* Android socket Name starts with \0.	*/
	memcpy(saddr.sun_path, local_sock_path, local_sock_path_len);
#else // CefC_Android
	strcpy (saddr.sun_path, local_sock_path);
#endif // CefC_Android
	/* Prepares a source socket 	*/
	unlink (local_sock_path);

#ifdef __APPLE__
	saddr.sun_len = sizeof (saddr);

	if (bind (sock, (struct sockaddr *)&saddr, SUN_LEN (&saddr)) < 0) {
		cef_log_write (CefC_Log_Error, "%s (bind:%s)\n", __func__, strerror(errno));
		return (-1);
	}
#else // __APPLE__
	if (bind (sock, (struct sockaddr *)&saddr
				, sizeof (saddr.sun_family) + local_sock_path_len) < 0) {
		cef_log_write (CefC_Log_Error, "%s (bind:%s)\n", __func__, strerror(errno));
		return (-1);
	}
#endif // __APPLE__

	switch ( sk_type ) {
	case SOCK_STREAM:
	case SOCK_SEQPACKET:
		if (listen (sock, 1) < 0) {
			cef_log_write (CefC_Log_Error, "%s (listen:%s)\n", __func__, strerror(errno));
			return (-1);
		}
		break;
	default:
		break;
	}
	flag = fcntl (sock, F_GETFL, 0);
	if (flag < 0) {
		cef_log_write (CefC_Log_Error, "%s (fcntl:%s)\n", __func__, strerror(errno));
		return (-1);
	}
	if (fcntl (sock, F_SETFL, flag | O_NONBLOCK) < 0) {
		cef_log_write (CefC_Log_Error, "%s (fcntl:%s)\n", __func__, strerror(errno));
		return (-1);
	}

	entry = cef_face_sock_entry_create (sock, NULL, 0, -1);
	entry->faceid = CefC_Faceid_Local;
	index = cef_hash_tbl_item_set (
		sock_tbl, 
		(const unsigned char*)local_sock_path, 
		local_sock_path_len, 
		entry);
	face_tbl[CefC_Faceid_Local].index 	= index;
	face_tbl[CefC_Faceid_Local].fd 		= entry->sock;

	return (CefC_Faceid_Local);
}
/*--------------------------------------------------------------------------------------
	Creates the local face for babeld that uses UNIX domain socket
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cef_face_babel_face_create (
	int sk_type
) {
	struct sockaddr_un saddr;
	int flag;
	int sock;
	int index;
	CefT_Sock* entry;
	
	if ((sock = socket (AF_UNIX, sk_type, 0)) < 0) {
		cef_log_write (CefC_Log_Error, "%s (sock:%s)\n", __func__, strerror(errno));
		return (-1);
	}
	
	/* Initialize a sockaddr_un 	*/
	memset (&saddr, 0, sizeof (saddr));
	saddr.sun_family = AF_UNIX;
#ifdef CefC_Android
	/* Android socket Name starts with \0.	*/
	memcpy(saddr.sun_path, babel_sock_path, babel_sock_path_len);
#else // CefC_Android
	strcpy (saddr.sun_path, babel_sock_path);
#endif // CefC_Android
	/* Prepares a source socket 	*/
	unlink (babel_sock_path);

#ifdef __APPLE__
	saddr.sun_len = sizeof (saddr);

	if (bind (sock, (struct sockaddr *)&saddr, SUN_LEN (&saddr)) < 0) {
		cef_log_write (CefC_Log_Error, "%s (bind:%s)\n", __func__, strerror(errno));
		return (-1);
	}
#else // __APPLE__
	if (bind (sock, (struct sockaddr *)&saddr
				, sizeof (saddr.sun_family) + babel_sock_path_len) < 0) {
		cef_log_write (CefC_Log_Error, "%s (bind:%s)\n", __func__, strerror(errno));
		return (-1);
	}
#endif // __APPLE__

	switch ( sk_type ) {
	case SOCK_STREAM:
	case SOCK_SEQPACKET:
		if (listen (sock, 1) < 0) {
			cef_log_write (CefC_Log_Error, "%s (listen:%s)\n", __func__, strerror(errno));
			return (-1);
		}
		break;
	default:
		break;
	}
	flag = fcntl (sock, F_GETFL, 0);
	if (flag < 0) {
		cef_log_write (CefC_Log_Error, "%s (fcntl:%s)\n", __func__, strerror(errno));
		return (-1);
	}
	if (fcntl (sock, F_SETFL, flag | O_NONBLOCK) < 0) {
		cef_log_write (CefC_Log_Error, "%s (fcntl:%s)\n", __func__, strerror(errno));
		return (-1);
	}

	entry = cef_face_sock_entry_create (sock, NULL, 0, -1);
	entry->faceid = CefC_Faceid_ListenBabel;
	index = cef_hash_tbl_item_set (
		sock_tbl, 
		(const unsigned char*) babel_sock_path, 
		babel_sock_path_len, 
		entry);
	face_tbl[CefC_Faceid_ListenBabel].index = index;
	face_tbl[CefC_Faceid_ListenBabel].fd 	= entry->sock;

	return (CefC_Faceid_ListenBabel);
}
/*--------------------------------------------------------------------------------------
	Converts the specified Face-ID into the corresponding file descriptor
----------------------------------------------------------------------------------------*/
int											/* the corresponding file descriptor		*/
cef_face_get_fd_from_faceid (
	uint16_t 		faceid					/* Face-ID									*/
) {
	return (face_tbl[faceid].fd);
}
/*--------------------------------------------------------------------------------------
	Obtains the Face structure from the specified Face-ID
----------------------------------------------------------------------------------------*/
CefT_Face* 									/* Face 									*/
cef_face_get_face_from_faceid (
	uint16_t 	faceid						/* Face-ID									*/
) {
	assert (faceid >= 0 && faceid <= max_tbl_size);
	return (&face_tbl[faceid]);
}
/*--------------------------------------------------------------------------------------
	Obtains the Face structure from the specified Face-ID
----------------------------------------------------------------------------------------*/
uint32_t 
cef_face_get_seqnum_from_faceid (
	uint16_t 	faceid						/* Face-ID									*/
) {
	assert (faceid >= 0 && faceid <= max_tbl_size);
	face_tbl[faceid].seqnum++;
	return (face_tbl[faceid].seqnum);
}

/*--------------------------------------------------------------------------------------
	Sends a message via the specified Face
----------------------------------------------------------------------------------------*/
void
cef_face_frame_send_forced (
	uint16_t 		faceid, 				/* Face-ID indicating the destination 		*/
	unsigned char* 	msg, 					/* a message to send						*/
	size_t			msg_len					/* length of the message to send 			*/
) {
	CefT_Sock* entry;
	int res;
	
	entry = (CefT_Sock*) cef_hash_tbl_item_get_from_index (
										sock_tbl, face_tbl[faceid].index);
	if (entry == NULL) {
		return;
	}
	
	if (face_tbl[faceid].local_f) {
		send (entry->sock, msg, msg_len, 0);
	} else {
		if (face_tbl[faceid].protocol != CefC_Face_Type_Tcp) {
			sendto (entry->sock, msg, msg_len
					, 0, entry->ai_addr, entry->ai_addrlen);
		} else {
			res = write (entry->sock, msg, msg_len);
			if (res < 0) {
				cef_face_close (faceid);
			}
		}
	}

	return;
}
/*--------------------------------------------------------------------------------------
	Sends a Content Object via the specified Face
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cef_face_object_send (
	uint16_t 		faceid, 				/* Face-ID indicating the destination 		*/
	unsigned char* 	msg, 					/* a message to send						*/
	size_t			msg_len,				/* length of the message to send 			*/
	CefT_Parsed_Message* pm 				/* Parsed message 							*/
) {
	CefT_Sock* entry;
	struct cef_app_frame app_frame;
	int res;
	
	if (face_tbl[faceid].fd < 3) {
		return (-1);
	}
	entry = (CefT_Sock*) cef_hash_tbl_item_get_from_index (
										sock_tbl, face_tbl[faceid].index);
	if (entry == NULL) {
		return (-1);
	}
	
	if (face_tbl[faceid].local_f) {
		res = cef_face_app_sdu_create (&app_frame, 
				pm->name, pm->name_len, pm->payload, pm->payload_len, pm->chnk_num);
		
		if (res > 0) {
			uint32_t magic_no = CefC_App_Magic_No;
			memcpy((void *)&app_frame.data_entity[app_frame.name_len+app_frame.payload_len]
				, (const void *)&magic_no, sizeof(magic_no));
			send (entry->sock, &app_frame, app_frame.actual_data_len, 0);
		}
	} else {
		if (face_tbl[faceid].protocol != CefC_Face_Type_Tcp) {
			sendto (entry->sock, msg, msg_len
					, 0, entry->ai_addr, entry->ai_addrlen);
		} else {
			res = write (entry->sock, msg, msg_len);
			if (res < 0) {
				cef_face_close (faceid);
			}
		}
	}
	
	return (1);
}
/*--------------------------------------------------------------------------------------
	Sends a Content Object if the specified is local Face
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cef_face_object_send_iflocal (
	uint16_t 		faceid, 				/* Face-ID indicating the destination 		*/
	unsigned char* 	name, 
	uint16_t 		name_len, 
	unsigned char* 	payload, 				/* a message to send						*/
	size_t			payload_len,			/* length of the message to send 			*/
	uint32_t		chnk_num				/* Chunk Number 							*/
) {
	CefT_Sock* entry;
	struct cef_app_frame app_frame;
	int res;
	
	if (face_tbl[faceid].fd < 3) {
		return (-1);
	}

	entry = (CefT_Sock*) cef_hash_tbl_item_get_from_index (
										sock_tbl, face_tbl[faceid].index);
	if (entry == NULL) {
		return (-1);
	}
	
	if (face_tbl[faceid].local_f) {
		res = cef_face_app_sdu_create (&app_frame, 
				name, name_len, payload, payload_len, chnk_num);
		
		if (res > 0) {
			uint32_t magic_no = CefC_App_Magic_No;
			memcpy((void *)&app_frame.data_entity[app_frame.name_len+app_frame.payload_len]
				, (const void *)&magic_no, sizeof(magic_no));
			send (entry->sock, &app_frame, app_frame.actual_data_len, 0);
		}
	} else {
		res = 0;
	}
	
	return (res);
}
/*--------------------------------------------------------------------------------------
	Set the informations and payload for the applications
----------------------------------------------------------------------------------------*/
static int
cef_face_app_sdu_create (
	struct cef_app_frame* app_frame, 
	unsigned char* name, 
	uint16_t name_len, 
	unsigned char* payload, 
	uint16_t payload_len, 
	uint32_t chnk_num
) {
	if (!app_frame) {
		return (-1);
	}
	
	app_frame->version 		= CefC_App_Version;
	app_frame->type 		= CefC_App_Type_Internal;
	app_frame->name_len 	= name_len;
	app_frame->payload_len 	= payload_len;
	app_frame->chunk_num 	= chnk_num;
	
    memcpy (&(app_frame->data_entity[0]), name, name_len);
	memcpy (&(app_frame->data_entity[name_len]), payload, payload_len);
	app_frame->actual_data_len = sizeof(struct cef_app_frame)
	                             - sizeof(app_frame->data_entity)
	                             + name_len + payload_len + sizeof(CefC_App_Magic_No);
	return (1);
}
/*--------------------------------------------------------------------------------------
	Checks whether the specified Face is local or not
----------------------------------------------------------------------------------------*/
int											/* local face is 1, no-local face is 0	 	*/
cef_face_is_local_face (
	uint16_t 		faceid 					/* Face-ID indicating the destination 		*/
) {
	if (face_tbl[faceid].local_f) {
		return (1);
	}

	return (0);
}
/*--------------------------------------------------------------------------------------
	Obtains type of Face (local/UDP/TCP)
----------------------------------------------------------------------------------------*/
int											/* type of Face							 	*/
cef_face_type_get (
	uint16_t 		faceid 					/* Face-ID									*/
) {
	if (face_tbl[faceid].local_f) {
		return (CefC_Face_Type_Local);
	}
	return ((int) face_tbl[faceid].protocol);
}
/*--------------------------------------------------------------------------------------
	Sends a message if the specified is local Face with API Header
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cef_face_apimsg_send_iflocal (
	uint16_t 		faceid, 				/* Face-ID indicating the destination 		*/
	void *			api_hdr, 				/* a header to send							*/
	size_t			api_hdr_len,			/* length of the header to send 			*/
	void *			payload, 				/* a message to send						*/
	size_t			payload_len				/* length of the message to send 			*/
) {
	CefT_Sock* entry;
	unsigned char api_frame[CefC_Max_Length];
	int ret = 1;

	if (face_tbl[faceid].fd < 3) {
		return (-1);
	}

	entry = (CefT_Sock*) cef_hash_tbl_item_get_from_index (
										sock_tbl, face_tbl[faceid].index);
	if (entry == NULL) {
		return (-1);
	}
	
	if (face_tbl[faceid].local_f) {
		memcpy (api_frame, api_hdr, api_hdr_len);
		if ( payload && 0 < payload_len )
			memcpy (api_frame + api_hdr_len, payload, payload_len);

		ret = send (entry->sock, api_frame, (api_hdr_len + payload_len), 0);

	} else {
		ret = 0;
	}

	return (ret);
}
/*--------------------------------------------------------------------------------------
	Looks up the protocol type from the FD
----------------------------------------------------------------------------------------*/
int										/* Face-ID that is not used				*/
cef_face_get_protocol_from_fd (
	int fd
) {
	int i;

	for (i = 0 ; i < max_tbl_size ; i++) {
		if (face_tbl[i].fd != fd) {
			continue;
		}
		return (face_tbl[i].protocol);
	}

	return (CefC_Face_Type_Invalid);
}
/*--------------------------------------------------------------------------------------
	Closes all faces
----------------------------------------------------------------------------------------*/
void
cef_face_all_face_close (
	void
) {
	int i;

	for (i = 0 ; i < max_tbl_size ; i++) {
		if (face_tbl[i].fd) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finer, 
				"[face] Close the Face#%d (FD#%d)\n", i, face_tbl[i].fd);
#endif // CefC_Debug
			close (face_tbl[i].fd);
		}
	}

	free (face_tbl);
#ifdef CefC_Android
	/* Process for Android next running	*/
	face_tbl = NULL;
#endif // CefC_Android
	max_tbl_size = 0;
}
/*--------------------------------------------------------------------------------------
	Obtains the neighbor information
----------------------------------------------------------------------------------------*/
int 
cef_face_neighbor_info_get (
	char* info_buff
) {
	CefT_Sock* sock;
	uint32_t index = 0;
	int table_num;
	int i;
	
	char node[NI_MAXHOST];
	int res;
	CefT_Face* face;
	char prot_str[3][16] = {"invalid", "tcp", "udp"};
	
	/* get table num		*/
	info_buff[0] = 0x00;
	table_num = cef_hash_tbl_item_num_get (sock_tbl);
	if (table_num == 0) {
		return (0);
	}
	
	/* output table		*/
	for (i = 0; i < table_num; i++) {
		/* get socket table	*/
		sock = (CefT_Sock*) cef_hash_tbl_elem_get (sock_tbl, &index);
		if (sock == NULL) {
			break;
		}
		
		/* check local face flag	*/
		face = cef_face_get_face_from_faceid (sock->faceid);
		
		if ((face->local_f == 1) || (sock->faceid < CefC_Face_Reserved)) {
			index++;
			continue;
		}
		
		/* output face info	*/
		memset (node, 0, sizeof(node));
		res = getnameinfo (	sock->ai_addr,
							sock->ai_addrlen,
							node, sizeof (node),
							NULL, 0,
							NI_NUMERICHOST);
		if (res != 0) {
			index++;
			continue;
		}
		sprintf (info_buff, "%sfaceid = %d %s %s:%d\n", 
			info_buff, sock->faceid, prot_str[sock->protocol], node, sock->port_num);
		index++;
	}
	return (strlen (info_buff));
}

/*--------------------------------------------------------------------------------------
	Obtains the face information
----------------------------------------------------------------------------------------*/
int 
cef_face_info_get (
	char* face_info, 
	uint16_t faceid
) {
	CefT_Sock* sock;
	uint32_t index = 0;
	int table_num;
	int i;
	
	char node[NI_MAXHOST];
	int res;
	CefT_Face* face;
	char prot_str[3][16] = {"invalid", "tcp", "udp"};
	
	/* get table num		*/
	face_info[0] = 0x00;
	table_num = cef_hash_tbl_item_num_get (sock_tbl);
	if (table_num == 0) {
		return (0);
	}
	
	/* output table		*/
	for (i = 0; i < table_num; i++) {
		/* get socket table	*/
		sock = (CefT_Sock*) cef_hash_tbl_elem_get (sock_tbl, &index);
		if (sock == NULL) {
			break;
		}
		
		/* check local face flag	*/
		face = cef_face_get_face_from_faceid (sock->faceid);
		
		if ((face->local_f == 1) || 
			(sock->faceid < CefC_Face_Reserved) ||
			(faceid != sock->faceid)) {
			index++;
			continue;
		}
		/* output face info	*/
		memset (node, 0, sizeof(node));
		res = getnameinfo (	sock->ai_addr,
							sock->ai_addrlen,
							node, sizeof (node),
							NULL, 0,
							NI_NUMERICHOST);
		if (res != 0) {
			index++;
			continue;
		}
		sprintf (face_info, "faceid = %d %s %s:%d", 
			sock->faceid, prot_str[sock->protocol], node, sock->port_num);
		break;
	}
	return (strlen (face_info));
}

/*--------------------------------------------------------------------------------------
	Obtains the node id of the specified face
----------------------------------------------------------------------------------------*/
int 
cef_face_node_id_get (
	uint16_t faceid, 
	unsigned char* node_id
) {
	CefT_Sock* sock;
	int table_num;
	CefT_Face* face;
	int len = 0;
	
	/* get table num		*/
	table_num = cef_hash_tbl_item_num_get (sock_tbl);
	if (table_num == 0) {
		return (0);
	}
	
	face = cef_face_get_face_from_faceid (faceid);
	if (face->fd == -1) {
		return (0);
	}
	sock = (CefT_Sock*) cef_hash_tbl_item_get_from_index (sock_tbl, face->index);
	if (sock == NULL) {
		return (0);
	}
	if (faceid != sock->faceid) {
		return (0);
	}
	
	if (sock->ai_family == AF_INET6) {
		len = 16;
		memcpy (&node_id[0],
			&((struct sockaddr_in6*)(sock->ai_addr))->sin6_addr, 16);
	} else if (sock->ai_family == AF_INET) {
		len = 4;
		memcpy (&node_id[0],
			&((struct sockaddr_in*)(sock->ai_addr))->sin_addr, 4);
	} else {
		len = 0;
	}
	return (len);
}

CefT_Hash_Handle*
cef_face_return_sock_table (
	void
) {
	return (&sock_tbl);
}
/*--------------------------------------------------------------------------------------
	Looks up and creates the specified Face
----------------------------------------------------------------------------------------*/
static int									/* Face-ID									*/
cef_face_lookup_faceid (
	int protocol,
	char* peer_id, 
	char* usr_id, 
	char* port_str, 
	int* create_f
) {
	struct addrinfo hints;
	struct addrinfo* res;
	struct addrinfo* cres;
	int err;
	int sock;
	CefT_Sock* entry;
	int faceid;
	int index;
	int flag;
	int val;
	fd_set readfds;
#ifdef CefC_Neighbour
	struct timeval timeout;
	int ret;
#endif
	int port_num;
	int optval = 1;
	int rtry_count = 0;
	int reuse_faceid = -1;

	if (create_f) {
		*create_f = 0;
	}
	
	entry = (CefT_Sock*) cef_hash_tbl_item_get (
				sock_tbl, (const unsigned char*) peer_id, strlen (peer_id));
	
	if (entry) {
		if (face_tbl[entry->faceid].fd > 0) {
			return (entry->faceid);
		}
	}
	
	memset (&hints, 0, sizeof (hints));
	hints.ai_family = AF_UNSPEC;
	if (protocol != CefC_Face_Type_Tcp) {
		hints.ai_socktype = SOCK_DGRAM;
	} else {
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_NUMERICSERV;
	}
	
	if ((err = getaddrinfo (usr_id, port_str, &hints, &res)) != 0) {
		cef_log_write (CefC_Log_Error, 
			"%s (getaddrinfo:%s)\n", __func__, gai_strerror(err));
		return (-1);
	}

	for (cres = res ; cres != NULL ; cres = res) {
		res = cres->ai_next;
		if ((doing_ip_version[0] != -1 && doing_ip_version[0] == cres->ai_family) ||
			(doing_ip_version[1] != -1 && doing_ip_version[1] == cres->ai_family)) {
			/* NOP */
		}
		else {
			cef_face_addrinfo_free (cres);
			continue;
		}
		
		if (protocol != CefC_Face_Type_Tcp) {
			sock = socket (cres->ai_family, cres->ai_socktype, 0);
		} else {
			sock = socket (cres->ai_family, cres->ai_socktype, cres->ai_protocol);
		}
		
		if (sock < 0) {
			cef_face_addrinfo_free (cres);
			continue;
		}
		/*+++++ for Metis: Bind its own listen port to the source port +++++*/
		if (protocol != CefC_Face_Type_Tcp) {
			port_num = my_udp_listen_port_num;
		} else {
			port_num = my_tcp_listen_port_num;
		}
#if 0
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&optval, sizeof(optval)) < 0){
			cef_log_write (CefC_Log_Error, "%s (setsockopt:%s)\n", __func__, strerror(errno));
			close (sock);
			cef_face_addrinfo_free (cres);
			continue;
		}
#endif
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char *)&optval, sizeof(optval)) < 0){
			cef_log_write (CefC_Log_Error, "%s (setsockopt:%s)\n", __func__, strerror(errno));
			close (sock);
			cef_face_addrinfo_free (cres);
			continue;
		}
		if (cres->ai_family == AF_INET){
			struct sockaddr_in myname;
			
			memset(&myname, 0, sizeof(myname));
			myname.sin_family = cres->ai_family;
			myname.sin_addr.s_addr = INADDR_ANY;
			myname.sin_port = htons(port_num);
			if(bind(sock, (struct sockaddr *)&myname, sizeof(myname)) < 0){
				cef_log_write (CefC_Log_Error, "%s (bind:%s)\n", __func__, strerror(errno));
				close (sock);
				cef_face_addrinfo_free (cres);
				continue;
			}
		} else {
			struct sockaddr_in6 myname;
			
			memset(&myname, 0, sizeof(myname));
			myname.sin6_family = cres->ai_family;
			myname.sin6_addr = in6addr_any;
			myname.sin6_port = htons(port_num);
			if(bind(sock, (struct sockaddr *)&myname, sizeof(myname)) < 0){
				cef_log_write (CefC_Log_Error, "%s (bind:%s)\n", __func__, strerror(errno));
				close (sock);
				cef_face_addrinfo_free (cres);
				continue;
			}
		}
		if (entry) {
			reuse_faceid = entry->faceid;
			cef_face_close (entry->faceid);
		}
		/*----- for Metis: Bind its own standby port to the source port -----*/
		if (protocol != CefC_Face_Type_Udp) {
			flag = fcntl (sock, F_GETFL, 0);
			if (flag < 0) {
				close (sock);
				cef_face_addrinfo_free (cres);
				continue;
			}
			if (fcntl (sock, F_SETFL, flag | O_NONBLOCK) < 0) {
				close (sock);
				cef_face_addrinfo_free (cres);
				continue;
			}
RETRY:;
			if (connect (sock, cres->ai_addr, cres->ai_addrlen) < 0) {
#ifdef __APPLE__
				int retry_errno = EADDRINUSE;
#else // __APPLE__
				int retry_errno = EADDRNOTAVAIL;
#endif // __APPLE__
				if(errno==retry_errno){
					usleep(1000);
					rtry_count++;
					if(rtry_count > 10){
						cef_log_write (CefC_Log_Error, "[face] Failed to connect (%s)\n", strerror(errno));
						close (sock);
						cef_face_addrinfo_free (cres);
						continue;
				    }
					goto RETRY;
				}
#ifndef __APPLE__
					if (errno == EINVAL) {
						cef_log_write (CefC_Log_Error, "[face] Failed to connect (%s)\n", strerror(errno));
						close (sock);
						cef_face_addrinfo_free (cres);
						continue;
					}
#else // __APPLE__
					if (errno == EHOSTUNREACH) {
						cef_log_write (CefC_Log_Error, "[face] Failed to connect (%s)\n", strerror(errno));
						close (sock);
						cef_face_addrinfo_free (cres);
						continue;
					}					
#endif // __APPLE__
			}
			val = 1;
			ioctl (sock, FIONBIO, &val);
			FD_ZERO (&readfds);
			FD_SET (sock, &readfds);
#ifdef CefC_Neighbour
			timeout.tv_sec = 5;
			timeout.tv_usec = 0;
			ret = select (sock + 1, &readfds, NULL, NULL, &timeout);
			if (ret == 0) {
				close (sock);
				cef_face_addrinfo_free (cres);
				continue;
			} else {
				if (FD_ISSET (sock, &readfds)) {
					ret = recv (sock, port_str, 0, 0);
					if (ret == -1) {
						close (sock);
						cef_face_addrinfo_free (cres);
						continue;
					} else {
						/* NOP */;
					}
				}
			}
#endif
		}

		if (reuse_faceid != -1) {
			faceid = reuse_faceid;
		}
		else{
			faceid = cef_face_unused_faceid_search ();
			if (faceid < 0) {
				close (sock);
				cef_face_addrinfo_free (cres);
				continue;
			}
		}
		
		cres->ai_next = NULL;
		entry = cef_face_sock_entry_create (
					sock, cres->ai_addr, cres->ai_addrlen, cres->ai_family);
		entry->faceid   = faceid;
		entry->port_num = atoi (port_str);
		entry->protocol = (uint8_t) protocol;

		index = cef_hash_tbl_item_set (
			sock_tbl, (const unsigned char*) peer_id, strlen (peer_id), entry);

		if (index < 0) {
			close (sock);
			cef_face_sock_entry_destroy (entry);
			continue;
		}
		face_tbl[faceid].index = index;
		face_tbl[faceid].fd = entry->sock;
		face_tbl[faceid].protocol = (uint8_t) protocol;
		
		if (create_f) {
			*create_f = 1;
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finer, 
			"[face] Creation the new Face#%d (FD#%d) for %s:%s\n", 
			entry->faceid, face_tbl[entry->faceid].fd, usr_id, port_str);
#endif // CefC_Debug
		}
#ifndef CefC_Android
		freeaddrinfo (res);
#endif // CefC_Android
		return (entry->faceid);
	}

	return (-1);
}
/*--------------------------------------------------------------------------------------
	Creates the peer ID 
----------------------------------------------------------------------------------------*/
static void 
cef_face_peer_id_create (
	const char* destination, 				/* String of the destination address 		*/
	int protocol,							/* protoco (udp,tcp,local) 					*/
	char* peer_id, 
	char* usr_id, 
	char* port_str
) {
	int ret;
	int i, n, t;
	int is_exist;
	
	ret = strlen (destination);
	n = 0;
	t = 0;
	
	if (strlen (port_str) == 0) {
		if (destination[0] == '[') {
			/* IPv6 */
			for (i = 1 ; i < ret ; i++) {
				if (destination[i] != ']') {
					usr_id[n] = destination[i];
					n++;
				} else {
					break;
				}
			}
			usr_id[n] = 0x00;
			is_exist = 0;
			for (i = n ; i < ret ; i++) {
				if (destination[i] == ':') {
					is_exist = 1;
					continue;
				}
				else
				{
					if (is_exist == 0) continue;
				}
				port_str[t] = destination[i];
				t++;
			}
			port_str[t] = 0x00;
			
			if (t == 0) {
				sprintf (port_str, "%d", process_port_num);
				sprintf (peer_id, "%s:%d:%d", usr_id, process_port_num, protocol);
			} else {
				sprintf (peer_id, "%s:%s:%d", usr_id, port_str, protocol);
			}
		}
		else {
			/* IPv4 */
			for (i = 0 ; i < ret ; i++) {
				if (destination[i] != ':') {
					usr_id[n] = destination[i];
					n++;
				} else {
					break;
				}
			}
			usr_id[n] = 0x00;
			
			for (i = n + 1 ; i < ret ; i++) {
				port_str[t] = destination[i];
				t++;
			}
			port_str[t] = 0x00;
			
			if (t == 0) {
				sprintf (port_str, "%d", process_port_num);
				sprintf (peer_id, "%s:%d:%d", destination, process_port_num, protocol);
			} else {
				sprintf (peer_id, "%s:%d", destination, protocol);
			}
		}
	}
	else {
		strcpy(usr_id, destination);
		sprintf (peer_id, "%s:%s:%d", usr_id, port_str, protocol);
	}
	
	return;
}
/*--------------------------------------------------------------------------------------
	Looks up Face-ID that is not used
----------------------------------------------------------------------------------------*/
static int										/* Face-ID that is not used				*/
cef_face_unused_faceid_search (
	void
) {
	int i;

	for (i = assigned_faceid ; i < max_tbl_size ; i++) {
		if (face_tbl[i].fd != 0) {
			continue;
		}
		assigned_faceid = i + 1;
		return (i);
	}

	for (i = CefC_Face_Reserved ; i < assigned_faceid ; i++) {
		if (face_tbl[i].fd != 0) {
			continue;
		}
//		assigned_faceid = i + 1;
		return (i);
	}
	assigned_faceid = CefC_Face_Reserved;
	return (-1);
}

/*--------------------------------------------------------------------------------------
	Deallocates the specified addrinfo
----------------------------------------------------------------------------------------*/
static void
cef_face_addrinfo_free (
	struct addrinfo* ai							/* addrinfo to free 					*/
) {
	if (ai) {
		free (ai);
	}
}
/*--------------------------------------------------------------------------------------
	Creates a new entry of Socket Table
----------------------------------------------------------------------------------------*/
static CefT_Sock*								/* the created new entry				*/
cef_face_sock_entry_create (
	int sock, 									/* file descriptor to register			*/
	struct sockaddr* ai_addr,
	socklen_t ai_addrlen, 
	int ai_family
) {
	CefT_Sock* entry;

	entry = (CefT_Sock*) malloc (sizeof (CefT_Sock));
	entry->ai_addr = ai_addr;
	entry->ai_addrlen = ai_addrlen;
	entry->sock = sock;
	entry->faceid = -1;
	entry->ai_family = ai_family;
	
	return (entry);
}
/*--------------------------------------------------------------------------------------
	Destroy the specified entry of Socket Table
----------------------------------------------------------------------------------------*/
static void
cef_face_sock_entry_destroy (
	CefT_Sock* entry							/* the entry to destroy					*/
) {

	if (entry->ai_addr) {
		free (entry->ai_addr);
	}
	free (entry);
}

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
 * cef_face.h
 */

#ifndef __CEF_FACE_HEADER__
#define __CEF_FACE_HEADER__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/un.h>

#include <cefore/cef_hash.h>
#include <cefore/cef_define.h>
#include <cefore/cef_frame.h>
#include <cefore/cef_rcvbuf.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

/********** Reserved Face-IDs 				**********/

#define CefC_Face_Reserved			32

#define CefC_Faceid_Local			0
#define CefC_Faceid_ListenUdpv4		4
#define CefC_Faceid_ListenUdpv6		5
#define CefC_Faceid_ListenTcpv4		6
#define CefC_Faceid_ListenTcpv6		7

#define CefC_Faceid_ListenBabel		8


/********** FD for UNIX domain socket 		**********/
#define CefC_Local_Sock_Name		".cefore.sock"

/********** Invalid File Descriptor value	**********/
#define CefC_Fd_Invalid				-1

/********** Identifier to close Face 		**********/
#define CefC_Face_Close				"/CLOSE:Face"

/********** Neighbor Management				**********/
#define CefC_Max_RTT 				1000000		/* Maximum RTT (us) 					*/

/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/

typedef struct {
	uint16_t		index;
	int				fd;
	CefT_RcvBuf		rcvbuf;
	uint8_t 		local_f;
	uint8_t 		protocol;
	uint32_t 		seqnum;
#ifdef __APPLE__
	int 			ifindex;
#endif // __APPLE__
	int				bw_stat_i;
	long			tv_sec;
} CefT_Face;

/********** Neighbor Management				**********/
typedef struct {
	uint16_t 			faceid;
	uint64_t 			rtt;
} CefT_Rtts;

/****** Entry of Socket Table 			*****/
typedef struct {
	struct sockaddr_storage sa;
	struct sockaddr* ai_addr;
	socklen_t ai_addrlen;
	int 	ai_family;
	int 	skfd;								/* File descriptor 						*/
	int 	faceid;								/* Assigned Face-ID 					*/
	int 	port_num;							/* Number of port 						*/
	uint8_t protocol;
	uint8_t listener;
	uint8_t shared_fd;
} CefT_Sock;

/****************************************************************************************
 Global Variables
 ****************************************************************************************/

/****************************************************************************************
 Macros
 ****************************************************************************************/

#define CefC_Face_Type_Num			4
#define CefC_Face_Type_Invalid		0x00
#define CefC_Face_Type_Tcp			0x01
#define CefC_Face_Type_Udp			0x02
#define CefC_Face_Type_Local		0x03
#define CefC_Face_Type_Quic			0x04


/****************************************************************************************
 Function Declarations
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Initialize the face module
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cef_face_init (
	uint8_t 	node_type					/* Node Type (Router/Receiver....)			*/
);
/*--------------------------------------------------------------------------------------
	Creates the listening UDP socket with the specified port
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cef_face_udp_listen_face_create (
	uint16_t 		port_num,				/* Port Number that cefnetd listens			*/
	int*			res_v4,
	int*			res_v6
);
/*--------------------------------------------------------------------------------------
	Creates the listening TCP socket with the specified port
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cef_face_tcp_listen_face_create (
	uint16_t 		port_num,				/* Port Number that cefnetd listens			*/
	int*			res_v4,
	int*			res_v6
);
/*--------------------------------------------------------------------------------------
	Accepts the TCP socket
----------------------------------------------------------------------------------------*/
int
cef_face_accept_connect (
	void
);
/*--------------------------------------------------------------------------------------
	Creates the local face that uses UNIX domain socket
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cef_face_local_face_create (
	int sk_type
);
/*--------------------------------------------------------------------------------------
	Creates the local face for babeld that uses UNIX domain socket
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cef_face_babel_face_create (
	int sk_type
);
/*--------------------------------------------------------------------------------------
	Closes all faces
----------------------------------------------------------------------------------------*/
void
cef_face_all_face_close (
	void
);
/*--------------------------------------------------------------------------------------
	Checks the specified Face is active or not
----------------------------------------------------------------------------------------*/
int										/* Returns the value less than 1 if it fails 	*/
cef_face_check_active (
	int faceid								/* Face-ID									*/
);
/*--------------------------------------------------------------------------------------
	Checks the specified Face is close or not
----------------------------------------------------------------------------------------*/
int										/* Returns the value less than 1 if it fails 	*/
cef_face_check_close (
	int faceid								/* Face-ID									*/
);
/*--------------------------------------------------------------------------------------
	Obtains the Face structure from the specified Face-ID
----------------------------------------------------------------------------------------*/
uint32_t
cef_face_get_seqnum_from_faceid (
	uint16_t 	faceid						/* Face-ID									*/
);
/*--------------------------------------------------------------------------------------
	Updates the listen faces with TCP
----------------------------------------------------------------------------------------*/
int											/* number of the listen face with TCP 		*/
cef_face_update_listen_faces (
	struct pollfd* inudpfds,
	uint16_t* inudpfaces,
	uint16_t* inudpfdc,
	struct pollfd* intcpfds,
	uint16_t* intcpfaces,
	uint16_t* intcpfdc
);
/*--------------------------------------------------------------------------------------
	Converts the specified Face-ID into the corresponding file descriptor
----------------------------------------------------------------------------------------*/
int											/* the corresponding file descriptor		*/
cef_face_get_fd_from_faceid (
	uint16_t 		faceid					/* Face-ID									*/
);
/*--------------------------------------------------------------------------------------
	Looks up and creates the peer Face
----------------------------------------------------------------------------------------*/
int											/* Peer Face-ID 							*/
cef_face_lookup_peer_faceid (
	struct addrinfo* sas, 					/* sockaddr_storage structure				*/
	socklen_t sas_len,						/* length of sockaddr_storage				*/
	int protocol,
	char* usr_id							//0.8.3
);
/*--------------------------------------------------------------------------------------
	Looks up and creates the Face from the specified string of the destination address
----------------------------------------------------------------------------------------*/
int											/* Face-ID									*/
cef_face_lookup_faceid_from_addrstr (
	const char* destination, 				/* String of the destination address 		*/
	const char* protocol					/* protoco (udp,tcp,local) 					*/
);
/*--------------------------------------------------------------------------------------
	Searches the specified Face
----------------------------------------------------------------------------------------*/
int											/* Face-ID									*/
cef_face_search_faceid (
	const char* destination, 				/* String of the destination address 		*/
	const char* protocol					/* protoco (udp,tcp,local) 					*/
);
/*--------------------------------------------------------------------------------------
	Sends a message via the specified Face
----------------------------------------------------------------------------------------*/
void
cef_face_frame_send_forced (
	uint16_t 		faceid, 				/* Face-ID indicating the destination 		*/
	unsigned char* 	msg, 					/* a message to send						*/
	size_t			msg_len					/* length of the message to send 			*/
);
int
cef_face_frame_send (
	uint16_t 		faceid, 				/* Face-ID indicating the destination 		*/
	unsigned char* 	msg, 					/* a message to send						*/
	size_t			msg_len					/* length of the message to send 			*/
);
/*--------------------------------------------------------------------------------------
	Obtains the Face structure from the specified Face-ID
----------------------------------------------------------------------------------------*/
CefT_Face* 									/* Face 									*/
cef_face_get_face_from_faceid (
	uint16_t 	faceid						/* Face-ID									*/
);
/*--------------------------------------------------------------------------------------
	Searches and creates the local Face-ID corresponding to the specified FD
----------------------------------------------------------------------------------------*/
int											/* the corresponding Face-ID				*/
cef_face_lookup_local_faceid (
	int fd									/* File descriptor							*/
);
/*--------------------------------------------------------------------------------------
	Closes the specified Face
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cef_face_close (
	int faceid								/* Face-ID									*/
);
/*--------------------------------------------------------------------------------------
	Closes the specified Face for down
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cef_face_close_for_down (
	int faceid								/* Face-ID									*/
);
/*--------------------------------------------------------------------------------------
	Half-closes the specified Face
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cef_face_down (
	int faceid								/* Face-ID									*/
);
/*--------------------------------------------------------------------------------------
	Sends a frame if the specified is local Face
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cef_face_frame_send_iflocal (
	uint16_t 		faceid, 				/* Face-ID indicating the destination 		*/
	unsigned char* 	msg, 					/* a message to send						*/
	size_t			msg_len					/* length of the message to send 			*/
);
/*--------------------------------------------------------------------------------------
	Sends a Content Object if the specified is local Face
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cef_face_object_send_iflocal (
	uint16_t 		faceid, 				/* Face-ID indicating the destination 		*/
	unsigned char* 	msg, 					/* a message to send						*/
	size_t			msg_len					/* length of the message to send 			*/
);
/*--------------------------------------------------------------------------------------
	Sends a message if the specified is local Face with API Header
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cef_face_apimsg_send_iflocal (
	uint16_t 		faceid, 				/* Face-ID indicating the destination 		*/
	void * 			api_hdr, 				/* a header to send						*/
	size_t			api_hdr_len,			/* length of the header to send 			*/
	void *		 	payload, 				/* a message to send						*/
	size_t			payload_len				/* length of the message to send 			*/
);
CefT_Hash_Handle*
cef_face_return_sock_table (
	void
);
/*--------------------------------------------------------------------------------------
	Checks whether the specified Face is local or not
----------------------------------------------------------------------------------------*/
int											/* local face is 1, no-local face is 0	 	*/
cef_face_is_local_face (
	uint16_t 		faceid 					/* Face-ID indicating the destination 		*/
);
/*--------------------------------------------------------------------------------------
	Obtains type of Face (local/UDP/TCP)
----------------------------------------------------------------------------------------*/
int											/* type of Face							 	*/
cef_face_type_get (
	uint16_t 		faceid 					/* Face-ID									*/
);
/*--------------------------------------------------------------------------------------
	Looks up the protocol type from the FD
----------------------------------------------------------------------------------------*/
int										/* Face-ID that is not used				*/
cef_face_get_protocol_from_fd (
	int fd
);
/*--------------------------------------------------------------------------------------
	Obtains the neighbor information
----------------------------------------------------------------------------------------*/
int
cef_face_neighbor_info_get (
	char* info_buff
);
/*--------------------------------------------------------------------------------------
	Obtains the node id of the specified face
----------------------------------------------------------------------------------------*/
int
cef_face_node_id_get (
	uint16_t faceid,
	unsigned char* node_id
);
/*--------------------------------------------------------------------------------------
	Obtains the face num
----------------------------------------------------------------------------------------*/
int
cef_face_num_get ();
/*--------------------------------------------------------------------------------------
	Obtains the face information
----------------------------------------------------------------------------------------*/
int
cef_face_info_get (
	char* face_info,
	uint16_t faceid
);

//0.8.3
/*--------------------------------------------------------------------------------------
	Obtains the bw_stat_i get of the specified face
----------------------------------------------------------------------------------------*/
int
cef_face_bw_stat_i_get (
	uint16_t faceid
);
/*--------------------------------------------------------------------------------------
	Obtains the bw_stat_i set of the specified face
----------------------------------------------------------------------------------------*/
int
cef_face_bw_stat_i_set (
	uint16_t faceid,
	int		 index
);

/*--------------------------------------------------------------------------------------
	Creates the listening UDP socket for assinged IP address with the specified port
----------------------------------------------------------------------------------------*/
extern int
cef_face_create_listener_from_ipaddrs(
    int faceid,     // assigend by cefnetd
	int fd,
	int af_type,
	struct sockaddr_storage *saaddr,
	char *ip_str,
	int listen_port_num,
	int face_proto
);

/*--------------------------------------------------------------------------------------
	Get the time the face was last referenced.
----------------------------------------------------------------------------------------*/
long
cef_face_get_reftime (
	int	faceid
);

#endif // __CEF_FACE_HEADER__

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
 * cef_status.c
 */

#define __CEF_STATUS_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "cef_status.h"
#include <cefore/cef_hash.h>
#include <cefore/cef_fib.h>
#include <cefore/cef_face.h>
#include <cefore/cef_frame.h>
#include <cefore/cef_print.h>
#include <cefore/cef_plugin_com.h>


/****************************************************************************************
 Macros
 ****************************************************************************************/



/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

/****************************************************************************************
 State Variables
 ****************************************************************************************/

static char* work_str = NULL;

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

static char prot_str[3][16] = {"invalid", "tcp", "udp"};

/*--------------------------------------------------------------------------------------
	Output Face status
----------------------------------------------------------------------------------------*/
static void
cef_status_face_output (
	void
);
/*--------------------------------------------------------------------------------------
	Output FIB status
----------------------------------------------------------------------------------------*/
static void
cef_status_forward_output (
	CefT_Hash_Handle* handle
);
/*--------------------------------------------------------------------------------------
	Output PIT status
----------------------------------------------------------------------------------------*/
static void
cef_status_pit_output (
	CefT_Hash_Handle* handle
);


/****************************************************************************************
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Output CEFORE status
----------------------------------------------------------------------------------------*/
int 
cef_status_stats_output (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	unsigned char* rsp
) {
	char node_type[32] = {0};
	char cache_type[32] = {0};
	
	work_str = (char*) rsp;
	
	switch (hdl->node_type) {
		case CefC_Node_Type_Receiver: {
			sprintf (node_type, "Receiver");
			break;
		}
		case CefC_Node_Type_Publisher: {
			sprintf (node_type, "Publisher");
			break;
		}
		case CefC_Node_Type_Router: {
			sprintf (node_type, "Router");
			break;
		}
		default: {
			sprintf (node_type, "Unknown");
			return (0);
		}
	}

	if (hdl->cs_stat) {
		switch (hdl->cs_stat->cache_type) {
			case CefC_Cache_Type_None: {
#ifndef CefC_Dtc
				sprintf (cache_type, "None");
#else // CefC_Dtc
				sprintf (cache_type, "DTC");
#endif // CefC_Dtc
				break;
			}
			case CefC_Cache_Type_Excache: {
				sprintf (cache_type, "Excache");
				break;
			}
			default: {
				sprintf (cache_type, "Unknown");
				return (0);
			}
		}
	} else {
		sprintf (cache_type, "None");
	}
	
	sprintf (work_str, 
			"Version    : %x\n"
			"Port       : %u\n"
			"Rx Frames  : %llu\n"
			"Tx Frames  : %llu\n"
			"Cache Mode : %s\n",
			CefC_Version,
			hdl->port_num,
			(unsigned long long)hdl->stat_recv_frames,
			(unsigned long long)hdl->stat_send_frames,
			cache_type);
	
#ifdef CefC_Ccore
	if (hdl->rt_hdl) {
		sprintf (work_str, "%sController : %s %s\n"
			, work_str, hdl->rt_hdl->controller_id
			, (hdl->rt_hdl->sock != -1) ? "" : "#down");
	} else {
		sprintf (work_str, "%sController : Not Used\n", work_str);
	}
#endif
	
	/* output Face	*/
	sprintf (work_str, "%sFaces :\n", work_str);
	cef_status_face_output ();
	
	/* output FIB	*/
	sprintf (work_str, "%sFIB :\n", work_str);
	cef_status_forward_output (&hdl->fib);

	/* output PIT	*/
	sprintf (work_str, "%sPIT :\n", work_str);
	cef_status_pit_output (&hdl->pit);
	
#ifdef CefC_NdnPlugin
	sprintf (work_str, "%sNDN :\n", work_str);
	cef_plugin_ndn_fib_print (work_str);
#endif // CefC_NdnPlugin
	
	sprintf (work_str, "%s\n", work_str);
	
	return (strlen (work_str));
}
/*--------------------------------------------------------------------------------------
	Output Face status
----------------------------------------------------------------------------------------*/
static void
cef_status_face_output (
	void
) {
	CefT_Sock* sock = NULL;
	CefT_Hash_Handle* sock_tbl = NULL;
	uint32_t index = 0;
	int table_num = 0;
	int i = 0;

	char node[NI_MAXHOST] = {0};			/* node name	*/
	int res;
	CefT_Face* face = NULL;

	char face_info[65535] = {0};
	int face_info_index = 0;

	/* get socket table	*/
	sock_tbl = cef_face_return_sock_table ();
	/* get table num		*/
	table_num = cef_hash_tbl_item_num_get (*sock_tbl);
	if (table_num == 0) {
		sprintf (work_str, "%s  Entry is empty\n", work_str);
		return;
	}

	/* output table		*/
	for (i = 0; i < table_num; i++) {
		/* get socket table	*/
		sock = (CefT_Sock*) cef_hash_tbl_elem_get (*sock_tbl, &index);
		if (sock == NULL) {
			break;
		}

		/* check local face flag	*/
		face = cef_face_get_face_from_faceid (sock->faceid);
		if (face->local_f || (sock->faceid == 0)) {
			sprintf (work_str, "%s  faceid = %3d : Local face\n", work_str, sock->faceid);
			index++;
			continue;
		}
		if (sock->faceid == CefC_Faceid_ListenBabel) {
			sprintf (work_str, 
				"%s  faceid = %3d : Local face (for cefbabeld)\n", 
				work_str, sock->faceid);
			index++;
			continue;
		}
		/* check IPv4 Listen port	*/
		if (sock->faceid == CefC_Faceid_ListenUdpv4) {
			sprintf (work_str, 
				"%s  faceid = %3d : IPv4 Listen face (udp)\n", work_str, sock->faceid);
			index++;
			continue;
		}
		/* check IPv6 Listen port	*/
		if (sock->faceid == CefC_Faceid_ListenUdpv6) {
			sprintf (work_str, 
				"%s  faceid = %3d : IPv6 Listen face (udp)\n", work_str, sock->faceid);
			index++;
			continue;
		}
		/* check IPv4 Listen port	*/
		if (sock->faceid == CefC_Faceid_ListenTcpv4) {
			sprintf (work_str, 
				"%s  faceid = %3d : IPv4 Listen face (tcp)\n", work_str, sock->faceid);
			index++;
			continue;
		}
		/* check IPv6 Listen port	*/
		if (sock->faceid == CefC_Faceid_ListenTcpv6) {
			sprintf (work_str, 
				"%s  faceid = %3d : IPv6 Listen face (tcp)\n", work_str, sock->faceid);
			index++;
			continue;
		}
		
		/* check IPv4 Listen port for NDN	*/
		if (sock->faceid == CefC_Faceid_ListenNdnv4) {
			sprintf (work_str, 
				"%s  faceid = %3d : IPv4 Listen face (ndn)\n", work_str, sock->faceid);
			index++;
			continue;
		}
		/* check IPv6 Listen port for NDN	*/
		if (sock->faceid == CefC_Faceid_ListenNdnv6) {
			sprintf (work_str, 
				"%s  faceid = %3d : IPv6 Listen face (ndn)\n", work_str, sock->faceid);
			index++;
			continue;
		}
		
		/* output face info	*/
		face_info_index = sprintf (face_info, "  faceid = %3d : ", sock->faceid);
		memset (node, 0, sizeof(node));
		res = getnameinfo (	sock->ai_addr,
							sock->ai_addrlen,
							node, sizeof(node),
							NULL, 0,
							NI_NUMERICHOST);
		if (res != 0) {
			index++;
			continue;
		}
		sprintf (
			face_info + face_info_index,
			 "address = %s:%d (%s)%s", node, sock->port_num, prot_str[sock->protocol], 
			 (cef_face_check_active (sock->faceid) < 1) ? " # down" : "");
		
		sprintf (work_str, "%s%s\n", work_str, face_info);
		index++;
	}
	return;
}
/*--------------------------------------------------------------------------------------
	Output FIB status
----------------------------------------------------------------------------------------*/
static void
cef_status_forward_output (
	CefT_Hash_Handle* handle
) {
	CefT_Fib_Entry* entry = NULL;
	uint32_t index = 0;
	int table_num = 0;
	int i = 0;
	char uri[65535] = {0};
	CefT_Fib_Face* faces = NULL;
	int res = 0;
	char face_info[65535] = {0};
	int face_info_index = 0;

	/* get table num		*/
	table_num = cef_hash_tbl_item_num_get (*handle);
	if (table_num == 0) {
		sprintf (work_str, "%s  Entry is empty\n", work_str);
		return;
	}

	/* output table		*/
	for (i = 0; i < table_num; i++) {
		entry = (CefT_Fib_Entry*) cef_hash_tbl_elem_get (*handle, &index);
		if (entry == NULL) {
			break;
		}
		res = cef_frame_conversion_name_to_uri (entry->key, entry->klen, uri);
		if (res < 0) {
			continue;
		}
		/* output uri	*/
		sprintf (work_str, "%s  %s\n", work_str, uri);
		memset (uri, 0, sizeof(uri));

		/* output faces	*/
		faces = entry->faces.next;
		face_info_index = sprintf (face_info, "    Faces : ");
		while (faces != NULL) {
			
			face_info_index += 
				sprintf (face_info + face_info_index, "%d (%c%c%c)  "
					, faces->faceid
					, ((faces->type >> 2) & 0x01) ? 'c' : '-'
					, ((faces->type >> 1) & 0x01) ? 's' : '-'
					, ((faces->type) & 0x01) ? 'd' : '-');
			
			faces = faces->next;
		}
		sprintf (work_str, "%s%s\n", work_str, face_info);
		
		index++;
	}

	return;
}
/*--------------------------------------------------------------------------------------
	Output PIT status
----------------------------------------------------------------------------------------*/
static void
cef_status_pit_output (
	CefT_Hash_Handle* handle
) {
	CefT_Pit_Entry* entry;
	uint32_t index = 0;
	int table_num = 0;
	int i = 0;
	char uri[65535] = {0};
	uint32_t chunk_num = 0;
	int res = 0;
	CefT_Down_Faces* dnfaces = NULL;
	CefT_Up_Faces* upfaces = NULL;

	uint16_t dec_name_len;

	char face_info[65535] = {0};
	int face_info_index = 0;
	
	uint16_t sub_type;
	uint16_t sub_length;
	uint16_t name_index;
	struct tlv_hdr* thdr;
	uint16_t chunknum_f;
	
	/* get table num		*/
	table_num = cef_hash_tbl_item_num_get (*handle);
	if (table_num == 0) {
		sprintf (work_str, "%s  Entry is empty\n", work_str);
		return;
	}

	/* output table		*/
	for (i = 0; i < table_num; i++) {
		entry = (CefT_Pit_Entry*) cef_hash_tbl_elem_get (*handle, &index);
		if (entry == NULL) {
			sprintf (work_str, "%sentry is NULL\n", work_str);
			break;
		}
		
		/* Gets Chunk Number 	*/
		name_index 		= 0;
		chunknum_f 		= 0;
		dec_name_len 	= 0;
		
		while (name_index < entry->klen) {
			thdr = (struct tlv_hdr*)(&entry->key[name_index]);
			sub_type 	= ntohs (thdr->type);
			sub_length  = ntohs (thdr->length);
			name_index += CefC_S_TLF;
			
			switch (sub_type) {
				case CefC_T_NAMESEGMENT: {
					dec_name_len += CefC_S_TLF + sub_length;
					break;
				}
				case CefC_T_CHUNK: {
					chunknum_f = 1;
					memcpy (&chunk_num, &entry->key[name_index], CefC_S_ChunkNum);
					chunk_num = ntohl (chunk_num);
					break;
				}
				default: {
					break;
				}
			}
			name_index += sub_length;
		}
		
		res = cef_frame_conversion_name_to_uri (entry->key, dec_name_len, uri);
		
		if (res < 0) {
			continue;
		}
		/* output uri	*/
		if (chunknum_f) {
			sprintf (work_str, "%s  %s%%%04X/\n", work_str, uri, chunk_num);
		} else {
			sprintf (work_str, "%s  %s\n", work_str, uri);
		}
		memset (uri, 0, sizeof(uri));

		/* output down faces	*/
		dnfaces = entry->dnfaces.next;
		face_info_index = sprintf (face_info, "    DownFaces : ");
		while (dnfaces != NULL) {
			face_info_index += sprintf (
									face_info + face_info_index, "%d ", dnfaces->faceid);
			dnfaces = dnfaces->next;
		}
		sprintf (work_str, "%s%s\n", work_str, face_info);

		/* output upfaces	*/
		upfaces = entry->upfaces.next;
		face_info_index = sprintf (face_info, "    UpFaces   : ");
		while (upfaces != NULL) {
			face_info_index += sprintf (
									face_info + face_info_index, "%d ", upfaces->faceid);
			upfaces = upfaces->next;
		}
		sprintf (work_str, "%s%s\n", work_str, face_info);

		index++;
	}

	return;
}


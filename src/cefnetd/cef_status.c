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
 * cef_status.c
 */

#define __CEF_STATUS_SOURECE__

//#define	__DEV_RSP_LEN__

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
#if ((defined CefC_CefnetdCache) && (defined CefC_Develop))
#include <cefore/cef_mem_cache.h>
#endif


/****************************************************************************************
 Macros
 ****************************************************************************************/
#define CefC_Display_Max		CefC_Max_Length

#define SPRINTF_FACETYPE_URI(index, face_type, uri)		\
	(sprintf (face_info + face_info_index,"%c%c%c %s "	\
	, ((face_type >> 2) & 0x01) ? 'c' : '-'				\
	, ((face_type >> 1) & 0x01) ? 's' : '-'				\
	, ((face_type) & 0x01) ? 'd' : '-'					\
	, uri));

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

/****************************************************************************************
 State Variables
 ****************************************************************************************/

static char* rsp_bufp;
static int   rsp_buf_size;

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

static char prot_str[3][16] = {"invalid", "tcp", "udp"};
/*
	Define prot_str as following the macros of cef_face.h

	#define CefC_Face_Type_Invalid      0x00
	#define CefC_Face_Type_Tcp          0x01
	#define CefC_Face_Type_Udp          0x02
	#define CefC_Face_Type_Local        0x03
*/

/*--------------------------------------------------------------------------------------
	Output Face status
----------------------------------------------------------------------------------------*/
static int
cef_status_face_output (
	void
);
/*--------------------------------------------------------------------------------------
	Output FIB status
----------------------------------------------------------------------------------------*/
//static int
//cef_status_forward_output (
//	CefT_Hash_Handle* handle
//);
static int
cef_status_forward_output (
	CefT_Hash_Handle* handle,
	uint16_t output_opt_f
);
#if CefC_Develop
static int
cef_status_forward_output_with_ip (
	CefT_Hash_Handle* handle,
	uint16_t output_opt_f
);
#endif  // CefC_Develop
/*--------------------------------------------------------------------------------------
	Output PIT status
----------------------------------------------------------------------------------------*/
static int
cef_status_pit_output (
	CefT_Hash_Handle* handle,
	uint16_t output_opt_f,
	uint16_t num_of_pit
);
/*--------------------------------------------------------------------------------------
	Output App FIB status
----------------------------------------------------------------------------------------*/
static int
cef_status_app_forward_output (
	CefT_Hash_Handle* handle
);
/*--------------------------------------------------------------------------------------
	Add output to response buffer
----------------------------------------------------------------------------------------*/
static int
cef_status_add_output_to_rsp_buf(
	char* buff
);
#if ((defined CefC_CefnetdCache) && (defined CefC_Develop))
/*--------------------------------------------------------------------------------------
	Output LocalCache status
----------------------------------------------------------------------------------------*/
static int
cef_status_localcache_output (
	uint16_t output_opt_f
);
#endif


/****************************************************************************************
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Output CEFORE status
----------------------------------------------------------------------------------------*/
int
cef_status_stats_output (
	CefT_Netd_Handle* hdl,						/* cefnetd handle						*/
	unsigned char** rspp,
	uint16_t output_opt_f,
	uint16_t numofpit
) {
	char node_type[32] = {0};
	char cache_type[32] = {0};
	char work_str[CefC_Max_Length];
	int  fret = 0;
	(*rspp)[0] = 0;
	rsp_bufp = (char*) *rspp;
	rsp_buf_size = CefC_Max_Length*10;

#ifdef	CefC_Develop
	if( output_opt_f & CefC_Ctrl_StatusOpt_FibOnly ){
		cef_status_forward_output_with_ip (&hdl->fib, output_opt_f);
		goto endfunc;
	}
#endif	// CefC_Develop

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
				sprintf (cache_type, "None");
				break;
			}
			case CefC_Cache_Type_Excache: {
				sprintf (cache_type, "Excache");
				break;
			}
			case CefC_Cache_Type_Localcache: {
				sprintf (cache_type, "Localcache");
				break;
			}
			case CefC_Cache_Type_ExConpub: {
				sprintf (cache_type, "Conpub");
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

	sprintf (rsp_bufp,
			"CCNx Version     : %x\n"
			"Port             : %u\n"
			"Rx Interest      : %llu (RGL[%llu], SYM[%llu], SEL[%llu])\n"
			"Tx Interest      : %llu (RGL[%llu], SYM[%llu], SEL[%llu])\n"
			"Rx ContentObject : %llu\n"
			"Tx ContentObject : %llu\n"
			"Cache Mode       : %s\n"
			"FWD Strategy     : %s\n",
			CefC_Version,
			hdl->port_num,
			(unsigned long long)hdl->stat_recv_interest,
			(unsigned long long)hdl->stat_recv_interest_types[0],
			(unsigned long long)hdl->stat_recv_interest_types[1],
			(unsigned long long)hdl->stat_recv_interest_types[2],
			(unsigned long long)hdl->stat_send_interest,
			(unsigned long long)hdl->stat_send_interest_types[0],
			(unsigned long long)hdl->stat_send_interest_types[1],
			(unsigned long long)hdl->stat_send_interest_types[2],
			(unsigned long long)hdl->stat_recv_frames,
			(unsigned long long)hdl->stat_send_frames,
			cache_type,
			hdl->forwarding_strategy);
#ifdef CefC_INTEREST_RETURN
	sprintf (work_str, "Interest Return  : %s\n"
		, (hdl->IR_Option != 1) ? "Disabled" : "Enabled");
	if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
		goto endfunc;
	}
#endif	// CefC_INTEREST_RETURN

	/* output Face	*/
	sprintf (work_str, "Faces :");
	if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
		goto endfunc;
	}
	if ((fret=cef_status_face_output ()) != 0){
		goto endfunc;
	}

	/* output FIB	*/
	sprintf (work_str, "FIB(App) :");
	if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
		goto endfunc;
	}
	if ((fret=cef_status_app_forward_output (&hdl->app_reg)) != 0){
		goto endfunc;
	}

	sprintf (work_str, "FIB :");
	if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
		goto endfunc;
	}
	if ((fret=cef_status_forward_output (&hdl->fib, output_opt_f)) != 0){
		goto endfunc;
	}

	/* output PIT	*/
	sprintf (work_str, "PIT(App) :");
	if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
		goto endfunc;
	}
	if ((fret=cef_status_pit_output (&hdl->app_pit, output_opt_f, numofpit)) != 0){
		goto endfunc;
	}
	sprintf (work_str, "PIT :");
	if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
		goto endfunc;
	}
	if ((fret=cef_status_pit_output (&hdl->pit, output_opt_f, numofpit)) != 0){
		goto endfunc;
	}

#if ((defined CefC_CefnetdCache) && (defined CefC_Develop))
	if (hdl->cs_mode == 1) {
		if ((fret=cef_status_localcache_output (output_opt_f)) != 0){
			goto endfunc;
		}
	}
#endif

endfunc:;

	*rspp = (unsigned char*) rsp_bufp;
	if (fret == 0) {
		return (strlen (rsp_bufp));
	} else {
		return (0);
	}
}
/*--------------------------------------------------------------------------------------
	Output Face status
----------------------------------------------------------------------------------------*/
static int
cef_status_face_output (
	void
) {
	CefT_Sock* sock = NULL;
	CefT_Hash_Handle* sock_tbl = NULL;
	uint32_t index = 0;
	int table_num = 0;
	int i = 0;

	char node[NI_MAXHOST] = {0};			/* node name	*/
	char port[32] = {0};					/* port No.		*/
	int res;
	CefT_Face* face = NULL;

	char face_info[BUFSIZ] = {0};
	int face_info_index = 0;
	char work_str[CefC_Max_Length*2];
	int fret = 0;

	/* get socket table	*/
	sock_tbl = cef_face_return_sock_table ();
	/* get table num		*/
	table_num = cef_hash_tbl_item_num_get (*sock_tbl);

	sprintf (work_str, " %d\n", table_num);
	if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
		return (-1);
	}

	if (table_num == 0) {
		sprintf (work_str, "  Entry is empty\n");
		if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
			return (-1);
		}
		return (0);
	}
	/* output table		*/
	for (i = 0; i < table_num; i++) {
        char fd_str[16];
		/* get socket table	*/
		sock = (CefT_Sock*) cef_hash_tbl_elem_get (*sock_tbl, &index);
		if (sock == NULL) {
			break;
		}
        memset(fd_str, 0x00, sizeof(fd_str));
		if ( !cef_face_check_active (sock->faceid) )
			strcpy (fd_str, " # down");
#ifdef  CefC_Develop
		else
			sprintf (fd_str, " # %d", sock->skfd);
#endif  // CefC_Develop

		/* check local face flag	*/
		face = cef_face_get_face_from_faceid (sock->faceid);
		if (face->local_f || (sock->faceid == 0)) {
			sprintf (work_str, "  faceid = %3d : Local face%s\n", sock->faceid, fd_str);
			if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
				return (-1);
			}
			index++;
			continue;
		}
		if (sock->faceid == CefC_Faceid_ListenBabel) {
			sprintf (work_str,
				"  faceid = %3d : Local face (for cefbabeld)%s\n",
				 sock->faceid, fd_str);
			if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
				return (-1);
			}
			index++;
			continue;
		}
		/* check IPv4 Listen port	*/
		if (sock->faceid == CefC_Faceid_ListenUdpv4) {
			sprintf (work_str,
				"  faceid = %3d : IPv4 Listen face (udp)%s\n", sock->faceid, fd_str);
			if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
				return (-1);
			}
			index++;
			continue;
		}
		/* check IPv6 Listen port	*/
		if (sock->faceid == CefC_Faceid_ListenUdpv6) {
			sprintf (work_str,
				"  faceid = %3d : IPv6 Listen face (udp)%s\n", sock->faceid, fd_str);
			if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
				return (-1);
			}
			index++;
			continue;
		}
		/* check IPv4 Listen port	*/
		if (sock->faceid == CefC_Faceid_ListenTcpv4) {
			sprintf (work_str,
				"  faceid = %3d : IPv4 Listen face (tcp)%s\n", sock->faceid, fd_str);
			if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
				return (-1);
			}
			index++;
			continue;
		}
		/* check IPv6 Listen port	*/
		if (sock->faceid == CefC_Faceid_ListenTcpv6) {
			sprintf (work_str,
				"  faceid = %3d : IPv6 Listen face (tcp)%s\n", sock->faceid, fd_str);
			if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
				return (-1);
			}
			index++;
			continue;
		}

		/* output face info	*/
		face_info_index = sprintf (face_info, "  faceid = %3d : ", sock->faceid);
		memset (node, 0, sizeof(node));
		res = getnameinfo (	sock->ai_addr,
							sock->ai_addrlen,
							node, sizeof(node),
							port, sizeof(port),
							NI_NUMERICHOST);
		if (res != 0) {
			index++;
			continue;
		}
		if (sock->listener) {
			if (sock->ai_family == AF_INET6) {
				sprintf (
					face_info + face_info_index,
					 "IPv6 Listen Face ([%s]:%s/%s)%s", node, port, prot_str[sock->protocol],
					 fd_str);
			} else {
				sprintf (
					face_info + face_info_index,
					 "IPv4 Listen Face (%s:%s/%s)%s", node, port, prot_str[sock->protocol],
					 fd_str);
			}
		} else {
			if (sock->ai_family == AF_INET6) {
				sprintf (
					face_info + face_info_index,
					 "address = [%s]:%s (%s)%s", node, port, prot_str[sock->protocol],
					 fd_str);
			} else {
				sprintf (
					face_info + face_info_index,
					 "address = %s:%s (%s)%s", node, port, prot_str[sock->protocol],
					 fd_str);
			}
		}

		sprintf (work_str, "%s\n", face_info);
		if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
			return (-1);
		}
		index++;
	}
	return(0);
}
/*--------------------------------------------------------------------------------------
	Output FIB status
----------------------------------------------------------------------------------------*/
static int
cef_status_forward_output (
	CefT_Hash_Handle* handle,
	uint16_t output_opt_f
) {
	CefT_Fib_Entry* entry = NULL;
	uint32_t index = 0;
	int table_num = 0;
	int i = 0;
	char uri[CefC_NAME_BUFSIZ] = {0};
	CefT_Fib_Face* faces = NULL;
	int res = 0;
	char face_info[BUFSIZ] = {0};
	int face_info_index = 0;
	char work_str[CefC_Max_Length*2];
	int fret = 0;


	/* get table num		*/
	table_num = cef_hash_tbl_item_num_get (*handle);
	if (table_num == 0) {
		sprintf (work_str, "\n  Entry is empty\n");
		if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
			return (-1);
		}
		return (0);
	}

	sprintf (work_str, " %d\n", table_num);
	if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
		return (-1);
	}

	/* output table		*/
	for (i = 0; i < table_num; i++) {
		entry = (CefT_Fib_Entry*) cef_hash_tbl_elem_get (*handle, &index);
		if (entry == NULL) {
			if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
				return (-1);
			}
			break;
		}
		res = cef_frame_conversion_name_to_uri (entry->key, entry->klen, uri);
		if (res < 0) {
			continue;
		}
		/* output uri	*/
		sprintf (work_str, "  %s\n", uri);
		if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
			return (-1);
		}
		memset (uri, 0, sizeof(uri));

		/* output faces	*/
		faces = entry->faces.next;
		face_info_index = sprintf (face_info, "    Faces : ");
		while (faces != NULL) {
			if (face_info_index != strlen("    Faces : ")) {
				face_info_index +=
					sprintf (face_info + face_info_index, "            ");
			}
			face_info_index +=
				sprintf (face_info + face_info_index, "%d (%c%c%c) RtCost=%d "
					, faces->faceid
					, ((faces->type >> 2) & 0x01) ? 'c' : '-'
					, ((faces->type >> 1) & 0x01) ? 's' : '-'
					, ((faces->type) & 0x01) ? 'd' : '-'
					, faces->metric.cost);
			if (output_opt_f & CefC_Ctrl_StatusOpt_Metric) {
				face_info_index +=
					sprintf (face_info + face_info_index, "DummyMetric=%d\n", faces->metric.dummy_metric);
			} else {
				face_info_index +=
					sprintf (face_info + face_info_index, "\n");
			}

			if (output_opt_f & CefC_Ctrl_StatusOpt_Stat) {
				face_info_index +=
					sprintf (face_info + face_info_index, "                     TxInt=%llu (RGL[%llu], SYM[%llu], SEL[%llu])\n"
						, (unsigned long long)faces->tx_int
						, (unsigned long long)faces->tx_int_types[CefC_PIT_TYPE_Rgl]
						, (unsigned long long)faces->tx_int_types[CefC_PIT_TYPE_Sym]
						, (unsigned long long)faces->tx_int_types[CefC_PIT_TYPE_Sel]);
			}
			faces = faces->next;
		}
		if (output_opt_f & CefC_Ctrl_StatusOpt_Stat) {
			face_info_index +=
				sprintf (face_info + face_info_index, "    RxInt : %llu (RGL[%llu], SYM[%llu], SEL[%llu])\n"
					, (unsigned long long)entry->rx_int
					, (unsigned long long)entry->rx_int_types[CefC_PIT_TYPE_Rgl]
					, (unsigned long long)entry->rx_int_types[CefC_PIT_TYPE_Sym]
					, (unsigned long long)entry->rx_int_types[CefC_PIT_TYPE_Sel]);
		}
		sprintf (work_str, "%s", face_info);
		if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
			return (-1);
		}
		index++;
	}

	return (0);
}
#ifdef  CefC_Develop
/*--------------------------------------------------------------------------------------
	Output FIB status
----------------------------------------------------------------------------------------*/
static int
cef_status_forward_output_with_ip (
	CefT_Hash_Handle* handle,
	uint16_t output_opt_f
) {
	CefT_Fib_Entry* entry = NULL;
	uint32_t index = 0;
	int table_num = 0;
	int i = 0;
	char uri[CefC_NAME_BUFSIZ] = {0};
	CefT_Fib_Face* faces = NULL;
	int res = 0;
	char face_info[BUFSIZ] = {0};
	int face_info_index = 0;
	char work_str[CefC_Max_Length*2];
	int fret = 0;

	CefT_Hash_Handle* sock_tbl;
	CefT_Sock* sock;
	char node[NI_MAXHOST] = {0};	/* node name	*/
	char port[32] = {0};			/* port No.		*/


	/* get table num	*/
	table_num = cef_hash_tbl_item_num_get (*handle);
	if (table_num == 0) {
		sprintf (work_str, "\n");
		if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
			return (-1);
		}
		return (0);
	}

	/* output table	*/
	for (i = 0; i < table_num; i++) {
		/* get FIB entry	*/
		entry = (CefT_Fib_Entry*) cef_hash_tbl_elem_get (*handle, &index);
		if (entry == NULL) {
			if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
				return (-1);
			}
			break;
		}

		res = cef_frame_conversion_name_to_uri (entry->key, entry->klen, uri);
		if (res < 0) {
			continue;
		}

		faces = entry->faces.next;

		memset (face_info, 0, sizeof(face_info));
		face_info_index = 0;

		while (faces != NULL) {
			/* get face info */
			CefT_Face*  face;
			face = cef_face_get_face_from_faceid (faces->faceid);
#ifdef __APPLE__
			if (face->ifindex != -1) {
				faces = faces->next;
				continue;
			}
#endif // __APPLE__

			/* get socket info associated with this faceID */
			sock_tbl = cef_face_return_sock_table ();
			sock = (CefT_Sock*) cef_hash_tbl_item_get_from_index (*sock_tbl, face->index);
			if (sock == NULL) {
				faces = faces->next;
				continue;
			}

			/* get IPaddress and port number from socket info	*/
			memset (node, 0, sizeof(node));
			res = getnameinfo ( sock->ai_addr,
					sock->ai_addrlen,
					node, sizeof(node),
					port, sizeof(port),
					NI_NUMERICHOST);
			if (res != 0) {
				faces = faces->next;
				continue;
			}

			/* If "--fibinet-only" option is specified, output olny FIB with TCP or UDP */
			if (output_opt_f & CefC_Ctrl_StatusOpt_FibInetOnly) {
				if ( !(sock->ai_family == AF_INET6 || sock->ai_family == AF_INET) ) {
					faces = faces->next;
					continue;
				}
			}

			/* If "--fibv4udp-only" option is specified, output olny FIB with IPv4 and UDP */
			if (output_opt_f & CefC_Ctrl_StatusOpt_FibV4UdpOnly) {
				if ( !(sock->ai_family == AF_INET) || !(sock->protocol == CefC_Face_Type_Udp) ) {
					faces = faces->next;
					continue;
				}
			}

			/* output FIB info (Face type, URI, IP Address, Port Number, Socket Protcol)	*/
			if (sock->ai_family == AF_INET6) { // IPv6
				face_info_index += SPRINTF_FACETYPE_URI(face_info + face_info_index, faces->type, uri);
				face_info_index +=
					sprintf (face_info + face_info_index, "[%s]:%s/%s"
						, node
						, port
						, prot_str[sock->protocol]);
			} else if (sock->ai_family == AF_INET) { // IPv4
				face_info_index += SPRINTF_FACETYPE_URI(face_info + face_info_index, faces->type, uri);
				face_info_index +=
					sprintf (face_info + face_info_index, "%s:%s/%s"
						, node
						, port
						, prot_str[sock->protocol]);
			} else if (face->local_f || (sock->faceid == 0)) { // LocalSocket
				face_info_index += SPRINTF_FACETYPE_URI(face_info + face_info_index, faces->type, uri);
				face_info_index +=
					sprintf (face_info + face_info_index, "LocalSocket/%s"
						, prot_str[sock->protocol]);
			} else {
				faces = faces->next;
				continue;
			}

			/* Output other info */
			face_info_index += sprintf (face_info + face_info_index, " RtCost=%d", faces->metric.cost);
			if (output_opt_f & CefC_Ctrl_StatusOpt_Metric) {
				face_info_index +=
					sprintf (face_info + face_info_index, ";DummyMetric=%d", faces->metric.dummy_metric);
			}

			face_info_index += sprintf (face_info + face_info_index, "\n");
			faces = faces->next;
		}

		sprintf (work_str, "%s", face_info);
		if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
			return (-1);
		}

		memset (uri, 0, sizeof(uri));
		index++;
	}

	return (0);
}
#endif  // CefC_Develop
/*--------------------------------------------------------------------------------------
	Output PIT status
----------------------------------------------------------------------------------------*/
#define	NUM_PIT_OUT_MAX	128
#define	MIN(a,b)		((a)>(b)?(b):(a))
#define	MAX(a,b)		((a)<(b)?(b):(a))
static int
cef_status_pit_output (
	CefT_Hash_Handle* handle,
	uint16_t output_opt_f,
	uint16_t num_of_pit
) {
	uint32_t index = 0, index_1st = 0;
	int table_num = 0;
	int i = 0;
	char uri[CefC_NAME_BUFSIZ] = {0};
	uint32_t chunk_num = 0;
	int res = 0;
	CefT_Down_Faces* dnfaces = NULL;
	CefT_Up_Faces* upfaces = NULL;

	uint16_t dec_name_len;

	char face_info[BUFSIZ] = {0};
	int face_info_index = 0;

	uint16_t sub_type;
	uint16_t sub_length;
	uint16_t name_index;
	struct tlv_hdr* thdr;
	uint16_t chunknum_f;
	char work_str[CefC_Max_Length*2];
	int fret = 0;
	uint32_t elem_num, elem_index;
	uint64_t nowt = cef_client_present_timeus_get ();		// 2023/04/05 by iD
	CefT_Pit_Entry* entry = NULL;

	/* get table num		*/
	table_num = cef_lhash_tbl_item_num_get (*handle);
	if (table_num == 0) {
		sprintf (work_str, "\n  Entry is empty\n");
		if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
			return (-1);
		}
		return (0);
	}

	sprintf (work_str, " %d\n", table_num);
	if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
		return (-1);
	}

	if ( output_opt_f & CefC_Ctrl_StatusOpt_Numofpit ) {
		table_num = MIN(num_of_pit, table_num);
	} else {
		table_num = MIN(NUM_PIT_OUT_MAX, table_num);
	}

	if ( !cef_lhash_tbl_elem_get (*handle, &index_1st, &elem_num) ){
		return (0);
	}

	/* output table		*/
	for (i = 0; i < table_num; ) {
		elem_num = 0;

		if (!cef_lhash_tbl_elem_get (*handle, &index, &elem_num)) {
			break;
		}

		for (elem_index = 0; elem_index < elem_num; elem_index++) {
			entry = (CefT_Pit_Entry*) cef_lhash_tbl_item_get_from_index (*handle, index, elem_index);

			if ( !entry )
				continue;
			if (entry->dnfacenum < 1)
				continue;
			if (entry->adv_lifetime_us < nowt)
				continue;
			if (!cef_pit_entry_lock(entry))
				continue;

			/* Gets Chunk Number 	*/
			name_index 		= 0;
			chunknum_f 		= 0;
			dec_name_len 	= 0;

			while (name_index < entry->klen) {
				thdr = (struct tlv_hdr*)(&entry->key[name_index]);
				sub_type 	= ntohs (thdr->type);
				sub_length  = ntohs (thdr->length);
				name_index += CefC_S_TLF;

				if ( CefC_NAME_MAXLEN <= sub_length ){
					break;
				}

				switch (sub_type) {
					case CefC_T_NAMESEGMENT: {
						dec_name_len += CefC_S_TLF + sub_length;
						break;
					}
					case CefC_T_CHUNK: {
						chunknum_f = 1;
						chunk_num = 0;
			    		for (int j = 0; j < sub_length; j++) {
							chunk_num = (chunk_num << 8) | entry->key[name_index+j];
			    		}
						break;
					}
					default: {
						dec_name_len += CefC_S_TLF + sub_length;
						break;
					}
				}
				name_index += sub_length;
			}

			memset (uri, 0, sizeof(uri));
			res = cef_frame_conversion_name_to_uri (entry->key, dec_name_len, uri);
			if (res < 0) {
				cef_pit_entry_unlock(entry);
				continue;
			}

			/* output uri	*/
			if (chunknum_f) {
#ifdef	CefC_Develop
				sprintf (work_str, "  %s/Chunk=%d, PitType=%d, longlife=%d\n", uri, chunk_num, entry->PitType, entry->longlife_f);
#else
				sprintf (work_str, "  %s/Chunk=%d\n", uri, chunk_num);
#endif
				if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
					goto cef_status_pit_output_err_ret;
				}
			} else {
#ifdef	CefC_Develop
				sprintf (work_str, "  %s, PitType=%d, longlife=%d\n", uri, entry->PitType, entry->longlife_f);
#else
				sprintf (work_str, "  %s\n", uri);
#endif
				if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
					goto cef_status_pit_output_err_ret;
				}
			}

			/* output down faces	*/
			dnfaces = entry->dnfaces.next;
			face_info_index = sprintf (face_info, "    DownFaces : ");
			while (dnfaces != NULL) {
				face_info_index += sprintf (
										face_info + face_info_index, "%d ", dnfaces->faceid);
				dnfaces = dnfaces->next;
			}
			sprintf (work_str, "%s\n", face_info);
			if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
				goto cef_status_pit_output_err_ret;
			}

			/* output upfaces	*/
			upfaces = entry->upfaces.next;
			face_info_index = sprintf (face_info, "    UpFaces   : ");
			while (upfaces != NULL) {
				face_info_index += sprintf (
										face_info + face_info_index, "%d ", upfaces->faceid);
				upfaces = upfaces->next;
			}
			sprintf (work_str, "%s\n", face_info);
			if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
				goto cef_status_pit_output_err_ret;
			}
			cef_pit_entry_unlock(entry);
		}
		i += elem_num;	//20230324
		index++;
	}

	if ( cef_lhash_tbl_elem_get (*handle, &index, &elem_num) && index_1st != index ){
		cef_status_add_output_to_rsp_buf("and more...\n");
	}

	return (0);

cef_status_pit_output_err_ret:
	if ( entry )
		cef_pit_entry_unlock(entry);
	cef_log_write (CefC_Log_Error, "%s(%u) cef_status_pit_output_err_ret\n", __func__, __LINE__);
	return (-1);
}

/*--------------------------------------------------------------------------------------
	Output App FIB status
----------------------------------------------------------------------------------------*/
static int
cef_status_app_forward_output (
	CefT_Hash_Handle* handle
){
	CefT_App_Reg *entry = NULL;
	int table_num = 0;
	int i = 0;
	char uri[CefC_NAME_BUFSIZ] = {0};
	int res = 0;
	char work_str[CefC_Max_Length*2];
	int fret = 0;

	CefT_Hash* ht = (CefT_Hash*)(*handle);	//20210104
	int		elem_cnt = 0;

	/* get table num		*/
	table_num = cef_hash_tbl_item_num_get (*handle);
	if (table_num == 0) {
		sprintf (work_str, "\n  Entry is empty\n");
		if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
			return (-1);
		}
		return (0);
	}

	sprintf (work_str, " %d\n", table_num);
	if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
		return (-1);
	}

	for ( i = 0; i < ht->elem_max; i++ ) {
		if (ht->tbl[i].klen > 0) {
			entry = (CefT_App_Reg *)ht->tbl[i].elem;
			elem_cnt++;
			res = cef_frame_conversion_name_to_uri (entry->name, entry->name_len, uri);
			if (res < 0) {
				continue;
			}
			/* output uri	*/
			sprintf (work_str, "  %s\n", uri);

			if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
				return (-1);
			}
			/* output faces	*/
			sprintf (work_str, "    Faces : %d\n", entry->faceid);
			if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
				return (-1);
			}
			if ( elem_cnt >= table_num ) {
				break;
			}
		}
	}

	return (0);
}

/*--------------------------------------------------------------------------------------
	Output PIT status ONLY
----------------------------------------------------------------------------------------*/
int
cef_status_stats_output_pit (
	CefT_Netd_Handle* hdl						/* cefnetd handle						*/
) {
	uint32_t index = 0;
	int table_num = 0;
	int i = 0;
	char uri[CefC_NAME_BUFSIZ] = {0};
	uint32_t chunk_num = 0;
	int res = 0;
	CefT_Down_Faces* dnfaces = NULL;
	CefT_Up_Faces* upfaces = NULL;
	uint16_t dec_name_len;
	char face_info[BUFSIZ] = {0};
	int face_info_index = 0;
	uint16_t sub_type;
	uint16_t sub_length;
	uint16_t name_index;
	struct tlv_hdr* thdr;
	uint16_t chunknum_f;
	CefT_Hash_Handle* handle;
	uint32_t elem_num, elem_index;

	FILE* fp = NULL;

	fp = fopen ("/tmp/cefore_pit_info", "w");
	if (fp == NULL) {
		cef_log_write (CefC_Log_Error,
			"<Fail> Write /tmp/cefore_pit_info (%s)\n", strerror (errno));
		return (1);
	}

	for (int pit_cnt = 0; pit_cnt < 2; pit_cnt++) {
		if (pit_cnt == 0) {
			handle = &hdl->app_pit;
			fprintf (fp, "PIT(App) :");
		} else {
			handle = &hdl->pit;
			fprintf (fp, "PIT :");
		}

		/* get table num		*/
		table_num = cef_lhash_tbl_item_num_get (*handle);
		if (table_num == 0) {
			fprintf (fp, "\n  Entry is empty\n");
			continue;
		}

		fprintf (fp, " %d\n", table_num);

		/* output table		*/
		for (i = 0; i < table_num; i++) {
			elem_num = 0;
			if (!cef_lhash_tbl_elem_get (*handle, &index, &elem_num)) {
				fprintf (fp, "entry is NULL\n");
				continue;
			}

			for (elem_index = 0; elem_index < elem_num; elem_index++) {
				CefT_Pit_Entry* entry;
				entry = (CefT_Pit_Entry*) cef_lhash_tbl_item_get_from_index (*handle, index, elem_index);

				if ( !entry )
					continue;

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
							chunk_num = 0;
				    		for (int j = 0; j < sub_length; j++) {
								chunk_num = (chunk_num << 8) | entry->key[name_index+j];
				    		}
							break;
						}
						default: {
							dec_name_len += CefC_S_TLF + sub_length;	//20190918 For HEX_Type
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
					fprintf (fp, "  %s/Chunk=%d\n", uri, chunk_num);
				} else {
					fprintf (fp, "  %s\n", uri);
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
				fprintf (fp, "%s\n", face_info);

				/* output upfaces	*/
				upfaces = entry->upfaces.next;
				face_info_index = sprintf (face_info, "    UpFaces   : ");
				while (upfaces != NULL) {
					face_info_index += sprintf (
											face_info + face_info_index, "%d ", upfaces->faceid);
					upfaces = upfaces->next;
				}

				fprintf (fp, "%s\n", face_info);
			}
			index++;
		}
	}

	fclose (fp);
	return (1);
}
/*--------------------------------------------------------------------------------------
	Add output to response buffer
----------------------------------------------------------------------------------------*/
static int
cef_status_add_output_to_rsp_buf(
	char* buff
) {

#if 1
	int		rsp_buf_len = strlen(rsp_bufp);
	int		buff_len	= strlen(buff);

	if ( (rsp_buf_len + buff_len) >= ( rsp_buf_size - 1) ) {
		void *new = realloc(rsp_bufp, rsp_buf_size+(CefC_Max_Length*10));
		if (new == NULL) {
			free( rsp_bufp );
			rsp_bufp = NULL;
			return(-1);
		}
		rsp_bufp = new;
		rsp_buf_size += (CefC_Max_Length*10);
	}
	strncpy( rsp_bufp + rsp_buf_len, buff, buff_len+1 );


#else
	if ((strlen(rsp_bufp)+strlen(buff)) >= (rsp_buf_size-1)){
		void *new = realloc(rsp_bufp, rsp_buf_size+(CefC_Max_Length*10));
		if (new == NULL) {
			free( rsp_bufp );
			return(-1);
		}
		rsp_bufp = new;
		rsp_buf_size += (CefC_Max_Length*10);
	}
	strcat(rsp_bufp, buff);
#endif

	return(0);
}
#if ((defined CefC_CefnetdCache) && (defined CefC_Develop))
/*--------------------------------------------------------------------------------------
	Output LocalCache status
----------------------------------------------------------------------------------------*/
static int
cef_status_localcache_output (
	uint16_t output_opt_f
) {
	char work_str[CefC_Max_Length*2];
	char buff_str[CefC_Max_Length];
	int fret = 0;

	if (!(output_opt_f & CefC_Ctrl_StatusOpt_LCache)) {
		return (0);
	}

	sprintf (work_str, "Local Cache :");
	if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
		return (-1);
	}

	fret = cef_mem_cache_mstat_get_buff (buff_str, CefC_Max_Length);

	if (fret == 0) {
		sprintf (work_str, "\n  Cache is empty\n");
		if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
			return (0);
		}
	} else {
		uint16_t *val16t;
		uint32_t *val32t;
		uint64_t *val64t;
		uint32_t entry_num;
		int cnt;
		int num = 0;
		char* wk_buff = buff_str;
		char* wk_work = work_str;

		val32t = (uint32_t*)wk_buff;
		entry_num = *val32t;
		wk_buff += 4;
		if (entry_num == 0) {
			sprintf (work_str, "\n  Cache is empty\n");
			if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
				return (0);
			}
			return (0);
		}

		num = sprintf (wk_work, "\nName    Ver    Size    Cobs    Start-End    Access    Access(Ver)\n");
		wk_work += num;

		for (cnt = 0; cnt < entry_num; cnt++) {
			/* Name */
			val32t = (uint32_t*)wk_buff;
			wk_buff += 4;
			memcpy (wk_work, wk_buff, *val32t);
			wk_work += *val32t;
			wk_buff += *val32t;

			/* Version */
			num = sprintf (wk_work, "    ");
			wk_work += num;
			val16t = (uint16_t*)wk_buff;
			wk_buff += 2;
			memcpy (wk_work, wk_buff, *val16t);
			wk_work += *val16t;
			wk_buff += *val16t;

			/* Size */
			val64t = (uint64_t*)wk_buff;
			num = sprintf (wk_work, "    "FMTU64, *val64t);
			wk_work += num;
			wk_buff += 8;

			/* Cob */
			val64t = (uint64_t*)wk_buff;
			num = sprintf (wk_work, "    "FMTU64, *val64t);
			wk_work += num;
			wk_buff += 8;

			/* Min-Max */
			val64t = (uint64_t*)wk_buff;
			num = sprintf (wk_work, "    "FMTU64"-", *val64t);
			wk_work += num;
			wk_buff += 8;
			val64t = (uint64_t*)wk_buff;
			num = sprintf (wk_work, FMTU64, *val64t);
			wk_work += num;
			wk_buff += 8;

			/* AC */
			val64t = (uint64_t*)wk_buff;
			num = sprintf (wk_work, "    "FMTU64, *val64t);
			wk_work += num;
			wk_buff += 8;

			/* AC(ver) */
			val64t = (uint64_t*)wk_buff;
			num = sprintf (wk_work, "    "FMTU64"\n", *val64t);
			wk_work += num;
			wk_buff += 8;
		}
		if (buff_str[fret] == '*') {
			sprintf (work_str, "and more...\n");
		}
		if ((fret=cef_status_add_output_to_rsp_buf(work_str)) != 0){
			return (-1);
		}
	}

	return (0);
}
#endif //((defined CefC_CefnetdCache) && (defined CefC_Develop))

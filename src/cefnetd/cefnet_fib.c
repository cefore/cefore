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
 * cefnet_fib.c
 */

#define __CEFNET_FIB_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include "cef_netd.h"
#include "cefore/cef_fib.h"

#define CefC_Fib_DefaultRoute_Len	4

#define	CefC_BufSiz_1KB			1024
#define	CefC_BufSiz_2KB			2048
#define	CefC_KeyIdSiz			CefC_KeyId_SIZ
#define	CefC_UserIdSiz			512

static char prot_str[5][16] = {"invalid", "tcp", "udp", "invalid", "quic"};

static void
cefnetd_fib_set_faceid (
	CefT_Fib_Entry* entry,
	int faceid,
	uint8_t type,							//0.8.3c
	CefT_Fib_Metric*	fib_metric,			//0.8.3c
	int keyid_len,
	unsigned char*  keyid
) {
	CefT_Fib_Face* face = &(entry->faces);

	while (face->next) {
		face = face->next;
		//if ((face->faceid == faceid) && (strncmp ((char*)face->keyid, (char*)keyid, CefC_Fib_Keyid_Len) == 0)) {
		if ((face->faceid == faceid) &&
			((keyid == NULL && face->keyid_len == 0) ||
				((face->keyid_len == keyid_len) &&
				 !memcmp (face->keyid, keyid, CefC_Fib_Keyid_Len))
			)){

			face->type |= type;

			if ( fib_metric != NULL ) {
				memcpy(&(face->metric), fib_metric, sizeof(CefT_Fib_Metric));
			}

			return;
		}
	}

	face->next = (CefT_Fib_Face*) malloc (sizeof (CefT_Fib_Face));
	if ( !face->next ){
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "malloc(CefT_Fib_Face), failed.");
#endif // CefC_Debug
		return;
	}
	memset(face->next, 0x00, sizeof (CefT_Fib_Face));
	face->next->faceid = faceid;
	face->next->type = type;
	face->next->next = NULL;
	face->next->tx_int = 0;
	face->next->tx_int_types[0] = 0;
	face->next->tx_int_types[1] = 0;
	face->next->tx_int_types[2] = 0;
	if ( fib_metric != NULL ) {
		memcpy(&(face->next->metric), fib_metric, sizeof(CefT_Fib_Metric));
	}

	memset (&(face->next->keyid), 0, sizeof(face->next->keyid));
	if ( keyid != NULL && keyid_len > 0 ) {
		memcpy (&(face->next->keyid), keyid, keyid_len);
	}
	face->next->keyid_len = keyid_len;

#ifdef	__FIB_METRIC_DEV__
	fprintf( stderr, "[%s] face->next->metric.cost:%d   face->next->metric.dummy_metric:%d \n",
							__func__, face->next->metric.cost, face->next->metric.dummy_metric );
#endif

	return;
}

/*--------------------------------------------------------------------------------------
	Remove the specified face from the forwarding destination of the FIB entry.
----------------------------------------------------------------------------------------*/
static int
cefnetd_fib_remove_faceid (
	CefT_Fib_Entry* entry,
	int faceid,
	uint8_t fe_type,
	int keyid_len,
	unsigned char*  keyid
) {
	CefT_Fib_Face* face = &(entry->faces);
	CefT_Fib_Face* prev = face;

	while (face->next) {
		face = face->next;
		if ((face->faceid == faceid) &&
			(keyid == NULL ||
				((face->keyid_len == keyid_len) &&
				 !memcmp (face->keyid, keyid, CefC_Fib_Keyid_Len))
			)){

			face->type &= ~fe_type;

			if (fe_type > face->type) {
				prev->next = face->next;
				free (face);
			}
			return (1);
		}
		prev = face;
	}

	return (-1);
}

/*--------------------------------------------------------------------------------------
	Obtain the Name from the received route message
----------------------------------------------------------------------------------------*/
int
cefnetd_fib_name_get_from_route_msg (
	unsigned char* msg, 					/* the received message(s)					*/
	int msg_size,
	unsigned char* name
) {
	int index = 0;
	char uri[CefC_NAME_MAXLEN];
	uint16_t uri_len;
	int name_len;

	if ((msg_size - index) < sizeof (uint8_t)) {
		return (-1);
	}
	index += sizeof (uint8_t);

	if ((msg_size - index) < sizeof (uint8_t)) {
		return (-1);
	}
	index += sizeof (uint8_t);

	memcpy (&uri_len, &msg[index], sizeof (uint16_t));
	index += sizeof (uint16_t);
	if (uri_len <= 0) {
		return (-1);
	}
	if ((msg_size - index) < uri_len) {
		return (-1);
	}
	memcpy (uri, &msg[index], uri_len);
	uri[uri_len] = 0x00;
	index += uri_len;

	name_len = cef_frame_conversion_uri_to_name ((const char*) uri, name);
	if ((name_len < 0) || (name_len > CefC_NAME_MAXLEN)) {
		cef_log_write (CefC_Log_Error, "Invalid URI, \"%s\"\n", uri);
		return (-1);
	}

	return (name_len);
}
/*--------------------------------------------------------------------------------------
	Add route in FIB
----------------------------------------------------------------------------------------*/
int
cefnetd_fib_route_add (
	CefT_Hash_Handle fib,					/* FIB										*/
	int faceid,								/* face id									*/
	uint8_t fe_type,						/* CefC_Fib_Entry_XXX				0.8.3c	*/
	CefT_Fib_Metric	*fib_metric,			//0.8.3c
	int name_len,
	unsigned char *name,
	int keyid_len,							/* extantion for full-source forwarding		*/
	unsigned char *keyid					/* extantion for full-source forwarding		*/
) {
	CefT_Fib_Entry* entry;

	/* search this name from FIB */
	entry = (CefT_Fib_Entry*) cef_hash_tbl_item_get (fib, name, name_len);
	if (entry == NULL) {
		if(cef_hash_tbl_item_num_get(fib) == cef_hash_tbl_def_max_get(fib)) {
			cef_log_write (CefC_Log_Error,
				"FIB table is full(FIB_SIZE = %d)\n", cef_hash_tbl_def_max_get(fib));
			return (-1);
		}

		/* create new entry */
		entry = cef_fib_entry_create (name, name_len);
		cef_hash_tbl_item_set (fib, name, name_len, entry);
	}

	cefnetd_fib_set_faceid (entry, faceid, fe_type, fib_metric, keyid_len, keyid);

	if (name_len == CefC_Fib_DefaultRoute_Len) {
		cef_fib_set_default_route (entry);
	}
	return (1);
}
/*--------------------------------------------------------------------------------------
	Delete route in FIB
----------------------------------------------------------------------------------------*/
int
cefnetd_fib_route_del (
	CefT_Hash_Handle fib,					/* FIB										*/
	int faceid,								/* face id									*/
	uint8_t fe_type,						/* CefC_Fib_Entry_XXX				0.8.3c	*/
	int name_len,
	unsigned char *name,
	int keyid_len,
	unsigned char *keyid
) {
	CefT_Fib_Entry* fib_entry;
	int res, num_faces = -1;

	/* search this name from FIB */
	fib_entry = (CefT_Fib_Entry*) cef_hash_tbl_item_get (fib, name, name_len);
	if (fib_entry == NULL) {
		/* URI not found */
		return (-1);
	}

	/* remove the specified face from fib entry */
	res = cefnetd_fib_remove_faceid (fib_entry, faceid, fe_type, keyid_len, keyid);
	if (res <= 0) {
		return (-2);
	}

	/* Checks whether the face is referenced by another FIB entry */
	/* and close the face if no one is using it. */
	{
		uint32_t index = 0;
		CefT_Fib_Entry *check_fe;
		int	 f_exist = 0;

		for ( f_exist = 0;
				!f_exist &&
				(check_fe = (CefT_Fib_Entry*)
					cef_hash_tbl_item_check_from_index (fib, &index)) != NULL;
					index++ ){
			CefT_Fib_Face *current = &(check_fe->faces);

			/* Check each FIB entry for the face it references. */
			while (!f_exist && current->next) {
				current = current->next;
				if(faceid == current->faceid) {
					/* It is referenced by other FIB entries. */
					f_exist = 1;
					break;
				}
			}
		}

		if (!f_exist) {
			/* This face is not referenced in any FIB entry */
			/* and close the face if no one is using it. */
			cef_face_close (faceid);
		}
	}

	/* check fib entry */
	if (fib_entry->faces.next == NULL) {
		/* fib entry is empty */
		fib_entry = (CefT_Fib_Entry*) cef_hash_tbl_item_remove (fib, name, name_len);
		free (fib_entry->key);
		fib_entry->key = NULL;
		free (fib_entry);
		fib_entry = NULL;

		num_faces = 0;
	} else {
		CefT_Fib_Face *current = fib_entry->faces.next;
		for ( num_faces = 0; current != NULL; num_faces++ ){
			current = current->next;
		}
	}

	return (num_faces);
}
/*--------------------------------------------------------------------------------------
	Process the FIB route message
----------------------------------------------------------------------------------------*/
int
cefnetd_fib_route_msg_process (
	CefT_Hash_Handle fib,					/* FIB										*/
	unsigned char* msg, 					/* the received message(s)					*/
	int msg_size,							/* size of received message(s)				*/
	uint8_t fe_type,							/* CefC_Fib_Entry_XXX						*/
	int* rc, 								/* 0x01=New Entry, 0x02=Free Entry 0.8.3c	*/
	CefT_Fib_Metric*	fib_metric
) {
	uint8_t op;
	uint8_t prot;
	uint8_t host_len;
	char host[64] = {0};
	int index = 0;
	char uri[CefC_NAME_MAXLEN];
	uint16_t uri_len;
	int res = -1;
	unsigned char name[CefC_NAME_MAXLEN];
	int name_len;
	CefT_Fib_Entry* bentry;
	CefT_Fib_Entry* aentry;
	//
	CefT_Fib_Face* faces = NULL;
	int			b_type_c = 0;
	int			b_type_s = 0;
	int			a_type_c = 0;
	int			a_type_s = 0;
	//
	int cost = 0;
	int keyid_len = 0;
	unsigned char keyid[CefC_Fib_Keyid_Len] = {0};
	CefT_Fib_Metric fib_metric_tmp;

	memset( &fib_metric_tmp, 0x00, sizeof(CefT_Fib_Metric) );

	/* Inits the return code 		*/
	*rc = 0x00;

	/* get operation */
	if ((msg_size - index) < sizeof (op)) {
		/* message is too short */
		return (-1);
	}
	op = msg[index];
	index += sizeof (op);

	/* get protocol */
	if ((msg_size - index) < sizeof (prot)) {
		/* message is too short */
		return (-1);
	}
	prot = msg[index];
	index += sizeof (prot);

	/* get uri */
	memcpy (&uri_len, &msg[index], sizeof (uint16_t));
	index += sizeof (uint16_t);
	if (uri_len <= 0) {
		/* message is too short */
		return (-1);
	}
	if ((msg_size - index) < uri_len) {
		/* message is too short */
		return (-1);
	}
	memcpy (uri, &msg[index], uri_len);
	uri[uri_len] = 0x00;
	index += uri_len;

	name_len = cef_frame_conversion_uri_to_name ((const char*) uri, name);
	if ((name_len < 0)) {
		cef_log_write (CefC_Log_Error, "Invalid URI, \"%s\"\n", uri);
		return (-1);
	}
	if (CefC_NAME_MAXLEN < name_len) {
		cef_log_write (CefC_Log_Error,
			"T_NAME is too long (%d bytes), "
			"cefore does not support T_NAMEs longer than %u bytes.\n",
				name_len, CefC_NAME_MAXLEN);
		return (-1);
	}

	/* get rtcost */
	if (strncmp ((char *)&msg[index], CefC_Fib_RtCost_Identifier, strlen(CefC_Fib_RtCost_Identifier)) == 0) {
		index += strlen(CefC_Fib_RtCost_Identifier);
		memcpy (&cost, &msg[index], sizeof(int));
		index += sizeof(int);

		if (fib_metric == NULL) {
			fib_metric_tmp.cost = cost;
			fib_metric_tmp.dummy_metric = 0;
			fib_metric = &fib_metric_tmp;
		} else {
			fib_metric->cost = cost;
		}
	}

	/* get keyid */
	if (strncmp ((char *)&msg[index], CefC_Fib_Keyid_Identifier, strlen(CefC_Fib_Keyid_Identifier)) == 0) {
		index += strlen(CefC_Fib_Keyid_Identifier);
		memcpy (keyid, &msg[index], CefC_Fib_Keyid_Len);
		keyid_len = CefC_Fib_Keyid_Len;
		index += CefC_Fib_Keyid_Len;
	}

	bentry = cef_hash_tbl_item_get(fib, name, name_len);
	//FaceInfo
	if ( bentry != NULL ) {
		faces = bentry->faces.next;
		while (faces != NULL) {

			if ( faces->type & CefC_Fib_Entry_Ctrl ) {
				b_type_c = 1;
			}
			if ( faces->type & CefC_Fib_Entry_Static ) {
				b_type_s = 1;
			}
			faces = faces->next;
		}
	}

	while (index < msg_size) {
		int faceid = -1;

		/* get host */
		if ((msg_size - index) < sizeof (host_len)) {
			/* message is too short */
			return (-1);
		}
		host_len = msg[index];
		index += sizeof (host_len);
		if ((msg_size - index) < host_len) {
			/* message is too short */
			return (-1);
		}
		memcpy (host, &msg[index], host_len);
		host[host_len] = 0x00;
		index += host_len;

		if (!cef_fib_check_addr(host)) {
			continue;
		}

		if (op == CefC_Fib_Route_Ope_Add) {
			/* Lookup Face */
			faceid = cef_face_lookup_faceid_from_addrstr (host, prot_str[prot]);
			if ( faceid < 0 ){
				/* face resource empty */
				cef_log_write (CefC_Log_Error,
					"Failed to create Face:ID=%s, Prot=%s\n", host, prot_str[prot]);
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine,
					"Failed to create Face:ID=%s, Prot=%s\n", host, prot_str[prot]);
#endif
				return (-1);
			}
			res = cefnetd_fib_route_add (fib, faceid, fe_type, fib_metric,
						name_len, name, keyid_len, keyid);
			switch ( res ){
			case 1:
				cef_log_write (CefC_Log_Info,
					"Insert the FIB entry: URI=%s, Prot=%s, Next=%s, Face=%d\n",
					uri, prot_str[prot], host, faceid);
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine,
					"Insert the FIB entry: URI=%s, Prot=%s, Next=%s, Face=%d\n",
					uri, prot_str[prot], host, faceid);
#endif // CefC_Debug
			default:
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine, "cefnetd_fib_route_add:res=%d\n", res);
#endif // CefC_Debug
				break;
			}
		} else if (op == CefC_Fib_Route_Ope_Del) {
			/* Search Face */
			faceid = cef_face_search_faceid (host, prot_str[prot]);

			if (faceid <= 0) {
				cef_log_write (CefC_Log_Error,
					"%s (%s) is not registered in the Face Table\n",
					host, prot_str[prot]);
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine,
					"%s (%s) is not registered in the Face Table\n",
					host, prot_str[prot]);
#endif // CefC_Debug
				return (-1);
			}

			res = cefnetd_fib_route_del (fib, faceid, fe_type,
						name_len, name, keyid_len, keyid);
			switch ( res ){
			case -1:
				cef_log_write (CefC_Log_Error,"%s is not registered in FIB\n", uri);
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine, "%s is not registered in FIB\n", uri);
#endif // CefC_Debug
				break;
			case -2:
				cef_log_write (CefC_Log_Error,
					"%s (%s) is not registered in FIB entry [ %s ]\n",
					host, prot_str[prot], uri);
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine,
					"%s (%s) is not registered in FIB entry [ %s ]\n",
					host, prot_str[prot], uri);
#endif // CefC_Debug
				break;
			default:
				/* If res is 1 or more, the number of destination faces remaining in the entry */
				cef_log_write (CefC_Log_Info,
					"Remove the FIB face: URI=%s, Prot=%s, Next=%s, Face=%d\n",
					uri, prot_str[prot], host, faceid);
				if ( res == 0 )
					cef_log_write (CefC_Log_Info, "Delete the FIB entry: URI=%s\n", uri);
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine,
					"Remove the FIB face: URI=%s, Prot=%s, Next=%s, Face=%d\n",
					uri, prot_str[prot], host, faceid);
				if ( res == 0 )
					cef_dbg_write (CefC_Dbg_Fine, "Delete the FIB entry: URI=%s\n", uri);
#endif // CefC_Debug
				break;
			}
		}
	}
	aentry = cef_hash_tbl_item_get(fib, name, name_len);
	//FaceInfo
	if ( aentry != NULL ) {
		faces = aentry->faces.next;
		while (faces != NULL) {

			if ( faces->type & CefC_Fib_Entry_Ctrl ) {
				a_type_c = 1;
			}
			if ( faces->type & CefC_Fib_Entry_Static ) {
				a_type_s = 1;
			}
			faces = faces->next;
		}
	}

	if (bentry) {
		if (aentry == NULL) {
			*rc = 0x02;
		}
	} else {
		if (aentry) {
			*rc = 0x01;
		}
	}
	//Face Modify Check
	if ( (bentry != NULL) && (aentry != NULL) ) {
		if ( (b_type_c == 0) && (b_type_s == 0) ) {
			if ( (a_type_c == 1) || (a_type_s == 1) ) {
				*rc = 0x01;
			}
		} else if ( (b_type_c == 1) || (b_type_s == 1) ) {
			if ( (a_type_c == 0) && (a_type_s == 0) ) {
				*rc = 0x02;
			}
		} else {
			*rc = 0x00;
		}
	}

	return (res);
}

/*--------------------------------------------------------------------------------------
	Reads the FIB configuration file
----------------------------------------------------------------------------------------*/
#define CefC_Fib_DefaultRoute_Len	4
#define CefC_Fib_Addr_Max		32
#define CefC_Fib_Addr_Siz		INET6_ADDRSTRLEN
static int
cefnetd_route_msg_create(
	unsigned char *msgbuf,
	uint8_t		op,
	uint8_t		prot,
	const char *uri,
	int			addr_num,
	char		addr[CefC_Fib_Addr_Max][CefC_Fib_Addr_Siz]
) {
	int i, index = 0;
	uint16_t	uri_len = 0;

	if ( !uri || uri[0] <= ' ' )
		return (-1);

	msgbuf[index++] = op;
	msgbuf[index++] = prot;
	uri_len = strlen(uri);
	if ( CefC_NAME_MAXLEN < uri_len ){
		cef_log_write (CefC_Log_Error,
			"URL is too long (%d bytes), cefore does not support T_NAMEs longer than %u bytes.\n",
				uri_len, CefC_NAME_MAXLEN);
		return (-1);
	}
	memcpy(&msgbuf[index], &uri_len, sizeof(uri_len));
	index += sizeof(uri_len);
	memcpy(&msgbuf[index], uri, uri_len);
	index += uri_len;

	for ( i = 0; i < addr_num; i++ ){
		struct addrinfo hints;
		struct addrinfo* gai_res;
		struct addrinfo* gai_cres;
		uint8_t host_len;
		char host[CefC_NAME_BUFSIZ] = {0};
		char addr_str[INET6_ADDRSTRLEN];
		char port_str[INET6_ADDRSTRLEN], *port_ptr = NULL;
		char ifname[INET6_ADDRSTRLEN], *ifname_ptr = NULL;
		char *IPv6_endmark = NULL;
		int	 err;

		memset (&hints, 0, sizeof (hints));
		memset (addr_str, 0, sizeof (addr_str));
		memset (port_str, 0, sizeof (port_str));
		memset (ifname, 0, sizeof (ifname));

		strcpy(host, addr[i]);
		IPv6_endmark = strchr(host, ']');	/* Rules for enclosing IPv6 strings in [] */

		if ( host[0] != '[' ){			/* not IPv6 */
			if ( (port_ptr = strchr(host, ':')) != NULL ){
				strcpy(port_str, port_ptr);
				*port_ptr++ = '\0';
			}
		} else if ( IPv6_endmark ) {	/* IPv6 */
			*IPv6_endmark++ = '\0';
			if ( (port_ptr = strchr(IPv6_endmark, ':')) != NULL ){
				strcpy(port_str, port_ptr);
				*port_ptr++ = '\0';
			}
			strcpy(host, &host[1]);
			/*-----------------------------------------------------------*
				When specifying the next hop with a link-local address,
				you must also specify the interface name with the IFNAME
			 *-----------------------------------------------------------*/
			ifname_ptr = strchr(host, '%');
			if ( ifname_ptr ){
				strcpy(ifname, ifname_ptr);
			}
		}
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "host=%s, port=%s, ifname=%s\n", host, port_str, ifname);
#endif // CefC_Debug

		hints.ai_family = AF_UNSPEC;
		hints.ai_flags = AI_NUMERICSERV;
		if (prot != CefC_Face_Type_Tcp) {
			hints.ai_socktype = SOCK_DGRAM;
		} else {
			hints.ai_socktype = SOCK_STREAM;
		}

		/* This getaddrinfo converts the host name to an IPv4/v6 address */
		if ((err = getaddrinfo (host, port_ptr, &hints, &gai_res)) != 0) {
			cef_log_write (CefC_Log_Error,
				"getaddrinfo(%s)=%s\n", host, gai_strerror(err));
			return (-1);
		}
		for (gai_cres = gai_res ; gai_cres != NULL && !addr_str[0]; gai_cres = gai_cres->ai_next) {
			struct sockaddr_in *ai = (struct sockaddr_in *)(gai_cres->ai_addr);
			struct sockaddr_in6 *ai6 = (struct sockaddr_in6 *)(gai_cres->ai_addr);

			switch ( ai->sin_family ){
			case AF_INET:
				inet_ntop(ai->sin_family, &(ai->sin_addr), addr_str, sizeof(addr_str));
				sprintf(host, "%s", addr_str);
				break;
			case AF_INET6:
				inet_ntop(ai6->sin6_family, &(ai6->sin6_addr), addr_str, sizeof(addr_str));
				if ( ifname[0] ){
					sprintf(host, "[%s%s]", addr_str, ifname);
				} else {
					sprintf(host, "[%s]", addr_str);
				}
				break;
			default:
				continue;
			}
		}
		freeaddrinfo (gai_res);
		if ( port_str[0] ){
			strcat(host, port_str);
		}

#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "host=%s, addr=%s\n", host, addr_str);
#endif // CefC_Debug
		host_len = strlen(host);
		msgbuf[index++] = host_len;
		memcpy(&msgbuf[index], host, host_len);
		index += host_len;
	}
	return index;
}

static int
cefnetd_fib_parse_line (
	char* p, 									/* target string for trimming 			*/
	char* name,									/* name string after trimming			*/
	char* prot,									/* protocol string after trimming		*/
	char addr[CefC_Fib_Addr_Max][CefC_Fib_Addr_Siz]
) {
	int addr_num = 0;
	char* wp;


	if ((*p == 0x23) || (*p == 0x0D) || (*p == 0x0A)|| (*p == 0x00)) {
		return (0);
	}

	wp = p;
	while (*wp) {
		if ((*wp == 0x0D) || (*wp == 0x0A)) {
			*wp = 0x00;
		}
		wp++;
	}

	/* URI 				*/
	wp = strtok (p," \t");
	if (wp) {
		strcpy (name, wp);
	} else {
		return (0);
	}

	/* protocol			*/
	wp = strtok (NULL, " \t");
	if (wp) {
		strcpy (prot, wp);
		if (strcmp(prot, "tcp") != 0 && strcmp(prot, "udp") != 0 && strcmp(prot, "quic") != 0) {
			return (0);
		}
	} else {
		return (0);
	}

	/* addresses		*/
	while (wp != NULL) {

		wp = strtok (NULL, " \t");

		if (wp) {
			if (cef_fib_check_addr(wp)) {
				strcpy (addr[addr_num], wp);
				addr_num++;
			}
		}

		if (addr_num == CefC_Fib_Addr_Max) {
			break;
		}
	}

	return (addr_num);
}

/*--------------------------------------------------------------------------------------
	Reads the FIB configuration file
----------------------------------------------------------------------------------------*/
int									/* Returns a negative value if it fails 	*/
cefnetd_config_fib_read (
	CefT_Netd_Handle* hdl					/* cefnetd handle							*/
) {
	char	ws[PATH_MAX];
	FILE*	fp = NULL;
	char	buff[BUFSIZ_8K+1];

	cef_client_config_dir_get (ws);
	strcat (ws, "/cefnetd.fib");

	fp = fopen (ws, "r");
	if (fp == NULL) {
		fp = fopen (ws, "w");
		if (fp == NULL) {
			cef_log_write (CefC_Log_Error, "Failed to open the FIB File (%s)\n", ws);
			return (-1);
		}
		fclose (fp);
		fp = fopen (ws, "r");
	}

	while (fgets (buff, sizeof(buff), fp) != NULL) {
		char	uri[CefC_NAME_BUFSIZ];
		char	addr[CefC_Fib_Addr_Max][CefC_Fib_Addr_Siz];
		char	prot[CefC_NAME_BUFSIZ];
		char	face_type = CefC_Face_Type_Udp;
		unsigned char	routemsg[BUFSIZ_8K] = { 0 };
		int		routemsg_len, addr_num;
		int		change_f = 0;

		buff[sizeof(buff)-1] = 0;

		if (strlen (buff) >= BUFSIZ_8K) {
			cef_log_write (CefC_Log_Warn,
				"[cefnetd.fib] Detected the too long line:%s\n", buff);
			continue;
		}

		if ((buff[0] == '#') || isspace(buff[0])) {
			continue;
		}

		/* parse the read line		*/
		addr_num = cefnetd_fib_parse_line (buff, uri, prot, addr);
		if (addr_num < 1) {
			cef_log_write (CefC_Log_Warn, "[cefnetd.fib] Invalid line:%s\n", buff);
			continue;
		}
		if ( !strcasecmp(prot, "TCP") ){
			face_type = CefC_Face_Type_Tcp;
		} else if ( !strcasecmp(prot, "QUIC") ){
			face_type = CefC_Face_Type_Quic;
		}

		routemsg_len = cefnetd_route_msg_create(routemsg,
				CefC_Fib_Route_Ope_Add, face_type, uri, addr_num, addr);

		if ( routemsg_len <= 0 )
			continue;

		if ( cefnetd_route_msg_check (hdl, routemsg, routemsg_len) < 0 )
			continue;

		cefnetd_fib_route_msg_process (hdl->fib, routemsg, routemsg_len,
				CefC_Fib_Entry_Static, &change_f, NULL);
	}

	fclose (fp);

	return (1);
}

/*--------------------------------------------------------------------------------------
	Handles the request forwarding infomation for CefBabel
----------------------------------------------------------------------------------------*/
int
cefnetd_request_forwarding_info (
	CefT_Netd_Handle* hdl,
	unsigned char** rsp_msgpp
) {
	uint32_t msg_len = 5; /* code(1byte)+length(4byte) */
	uint32_t length;
	CefT_App_Reg* aentry;
	uint32_t index = 0;
	CefT_Fib_Entry* fentry = NULL;
	int table_num;
	int i;
	char* buff;
	int buff_size;

	buff = (char*)*rsp_msgpp;
	buff_size = CefC_Max_Length;

	if (!hdl->babel_use_f) {
		buff[0] = 0x01;
		length = 0;
		memcpy (&buff[1], &length, sizeof (uint32_t));
		return (5);
	}

	do {
		aentry = (CefT_App_Reg*)
					cef_hash_tbl_item_check_from_index (hdl->app_reg, &index);

		if (aentry) {
			if ((msg_len + sizeof (uint16_t) + aentry->name_len) > buff_size){
				void *new = realloc(buff, buff_size+CefC_Max_Length);
				if (new == NULL) {
					buff[0] = 0x01;
					length = 0;
					memcpy (&buff[1], &length, sizeof (uint32_t));
					return (5);
				}
				buff = new;
				*rsp_msgpp = (unsigned char*)new;
				buff_size += CefC_Max_Length;
			}
			memcpy (&buff[msg_len], &aentry->name_len, sizeof (uint16_t));
			memcpy (&buff[msg_len + sizeof (uint16_t)], aentry->name, aentry->name_len);
			msg_len += sizeof (uint16_t) + aentry->name_len;
		}
		index++;
	} while (aentry);

	table_num = cef_hash_tbl_item_num_get (hdl->fib);
	index = 0;

	for (i = 0; i < table_num; i++) {
		fentry = (CefT_Fib_Entry*) cef_hash_tbl_elem_get (hdl->fib, &index);
		if (fentry == NULL) {
			break;
		}

		/* Face Check */
		{
			CefT_Fib_Face* faces = NULL;
			int			type_c = 0;
			int			type_s = 0;
			int			type_d = 0;

			faces = fentry->faces.next;
			while (faces != NULL) {

				if ( faces->type & CefC_Fib_Entry_Ctrl ) {
					type_c = 1;
				}
				if ( faces->type & CefC_Fib_Entry_Static ) {
					type_s = 1;
				}
				if ( faces->type & CefC_Fib_Entry_Dynamic ) {
					type_d = 1;
				}
				faces = faces->next;
			}
			if ( (type_c == 0) && (type_s == 0) && (type_d == 1) ) {
				index++;
				continue;
			}
		}

		if ((msg_len + sizeof (uint16_t) + fentry->klen) > buff_size){
			void *new = realloc(buff, buff_size+CefC_Max_Length);
			if (new == NULL) {
				buff[0] = 0x01;
				length = 0;
				memcpy (&buff[1], &length, sizeof (uint32_t));
				return (5);
			}
			buff = new;
			*rsp_msgpp = (unsigned char*)new;
			buff_size += CefC_Max_Length;
		}
		memcpy (&buff[msg_len], &fentry->klen, sizeof (uint16_t));
		memcpy (&buff[msg_len + sizeof (uint16_t)], fentry->key, fentry->klen);
		msg_len += sizeof (uint16_t) + fentry->klen;
		index++;
	}

	buff[0] = 0x01;
	length = msg_len - 5;
	memcpy (&buff[1], &length, sizeof (uint32_t));

	return ((int) msg_len);
}

/*--------------------------------------------------------------------------------------
	Handles the retrieve forwarding infomation for Ccore
----------------------------------------------------------------------------------------*/
int
cefnetd_retrieve_forwarding_info (
	CefT_Hash_Handle* fib,
	char* info_buff,
	int info_buff_size,
	const unsigned char* name,
	int name_len,
	int partial_match_f
) {
	CefT_Fib_Entry* entry;
	uint32_t index;
	int table_num;
	int i;
	CefT_Fib_Face* fib_face;
	int res;
	int cmp_len;
	uint8_t def_name_f = 0;

	index = 0;

	/* get table num		*/
	table_num = cef_hash_tbl_item_num_get (*fib);
	if (table_num == 0) {
		return (0);
	}

	/* output table		*/
	for (i = 0; i < table_num; i++) {
		char uri[CefC_NAME_MAXLEN];

		entry = (CefT_Fib_Entry*) cef_hash_tbl_elem_get (*fib, &index);
		if (entry == NULL) {
			break;
		}
		if (partial_match_f) {
			cmp_len = name_len;
			if (name_len == 4) {
				/* Name is default name. and partial match */
				/* Get All FIB entry                       */
				def_name_f = 1;
			}
		} else {
			if (name_len != entry->klen) {
				index++;
				continue;
			}
			cmp_len = name_len;
		}
		if (!def_name_f && (memcmp (name, entry->key, cmp_len) != 0)) {
			index++;
			continue;
		}

		memset (uri, 0, sizeof (uri));
		res = cef_frame_conversion_name_to_uri (entry->key, entry->klen, uri);
		if (res < 0) {
			index++;
			continue;
		}
		/* output faces	*/
		fib_face = entry->faces.next;

		while (fib_face != NULL) {
			char face_info[CefC_NAME_MAXLEN];

			res = cef_face_info_get (face_info, fib_face->faceid);

			if (res > 0) {
				char work_buff[BUFSIZ_8K];

				/**************************************************************
					I refactored the source code to optimize memory usage,
					but I can't debug it using Ccore.
				 **************************************************************/

				snprintf (work_buff, sizeof(work_buff)-1, "FIB: %s %s\n", uri, face_info);
				if (info_buff_size < (strlen(info_buff) + strlen(work_buff) - 1)){
					goto endfunc;
				}
				strcat (info_buff, work_buff);
			}
			fib_face = fib_face->next;
		}
		index++;
	}
endfunc:;
	return (strlen (info_buff));
}


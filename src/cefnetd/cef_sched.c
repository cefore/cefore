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
 * cef_sched.c
 */

#define __CEF_SCHED_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/

#include "cef_netd.h"
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

/****************************************************************************************
 ****************************************************************************************/
/*--------------------------------------------------------------------------------------
	Forwards the specified Interest
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cefnetd_interest_forward (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	uint16_t faceids[], 					/* Face-IDs to forward						*/
	uint16_t faceid_num, 					/* Number of Face-IDs to forward			*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed message 							*/
	CefT_CcnMsg_OptHdr* poh, 				/* Parsed Option Header						*/
	CefT_Pit_Entry* pe, 					/* PIT entry matching this Interest 		*/
	CefT_Fib_Entry* fe						/* FIB entry matching this Interest 		*/
) {
	CefT_FwdStrtgy_Param		fwdstr = { 0 };

	if (fe != NULL) {

		/* Forwards the Interest to next node 		*/
		if (pm->hoplimit < 1) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Not forwarded due to hop limit.\n");
#endif // CefC_Debug
			return (1);
		}

	} else {
		/* Forwards the Interest to local process, if it matches the Interest Filter 	*/
		// TBD: interest filter
	}

	if (!cef_face_is_local_face (peer_faceid)) {
		/* Updates Hoplimit 		*/
		pm->hoplimit--;
		if (pm->hoplimit < 1) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Not forwarded due to hop limit.\n");
#endif // CefC_Debug
			return (1);
		}
		msg[CefC_O_Fix_HopLimit] = pm->hoplimit;
	}

	if (hdl->fwd_strtgy_hdl->fwd_int) {

		/* Set parameters */
		fwdstr.hdl_cefnetd     = (void *)hdl;
		fwdstr.faceids         = faceids;
		fwdstr.faceid_num      = faceid_num;
		fwdstr.peer_faceid     = peer_faceid;
		fwdstr.msg             = msg;
		fwdstr.payload_len     = payload_len;
		fwdstr.header_len      = header_len;
		fwdstr.pm              = pm;
		fwdstr.poh             = poh;
		fwdstr.pe              = pe;

		if (pm->chunk_num_f){
			uint16_t name_len_wo_chunk = pm->name_len;
			name_len_wo_chunk -= (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);

			/* Find for PIT without chunk number (Anker PIT) */
			fwdstr.pe_refer        =
				(CefT_Pit_Entry*) cef_lhash_tbl_item_get (hdl->pit, pm->name, name_len_wo_chunk);

			if ( fwdstr.pe_refer == NULL ){
				/* Find PIT with lower chunk number */
				fwdstr.pe_refer    = cef_pit_entry_search_with_anychunk (hdl->pit, pm, poh);
			}
		}

		fwdstr.fe              = fe;
		fwdstr.cnt_send_frames = &(hdl->stat_send_interest);
		fwdstr.cnt_send_types  = hdl->stat_send_interest_types;

		/* Forwards the Interest according to Forwarding Strategy. */
		hdl->fwd_strtgy_hdl->fwd_int(&fwdstr);
	}

	return (1);
}
/*--------------------------------------------------------------------------------------
	Forwards the specified ccninfo request
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cefnetd_ccninforeq_forward (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	uint16_t faceids[], 					/* Face-IDs to forward						*/
	uint16_t faceid_num, 					/* Number of Face-IDs to forward			*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed message 							*/
	CefT_CcnMsg_OptHdr* poh, 				/* Parsed Option Header						*/
	CefT_Pit_Entry* pe, 					/* PIT entry matching this Interest 		*/
	CefT_Fib_Entry* fe						/* FIB entry matching this Interest 		*/
) {
	int fulldiscovery_authNZ = 0;
	CefT_FwdStrtgy_Param		fwdstr = { 0 };

	/* Ccninfo Full discovery authentication & authorization */
	if (hdl->ccninfo_full_discovery == 2 /* Authentication and Authorization */
		&& poh->ccninfo_flag & CefC_CtOp_FullDisCover) {
		fulldiscovery_authNZ = cefnetd_ccninfo_fulldiscovery_authNZ(
													hdl->ccninfousr_id_len,
													hdl->ccninfousr_node_id,
													hdl->ccninfo_rcvdpub_key_bi_len,
													hdl->ccninfo_rcvdpub_key_bi);
	}

	/* Set parameters */
	fwdstr.hdl_cefnetd     = (void *)hdl;
	fwdstr.faceids         = faceids;
	fwdstr.faceid_num      = faceid_num;
	fwdstr.peer_faceid     = peer_faceid;
	fwdstr.msg             = msg;
	fwdstr.payload_len     = payload_len;
	fwdstr.header_len      = header_len;
	fwdstr.pm              = pm;
	fwdstr.poh             = poh;
	fwdstr.pe              = pe;
	fwdstr.fe              = fe;

	/* Forwards the CcninfoReq according to Forwarding Strategy. */
	cef_forward_ccninforeq(&fwdstr, fulldiscovery_authNZ, hdl->ccninfo_full_discovery);

	return (1);
}

/*--------------------------------------------------------------------------------------
	Forwards the specified Content Object
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cefnetd_object_forward (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	uint16_t faceids[], 					/* Face-IDs to forward						*/
	uint16_t faceid_num, 					/* Number of Face-IDs to forward			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed message 							*/
	CefT_CcnMsg_OptHdr* poh, 				/* Parsed Option Header						*/
	CefT_Pit_Entry* pe	 					/* PIT entry matching this Interest 		*/
) {
	CefT_FwdStrtgy_Param		fwdstr = { 0 };
	uint16_t					name_len;

	if (hdl->fwd_strtgy_hdl->fwd_cob) {

		/* Set parameters */
		fwdstr.hdl_cefnetd     = (void *)hdl;
		fwdstr.faceids         = faceids;
		fwdstr.faceid_num      = faceid_num;
		fwdstr.msg             = msg;
		fwdstr.payload_len     = payload_len;
		fwdstr.header_len      = header_len;
		fwdstr.pm              = pm;
		fwdstr.poh             = poh;
		fwdstr.pe              = pe;
		fwdstr.cnt_send_frames = &(hdl->stat_send_frames);

		/* Searches a FIB entry matching the Interest requested this ContentObject */
		if (pm->chunk_num_f) {
			name_len = pm->name_len - (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
		} else {
			/* Symbolic Interest	*/
			name_len = pm->name_len;
		}

		fwdstr.fe = cef_fib_entry_search (hdl->fib, pm->name, name_len);

		/* Forwards the ContentObject according to Forwarding Strategy. */
		hdl->fwd_strtgy_hdl->fwd_cob(&fwdstr);

	}

	return (1);
}

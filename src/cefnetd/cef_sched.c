/*
 * Copyright (c) 2016-2020, National Institute of Information and Communications
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
#include <cefore/cef_plugin.h>

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
	CefT_Parsed_Message* pm, 				/* Parsed message 							*/
	CefT_Parsed_Opheader* poh, 				/* Parsed Option Header						*/
	CefT_Pit_Entry* pe, 					/* PIT entry matching this Interest 		*/
	CefT_Fib_Entry* fe						/* FIB entry matching this Interest 		*/
) {
	int i;
	
	if (fe != NULL) {
		
		/* Forwards the Interest to next node 		*/
		if (pm->hoplimit < 1) {
			return (1);
		}
		
	} else {
		/* Forwards the Interest to local process, if it matches the Interest Filter 	*/
		// TBD: interest filter
	}
	
	if (!cef_face_is_local_face (peer_faceid)) {
		/* Updates Hoplimit 		*/
		pm->hoplimit--;
		msg[CefC_O_Fix_HopLimit] = pm->hoplimit;
	}
	
	if (pm->hoplimit < 1) {
		return (1);
	}
	
	for (i = 0 ; i < faceid_num ; i++) {
		
		if (peer_faceid == faceids[i]) {
			continue;
		}
		cef_pit_entry_up_face_update (pe, faceids[i], pm, poh);
		
		if (cef_face_check_active (faceids[i]) > 0) {
			cef_face_frame_send_forced (
				faceids[i], msg, payload_len + header_len);
			if (hdl->forwarding_info_strategy == CefC_Default_ForwardingInfoStrategy) {
				break;
			}
		} else {
//			cef_fib_faceid_remove (hdl->fib, fe, faceids[i]);
		}
		
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
	CefT_Parsed_Message* pm, 				/* Parsed message 							*/
	CefT_Parsed_Opheader* poh, 				/* Parsed Option Header						*/
	CefT_Pit_Entry* pe, 					/* PIT entry matching this Interest 		*/
	CefT_Fib_Entry* fe						/* FIB entry matching this Interest 		*/
) {
	int i;
	int fulldiscovery_authNZ = 0;
	
	/* Ccninfo Full discovery authentication & authorization */
	if (hdl->ccninfo_full_discovery == 2 /* Authentication and Authorization */
		&& poh->ccninfo_flag & CefC_CtOp_FullDisCover) {
		fulldiscovery_authNZ = cefnetd_ccninfo_fulldiscovery_authNZ(
													hdl->ccninfousr_id_len, 
													hdl->ccninfousr_node_id,
													hdl->ccninfo_rcvdpub_key_bi_len,
													hdl->ccninfo_rcvdpub_key_bi);
	}
	
	for (i = 0 ; i < faceid_num ; i++) {
		
		if (peer_faceid == faceids[i]) {
			continue;
		}
		cef_pit_entry_up_face_update (pe, faceids[i], pm, poh);
		
		if (cef_face_check_active (faceids[i]) > 0) {
			cef_face_frame_send_forced (
				faceids[i], msg, payload_len + header_len);
			if (hdl->forwarding_info_strategy == CefC_Default_ForwardingInfoStrategy) {
				if (poh->ccninfo_flag & CefC_CtOp_FullDisCover) {
					if (hdl->ccninfo_full_discovery == 0 /* Allow */) {
						;	/* Full discover is performed.			*/
					} else 
					if (hdl->ccninfo_full_discovery == 1 /* Not Allow */) {
						break;
					} else {
						if (fulldiscovery_authNZ != 0/* fulldiscovery_authNZ = NG */) {
							break;
						}
					}
				} else {
					break;
				}
			} else {
				if (fulldiscovery_authNZ != 0/* fulldiscovery_authNZ = NG */) {
					break;
				}
			}
		} else {
//			cef_fib_faceid_remove (hdl->fib, fe, faceids[i]);
		}
		
	}
	
	return (1);
}
/*--------------------------------------------------------------------------------------
	Forwards the specified cefping request
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cefnetd_cefpingreq_forward (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	uint16_t faceids[], 					/* Face-IDs to forward						*/
	uint16_t faceid_num, 					/* Number of Face-IDs to forward			*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	CefT_Parsed_Message* pm, 				/* Parsed message 							*/
	CefT_Parsed_Opheader* poh, 				/* Parsed Option Header						*/
	CefT_Pit_Entry* pe, 					/* PIT entry matching this Interest 		*/
	CefT_Fib_Entry* fe						/* FIB entry matching this Interest 		*/
) {
	int i;
	
	if (fe != NULL) {
		
		/* Forwards the Interest to next node 		*/
		if (pm->hoplimit < 1) {
			return (1);
		}
		
	} else {
		/* Forwards the Interest to local process, if it matches the Interest Filter 	*/
		// TBD: interest filter
	}
	
	if (!cef_face_is_local_face (peer_faceid)) {
		/* Updates Hoplimit 		*/
		pm->hoplimit--;
		msg[CefC_O_Fix_HopLimit] = pm->hoplimit;
	}
	
	if (pm->hoplimit < 1) {
		return (1);
	}
	
	for (i = 0 ; i < faceid_num ; i++) {
		
		if (peer_faceid == faceids[i]) {
			continue;
		}
		cef_pit_entry_up_face_update (pe, faceids[i], pm, poh);
		
		if (cef_face_check_active (faceids[i]) > 0) {
			cef_face_frame_send_forced (
				faceids[i], msg, payload_len + header_len);
			if (hdl->forwarding_info_strategy == CefC_Default_ForwardingInfoStrategy) {
				break;
			}
		} else {
//			cef_fib_faceid_remove (hdl->fib, fe, faceids[i]);
		}
		
	}
	
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
	CefT_Parsed_Message* pm, 				/* Parsed message 							*/
	CefT_Parsed_Opheader* poh, 				/* Parsed Option Header						*/
	CefT_Pit_Entry* pe	 					/* PIT entry matching this Interest 		*/
) {
	int i;
	uint32_t seqnum;
	uint16_t new_buff_len = 0;
	
	for (i = 0 ; i < faceid_num ; i++) {
		
		if (cef_face_check_active (faceids[i]) > 0) {
			seqnum = cef_face_get_seqnum_from_faceid (faceids[i]);
			new_buff_len = cef_frame_seqence_update (msg, seqnum);
			cef_face_object_send (faceids[i], msg, new_buff_len, pm);
			hdl->stat_send_frames++;
		} else {
			cef_pit_down_faceid_remove (pe, faceids[i]);
		}
	}
	
	return (1);
}

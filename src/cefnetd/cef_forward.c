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
 * cef_forward.c
 */

#define __CEF_FORWARD_SOURCE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdio.h>
#include <stdlib.h>

#include <cefore/cef_face.h>
#include <cefore/cef_fib.h>
#include <cefore/cef_frame.h>
#include <cefore/cef_log.h>
#include <cefore/cef_pit.h>
#include <cefore/cef_plugin.h>

#include "cef_netd.h"

/****************************************************************************************
 Macros
 ****************************************************************************************/
#define LOGTAG				"[FwdStr:built-in] "

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/


/****************************************************************************************
 State Variables
 ****************************************************************************************/


/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

void
cef_forward_send_txque (
	uint16_t 		faceid, 				/* Face-ID indicating the destination 		*/
	CefT_FwdStrtgy_Param* fwdstr
) {
	uint16_t 		faceids[CefC_Elem_Face_Num];	/* outgoing FaceIDs that were 		*/

	memset(faceids, 0x00, sizeof(faceids));
	faceids[0] = faceid;

	cefnetd_frame_send_core(fwdstr->hdl_cefnetd, 1, faceids,
			fwdstr->msg, fwdstr->payload_len + fwdstr->header_len,
			fwdstr->tx_prio, fwdstr->tx_copies);
}

/*--------------------------------------------------------------------------------------
	Forward Interest API
----------------------------------------------------------------------------------------*/
void
cef_forward_interest (
	CefT_FwdStrtgy_Param* fwdstr
) {
	CefT_Fib_Face*	face;
	int				incoming_face_type, face_type;

	/*----------------------------------------------------------------------------------*/
	/* Forward using any 1 Longest prefix match FIB entry.								*/
	/*----------------------------------------------------------------------------------*/

	face = &(fwdstr->fe->faces);
	incoming_face_type = cef_face_type_get (fwdstr->peer_faceid);

	while (face->next) {
		face = face->next;

		if (fwdstr->peer_faceid == face->faceid)
			continue;

		if (cef_face_check_active (face->faceid) > 0) {

			face_type = cef_face_type_get (face->faceid);
			if (incoming_face_type == face_type) {

				cef_pit_entry_up_face_update (fwdstr->pe, face->faceid, fwdstr->pm, fwdstr->poh);

				cef_forward_send_txque (face->faceid, fwdstr);

#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Finest, LOGTAG"Forward the Interest to Face#%d\n", face->faceid);
#endif // CefC_Debug

				/* Count send Interest */
				(*(fwdstr->cnt_send_frames))++;
				fwdstr->cnt_send_types[fwdstr->pm->InterestType]++;
				face->tx_int_types[fwdstr->pm->InterestType]++;
				face->tx_int++;

				return;
			}
		}
	}
	face = &(fwdstr->fe->faces);
	while (face->next) {
		face = face->next;

		if (fwdstr->peer_faceid == face->faceid)
			continue;

		if (cef_face_check_active (face->faceid) > 0) {

			cef_pit_entry_up_face_update (fwdstr->pe, face->faceid, fwdstr->pm, fwdstr->poh);

			cef_forward_send_txque (face->faceid, fwdstr);

#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, LOGTAG"Forward the Interest to Face#%d\n", face->faceid);
#endif // CefC_Debug

			/* Count send Interest */
			(*(fwdstr->cnt_send_frames))++;
			fwdstr->cnt_send_types[fwdstr->pm->InterestType]++;
			face->tx_int_types[fwdstr->pm->InterestType]++;
			face->tx_int++;

			break;
		}
	}

	return;
}

/*--------------------------------------------------------------------------------------
	Forward ContentObject API
----------------------------------------------------------------------------------------*/
void
cef_forward_object (
	CefT_FwdStrtgy_Param* fwdstr
) {
	int					fidx;
	uint16_t			fid;

	for (fidx = 0; fidx < fwdstr->faceid_num;fidx++) {
		fid = fwdstr->faceids[fidx];

		if (cef_face_check_active (fid) > 0) {
			cef_forward_send_txque (fid, fwdstr);
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, LOGTAG"Forward the ContentObject to Face#%d\n", fid);
#endif // CefC_Debug

			/* Count send ContentObject */
			(*(fwdstr->cnt_send_frames))++;
		}
	}

	return;
}

/*--------------------------------------------------------------------------------------
	Forward CcninfoReq API
----------------------------------------------------------------------------------------*/
void
cef_forward_ccninforeq (
	CefT_FwdStrtgy_Param* fwdstr,
	int fdcv_authNZ,
	uint32_t fdcv_f
) {
	CefT_Fib_Face*	face;
	int				incoming_face_type, face_type;
	int				full_discovery_f = 1;

	if (fwdstr->poh->ccninfo_flag & CefC_CtOp_FullDisCover) {
		/* Allow ccninfo-03 */
		if (fdcv_f == 1) {
			/* Full discover is performed. */
			;
		} else if (fdcv_f == 0) {
			/* Not Allow */
			full_discovery_f = 0;
		} else {
			/* Authentication and Authorization */
			if (fdcv_authNZ != 0) {
				/* fulldiscovery_authNZ = NG */
				full_discovery_f = 0;
			}
		}
	} else {
		full_discovery_f = 0;
	}

	/*----------------------------------------------------------------------------------*/
	/* Forward using any 1 Longest prefix match FIB entry.								*/
	/*----------------------------------------------------------------------------------*/

	face = &(fwdstr->fe->faces);
	incoming_face_type = cef_face_type_get (fwdstr->peer_faceid);

	while (face->next) {
		face = face->next;

		if (fwdstr->peer_faceid == face->faceid)
			continue;

		if (cef_face_check_active (face->faceid) > 0) {

			face_type = cef_face_type_get (face->faceid);
			if (incoming_face_type == face_type) {

				cef_pit_entry_up_face_update (fwdstr->pe, face->faceid, fwdstr->pm, fwdstr->poh);

				cef_forward_send_txque (face->faceid, fwdstr);

#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Finest, LOGTAG"Forward the CcninfoReq to Face#%d\n", face->faceid);
#endif // CefC_Debug

				if (!full_discovery_f)
					return;
			}
		}
	}
	face = &(fwdstr->fe->faces);
	while (face->next) {
		face = face->next;

		if (fwdstr->peer_faceid == face->faceid)
			continue;

		if (cef_face_check_active (face->faceid) > 0) {

			cef_pit_entry_up_face_update (fwdstr->pe, face->faceid, fwdstr->pm, fwdstr->poh);

			cef_forward_send_txque (face->faceid, fwdstr);

#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, LOGTAG"Forward the CcninfoReq to Face#%d\n", face->faceid);
#endif // CefC_Debug

			if (!full_discovery_f)
				return;
		}
	}

	return;
}


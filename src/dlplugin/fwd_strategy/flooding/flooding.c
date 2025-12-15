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
 * flooding.c
 */

#define __CEFNETD_FWD_FLOODING_SOURCE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include "flooding.h"


/****************************************************************************************
 Macros
 ****************************************************************************************/
#define LOGTAG				"[FwdStr:flooding] "


/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/


/****************************************************************************************
 State Variables
 ****************************************************************************************/


/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/


/*--------------------------------------------------------------------------------------
	Init API
----------------------------------------------------------------------------------------*/
int							/* The return value is negative if an error occurs	*/
fwd_flooding_init (
	void
) {
	/* Nothing to do at [flooding] ... */
	cef_log_write (CefC_Log_Info, LOGTAG"Initialization Forwarding Strategy plugin ... OK\n");

	return (0);
}

/*--------------------------------------------------------------------------------------
	Destory API
----------------------------------------------------------------------------------------*/
void
fwd_flooding_destroy (
	void
) {
	/* Nothing to do at [flooding] ... */
	cef_log_write (CefC_Log_Info, LOGTAG"Finish Forwarding Strategy plugin ... OK\n");

	return;
}

/*--------------------------------------------------------------------------------------
	Forward Interest API
----------------------------------------------------------------------------------------*/
void
fwd_flooding_forward_interest (
	CefT_FwdStrtgy_Param* fwdstr
) {
	uint16_t 		faceids[CefC_Elem_Face_Num];	/* outgoing FaceIDs that were 		*/
	CefT_Fib_Face*	face;
	int				incoming_face_type, face_type;
	int				send_num = 0;

	memset(faceids, 0x00, sizeof(faceids));

	/*----------------------------------------------------------------------------------*/
	/* Forward using all Longest prefix match FIB entries.								*/
	/*----------------------------------------------------------------------------------*/

	face =  &(fwdstr->fe->faces);
	incoming_face_type = cef_face_type_get (fwdstr->peer_faceid);

	while (face->next && send_num < CefC_Elem_Face_Num) {
		face = face->next;

		if (fwdstr->peer_faceid == face->faceid)
			continue;

		if (cef_face_check_active (face->faceid) > 0) {

			face_type = cef_face_type_get (face->faceid);
			if (incoming_face_type == face_type) {

				cef_pit_entry_up_face_update (fwdstr->pe, face->faceid, fwdstr->pm, fwdstr->poh);

#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Finest, LOGTAG"Forward the Interest to Face#%d\n", face->faceid);
#endif // CefC_Debug

				/* Count number of send face */
				faceids[send_num++] = face->faceid;

				/* Count send Interest */
				(*(fwdstr->cnt_send_frames))++;
				fwdstr->cnt_send_types[fwdstr->pm->InterestType]++;
				face->tx_int_types[fwdstr->pm->InterestType]++;
				face->tx_int++;
			}
		}
	}
	if (send_num == 0) {
		face = &(fwdstr->fe->faces);
		while (face->next && send_num < CefC_Elem_Face_Num) {
			face = face->next;

			if (fwdstr->peer_faceid == face->faceid)
				continue;

			if (cef_face_check_active (face->faceid) > 0) {

				cef_pit_entry_up_face_update (fwdstr->pe, face->faceid, fwdstr->pm, fwdstr->poh);

#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Finest, LOGTAG"Forward the Interest to Face#%d\n", face->faceid);
#endif // CefC_Debug

				/* Count number of send face */
				faceids[send_num++] = face->faceid;

				/* Count send Interest */
				(*(fwdstr->cnt_send_frames))++;
				fwdstr->cnt_send_types[fwdstr->pm->InterestType]++;
				face->tx_int_types[fwdstr->pm->InterestType]++;
				face->tx_int++;
			}
		}
	}

	if ( send_num ){
#ifdef CefC_Debug
		for ( int i = 0; i < send_num; i++ )
			cef_dbg_write (CefC_Dbg_Finest, LOGTAG"Forward the Interest to Face#%d\n", faceids[i]);
#endif // CefC_Debug
		cefnetd_frame_send_core (fwdstr->hdl_cefnetd,
			send_num, faceids, fwdstr->msg, fwdstr->payload_len + fwdstr->header_len, CefT_TxQue_Normal, 1);
	}

	return;
}

/*--------------------------------------------------------------------------------------
	Forward ContentObject API
----------------------------------------------------------------------------------------*/

/*	Do not implement your own forwarding strategy, 	*/
/*	rely on the default common processing. 			*/

/*--------------------------------------------------------------------------------------
	Road the plugin
----------------------------------------------------------------------------------------*/
int
cefnetd_fwd_flooding_plugin_load (
	CefT_Plugin_Fwd_Strtgy* fwd_in
) {
	fwd_in->init           = fwd_flooding_init;
	fwd_in->destroy        = fwd_flooding_destroy;
	fwd_in->fwd_int        = fwd_flooding_forward_interest;

	return (0);
}


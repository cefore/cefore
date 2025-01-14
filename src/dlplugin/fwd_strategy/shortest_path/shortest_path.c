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
 * shortest_path.c
 */

#define __CEFNETD_FWD_SHORTEST_PATH_SOURCE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include "shortest_path.h"


/****************************************************************************************
 Macros
 ****************************************************************************************/
#define LOGTAG				"[FwdStr:s_path] "


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
fwd_shortest_path_init (
	void
) {
	/* Nothing to do at [shortest_path] ... */
	cef_log_write (CefC_Log_Info, LOGTAG"Initialization Forwarding Strategy plugin ... OK\n");

	return (0);
}

/*--------------------------------------------------------------------------------------
	Destory API
----------------------------------------------------------------------------------------*/
void
fwd_shortest_path_destroy (
	void
) {
	/* Nothing to do at [shortest_path] ... */
	cef_log_write (CefC_Log_Info, LOGTAG"Finish Forwarding Strategy plugin ... OK\n");

	return;
}

/*--------------------------------------------------------------------------------------
	Forward Interest API
----------------------------------------------------------------------------------------*/
void
fwd_shortest_path_forward_interest (
	CefT_FwdStrtgy_Param* fwdstr
) {
	CefT_Fib_Face*	face;
	int				lowest_cost = 65535;
	CefT_Fib_Face*	selected_face = NULL;
	int				incoming_face_type, face_type;

	/*----------------------------------------------------------------------------------*/
	/* Forward using the lowest Routing Cost in Longest prefix match FIB entries.		*/
	/* If a Face with the same Routine Cost exists, the 1st Face detected is selected.	*/
	/*----------------------------------------------------------------------------------*/

	face =  &(fwdstr->fe->faces);
	incoming_face_type = cef_face_type_get (fwdstr->peer_faceid);

	while (face->next) {
		face = face->next;

		if (fwdstr->peer_faceid == face->faceid)
			continue;

		if (cef_face_check_active (face->faceid) > 0) {

			face_type = cef_face_type_get (face->faceid);
			if (incoming_face_type == face_type) {

				if (lowest_cost > face->metric.cost) {

					selected_face   = face;
					lowest_cost     = face->metric.cost;
				}
			}
		}
	}
	if (selected_face == NULL) {
		face = &(fwdstr->fe->faces);
		while (face->next) {
			face = face->next;

			if (fwdstr->peer_faceid == face->faceid)
				continue;

			if (cef_face_check_active (face->faceid) > 0) {

				if (lowest_cost > face->metric.cost) {

					selected_face   = face;
					lowest_cost     = face->metric.cost;
				}
			}
		}
	}

	if (selected_face == NULL)
		return;

	cef_pit_entry_up_face_update (fwdstr->pe, selected_face->faceid, fwdstr->pm, fwdstr->poh);

/*	cef_face_frame_send_forced (	*/
	cefnetd_frame_send_txque (fwdstr->hdl_cefnetd,
		selected_face->faceid, fwdstr->msg, fwdstr->payload_len + fwdstr->header_len);

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, LOGTAG"Forward the Interest to Face#%d\n", face->faceid);
#endif // CefC_Debug

	/* Count send Interest */
	(*(fwdstr->cnt_send_frames))++;
	fwdstr->cnt_send_types[fwdstr->pm->InterestType]++;
	selected_face->tx_int_types[fwdstr->pm->InterestType]++;
	selected_face->tx_int++;

	return;
}

/*--------------------------------------------------------------------------------------
	Forward ContentObject API
----------------------------------------------------------------------------------------*/
void
fwd_shortest_path_forward_object (
	CefT_FwdStrtgy_Param* fwdstr
) {
	CefT_Down_Faces*	face;
	int					fidx;
	uint16_t			fid;
	int					break_f = 0;

	for (fidx = 0; fidx < fwdstr->faceid_num;fidx++) {
		fid = fwdstr->faceids[fidx];

		face = &(fwdstr->pe->dnfaces);

		while (face->next) {
			face = face->next;

			if (fwdstr->pm->org.longlife_f) {
				if (face->faceid == fid) {
					break_f = 1;
					break;
				}
			} else {
				if ((face->faceid == fid) && (face->nonce == fwdstr->pm->nonce)) {
					break_f = 1;
					break;
				}
			}
		}
		if (break_f == 0) {
			continue;
		}
		break_f = 0;

		if (!cef_pit_entry_down_face_search (face, 0, fwdstr->pm))
			continue;

		if (cef_face_check_active (face->faceid) > 0) {
			unsigned char buff[CefC_Max_Length];
			size_t		buff_len = 0;
			uint32_t	seqnum;

			seqnum = cef_face_get_seqnum_from_faceid (face->faceid);
			buff_len = cef_frame_seqence_update (buff, fwdstr->msg, seqnum);

			cefnetd_frame_send_txque (fwdstr->hdl_cefnetd,
				face->faceid, buff, buff_len);

#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, LOGTAG"Forward the ContentObject to Face#%d\n", face->faceid);
#endif // CefC_Debug

			/* Count send ContentObject */
			(*(fwdstr->cnt_send_frames))++;

			cef_pit_entry_down_face_remove (fwdstr->pe, face, fwdstr->pm);
		} else {

			cef_pit_down_faceid_remove (fwdstr->pe, face->faceid);
		}
	}

	return;
}

/*--------------------------------------------------------------------------------------
	Road the plugin
----------------------------------------------------------------------------------------*/
int
cefnetd_fwd_shortest_path_plugin_load (
	CefT_Plugin_Fwd_Strtgy* fwd_in
) {
	fwd_in->init           = fwd_shortest_path_init;
	fwd_in->destroy        = fwd_shortest_path_destroy;
	fwd_in->fwd_int        = fwd_shortest_path_forward_interest;
	fwd_in->fwd_cob        = fwd_shortest_path_forward_object;

	return (0);
}

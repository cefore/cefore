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
 * cef_plugin_samptp.c
 */

#define __CEF_PLUGIN_SAMPTP_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>

#include <cefore/cef_face.h>
#include <cefore/cef_plugin.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

#define CefC_St_Disable 	0
#define CefC_St_Enable 		1

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/


/****************************************************************************************
 State Variables
 ****************************************************************************************/

static int m_stat_output_f = CefC_St_Disable;
static uint64_t m_stat_int_rx = 0;
static uint64_t m_stat_int_tx = 0;
static uint64_t m_stat_cob_rx = 0;
static uint64_t m_stat_cob_tx = 0;

static int* stat_table;

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

/****************************************************************************************
 For Debug Trace
 ****************************************************************************************/


/****************************************************************************************
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Callback for init process
----------------------------------------------------------------------------------------*/
int
cef_plugin_samptp_init (
	CefT_Plugin_Tp* 	tp, 						/* Transport Plugin Handle			*/
	void* 				arg_ptr						/* Input argment block  			*/
) {
	CefT_List* lp 		= NULL;
	char* value_str 	= NULL;
	
	/* Obtains the attributes 			*/
	lp = cef_plugin_parameter_value_get ("SAMPTP", "stat");
	
	if (lp) {
		value_str = (char*) cef_plugin_list_access (lp, 0);
		
		if (strcmp (value_str, "yes") == 0) {
			m_stat_output_f = CefC_St_Enable;
		}
	}
	
	stat_table = (int*) arg_ptr;
	
	return (1);
}
/*--------------------------------------------------------------------------------------
	Callback for incoming object process
----------------------------------------------------------------------------------------*/
int
cef_plugin_samptp_cob (
	CefT_Plugin_Tp* 	tp, 						/* Transport Plugin Handle			*/
	CefT_Rx_Elem* 		rx_elem
) {
	CefT_Tx_Elem* tx_elem;
	int idx = 0;
	uint16_t faceids[CefC_Elem_Face_Num];
	int i;
	
	/* Updates statistics 		*/
	m_stat_int_rx++;
	
	/* Forwards the Object to app 			*/
	for (i = 0 ; i < rx_elem->out_faceid_num ; i++) {
		if (!cef_face_object_send_iflocal (
			rx_elem->out_faceids[i], rx_elem->parsed_msg->payload,
			rx_elem->parsed_msg->payload_len, rx_elem->parsed_msg->chnk_num)) {
			
			faceids[idx] = rx_elem->out_faceids[i];
			idx++;
		}
	}
	
	if (idx > 0) {
		/* Creates the forward object 				*/
		tx_elem = (CefT_Tx_Elem*) cef_mpool_alloc (tp->tx_que_mp);
		tx_elem->type 		= CefC_Elem_Type_Object;
		tx_elem->msg_len 	= rx_elem->msg_len;
		tx_elem->faceid_num = idx;
		
		for (i = 0 ; i < idx ; i++) {
			tx_elem->faceids[i] = faceids[i];
		}
		memcpy (tx_elem->msg, rx_elem->msg, rx_elem->msg_len);
		
		/* Pushes the forward object to tx buffer	*/
		i = cef_rngque_push (tp->tx_que, tx_elem);
		
		if (i < 1) {
			cef_mpool_free (tp->tx_que_mp, tx_elem);
		}
		/* Updates statistics 		*/
		m_stat_int_tx += idx;
	}
	
	return (CefC_Pi_Object_NoSend);
}

/*--------------------------------------------------------------------------------------
	Callback for incoming interest process
----------------------------------------------------------------------------------------*/
int
cef_plugin_samptp_interest (
	CefT_Plugin_Tp* 	tp, 						/* Transport Plugin Handle			*/
	CefT_Rx_Elem* 		rx_elem
) {
	CefT_Tx_Elem* tx_elem;
	int i;
	
	/* Updates statistics 		*/
	m_stat_cob_rx++;
	
	/* Creates the forward object 				*/
	tx_elem = (CefT_Tx_Elem*) cef_mpool_alloc (tp->tx_que_mp);
	tx_elem->type 		= CefC_Elem_Type_Interest;
	tx_elem->msg_len 	= rx_elem->msg_len;
	tx_elem->faceid_num = rx_elem->out_faceid_num;
	
	for (i = 0 ; i < rx_elem->out_faceid_num ; i++) {
		tx_elem->faceids[i] = rx_elem->out_faceids[i];
	}
	memcpy (tx_elem->msg, rx_elem->msg, rx_elem->msg_len);
	
	/* Pushes the forward object to tx buffer	*/
	i = cef_rngque_push (tp->tx_que, tx_elem);
	
	if (i < 1) {
		cef_mpool_free (tp->tx_que_mp, tx_elem);
	}
	
	/* Updates statistics 		*/
	m_stat_cob_tx += rx_elem->out_faceid_num;
	
	return (CefC_Pi_Interest_NoSend);
}

/*--------------------------------------------------------------------------------------
	Callback for signal indicating that PIT changes
----------------------------------------------------------------------------------------*/
void 
cef_plugin_samptp_delpit (
	CefT_Plugin_Tp* 			tp, 				/* Transport Plugin Handle			*/
	CefT_Rx_Elem_Sig_DelPit* 	info
) {
	/* NOP */
	return;
}

/*--------------------------------------------------------------------------------------
	Callback for post process
----------------------------------------------------------------------------------------*/
void 
cef_plugin_samptp_destroy (
	CefT_Plugin_Tp* 	tp 							/* Transport Plugin Handle			*/
) {
	/* Outputs statistics 		*/
	if (m_stat_output_f) {
		fprintf (stderr, "[SAMPTP STATISTICS]\n");
		fprintf (stderr, " Rx Interests : "FMTU64"\n", m_stat_int_rx);
		fprintf (stderr, " Tx Interests : "FMTU64"\n", m_stat_int_tx);
		fprintf (stderr, " Rx Cobs      : "FMTU64"\n", m_stat_cob_rx);
		fprintf (stderr, " Tx Cobs      : "FMTU64"\n", m_stat_cob_tx);
	}
	
	return;
}


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
 * cef_plugin_com.h
 */

#ifndef __CEF_PLUGIN_COM_HEADER__
#define __CEF_PLUGIN_COM_HEADER__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>

#include <cefore/cef_frame.h>


/****************************************************************************************
 Macros
 ****************************************************************************************/


/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/


/****************************************************************************************
 Function declaration
 ****************************************************************************************/

/*============================================================================
	Transport Plugin
==============================================================================*/

/*-----------------------------------------------------------------
	Default Transport
-------------------------------------------------------------------*/
int 
cef_plugin_samptp_init (
	CefT_Plugin_Tp* 	tp, 						/* Transport Plugin Handle			*/
	void* 				arg_ptr						/* Input argment block  			*/
);

int 
cef_plugin_samptp_cob (
	CefT_Plugin_Tp* 	tp, 						/* Transport Plugin Handle			*/
	CefT_Rx_Elem* 		rx_elem
);

int 
cef_plugin_samptp_interest (
	CefT_Plugin_Tp* 	tp, 						/* Transport Plugin Handle			*/
	CefT_Rx_Elem* 		rx_elem
);
void 
cef_plugin_samptp_delpit (
	CefT_Plugin_Tp* 			tp, 				/* Transport Plugin Handle			*/
	CefT_Rx_Elem_Sig_DelPit* 	info
);
void 
cef_plugin_samptp_destroy (
	CefT_Plugin_Tp* 	tp 							/* Transport Plugin Handle			*/
);

/*============================================================================
	Mobility Plugin
==============================================================================*/

/*-----------------------------------------------------------------
	Default Mobility
-------------------------------------------------------------------*/
int 
cef_plugin_defmb_init (
	CefT_Plugin_Mb* 	tp, 						/* Mobility Plugin Handle			*/
	const CefT_Rtts* 	rtt_tbl,					/* RTT record table (read only) 	*/
	void** 				vret 						/* return to the allocated info 	*/
);

int 
cef_plugin_defmb_cob (
	CefT_Plugin_Mb* 	tp, 						/* Mobility Plugin Handle			*/
	CefT_Rx_Elem* 		rx_elem
);

int 
cef_plugin_defmb_interest (
	CefT_Plugin_Mb* 	tp, 						/* Mobility Plugin Handle			*/
	CefT_Rx_Elem* 		rx_elem
);
void 
cef_plugin_defmb_destroy (
	CefT_Plugin_Mb* 	tp 							/* Mobility Plugin Handle			*/
);


/*============================================================================
	NDN Plugin
==============================================================================*/

int 												/* variant caused the problem		*/
cef_plugin_ndn_init (
	CefT_Plugin_Ndn* ndn, 							/* NDN Plugin Handle				*/
	const CefT_Hash_Handle cefore_fib				/* FIB of cefnetd (Cefore) 			*/
);

int
cef_plugin_ndn_ndnmsg (
	CefT_Plugin_Ndn* 	ndn							/* NDN Plugin Handle				*/
);

int
cef_plugin_ndn_cefcob (
	CefT_Plugin_Ndn* 	ndn,						/* NDN Plugin Handle				*/
	unsigned char* 		cef_msg, 
	uint16_t 			cef_msg_len,
	CefT_Parsed_Message* 	pm, 					/* Parsed CEFORE message			*/
	CefT_Parsed_Opheader* 	poh						/* Parsed Option Header				*/
);

int
cef_plugin_ndn_cefint (
	CefT_Plugin_Ndn* 	ndn,						/* NDN Plugin Handle				*/
	unsigned char* 		cef_msg, 
	uint16_t 			cef_msg_len, 
	CefT_Parsed_Message* 	pm, 					/* Parsed CEFORE message			*/
	CefT_Parsed_Opheader* 	poh,					/* Parsed Option Header				*/
	uint16_t 				peer_faceid
);

void 
cef_plugin_ndn_destroy (
	CefT_Plugin_Ndn* 	ndn 						/* NDN Plugin Handle				*/
);

void 
cef_plugin_ndn_fib_print (
	char* rsp_msg
);

#endif // __CEF_PLUGIN_DEFMB_HEADER__

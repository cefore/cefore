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
 * cef_tp_plugin.c
 */

#define __CEF_TP_PLUGIN_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <cefore/cef_plugin.h>
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


/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/


/****************************************************************************************
 For Debug Trace
 ****************************************************************************************/


/****************************************************************************************
 ****************************************************************************************/


/*--------------------------------------------------------------------------------------
	Inits Transport Plugin
----------------------------------------------------------------------------------------*/
int 												/* variant caused the problem		*/
cef_tp_plugin_init (
	CefT_Plugin_Tp** 	tp, 						/* Transport Plugin Handle			*/
	CefT_Rngque* 		tx_que,						/* TX ring buffer 					*/
	CefT_Mp_Handle 		tx_que_mp,					/* Memory Pool for CefT_Tx_Elem 	*/
	void* 				arg_ptr						/* Input argment block  			*/
) {
	CefT_Plugin_Tp* work 	= NULL;
	CefT_Plugin_Tag* tag 	= NULL;
	
	/*---------------------------------------------------------
		Inits
	-----------------------------------------------------------*/
	work = (CefT_Plugin_Tp*) malloc (sizeof (CefT_Plugin_Tp) * CefC_T_OPT_TP_NUM);
	memset (work, 0, sizeof (CefT_Plugin_Tp) * CefC_T_OPT_TP_NUM);
	*tp = work;
	
	tag = cef_plugin_tag_get ("TRANSPORT");
	if (tag == NULL) {
		return (1);
	}
	if (tag->num == 0) {
		return (1);
	}
	
	/*---------------------------------------------------------
		Registration the callback functions
	-----------------------------------------------------------*/
	
#ifdef CefC_Plugin_Samptp
	{
		CefT_List* samptp_lp 	= NULL;
		char* samptp_param 		= NULL;
		
		/***** Sample Transport 							*****/
		samptp_lp = cef_plugin_parameter_value_get ("TRANSPORT", "samptp");
		
		if (samptp_lp) {
			samptp_param = (char*) cef_plugin_list_access (samptp_lp, 0);
			
			if (strcmp (samptp_param, "yes") == 0) {
				work[CefC_T_OPT_TP_SAMPTP].variant 		= CefC_T_OPT_TP_SAMPTP;
				work[CefC_T_OPT_TP_SAMPTP].tx_que 		= tx_que;
				work[CefC_T_OPT_TP_SAMPTP].tx_que_mp 	= tx_que_mp;
				work[CefC_T_OPT_TP_SAMPTP].init 			= cef_plugin_samptp_init;
				work[CefC_T_OPT_TP_SAMPTP].cob 			= cef_plugin_samptp_cob;
				work[CefC_T_OPT_TP_SAMPTP].interest 		= cef_plugin_samptp_interest;
				work[CefC_T_OPT_TP_SAMPTP].pit 			= cef_plugin_samptp_delpit;
				work[CefC_T_OPT_TP_SAMPTP].destroy		= cef_plugin_samptp_destroy;
				
				if (work[CefC_T_OPT_TP_SAMPTP].init) {
					(*work[CefC_T_OPT_TP_SAMPTP].init) (
							&work[CefC_T_OPT_TP_SAMPTP], arg_ptr);
				}
				/* Use OPT_SEQNUM */
				cef_frame_set_opt_seqnum_f (CefC_OptSeqnum_Use);
			}
		}
	}
#endif // CefC_Plugin_Samptp
	
	
	return (1);
}

/*--------------------------------------------------------------------------------------
	Post process for Transport Plugin
----------------------------------------------------------------------------------------*/
void 
cef_tp_plugin_destroy (
	CefT_Plugin_Tp* 	tp 							/* Transport Plugin Handle			*/
) {
	
#ifdef CefC_Plugin_Samptp
	/*---------------------------------------------------------
		Default Transport
	-----------------------------------------------------------*/
	{
		CefT_List* samptp_lp = NULL;
		char* samptp_param 	= NULL;
		
		samptp_lp = cef_plugin_parameter_value_get ("TRANSPORT", "samptp");
		
		if (samptp_lp) {
			samptp_param = (char*) cef_plugin_list_access (samptp_lp, 0);
			
			if (strcmp (samptp_param, "yes") == 0) {
				if (tp[CefC_T_OPT_TP_SAMPTP].destroy) {
					(*tp[CefC_T_OPT_TP_SAMPTP].destroy) (&tp[CefC_T_OPT_TP_SAMPTP]);
				}
			}
		}
	}
#endif // CefC_Plugin_Samptp
	
	
	return;
}


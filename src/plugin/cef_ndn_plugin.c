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
 * cef_ndn_plugin.c
 */
#define __CEF_NDN_PLUGIN_SOURECE__

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
	Inits NDN Plugin
----------------------------------------------------------------------------------------*/
int 												/* variant caused the problem		*/
cef_ndn_plugin_init (
	CefT_Plugin_Ndn** ndn, 							/* NDN Plugin Handle				*/
	const CefT_Hash_Handle cefore_fib				/* FIB of cefnetd (Cefore) 			*/
) {
#ifdef CefC_NdnPlugin
	CefT_Plugin_Ndn* work 	= NULL;
	CefT_Plugin_Tag* tag 	= NULL;
	CefT_List* lp 			= NULL;
	char* res 				= NULL;
	
	/*---------------------------------------------------------
		Inits
	-----------------------------------------------------------*/
	work = (CefT_Plugin_Ndn*) malloc (sizeof (CefT_Plugin_Ndn));
	memset (work, 0, sizeof (CefT_Plugin_Ndn));
	*ndn = work;
	
	tag = cef_plugin_tag_get ("NDN");
	if (tag == NULL) {
		return (-1);
	}
	if (tag->num == 0) {
		return (-1);
	}
	
	/*---------------------------------------------------------
		Registration the callback functions
	-----------------------------------------------------------*/
	lp = cef_plugin_parameter_value_get ("NDN", "support");
	
	if (lp == NULL) {
		return (-1);
	}
	res = (char*) cef_plugin_list_access (lp, 0);
	
	if (strcmp (res, "yes") == 0) {
		
		work->init 		= cef_plugin_ndn_init;
		work->ndn_msg 	= cef_plugin_ndn_ndnmsg;
		work->cef_int 	= cef_plugin_ndn_cefint;
		work->cef_cob 	= cef_plugin_ndn_cefcob;
		work->destroy	= cef_plugin_ndn_destroy;
		
		if (work->init) {
			(*work->init) (work, cefore_fib);
		}
		return (1);
	}
#endif // CefC_NdnPlugin
	
	return (-1);
}

/*--------------------------------------------------------------------------------------
	Post process for NDN Plugin
----------------------------------------------------------------------------------------*/
void 
cef_ndn_plugin_destroy (
	CefT_Plugin_Ndn* 	ndn							/* NDN Plugin Handle				*/
) {
	if (ndn->destroy) {
		(*ndn->destroy) (ndn);
	}
	
	return;
}


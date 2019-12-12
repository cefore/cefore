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
 * cef_node.c
 */

#define __CEF_NODE_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include "cef_netd.h"

/****************************************************************************************
 Macros
 ****************************************************************************************/

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/


/****************************************************************************************
 State Variables
 ****************************************************************************************/
static CefT_Netd_Handle* netd_hdl = NULL;

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

/****************************************************************************************
 ****************************************************************************************/
int
cef_node_run (
	void
){
	
	/* Creates a main handle for cefnetd 		*/
	netd_hdl = cefnetd_handle_create (CefC_Node_Type_Router);
	if (netd_hdl == NULL) {
		cef_log_write (CefC_Log_Error, "Failed to create cefnetd handle\n");
		cef_log_write (CefC_Log_Error, "Stop\n");
		return (-1);
	}
	
	/* Calls the main loop function 			*/
	cefnetd_event_dispatch (netd_hdl);

	/* Destroys a main handle for cefnetd 		*/
	cefnetd_handle_destroy (netd_hdl);

	return (1);
}

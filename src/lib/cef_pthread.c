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
 * cef_pthread.c
 */

#define __CEF_PTHREAD_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include <cefore/cef_pthread.h>
#include <cefore/cef_log.h>

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

/*--------------------------------------------------------------------------------------
	create a new thread
  --------------------------------------------------------------------------------------
	MacOS default stack size is 512KB, so 8MB is the same as Linux.
	8MB is defined by CefC_Pthread_StackSize
----------------------------------------------------------------------------------------*/
int
cef_pthread_create (
	pthread_t* t_handle,
	pthread_attr_t* t_attr,
	void* (*start_routine) (void*),
	void* arg
) {
	pthread_attr_t w_attr;
	int		rc;

	if ( !t_attr ){
		t_attr = &w_attr;
		rc = pthread_attr_init(&w_attr);
		if (rc != 0) {
			cef_log_write (CefC_Log_Error, "error in pthread_attr_init");
			return rc;
		}

		rc = pthread_attr_setstacksize(&w_attr, CefC_Pthread_StackSize);
		if (rc != 0) {
			cef_log_write (CefC_Log_Error, "error in pthread_attr_setstacksize\n");
			return rc;
		}
	}

	rc = pthread_create (t_handle, t_attr, start_routine, arg);
	if (rc != 0) {
		cef_log_write (CefC_Log_Error, "Failed to create the new thread.\n");
		return rc;
	}

#ifdef	CefC_Debug
{	size_t	stacksize;
	pthread_attr_getstacksize(t_attr, &stacksize);
	cef_dbg_write (CefC_Dbg_Fine, "*pthread_t:%p stacksize=%u bytes.\n", *t_handle, stacksize);	}
#endif	// CefC_Debug

	return rc;
}

/*--------------------------------------------------------------------------------------
	create a new thread with the specified stack size
----------------------------------------------------------------------------------------*/
int
cef_pthread_create_with_stacksize (
	pthread_t* t_handle,
	size_t	stacksize,
	void* (*start_routine) (void*),
	void* arg
) {
	pthread_attr_t w_attr;
	int		rc;

	rc = pthread_attr_init(&w_attr);
	if (rc != 0) {
		cef_log_write (CefC_Log_Error, "error in pthread_attr_init");
		return rc;
	}

	rc = pthread_attr_setstacksize(&w_attr, stacksize);
	if (rc != 0) {
		cef_log_write (CefC_Log_Error, "error in pthread_attr_setstacksize\n");
		return rc;
	}

	return cef_pthread_create (t_handle, &w_attr, start_routine, arg);
}

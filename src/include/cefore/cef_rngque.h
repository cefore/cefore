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
 * cef_rngque.h
 */

#ifndef __CEF_RINGQUE_HEADER__
#define __CEF_RINGQUE_HEADER__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/


/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/

typedef struct {

	void* 	body;

} CefT_Rngque_Elem;

/********** Tx queue (ring buffer) 	**********/
typedef struct {

	int top;						/* top of the ring buffer 							*/
	int bottom;						/* bottom of the ring buffer 						*/
	int mask;						/* capacity of the ring buffer 						*/
	CefT_Rngque_Elem* que;			/* line buffer 										*/
	pthread_mutex_t mutex;			/* mutex for thread safe 							*/
	
} CefT_Rngque;

/****************************************************************************************
 Global Variables
 ****************************************************************************************/



/****************************************************************************************
 Function Declarations
 ****************************************************************************************/

CefT_Rngque* 								/* Created Ring Queue Information 			*/
cef_rngque_create (
	int capacity							/* Capacity of Ring queue 					*/
);
void
cef_rngque_destroy (
	CefT_Rngque* qp							/* Ring Queue Information 					*/
);

int
cef_rngque_push (
	CefT_Rngque* qp, 						/* Ring Queue Information 					*/
	void* item
);

void*										/* item which is removed from queue 		*/
cef_rngque_pop (
	CefT_Rngque* qp							/* Ring Queue Information 					*/
);
/*--------------------------------------------------------------------------------------
	Read the value (int) from the top of Ring Queue
----------------------------------------------------------------------------------------*/
void*										/* item which is removed from queue 		*/
cef_rngque_read (
	CefT_Rngque* qp							/* Ring Queue Information 					*/
);

#endif // __CEF_NETD_HEADER__

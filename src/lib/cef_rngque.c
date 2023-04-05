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
 * cef_rngque.c
 */

#define __CEF_RINGQUE_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/

#include <cefore/cef_rngque.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

#define cef_mpool_mutex_lock		pthread_mutex_lock
#define cef_mpool_mutex_unlock		pthread_mutex_unlock

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
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Creates Ring Queue
----------------------------------------------------------------------------------------*/
CefT_Rngque* 								/* Created Ring Queue Information 			*/
cef_rngque_create (
	int capacity							/* Capacity of Ring queue 					*/
) {
	int p;
	CefT_Rngque* qp;

	/* Obtains the capacity of index queue 		*/
	if (capacity < 32) {
		capacity = 32;
	}
	if (capacity > 65536) {
		capacity = 65536;
	}
	capacity--;

	for (p = 0 ; capacity != 0 ; capacity >>= 1) {
		p = (p << 1) + 1;
	}
	capacity = p + 1;

	/* Allocates the index queue 			*/
	qp = (CefT_Rngque*) malloc (sizeof (CefT_Rngque));
	qp->top = 0;
	qp->bottom = 0;
	qp->mask = capacity - 1;
	qp->que = (CefT_Rngque_Elem*) malloc (sizeof (CefT_Rngque_Elem) * capacity);
	
	pthread_mutex_init (&qp->mutex, NULL);

	return (qp);
}

/*--------------------------------------------------------------------------------------
	Free Ring Queue
----------------------------------------------------------------------------------------*/
void
cef_rngque_destroy (
	CefT_Rngque* qp							/* Ring Queue Information 					*/
) {
	pthread_mutex_destroy (&qp->mutex);
	free (qp->que);
	free (qp);
}

/*--------------------------------------------------------------------------------------
	Removes the value (int) from the top of Ring Queue
----------------------------------------------------------------------------------------*/
void*										/* item which is removed from queue 		*/
cef_rngque_pop (
	CefT_Rngque* qp							/* Ring Queue Information 					*/
) {
	int value;

	if (qp->bottom != qp->top) {
		cef_mpool_mutex_lock (&qp->mutex);
		value = qp->top;
		qp->top = (qp->top + 1) & qp->mask;
		cef_mpool_mutex_unlock (&qp->mutex);
		return (qp->que[value].body);
	}

	return (NULL);
}

/*--------------------------------------------------------------------------------------
	Inserts the value (int) to the bottom of Ring Queue
----------------------------------------------------------------------------------------*/
int
cef_rngque_push (
	CefT_Rngque* qp, 						/* Ring Queue Information 					*/
	void* item
) {

	if (((qp->bottom + 1) & qp->mask) != qp->top) {
		cef_mpool_mutex_lock (&qp->mutex);
		qp->que[qp->bottom].body = item;
		qp->bottom = (qp->bottom + 1) & qp->mask;
		cef_mpool_mutex_unlock (&qp->mutex);
		return (1);
	}

	return (0);
}

/*--------------------------------------------------------------------------------------
	Read the value (int) from the top of Ring Queue
----------------------------------------------------------------------------------------*/
void*										/* item which is removed from queue 		*/
cef_rngque_read (
	CefT_Rngque* qp							/* Ring Queue Information 					*/
) {
	int value;

	if (qp->bottom != qp->top) {
		cef_mpool_mutex_lock (&qp->mutex);
		value = qp->top;
		cef_mpool_mutex_unlock (&qp->mutex);
		return (qp->que[value].body);
	}

	return (NULL);
}

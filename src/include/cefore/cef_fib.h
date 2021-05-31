/*
 * Copyright (c) 2016-2021, National Institute of Information and Communications
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
 * cef_fib.h
 */

#ifndef __CEF_FIB_HEADER__
#define __CEF_FIB_HEADER__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>

#include <cefore/cef_hash.h>
#include <cefore/cef_define.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

#define CefC_Fib_UpFace_Max				64
#define CefC_Fib_Route_Ope_Invalid		0x00
#define CefC_Fib_Route_Ope_Add			0x01
#define CefC_Fib_Route_Ope_Del			0x02
#define CefC_Fib_Route_Pro_Invalid		0x00
#define CefC_Fib_Route_Pro_TCP			0x01
#define CefC_Fib_Route_Pro_UDP			0x02

#define CefC_Fib_Entry_Dynamic			0x01
#define CefC_Fib_Entry_Static			0x02
#define CefC_Fib_Entry_Ctrl				0x04


/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/

/***** Face Information for FIB entry 	*****/
typedef struct CefT_Fib_Face {
	
	int 	faceid;							/* Face-ID 									*/
	struct CefT_Fib_Face* 	next;			/* Pointer to next Face Information 		*/
	int 	type;							/* CefC_Fib_Entry_XXX 						*/
	
} CefT_Fib_Face;

/***** FIB entry 						*****/
typedef struct {
	
	unsigned char* 	key;					/* Key of the entry 						*/
	unsigned int 	klen;					/* Length of the key 						*/
	CefT_Fib_Face	faces;					/* Faces to forward interest 				*/
	
	/* for Application Components */
	uint16_t 		app_comp;				/* index of Application Components 			*/
	uint64_t 		lifetime;				/* lifetime in UNIX time[us] 				*/
	
} CefT_Fib_Entry;

/****************************************************************************************
 Global Variables
 ****************************************************************************************/


/****************************************************************************************
 Function Declarations
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Initialize FIB module
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cef_fib_init (
	CefT_Hash_Handle fib					/* FIB										*/
);
/*--------------------------------------------------------------------------------------
	Searches FIB entry matching the specified Key
----------------------------------------------------------------------------------------*/
CefT_Fib_Entry* 							/* FIB entry 								*/
cef_fib_entry_search (
	CefT_Hash_Handle fib,					/* FIB										*/
	unsigned char* name, 					/* Key of the FIB entry						*/
	uint16_t name_len						/* Length of Key							*/
);
/*--------------------------------------------------------------------------------------
	Obtains Face-ID(s) to forward the Interest matching the specified FIB entry
----------------------------------------------------------------------------------------*/
int 										/* the number of Face-ID to forward			*/
cef_fib_forward_faceid_get (
	CefT_Fib_Entry* entry, 					/* FIB entry								*/
	uint16_t faceids[]						/* sets Face-ID to forward the Interest		*/
);
/*--------------------------------------------------------------------------------------
	Obtains Face-ID(s) to forward the Interest matching the specified FIB entry
----------------------------------------------------------------------------------------*/
int 										/* the number of Face-ID to forward			*/
cef_fib_forward_faceid_select (
	CefT_Fib_Entry* entry, 					/* FIB entry								*/
	uint16_t incoming_faceid, 				/* FaceID at which the Interest arived 		*/
	uint16_t faceids[]						/* set Face-ID to forward the Interest		*/
);
/*--------------------------------------------------------------------------------------
	Receive the FIB route message
----------------------------------------------------------------------------------------*/
int 
cef_fib_route_msg_read (
	CefT_Hash_Handle fib,					/* FIB										*/
	unsigned char* msg, 					/* the received message(s)					*/
	int msg_size,							/* size of received message(s)				*/
	uint8_t type,							/* CefC_Fib_Entry_XXX						*/
	int* rc 								/* 0x01=New Entry, 0x02=Free Entry 			*/
);
/*--------------------------------------------------------------------------------------
	Obtain the Name from the received route message
----------------------------------------------------------------------------------------*/
int 
cef_fib_name_get_from_route_msg (
	unsigned char* msg, 					/* the received message(s)					*/
	int msg_size, 
	unsigned char* name
);
/*--------------------------------------------------------------------------------------
	Removes the specified Faceid from the specified FIB entry
----------------------------------------------------------------------------------------*/
int 
cef_fib_faceid_remove (
	CefT_Hash_Handle fib,					/* FIB										*/
	CefT_Fib_Entry* entry, 					/* FIB entry								*/
	uint16_t faceid							/* set Face-ID to forward the Interest		*/
);
/*--------------------------------------------------------------------------------------
	Inserts the specified Faceid to the specified FIB entry
----------------------------------------------------------------------------------------*/
int 										/* if successful, more than 0				*/
cef_fib_faceid_insert (
	CefT_Fib_Entry* entry, 					/* FIB entry								*/
	uint16_t faceid							/* set Face-ID to forward the Interest		*/
);
/*--------------------------------------------------------------------------------------
	Lookups FIB entry exact-matching the specified Key
----------------------------------------------------------------------------------------*/
CefT_Fib_Entry* 							/* FIB entry 								*/
cef_fib_entry_lookup (
	CefT_Hash_Handle fib,					/* FIB										*/
	unsigned char* name, 					/* Key of the FIB entry						*/
	uint16_t name_len						/* Length of Key							*/
);
/*--------------------------------------------------------------------------------------
	Remove a FIB entry from FIB
----------------------------------------------------------------------------------------*/
int
cef_fib_entry_destroy (
	CefT_Hash_Handle fib,					/* FIB										*/
	unsigned char* name, 					/* Key of the FIB entry						*/
	uint16_t name_len						/* Length of Key							*/
);
/*--------------------------------------------------------------------------------------
	Clean FaceID from FIB
----------------------------------------------------------------------------------------*/
void
cef_fib_faceid_cleanup (
	CefT_Hash_Handle fib
);
/*--------------------------------------------------------------------------------------
	Obtains the FIB information
----------------------------------------------------------------------------------------*/
int 
cef_fib_info_get (
	CefT_Hash_Handle* fib, 
	char* info_buff, 
	const unsigned char* name, 
	int name_len, 
	int partial_match_f
);
/*--------------------------------------------------------------------------------------
	Check FIB ip address
----------------------------------------------------------------------------------------*/
int
cef_fib_check_addr(
	const char *addr						// Ip address
);


#endif // __CEF_FIB_HEADER__

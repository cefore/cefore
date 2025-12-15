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
 * cef_pit.h
 */

#ifndef __CEF_PIT_HEADER__
#define __CEF_PIT_HEADER__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/time.h>
#include <pthread.h>

#include <cefore/cef_hash.h>
#include <cefore/cef_define.h>
#include <cefore/cef_frame.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/
#define CefC_PitEntryVersion_Max		2	/* Max number of versions that can be 		*/
											/* registered in 1 Down Face Entry (other than AnyVer) */

#define	CefC_Pit_CleaningTime		1000000U
#define	CefC_Pit_WithoutLOCK	0
#define	CefC_Pit_WithLOCK		(~CefC_Pit_WithoutLOCK)

/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/

/*------------------------------------------------------------------*/
/* Down Stream Face entry											*/
/*------------------------------------------------------------------*/
typedef struct CefT_Down_Faces {

	/*--------------------------------------------
		Variables related to Network
	----------------------------------------------*/
	uint16_t		faceid;					/* Face-ID 									*/
	uint64_t	 	lifetime_us;			/* Lifetime 								*/
	uint64_t		nonce;					/* Nonce 									*/
	struct CefT_Down_Faces* next;			/* pointer to next Down Stream Face entry 	*/

	//0.8.3
	uint8_t				IR_Type;			/* InterestReturn Type 						*/
	unsigned int 		IR_len;				/* Length of IR_msg 						*/
	unsigned char* 		IR_msg;				/* InterestReturn msg 						*/

} CefT_Down_Faces;

/*------------------------------------------------------------------*/
/* Up Stream Face entry												*/
/*------------------------------------------------------------------*/

typedef struct CefT_Up_Faces {

	/*--------------------------------------------
		Variables related to Network
	----------------------------------------------*/
	uint16_t		faceid;					/* Face-ID 									*/
	struct CefT_Up_Faces* next;				/* pointer to next Up Stream Face entry 	*/

} CefT_Up_Faces;

/*------------------------------------------------------------------*/
/* PIT entry														*/
/*------------------------------------------------------------------*/

typedef struct {

	unsigned char 		resv4malloc[16];	/* reserved area for malloc					*/

	unsigned char* 		key;				/* Key of the PIT entry 					*/
	unsigned int 		klen;				/* Length of this key 						*/
	uint8_t				longlife_f;			/* set to not 0 if it shows Longlife PIT 	*/
#ifdef REFLEXIVE_FORWARDING
	int16_t				rnp_pos;			/* Position of RNP in this Key				*/
											/*  less than 0   : Normal message			*/
											/*  equal to 0    : Reflexive message		*/
											/*  greater than 0: Trigger message 		*/
#endif // REFLEXIVE_FORWARDING
	CefT_Down_Faces		dnfaces;			/* Down Stream Face entries 				*/
	unsigned int 		dnfacenum;			/* Number of Down Stream Face entries 		*/
	CefT_Up_Faces		upfaces;			/* Up Stream Face entry		 				*/
	uint8_t				stole_f;			/* sets to not 0 if it will be deleted	 	*/
	uint32_t 			hashv;				/* Hash value of this entry 				*/
	uint16_t 			tp_variant;			/* Transport Variant 						*/
	uint64_t	 		clean_us;			/* time to cleaning							*/
	CefT_Down_Faces		clean_dnfaces;		/* Down Stream Face entries to clean		*/
	uint64_t 			adv_lifetime_us;	/* Advertised lifetime 						*/
	uint64_t 			drp_lifetime_us;
	//0.8.3
	uint8_t				hoplimit;			/* Hop Limit of Forwarding Interest 		*/
	int					PitType;			/* PitType									*/
	int64_t				Last_chunk_num;		/* Last Forward Object Chunk Number 		*/

	pthread_mutex_t 	pe_mutex_pt;		/* mutex for thread safe for Pthread 		*/

	/********************** Key entity follows here **************************/
	/*  entry = (CefT_Pit_Entry*) malloc(sizeof (CefT_Pit_Entry) + name_len) */
	/*  entry->key = (unsigned char*)entry + sizeof (CefT_Pit_Entry)         */
	/********************** Key entity follows here **************************/
} CefT_Pit_Entry;

/****************************************************************************************
 Global Variables
 ****************************************************************************************/



/****************************************************************************************
 Function Declarations
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Initialize the PIT module
----------------------------------------------------------------------------------------*/
void cef_pit_init (
	uint32_t reply_timeout,        /* PIT lifetime(seconds) at "full discovery request" */
	uint32_t symbolic_max_lt,       /* Symbolic Interest max Lifetime 0.8.3             */
	uint32_t regular_max_lt         /* Regular Interest max Lifetime 0.8.3              */
);
/*--------------------------------------------------------------------------------------
	Looks up and creates a PIT entry matching the specified Name
----------------------------------------------------------------------------------------*/
CefT_Pit_Entry* 							/* a PIT entry								*/
cef_pit_entry_lookup (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh,				/* Parsed Option Header						*/
	unsigned char* ccninfo_pit,				/* pit name for ccninfo ccninfo-03			*/
	int	ccninfo_pit_len,					/* ccninfo pit length						*/
	unsigned int key_type_f					/* Flag to make PIT key with KeyID or COH	*/
);
/*--------------------------------------------------------------------------------------
	Searches a PIT entry matching the specified Name
----------------------------------------------------------------------------------------*/
CefT_Pit_Entry* 							/* a PIT entry								*/
cef_pit_entry_search (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh,				/* Parsed Option Header						*/
	unsigned char* ccninfo_pit,				/* pit name for ccninfo ccninfo-03			*/
	int	ccninfo_pit_len,					/* ccninfo pit length						*/
	unsigned int key_type_f					/* Flag to make PIT key with KeyID or COH	*/
);

#ifdef CefC_Debug
void
cef_pit_entry_print (
	CefT_Hash_Handle pit					/* PIT										*/
);
#endif // CefC_Debug
/*--------------------------------------------------------------------------------------
	Looks up and creates the specified Down Face entry
----------------------------------------------------------------------------------------*/
int 										/* Returns 1 if the return entry is new	 	*/
cef_pit_entry_down_face_update (
	CefT_Pit_Entry* entry, 					/* PIT entry								*/
	uint16_t faceid,						/* Face-ID									*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh,				/* Parsed Option Header						*/
	unsigned char* msg,						/* cefore packet 							*/
	int		 Resend_method					/* Resend method 0.8.3						*/
);
CefT_Pit_Entry*
cef_pit_entry_lookup_and_down_face_update (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh,				/* Parsed Option Header						*/
	unsigned char* ccninfo_pit,				/* pit name for ccninfo ccninfo-03			*/
	int	ccninfo_pit_len,					/* ccninfo pit length						*/
	uint16_t faceid,						/* Face-ID									*/
	unsigned char* msg,						/* cefore packet 							*/
	int		 Resend_method,					/* Resend method 0.8.3 						*/
	int		 *pit_res,						/* Returns 1 if the return entry is new	 	*/
	unsigned int key_type_f					/* Flag to make PIT key with KeyID or COH	*/
);
/*--------------------------------------------------------------------------------------
	Looks up and creates the specified Up Face entry
----------------------------------------------------------------------------------------*/
int 										/* Returns 1 if the return entry is new	 	*/
cef_pit_entry_up_face_update (
	CefT_Pit_Entry* entry, 					/* PIT entry								*/
	uint16_t faceid,						/* Face-ID									*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh					/* Parsed Option Header						*/
);
/*--------------------------------------------------------------------------------------
	Free the specified PIT entry
----------------------------------------------------------------------------------------*/
void
cef_pit_entry_free (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_Pit_Entry* entry 					/* PIT entry 								*/
);
/*--------------------------------------------------------------------------------------
	Removes the specified FaceID from the specified PIT entry
----------------------------------------------------------------------------------------*/
void
cef_pit_down_faceid_remove (
	CefT_Pit_Entry* entry, 					/* PIT entry 								*/
	uint16_t faceid 						/* Face-ID									*/
);
//0.8.3
/*--------------------------------------------------------------------------------------
	Symbolic PIT Check
----------------------------------------------------------------------------------------*/
int
cef_pit_symbolic_pit_check (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh,				/* Parsed Option Header						*/
	unsigned int key_type_f					/* Flag to make PIT key with KeyID or COH	*/
);
/*--------------------------------------------------------------------------------------
	Searches a PIT entry matching the specified Name with chunk number
----------------------------------------------------------------------------------------*/
CefT_Pit_Entry* 							/* a PIT entry								*/
cef_pit_entry_search_with_chunk (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh,				/* Parsed Option Header						*/
	unsigned int key_type_f					/* Flag to make PIT key with KeyID or COH	*/
);
/*--------------------------------------------------------------------------------------
	Searches a Symbolic-PIT entry matching the specified Name
----------------------------------------------------------------------------------------*/
CefT_Pit_Entry* 							/* a PIT entry								*/
cef_pit_entry_search_symbolic (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh,				/* Parsed Option Header						*/
	unsigned int key_type_f					/* Flag to make PIT key with KeyID or COH	*/
);
/*--------------------------------------------------------------------------------------
	Searches a PIT entry matching the specified Name with any chunk number
----------------------------------------------------------------------------------------*/
CefT_Pit_Entry* 							/* a PIT entry								*/
cef_pit_entry_search_with_anychunk (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh,				/* Parsed Option Header						*/
	unsigned int key_type_f					/* Flag to make PIT key with KeyID or COH	*/
);
/*--------------------------------------------------------------------------------------
	Returns the faceid of the upstream face from an existing PIT entry
----------------------------------------------------------------------------------------*/
uint16_t
cef_pit_entry_up_face_idget (
	CefT_Pit_Entry* entry					/* PIT entry 								*/
);
/*--------------------------------------------------------------------------------------
	Set InterestReturn Info to DownFace
----------------------------------------------------------------------------------------*/
int
cef_pit_interest_return_set (
	CefT_Pit_Entry* entry, 					/* PIT entry 								*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh,				/* Parsed Option Header						*/
	uint16_t faceid, 						/* Face-ID									*/
	uint8_t				IR_Type,			/* InterestReturn Type 						*/
	unsigned int 		IR_len,				/* Length of IR_msg 						*/
	unsigned char* 		IR_msg				/* InterestReturn msg 						*/
) ;
/*--------------------------------------------------------------------------------------
	Remove the version entry in specified Down Face entry
----------------------------------------------------------------------------------------*/
void
cef_pit_entry_down_face_remove (
	CefT_Pit_Entry* pe, 					/* PIT entry								*/
	CefT_Down_Faces* dnface,				/* Down Face entry							*/
	CefT_CcnMsg_MsgBdy* pm 					/* Parsed CEFORE message					*/
);
/*--------------------------------------------------------------------------------------
	Searches a Up Face entry
----------------------------------------------------------------------------------------*/
CefT_Up_Faces*								/* Returns  Up Face info				 	*/
cef_pit_entry_up_face_search (
	CefT_Pit_Entry* entry, 					/* PIT entry 								*/
	uint16_t faceid 						/* Face-ID									*/
);
/*--------------------------------------------------------------------------------------
	Lock/Unlock the specified PIT entry
----------------------------------------------------------------------------------------*/
int
cef_pit_entry_lock (
	CefT_Pit_Entry* entry 					/* PIT entry 								*/
);
void
cef_pit_entry_unlock (
	CefT_Pit_Entry* entry 					/* PIT entry 								*/
);
CefT_Pit_Entry* 							/* a PIT entry								*/
cef_pit_entry_lookup_with_lock (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh,				/* Parsed Option Header						*/
	unsigned char* name,					/* pit name (for ccninfo ccninfo-03)		*/
	int	name_len,							/* pit name length							*/
	int	with_lock,							/* entry lock flag							*/
	unsigned int key_type_f					/* Flag to make PIT key with KeyID or COH	*/
);
#ifdef REFLEXIVE_FORWARDING
/*--------------------------------------------------------------------------------------
	Searches a t-PIT entry matching the specified Name with chunk number
----------------------------------------------------------------------------------------*/
CefT_Pit_Entry*
cef_pit_entry_search_templete_pit (
	CefT_Hash_Handle pit,		/* PIT */
	CefT_CcnMsg_MsgBdy* pm, 	/* Parsed CEFORE message */
	CefT_CcnMsg_OptHdr* poh,	/* Parsed Option Header */
	uint16_t peer_faceid		/* peer Face-ID */
);
#endif // REFLEXIVE_FORWARDING
#endif // __CEF_PIT_HEADER__

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
 * cef_pit.c
 */

#define __CEF_PIT_SOURECE__

//#define	__PIT_DEBUG__
//#define		__RESTRICT__
//#define		__INTEREST__
//#define		__PIT_CLEAN__
/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>

#include <sys/time.h>

#include <cefore/cef_pit.h>
#include <cefore/cef_face.h>
#include <cefore/cef_client.h>
#include <cefore/cef_log.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

#define CefC_Pit_False				1		/* False									*/
#define CefC_Pit_True				1		/* True										*/
#define CefC_Maximum_Lifetime		16000	/* Maximum lifetime [ms] 					*/

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/


/****************************************************************************************
 State Variables
 ****************************************************************************************/

#ifdef CefC_Debug
static char 	pit_dbg_msg[2048];
#endif // CefC_Debug
#ifdef CefC_Dtc
CefT_Dtc_Pit_List* dtc_pit = NULL;
#endif // CefC_Dtc
#ifdef __PIT_DEBUG__
//static char 	pit_dbg[2048];
#endif
static uint32_t ccninfo_reply_timeout = CefC_Default_CcninfoReplyTimeout;
//0.8.3
static uint32_t symbolic_max_lifetime;
static uint32_t regular_max_lifetime;

#define	CefC_IR_SUPPORT_NUM			3
uint8_t	IR_PRIORITY_TBL[CefC_IR_SUPPORT_NUM] = {
	CefC_IR_HOPLIMIT_EXCEEDED,
	CefC_IR_NO_ROUTE,
	CefC_IR_CONGESION
};

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Looks up and creates the specified Down Face entry
----------------------------------------------------------------------------------------*/
static int									/* Returns 1 if the return entry is new	 	*/
cef_pit_entry_down_face_lookup (
	CefT_Pit_Entry* entry, 					/* PIT entry 								*/
	uint16_t faceid, 						/* Face-ID									*/
	CefT_Down_Faces** rt_dnface,			/* Down Face entry to return				*/
	uint64_t nonce,							/* Nonce 									*/
	uint8_t longlife_f 						/* Long Life Interest 						*/
);
/*--------------------------------------------------------------------------------------
	Looks up and creates the specified Up Face entry
----------------------------------------------------------------------------------------*/
static int 									/* Returns 1 if the return entry is new	 	*/
cef_pit_entry_up_face_lookup (
	CefT_Pit_Entry* entry, 					/* PIT entry 								*/
	uint16_t faceid, 						/* Face-ID									*/
	CefT_Up_Faces** rt_face					/* Up Face entry to return		 			*/
);
/*--------------------------------------------------------------------------------------
	Cleanups PIT entry which expires the lifetime
----------------------------------------------------------------------------------------*/
static CefT_Pit_Entry*
cef_pit_cleanup (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_Pit_Entry* entry 					/* PIT entry 								*/
);
#if 0
/*--------------------------------------------------------------------------------------
	Cleanups PIT entry which expires the lifetime for Cefore-Router
----------------------------------------------------------------------------------------*/
static CefT_Pit_Entry*
cefrt_pit_cleanup (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_Pit_Entry* entry 					/* PIT entry 								*/
);
#endif
/****************************************************************************************
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Initialize the PIT module
----------------------------------------------------------------------------------------*/
void
cef_pit_init (
	uint32_t reply_timeout,		   /* PIT lifetime(seconds) at "full discovery request" */
	uint32_t symbolic_max_lt,      /* Symbolic Interest max Lifetime 0.8.3             */
	uint32_t regular_max_lt        /* Regular Interest max Lifetime 0.8.3              */
){
	ccninfo_reply_timeout = reply_timeout;
	symbolic_max_lifetime = symbolic_max_lt;
	regular_max_lifetime = regular_max_lt;
	return;
}
/*--------------------------------------------------------------------------------------
	Looks up and creates a PIT entry matching the specified Name
----------------------------------------------------------------------------------------*/
CefT_Pit_Entry* 							/* a PIT entry								*/
cef_pit_entry_lookup (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_Parsed_Message* pm, 				/* Parsed CEFORE message					*/
	CefT_Parsed_Opheader* poh				/* Parsed Option Header						*/
	, unsigned char* ccninfo_pit,			/* pit name for ccninfo ccninfo-03			*/
	int	ccninfo_pit_len						/* ccninfo pit length						*/
) {
	CefT_Pit_Entry* entry;
	unsigned char* tmp_name = NULL;
	uint16_t tmp_name_len = 0;

#ifdef	__PIT_DEBUG__
	fprintf (stderr, "[%s] IN\n",
			 "cef_pit_entry_lookup" );
#endif

	if (pm->top_level_type == CefC_T_DISCOVERY) {  /* for CCNINFO */
		/* KEY: Name + NodeIdentifier + RequestID */
		tmp_name_len = ccninfo_pit_len;
		tmp_name = (unsigned char*)malloc( sizeof(char) * tmp_name_len );
		memcpy( tmp_name, ccninfo_pit, tmp_name_len );
	} else {
		tmp_name = pm->name;
		tmp_name_len = pm->name_len;
	}
	/* Searches a PIT entry 	*/
	entry = (CefT_Pit_Entry*) cef_hash_tbl_item_get (pit, tmp_name, tmp_name_len);
#ifdef	__PIT_DEBUG__
	fprintf (stderr, "\t %p\n",
			 (void*)entry );
#endif

	/* Creates a new PIT entry, if it dose not match 	*/
	if (entry == NULL) {
		if(cef_hash_tbl_item_num_get(pit) == cef_hash_tbl_def_max_get(pit)) {
			cef_log_write (CefC_Log_Warn, 
				"PIT table is full(PIT_SIZE = %d)\n", cef_hash_tbl_def_max_get(pit));
			return (NULL);
		}
		
		entry = (CefT_Pit_Entry*) malloc (sizeof (CefT_Pit_Entry));
		memset (entry, 0, sizeof (CefT_Pit_Entry));
		entry->key = (unsigned char*) malloc (sizeof (char) * tmp_name_len);
		entry->klen = tmp_name_len;
		memcpy (entry->key, tmp_name, tmp_name_len);
		entry->hashv = cef_hash_tbl_hashv_get (pit, entry->key, entry->klen);
		entry->clean_us = cef_client_present_timeus_get () + 1000000;
		cef_hash_tbl_item_set (pit, entry->key, entry->klen, entry);
		entry->tp_variant = poh->tp_variant;
		entry->nonce = 0;
		entry->adv_lifetime_us = 0;
		entry->drp_lifetime_us = 0;
		//0.8.3
		entry->hoplimit = 0;
		entry->PitType  = pm->InterestType;
		entry->Last_chunk_num = 0;
		entry->KIDR_len = pm->KeyIdRester_sel_len;
		if ( entry->KIDR_len == 0 ) {
			entry->KIDR_selector = NULL;
		} else {
			entry->KIDR_selector = (unsigned char*)malloc( entry->KIDR_len );
			memcpy( entry->KIDR_selector, pm->KeyIdRester_selector, entry->KIDR_len );
		}
		entry->COBHR_len = pm->ObjHash_len;
		if ( entry->COBHR_len == 0 ) {
			entry->COBHR_selector = NULL;
		} else {
			entry->COBHR_selector = (unsigned char*)malloc( entry->COBHR_len );
			memcpy( entry->COBHR_selector, pm->ObjHash, entry->COBHR_len );
		}
#ifdef __RESTRICT__
		printf( "%s entry->KIDR_len:%d   entry->COBHR_len:%d\n", __func__, entry->KIDR_len, entry->COBHR_len );
#endif
	}
#ifdef CefC_Debug
	{
		int dbg_x;
		
		sprintf (pit_dbg_msg, "[pit] Lookup the entry [");
		for (dbg_x = 0 ; dbg_x < entry->klen ; dbg_x++) {
			sprintf (pit_dbg_msg, "%s %02X", pit_dbg_msg, entry->key[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", pit_dbg_msg);
	}
#endif // CefC_Debug
#ifdef __PIT_DEBUG__
	{
		int dbg_xx;
		
		fprintf (stderr, "[" );
		for (dbg_xx = 0 ; dbg_xx < entry->klen ; dbg_xx++) {
			fprintf (stderr, "%02X ", entry->key[dbg_xx]);
			
		}
		fprintf (stderr, "]\n" );
	}
#endif // CefC_Debug
	
	if (pm->top_level_type == CefC_T_DISCOVERY) {  /* for CCNINFO */
		free (tmp_name);
	}
	return (entry);
}
/*--------------------------------------------------------------------------------------
	Searches a PIT entry matching the specified Name
----------------------------------------------------------------------------------------*/
CefT_Pit_Entry* 							/* a PIT entry								*/
cef_pit_entry_search (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_Parsed_Message* pm, 				/* Parsed CEFORE message					*/
	CefT_Parsed_Opheader* poh				/* Parsed Option Header						*/
	, unsigned char* ccninfo_pit,			/* pit name for ccninfo ccninfo-03			*/
	int	ccninfo_pit_len						/* ccninfo pit length						*/
) {
	CefT_Pit_Entry* entry;
	uint16_t name_len = pm->name_len;
	unsigned char* tmp_name = NULL;
	uint16_t tmp_name_len;
	uint64_t now;
	
	if (poh->symbolic_code_f) {
		memcpy (&pm->name[name_len], &poh->symbolic_code, sizeof (struct value32x2_tlv));
		name_len += sizeof (struct value32x2_tlv);
	}
	if (pm->top_level_type == CefC_T_DISCOVERY) { /* for CCNINFO */
		/* KEY: Name + NodeIdentifier + RequestID */
		tmp_name_len = ccninfo_pit_len;
		tmp_name = (unsigned char*)malloc( sizeof(char) * tmp_name_len );
		memcpy( tmp_name, ccninfo_pit, tmp_name_len );
	} else {
		tmp_name = pm->name;
		tmp_name_len = pm->name_len;
	}
#ifdef CefC_Debug
	{
		int dbg_x;
		
		sprintf (pit_dbg_msg, "[pit] Search the entry [");
		for (dbg_x = 0 ; dbg_x < tmp_name_len ; dbg_x++) {
			sprintf (pit_dbg_msg, "%s %02X", pit_dbg_msg, tmp_name[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", pit_dbg_msg);
	}
#endif // CefC_Debug
	
	/* Searches a PIT entry 	*/
	entry = (CefT_Pit_Entry*) cef_hash_tbl_item_get (pit, tmp_name, tmp_name_len);
	now = cef_client_present_timeus_get ();
	
	if (entry != NULL) {
		if (!entry->symbolic_f) {
			entry->stole_f = 1;
		}
		/* for ccninfo "full discovery" */
		if (poh->ccninfo_flag & CefC_CtOp_FullDisCover) {
			entry->stole_f = 0;
		}
#ifdef CefC_Debug
		{
			int dbg_x;
			
			sprintf (pit_dbg_msg, "[pit] Exact matched to the entry [");
			for (dbg_x = 0 ; dbg_x < entry->klen ; dbg_x++) {
				sprintf (pit_dbg_msg, "%s %02X", pit_dbg_msg, entry->key[dbg_x]);
			}
			cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", pit_dbg_msg);
		}
#endif // CefC_Debug
		if (pm->top_level_type == CefC_T_DISCOVERY) {  /* for CCNINFO */
			free (tmp_name);
		}
/*		if (now > entry->adv_lifetime_us) {	20190822*/
		if ((now > entry->adv_lifetime_us) && (poh->app_reg_f != CefC_App_DeRegPit)){	//20190822
			return (NULL);
		}
		return (entry);
	}
	
	if (pm->chnk_num_f) {
		uint16_t name_len_wo_chunk;
		name_len_wo_chunk = tmp_name_len - (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
		entry = (CefT_Pit_Entry*) cef_hash_tbl_item_get (pit, tmp_name, name_len_wo_chunk);

		if (entry != NULL) {
			if (entry->symbolic_f) {
				entry = cef_pit_cleanup (pit, entry);
#ifdef CefC_Debug
				{
					int dbg_x;
					
					if (entry) {
						sprintf (pit_dbg_msg, "[pit] Partial matched to the entry [");
						for (dbg_x = 0 ; dbg_x < entry->klen ; dbg_x++) {
							sprintf (pit_dbg_msg, 
								"%s %02X", pit_dbg_msg, entry->key[dbg_x]);
						}
						cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", pit_dbg_msg);
					} else {
						cef_dbg_write (CefC_Dbg_Finest, "[pit] Mismatched\n");
					}
				}
#endif // CefC_Debug
				if (pm->top_level_type == CefC_T_DISCOVERY) {  /* for CCNINFO */
					free (tmp_name);
				}
				if (now > entry->adv_lifetime_us) {
					return (NULL);
				}
				return (entry);
			}
		}
	}
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, "[pit] Mismatched\n");
#endif // CefC_Debug
	
	if (pm->top_level_type == CefC_T_DISCOVERY) {  /* for CCNINFO */
		free (tmp_name);
	}
	return (NULL);
}
/*--------------------------------------------------------------------------------------
	Searches a PIT entry matching the specified Name
----------------------------------------------------------------------------------------*/
CefT_Pit_Entry* 							/* a PIT entry								*/
cef_pit_entry_search_specified_name (
	CefT_Hash_Handle pit,					/* PIT										*/
	unsigned char* sp_name,					/* specified Name							*/
	uint16_t sp_name_len,					/* length of Name							*/
	CefT_Parsed_Message* pm, 				/* Parsed CEFORE message					*/
	CefT_Parsed_Opheader* poh,				/* Parsed Option Header						*/
	int match_type							/* 0:Exact, 1:Prefix						*/
) {
	CefT_Pit_Entry* entry;
	uint16_t name_len = sp_name_len;
	
	if (poh->symbolic_code_f) {
		memcpy (&sp_name[name_len], &poh->symbolic_code, sizeof (struct value32x2_tlv));
		name_len += sizeof (struct value32x2_tlv);
	}
#ifdef CefC_Debug
	{
		int dbg_x;
		
		sprintf (pit_dbg_msg, "[pit] Search the entry [");
		for (dbg_x = 0 ; dbg_x < name_len ; dbg_x++) {
			sprintf (pit_dbg_msg, "%s %02X", pit_dbg_msg, sp_name[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", pit_dbg_msg);
	}
#endif // CefC_Debug
	
	/* Searches a PIT entry 	*/
	entry = (CefT_Pit_Entry*) cef_hash_tbl_item_get (pit, sp_name, name_len);
	
	if (entry != NULL) {
		if (match_type) {
			/* PrefixMatch */
			if (pm->chnk_num_f) {
				if (entry->symbolic_f) {
					entry = cef_pit_cleanup (pit, entry);
				}
			}
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, "[pit] Partial matched to the entry\n");
#endif // CefC_Debug
			return (entry);
		} else {
			/* ExactMatch */
			if (!entry->symbolic_f) {
				entry->stole_f = 1;
			}
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, "[pit] Exact matched to the entry\n");
#endif // CefC_Debug
			return (entry);
		}
	}
	
	if (pm->chnk_num_f) {
		uint16_t name_len_wo_chunk;
		name_len_wo_chunk = name_len - (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
		entry = (CefT_Pit_Entry*) cef_hash_tbl_item_get (pit, pm->name, name_len_wo_chunk);

		if (entry != NULL) {
			if (entry->symbolic_f) {
				entry = cef_pit_cleanup (pit, entry);
#ifdef CefC_Debug
				{
					int dbg_x;
					
					if (entry) {
						sprintf (pit_dbg_msg, "[pit] Partial matched to the entry [");
						for (dbg_x = 0 ; dbg_x < entry->klen ; dbg_x++) {
							sprintf (pit_dbg_msg, 
								"%s %02X", pit_dbg_msg, entry->key[dbg_x]);
						}
						cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", pit_dbg_msg);
					} else {
						cef_dbg_write (CefC_Dbg_Finest, "[pit] Mismatched\n");
					}
				}
#endif // CefC_Debug
				return (entry);
			}
		}
	}

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, "[pit] Mismatched\n");
#endif // CefC_Debug
	return (NULL);
}
/*--------------------------------------------------------------------------------------
	Searches a PIT(for App) entry matching the specified Name --- Prefix(Longest) Match
----------------------------------------------------------------------------------------*/
CefT_Pit_Entry* 							/* a PIT entry								*/
cef_pit_entry_search_specified_name_for_app (
	CefT_Hash_Handle pit,					/* PIT										*/
	unsigned char* sp_name,					/* specified Name							*/
	uint16_t sp_name_len,					/* length of Name							*/
	CefT_Parsed_Message* pm, 				/* Parsed CEFORE message					*/
	CefT_Parsed_Opheader* poh				/* Parsed Option Header						*/
) {
	CefT_Pit_Entry* entry;
	uint16_t name_len = sp_name_len;

	unsigned char* msp;
	unsigned char* mep;
	uint16_t length;

	
	if (poh->symbolic_code_f) {
		memcpy (&sp_name[name_len], &poh->symbolic_code, sizeof (struct value32x2_tlv));
		name_len += sizeof (struct value32x2_tlv);
	}
#ifdef CefC_Debug
	{
		int dbg_x;
		
		sprintf (pit_dbg_msg, "[pit] Search the entry [");
		for (dbg_x = 0 ; dbg_x < name_len ; dbg_x++) {
			sprintf (pit_dbg_msg, "%s %02X", pit_dbg_msg, sp_name[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", pit_dbg_msg);
	}
#endif // CefC_Debug
	
	/* Searches a PIT entry 	*/
	while (name_len > 0) {
		entry = (CefT_Pit_Entry*) cef_hash_tbl_item_get (pit, sp_name, name_len);
		if (entry != NULL) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "[pit] Matched to the entry\n");
#endif // CefC_Debug
			return (entry);
		}
		
		msp = sp_name;
		mep = sp_name + name_len - 1;
		while (msp < mep) {
			memcpy (&length, &msp[CefC_S_Length], CefC_S_Length);
			length = ntohs (length);
			
			if (msp + CefC_S_Type + CefC_S_Length + length < mep) {
				msp += CefC_S_Type + CefC_S_Length + length;
			} else {
				break;
			}
		}
		name_len = msp - sp_name;
	}
	
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, "[pit] Mismatched\n");
#endif // CefC_Debug
	return (NULL);
}

#ifdef CefC_Debug
void
cef_pit_entry_print (
	CefT_Hash_Handle pit					/* PIT										*/
) {
	int pit_num, cnt, index;
	CefT_Pit_Entry* entry;
	int pit_max = cef_hash_tbl_item_max_idx_get (pit);
	
	pit_num = cef_hash_tbl_item_num_get (pit);
	fprintf(stderr,"===== PIT (entry=%d) =====\n", pit_num);
	for (index = 0, cnt = 0; (cnt < pit_num && index < pit_max); index++) {
		entry = (CefT_Pit_Entry*)cef_hash_tbl_item_get_from_index (pit, index);
		if (entry != NULL) {
			if (entry->klen != -1) {
				fprintf(stderr,"    (%d)(%d) len=%d [", index, cnt, entry->klen);
				{
					int dbg_x;
					for (dbg_x = 0 ; dbg_x < entry->klen ; dbg_x++) {
						fprintf (stderr, "%02x ", entry->key[dbg_x]);
					}
					fprintf (stderr, "]\n");
				}
				cnt++;
			} else {
				fprintf(stderr,"    (%d) len=-1 **************************************\n", index);
			}
		}
	}
	fprintf(stderr,"==============================\n");
	return;
}
#endif // CefC_Debug
#if 0
/*--------------------------------------------------------------------------------------
	Searches a PIT entry matching the specified Name for Cefore-Router
----------------------------------------------------------------------------------------*/
CefT_Pit_Entry* 							/* a PIT entry								*/
cefrt_pit_entry_search (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_Parsed_Message* pm, 				/* Parsed CEFORE message					*/
	CefT_Parsed_Opheader* poh				/* Parsed Option Header						*/
) {
	CefT_Pit_Entry* entry;
	uint16_t name_len = pm->name_len;

	/* Searches a PIT entry 	*/
	entry = (CefT_Pit_Entry*) cef_hash_tbl_item_get (pit, pm->name, name_len);

	if (entry != NULL) {
		entry->stole_f = CefC_Pit_True;
		return (entry);
	}

	if (pm->chnk_num_f) {
		entry = (CefT_Pit_Entry*) cef_hash_tbl_item_get (
			pit, pm->name, name_len  - (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum));

		if (entry != NULL) {
			if (entry->symbolic_f) {
				entry = cefrt_pit_cleanup (pit, entry);
				return (entry);
			}
		}
	}

	return (NULL);
}
#endif
/*--------------------------------------------------------------------------------------
	Looks up and creates the specified Down Face entry
----------------------------------------------------------------------------------------*/
int 										/* Returns 1 if the return entry is new	 	*/
cef_pit_entry_down_face_update (
	CefT_Pit_Entry* entry, 					/* PIT entry								*/
	uint16_t faceid,						/* Face-ID									*/
	CefT_Parsed_Message* pm, 				/* Parsed CEFORE message					*/
	CefT_Parsed_Opheader* poh,				/* Parsed Option Header						*/
	unsigned char* msg,						/* cefore packet 							*/
	int		 Resend_method					/* Resend method 0.8.3 						*/
) {
	CefT_Down_Faces* face;
#ifdef	__PIT_DEBUG__
	fprintf (stderr, "[%s] IN faceid=%d\n",
			 "cef_pit_entry_down_face_update", faceid );
#endif
	
	int new_downface_f = 0;
	int forward_interest_f = 0;
	struct timeval now;
	uint64_t nowt_us;
	uint64_t max_lifetime_us;
	uint64_t prev_lifetime_us;
	uint64_t extent_us;
	uint16_t nw_lifetime_ms;
	uint16_t new_lifetime_ms;
	
	gettimeofday (&now, NULL);
	nowt_us = now.tv_sec * 1000000llu + now.tv_usec;
	
	/* Looks up a Down Face entry 		*/
	new_downface_f = cef_pit_entry_down_face_lookup (
						entry, faceid, &face, pm->nonce, pm->org.longlife_f);
#ifdef	__PIT_DEBUG__
	fprintf (stderr, "\t new_downface_f=%d (1:NEW)\n",
			 new_downface_f );
	fprintf (stderr, "\t face->lifetime_us= "FMTU64"\n", face->lifetime_us / 1000 );
#endif
	
	/* Checks flags 					*/
	if (new_downface_f) {
		face->nonce = pm->nonce;
	} else {
		if ((pm->nonce) && (pm->nonce == face->nonce)) {
#ifdef	__PIT_DEBUG__
			fprintf (stderr, "[%s] return(0) ((pm->nonce) && (pm->nonce == face->nonce))\n",
			 "cef_pit_entry_down_face_update" );
#endif
			return (0);
		}
		face->nonce = pm->nonce;
	}
	
	if (pm->org.longlife_f) {
		if (new_downface_f) {
			entry->symbolic_f++;
		}
	}
#ifdef	__PIT_DEBUG__
	fprintf (stderr, "\t entry->symbolic_f=%d\n",
			 entry->symbolic_f );
#endif
#ifdef CefC_Ccninfo
	/* for ccninfo */
	if (pm->top_level_type == CefC_T_DISCOVERY) {
		if (poh->ccninfo_flag & CefC_CtOp_FullDisCover)
			poh->lifetime = ccninfo_reply_timeout * 1000;
		else
			poh->lifetime = CefC_Default_CcninfoReplyTimeout * 1000;
		
		poh->lifetime_f = 1;
	}
#endif //CefC_Ccninfo
	
	/* Checks whether the life time is smaller than the limit 	*/
#ifndef CefC_Nwproc
	if ( entry->PitType != CefC_PIT_TYPE_Reg ) {	//0.8.3
		if (poh->lifetime > symbolic_max_lifetime) {
			poh->lifetime = symbolic_max_lifetime;
		}
	} else {
		if (poh->lifetime > regular_max_lifetime) {
			poh->lifetime = regular_max_lifetime;
		}
	}
#else // CefC_Nwproc
	if (!poh->nwproc_f) {
		if ( entry->PitType != CefC_PIT_TYPE_Reg ) {	//0.8.3
			if (poh->lifetime > symbolic_max_lifetime) {
				poh->lifetime = symbolic_max_lifetime;
			}
		} else {
			if (poh->lifetime > regular_max_lifetime) {
				poh->lifetime = regular_max_lifetime;
			}
		}
	}
#endif // CefC_Nwproc
	
	/* Updates Interest Lifetime of this PIT entry 		*/
	if (poh->lifetime_f) {
#ifdef CefC_Dtc
		if (pm->app_comp == CefC_T_APP_DTC) {
			extent_us = (uint64_t)poh->lifetime * 1000000llu;
		} else {
			extent_us = poh->lifetime * 1000;
		}
#else // CefC_Dtc
		extent_us = poh->lifetime * 1000;
#endif // CefC_Dtc
	} else {
		extent_us = CefC_Default_LifetimeUs;
	}
	prev_lifetime_us  = face->lifetime_us;
	face->lifetime_us = nowt_us + extent_us;
	

#ifdef	__PIT_DEBUG__
	fprintf (stderr, "\t Before\n" );
	fprintf (stderr, "\t extent_us= "FMTU64"\n", extent_us / 1000 );
	fprintf (stderr, "\t prev_lifetime_us= "FMTU64"\n", prev_lifetime_us / 1000 );
	fprintf (stderr, "\t face->lifetime_us= "FMTU64"\n", face->lifetime_us / 1000 );
	fprintf (stderr, "\t entry->drp_lifetime_us= "FMTU64"\n", entry->drp_lifetime_us / 1000 );
	fprintf (stderr, "\t entry->adv_lifetime_us= "FMTU64"\n", entry->adv_lifetime_us / 1000 );
#endif

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, "[pit] Lifetime = "FMTU64"\n", extent_us / 1000);
#endif // CefC_Debug
	
	/* Checks the advertised lifetime to upstream 		*/
	if (face->lifetime_us > entry->drp_lifetime_us) {
#ifdef	__PIT_DEBUG__
		fprintf (stderr, "\t (face->lifetime_us > entry->drp_lifetime_us)\n" );
#endif
		forward_interest_f = 1;
#ifndef CefC_Nwproc
		entry->drp_lifetime_us = face->lifetime_us + 1000000;
#else // CefC_Nwproc
		entry->drp_lifetime_us = face->lifetime_us + extent_us;
#endif // CefC_Nwproc
		entry->adv_lifetime_us = face->lifetime_us;
	} else {
#ifdef	__PIT_DEBUG__
		fprintf (stderr, "\t !(face->lifetime_us > entry->drp_lifetime_us)\n" );
#endif
#ifdef CefC_Ccninfo
		if (pm->top_level_type == CefC_T_DISCOVERY) {
			return (forward_interest_f);
		}
#endif //CefC_Ccninfo
		if (face->lifetime_us < prev_lifetime_us) {
#ifdef	__PIT_DEBUG__
			fprintf (stderr, "\t (face->lifetime_us < prev_lifetime_us)\n" );
#endif
			face = &(entry->dnfaces);
			max_lifetime_us = face->lifetime_us;
			
			while (face->next) {
				face = face->next;
				if (face->lifetime_us > max_lifetime_us) {
					max_lifetime_us = face->lifetime_us;
				}
			}
			if (max_lifetime_us < entry->adv_lifetime_us) {
				forward_interest_f = 1;
				
				if (poh->lifetime_f) {
					new_lifetime_ms = (max_lifetime_us - nowt_us) / 1000;
					nw_lifetime_ms = htons (new_lifetime_ms);
					memcpy (&msg[poh->lifetime_f], &nw_lifetime_ms, CefC_S_Lifetime);
#ifdef	__PIT_DEBUG__
					fprintf (stderr, "\t Lifetime (update)= %d\n", new_lifetime_ms );
#endif
#ifdef CefC_Debug
					cef_dbg_write (CefC_Dbg_Finest, 
						"[pit] Lifetime (update) = "FMTU64"\n", nw_lifetime_ms);
#endif // CefC_Debug
				}
				entry->adv_lifetime_us = max_lifetime_us;
				entry->drp_lifetime_us = max_lifetime_us + 1000000;
			}
			
			/* If the other down stream node exists, we do not forward 		*/
			/* the Interest with lifetime. 									*/
			if ((poh->lifetime_f) && (poh->lifetime == 0)) {
				cef_pit_down_faceid_remove (entry, face->faceid);
			}
		}
	}
#ifdef	__PIT_DEBUG__
	fprintf (stderr, "[%s] Before (%d) forward (yes=1/no=0)\n",
			 "cef_pit_entry_down_face_update", forward_interest_f );
	fprintf (stderr, "\t Resend_method:%s\n",
			  (Resend_method == CefC_IntRetrans_Type_RFC) ? "RFC":"SUP");
#endif

#if 1
	//0.8.3  RFC
	//	forward_interest_f=0
	//		new_downface_f=0 Same Face:Retransmit
	//		new_downface_f=1 Not Same Face: Check HopLimit
	//	forward_interest_f=1
	if ( Resend_method == CefC_IntRetrans_Type_RFC ) {
		if ( forward_interest_f == 0 ) {
			if ( new_downface_f == 0 ) {
				forward_interest_f = 1;
			} else {
				if ( pm->hoplimit > entry->hoplimit ) {
					forward_interest_f = 1;
				}
			}
		} else {	/* ( forward_interest_f == 1 ) */
			if ( new_downface_f == 0 ) {
				/* NOP */
			} else {	/*  */
				if ( pm->hoplimit <= entry->hoplimit ) {
					forward_interest_f = 0;
				}
			}
		}
	}
	/* Update HopLimit */
	if ( (forward_interest_f == 1) && (pm->hoplimit > entry->hoplimit) ) {
		entry->hoplimit = pm->hoplimit;
	}
#endif

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, 
		"[pit] forward (yes=1/no=0) = %d\n", forward_interest_f);
#endif

#ifdef	__PIT_DEBUG__
	fprintf (stderr, "\t After\n" );
	fprintf (stderr, "\t extent_us= "FMTU64"\n", extent_us / 1000 );
	fprintf (stderr, "\t prev_lifetime_us= "FMTU64"\n", prev_lifetime_us / 1000 );
	fprintf (stderr, "\t face->lifetime_us= "FMTU64"\n", face->lifetime_us / 1000 );
	fprintf (stderr, "\t entry->drp_lifetime_us= "FMTU64"\n", entry->drp_lifetime_us / 1000 );
	fprintf (stderr, "\t entry->adv_lifetime_us= "FMTU64"\n", entry->adv_lifetime_us / 1000 );
	fprintf (stderr, "[%s] OUT return(%d) forward (yes=1/no=0)\n",
			 "cef_pit_entry_down_face_update", forward_interest_f );
#endif
	
	return (forward_interest_f);
}
/*--------------------------------------------------------------------------------------
	Looks up and creates the specified Up Face entry
----------------------------------------------------------------------------------------*/
int 										/* Returns 1 if the return entry is new	 	*/
cef_pit_entry_up_face_update (
	CefT_Pit_Entry* entry, 					/* PIT entry								*/
	uint16_t faceid,						/* Face-ID									*/
	CefT_Parsed_Message* pm, 				/* Parsed CEFORE message					*/
	CefT_Parsed_Opheader* poh				/* Parsed Option Header						*/
) {
	CefT_Up_Faces* face;
	int new_create_f;

	/* Looks up an Up Face entry 		*/
	new_create_f = cef_pit_entry_up_face_lookup (entry, faceid, &face);

	/* If this entry has Symbolic Interest, always it forwards the Interest */
	if (entry->symbolic_f) {
		new_create_f = 1;
	}

	return (new_create_f);
}
/*--------------------------------------------------------------------------------------
	Free the specified PIT entry
----------------------------------------------------------------------------------------*/
void
cef_pit_entry_free (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_Pit_Entry* entry 					/* PIT entry 								*/
) {
	CefT_Up_Faces* upface_next;
	CefT_Up_Faces* upface = entry->upfaces.next;
	CefT_Down_Faces* dnface_next;
	CefT_Down_Faces* dnface = entry->dnfaces.next;

#ifdef	__PIT_CLEAN__
	fprintf( stderr, "[%s] IN entry->dnfacenum:%d\n", __func__, entry->dnfacenum );
#endif

	entry = (CefT_Pit_Entry*) cef_hash_tbl_item_remove (pit, entry->key, entry->klen);

#ifdef CefC_Debug
	{
		int dbg_x;
		
		sprintf (pit_dbg_msg, "[pit] Free the entry [");
		for (dbg_x = 0 ; dbg_x < entry->klen ; dbg_x++) {
			sprintf (pit_dbg_msg, "%s %02X", pit_dbg_msg, entry->key[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", pit_dbg_msg);
	}
#endif // CefC_Debug
	
	while (upface) {
		upface_next = upface->next;
		free (upface);
		upface = upface_next;
	}
	
	while (dnface) {
		dnface_next = dnface->next;
		if ( dnface->IR_len > 0 ) {
#ifdef	__PIT_CLEAN__
	fprintf( stderr, "\t dnface->IR_len:%d Type:%d\n", dnface->IR_len, dnface->IR_Type );
#endif
			free( dnface->IR_msg );
		}
		free (dnface);
		dnface = dnface_next;
	}
	
	dnface = entry->clean_dnfaces.next;
	while (dnface) {
		dnface_next = dnface->next;
		if ( dnface->IR_len > 0 ) {
#ifdef	__PIT_CLEAN__
	fprintf( stderr, "\t clean dnface->IR_len:%d Type:%d\n", dnface->IR_len, dnface->IR_Type );
#endif
			free( dnface->IR_msg );
		}
		free (dnface);
		dnface = dnface_next;
	}

#if CefC_Dtc
	if (entry->dtc_f) {
		cef_pit_dtc_entry_delete (&entry->dtc_entry);
	}
#endif // CefC_Dtc

	//0.8.3
	if ( entry->KIDR_len > 0 ) {
		free( entry->KIDR_selector );
	}
	if ( entry->COBHR_len > 0 ) {
		free( entry->COBHR_selector );
	}

	free (entry->key);
	free (entry);

	return;
}
/*--------------------------------------------------------------------------------------
	Cleanups PIT entry which expires the lifetime
----------------------------------------------------------------------------------------*/
void
cef_pit_clean (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_Pit_Entry* entry 					/* PIT entry 								*/
) {
	CefT_Down_Faces* dnface;
	CefT_Down_Faces* dnface_prv;
	uint64_t now;
	CefT_Down_Faces* clean_dnface;
	
	now = cef_client_present_timeus_get ();

#ifdef	__PIT_CLEAN__
	fprintf( stderr, "[%s] IN entry->dnfacenum:%d\n", __func__, entry->dnfacenum );
#endif
	if (now > entry->adv_lifetime_us) {
#ifdef	__PIT_CLEAN__
	fprintf( stderr, "\t(now > entry->adv_lifetime_us)\n" );
#endif
		
		clean_dnface = &(entry->clean_dnfaces);
		while (clean_dnface->next) {
			clean_dnface = clean_dnface->next;
		}
		
		dnface = &(entry->dnfaces);
		
		while (dnface->next) {
			dnface = dnface->next;
			clean_dnface->next = dnface;
			clean_dnface = dnface;
			clean_dnface->next = NULL;
#ifdef	__PIT_CLEAN__
	fprintf( stderr, "\t move to clean\n" );
#endif
#ifdef	__PIT_CLEAN__
	fprintf( stderr, "\t clean dnface->IR_len:%d Type:%d\n", dnface->IR_len, dnface->IR_Type );
#endif
			if (cef_face_check_active (dnface->faceid) > 0) {
#ifdef	__PIT_CLEAN__
	fprintf( stderr, "\t Send IR\n" );
#endif
				cef_face_frame_send_forced (dnface->faceid, dnface->IR_msg, dnface->IR_len);
			}

		}
		entry->dnfaces.next = NULL;
		entry->dnfacenum = 0;
		
#ifdef	__PIT_CLEAN__
	fprintf( stderr, "\t entry->dnfacenum:%d\n", entry->dnfacenum );
#endif
		return;
	}
	
	if (now < entry->clean_us) {
#ifdef	__PIT_CLEAN__
	fprintf( stderr, "\t(now < entry->clean_us) RETURN\n" );
#endif
		return;
	}
	entry->clean_us = now + 1000000;
	
	dnface = &(entry->dnfaces);
	dnface_prv = dnface;
	
#ifdef	__PIT_CLEAN__
	fprintf( stderr, "\t Before while\n" );
#endif
	while (dnface->next) {
		dnface = dnface->next;
		
		if (now > dnface->lifetime_us) {
#ifdef	__PIT_CLEAN__
	fprintf( stderr, "\t(now > dnface->lifetime_us)\n" );
#endif
			dnface_prv->next = dnface->next;
			clean_dnface = &(entry->clean_dnfaces);
			while (clean_dnface->next) {
				clean_dnface = clean_dnface->next;
			}
			clean_dnface->next = dnface;
			clean_dnface->next->next = NULL;
			dnface = dnface_prv;
			entry->dnfacenum--;
#ifdef	__PIT_CLEAN__
	fprintf( stderr, "\t move to clean\n" );
#endif
#ifdef	__PIT_CLEAN__
	fprintf( stderr, "\t dnface->IR_len:%d Type:%d\n", dnface->IR_len, dnface->IR_Type );
#endif
			if (cef_face_check_active (dnface->faceid) > 0) {
#ifdef	__PIT_CLEAN__
	fprintf( stderr, "\t Send IR\n" );
#endif
				cef_face_frame_send_forced (dnface->faceid, dnface->IR_msg, dnface->IR_len);
			}
		} else {
			dnface_prv = dnface;
		}
	}
#ifdef	__PIT_CLEAN__
	fprintf( stderr, "\t After while RETURN entry->dnfacenum:%d\n", entry->dnfacenum );
#endif
	
	return;
}
/*--------------------------------------------------------------------------------------
	Looks up and creates the specified Down Face entry
----------------------------------------------------------------------------------------*/
static int									/* Returns 1 if the return entry is new	 	*/
cef_pit_entry_down_face_lookup (
	CefT_Pit_Entry* entry, 					/* PIT entry 								*/
	uint16_t faceid, 						/* Face-ID									*/
	CefT_Down_Faces** rt_dnface,			/* Down Face entry to return				*/
	uint64_t nonce,							/* Nonce 									*/
	uint8_t longlife_f 						/* Long Life Interest 						*/
) {
	CefT_Down_Faces* dnface = &(entry->dnfaces);
	
	while (dnface->next) {
		dnface = dnface->next;
		
		if (longlife_f) {
			if (dnface->faceid == faceid) {
				*rt_dnface = dnface;
				return (0);
			}
		} else {
			if ((dnface->faceid == faceid) && (dnface->nonce == nonce)) {
				*rt_dnface = dnface;
				return (0);
			}
		}
	}
	
	entry->dnfacenum++;
	dnface->next = (CefT_Down_Faces*) malloc (sizeof (CefT_Down_Faces));
	memset (dnface->next, 0, sizeof (CefT_Down_Faces));
	dnface->next->faceid = faceid;
	dnface->next->nonce  = nonce;
	*rt_dnface = dnface->next;
	//0.8.3
	dnface->next->IR_Type = 0;
	dnface->next->IR_len  = 0;
	dnface->next->IR_msg  = NULL;
	
#ifdef	__INTEREST__
	fprintf (stderr, "%s New DnFace id:%d\n", __func__, faceid );
#endif
	
	return (1);
}
/*--------------------------------------------------------------------------------------
	Removes the specified FaceID from the specified PIT entry
----------------------------------------------------------------------------------------*/
void
cef_pit_down_faceid_remove (
	CefT_Pit_Entry* entry, 					/* PIT entry 								*/
	uint16_t faceid 						/* Face-ID									*/
) {
	CefT_Down_Faces* dnface = &(entry->dnfaces);
	CefT_Down_Faces* prev = dnface;
	CefT_Down_Faces* clean_dnface;

	while (dnface->next) {
		dnface = dnface->next;

		if (dnface->faceid == faceid) {
			prev->next = dnface->next;
			clean_dnface = &(entry->clean_dnfaces);
			while (clean_dnface->next) {
				clean_dnface = clean_dnface->next;
			}
			clean_dnface->next = dnface;
			clean_dnface->next->next = NULL;
			dnface = prev;
			entry->dnfacenum--;

			break;
		}
		prev = dnface;
	}

	return;
}
/*--------------------------------------------------------------------------------------
	Looks up and creates a Up Face entry
----------------------------------------------------------------------------------------*/
static int 									/* Returns 1 if the return entry is new	 	*/
cef_pit_entry_up_face_lookup (
	CefT_Pit_Entry* entry, 					/* PIT entry 								*/
	uint16_t faceid, 						/* Face-ID									*/
	CefT_Up_Faces** rt_face					/* Up Face entry to return		 			*/
) {
	CefT_Up_Faces* face = &(entry->upfaces);

	while (face->next) {
		face = face->next;
		if (face->faceid == faceid) {
			*rt_face = face;
			return (0);
		}
	}
	face->next = (CefT_Up_Faces*) malloc (sizeof (CefT_Up_Faces));
	face->next->faceid = faceid;
	face->next->next = NULL;

	*rt_face = face->next;

	return (1);
}
/*--------------------------------------------------------------------------------------
	Cleanups PIT entry which expires the lifetime
----------------------------------------------------------------------------------------*/
static CefT_Pit_Entry*
cef_pit_cleanup (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_Pit_Entry* entry 					/* PIT entry 								*/
) {
	CefT_Down_Faces* dnface;
	CefT_Down_Faces* dnface_prv;
	int fd;
	uint64_t now;
	CefT_Down_Faces* clean_dnface;

	now = cef_client_present_timeus_get ();

	if (now < entry->clean_us) {
		return (entry);
	}
	entry->clean_us = now + 1000000;

	dnface = &(entry->dnfaces);
	dnface_prv = dnface;

	while (dnface->next) {
		dnface = dnface->next;
		fd = cef_face_get_fd_from_faceid (dnface->faceid);

		if ((now > dnface->lifetime_us) || (fd < 3)) {
			dnface_prv->next = dnface->next;
			clean_dnface = &(entry->clean_dnfaces);
			while (clean_dnface->next) {
				clean_dnface = clean_dnface->next;
			}
			clean_dnface->next = dnface;
			clean_dnface->next->next = NULL;
			dnface = dnface_prv;
			entry->dnfacenum--;
		} else {
			dnface_prv = dnface;
		}
	}

	return (entry);
}
#if 0
/*--------------------------------------------------------------------------------------
	Cleanups PIT entry which expires the lifetime
----------------------------------------------------------------------------------------*/
static CefT_Pit_Entry*
cefrt_pit_cleanup (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_Pit_Entry* entry 					/* PIT entry 								*/
) {
	CefT_Down_Faces* dnface;
	CefT_Down_Faces* dnface_prv;
	uint64_t now;
	struct timeval t;

	gettimeofday (&t, NULL);
	now = t.tv_sec * 1000000llu + t.tv_usec;

	if (now < entry->clean_us) {
		return (entry);
	}
	entry->clean_us = now + 1000000;

	dnface = &(entry->dnfaces);
	dnface_prv = dnface;

	while (dnface->next) {
		dnface = dnface->next;

		if (now > dnface->lifetime_us) {
			dnface_prv->next = dnface->next;
			free (dnface);
			dnface = dnface_prv;
			entry->dnfacenum--;
		} else {
			dnface_prv = dnface;
		}
	}
	if (entry->dnfacenum > 0) {
		return (entry);
	}

	cef_pit_entry_free (pit, entry);
	return (NULL);
}
#endif
#ifdef CefC_Dtc
/*--------------------------------------------------------------------------------------
	Create Cefore-DTC PIT List
----------------------------------------------------------------------------------------*/
int
cef_pit_dtc_init (
	void
) {
	if (dtc_pit) {
		free (dtc_pit);
		dtc_pit = NULL;
	}
	dtc_pit = (CefT_Dtc_Pit_List*)malloc (sizeof (CefT_Dtc_Pit_List));
	if (dtc_pit) {
		dtc_pit->top = NULL;
		dtc_pit->end = NULL;
		dtc_pit->work = NULL;
		return (0);
	}
	return (-1);
}
/*--------------------------------------------------------------------------------------
	Destroy Cefore-DTC PIT List
----------------------------------------------------------------------------------------*/
void
cef_pit_dtc_destroy (
	void
) {
	CefT_Dtc_Pit_Entry* entry;
	CefT_Dtc_Pit_Entry* next;
	if (!dtc_pit) {
		return;
	}
	entry = dtc_pit->top;
	while (entry) {
		next = entry->next;
		free (entry);
		entry = next;
	}
	free (dtc_pit);
	dtc_pit = NULL;
	return;
}
/*--------------------------------------------------------------------------------------
	Create Cefore-DTC PIT Entry
----------------------------------------------------------------------------------------*/
CefT_Dtc_Pit_Entry*
cef_pit_dtc_entry_create (
	unsigned char* msg,
	uint16_t msg_len
) {
	CefT_Dtc_Pit_Entry* entry;
	entry = (CefT_Dtc_Pit_Entry*)malloc (sizeof (CefT_Dtc_Pit_Entry));
	if (entry) {
		entry->prev = NULL;
		entry->next = NULL;
		entry->msg_len = msg_len;
		memcpy (entry->msg, msg, msg_len);
	} else {
		cef_log_write (CefC_Log_Warn, "Cannot allocate memory (DTC PIT entry)");
	}
	return (entry);
}
/*--------------------------------------------------------------------------------------
	Delete Cefore-DTC PIT Entry
----------------------------------------------------------------------------------------*/
int
cef_pit_dtc_entry_delete (
	CefT_Dtc_Pit_Entry** entry_p
) {
	CefT_Dtc_Pit_Entry* entry = *entry_p;
	/* Delete entry */
	if (dtc_pit->top == dtc_pit->end) {
		/* Entry is last one */
		dtc_pit->top = NULL;
		dtc_pit->end = NULL;
	} else if (dtc_pit->top == entry) {
		/* The entry is the top of the dtc_pit */
		dtc_pit->top = entry->next;
		dtc_pit->top->prev = NULL;
	} else if (dtc_pit->end == entry) {
		/* The entry is the end of the dtc_pit */
		dtc_pit->end = entry->prev;
		dtc_pit->end->next = NULL;
	} else {
		/* Other */
		entry->prev->next = entry->next;
		entry->next->prev = entry->prev;
	}
	/* Move working entry */
	if (dtc_pit->work == entry) {
		if (dtc_pit->work->next) {
			dtc_pit->work = dtc_pit->work->next;
		} else {
			dtc_pit->work = dtc_pit->top;
		}
	}
	free (entry);
	*entry_p = NULL;
	return (0);
}
/*--------------------------------------------------------------------------------------
	Insert Cefore-DTC PIT Entry
----------------------------------------------------------------------------------------*/
void
cef_pit_dtc_entry_insert (
	CefT_Dtc_Pit_Entry* entry
) {
	if (entry == NULL) {
		return;
	}
	if (dtc_pit->end) {
		/* DTC-PIT has some entry */
		entry->prev = dtc_pit->end;
		dtc_pit->end->next = entry;
		dtc_pit->end = entry;
	} else if (dtc_pit->top) {
		/* DTC-PIT has single entry */
		entry->prev = dtc_pit->top;
		dtc_pit->top->next = entry;
		dtc_pit->end = entry;
	} else {
		/* DTC-PIT has no entry */
		dtc_pit->top = entry;
		dtc_pit->end = entry;
		dtc_pit->work = entry;
	}
	return;
}
/*--------------------------------------------------------------------------------------
	Read Current Cefore-DTC PIT Entry
----------------------------------------------------------------------------------------*/
CefT_Dtc_Pit_Entry*
cef_pit_dtc_entry_read (
	void
) {
	if (dtc_pit->work == NULL) {
		/* DTC Entry is empty */
		return (NULL);
	}
	/* Move next */
	if (dtc_pit->work->next) {
		dtc_pit->work = dtc_pit->work->next;
	} else {
		/* The entry is the end of the dtc_pit */
		dtc_pit->work = dtc_pit->top;
	}
	return (dtc_pit->work);
}
#endif // CefC_Dtc

//0.8.3
/*--------------------------------------------------------------------------------------
	Symbolic PIT Check
----------------------------------------------------------------------------------------*/
int
cef_pit_symbolic_pit_check (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_Parsed_Message* pm, 				/* Parsed CEFORE message					*/
	CefT_Parsed_Opheader* poh				/* Parsed Option Header						*/
)	{
	CefT_Pit_Entry* entry;

#ifdef	__INTEREST__
	fprintf (stderr, "%s IN\n", __func__ );
#endif
	/* Searches a PIT entry 	*/
	entry = (CefT_Pit_Entry*) cef_hash_tbl_item_get (pit, pm->name, pm->name_len);
	
	if ( entry == NULL ) {
#ifdef	__INTEREST__
	fprintf (stderr, "%s Return(0) ( entry == NULL )\n", __func__ );
#endif
		return (0);
	}
	
	if ( entry->PitType == pm->InterestType ) {
#ifdef	__INTEREST__
	fprintf (stderr, "%s Return(0) ( entry->PitType == pm->InterestType )\n", __func__ );
#endif
		return (0);
	} else {
#ifdef	__INTEREST__
	fprintf (stderr, "%s Return(-0) ( entry->PitType != pm->InterestType )\n", __func__ );
#endif
		return (-1);
	}
}
/*--------------------------------------------------------------------------------------
	Searches a PIT entry matching the specified Name with chunk number
----------------------------------------------------------------------------------------*/
CefT_Pit_Entry* 							/* a PIT entry								*/
cef_pit_entry_search_with_chunk (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_Parsed_Message* pm, 				/* Parsed CEFORE message					*/
	CefT_Parsed_Opheader* poh				/* Parsed Option Header						*/
) {
	CefT_Pit_Entry* entry;
	uint64_t now;
	
#ifdef CefC_Debug
	{
		int dbg_x;
		
		sprintf (pit_dbg_msg, "[pit] Search the entry [");
		for (dbg_x = 0 ; dbg_x < pm->name_len ; dbg_x++) {
			sprintf (pit_dbg_msg, "%s %02X", pit_dbg_msg, pm->name[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", pit_dbg_msg);
	}
#endif // CefC_Debug
	
	/* Searches a PIT entry 	*/
	entry = (CefT_Pit_Entry*) cef_hash_tbl_item_get (pit, pm->name, pm->name_len);
	now = cef_client_present_timeus_get ();
	
	if (entry != NULL) {
		if (!entry->symbolic_f) {
			entry->stole_f = 1;
		}
#ifdef CefC_Debug
		{
			int dbg_x;
			
			sprintf (pit_dbg_msg, "[pit] Exact matched to the entry [");
			for (dbg_x = 0 ; dbg_x < entry->klen ; dbg_x++) {
				sprintf (pit_dbg_msg, "%s %02X", pit_dbg_msg, entry->key[dbg_x]);
			}
			cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", pit_dbg_msg);
		}
#endif // CefC_Debug
		if ((now > entry->adv_lifetime_us) && (poh->app_reg_f != CefC_App_DeRegPit)){	//20190822
			return (NULL);
		}
		return (entry);
	}
	
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, "[pit] Mismatched\n");
#endif // CefC_Debug
	
	return (NULL);
}
/*--------------------------------------------------------------------------------------
	Searches a PIT entry matching the specified Name without chunk number
----------------------------------------------------------------------------------------*/
CefT_Pit_Entry* 							/* a PIT entry								*/
cef_pit_entry_search_without_chunk (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_Parsed_Message* pm, 				/* Parsed CEFORE message					*/
	CefT_Parsed_Opheader* poh				/* Parsed Option Header						*/
) {
	CefT_Pit_Entry* entry;
	uint16_t tmp_name_len;
	uint64_t now;
	
	tmp_name_len = pm->name_len;

#ifdef CefC_Debug
	{
		int dbg_x;
		
		sprintf (pit_dbg_msg, "[pit] Search the entry [");
		for (dbg_x = 0 ; dbg_x < tmp_name_len ; dbg_x++) {
			sprintf (pit_dbg_msg, "%s %02X", pit_dbg_msg, pm->name[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", pit_dbg_msg);
	}
#endif // CefC_Debug
	
	now = cef_client_present_timeus_get ();
	if (pm->chnk_num_f) {
		uint16_t name_len_wo_chunk;
		name_len_wo_chunk = tmp_name_len - (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
		entry = (CefT_Pit_Entry*) cef_hash_tbl_item_get (pit, pm->name, name_len_wo_chunk);

		if (entry != NULL) {
			if (entry->symbolic_f) {
				entry = cef_pit_cleanup (pit, entry);
#ifdef CefC_Debug
				{
					int dbg_x;
					
					if (entry) {
						sprintf (pit_dbg_msg, "[pit] Partial matched to the entry [");
						for (dbg_x = 0 ; dbg_x < entry->klen ; dbg_x++) {
							sprintf (pit_dbg_msg, 
								"%s %02X", pit_dbg_msg, entry->key[dbg_x]);
						}
						cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", pit_dbg_msg);
					} else {
						cef_dbg_write (CefC_Dbg_Finest, "[pit] Mismatched\n");
					}
				}
#endif // CefC_Debug
				if (now > entry->adv_lifetime_us) {
					return (NULL);
				}
				return (entry);
			}
		}
	}
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, "[pit] Mismatched\n");
#endif // CefC_Debug
	
	return (NULL);
}

/*--------------------------------------------------------------------------------------
	Set InterestReturn Info to DownFace
----------------------------------------------------------------------------------------*/
int
cef_pit_interest_return_set (
	CefT_Pit_Entry* entry, 					/* PIT entry 								*/
	CefT_Parsed_Message* pm, 				/* Parsed CEFORE message					*/
	CefT_Parsed_Opheader* poh,				/* Parsed Option Header						*/
	uint16_t faceid, 						/* Face-ID									*/
	uint8_t				IR_Type,			/* InterestReturn Type 						*/
	unsigned int 		IR_len,				/* Length of IR_msg 						*/
	unsigned char* 		IR_msg				/* InterestReturn msg 						*/
) {

	CefT_Down_Faces* dnface = &(entry->dnfaces);
	while (dnface->next) {
		dnface = dnface->next;
		
		if (dnface->faceid == faceid) {
			break;
		}
	}
	if ( dnface != NULL ) {
		if ( dnface->IR_Type != 0 ) {
			if ( dnface->IR_Type == IR_Type ) {
				/* Same set input */
				free(dnface->IR_msg);
			} else {
				if ( dnface->IR_Type == IR_PRIORITY_TBL[2] ) {
					/* Low set input */
					free(dnface->IR_msg);
				} else if ( dnface->IR_Type == IR_PRIORITY_TBL[1] ) {
					/* Middle set input */
					free(dnface->IR_msg);
				} else {
					/* High not set */
					return(0);
				}
			}
		}
		dnface->IR_Type = IR_Type;
		dnface->IR_len  = IR_len;
		dnface->IR_msg  = (unsigned char*)malloc(sizeof(char)*IR_len);
		memcpy( dnface->IR_msg, IR_msg, IR_len );
		return(0);
	}

	return(-1);
}

/*
 * Copyright (c) 2016-2019, National Institute of Information and Communications
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
#define CefC_Maximum_Lifetime		8000	/* Maximum lifetime [ms] 					*/

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
	void
){
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
) {
	CefT_Pit_Entry* entry;
	uint16_t name_len = pm->name_len;

	if(cef_hash_tbl_item_num_get(pit) == cef_hash_tbl_def_max_get(pit)) {
		cef_log_write (CefC_Log_Warn, 
			"PIT table is full(PIT_SIZE = %d)\n", cef_hash_tbl_def_max_get(pit));
		return (NULL);
	}
	
	/* Searches a PIT entry 	*/
	entry = (CefT_Pit_Entry*) cef_hash_tbl_item_get (pit, pm->name, name_len);

	/* Creates a new PIT entry, if it dose not match 	*/
	if (entry == NULL) {
		entry = (CefT_Pit_Entry*) malloc (sizeof (CefT_Pit_Entry));
		memset (entry, 0, sizeof (CefT_Pit_Entry));
		entry->key = (unsigned char*) malloc (sizeof (char) * name_len);
		entry->klen = name_len;
		memcpy (entry->key, pm->name, name_len);
		entry->hashv = cef_hash_tbl_hashv_get (pit, entry->key, entry->klen);
		entry->clean_us = cef_client_present_timeus_get () + 1000000;
		cef_hash_tbl_item_set (pit, entry->key, entry->klen, entry);
		entry->tp_variant = poh->tp_variant;
		entry->nonce = 0;
		entry->adv_lifetime_us = 0;
		entry->drp_lifetime_us = 0;
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
) {
	CefT_Pit_Entry* entry;
	uint16_t name_len = pm->name_len;
	
	if (poh->symbolic_code_f) {
		memcpy (&pm->name[name_len], &poh->symbolic_code, sizeof (struct value32x2_tlv));
		name_len += sizeof (struct value32x2_tlv);
	}
#ifdef CefC_Debug
	{
		int dbg_x;
		
		sprintf (pit_dbg_msg, "[pit] Search the entry [");
		for (dbg_x = 0 ; dbg_x < name_len ; dbg_x++) {
			sprintf (pit_dbg_msg, "%s %02X", pit_dbg_msg, pm->name[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", pit_dbg_msg);
	}
#endif // CefC_Debug
	
	/* Searches a PIT entry 	*/
	entry = (CefT_Pit_Entry*) cef_hash_tbl_item_get (pit, pm->name, name_len);
	
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
		return (entry);
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
	unsigned char* msg 						/* cefore packet 							*/
) {
	CefT_Down_Faces* face;
	
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
	
	/* Checks flags 					*/
	if (new_downface_f) {
		face->nonce = pm->nonce;
	} else {
		if ((pm->nonce) && (pm->nonce == face->nonce)) {
			return (0);
		}
		face->nonce = pm->nonce;
	}
	
	if (pm->org.longlife_f) {
		face->symbolic_f = CefC_Pit_True;
		if (new_downface_f) {
			entry->symbolic_f++;
		}
	}
	if (poh->timeout > 0) {
		face->symbolic_f = CefC_Pit_True;
		poh->lifetime = poh->timeout * 1000;
	}
	
	/* Checks whether the life time is smaller than the limit 	*/
#ifndef CefC_Nwproc
	if (poh->lifetime > CefC_Maximum_Lifetime) {
		poh->lifetime = CefC_Maximum_Lifetime;
	}
#else // CefC_Nwproc
	if (!poh->nwproc_f){
		if (poh->lifetime > CefC_Maximum_Lifetime) {
			poh->lifetime = CefC_Maximum_Lifetime;
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
	
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, "[pit] Lifetime = "FMTU64"\n", extent_us / 1000);
#endif // CefC_Debug
	
	/* Checks the advertised lifetime to upstream 		*/
	if (face->lifetime_us > entry->drp_lifetime_us) {
		forward_interest_f = 1;
#ifndef CefC_Nwproc
		entry->drp_lifetime_us = face->lifetime_us + 1000000;
#else // CefC_Nwproc
		entry->drp_lifetime_us = face->lifetime_us + extent_us;
#endif // CefC_Nwproc
		entry->adv_lifetime_us = face->lifetime_us;
	} else {
		
		if (face->lifetime_us < prev_lifetime_us) {
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
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, 
		"[pit] forward (yes=1/no=0) = %d\n", forward_interest_f);
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
		free (dnface);
		dnface = dnface_next;
	}
	
	dnface = entry->clean_dnfaces.next;
	while (dnface) {
		dnface_next = dnface->next;
		free (dnface);
		dnface = dnface_next;
	}

#if CefC_Dtc
	if (entry->dtc_f) {
		cef_pit_dtc_entry_delete (&entry->dtc_entry);
	}
#endif // CefC_Dtc

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
	
	if (now > entry->adv_lifetime_us) {
		
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
		}
		entry->dnfaces.next = NULL;
		entry->dnfacenum = 0;
		
		return;
	}
	
	if (now < entry->clean_us) {
		return;
	}
	entry->clean_us = now + 1000000;
	
	dnface = &(entry->dnfaces);
	dnface_prv = dnface;
	
	while (dnface->next) {
		dnface = dnface->next;
		
		if (now > dnface->lifetime_us) {
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

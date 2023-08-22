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
 * cef_pit.c
 */

#define __CEF_PIT_SOURECE__

//#define	__PIT_DEBUG__
//#define		__RESTRICT__
//#define		__INTEREST__
//#define		__PIT_CLEAN__
//#define __T_VERSION__

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

#ifdef	CefC_PitEntryMutex
#include <pthread.h>
#endif	// CefC_PitEntryMutex

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
	Looks up and creates the version entry in specified Down Face entry
----------------------------------------------------------------------------------------*/
static int
cef_pit_entry_down_face_ver_lookup (
	CefT_Down_Faces* dnface,				/* Down Face entry							*/
	CefT_CcnMsg_MsgBdy* pm 					/* Parsed CEFORE message					*/
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
#define	CefC_WITHOUT_LOCK	0
#define	CefC_WITH_LOCK		(~CefC_WITHOUT_LOCK)
CefT_Pit_Entry* 							/* a PIT entry								*/
cef_pit_entry_lookup_with_lock (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh,				/* Parsed Option Header						*/
	unsigned char* name,					/* pit name (for ccninfo ccninfo-03)		*/
	int	name_len,							/* pit name length							*/
	int	with_lock							/* entry lock flag							*/
) {
	CefT_Pit_Entry* entry;
	int		f_new_entry = 0;

#ifdef	__PIT_DEBUG__
	fprintf (stderr, "[%s] IN\n",
			 "cef_pit_entry_lookup" );
#endif

	/* Searches a PIT entry 	*/
	entry = (CefT_Pit_Entry*) cef_lhash_tbl_item_get (pit, name, name_len);
#ifdef	__PIT_DEBUG__
	if (entry)
		fprintf (stderr, "\t entry=%p\n", (void*)entry);
	else
		fprintf (stderr, "\t entry=(NULL)\n");
#endif

	/* allocate a new PIT entry, if it dose not match 	*/
	if (entry == NULL) {
		size_t	alloc_size = (((sizeof (CefT_Pit_Entry) + name_len + 15) / 16) * 16);

		if(cef_lhash_tbl_item_num_get(pit) == cef_lhash_tbl_def_max_get(pit)) {
			cef_log_write (CefC_Log_Warn,
				"PIT table is full(PIT_SIZE = %d)\n", cef_lhash_tbl_def_max_get(pit));
			return (NULL);
		}

		entry = (CefT_Pit_Entry*) malloc (alloc_size);

#ifdef CefC_Debug_20230404
cef_dbg_write(CefC_Dbg_Fine, "malloc(CefT_Pit_Entry=%p)\n", entry);
#endif // CefC_Debug_20230404
		if ( entry == NULL ){
			cef_log_write (CefC_Log_Error, "%s(%u) malloc(%ld) failed, %s\n", __func__, __LINE__,
				alloc_size, strerror(errno));
			return (NULL);
		}
		memset (entry, 0, alloc_size);
		entry->key = (unsigned char*)entry + sizeof (CefT_Pit_Entry);

#ifdef	CefC_PitEntryMutex
		pthread_mutex_init (&entry->pe_mutex_pt, NULL);
#endif	// CefC_PitEntryMutex

		f_new_entry = 1;
	}

	/* lock a PIT entry */
	if (with_lock && !cef_pit_entry_lock (entry) ) {
		cef_log_write (CefC_Log_Warn, "%s(%u) cef_pit_entry_lock failed.\n", __func__, __LINE__);
		if (f_new_entry) {
#ifdef CefC_Debug_20230404
cef_dbg_write(CefC_Dbg_Fine, "free(CefT_Pit_Entry=%p)\n", entry);
#endif // CefC_Debug_20230404
			free(entry);
		}
		return (NULL);
	}

	/* Creates a new PIT entry, if it dose not match 	*/
	if (f_new_entry) {
		int res = cef_lhash_tbl_item_set (pit, name, name_len, entry);
		if (res) {
			cef_log_write (CefC_Log_Warn, "%s(%u) cef_lhash_tbl_item_set=%d\n", __func__, __LINE__, res);
		}

		entry->klen = name_len;
		memcpy (entry->key, name, name_len);
		entry->hashv = cef_lhash_tbl_hashv_get (pit, entry->key, entry->klen);
		entry->clean_us = cef_client_present_timeus_get () + CefC_Pit_CleaningTime;
		entry->tp_variant = poh->org.tp_variant;
		entry->nonce = 0;
		entry->adv_lifetime_us = 0;
		entry->drp_lifetime_us = 0;
		//0.8.3
		entry->hoplimit = 0;
		entry->PitType  = pm->InterestType;
		entry->Last_chunk_num = 0;
		entry->KIDR_len = pm->KeyIdRester_len;
		if ( entry->KIDR_len == 0 ) {
			entry->KIDR_selector = NULL;
		} else {
			entry->KIDR_selector = (unsigned char*)malloc( entry->KIDR_len );
			memcpy( entry->KIDR_selector, pm->KeyIdRester_val, entry->KIDR_len );
		}
		entry->COBHR_len = pm->ObjHash_len;
		if ( entry->COBHR_len == 0 ) {
			entry->COBHR_selector = NULL;
		} else {
			entry->COBHR_selector = (unsigned char*)malloc( entry->COBHR_len );
			memcpy( entry->COBHR_selector, pm->ObjHash_val, entry->COBHR_len );
		}
#ifdef __RESTRICT__
		printf( "%s entry->KIDR_len:%d   entry->COBHR_len:%d\n", __func__, entry->KIDR_len, entry->COBHR_len );
#endif
	}
#ifdef CefC_Debug
	{
		int dbg_x;
		int	len = 0;

		len = sprintf (pit_dbg_msg, "[pit] Lookup the entry [");
		for (dbg_x = 0 ; dbg_x < entry->klen ; dbg_x++) {
			len = len + sprintf (pit_dbg_msg + len, " %02X", entry->key[dbg_x]);
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
#endif // __PIT_DEBUG__

	return (entry);
}
CefT_Pit_Entry* 							/* a PIT entry								*/
cef_pit_entry_lookup (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh,				/* Parsed Option Header						*/
	unsigned char* ccninfo_pit,				/* pit name for ccninfo ccninfo-03			*/
	int	ccninfo_pit_len						/* ccninfo pit length						*/
) {
	CefT_Pit_Entry* entry = NULL;			/* PIT entry								*/

	if (pm->top_level_type == CefC_T_DISCOVERY && 0 < ccninfo_pit_len ) {  /* for CCNINFO */
		unsigned char* tmp_name = (unsigned char*)malloc( ccninfo_pit_len );

		/* KEY: Name + NodeIdentifier + RequestID */
		if ( tmp_name != NULL ){
			memcpy( tmp_name, ccninfo_pit, ccninfo_pit_len );
			// entry lookup without lock
			entry = cef_pit_entry_lookup_with_lock(pit, pm, poh, tmp_name, ccninfo_pit_len, CefC_WITHOUT_LOCK);
			free(tmp_name);
		}
	} else {
		// entry lookup without lock
		entry = cef_pit_entry_lookup_with_lock(pit, pm, poh, pm->name, pm->name_len, CefC_WITHOUT_LOCK);
	}

	return entry;
}

/*--------------------------------------------------------------------------------------
	Searches a PIT entry matching the specified Name
----------------------------------------------------------------------------------------*/
CefT_Pit_Entry* 							/* a PIT entry								*/
cef_pit_entry_search (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh,				/* Parsed Option Header						*/
	unsigned char* ccninfo_pit,			/* pit name for ccninfo ccninfo-03			*/
	int	ccninfo_pit_len						/* ccninfo pit length						*/
) {
	CefT_Pit_Entry* entry;
	unsigned char* tmp_name = NULL;
	uint16_t tmp_name_len;
	uint64_t now;
	int found_ver_f = 0;

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
		int len = 0;

		len = sprintf (pit_dbg_msg, "[pit] Search the entry [");
		for (dbg_x = 0 ; dbg_x < tmp_name_len ; dbg_x++) {
			len = len + sprintf (pit_dbg_msg + len, " %02X", tmp_name[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", pit_dbg_msg);
	}
#endif // CefC_Debug

	/* Searches a PIT entry 	*/
	entry = (CefT_Pit_Entry*) cef_lhash_tbl_item_get (pit, tmp_name, tmp_name_len);
	now = cef_client_present_timeus_get ();

	if (entry != NULL) {
//0.8.3c ----- START ----- version
		//move to pit_entry_down_face_ver_remove
//		if (!entry->longlife_f) {
//			entry->stole_f = 1;
//		}
//0.8.3c ----- END ----- version
		/* for ccninfo "full discovery" */
		if (poh->ccninfo_flag & CefC_CtOp_FullDisCover) {
			entry->stole_f = 0;
		}
#ifdef CefC_Debug
		{
			int dbg_x;
			int len = 0;

			len = sprintf (pit_dbg_msg, "[pit] Exact matched to the entry [");
			for (dbg_x = 0 ; dbg_x < entry->klen ; dbg_x++) {
				len = len + sprintf (pit_dbg_msg + len, " %02X", entry->key[dbg_x]);
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
		found_ver_f = cef_pit_entry_down_face_ver_search (&(entry->dnfaces), 1, pm);
		if (found_ver_f)
			return (entry);
		else
			return (NULL);
	}

	if (pm->chunk_num_f) {
		uint16_t name_len_wo_chunk;
		name_len_wo_chunk = tmp_name_len - (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
		entry = (CefT_Pit_Entry*) cef_lhash_tbl_item_get (pit, tmp_name, name_len_wo_chunk);

		if (entry != NULL) {
			if (entry->longlife_f) {
				entry = cef_pit_cleanup (pit, entry);
#ifdef CefC_Debug
				{
					int dbg_x;
					int len = 0;

					if (entry) {
						len = sprintf (pit_dbg_msg, "[pit] Partial matched to the entry [");
						for (dbg_x = 0 ; dbg_x < entry->klen ; dbg_x++) {
							len = len + sprintf (pit_dbg_msg + len, " %02X", entry->key[dbg_x]);
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
				found_ver_f = cef_pit_entry_down_face_ver_search (&(entry->dnfaces), 1, pm);
				if (found_ver_f)
					return (entry);
				else
					return (NULL);
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
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh,				/* Parsed Option Header						*/
	int match_type							/* 0:Exact, 1:Prefix						*/
) {
	CefT_Pit_Entry* entry;
	uint16_t name_len = sp_name_len;
	int found_ver_f = 0;

#ifdef CefC_Debug
	{
		int dbg_x;
		int len;

		len = sprintf (pit_dbg_msg, "[pit] Search the entry [");
		for (dbg_x = 0 ; dbg_x < name_len ; dbg_x++) {
			len = len + sprintf (pit_dbg_msg + len, " %02X", sp_name[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", pit_dbg_msg);
	}
#endif // CefC_Debug

	/* Searches a PIT entry 	*/
	entry = (CefT_Pit_Entry*) cef_lhash_tbl_item_get (pit, sp_name, name_len);

	if (entry != NULL) {
		if (match_type) {
			/* PrefixMatch */
			if (pm->chunk_num_f) {
				if (entry->longlife_f) {
					entry = cef_pit_cleanup (pit, entry);
				}
			}
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, "[pit] Partial matched to the entry\n");
#endif // CefC_Debug
			found_ver_f = cef_pit_entry_down_face_ver_search (&(entry->dnfaces), 1, pm);
			if (found_ver_f)
				return (entry);
			else
				return (NULL);
		} else {
			/* ExactMatch */
//0.8.3c ----- START -----
			//move to pit_entry_down_face_ver_remove
//			if (!entry->longlife_f) {
//				entry->stole_f = 1;
//			}
//0.8.3c ----- END -----
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, "[pit] Exact matched to the entry\n");
#endif // CefC_Debug
			found_ver_f = cef_pit_entry_down_face_ver_search (&(entry->dnfaces), 1, pm);
			if (found_ver_f)
				return (entry);
			else
				return (NULL);
		}
	}

	if (pm->chunk_num_f) {
		uint16_t name_len_wo_chunk;
		name_len_wo_chunk = name_len - (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
		entry = (CefT_Pit_Entry*) cef_lhash_tbl_item_get (pit, pm->name, name_len_wo_chunk);

		if (entry != NULL) {
			if (entry->longlife_f) {
				entry = cef_pit_cleanup (pit, entry);
#ifdef CefC_Debug
				{
					int dbg_x;
					int len = 0;

					if (entry) {
						len = sprintf (pit_dbg_msg, "[pit] Partial matched to the entry [");
						for (dbg_x = 0 ; dbg_x < entry->klen ; dbg_x++) {
							len = len + sprintf (pit_dbg_msg + len, " %02X", entry->key[dbg_x]);
						}
						cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", pit_dbg_msg);
					} else {
						cef_dbg_write (CefC_Dbg_Finest, "[pit] Mismatched\n");
					}
				}
#endif // CefC_Debug
				found_ver_f = cef_pit_entry_down_face_ver_search (&(entry->dnfaces), 1, pm);
				if (found_ver_f) {
					return (entry);
				} else {
					return (NULL);
				}
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
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh				/* Parsed Option Header						*/
) {
	CefT_Pit_Entry* entry;
	uint16_t name_len = sp_name_len;

	unsigned char* msp;
	unsigned char* mep;
	uint16_t length;

	/*----- Do not check the version with PIT (for App) -----*/

#ifdef CefC_Debug
	{
		int dbg_x;
		int len = 0;

		len = sprintf (pit_dbg_msg, "[pit] Search the entry [");
		for (dbg_x = 0 ; dbg_x < name_len ; dbg_x++) {
			len = len + sprintf (pit_dbg_msg + len, " %02X", sp_name[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", pit_dbg_msg);
	}
#endif // CefC_Debug

	/* Searches a PIT entry 	*/
	while (name_len > 0) {
		entry = (CefT_Pit_Entry*) cef_lhash_tbl_item_get (pit, sp_name, name_len);
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
	int pit_num, cnt;
	CefT_Pit_Entry* entry;
	int pit_max = cef_lhash_tbl_item_max_idx_get (pit);
	uint32_t elem_index, elem_num, index;

	pit_num = cef_lhash_tbl_item_num_get (pit);
	fprintf(stderr,"===== PIT (entry=%d) =====\n", pit_num);
	for (index = 0, cnt = 0; (cnt < pit_num && index < pit_max); index++) {
		entry = (CefT_Pit_Entry*)cef_lhash_tbl_elem_get (pit, &index, &elem_num);
		if (entry != NULL) {
			for (elem_index = 0; elem_index < elem_num; elem_index++) {
				entry = (CefT_Pit_Entry*)
						cef_lhash_tbl_item_get_from_index (pit, index, elem_index);
				if (entry->klen != -1) {
					fprintf(stderr,"    (%d)(%d) len=%d [", index, cnt, entry->klen);
					{
						int dbg_x;
						for (dbg_x = 0 ; dbg_x < entry->klen ; dbg_x++) {
							fprintf (stderr, "%02X ", entry->key[dbg_x]);
						}
						fprintf (stderr, "]\n");
					}
#ifdef __T_VERSION__
					{
						CefT_Down_Faces* dnfaces = NULL;
						CefT_Pit_Tversion* tver = NULL;
						fprintf(stderr, "        stole_f=%d\n", entry->stole_f);
						dnfaces = entry->dnfaces.next;
						fprintf(stderr, "        [dnface]\n");
						while (dnfaces != NULL) {
							fprintf(stderr,"        [%d] tver_none=%d, ", dnfaces->faceid, dnfaces->tver_none);
							tver = &(dnfaces->tver);
							while (tver->tvnext) {
								tver = tver->tvnext;
								if (tver->tver_len == 0) {
									fprintf(stderr, "VerReq, ");
								} else {
									fprintf(stderr, "%s(%d), ", tver->tver_value, tver->tver_len);
								}
							}
							dnfaces = dnfaces->next;
							fprintf(stderr, "\n");
						}
						fprintf(stderr, "\n");
					}
#endif //__VERSION__
					cnt++;
				} else {
					fprintf(stderr,"    (%d) len=-1 **************************************\n", index);
				}
			}
		}
	}
	return;
}
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
	int		 Resend_method					/* Resend method 0.8.3 						*/
) {
	CefT_Down_Faces* face = NULL;
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
	int new_ver_f = 0;

	gettimeofday (&now, NULL);
	nowt_us = now.tv_sec * 1000000llu + now.tv_usec;

	/* Looks up a Down Face entry 		*/
	new_downface_f = cef_pit_entry_down_face_lookup (
						entry, faceid, &face, 0, pm->org.longlife_f);
	if ( !face ){
		return (0);		// lookup failed
	}

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

	new_ver_f = cef_pit_entry_down_face_ver_lookup (face, pm);
	if (new_ver_f == -1) {
		cef_log_write (CefC_Log_Warn,
			"Versions in this Down Face is full(Up to %d)\n", CefC_PitEntryVersion_Max);
		return (0);
	}

	if (pm->org.longlife_f) {
		if (new_downface_f) {
			entry->longlife_f++;
		}
	}
#ifdef	__PIT_DEBUG__
	fprintf (stderr, "\t entry->longlife_f=%d\n",
			 entry->longlife_f );
#endif

	/* for ccninfo */
	if (pm->top_level_type == CefC_T_DISCOVERY) {
		if (poh->ccninfo_flag & CefC_CtOp_FullDisCover)
			poh->lifetime = ccninfo_reply_timeout * 1000;
		else
			poh->lifetime = CefC_Default_CcninfoReplyTimeout * 1000;

		poh->lifetime_f = 1;
	}

	/* Checks whether the life time is smaller than the limit 	*/
	if ( entry->PitType != CefC_PIT_TYPE_Rgl ) {	//0.8.3
		if (poh->lifetime > symbolic_max_lifetime) {
			poh->lifetime = symbolic_max_lifetime;
		}
	} else {
		if (poh->lifetime > regular_max_lifetime) {
			poh->lifetime = regular_max_lifetime;
		}
	}

	/* Updates Interest Lifetime of this PIT entry 		*/
	if (poh->lifetime_f) {
		extent_us = poh->lifetime * 1000;
	} else {
		extent_us = CefC_Default_LifetimeUs;
	}
	if (poh->app_reg_f == CefC_Dev_RegPit) {
		/* Use cache time instead of lifetime */
		extent_us = poh->cachetime;	/* poh->cachetime is usec */
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
	if (face->lifetime_us > entry->adv_lifetime_us) {
#ifdef	__PIT_DEBUG__
		fprintf (stderr, "\t (face->lifetime_us > entry->drp_lifetime_us)\n" );
#endif
		forward_interest_f = 1;
		entry->adv_lifetime_us = face->lifetime_us;
		entry->drp_lifetime_us = face->lifetime_us + CefC_Pit_CleaningTime;
	} else {
#ifdef	__PIT_DEBUG__
		fprintf (stderr, "\t !(face->lifetime_us > entry->drp_lifetime_us)\n" );
#endif
		if (pm->top_level_type == CefC_T_DISCOVERY) {
			return (forward_interest_f);
		}

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
				entry->drp_lifetime_us = max_lifetime_us + CefC_Pit_CleaningTime;
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

	/* Not Same Face */
	if (new_downface_f) {
			forward_interest_f = 1;
	}
	/* Same Face, Not Same Version */
	if (!new_downface_f && new_ver_f) {
			forward_interest_f = 1;
	}

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
	int		 *pit_res						/* Returns 1 if the return entry is new	 	*/
) {
	CefT_Pit_Entry* entry = NULL;			/* PIT entry								*/
	int	 forward_interest_f = 0;

	// entry lookup with lock
	if (pm->top_level_type == CefC_T_DISCOVERY
			&& 0 < ccninfo_pit_len ) {  /* for CCNINFO */

		unsigned char* tmp_name = NULL;
		uint16_t tmp_name_len = 0;

		/* KEY: Name + NodeIdentifier + RequestID */
		tmp_name_len = ccninfo_pit_len;
		tmp_name = (unsigned char*)malloc( sizeof(char) * tmp_name_len );
		if ( tmp_name != NULL ){
			memcpy( tmp_name, ccninfo_pit, tmp_name_len );
			// entry lookup with lock
			entry = cef_pit_entry_lookup_with_lock (pit, pm, poh, tmp_name, tmp_name_len, CefC_WITH_LOCK);
			free(tmp_name);
		}
	} else {
		// entry lookup with lock
		entry = cef_pit_entry_lookup_with_lock (pit, pm, poh, pm->name, pm->name_len, CefC_WITH_LOCK);
	}

	if (entry != NULL) {
		forward_interest_f = cef_pit_entry_down_face_update (entry, faceid, pm, poh, msg, Resend_method);
		cef_pit_entry_unlock (entry);
	}
	if (pit_res != NULL) {
		*pit_res = forward_interest_f;
	}
	return entry;
}

/*--------------------------------------------------------------------------------------
	Looks up and creates the specified Up Face entry
----------------------------------------------------------------------------------------*/
int 										/* Returns 1 if the return entry is new	 	*/
cef_pit_entry_up_face_update (
	CefT_Pit_Entry* entry, 					/* PIT entry								*/
	uint16_t faceid,						/* Face-ID									*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh				/* Parsed Option Header						*/
) {
	CefT_Up_Faces* face;
	int new_create_f;
	/* Looks up an Up Face entry 		*/
	new_create_f = cef_pit_entry_up_face_lookup (entry, faceid, &face);

	/* If this entry has Symbolic Interest, always it forwards the Interest */
	if (entry->longlife_f) {
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
	CefT_Pit_Entry* rm_entry;

#ifdef	__PIT_CLEAN__
	fprintf( stderr, "[%s] IN entry->dnfacenum:%d\n", __func__, entry->dnfacenum );
#endif

	rm_entry = (CefT_Pit_Entry*) cef_lhash_tbl_item_remove (pit, entry->key, entry->klen);
	if ( rm_entry != entry ){
		cef_log_write (CefC_Log_Warn, "%s(%u) cef_lhash_tbl_item_remove() failed, entry=%p, rm_entry=%p.\n",
			__func__, __LINE__, entry, rm_entry);
	}

	// =========== free up faces ==============
{	CefT_Up_Faces* upface = entry->upfaces.next;
	while (upface) {
		CefT_Up_Faces* upface_next = upface->next;
#ifdef CefC_Debug_20230404
cef_dbg_write (CefC_Dbg_Fine, "free(upface=%p)\n", upface);
#endif // CefC_Debug_20230404
		free (upface);
		upface = upface_next;
	}
}

	// =========== free down faces ==============
{	CefT_Down_Faces* dnface = entry->dnfaces.next;
	while (dnface) {
		CefT_Down_Faces* dnface_next = dnface->next;
		if ( dnface->IR_len > 0 ) {
#ifdef	__PIT_CLEAN__
	fprintf( stderr, "\t dnface->IR_len:%d Type:%d\n", dnface->IR_len, dnface->IR_Type );
#endif
			free( dnface->IR_msg );
		}
#ifdef CefC_Debug_20230404
cef_dbg_write (CefC_Dbg_Fine, "free(dnface=%p)\n", dnface);
#endif // CefC_Debug_20230404
		free (dnface);
		dnface = dnface_next;
	}

	// =========== free cleand down faces ==============
	dnface = entry->clean_dnfaces.next;
	while (dnface) {
		CefT_Down_Faces* dnface_next = dnface->next;
		if ( dnface->IR_len > 0 ) {
#ifdef	__PIT_CLEAN__
	fprintf( stderr, "\t clean dnface->IR_len:%d Type:%d\n", dnface->IR_len, dnface->IR_Type );
#endif
			free( dnface->IR_msg );
		}
#ifdef CefC_Debug_20230404
cef_dbg_write (CefC_Dbg_Fine, "free(dnface=%p)\n", dnface);
#endif // CefC_Debug_20230404
		free (dnface);
		dnface = dnface_next;
	}
}

	//0.8.3
	if ( entry->KIDR_len > 0 ) {
		free( entry->KIDR_selector );
	}
	if ( entry->COBHR_len > 0 ) {
		free( entry->COBHR_selector );
	}
#ifdef	CefC_PitEntryMutex
	pthread_mutex_destroy (&entry->pe_mutex_pt);
#endif	// CefC_PitEntryMutex

#ifdef CefC_Debug_20230404
cef_dbg_write (CefC_Dbg_Fine, "free(entry=%p)\n", entry);
#endif // CefC_Debug_20230404
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
	CefT_Down_Faces* clean_dnface;
	uint64_t now;

	now = cef_client_present_timeus_get ();

#ifdef	__PIT_CLEAN__
	fprintf( stderr, "[%s] IN entry->dnfacenum:%d\n", __func__, entry->dnfacenum );
#endif
	if (now > entry->adv_lifetime_us) {
		clean_dnface = &(entry->clean_dnfaces);
		while (clean_dnface->next) {
			clean_dnface = clean_dnface->next;
		}

		dnface = &(entry->dnfaces);

		while (dnface->next) {
			dnface = dnface->next;
#ifdef CefC_Debug_20230404
cef_dbg_write (CefC_Dbg_Fine, "dnface=%p, next=%p\n", dnface, dnface->next);
#endif // CefC_Debug_20230404
			clean_dnface->next = dnface;
			clean_dnface = dnface;
//			clean_dnface->next = NULL;	// CefC_Debug_20230404

			if (cef_face_check_active (dnface->faceid) > 0 && dnface->IR_msg) {
				cef_face_frame_send_forced (dnface->faceid, dnface->IR_msg, dnface->IR_len);
			}
		}
		entry->dnfaces.next = NULL;
		entry->dnfacenum = 0;

		return;
	}

	if (now < entry->clean_us) {
#ifdef	__PIT_CLEAN__
	fprintf( stderr, "\t(now < entry->clean_us) RETURN\n" );
#endif
		return;
	}
	entry->clean_us = now + CefC_Pit_CleaningTime;

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
#ifdef CefC_Debug_20230404
cef_dbg_write (CefC_Dbg_Fine, "clean_dnface=%p, next=%p\n", clean_dnface, clean_dnface->next);
#endif // CefC_Debug_20230404
			clean_dnface->next->next = NULL;
			dnface = dnface_prv;
			entry->dnfacenum--;

			if (cef_face_check_active (dnface->faceid) > 0 && dnface->IR_msg) {
#ifdef	__PIT_CLEAN__
	fprintf( stderr, "\t Send IR\n" );
#endif
				cef_face_frame_send_forced (dnface->faceid, dnface->IR_msg, dnface->IR_len);
			}
		} else {
			dnface_prv = dnface;
		}
#ifdef CefC_Debug_20230404
cef_dbg_write (CefC_Dbg_Fine, "dnface_prv=%p, next=%p\n", dnface_prv, dnface_prv->next);
#endif // CefC_Debug_20230404
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

	*rt_dnface = NULL;
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

	dnface->next = (CefT_Down_Faces*) malloc (sizeof (CefT_Down_Faces));
	if (dnface->next == NULL) {
		cef_log_write (CefC_Log_Error, "%s(%u) malloc(%ld) failed\n", __func__, __LINE__, sizeof (CefT_Down_Faces));
		return (0);
	}
	memset (dnface->next, 0, sizeof (CefT_Down_Faces));
	dnface->next->faceid = faceid;
	dnface->next->nonce  = nonce;
	*rt_dnface = dnface->next;
	entry->dnfacenum++;
#ifdef CefC_Debug_20230404
cef_dbg_write (CefC_Dbg_Fine, "malloc(dnface->next=%p), dnface=%p\n", dnface->next, dnface);
#endif // CefC_Debug_20230404
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
	Looks up and creates the version entry in specified Down Face entry
----------------------------------------------------------------------------------------*/
static int									/* create entry = 1, lookup entry = 0		*/
cef_pit_entry_down_face_ver_lookup (
	CefT_Down_Faces* dnface,				/* Down Face entry							*/
	CefT_CcnMsg_MsgBdy* pm 				/* Parsed CEFORE message					*/
) {
	CefT_Pit_Tversion*	tver = &(dnface->tver);
	int tver_num = 0;

	/* Unversioned */
	if (!pm->org.version_f) {
		if (dnface->tver_none) {
			return (0);
		} else {
			dnface->tver_none = 1;
			return (1);
		}
	}

	/* Versioned */
	while (tver->tvnext) {
		tver = tver->tvnext;
		if (pm->org.version_len == tver->tver_len &&
			memcmp (pm->org.version_val, tver->tver_value, tver->tver_len) == 0) {
			return (0);
		}
		tver_num++;
	}

	if (tver_num >= CefC_PitEntryVersion_Max ) {
		return (-1);
	}

	/* create new entry */
	tver->tvnext = (CefT_Pit_Tversion*) malloc (sizeof (CefT_Pit_Tversion) + pm->org.version_len + 1);
	memset (tver->tvnext, 0, sizeof (CefT_Pit_Tversion));
	if (pm->org.version_len) {
		tver->tvnext->tver_len = pm->org.version_len;
		tver->tvnext->tver_value = ((unsigned char*) tver->tvnext) + sizeof(CefT_Pit_Tversion);
		memcpy (tver->tvnext->tver_value, pm->org.version_val, tver->tvnext->tver_len);
		tver->tvnext->tver_value[tver->tvnext->tver_len] = 0x00;
	} else {
		tver->tvnext->tver_len = 0;
		tver->tvnext->tver_value = NULL;
	}

	return (1);
}
/*--------------------------------------------------------------------------------------
	Search the version entry in specified Down Face entry
----------------------------------------------------------------------------------------*/
int											/* found entry = 1							*/
cef_pit_entry_down_face_ver_search (
	CefT_Down_Faces* dnface,				/* Down Face entry							*/
	int head_or_point_f,					/* 1: dnface is head of down face list		*/
											/* 0: dnface is pointer of 1 entry			*/
	CefT_CcnMsg_MsgBdy* pm 				/* Parsed CEFORE message					*/
) {
	CefT_Pit_Tversion* tver;

	if (head_or_point_f) {
		while (dnface->next) {
			dnface = dnface->next;

			if (!pm->org.version_f) {
				/* Unversioned */
				if (dnface->tver_none) {
					return (1);
				}
			} else {
				/* Versioned */

				if (dnface->tver_none) {
					return (1);
				}

				tver = &(dnface->tver);

				while (tver->tvnext) {
					tver = tver->tvnext;

					if (pm->org.version_len == tver->tver_len &&
						memcmp (pm->org.version_val, tver->tver_value, tver->tver_len) == 0) {
						return (1);
					}
				}
			}
		}
	} else {
		tver = &(dnface->tver);

		/* Unversioned */
		if (!pm->org.version_f) {
			if (dnface->tver_none) {
				return (1);
			} else {
				return (0);
			}
		} else {
			/* Versioned */
			if (dnface->tver_none) {
				return (1);
			}
		}

		/* Versioned */
		while (tver->tvnext) {
			tver = tver->tvnext;
			if (pm->org.version_len == tver->tver_len &&
				memcmp (pm->org.version_val, tver->tver_value, tver->tver_len) == 0) {
				return (1);
			}
		}
	}

	return (0);
}
/*--------------------------------------------------------------------------------------
	Remove the version entry in specified Down Face entry
----------------------------------------------------------------------------------------*/
void
cef_pit_entry_down_face_ver_remove (
	CefT_Pit_Entry* pe, 					/* PIT entry								*/
	CefT_Down_Faces* dnface,				/* Down Face entry							*/
	CefT_CcnMsg_MsgBdy* pm 				/* Parsed CEFORE message					*/
) {
	CefT_Pit_Tversion*	tver = &(dnface->tver);
	CefT_Pit_Tversion*	prev_tv;

	if (pe->longlife_f)
		return;

	if (dnface->tver_none) {
		dnface->tver_none = 0;
	}

	/* Versioned */
	prev_tv = tver;
	while (tver->tvnext) {
		tver = tver->tvnext;
		if (pm->org.version_len == tver->tver_len &&
			memcmp (pm->org.version_val, tver->tver_value, tver->tver_len) == 0) {

			prev_tv->tvnext = tver->tvnext;

			free (tver);
			break;
		}
		prev_tv = tver;
	}

	tver = &(dnface->tver);
	if (dnface->tver_none == 0 && tver->tvnext == NULL) {
		cef_pit_down_faceid_remove (pe, dnface->faceid);
	}
	if (pe->dnfacenum == 0) {
		pe->stole_f = 1;
	}
	return;
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
	Searches a Up Face entry
----------------------------------------------------------------------------------------*/
CefT_Up_Faces*								/* Returns  Up Face info				 	*/
cef_pit_entry_up_face_search (
	CefT_Pit_Entry* entry, 					/* PIT entry 								*/
	uint16_t faceid 						/* Face-ID									*/
) {
	CefT_Up_Faces* face = &(entry->upfaces);
	CefT_Up_Faces* ret = NULL;

	while (face->next) {
		face = face->next;
		if (face->faceid == faceid) {
			ret = face;
			break;
		}
	}

	return (ret);
}
/*--------------------------------------------------------------------------------------
	Cleanups PIT entry which expires the lifetime
----------------------------------------------------------------------------------------*/
static CefT_Pit_Entry*
cef_pit_cleanup (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_Pit_Entry* entry 					/* PIT entry 								*/
) {
	uint64_t now;

	now = cef_client_present_timeus_get ();

	if (now < entry->clean_us) {
		return (entry);
	}

	if ( cef_pit_entry_lock (entry) ){
		CefT_Down_Faces* dnface = &(entry->dnfaces);
		CefT_Down_Faces* dnface_prv = dnface;

		now = cef_client_present_timeus_get ();
		entry->clean_us = now + CefC_Pit_CleaningTime;

		while (dnface->next) {
			int fd;

			dnface = dnface->next;
			fd = cef_face_get_fd_from_faceid (dnface->faceid);

			if ((now > dnface->lifetime_us) || (fd < 3)) {
				CefT_Down_Faces* clean_dnface;

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
		cef_pit_entry_unlock(entry);
	}

	return (entry);
}

//0.8.3
/*--------------------------------------------------------------------------------------
	Symbolic PIT Check
----------------------------------------------------------------------------------------*/
int
cef_pit_symbolic_pit_check (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh				/* Parsed Option Header						*/
)	{
	CefT_Pit_Entry* entry;

#ifdef	__INTEREST__
	fprintf (stderr, "%s IN\n", __func__ );
#endif
	/* Searches a PIT entry 	*/
	entry = (CefT_Pit_Entry*) cef_lhash_tbl_item_get (pit, pm->name, pm->name_len);

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
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh				/* Parsed Option Header						*/
) {
	CefT_Pit_Entry* entry;
	uint64_t now;
	int found_ver_f = 0;

#ifdef CefC_Debug
	{
		int dbg_x;
		int len = 0;

		len = sprintf (pit_dbg_msg, "[pit] Search the entry [");
		for (dbg_x = 0 ; dbg_x < pm->name_len ; dbg_x++) {
			len = len + sprintf (pit_dbg_msg + len, " %02X", pm->name[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", pit_dbg_msg);
	}
#endif // CefC_Debug

	/* Searches a PIT entry 	*/
	entry = (CefT_Pit_Entry*) cef_lhash_tbl_item_get (pit, pm->name, pm->name_len);
	now = cef_client_present_timeus_get ();

	if (entry != NULL) {
		found_ver_f = cef_pit_entry_down_face_ver_search (&(entry->dnfaces), 1, pm);
//0.8.3c ----- START ----- version
		//move to pit_entry_down_face_ver_remove
//		if (!entry->longlife_f) {
//			entry->stole_f = 1;
//		}
//0.8.3c ----- END ----- version
#ifdef CefC_Debug
		{
			int dbg_x;
			int len = 0;

			len = sprintf (pit_dbg_msg, "[pit] Exact matched to the entry [");
			for (dbg_x = 0 ; dbg_x < entry->klen ; dbg_x++) {
				len = len + sprintf (pit_dbg_msg + len, " %02X", entry->key[dbg_x]);
			}
			cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", pit_dbg_msg);
		}
#endif // CefC_Debug
		if ((now > entry->adv_lifetime_us) && (poh->app_reg_f != CefC_App_DeRegPit)){	//20190822
			return (NULL);
		}
		if (found_ver_f) {
			return (entry);
		} else {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "[pit] ... Unmatched Version.\n");
#endif // CefC_Debug
			return (NULL);
		}
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
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh				/* Parsed Option Header						*/
) {
	CefT_Pit_Entry* entry;
	uint16_t tmp_name_len;
	uint64_t now;
	int found_ver_f = 0;

	tmp_name_len = pm->name_len;

#ifdef CefC_Debug
	{
		int dbg_x;
		int len = 0;

		len = sprintf (pit_dbg_msg, "[pit] Search the entry [");
		for (dbg_x = 0 ; dbg_x < tmp_name_len ; dbg_x++) {
			len = len + sprintf (pit_dbg_msg + len, " %02X", pm->name[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", pit_dbg_msg);
	}
#endif // CefC_Debug

	now = cef_client_present_timeus_get ();
	if (pm->chunk_num_f) {
		uint16_t name_len_wo_chunk;
		name_len_wo_chunk = tmp_name_len - (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
		entry = (CefT_Pit_Entry*) cef_lhash_tbl_item_get (pit, pm->name, name_len_wo_chunk);

		if (entry != NULL) {
			if (entry->longlife_f) {
				entry = cef_pit_cleanup (pit, entry);
#ifdef CefC_Debug
				{
					int dbg_x;
					int len = 0;

					if (entry) {
						len = sprintf (pit_dbg_msg, "[pit] Partial matched to the entry [");
						for (dbg_x = 0 ; dbg_x < entry->klen ; dbg_x++) {
							len = len + sprintf (pit_dbg_msg + len, " %02X", entry->key[dbg_x]);
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
				found_ver_f = cef_pit_entry_down_face_ver_search (&(entry->dnfaces), 1, pm);
				if (found_ver_f) {
#ifdef CefC_Debug
					cef_dbg_write (CefC_Dbg_Finest, "[pit] ... Matched Version\n");
#endif // CefC_Debug
					return (entry);
				} else {
#ifdef CefC_Debug
					cef_dbg_write (CefC_Dbg_Finest, "[pit] ... Unmatched Version\n");
#endif // CefC_Debug
					return (NULL);
				}
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
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh,				/* Parsed Option Header						*/
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
/*--------------------------------------------------------------------------------------
	Lock/Unlock the specified PIT entry
----------------------------------------------------------------------------------------*/
int
cef_pit_entry_lock (
	CefT_Pit_Entry* entry 					/* PIT entry 								*/
) {
	int	ret = -1;
#ifdef	CefC_PitEntryMutex
	{	int res;
		while ((res = pthread_mutex_trylock (&entry->pe_mutex_pt)) != 0) {
			if (EBUSY != res) {
				cef_log_write (CefC_Log_Warn, "%s(%u) pthread_mutex_trylock=%d:%s\n", __func__, __LINE__, res, strerror(errno));
				ret = 0;	// failed
				break;
			}
		}
	}
#endif	// CefC_PitEntryMutex
	return ret;
}
void
cef_pit_entry_unlock (
	CefT_Pit_Entry* entry 					/* PIT entry 								*/
) {
#ifdef	CefC_PitEntryMutex
	pthread_mutex_unlock (&entry->pe_mutex_pt);
#endif	// CefC_PitEntryMutex
	return;
}


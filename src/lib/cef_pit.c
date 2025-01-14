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
#include <pthread.h>

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
static uint32_t ccninfo_reply_timeout = CefC_Default_CcninfoReplyTimeout;
//0.8.3
static uint32_t symbolic_max_lifetime;
static uint32_t regular_max_lifetime;

#define	CefC_IR_SUPPORT_NUM			3
uint8_t	IR_PRIORITY_TBL[CefC_IR_SUPPORT_NUM] = {
	CefC_IR_HOPLIMIT_EXCEEDED,
	CefC_IR_NO_ROUTE,
	CefC_IR_CONGESTION
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
#define	CefC_PitEntry_NoLock	0
#define	CefC_PitEntry_Lock		(~CefC_PitEntry_NoLock)

inline int
cef_pit_set_typelen(unsigned char *buff, int tlv_type, int tlv_len)
{
	int	ix = 0;

	buff[ix++] = ((tlv_type >> 8) & 0xff);
	buff[ix++] = (tlv_type & 0xff);
	buff[ix++] = ((tlv_len >> 8) & 0xff);
	buff[ix++] = (tlv_len & 0xff);

	return ( ix );
}

static unsigned char *						/* address of search key buffer				*/
make_searchkey_interest (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_CcnMsg_MsgBdy *pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr *poh,				/* Parsed Option Header						*/
	unsigned char *name,					/* pit name (for ccninfo ccninfo-03)		*/
	int	name_len,							/* pit name length							*/
	unsigned char *key_buff,
	int	*ret_key_len
) {
	unsigned char *key_ptr = name;
	int		key_len = name_len;

	if ( CefC_NAME_MAXLEN < name_len ){
		*ret_key_len = -1;
		return (NULL);
	}

#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "[pit] KeyIdRester_f=%d, KeyIdRester_len=%d, ObjHash_f=%d, ObjHash_len=%d,\n",
	pm->KeyIdRester_f, pm->KeyIdRester_len, pm->ObjHash_f, pm->ObjHash_len);
#endif // CefC_Debug

	/* PIT search key extended by KeyIdRester */
	if ( pm->KeyIdRester_f && 0 < pm->KeyIdRester_len
			&& ((key_len + pm->KeyIdRester_len) < CefC_NAME_BUFSIZ) ){

		key_len = 0;
		key_len += cef_pit_set_typelen(key_buff, CefC_T_PIT_KEYID, pm->KeyIdRester_len);
		memcpy(&key_buff[key_len], pm->KeyIdRester_val, pm->KeyIdRester_len);
		key_len += pm->KeyIdRester_len;

		/* KeyIdRester and ObjectHashRester */
		if ( pm->ObjHash_f && 0 < pm->ObjHash_len
				&& ((key_len + pm->ObjHash_len) < CefC_NAME_BUFSIZ) ){

			key_len += cef_pit_set_typelen(key_buff, CefC_T_PIT_COBHASH, pm->ObjHash_len);
			memcpy(&key_buff[key_len], pm->ObjHash_val, pm->ObjHash_len);
			key_len += pm->ObjHash_len;
		}
		memcpy(&key_buff[key_len], name, name_len);
		key_len += name_len;
		key_ptr = key_buff;

	/* PIT search key extended by ObjectHashRester */
	} else if ( pm->ObjHash_f && 0 < pm->ObjHash_len
			&& ((key_len + pm->ObjHash_len) < CefC_NAME_BUFSIZ) ){

		key_len = 0;
		key_len += cef_pit_set_typelen(key_buff, CefC_T_PIT_COBHASH, pm->ObjHash_len);
		memcpy(&key_buff[key_len], pm->ObjHash_val, pm->ObjHash_len);
		key_len += pm->ObjHash_len;
		memcpy(&key_buff[key_len], name, name_len);
		key_len += name_len;
		key_ptr = key_buff;
	}

	/***************************************************************
	 * If neither KeyIdRester nor ObjectHashRester is present,
	 * the original name address is returned without duplication.
	 ***************************************************************/

	*ret_key_len = key_len;
	return key_ptr;
}

static unsigned char *						/* address of search key buffer				*/
make_searchkey_object (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_CcnMsg_MsgBdy *pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr *poh,				/* Parsed Option Header						*/
	unsigned char *name,					/* pit name (for ccninfo ccninfo-03)		*/
	int	name_len,							/* pit name length							*/
	unsigned char *key_buff,
	int	*ret_key_len
) {
	unsigned char *key_ptr = name;
	int		key_len = name_len;

	if ( CefC_NAME_MAXLEN < name_len ){
		*ret_key_len = -1;
		return (NULL);
	}

#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "[pit] alg.valid_type=%d, alg.keyid_len=%d, alg.publickey_len=%d,\n",
	pm->alg.valid_type, pm->alg.keyid_len, pm->alg.publickey_len);
#endif // CefC_Debug

	/* PIT search key extended by KeyIdRester */
	if ( pm->alg.valid_type && 0 < pm->alg.keyid_len
			&& ((key_len + pm->alg.keyid_len) < CefC_NAME_BUFSIZ) ){

		key_len = 0;
		key_len += cef_pit_set_typelen(key_buff, CefC_T_PIT_KEYID, pm->alg.keyid_len);
		memcpy(&key_buff[key_len], pm->alg.keyid, pm->alg.keyid_len);
		key_len += pm->alg.keyid_len;

		memcpy(&key_buff[key_len], name, name_len);
		key_len += name_len;
		key_ptr = key_buff;

	}

	/***************************************************************
	 * If neither KeyIdRester nor ObjectHashRester is present,
	 * the original name address is returned without duplication.
	 ***************************************************************/

	*ret_key_len = key_len;
	return key_ptr;
}

static unsigned char *						/* address of search key buffer				*/
make_searchkey (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_CcnMsg_MsgBdy *pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr *poh,				/* Parsed Option Header						*/
	unsigned char *name,					/* pit name (for ccninfo ccninfo-03)		*/
	int	name_len,							/* pit name length							*/
	unsigned char *key_buff,
	int	*ret_key_len
) {
	unsigned char *key_ptr = NULL;

	switch ( pm->top_level_type ){
	case CefC_T_OBJECT:			/* for T_OBJECT */
		key_ptr = make_searchkey_object(pit, pm, poh, name, name_len, key_buff, ret_key_len);
		break;
	case CefC_T_INTEREST:		/* for T_INTEREST */
	default:
		key_ptr = make_searchkey_interest(pit, pm, poh, name, name_len, key_buff, ret_key_len);
		break;
	}

	return key_ptr;
}

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
	unsigned char key_buff[CefC_NAME_BUFSIZ], *key_ptr;
	int		key_len = 0;

	/* PIT search key extended with KeyIdRester/ObjectHashRester */
	key_ptr = make_searchkey(pit, pm, poh, name, name_len, key_buff, &key_len);

	if ( !key_ptr || key_len < 1 ){
		return (NULL);
	}

	/***********************************************************************
	 * If neither KeyIdRester nor ObjectHashRester is present,
	 * key_ptr points to the address of the original name, not the key_buff
	 ***********************************************************************/

	/* Searches a PIT entry 	*/
	entry = (CefT_Pit_Entry*) cef_lhash_tbl_item_get (pit, key_ptr, key_len);

	/* allocate a new PIT entry, if it dose not match 	*/
	if (entry == NULL) {
		size_t	alloc_size = (((sizeof (CefT_Pit_Entry) + key_len + 15) / 16) * 16);

		if(cef_lhash_tbl_item_num_get(pit) == cef_lhash_tbl_def_max_get(pit)) {
			cef_log_write (CefC_Log_Error,
				"PIT table is full(PIT_SIZE = %d)\n", cef_lhash_tbl_def_max_get(pit));
			return (NULL);
		}

		entry = (CefT_Pit_Entry*) malloc (alloc_size);
		if ( entry == NULL ){
			cef_log_write (CefC_Log_Error, "%s(%u) malloc(%ld) failed, %s\n", __func__, __LINE__,
				alloc_size, strerror(errno));
			return (NULL);
		}
		memset (entry, 0, alloc_size);
		entry->key = (unsigned char*)entry + sizeof (CefT_Pit_Entry);

		pthread_mutex_init (&entry->pe_mutex_pt, NULL);

		f_new_entry = 1;
	}

	/* lock a PIT entry */
	if (with_lock && !cef_pit_entry_lock (entry)) {
		cef_log_write (CefC_Log_Error, "%s(%u) cef_pit_entry_lock failed.\n", __func__, __LINE__);
		if (f_new_entry) {
			free(entry);
		}
		return (NULL);
	}

	/* Creates a new PIT entry, if it dose not match 	*/
	if (f_new_entry) {
		int res = cef_lhash_tbl_item_set (pit, key_ptr, key_len, entry);
		if (res) {
			cef_log_write (CefC_Log_Warn, "%s(%u) cef_lhash_tbl_item_set=%d\n", __func__, __LINE__, res);
		}

		entry->klen = key_len;
		memcpy (entry->key, key_ptr, key_len);
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
		if ( 0 < entry->KIDR_len ) {
			entry->KIDR_selector = (unsigned char*)malloc( entry->KIDR_len );
			memcpy( entry->KIDR_selector, pm->KeyIdRester_val, entry->KIDR_len );
		} else {
			entry->KIDR_selector = NULL;
		}
		entry->COBHR_len = pm->ObjHash_len;
		if ( 0 < entry->COBHR_len ) {
			entry->COBHR_selector = (unsigned char*)malloc( entry->COBHR_len );
			memcpy( entry->COBHR_selector, pm->ObjHash_val, entry->COBHR_len );
		} else {
			entry->COBHR_selector = NULL;
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
			entry = cef_pit_entry_lookup_with_lock(pit, pm, poh, tmp_name, ccninfo_pit_len, CefC_PitEntry_NoLock);
			free(tmp_name);
		}
	} else {
		// entry lookup without lock
		entry = cef_pit_entry_lookup_with_lock(pit, pm, poh, pm->name, pm->name_len, CefC_PitEntry_NoLock);
	}

	return entry;
}

/*--------------------------------------------------------------------------------------
	Searches a PIT entry matching the specified Name
----------------------------------------------------------------------------------------*/
static
CefT_Pit_Entry* 							/* a PIT entry								*/
cef_pit_entry_search_core (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh,				/* Parsed Option Header						*/
	unsigned char* name,					/* pit name									*/
	int	name_len							/* pit name length							*/
) {
	CefT_Pit_Entry* entry;
	uint64_t now;
	int found_ver_f = 0;
	unsigned char key_buff[CefC_NAME_BUFSIZ], *key_ptr;
	int		key_len = 0;

	/* PIT search key extended with KeyIdRester/ObjectHashRester */
	key_ptr = make_searchkey(pit, pm, poh, name, name_len, key_buff, &key_len);

	if ( !key_ptr || key_len < 1 ){
		return (NULL);
	}

	/***********************************************************************
	 * If neither KeyIdRester nor ObjectHashRester is present,
	 * key_ptr points to the address of the original name, not the key_buff
	 ***********************************************************************/

#ifdef CefC_Debug
	{
		int dbg_x;
		int len = 0;

		len = sprintf (pit_dbg_msg, "[pit] Search the entry [");
		for (dbg_x = 0 ; dbg_x < key_len ; dbg_x++) {
			len = len + sprintf (pit_dbg_msg + len, " %02X", key_ptr[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", pit_dbg_msg);
	}
#endif // CefC_Debug

	/* Searches a PIT entry 	*/
	entry = (CefT_Pit_Entry*) cef_lhash_tbl_item_get (pit, key_ptr, key_len);
	now = cef_client_present_timeus_get ();

	if (entry != NULL) {
//0.8.3c ----- START ----- version
		//move to pit_entry_down_face_remove
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
/*		if (now > entry->adv_lifetime_us) {	20190822*/
		if ((now > entry->adv_lifetime_us) && (poh->app_reg_f != CefC_T_OPT_APP_PIT_DEREG)){	//20190822
			return (NULL);
		}
		found_ver_f = cef_pit_entry_down_face_search (&(entry->dnfaces), 1, pm);
		if (found_ver_f)
			return (entry);
		else
			return (NULL);
	}

	if (pm->chunk_num_f) {
		uint16_t key_len_wo_chunk;
		key_len_wo_chunk = key_len - (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
		entry = (CefT_Pit_Entry*) cef_lhash_tbl_item_get (pit, key_ptr, key_len_wo_chunk);

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
				found_ver_f = cef_pit_entry_down_face_search (&(entry->dnfaces), 1, pm);
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

	return (NULL);
}

CefT_Pit_Entry* 							/* a PIT entry								*/
cef_pit_entry_search (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh,				/* Parsed Option Header						*/
	unsigned char* ccninfo_pit,				/* pit name for ccninfo ccninfo-03			*/
	int	ccninfo_pit_len						/* ccninfo pit length						*/
) {
	CefT_Pit_Entry* ret = NULL;

	if (pm->top_level_type == CefC_T_DISCOVERY) { /* for CCNINFO */
		/* KEY: Name + NodeIdentifier + RequestID */
		ret = cef_pit_entry_search_core(pit, pm, poh, ccninfo_pit, ccninfo_pit_len);
	} else {
		ret = cef_pit_entry_search_core(pit, pm, poh, pm->name, pm->name_len);
	}
	return ret;
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
cef_dbg_write (CefC_Dbg_Finer, "IN faceid=%d\n", faceid );
#endif

	int new_downface_f = 0;
	int forward_interest_f = 0;
	struct timeval now;
	uint64_t nowt_us;
	uint64_t max_lifetime_us;
	uint64_t prev_lifetime_us;
	uint64_t prev_adv_lifetime_us;
	uint64_t extent_us;

	gettimeofday (&now, NULL);
	nowt_us = now.tv_sec * 1000000llu + now.tv_usec;

	/* Looks up a Down Face entry 		*/
	new_downface_f = cef_pit_entry_down_face_lookup (
						entry, faceid, &face, 0, pm->org.longlife_f);
	if ( !face ){
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Fine, "lookup failed, faceid=%d\n", faceid );
#endif // CefC_Debug
		return (0);		// lookup failed
	}

#ifdef	__PIT_DEBUG__
cef_dbg_write (CefC_Dbg_Finer, "\t entry=%p, new_downface_f=%d (1:NEW)\n", (void*)entry, new_downface_f );
cef_dbg_write (CefC_Dbg_Finer, "\t face->lifetime_us= "FMTU64"\n", face->lifetime_us / 1000 );
#endif

	/* Checks flags 					*/
	if (new_downface_f) {
		face->nonce = pm->nonce;
	} else {
		if ((pm->nonce) && (pm->nonce == face->nonce)) {
#ifdef	__PIT_DEBUG__
cef_dbg_write (CefC_Dbg_Finer, "return(0) ((pm->nonce) && (pm->nonce == face->nonce))\n");
#endif
			return (0);
		}
		face->nonce = pm->nonce;
	}

	if (pm->org.longlife_f) {
		if (new_downface_f) {
//			entry->longlife_f++;
			entry->longlife_f = pm->org.longlife_f;
		}
	}
#ifdef	__PIT_DEBUG__
cef_dbg_write (CefC_Dbg_Finer, "\t entry->longlife_f=%d\n", entry->longlife_f );
#endif

	/* for ccninfo */
	if (pm->top_level_type == CefC_T_DISCOVERY) {
		if (poh->ccninfo_flag & CefC_CtOp_FullDisCover)
			poh->lifetime = ccninfo_reply_timeout * 1000;
		else
			poh->lifetime = CefC_Default_CcninfoReplyTimeout * 1000;

		poh->lifetime_f = 1;
	}

	/* Updates Interest Lifetime of this PIT entry 		*/
	switch ( poh->app_reg_f ){
	default:
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

		if (poh->lifetime_f) {
			extent_us = (uint64_t)(poh->lifetime) * 1000;
		} else {
			extent_us = CefC_Default_LifetimeUs;
		}
		break;
	case CefC_T_OPT_APP_PIT_REG:
		if (poh->lifetime_f) {
			extent_us = (uint64_t)(poh->lifetime) * 1000;
		} else {
			/* lifetime : 60 min. */
			extent_us = (uint64_t)60 * 60 * 1000 * 1000;
			/* If you send a normal INTEREST, it will be overwritten. */
		}
		break;
	case CefC_T_OPT_DEV_REG_PIT:
		/* Use cache time instead of lifetime */
		extent_us = poh->cachetime;	/* poh->cachetime is usec */
		break;
	}
	prev_adv_lifetime_us = entry->adv_lifetime_us;
	prev_lifetime_us  = face->lifetime_us;
	face->lifetime_us = nowt_us + extent_us;

#ifdef	__PIT_DEBUG__
cef_dbg_write (CefC_Dbg_Finer, "\t extent_us= "FMTU64"\n", extent_us / 1000 );
cef_dbg_write (CefC_Dbg_Finer, "\t prev_lifetime_us= "FMTU64"\n", prev_lifetime_us / 1000 );
cef_dbg_write (CefC_Dbg_Finer, "\t face->lifetime_us= "FMTU64"\n", face->lifetime_us / 1000 );
cef_dbg_write (CefC_Dbg_Finer, "\t entry->drp_lifetime_us= "FMTU64"\n", entry->drp_lifetime_us / 1000 );
cef_dbg_write (CefC_Dbg_Finer, "\t entry->adv_lifetime_us= "FMTU64"\n", entry->adv_lifetime_us / 1000 );
#endif

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, "[pit] Lifetime = "FMTU64"\n", extent_us / 1000);
#endif // CefC_Debug

	/* Checks the advertised lifetime to upstream 		*/
	if (face->lifetime_us > entry->adv_lifetime_us) {
#ifdef	__PIT_DEBUG__
cef_dbg_write (CefC_Dbg_Finer, "\t (face->lifetime_us > entry->adv_lifetime_us)\n" );
#endif
		forward_interest_f = 1;
		entry->adv_lifetime_us = face->lifetime_us;
		entry->drp_lifetime_us = face->lifetime_us + CefC_Pit_CleaningTime;
	} else {
#ifdef	__PIT_DEBUG__
cef_dbg_write (CefC_Dbg_Finer, "\t !(face->lifetime_us > entry->adv_lifetime_us)\n" );
#endif
		if (pm->top_level_type == CefC_T_DISCOVERY) {
			return (forward_interest_f);
		}

		if (face->lifetime_us < prev_lifetime_us) {
#ifdef	__PIT_DEBUG__
cef_dbg_write (CefC_Dbg_Finer, "\t (face->lifetime_us < prev_lifetime_us)\n" );
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

				if (msg && poh->lifetime_f && 0 < poh->lifetime){
					uint16_t new_lifetime_ms, nbo_lifetime;

					new_lifetime_ms = (max_lifetime_us - nowt_us) / 1000;
					nbo_lifetime = htons (new_lifetime_ms);
					memcpy (&msg[poh->lifetime_f], &nbo_lifetime, CefC_S_Lifetime);

#ifdef	__PIT_DEBUG__
cef_dbg_write (CefC_Dbg_Finer, "\t Lifetime (update)= %d\n", new_lifetime_ms );
#endif
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
cef_dbg_write (CefC_Dbg_Finer, "Before (%d) forward (yes=1/no=0)\n", forward_interest_f );
cef_dbg_write (CefC_Dbg_Finer, "\t Resend_method:%s\n",
			  (Resend_method == CefC_IntRetrans_Type_RFC) ? "RFC":"NO_SUPPRESSION");
#endif

	switch ( Resend_method ){
	case CefC_IntRetrans_Type_NOSUP:	/* NO_SUPPRESSION */
		/* Not Same Face */
		if (new_downface_f) {
			forward_interest_f = 1;
		}
		break;

	default:
	case CefC_IntRetrans_Type_RFC:
		//0.8.3  RFC
		//	forward_interest_f=0
		//		new_downface_f=0 Same Face:Retransmit
		//		new_downface_f=1 Not Same Face: Check HopLimit
		//	forward_interest_f=1
		if ( prev_adv_lifetime_us == 0 ){	/* new pit entry */
			forward_interest_f = 1;
		} else if ( forward_interest_f == 0 ) {
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
		/* Update HopLimit */
		if ( (forward_interest_f == 1) && (pm->hoplimit > entry->hoplimit) ) {
			entry->hoplimit = pm->hoplimit;
		}
		break;
	}

	if ((poh->lifetime_f) && (poh->lifetime == 0) && entry) {
		CefT_Down_Faces* down_face = entry->dnfaces.next;

		if ( down_face && down_face->next ){
			forward_interest_f = 0;
		}
	}

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest,
		"[pit] forward (yes=1/no=0) = %d\n", forward_interest_f);
#endif

#ifdef	__PIT_DEBUG__
cef_dbg_write (CefC_Dbg_Finer, "\t extent_us= "FMTU64"\n", extent_us / 1000 );
cef_dbg_write (CefC_Dbg_Finer, "\t prev_lifetime_us= "FMTU64"\n", prev_lifetime_us / 1000 );
cef_dbg_write (CefC_Dbg_Finer, "\t face->lifetime_us= "FMTU64"\n", face->lifetime_us / 1000 );
cef_dbg_write (CefC_Dbg_Finer, "\t entry->drp_lifetime_us= "FMTU64"\n", entry->drp_lifetime_us / 1000 );
cef_dbg_write (CefC_Dbg_Finer, "\t entry->adv_lifetime_us= "FMTU64"\n", entry->adv_lifetime_us / 1000 );
cef_dbg_write (CefC_Dbg_Finer, "OUT return(%d) forward (yes=1/no=0)\n", forward_interest_f );
#endif

	return (forward_interest_f);
}

CefT_Pit_Entry*
cef_pit_entry_lookup_and_down_face_update (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh,				/* Parsed Option Header						*/
	unsigned char* ccninfo_name,			/* pit name for ccninfo ccninfo-03			*/
	int	ccninfo_namelen,					/* ccninfo name length						*/
	uint16_t faceid,						/* Face-ID									*/
	unsigned char* msg,						/* cefore packet 							*/
	int		 Resend_method,					/* Resend method 0.8.3 						*/
	int		 *pit_res						/* Returns 1 if the return entry is new	 	*/
) {
	CefT_Pit_Entry* entry = NULL;			/* PIT entry								*/
	int	 forward_interest_f = 0;

	// entry lookup with lock
	if (pm->top_level_type == CefC_T_DISCOVERY
		&& ccninfo_name != NULL && 0 < ccninfo_namelen ) {  /* for CCNINFO */

		/* CCNINFO PIT KEY: Name + NodeIdentifier + RequestID */
		// entry lookup with lock
		entry = cef_pit_entry_lookup_with_lock (pit, pm, poh, ccninfo_name, ccninfo_namelen, CefC_PitEntry_Lock);
	} else {
		// entry lookup with lock
		entry = cef_pit_entry_lookup_with_lock (pit, pm, poh, pm->name, pm->name_len, CefC_PitEntry_Lock);
	}

	if (entry != NULL) {
		forward_interest_f = cef_pit_entry_down_face_update (entry, faceid, pm, poh, msg, Resend_method);
		cef_pit_entry_unlock (entry);
	} else {
		cef_dbg_write (CefC_Dbg_Finer, "entry not found, down faceid=%d.\n", faceid);
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

	if ( !entry )
		return;

#ifdef	__PIT_DEBUG__
cef_dbg_write (CefC_Dbg_Finer, "IN entry=%p , dnfacenum=%d\n", entry, entry->dnfacenum );
#endif

	rm_entry = (CefT_Pit_Entry*) cef_lhash_tbl_item_remove (pit, entry->key, entry->klen);
	if ( rm_entry != entry ){
		cef_log_write (CefC_Log_Error, "%s(%u) cef_lhash_tbl_item_remove() failed, entry=%p, rm_entry=%p.\n",
			__func__, __LINE__, entry, rm_entry);
	}

	// =========== free up faces ==============
{	CefT_Up_Faces* upface = entry->upfaces.next;
	while (upface) {
		CefT_Up_Faces* upface_next = upface->next;
		free (upface);
		upface = upface_next;
	}
}

	// =========== free down faces ==============
{	CefT_Down_Faces* dnface = entry->dnfaces.next;
	while (dnface) {
		CefT_Down_Faces* dnface_next = dnface->next;
		if ( dnface->IR_len > 0 && dnface->IR_msg ) {
#ifdef	__PIT_DEBUG__
cef_dbg_write (CefC_Dbg_Finer, "\t dnface->IR_len:%d Type:%d\n", dnface->IR_len, dnface->IR_Type );
#endif
			free( dnface->IR_msg );
		}
		free (dnface);
		dnface = dnface_next;
	}

	// =========== free cleand down faces ==============
	dnface = entry->clean_dnfaces.next;
	while (dnface) {
		CefT_Down_Faces* dnface_next = dnface->next;
		if ( dnface->IR_len > 0 && dnface->IR_msg ) {
#ifdef	__PIT_DEBUG__
cef_dbg_write (CefC_Dbg_Finer, "\t clean dnface->IR_len:%d Type:%d\n", dnface->IR_len, dnface->IR_Type );
#endif
			free( dnface->IR_msg );
		}
		free (dnface);
		dnface = dnface_next;
	}
}

	//0.8.3
	if ( entry->KIDR_len > 0 && entry->KIDR_selector ) {
		free( entry->KIDR_selector );
	}
	if ( entry->COBHR_len > 0 && entry->COBHR_selector ) {
		free( entry->COBHR_selector );
	}

	pthread_mutex_destroy (&entry->pe_mutex_pt);

#ifdef	__PIT_DEBUG__
cef_dbg_write (CefC_Dbg_Finer, "OUT free(%p)\n", entry);
#endif

	free (entry);

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
	//0.8.3
	dnface->next->IR_Type = 0;
	dnface->next->IR_len  = 0;
	dnface->next->IR_msg  = NULL;

	cef_dbg_write (CefC_Dbg_Finest, "new downface=%p, faceid=%d.\n", dnface->next, faceid);

#ifdef	__INTEREST__
	fprintf (stderr, "%s New DnFace id:%d\n", __func__, faceid );
#endif

	return (1);
}
/*--------------------------------------------------------------------------------------
	Search the version entry in specified Down Face entry
----------------------------------------------------------------------------------------*/
int											/* found entry = 1							*/
cef_pit_entry_down_face_search (
	CefT_Down_Faces* dnface,				/* Down Face entry							*/
	int head_or_point_f,					/* 1: dnface is head of down face list		*/
											/* 0: dnface is pointer of 1 entry			*/
	CefT_CcnMsg_MsgBdy* pm 				/* Parsed CEFORE message					*/
) {

	return (1);
}
/*--------------------------------------------------------------------------------------
	Remove the version entry in specified Down Face entry
----------------------------------------------------------------------------------------*/
void
cef_pit_entry_down_face_remove (
	CefT_Pit_Entry* pe, 					/* PIT entry								*/
	CefT_Down_Faces* dnface,				/* Down Face entry							*/
	CefT_CcnMsg_MsgBdy* pm					/* Parsed CEFORE message					*/
) {
	if (!pe || pe->longlife_f)
		return;

	if ( dnface ){
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
	Returns the faceid of the upstream face from an existing PIT entry
----------------------------------------------------------------------------------------*/
uint16_t
cef_pit_entry_up_face_idget (
	CefT_Pit_Entry* entry					/* PIT entry 								*/
) {
	uint64_t	nowt = cef_client_present_timeus_get ();

	cef_dbg_write (CefC_Dbg_Finer, "entry = %p, hashv=%u, adv_lifetime_us="FMTU64"\n",
		entry, entry->hashv, entry->adv_lifetime_us);

	if ( !entry->adv_lifetime_us || (nowt < entry->adv_lifetime_us) ){
		CefT_Up_Faces* face = &(entry->upfaces);

		while (face && face->next) {
			face = face->next;
			cef_dbg_write (CefC_Dbg_Finest, "faceid = %u\n", face->faceid);
			if (cef_face_check_active (face->faceid) > 0) {
				return (face->faceid);
			}
		}
	}

	cef_dbg_write (CefC_Dbg_Finest, "face not found.\n");

	return (0);
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

	if ( !entry )
		return NULL;

	now = cef_client_present_timeus_get ();

#ifdef	__PIT_DEBUG__
cef_dbg_write (CefC_Dbg_Finer, "\t entry=%p, now="FMTU64", adv_lifetime_us="FMTU64", clean_us="FMTU64"\n",
 (void*)entry, now/1000, entry->adv_lifetime_us/1000, entry->clean_us/1000);
#endif
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
	CefT_CcnMsg_OptHdr* poh					/* Parsed Option Header						*/
)	{
	CefT_Pit_Entry* entry;
	unsigned char key_buff[CefC_NAME_BUFSIZ], *key_ptr;
	int		key_len = 0;

	/* PIT search key extended with KeyIdRester/ObjectHashRester */
	key_ptr = make_searchkey(pit, pm, poh, pm->name, pm->name_len, key_buff, &key_len);

	if ( !key_ptr || key_len < 1 ){
		return (-1);
	}

	/***********************************************************************
	 * If neither KeyIdRester nor ObjectHashRester is present,
	 * key_ptr points to the address of the original name, not the key_buff
	 ***********************************************************************/

#ifdef	__INTEREST__
	fprintf (stderr, "%s IN\n", __func__ );
#endif
	/* Searches a PIT entry 	*/
	entry = (CefT_Pit_Entry*) cef_lhash_tbl_item_get (pit, key_ptr, key_len);

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
	unsigned char key_buff[CefC_NAME_BUFSIZ], *key_ptr;
	int		key_len = 0;

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

	/* PIT search key extended with KeyIdRester/ObjectHashRester */
	key_ptr = make_searchkey(pit, pm, poh, pm->name, pm->name_len, key_buff, &key_len);
	if ( !key_ptr || key_len < 1 ){
		return (NULL);
	}

	/* Searches a PIT entry 	*/
	entry = (CefT_Pit_Entry*) cef_lhash_tbl_item_get (pit, key_ptr, key_len);
	if (!entry) {
		/* PIT search key without KeyIdRester/ObjectHashRester */
		key_ptr = pm->name;
		key_len = pm->name_len;
		entry = (CefT_Pit_Entry*) cef_lhash_tbl_item_get (pit, key_ptr, key_len);
	}
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "[pit] key_buff=%p, key_ptr=%p, name_len=%d, key_len=%d.\n",
key_buff, key_ptr, pm->name_len, key_len);
#endif // CefC_Debug
	now = cef_client_present_timeus_get ();

	if (entry != NULL) {
		found_ver_f = cef_pit_entry_down_face_search (&(entry->dnfaces), 1, pm);
//0.8.3c ----- START ----- version
		//move to pit_entry_down_face_remove
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
#ifdef	__PIT_DEBUG__
cef_dbg_write (CefC_Dbg_Finer, "\t entry=%p, now="FMTU64", adv_lifetime_us="FMTU64"\n",
 (void*)entry, now, entry->adv_lifetime_us);
#endif
		if ((now > entry->adv_lifetime_us) && (poh->app_reg_f != CefC_T_OPT_APP_PIT_DEREG)){	//20190822
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
	Searches a Symbolic-PIT entry matching the specified Name
----------------------------------------------------------------------------------------*/
CefT_Pit_Entry* 							/* a PIT entry								*/
cef_pit_entry_search_symbolic (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh					/* Parsed Option Header						*/
) {
	CefT_Pit_Entry* entry;
	uint16_t key_len_wo_chunk;
	uint64_t now;
	int found_ver_f = 0;
	unsigned char key_buff[CefC_NAME_BUFSIZ], *key_ptr;
	int		key_len = 0;

	if ( !pm ){
		cef_dbg_write (CefC_Dbg_Fine, "BUG:pm = NULLPTR.\n");
		return NULL;
	}

	if (!pm->chunk_num_f){
		cef_dbg_write (CefC_Dbg_Finer, "[pit] Mismatched, packet without chunk_num\n");
		return NULL;
	}

	/* PIT search key extended with KeyIdRester/ObjectHashRester */
	key_ptr = make_searchkey(pit, pm, poh, pm->name, pm->name_len, key_buff, &key_len);

	if ( !key_ptr || key_len < 1 ){
		return (NULL);
	}

	key_len_wo_chunk = key_len - (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);

#ifdef CefC_Debug
	{
		int dbg_x;
		int len = 0;

		len = sprintf (pit_dbg_msg, "[pit] Search the entry [");
		for (dbg_x = 0 ; dbg_x < key_len ; dbg_x++) {
			len = len + sprintf (pit_dbg_msg + len, " %02X", key_ptr[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", pit_dbg_msg);
	}
#endif // CefC_Debug

	/* Searches a PIT entry 	*/
	entry = (CefT_Pit_Entry*) cef_lhash_tbl_item_get (pit, key_ptr, key_len_wo_chunk);
	if (!entry) {
		/* PIT search key without KeyIdRester/ObjectHashRester */
		key_ptr = pm->name;
		key_len = pm->name_len;
		key_len_wo_chunk = key_len - (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
		entry = (CefT_Pit_Entry*) cef_lhash_tbl_item_get (pit, key_ptr, key_len_wo_chunk);
	}
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "[pit] key_buff=%p, key_ptr=%p, name_len=%d, key_len=%d.\n",
key_buff, key_ptr, pm->name_len, key_len);
#endif // CefC_Debug
	if (!entry) {
		cef_dbg_write (CefC_Dbg_Finer, "[pit] Mismatched, cef_lhash_tbl_item_get, not found.\n");
		return NULL;
	}

	if ( entry->PitType != CefC_PIT_TYPE_Sym ){
		cef_dbg_write (CefC_Dbg_Finer, "[pit] Mismatched, entry=%p is not Symbolic.\n", entry);
		return NULL;
	}

	now = cef_client_present_timeus_get ();

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

#ifdef	__PIT_DEBUG__
cef_dbg_write (CefC_Dbg_Finer, "\t entry=%p, now="FMTU64", adv_lifetime_us="FMTU64"\n",
(void*)entry, now, entry->adv_lifetime_us);
#endif
	if (now > entry->adv_lifetime_us) {
		cef_dbg_write (CefC_Dbg_Finer, "pit entry=%p, expired.\n", entry);
		return (NULL);
	}

	found_ver_f = cef_pit_entry_down_face_search (&(entry->dnfaces), 1, pm);
	if (found_ver_f) {
		cef_dbg_write (CefC_Dbg_Finest, "[pit] ... Matched Version\n");
		return (entry);
	}

	cef_dbg_write (CefC_Dbg_Finest, "[pit] ... Unmatched Version\n");

	return (NULL);
}

/*--------------------------------------------------------------------------------------
	Searches a PIT entry matching the specified Name with any chunk number
----------------------------------------------------------------------------------------*/
CefT_Pit_Entry* 							/* a PIT entry								*/
cef_pit_entry_search_with_anychunk (
	CefT_Hash_Handle pit,					/* PIT										*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh					/* Parsed Option Header						*/
) {
#ifdef CefC_Debug
	char pit_dbg_msg[2048];
#endif // CefC_Debug
	CefT_Pit_Entry* entry;
	unsigned char buf_tmpname[CefC_NAME_BUFSIZ], *key_ptr;
	const int num_chunks = 100;
	int      len_tmpname = 0;
	uint32_t *ptr_chunknum;
	uint32_t i, start, end;

	/* PIT search key extended with KeyIdRester/ObjectHashRester */
	memcpy(buf_tmpname, pm->name, pm->name_len);
	key_ptr = make_searchkey(pit, pm, poh, pm->name, pm->name_len, buf_tmpname, &len_tmpname);

	if ( !key_ptr || len_tmpname < 1 ){
		return (NULL);
	}

	if (!pm->chunk_num_f) {
		uint16_t	type_t_chunk = htons(CefC_T_CHUNK);
		uint16_t	len_t_chunk = htons(CefC_S_ChunkNum);

		memcpy(&buf_tmpname[len_tmpname], &type_t_chunk, sizeof(type_t_chunk));
		len_tmpname += sizeof(type_t_chunk);
		memcpy(&buf_tmpname[len_tmpname], &len_t_chunk, sizeof(len_t_chunk));
		len_tmpname += sizeof(len_t_chunk);
		len_tmpname += (CefC_S_ChunkNum);
		start = 0;
		end = num_chunks;
	} else {
		if ( num_chunks < pm->chunk_num ){
			start = pm->chunk_num - num_chunks;
		} else {
			start = 0;
		}
		end = pm->chunk_num;
	}
	ptr_chunknum = (uint32_t *)&buf_tmpname[len_tmpname-CefC_S_ChunkNum];
	*ptr_chunknum = 0;

#ifdef CefC_Debug
	{
		int dbg_x;
		int len = 0;

		len = sprintf (pit_dbg_msg, "[pit] Search the entry [");
		for (dbg_x = 0 ; dbg_x < len_tmpname ; dbg_x++) {
			len = len + sprintf (pit_dbg_msg + len, " %02X", pm->name[dbg_x]);
		}
		cef_dbg_write (CefC_Dbg_Finest, "%s ]\n", pit_dbg_msg);
	}
#endif // CefC_Debug

	entry = NULL;
	for ( i = start; entry == NULL && i <= end; i++ ){
		*ptr_chunknum = htonl(i);
		entry = (CefT_Pit_Entry*) cef_lhash_tbl_item_get (pit, buf_tmpname, len_tmpname);
	}

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

	return (entry);
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
#define	CefC_PitEntry_Lock_Retry	3
int
cef_pit_entry_lock (
	CefT_Pit_Entry* entry 					/* PIT entry 								*/
) {
	int	ret = CefC_PitEntry_Lock;
	int i, res;
	const struct timespec ts_req = { 0, 1000000 };	/* 1 mili sec. */

	for ( i = res = 0;
				i < CefC_PitEntry_Lock_Retry &&
				(res = pthread_mutex_trylock (&entry->pe_mutex_pt)) != 0;
						i++ ) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finer, "pthread_mutex_trylock=%d:%s\n", res, strerror(errno));
#endif // CefC_Debug

		if (EBUSY != res) {
			cef_log_write (CefC_Log_Error, "%s(%u) mutex_trylock=%d\n", __func__, __LINE__, res);
			break;
		}
		nanosleep(&ts_req, NULL);
	}
	if ( res != 0 ){
		cef_log_write (CefC_Log_Error, "%s(%u) mutex_trylock, %d retries exceeded.\n", __func__, __LINE__, CefC_PitEntry_Lock_Retry);
		ret = CefC_PitEntry_NoLock;		// lock failed
	}

	return ret;
}
void
cef_pit_entry_unlock (
	CefT_Pit_Entry* entry 					/* PIT entry 								*/
) {
#ifdef CefC_Debug
	int	res = pthread_mutex_unlock (&entry->pe_mutex_pt);
	if ( res ){
		cef_dbg_write (CefC_Dbg_Fine, "pthread_mutex_unlock=%d:%s\n", res, strerror(errno));
	}
#else // CefC_Debug
	pthread_mutex_unlock (&entry->pe_mutex_pt);
#endif // CefC_Debug

	return;
}


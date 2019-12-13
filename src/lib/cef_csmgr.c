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
 * cef_csmgr.c
 */

#define __CEF_CSMGR_SOURCE__


/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <cefore/cef_client.h>
#include <cefore/cef_csmgr.h>
#include <cefore/cef_define.h>
#include <cefore/cef_frame.h>
#include <cefore/cef_face.h>
#include <cefore/cef_log.h>
#ifdef CefC_Ccore
#include <ccore/ccore_frame.h>
#endif // CefC_Ccore



/****************************************************************************************
 Macros
 ****************************************************************************************/


/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/


/****************************************************************************************
 State Variables
 ****************************************************************************************/

static unsigned char* 	cefnetd_msg_buff 		= NULL;
static int 				cefnetd_msg_buff_index 	= 0;
static unsigned char* 	work_msg_buff 			= NULL;

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

#ifndef CefC_Dtc
/*--------------------------------------------------------------------------------------
	Increment Access Count in excache
----------------------------------------------------------------------------------------*/
static void
cef_csmgr_excache_access_increment (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	const unsigned char* key,				/* Content name								*/
	uint32_t klen,							/* Content name length						*/
	uint32_t chnk_num						/* Content Chunk Number 					*/
);
#endif // CefC_Dtc
/*--------------------------------------------------------------------------------------
	Create Interest message for csmgrd
----------------------------------------------------------------------------------------*/
static void
cef_csmgr_interest_msg_create (
	unsigned char buff[],					/* Interest message							*/
	uint16_t* index,						/* Length of message						*/
	CefT_Parsed_Opheader* poh,				/* Parsed Option Header						*/
	CefT_Parsed_Message* pm					/* Parsed CEFORE message					*/
);
/*--------------------------------------------------------------------------------------
	Connect csmgrd local socket
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
cef_csmgr_csmgrd_connect_local (
	CefT_Cs_Stat* cs_stat					/* Content Store Status						*/
);
/*--------------------------------------------------------------------------------------
	Send message from cefnetd to csmgrd
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
cef_csmgr_send_msg_to_csmgrd (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	unsigned char* msg,						/* send message								*/
	int msg_len								/* message length							*/
);

/****************************************************************************************
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Create Content Store Manager Status
----------------------------------------------------------------------------------------*/
CefT_Cs_Stat*						/* The return value is null if an error occurs		*/
cef_csmgr_stat_create (
	void
) {
	CefT_Cs_Stat* cs_stat = NULL;
	int res;
	char port_str[NI_MAXSERV];
	
	/* allocate memory */
	cs_stat = (CefT_Cs_Stat*) malloc (sizeof (CefT_Cs_Stat));
	if (cs_stat == NULL) {
		cef_log_write (CefC_Log_Error, "%s (malloc CefT_Cs_Stat)\n", __func__);
		return (NULL);
	}
	memset (cs_stat, 0, sizeof (CefT_Cs_Stat));
	cs_stat->tx_que = NULL;
	cs_stat->local_sock = -1;
	cs_stat->tcp_sock 	= -1;
	
	/* read config */
	res = cef_csmgr_config_read (cs_stat);
	if (res < 0) {
		cef_log_write (CefC_Log_Error, "%s (Loading csmgrd.conf)\n", __func__);
		cef_csmgr_stat_destroy (&cs_stat);
		return (NULL);
	}

	if (cs_stat->cache_type == CefC_Cache_Type_Excache) {
		
		if ((strcmp (cs_stat->peer_id_str, "localhost")) &&
			(strcmp (cs_stat->peer_id_str, "127.0.0.1"))) {
			sprintf (port_str, "%d", cs_stat->tcp_port_num);
			cs_stat->tcp_sock 
				= cef_csmgr_connect_tcp_to_csmgrd (cs_stat->peer_id_str, port_str);
			if (cs_stat->tcp_sock < 0) {
				cef_csmgr_stat_destroy (&cs_stat);
				cef_log_write (CefC_Log_Error, "%s (connect to csmgrd)\n", __func__);
				return (NULL);
			}
		} else {
			cs_stat->local_sock = cef_csmgr_csmgrd_connect_local (cs_stat);
			
			if (cs_stat->local_sock < 0) {
				cef_csmgr_stat_destroy (&cs_stat);
				cef_log_write (CefC_Log_Error, "%s (connect to csmgrd)\n", __func__);
				return (NULL);
			}
		}
	}
	
	/* Create memory cache */
	if (cs_stat->cache_type == CefC_Cache_Type_Excache) {
		/* create Cs_Tx_Que */
		cs_stat->tx_que = cef_rngque_create (CefC_Tx_Que_Size);
		cs_stat->tx_cob_mp = cef_mpool_init (
										"CefCsCobQue",
										sizeof (CefT_Cs_Tx_Elem_Cob),
										CefC_Tx_Que_Size);
		if (cs_stat->tx_cob_mp == 0) {
			cef_csmgr_stat_destroy (&cs_stat);
			cef_log_write (CefC_Log_Error, "%s (mpool CefCsCobQue)\n", __func__);
			return (NULL);
		}
		cs_stat->tx_que_mp =
				cef_mpool_init ("CefCsTxQue", sizeof (CefT_Cs_Tx_Elem), CefC_Tx_Que_Size);
		if (cs_stat->tx_que_mp == 0) {
			cef_csmgr_stat_destroy (&cs_stat);
			cef_log_write (CefC_Log_Error, "%s (mpool CefCsTxQue)\n", __func__);
			return (NULL);
		}
		
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "CACHE_TYPE     = Excache\n");
		cef_dbg_write (CefC_Dbg_Fine, "CACHE_CAPACITY = "FMTU64"\n", cs_stat->cache_cap);
#endif // CefC_Debug
		if (cs_stat->cache_cap > 0) {
			/* create CS */
			cs_stat->cs_cob_entry_mp = cef_mpool_init (
				"CefCsCobEnt", sizeof (CefT_Cob_Entry), cs_stat->cache_cap);
			if (cs_stat->cs_cob_entry_mp == 0) {
				cef_csmgr_stat_destroy (&cs_stat);
				cef_log_write (CefC_Log_Error, "%s (mpool CefCsCobEnt)\n", __func__);
				return (NULL);
			}
			cef_log_write (CefC_Log_Info, 
				"The maximum number of cached Cobs is "FMTU64"\n", cs_stat->cache_cap);
			
			cs_stat->cob_table = cef_hash_tbl_create (
				(uint16_t) cs_stat->cache_cap + CefC_Csmgr_Max_Table_Margin);
			if (cs_stat->cob_table == (CefT_Hash_Handle) NULL) {
				cef_log_write (CefC_Log_Error, "%s (creation buffer)\n", __func__);
				cef_csmgr_stat_destroy (&cs_stat);
			}
		} else {
			cs_stat->cob_table = (CefT_Hash_Handle) NULL;
		}
	}
	if (cefnetd_msg_buff) {
		free (cefnetd_msg_buff);
	}
	cefnetd_msg_buff = malloc (sizeof (unsigned char) * CefC_Cefnetd_Buff_Max);
	if (cefnetd_msg_buff == NULL) {
		cef_csmgr_stat_destroy (&cs_stat);
		cef_log_write (CefC_Log_Error, "%s (alloc message buffer)\n", __func__);
		return (NULL);
	}
	cefnetd_msg_buff_index = 0;
	cef_csmgr_buffer_init ();
	
	return (cs_stat);
}
/*--------------------------------------------------------------------------------------
	Create the work buffer for csmgrd
----------------------------------------------------------------------------------------*/
unsigned char* 
cef_csmgr_buffer_init (
	void 
) {
	if (work_msg_buff) {
		free (work_msg_buff);
	}
	work_msg_buff = malloc (sizeof (unsigned char) * CefC_Cefnetd_Buff_Max);
	if (work_msg_buff == NULL) {
		return (NULL);
	}
	
	return (work_msg_buff);
}
/*--------------------------------------------------------------------------------------
	Destroy the work buffer for csmgrd
----------------------------------------------------------------------------------------*/
void 
cef_csmgr_buffer_destroy (
	void 
) {
	if (work_msg_buff) {
		free (work_msg_buff);
	}
}
/*--------------------------------------------------------------------------------------
	Reads the config file
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_csmgr_config_read (
	CefT_Cs_Stat* cs_stat					/* Content Store Status						*/
) {
	FILE*	fp = NULL;								/* file pointer						*/
	char	file_name[1024];						/* file name						*/
	char	file_path[1024];						/* file path						*/

	char	param[4096] = {0};						/* parameter						*/
	char	param_buff[4096] = {0};					/* param buff						*/
	int		len;									/* read length						*/

	char*	option;									/* deny option						*/
	char*	value;									/* parameter						*/

	int		i, n;
	int64_t	res;
	
	char 	local_sock_id[1024] = {"0"};
	
	/* Obtains the directory path where the cefnetd's config file is located. */
#ifndef CefC_Android
	cef_client_config_dir_get (file_path);
#else // CefC_Android
	/* Android local cache storage is data/data/package_name/ */
	sprintf (file_path, "data/data/icn.app.cefore/.cefore");
#endif // CefC_Android

	if (mkdir (file_path, 0777) != 0) {
		if (errno == ENOENT) {
			cef_log_write (CefC_Log_Error, "%s (mkdir)\n", __func__);
			return (-1);
		}
	}
	sprintf (file_name, "%s/cefnetd.conf", file_path);
	
	/* Opens the cefnetd's config file. */
	fp = fopen (file_name, "r");
	if (fp == NULL) {
		fp = fopen (file_name, "w");
		if (fp == NULL) {
			cef_log_write (CefC_Log_Error, "%s (open cefnetd.conf)\n", __func__);
			return (-1);
		}
		fclose (fp);
		fp = fopen (file_name, "r");
	}
	
	/* Set default value */
	cs_stat->cache_type  	= CefC_Default_Cache_Type;
	cs_stat->def_rct		= CefC_Default_Def_Rct;
	cs_stat->cache_cap 		= CefC_Default_Cache_Capacity;
	cs_stat->tcp_port_num 	= CefC_Default_Tcp_Prot;
	strcpy (cs_stat->peer_id_str, CefC_Default_Node_Path);
	
	/* get parameter */
	while (fgets (param_buff, sizeof (param_buff), fp) != NULL) {
		len = strlen (param_buff);
		if ((param_buff[0] == '#') || (param_buff[0] == '\n') || (len == 0)) {
			continue;
		}
		if (param_buff[len - 1] == '\n') {
			param_buff[len - 1] = '\0';
		}

		for (i = 0, n = 0; i < len; i++) {
			if (param_buff[i] != ' ') {
				param[n] = param_buff[i];
				n++;
			}
		}
		/* get option */
		value = param;
		option = strsep (&value, "=");
		if(value == NULL){
			continue;
		}

		if (strcmp (option, "USE_CACHE") == 0) {
			res = cef_csmgr_config_get_value (option, value);
			if ((res < 0) || (res > 1)) {
				cef_log_write (CefC_Log_Warn, "USE_CACHE must be 0 or 1\n");
				return (-1);
			}
			cs_stat->cache_type = res;
		} else if (strcmp (option, "BUFFER_CAPACITY") == 0) {
			res = cef_csmgr_config_get_value (option, value);
			if ((res < 0) || (res > CefC_Csmgr_Max_Table_Num)) {
				cef_log_write (CefC_Log_Warn, 
					"BUFFER_CAPACITY must be higher than 0 and lower than 65536.\n");
				return (-1);
			}
			cs_stat->cache_cap = res;
		} else if (strcmp (option, "CSMGR_NODE") == 0) {
			strcpy (cs_stat->peer_id_str, value);
		} else if (strcmp (option, "CSMGR_PORT_NUM") == 0) {
			res = cef_csmgr_config_get_value (option, value);
			if ((res < 1025) || (res > 65535)) {
				cef_log_write (CefC_Log_Warn, 
					"CSMGR_PORT_NUM must be higher than 1024 and lower than 65536.\n");
				return (-1);
			}
			cs_stat->tcp_port_num = res;
		} else if (strcmp (option, "LOCAL_SOCK_ID") == 0) {
			if (strlen (value) > 1024) {
				cef_log_write (CefC_Log_Warn, 
					"LOCAL_SOCK_ID must be shorter than 1024.\n");
				return (-1);
			}
			strcpy (local_sock_id, value);
		} else {
			/* NOP */;
		}
	}
	fclose (fp);
	sprintf (cs_stat->local_sock_name, 
		"/tmp/csmgr_%d.%s", cs_stat->tcp_port_num, local_sock_id);
	
	sprintf (file_name, "%s/csmgrd.conf", file_path);
	
	fp = fopen (file_name, "r");
	if (fp == NULL) {
		cef_log_write (CefC_Log_Error, "%s (open csmgrd.conf)\n", __func__);
		return (-1);
	}
	
	/* get parameter */
	while (fgets (param_buff, sizeof (param_buff), fp) != NULL) {
		len = strlen (param_buff);
		if ((param_buff[0] == '#') || (param_buff[0] == '\n') || (len == 0)) {
			continue;
		}
		if (param_buff[len - 1] == '\n') {
			param_buff[len - 1] = '\0';
		}

		for (i = 0, n = 0; i < len; i++) {
			if (param_buff[i] != ' ') {
				param[n] = param_buff[i];
				n++;
			}
		}
		/* get option */
		value = param;
		option = strsep (&value, "=");
		if(value == NULL){
			continue;
		}

		if (strcmp (option, "CACHE_DEFAULT_RCT") == 0) {
			res = cef_csmgr_config_get_value (option, value);
			if ((res < 1000) || (res > 3600000)) {
				cef_log_write (CefC_Log_Warn, 
				"CACHE_DEFAULT_RCT must be higher than 1000 and lower than 3600000.\n");
				return (-1);
			}
			cs_stat->def_rct = (uint32_t)(res * 1000);
		} else {
			/* NOP */;
		}
	}
	fclose (fp);
	
	return (0);
}
/*--------------------------------------------------------------------------------------
	Connect csmgrd local socket
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
cef_csmgr_csmgrd_connect_local (
	CefT_Cs_Stat* cs_stat					/* Content Store Status						*/
) {
	struct sockaddr_un saddr;
	int sock;
	int flag;
	size_t len;
	
	if ((sock = socket (AF_UNIX, SOCK_STREAM, 0)) < 0) {
		return (-1);
	}
	
	/* initialize sockaddr_un */
	memset (&saddr, 0, sizeof (saddr));
	saddr.sun_family = AF_UNIX;
	strcpy (saddr.sun_path, cs_stat->local_sock_name);
	len = strlen (cs_stat->local_sock_name);
	
	/* prepares a source socket */
#ifdef __APPLE__
	saddr.sun_len = sizeof (saddr);
	
	if (connect (sock, (struct sockaddr*)&saddr, SUN_LEN (&saddr)) < 0) {
		close (sock);
		return (-1);
	}
#else
	if (connect (sock, (struct sockaddr*)&saddr, sizeof (saddr.sun_family) + len) < 0) {
		close (sock);
		return (-1);
	}
#endif // __APPLE__

	flag = fcntl (sock, F_GETFL, 0);
	if (flag < 0) {
		close (sock);
		return (-1);
	}
	if (fcntl (sock, F_SETFL, flag | O_NONBLOCK) < 0) {
		close (sock);
		return (-1);
	}

	return (sock);
}
/*--------------------------------------------------------------------------------------
	Destroy Content Store Status
----------------------------------------------------------------------------------------*/
void
cef_csmgr_stat_destroy (
	CefT_Cs_Stat** cs_stat					/* Content Store Status						*/
) {
	CefT_Cs_Stat* stat = *cs_stat;
	
	if (stat->cache_type == CefC_Cache_Type_Excache) {
		if (stat->cob_table != (CefT_Hash_Handle)NULL) {
			cef_hash_tbl_destroy (stat->cob_table);
		}
		if (stat->tx_que != NULL) {
			cef_rngque_destroy (stat->tx_que);
		}
		if (stat->tx_cob_mp != 0) {
			cef_mpool_destroy (stat->tx_cob_mp);
		}
		if (stat->tx_que_mp != 0) {
			cef_mpool_destroy (stat->tx_que_mp);
		}
		if (stat->cs_cob_entry_mp != 0) {
			cef_mpool_destroy (stat->cs_cob_entry_mp);
		}
		if (stat->cache_type == CefC_Cache_Type_Excache) {
			csmgr_sock_close (stat);
		}
	}

	if (stat != NULL) {
		free (stat);
		*cs_stat = NULL;
	}
	
	if (cefnetd_msg_buff) {
		free (cefnetd_msg_buff);
		cefnetd_msg_buff = NULL;
	}
	cefnetd_msg_buff_index = 0;
	
	return;
}
/*--------------------------------------------------------------------------------------
	Search and replies the Cob from the temporary cache
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_csmgr_cache_lookup (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	int faceid,								/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	CefT_Parsed_Message* pm,				/* Parsed CEFORE message					*/
	CefT_Parsed_Opheader* poh,				/* Parsed Option Header						*/
	CefT_Pit_Entry* pe						/* PIT entry								*/
) {
	CefT_Cob_Entry* cob_entry = NULL;
	uint64_t nowt;
	CefT_Cs_Tx_Elem* tx_elem_que;
	CefT_Cs_Tx_Elem_Cob* tx_elem_cob;
	int res;
	
	/* If the Interest is longlife or bulk, process is left to csmrd 	*/
	if (poh->longlife_f) {
		return (-1);
	}
	
	/* Searches content entry 	*/
	if (cs_stat->cob_table) {
		cob_entry = (CefT_Cob_Entry*) 
			cef_hash_tbl_item_get_prg (cs_stat->cob_table, pm->name, pm->name_len);
	}
	
	if (cob_entry) {
		nowt = cef_client_present_timeus_get ();
		
		if (nowt < cob_entry->expiry) {
			if (pm->chnk_num_f) {
#ifndef CefC_Dtc
				cef_csmgr_excache_access_increment (
					cs_stat, pm->name, pm->name_len, pm->chnk_num);
#endif // CefC_Dtc
			}
			
			/* Allocs memory */
			tx_elem_que = (CefT_Cs_Tx_Elem*) cef_mpool_alloc (cs_stat->tx_que_mp);
			tx_elem_cob = (CefT_Cs_Tx_Elem_Cob*) cef_mpool_alloc (cs_stat->tx_cob_mp);
			
			if ((tx_elem_que == NULL) || (tx_elem_cob == NULL)) {
				/* reply ring queue is full */
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine, "%s (cef_mpool_alloc)\n", __func__);
#endif // CefC_Debug
				if (tx_elem_que != NULL) {
					cef_mpool_free (cs_stat->tx_que_mp, tx_elem_que);
				}
				if (tx_elem_cob != NULL) {
					cef_mpool_free (cs_stat->tx_cob_mp, tx_elem_cob);
				}
				/* delete down face. wait next interest */
				if (pe->dnfacenum > 0) {
					cef_pit_down_faceid_remove (pe, faceid);
				}
				return (-1);
			}
			/* Inserts cob entry */
			memcpy (&tx_elem_cob->cob, cob_entry, sizeof (CefT_Cob_Entry));
			
			if (pm->symbolic_code_f) {
				tx_elem_cob->cob.msg_len = cef_frame_symbolic_code_add (
					tx_elem_cob->cob.msg, tx_elem_cob->cob.msg_len, pm);
			}
			
			tx_elem_cob->faceid = faceid;
			tx_elem_que->type = CefC_Cs_Tx_Elem_Type_Cob;
			tx_elem_que->data = (void*) tx_elem_cob;
			res = cef_rngque_push (cs_stat->tx_que, tx_elem_que);
			if (res < 1) {
				/* push failed */
				cef_mpool_free (cs_stat->tx_cob_mp, tx_elem_cob);
				cef_mpool_free (cs_stat->tx_que_mp, tx_elem_que);
				return (-1);
			}
			/* delete down face. reply content object */
			if (pe->dnfacenum > 0) {
				cef_pit_down_faceid_remove (pe, faceid);
			}
			return (1);
		}
	}
	
	return (-1);
}
/*--------------------------------------------------------------------------------------
	Insert the Cob into the temporary cache
----------------------------------------------------------------------------------------*/
void 
cef_csmgr_cache_insert (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t msg_len,						/* length of received message				*/
	CefT_Parsed_Message* pm,				/* Parsed CEFORE message					*/
	CefT_Parsed_Opheader* poh				/* Parsed Option Header						*/
) {
	uint64_t nowt;
	CefT_Cob_Entry* new_entry;
	CefT_Cob_Entry* old_entry;
	
	if (!cs_stat->cob_table) {
		return;
	}
	
	/* Checks the lifetime 			*/
	nowt = cef_client_present_timeus_get ();
	if (poh->cachetime_f) {
		if (poh->cachetime < nowt) {
			return;
		}
	}
	
	/* Insert Cob Table */
	new_entry = (CefT_Cob_Entry*) cef_mpool_alloc (cs_stat->cs_cob_entry_mp);
	if (new_entry == NULL) {
		return;
	}
	memcpy (new_entry->msg, msg, msg_len);
	new_entry->msg_len = msg_len;
	new_entry->chunk_num = pm->chnk_num;
#ifndef CefC_Dtc
	new_entry->expiry = nowt + 10000000;
#else // CefC_Dtc
	new_entry->expiry = pm->expiry;
#endif // CefC_Dtc
	
	old_entry = (CefT_Cob_Entry*) cef_hash_tbl_item_set_prg (
			cs_stat->cob_table, pm->name, pm->name_len, new_entry);
	
	if (old_entry) {
		cef_mpool_free (cs_stat->cs_cob_entry_mp, old_entry);
	}
	
	return;
}
/*--------------------------------------------------------------------------------------
	Check reply flag. Don't forward interest if reply flag is on.
----------------------------------------------------------------------------------------*/
int									/* The return value is 0 if an error occurs			*/
cef_csmgr_rep_f_check (
	CefT_Pit_Entry* pe, 					/* PIT entry								*/
	int faceid								/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
) {
	CefT_Down_Faces* dnface = &(pe->dnfaces);
	/* check PIT entry */
	while (dnface->next) {
		dnface = dnface->next;
		if (dnface->faceid == faceid) {
			if (dnface->reply_f) {
				return (0);
			} else {
				break;
			}
		}
	}
	return (1);
}
/*--------------------------------------------------------------------------------------
	Connect csmgrd external socket
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_csmgr_csmgrd_connect_ext (
	const char* destination, 				/* String of the destination address 		*/
	const char* port_str					/* String of the destination port			*/
) {
	struct addrinfo hints;
	struct addrinfo* res;
	struct addrinfo* cres;
	int flag;
	int ret;
	int sock = -1;
	struct pollfd fds[1];

	memset (&hints, 0, sizeof (hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;

	/* get address information */
	if ((ret = getaddrinfo (destination, port_str, &hints, &res)) != 0) {
		cef_log_write (CefC_Log_Error, 
			"%s (getaddrinfo:%s)\n", __func__, gai_strerror (ret));
		return (-1);
	}
	for (cres = res ; cres != NULL ; cres = cres->ai_next) {
		/* get socket */
		if ((sock = socket (cres->ai_family, cres->ai_socktype, cres->ai_protocol)) < 0) {
			cef_log_write (CefC_Log_Error, 
				"%s (socket:%s)\n", __func__, strerror (errno));
			continue;
		}
		flag = fcntl (sock, F_GETFL, 0);
		if (flag < 0) {
			close (sock);
			sock = -1;
			continue;
		}
		if (fcntl (sock, F_SETFL, flag | O_NONBLOCK) < 0) {
			close (sock);
			sock = -1;
			continue;
		}
		if (connect (sock, cres->ai_addr, cres->ai_addrlen) < 0) {
			if (errno != EINPROGRESS) {
				cef_log_write (CefC_Log_Error, 
					"%s (connect:%s)\n", __func__, strerror (errno));
				close (sock);
				sock = -1;
				continue;
			}
		} else {
			/* connect success */
			break;
		}
		fds[0].fd = sock;
		fds[0].events = POLLIN | POLLERR;
		/* poll */
		ret = poll (fds, 1, 1000);
		if (ret < 0) {
			/* poll error */
			cef_log_write (CefC_Log_Error, "%s (poll:%s)\n", __func__, strerror (errno));
			close (sock);
			sock = -1;
			continue;
		}
		
		if (fds[0].revents & (POLLERR | POLLNVAL | POLLHUP)) {
			/* events error. */
			if (fds[0].revents & POLLERR) {
				cef_log_write (CefC_Log_Error, "%s (POLLNVAL)\n", __func__);
			} else if (fds[0].revents & POLLNVAL) {
				cef_log_write (CefC_Log_Error, "%s (POLLNVAL)\n", __func__);
			} else {
				cef_log_write (CefC_Log_Error, "%s (POLLHUP)\n", __func__);
			}
			close (sock);
			sock = -1;
			continue;
		}
		break;
	}

	freeaddrinfo (res);

	return (sock);
}
/*--------------------------------------------------------------------------------------
	Send message from csmgrd to cefnetd
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_csmgr_send_msg (
	int fd,									/* socket fd								*/
	unsigned char* msg,						/* send message								*/
	uint16_t msg_len						/* message length							*/
) {
	int res;
	res = send (fd, msg, msg_len, 0);
	if (res < 0) {
		if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
			return (-1);
		}
	}
	return (0);
}
/*--------------------------------------------------------------------------------------
	Send message from cefnetd to csmgrd
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
cef_csmgr_send_msg_to_csmgrd (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	unsigned char* msg,						/* send message								*/
	int msg_len								/* message length							*/
) {
	int res;
	char port_str[NI_MAXSERV];
	
	if (cs_stat->local_sock != -1) {
		res = send (cs_stat->local_sock, msg, msg_len, 0);
		return (res);
	}
	
	if (cs_stat->tcp_sock != -1) {
		res = write (cs_stat->tcp_sock, msg, msg_len);
		if (res < 0) {
			close (cs_stat->tcp_sock);
			cs_stat->tcp_sock = -1;
		}
		return (res);
	}
	sprintf (port_str, "%d", cs_stat->tcp_port_num);
	cs_stat->tcp_sock 
			= cef_csmgr_connect_tcp_to_csmgrd (cs_stat->peer_id_str, port_str);
	
	if (cs_stat->tcp_sock != -1) {
		res = write (cs_stat->tcp_sock, msg, msg_len);
		if (res < 0) {
			close (cs_stat->tcp_sock);
			cs_stat->tcp_sock = -1;
		}
	}
	
	return (0);
}
/*--------------------------------------------------------------------------------------
	Puts Content Object to excache
----------------------------------------------------------------------------------------*/
void
cef_csmgr_excache_item_put (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t msg_len,						/* length of received message				*/
	int faceid,								/* Arrived face id							*/
	CefT_Parsed_Message* pm,				/* Parsed CEFORE message					*/
	CefT_Parsed_Opheader* poh				/* Parsed Option header						*/
) {
	unsigned char buff[CefC_Max_Length] = {0};
	uint16_t index = 0;
	uint16_t value16;
	uint32_t value32;
	uint64_t value64;
	int chunk_field_len = CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum;
	struct in_addr node;
	CefT_Face* face = NULL;
	CefT_Sock* sock = NULL;
	CefT_Hash_Handle* sock_tbl = NULL;
	uint64_t nowt = cef_client_present_timeus_get ();
	
	/* Checks cache time 		*/
	if (poh->cachetime_f) {
		if (poh->cachetime < nowt) {
			return;
		}
	} else {
		poh->cachetime = nowt + cs_stat->def_rct;
	}
	if (pm->expiry > 0) {
		if (pm->expiry > poh->cachetime) {
			pm->expiry = poh->cachetime;
		} else {
			poh->cachetime = pm->expiry;
		}
	} else {
		return;
	}
	
	/* Inserts the Cob into temporary cache 	*/
	cef_csmgr_cache_insert (cs_stat, msg, msg_len, pm, poh);
	
	/* Creates Upload Request message 		*/
	/* set header */
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_UpReq;
	index += CefC_Csmgr_Msg_HeaderLen;
	
	/* set payload length */
	value16 = htons (pm->payload_len);
	memcpy (buff + index, &value16, CefC_S_Length);
	index += CefC_S_Length;
	
	/* set cob message */
	value16 = htons (msg_len);
	memcpy (buff + index, &value16, CefC_S_Length);
	memcpy (buff + index + CefC_S_Length, msg, msg_len);
	index += CefC_S_Length + msg_len;
	
	/* set cob name */
	if (pm->chnk_num_f) {
		value16 = htons (pm->name_len - chunk_field_len);
		memcpy (buff + index, &value16, CefC_S_Length);
		memcpy (buff + index + CefC_S_Length, pm->name, pm->name_len - chunk_field_len);
		index += CefC_S_Length + (pm->name_len - chunk_field_len);
	} else {
		return;
	}
	
	/* set chunk num */
	value32 = htonl (pm->chnk_num);
	memcpy (buff + index, &value32, CefC_S_ChunkNum);
	index += CefC_S_ChunkNum;
	
	/* set cache time */
	value64 = cef_client_htonb (poh->cachetime);
	memcpy (buff + index, &value64, CefC_S_Cachetime);
	index += CefC_S_Cachetime;
	
	/* set expiry */
	value64 = cef_client_htonb (pm->expiry);
	memcpy (buff + index, &value64, CefC_S_Expiry);
	index += CefC_S_Expiry;
	
	/* get address */
	/* check local face flag */
	face = cef_face_get_face_from_faceid (faceid);
	if (face->local_f || (faceid == 0)) {
		/* local face */
		node.s_addr = 0;
	} else {
		/* set face info */
		sock_tbl = cef_face_return_sock_table ();
		sock = (CefT_Sock*)cef_hash_tbl_item_get_from_index (*sock_tbl, face->index);
		if ((sock != NULL) &&
			(sock->faceid >= CefC_Face_Reserved)) {
			/* set address */
			node.s_addr = ((struct sockaddr_in *)(sock->ai_addr))->sin_addr.s_addr;
		} else {
			/* unknown socket */
			node.s_addr = 0;
		}
	}

	/* set address */
	memcpy (buff + index, &node, sizeof (struct in_addr));
	index += sizeof (struct in_addr);
	
	/* set Length */
	value16 = htons (index);
	memcpy (buff + CefC_O_Length, &value16, CefC_S_Length);
	
	/* send message */
	if (cefnetd_msg_buff_index + index > CefC_Cefnetd_Buff_Max) {
		cef_csmgr_send_msg_to_csmgrd (
				cs_stat, cefnetd_msg_buff, cefnetd_msg_buff_index);
		cefnetd_msg_buff_index = 0;
	}
	memcpy (&cefnetd_msg_buff[cefnetd_msg_buff_index], buff, index);
	cefnetd_msg_buff_index += index;
	
	return;
}
/*--------------------------------------------------------------------------------------
	Puts Content Object to excache
----------------------------------------------------------------------------------------*/
void
cef_csmgr_excache_item_push (
	CefT_Cs_Stat* cs_stat					/* Content Store status						*/
) {
	if (cefnetd_msg_buff_index > 0) {
		cef_csmgr_send_msg_to_csmgrd (cs_stat, cefnetd_msg_buff, cefnetd_msg_buff_index);
		cefnetd_msg_buff_index = 0;
	}
	
	return;
}
/*--------------------------------------------------------------------------------------
	Search and queue entry
----------------------------------------------------------------------------------------*/
void 
cef_csmgr_excache_lookup (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	int faceid,								/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	CefT_Parsed_Message* pm,				/* Parsed CEFORE message					*/
	CefT_Parsed_Opheader* poh,				/* Parsed Option Header						*/
	CefT_Pit_Entry* pe						/* PIT entry								*/
) {
	unsigned char buff[CefC_Max_Length] = {0};
	uint16_t index = 0;
	int res;
	
	if (poh->longlife_f) {
		return;
	}
	
	/* Create Interest message 		*/
	cef_csmgr_interest_msg_create (buff, &index, poh, pm);
	
	/* Send messages 				*/
	res = cef_csmgr_send_msg_to_csmgrd (cs_stat, buff, index);
	if (res < 0) {
		cef_log_write (CefC_Log_Warn, "%s (%s)\n", __func__, strerror (errno));
	}
	
	return;
}
/*--------------------------------------------------------------------------------------
	Get frame from received message
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
csmgr_frame_get (
	unsigned char* buff,					/* receive message							*/
	int buff_len,							/* message length							*/
	unsigned char* msg,						/* frame of csmgr message					*/
	int* frame_size,						/* frame length								*/
	uint8_t* type							/* message type								*/
) {
	unsigned char* wp;
	int new_len;
	uint16_t len;
	uint16_t value16;
	*frame_size = 0;
	
	/* check message size */
	if (buff_len <= CefC_Csmgr_Msg_HeaderLen) {
		return (buff_len);
	}
	
	/* check header */
	if ((buff[CefC_O_Fix_Ver] != CefC_Version) ||
		(buff[CefC_O_Fix_Type] >= CefC_Csmgr_Msg_Type_Num) ||
		(buff[CefC_O_Fix_Type] == CefC_Csmgr_Msg_Type_Invalid)) {
		/* get message length */
		wp = buff + 1;
		new_len = buff_len - 1;

		/* pass invalid message */
		while (new_len > CefC_Csmgr_Msg_HeaderLen) {
			/* check header */
			if ((wp[CefC_O_Fix_Ver] != CefC_Version) ||
				(wp[CefC_O_Fix_Type] >= CefC_Csmgr_Msg_Type_Num) ||
				(wp[CefC_O_Fix_Type] == CefC_Csmgr_Msg_Type_Invalid)) {
				new_len--;
				wp++;
				continue;
			}
			memcpy (work_msg_buff, buff, buff_len);
			memcpy (buff, &work_msg_buff[buff_len - new_len], new_len);
			
			return (csmgr_frame_get (buff, new_len, msg, frame_size, type));
		}
		return (0);
	}
	memcpy (&value16, buff + CefC_O_Length, CefC_S_Length);
	len = ntohs (value16);
	
	/* check message length */
	if ((len <= CefC_Csmgr_Msg_HeaderLen) || (len > CefC_Max_Msg_Size * 2)) {
		buff[0] = 0;
		return (csmgr_frame_get (buff, buff_len, msg, frame_size, type));
	}
	
	if (len > buff_len) {
		return (buff_len);
	}
	*type = buff[CefC_O_Fix_Type];
	
	/* get frame */
	memcpy (work_msg_buff, buff, buff_len);
	memcpy (msg, buff + CefC_Csmgr_Msg_HeaderLen, len - CefC_Csmgr_Msg_HeaderLen);
	*frame_size = (int) len - CefC_Csmgr_Msg_HeaderLen;
	
	if (buff_len - len > 0) {
		memcpy (buff, work_msg_buff + len, buff_len - len);
	}
	
	return (buff_len - len);
}

/*--------------------------------------------------------------------------------------
	Forwarding content object
----------------------------------------------------------------------------------------*/
int
csmgr_cob_forward (
	int faceid,									/* Face-ID to reply to the origin of 	*/
	unsigned char* msg,							/* Receive message						*/
	uint16_t msg_len,							/* Length of message					*/
	uint32_t chnk_num							/* Chunk Number of content				*/
) {
	uint16_t name_len;
	uint16_t name_off;
	uint16_t pay_len;
	uint16_t pay_off;
	uint32_t seqnum;
	
	/* send content object */
	if (cef_face_check_active (faceid) > 0) {
		
		if (msg[CefC_O_Fix_Type] == CefC_PT_OBJECT) {
			seqnum = cef_face_get_seqnum_from_faceid (faceid);
			cef_frame_seqence_update (msg, seqnum);
		}
		
		if (cef_face_is_local_face (faceid)) {
			cef_frame_payload_parse (
				msg, msg_len, &name_off, &name_len, &pay_off, &pay_len);
			if (pay_len != 0) {
				cef_face_object_send_iflocal (
					faceid, msg + name_off, name_len, msg + pay_off, pay_len, chnk_num);
			}
		} else {
			/* face is not local */
			cef_face_frame_send_forced (faceid, msg, msg_len);
		}
	} else {
		return (-1);
	}
	return (0);
}
/*--------------------------------------------------------------------------------------
	parse cob name
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_csmgr_cob_name_parse (
	unsigned char* buff,						/* receive message						*/
	int buff_len,								/* receive message length				*/
	uint16_t* index,							/* index of message						*/
	unsigned char* name,						/* cob name								*/
	uint16_t* name_len							/* cob name length						*/
) {
	uint16_t 	value16;
	
	if ((buff_len - (*index) - CefC_S_Length) < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "message parse error (cob name length)\n");
#endif // CefC_Debug
		return (-1);
	}
	memcpy (&value16, buff + (*index), CefC_S_Length);
	*name_len = ntohs (value16);
	*index += CefC_S_Length;
	if ((buff_len - (*index) - (*name_len)) < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "message parse error (cob name length)\n");
#endif // CefC_Debug
		return (-1);
	}
	memcpy (name, buff + (*index), (*name_len));
	*index += (*name_len);
	return (0);
}
/*--------------------------------------------------------------------------------------
	close socket
----------------------------------------------------------------------------------------*/
void
csmgr_sock_close (
	CefT_Cs_Stat* cs_stat					/* Content Store status						*/
) {
	if (cs_stat->local_sock != -1) {
		close (cs_stat->local_sock);
		cs_stat->local_sock = -1;
	}
	
	if (cs_stat->tcp_sock != -1) {
		close (cs_stat->tcp_sock);
		cs_stat->tcp_sock = -1;
	}
	
	return;
}
/*--------------------------------------------------------------------------------------
	Change str to value
----------------------------------------------------------------------------------------*/
int64_t								/* The return value is negative if an error occurs	*/
cef_csmgr_config_get_value (
	char* option,							/* csmgr option								*/
	char* value								/* String									*/
) {
	int i;
	uint64_t res;
	/* check num */
	for (i = 0 ; value[i] ; i++) {
		if (isdigit (value[i]) == 0) {
			return (-1);
		}
	}
	/* change str */
	res = (uint64_t)strtoull (value, NULL, 10);
	if (res == ULLONG_MAX) {
		if (errno == ERANGE) {
			/* overflow */
			return (-1);
		}
	}
	/* check num */
	if (res > UINT32_MAX) {
		return (-1);
	}
	return (res);
}
/*--------------------------------------------------------------------------------------
	Incoming cefping message
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_csmgr_excache_item_check (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	unsigned char* name,					/* Content URI								*/
	uint16_t name_len						/* Length of Content URI					*/
) {
	unsigned char buff[CefC_Max_Length] = {0};
	int buff_size;
	uint16_t index = 0;
	uint16_t value16;
	
	struct pollfd fds[1];
	int len;
	int res;
	uint8_t type;
	
	char port_str[NI_MAXSERV];
	int tmp_sock;
	
	/*----------------------------------------------------
		Sends the cefping request message
	------------------------------------------------------*/
	/* Creates the socket to csmgrd with TCP 		*/
	sprintf (port_str, "%d", cs_stat->tcp_port_num);
	tmp_sock = cef_csmgr_connect_tcp_to_csmgrd (cs_stat->peer_id_str, port_str);
	if (tmp_sock < 0) {
		return (-1);
	}
	
	/* Creates the Ping Request message 		*/
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_Cefping;
	index += CefC_Csmgr_Msg_HeaderLen;
	
	memcpy (buff + index, name, name_len);
	index += name_len;
	
	value16 = htons (index);
	memcpy (buff + CefC_O_Length, &value16, CefC_S_Length);
	
	/* Sends the created message 		*/
	res = write (tmp_sock, buff, index);
	if (res < 0) {
		close (tmp_sock);
		return (-1);
	}
	
	/*----------------------------------------------------
		Receives the cefping response message
	------------------------------------------------------*/
	fds[0].fd = tmp_sock;
	fds[0].events = POLLIN | POLLERR;
	memset (buff, 0, sizeof (buff));
	
	res = poll (fds, 1, CefC_Csmgr_Max_Wait_Response);
	if (res <= 0) {
		goto PINGREQ_POST;
	}
	if (fds[0].revents & (POLLERR | POLLNVAL | POLLHUP)) {
		goto PINGREQ_POST;
	}
	
	len = recv (fds[0].fd, buff, CefC_Max_Length, 0);
	
	if (len > 0) {
		/* Parses the received message 		*/
		len = csmgr_frame_get (buff, len, buff, &buff_size, &type);
		if (buff_size > 0) {
			if (type != CefC_Csmgr_Msg_Type_Cefping) {
				goto PINGREQ_POST;
			}
			/* Checks the result 		*/
			if (buff[0] == CefC_Csmgr_Cob_Exist) {
				close (tmp_sock);
				return (1);
			}
		}
	}
	
PINGREQ_POST:
	close (tmp_sock);
	return (-1);
}
/*--------------------------------------------------------------------------------------
	Incoming Cefinfo message
----------------------------------------------------------------------------------------*/
int											/* length of Cache Information				*/
cef_csmgr_excache_info_get (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	unsigned char* name,					/* Content URI								*/
	uint16_t name_len,						/* Length of Content URI					*/
	unsigned char* info,					/* cache information from csmgr 			*/
	uint16_t trace_flag						/* Trace Flag 								*/
) {
	unsigned char buff[CefC_Max_Length] = {0};
	uint16_t index = 0;
	uint16_t value16;
	
	struct pollfd fds[1];
	int len;
	int res;
	
	int tmp_sock;
	char port_str[NI_MAXSERV];
	
	/*----------------------------------------------------
		Sends the cefinfo request message
	------------------------------------------------------*/
	/* Creates the socket to csmgrd with TCP 		*/
	sprintf (port_str, "%d", cs_stat->tcp_port_num);
	tmp_sock = cef_csmgr_connect_tcp_to_csmgrd (cs_stat->peer_id_str, port_str);
	if (tmp_sock < 0) {
		return (-1);
	}
	
	/* Creates the cefinfo request message 		*/
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_Cefinfo;
	index += CefC_Csmgr_Msg_HeaderLen;
	
	if (trace_flag != 0) {
		buff[index] = 1;
	} else {
		buff[index] = 0;
	}
	index++;
	
	memcpy (buff + index, name, name_len);
	index += name_len;
	
	value16 = htons (index);
	memcpy (buff + CefC_O_Length, &value16, CefC_S_Length);
	
	/* Sends the created message 		*/
	res = write (tmp_sock, buff, index);
	if (res < 0) {
		close (tmp_sock);
		return (-1);
	}
	
	/*----------------------------------------------------
		Receives the cefping response message
	------------------------------------------------------*/
	fds[0].fd = tmp_sock;
	fds[0].events = POLLIN | POLLERR;
	memset (buff, 0, sizeof (buff));
	
	res = poll (fds, 1, CefC_Csmgr_Max_Wait_Response);
	if (res <= 0) {
		goto TRACEREQ_POST;
	}
	if (fds[0].revents & (POLLERR | POLLNVAL | POLLHUP)) {
		goto TRACEREQ_POST;
	}
	
	len = recv (fds[0].fd, buff, CefC_Max_Length, 0);
	
	if (len > CefC_S_TLF) {
		memcpy (info, buff, len);
		close (tmp_sock);
		return (len);
	}
	
TRACEREQ_POST:
	close (tmp_sock);
	return (-1);
}
/*--------------------------------------------------------------------------------------
	print hex dump
----------------------------------------------------------------------------------------*/
void
cef_csmgr_hex_print (
	unsigned char* text,					/* Text										*/
	int text_len							/* Text length								*/
) {
	int i;

	fprintf (stderr, "output Hex len = %d\n", text_len);
	for(i = 0; i < text_len; i++){
		fprintf (stderr, "%02x ", text[i]);
		if (((i + 1) % 16) == 0) fprintf (stderr, "\n");
	}
	fprintf (stderr, "\n");
}
#ifdef CefC_Ccore
/*--------------------------------------------------------------------------------------
	Retrieve cache capacity
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_csmgr_capacity_retrieve (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	uint64_t* cap							/* Capacity									*/
) {
	unsigned char buff[CefC_Max_Length] = {0};
	unsigned char msg[CefC_Max_Length] = {0};
	int buff_size;
	uint16_t index = 0;
	struct pollfd fds[1];
	int len;
	int res = 0;
	uint8_t type;
	char port_str[NI_MAXSERV];
	int tmp_sock;
	uint8_t result;
	uint16_t value16;
	uint64_t value64;

	if (cs_stat == NULL) {
		/* CS is not used */
		return (0);
	}

	/* Creates the socket to csmgrd with TCP */
	sprintf (port_str, "%d", cs_stat->tcp_port_num);
	tmp_sock = cef_csmgr_connect_tcp_to_csmgrd (cs_stat->peer_id_str, port_str);
	if (tmp_sock < 0) {
		/* Connection Failed */
		return (-1);
	}

	/* Creates the retrieve capacity message */
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_RCap;
	index += CefC_Csmgr_Msg_HeaderLen;
	/* Insert dummy data */
	buff[index] = 0;
	index++;
	value16 = htons (index);
	memcpy (buff + CefC_O_Length, &value16, CefC_S_Length);
	/* Sends the created message 		*/
	res = write (tmp_sock, buff, index);
	if (res < 0) {
		close (tmp_sock);
		return (-1);
	}

	/*----------------------------------------------------
		Receives the capacity response message
	------------------------------------------------------*/
	fds[0].fd = tmp_sock;
	fds[0].events = POLLIN | POLLERR;
	memset (buff, 0, sizeof (buff));

	res = poll (fds, 1, CefC_Csmgr_Max_Wait_Response);
	if ((res <= 0) || (fds[0].revents & (POLLERR | POLLNVAL | POLLHUP))) {
		close (tmp_sock);
		return (-1);
	}

	len = recv (fds[0].fd, buff, CefC_Max_Length, 0);
	if (len > 0) {
		/* Parses the received message */
		len = csmgr_frame_get (buff, len, msg, &buff_size, &type);
		if (buff_size > 0) {
			if (type != CefC_Csmgr_Msg_Type_RCap) {
				res = -1;
			} else {
				if (buff_size < (sizeof (result) + sizeof (value64))) {
					res = -1;
				} else {
					/* Checks the result */
					memcpy (&result, msg, sizeof (result));
					if (result == CcoreC_Success) {
						memcpy (&value64, msg + sizeof (result), sizeof (value64));
						*cap = cef_client_ntohb (value64);
						res = 1;
					} else {
						fprintf (stderr,
							"Failed to acquire the value inside Content Store.\n");
						res = -1;
					}
				}
			}
		}
	}
	close (tmp_sock);
	return (res);
}
/*--------------------------------------------------------------------------------------
	Update cache capacity
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_csmgr_capacity_update (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	uint64_t cap							/* Capacity									*/
) {
	unsigned char buff[CefC_Max_Length] = {0};
	unsigned char msg[CefC_Max_Length] = {0};
	int buff_size;
	uint16_t index = 0;
	struct pollfd fds[1];
	int len;
	int res = 0;
	uint8_t type;
	char port_str[NI_MAXSERV];
	int tmp_sock;
	uint8_t result;
	uint16_t value16;
	uint64_t value64;

	/* Creates the socket to csmgrd with TCP */
	sprintf (port_str, "%d", cs_stat->tcp_port_num);
	tmp_sock = cef_csmgr_connect_tcp_to_csmgrd (cs_stat->peer_id_str, port_str);
	if (tmp_sock < 0) {
		/* Connection Failed */
		return (-1);
	}

	/* Creates the retrieve capacity message */
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_SCap;
	index += CefC_Csmgr_Msg_HeaderLen;
	value64 = cef_client_htonb (cap);
	memcpy (buff + index, &value64, sizeof (uint64_t));
	index += sizeof (uint64_t);
	value16 = htons (index);
	memcpy (buff + CefC_O_Length, &value16, CefC_S_Length);
	/* Sends the created message 		*/
	res = write (tmp_sock, buff, index);
	if (res < 0) {
		close (tmp_sock);
		return (-1);
	}

	/*----------------------------------------------------
		Receives the capacity response message
	------------------------------------------------------*/
	fds[0].fd = tmp_sock;
	fds[0].events = POLLIN | POLLERR;
	memset (buff, 0, sizeof (buff));

	res = poll (fds, 1, CefC_Csmgr_Max_Wait_Response);
	if ((res <= 0) || (fds[0].revents & (POLLERR | POLLNVAL | POLLHUP))) {
		close (tmp_sock);
		return (-1);
	}

	len = recv (fds[0].fd, buff, CefC_Max_Length, 0);
	if (len > 0) {
		/* Parses the received message */
		len = csmgr_frame_get (buff, len, msg, &buff_size, &type);
		if (buff_size > 0) {
			if (type != CefC_Csmgr_Msg_Type_SCap) {
				res = -1;
			} else {
				if (buff_size < (sizeof (result))) {
					res = -1;
				} else {
					/* Checks the result */
					memcpy (&result, msg, sizeof (result));
					if (result == CcoreC_Success) {
						res = 1;
					} else {
						fprintf (stderr,
							"Failed to update the value inside Content Store.\n");
						res = -1;
					}
				}
			}
		}
	}
	close (tmp_sock);
	return (res);
}
/*--------------------------------------------------------------------------------------
	Retrieve content Lifetime
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_csmgr_con_lifetime_retrieve (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	char* name,								/* Content name								*/
	uint16_t name_len,						/* Name length								*/
	uint64_t* lifetime						/* Lifetime									*/
) {
	char port_str[NI_MAXSERV];
	int tmp_sock;
	unsigned char buff[CefC_Max_Length] = {0};
	int buff_size;
	unsigned char msg[CefC_Max_Length] = {0};
	uint16_t index = 0;
	uint16_t value16;
	int res = 0;
	struct pollfd fds[1];
	int len;
	uint8_t type;
	uint8_t result;
	uint64_t value64;

	if (cs_stat == NULL) {
		/* CS is not used */
		return (0);
	}

	/* Creates the socket to csmgrd with TCP */
	sprintf (port_str, "%d", cs_stat->tcp_port_num);
	tmp_sock = cef_csmgr_connect_tcp_to_csmgrd (cs_stat->peer_id_str, port_str);
	if (tmp_sock < 0) {
		/* Connection Failed */
		return (-1);
	}

	/* Creates the retrieve content lifetime message */
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_RCLT;
	index += CefC_Csmgr_Msg_HeaderLen;
	/* Set content name */
	value16 = htons (name_len);
	memcpy (buff + index, &value16, CefC_S_Length);
	memcpy (buff + index + sizeof (value16), name, name_len);
	index += sizeof (value16) + name_len;
	/* Set length */
	value16 = htons (index);
	memcpy (buff + CefC_O_Length, &value16, CefC_S_Length);
	/* Sends the created message 		*/
	res = write (tmp_sock, buff, index);
	if (res < 0) {
		close (tmp_sock);
		return (-1);
	}

	/*----------------------------------------------------
		Receives the capacity response message
	------------------------------------------------------*/
	fds[0].fd = tmp_sock;
	fds[0].events = POLLIN | POLLERR;
	memset (buff, 0, sizeof (buff));
	res = poll (fds, 1, CefC_Csmgr_Max_Wait_Response);
	if ((res <= 0) || (fds[0].revents & (POLLERR | POLLNVAL | POLLHUP))) {
		close (tmp_sock);
		return (-1);
	}

	len = recv (fds[0].fd, buff, CefC_Max_Length, 0);
	if (len > 0) {
		/* Parses the received message */
		len = csmgr_frame_get (buff, len, msg, &buff_size, &type);
		if (buff_size > 0) {
			if (type != CefC_Csmgr_Msg_Type_RCLT) {
				res = -1;
			} else {
				if (buff_size < (sizeof (result) + sizeof (value64))) {
					res = -1;
				} else {
					/* Checks the result */
					memcpy (&result, msg, sizeof (result));
					if (result == CcoreC_Success) {
						memcpy (&value64, msg + sizeof (result), sizeof (value64));
						*lifetime = cef_client_ntohb (value64);
						res = 1;
					} else {
						cef_log_write (CefC_Log_Warn,
							"Failed to acquire the value inside Content Store.\n");
						res = -1;
					}
				}
			}
		}
	}
	close (tmp_sock);
	return (res);
}
/*--------------------------------------------------------------------------------------
	Set content Lifetime
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_csmgr_con_lifetime_set (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	char* name,								/* Content name								*/
	uint16_t name_len,						/* Name length								*/
	uint64_t lifetime						/* Lifetime									*/
) {
	char port_str[NI_MAXSERV];
	int tmp_sock;
	unsigned char buff[CefC_Max_Length] = {0};
	int buff_size;
	unsigned char msg[CefC_Max_Length] = {0};
	uint16_t index = 0;
	uint16_t value16;
	int res = 0;
	struct pollfd fds[1];
	int len;
	uint8_t type;
	uint8_t result;
	uint64_t value64;

	if (cs_stat == NULL) {
		/* CS is not used */
		return (0);
	}

	/* Creates the socket to csmgrd with TCP */
	sprintf (port_str, "%d", cs_stat->tcp_port_num);
	tmp_sock = cef_csmgr_connect_tcp_to_csmgrd (cs_stat->peer_id_str, port_str);
	if (tmp_sock < 0) {
		/* Connection Failed */
		return (-1);
	}

	/* Creates the retrieve content lifetime message */
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_SCLT;
	index += CefC_Csmgr_Msg_HeaderLen;
	/* Set content name */
	value16 = htons (name_len);
	memcpy (buff + index, &value16, CefC_S_Length);
	memcpy (buff + index + sizeof (value16), name, name_len);
	index += sizeof (value16) + name_len;
	/* Set Lifetime */
	value64 = cef_client_htonb (lifetime);
	memcpy (buff + index, &value64, sizeof (value64));
	index += sizeof (value64);
	/* Set length */
	value16 = htons (index);
	memcpy (buff + CefC_O_Length, &value16, CefC_S_Length);
	/* Sends the created message 		*/
	res = write (tmp_sock, buff, index);
	if (res < 0) {
		close (tmp_sock);
		return (-1);
	}

	/*----------------------------------------------------
		Receives the capacity response message
	------------------------------------------------------*/
	fds[0].fd = tmp_sock;
	fds[0].events = POLLIN | POLLERR;
	memset (buff, 0, sizeof (buff));
	res = poll (fds, 1, CefC_Csmgr_Max_Wait_Response);
	if ((res <= 0) || (fds[0].revents & (POLLERR | POLLNVAL | POLLHUP))) {
		close (tmp_sock);
		return (-1);
	}

	len = recv (fds[0].fd, buff, CefC_Max_Length, 0);
	if (len > 0) {
		/* Parses the received message */
		len = csmgr_frame_get (buff, len, msg, &buff_size, &type);
		if (buff_size > 0) {
			if (type != CefC_Csmgr_Msg_Type_RCLT) {
				res = -1;
			} else {
				if (buff_size < (sizeof (result))) {
					res = -1;
				} else {
					/* Checks the result */
					memcpy (&result, msg, sizeof (result));
					if (result == CcoreC_Success) {
						res = 1;
					} else {
						cef_log_write (CefC_Log_Warn,
							"Failed to set the value inside Content Store.\n");
						res = -1;
					}
				}
			}
		}
	}
	close (tmp_sock);
	return (res);
}
#endif // CefC_Ccore
#ifndef CefC_Dtc
/*--------------------------------------------------------------------------------------
	Increment Access Count in excache
----------------------------------------------------------------------------------------*/
static void
cef_csmgr_excache_access_increment (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	const unsigned char* key,				/* Content name								*/
	uint32_t klen,							/* Content name length						*/
	uint32_t chnk_num						/* Content Chunk Number 					*/
) {
	unsigned char buff[CefC_Max_Length] = {0};
	uint16_t index = 0;
	uint16_t value16;
	uint32_t value32;
	int res;

	/* Create Upload Request message */
	/* set header */
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_Increment;
	index += CefC_Csmgr_Msg_HeaderLen;

	/* set chunk number 	*/
	value32 = htonl (chnk_num);
	memcpy (buff + index, &value32, sizeof (uint32_t));
	index += sizeof (uint32_t);
	
	/* set cob name */
	value16 = htons ((uint16_t)klen);
	memcpy (buff + index, &value16, CefC_S_Length);
	memcpy (buff + index + CefC_S_Length, key, (uint16_t)klen);
	index += CefC_S_Length + (uint16_t)klen;
	
	/* set Length */
	value16 = htons (index);
	memcpy (buff + CefC_O_Length, &value16, CefC_S_Length);

	/* send message */
	res = cef_csmgr_send_msg_to_csmgrd (cs_stat, buff, index);
	if (res < 0) {
		cef_log_write (CefC_Log_Warn, "%s (%s)\n", __func__, strerror (errno));
	}

	return;
}
#endif // CefC_Dtc
/*--------------------------------------------------------------------------------------
	Create Interest message for csmgrd
----------------------------------------------------------------------------------------*/
static void
cef_csmgr_interest_msg_create (
	unsigned char buff[],					/* Interest message							*/
	uint16_t* index,						/* Length of message						*/
	CefT_Parsed_Opheader* poh,				/* Parsed Option Header						*/
	CefT_Parsed_Message* pm					/* Parsed CEFORE message					*/
) {
	uint16_t value16;
	uint16_t value16_nw;
	uint32_t value32_nw;
	int chunk_field_len = CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum;
	
	/* set header */
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_Interest;
	*index += CefC_Csmgr_Msg_HeaderLen;
	
	/* Sets Interest Type 		*/
	buff[*index] = CefC_Csmgr_Interest_Type_Normal;
	*index += sizeof (uint8_t);
	
	/* set Chunk num flag */
	if (pm->chnk_num_f) {
		buff[*index] = CefC_Csmgr_Interest_ChunkNum_Exist;
		value16 = pm->name_len - chunk_field_len;
	} else {
		buff[*index] = CefC_Csmgr_Interest_ChunkNum_NotExist;
		value16 = pm->name_len;
	}
	*index += sizeof (uint8_t);

	/* Sets Name Length 	*/
	value16_nw = htons (value16);
	memcpy (buff + *index, &value16_nw, sizeof (uint16_t));
	
	/* Sets Name 			*/
	memcpy (buff + *index + CefC_S_Length, pm->name, value16);
	*index += CefC_S_Length + value16;
	
	/* Sets chunk num		 */
	if (pm->chnk_num_f) {
		value32_nw = htonl (pm->chnk_num);
		memcpy (buff + *index, &value32_nw, CefC_S_ChunkNum);
		*index += CefC_S_ChunkNum;
	}
	
	/* set Length */
	value16_nw = htons (*index);
	memcpy (buff + CefC_O_Length, &value16_nw, CefC_S_Length);
	
	return;
}
/*--------------------------------------------------------------------------------------
	Connect csmgrd with TCP socket
----------------------------------------------------------------------------------------*/
int											/* created socket							*/
cef_csmgr_connect_tcp_to_csmgrd (
	const char* dest, 
	const char* port
) {
	struct addrinfo hints;
	struct addrinfo* res;
	struct addrinfo* cres;
	struct addrinfo* nres;
	int err;
	unsigned char cmd[CefC_Csmgr_Cmd_MaxLen];
	int sock;
	int flag;
	fd_set readfds;
	struct timeval timeout;
	int ret;
	
	/* Creates the hint 		*/
	memset (&hints, 0, sizeof (hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;
	
	/* Obtains the addrinfo 	*/
	if ((err = getaddrinfo (dest, port, &hints, &res)) != 0) {
		fprintf (stderr, "ERROR : connect_tcp_to_csmgrd (getaddrinfo)\n");
		return (-1);
	}
	
	for (cres = res ; cres != NULL ; cres = nres) {
		nres = cres->ai_next;
		
		sock = socket (cres->ai_family, cres->ai_socktype, cres->ai_protocol);
		
		if (sock < 0) {
			free (cres);
			continue;
		}
		
		flag = fcntl (sock, F_GETFL, 0);
		if (flag < 0) {
			close (sock);
			free (cres);
			continue;
		}
		if (fcntl (sock, F_SETFL, flag | O_NONBLOCK) < 0) {
			close (sock);
			free (cres);
			continue;
		}
		if (connect (sock, cres->ai_addr, cres->ai_addrlen) < 0) {
			/* NOP */;
		}
		
		FD_ZERO (&readfds);
		FD_SET (sock, &readfds);
		timeout.tv_sec 	= 5;
		timeout.tv_usec = 0;
		ret = select (sock + 1, &readfds, NULL, NULL, &timeout);
		
		if (ret == 0) {
			close (sock);
			free (cres);
			continue;
		} else if (ret < 0) {
			close (sock);
			free (cres);
			continue;
		} else {
			if (FD_ISSET (sock, &readfds)) {
				ret = read (sock, cmd, CefC_Csmgr_Cmd_MaxLen);
				if (ret < 1) {
					close (sock);
					free (cres);
					continue;
				} else {
					if (memcmp (CefC_Csmgr_Cmd_ConnOK, cmd, ret)) {
						close (sock);
						free (cres);
						continue;
					}
//					cmd[ret] = 0x00;
//					fprintf (stderr, "# %s\n", cmd);
					/* NOP */;
				}
			}
		}
		freeaddrinfo (res);
		return (sock);
	}
	return (-1);
}
#ifdef CefC_Dtc
/*--------------------------------------------------------------------------------------
	Create Content Store Manager Status
----------------------------------------------------------------------------------------*/
CefT_Cs_Stat*						/* The return value is null if an error occurs		*/
cef_csmgr_dtc_stat_create (
	void
) {
	CefT_Cs_Stat* cs_stat = NULL;
	
	/* allocate memory */
	cs_stat = (CefT_Cs_Stat*) malloc (sizeof (CefT_Cs_Stat));
	if (cs_stat == NULL) {
		cef_log_write (CefC_Log_Error, "%s (malloc CefT_Cs_Stat)\n", __func__);
		return (NULL);
	}
	memset (cs_stat, 0, sizeof (CefT_Cs_Stat));
	cs_stat->tx_que = NULL;
	cs_stat->local_sock = -1;
	cs_stat->tcp_sock 	= -1;
	
	/* Create memory cache */
	/* create Cs_Tx_Que */
	cs_stat->tx_que = cef_rngque_create (CefC_Tx_Que_Size);
	cs_stat->tx_cob_mp = cef_mpool_init (
									"CefCsCobQue",
									sizeof (CefT_Cs_Tx_Elem_Cob),
									CefC_Tx_Que_Size);
	if (cs_stat->tx_cob_mp == 0) {
		cef_csmgr_dtc_stat_destroy (&cs_stat);
		cef_log_write (CefC_Log_Error, "%s (mpool CefCsCobQue)\n", __func__);
		return (NULL);
	}
	cs_stat->tx_que_mp =
			cef_mpool_init ("CefCsTxQue", sizeof (CefT_Cs_Tx_Elem), CefC_Tx_Que_Size);
	if (cs_stat->tx_que_mp == 0) {
		cef_csmgr_dtc_stat_destroy (&cs_stat);
		cef_log_write (CefC_Log_Error, "%s (mpool CefCsTxQue)\n", __func__);
		return (NULL);
	}

	/* Set cache cap */
	cs_stat->cache_cap = 4096;
	if (cs_stat->cache_cap > 0) {
		/* create CS */
		cs_stat->cs_cob_entry_mp = cef_mpool_init (
			"CefCsCobEnt", sizeof (CefT_Cob_Entry), cs_stat->cache_cap);
		if (cs_stat->cs_cob_entry_mp == 0) {
			cef_csmgr_dtc_stat_destroy (&cs_stat);
			cef_log_write (CefC_Log_Error, "%s (mpool CefCsCobEnt)\n", __func__);
			return (NULL);
		}
		cef_log_write (CefC_Log_Info, 
			"The maximum number of cached Cobs is %u\n", cs_stat->cache_cap);
		
		cs_stat->cob_table = cef_hash_tbl_create (
			(uint16_t) cs_stat->cache_cap + CefC_Csmgr_Max_Table_Margin);
		if (cs_stat->cob_table == (CefT_Hash_Handle) NULL) {
			cef_log_write (CefC_Log_Error, "%s (creation buffer)\n", __func__);
			cef_csmgr_dtc_stat_destroy (&cs_stat);
		}
	} else {
		cs_stat->cob_table = (CefT_Hash_Handle) NULL;
	}

	return (cs_stat);
}
/*--------------------------------------------------------------------------------------
	Destroy Content Store Status
----------------------------------------------------------------------------------------*/
void
cef_csmgr_dtc_stat_destroy (
	CefT_Cs_Stat** cs_stat					/* Content Store Status						*/
) {
	CefT_Cs_Stat* stat = *cs_stat;

	if (stat == NULL) {
		return;
	}

	if (stat->cob_table != (CefT_Hash_Handle)NULL) {
		cef_hash_tbl_destroy (stat->cob_table);
	}
	if (stat->tx_que != NULL) {
		cef_rngque_destroy (stat->tx_que);
	}
	if (stat->tx_cob_mp != 0) {
		cef_mpool_destroy (stat->tx_cob_mp);
	}
	if (stat->tx_que_mp != 0) {
		cef_mpool_destroy (stat->tx_que_mp);
	}
	if (stat->cs_cob_entry_mp != 0) {
		cef_mpool_destroy (stat->cs_cob_entry_mp);
	}

	if (stat != NULL) {
		free (stat);
		*cs_stat = NULL;
	}
	return;
}
/*--------------------------------------------------------------------------------------
	Puts Content Object to Android temp cache
----------------------------------------------------------------------------------------*/
void
cef_csmgr_dtc_item_put (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t msg_len,						/* length of received message				*/
	CefT_Parsed_Message* pm,				/* Parsed CEFORE message					*/
	CefT_Parsed_Opheader* poh				/* Parsed Option header						*/
) {
	uint64_t nowt = cef_client_present_timeus_get ();

	/* Checks cache time 		*/
	if (poh->cachetime_f) {
		if (poh->cachetime < nowt) {
			return;
		}
	} else {
		return;
	}
	if (pm->expiry > 0) {
		if (pm->expiry > poh->cachetime) {
			pm->expiry = poh->cachetime;
		} else {
			poh->cachetime = pm->expiry;
		}
	} else {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "pm->expiry == 0\n");
#endif // CefC_Debug
		return;
	}
	
	/* Inserts the Cob into temporary cache 	*/
	cef_csmgr_cache_insert (cs_stat, msg, msg_len, pm, poh);
	return;
}
#endif // CefC_Dtc
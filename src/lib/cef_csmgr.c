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
 * cef_csmgr.c
 */

#define __CEF_CSMGR_SOURCE__

//#define	__DEV_CEF_CSMGR_SEND__

#define		CEF_CSMGR_SEND_USLEEP	100000
#define		CEF_CSMGR_SEND_TIMEOUT	10000

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <cefore/cef_client.h>
#include <cefore/cef_csmgr.h>
#include <cefore/cef_define.h>
#include <cefore/cef_frame.h>
#include <cefore/cef_face.h>
#include <cefore/cef_log.h>
#include <cefore/cef_mem_cache.h>
#include <cefore/cef_pthread.h>

uint32_t bchunk = 0xFFFF;

/****************************************************************************************
 Macros
 ****************************************************************************************/
#define	DEMO_RETRY_NUM	10

#define	CefC_PipeWrite_RetryMax		30
#define	CefC_PipeWrite_RetryWait(n)	usleep((n+1)*1000)

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

/*--------------------------------------------------------------------------------------
	Increment Access Count in excache
----------------------------------------------------------------------------------------*/
static void
cef_csmgr_excache_access_increment (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	const unsigned char* key,				/* Content name								*/
	uint32_t klen,							/* Content name length						*/
	uint32_t chunk_num						/* Content Chunk Number 					*/
);
/*--------------------------------------------------------------------------------------
	Create Interest message for csmgr
----------------------------------------------------------------------------------------*/
static void
cef_csmgr_interest_msg_create (
	unsigned char buff[],					/* Interest message							*/
	uint16_t* index,						/* Length of message						*/
	CefT_CcnMsg_OptHdr* poh,				/* Parsed Option Header						*/
	CefT_CcnMsg_MsgBdy* pm					/* Parsed CEFORE message					*/
);
/*--------------------------------------------------------------------------------------
	Send message from cefnetd to csmgr
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
cef_csmgr_send_msg_to_csmgr (
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
	uint8_t		cs_mode
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
	cs_stat->pipe_fd[0] = -1;
	cs_stat->pipe_fd[1] = -1;
	cs_stat->to_csmgrd_pipe_fd[0] = -1;
	cs_stat->to_csmgrd_pipe_fd[1] = -1;

	/* read config */
	if(cs_mode != CefC_Cache_Type_ExConpub){
		res = cef_csmgr_config_read (cs_stat);
		if (res < 0) {
			cef_log_write (CefC_Log_Error, "%s (Loading csmgrd.conf)\n", __func__);
			cef_csmgr_stat_destroy (&cs_stat);
			return (NULL);
		}
	} else {
		res = cef_csmgr_config_read_for_conpub (cs_stat);
		if (res < 0) {
			cef_log_write (CefC_Log_Error, "%s (Loading conpubd.conf)\n", __func__);
			cef_csmgr_stat_destroy (&cs_stat);
			return (NULL);
		}
	}

#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Fine, "cs_stat:socket=%s, peer=%s:%d\n",
		cs_stat->local_sock_name, cs_stat->peer_id_str, cs_stat->tcp_port_num);
#endif // CefC_Debug

	if (cs_stat->cache_type == CefC_Cache_Type_Excache) {
		if ((strcmp (cs_stat->peer_id_str, "localhost")) &&
			(strcmp (cs_stat->peer_id_str, "127.0.0.1"))) {
			sprintf (port_str, "%d", cs_stat->tcp_port_num);
			cs_stat->tcp_sock
				= cef_csmgr_connect_tcp_to_csmgr (cs_stat->peer_id_str, port_str);
			if (cs_stat->tcp_sock < 0) {
				cef_log_write (CefC_Log_Error, "cef_csmgr_connect_tcp_to_csmgr(%s:%s) failure, "
						"If you have customized the csmgrd port number, "
						"also check CSMGR_PORT_NUM in cefnetd.conf.\n",
					cs_stat->peer_id_str, port_str);
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Fine, "cef_csmgr_connect_tcp_to_csmgr(%s:%s) failure, "
						"If you have customized the csmgrd port number, "
						"also check CSMGR_PORT_NUM in cefnetd.conf.\n",
					cs_stat->peer_id_str, port_str);
#endif // CefC_Debug
				cef_csmgr_stat_destroy (&cs_stat);
				return (NULL);
			}
		} else {
			cs_stat->local_sock = cef_csmgr_csmgr_connect_local (cs_stat);

			if (cs_stat->local_sock < 0) {
				cef_log_write (CefC_Log_Error, "cef_csmgr_csmgr_connect_local(%s) failure, "
						"If you have customized the csmgrd port number, "
						"also check CSMGR_PORT_NUM in cefnetd.conf.\n",
					cs_stat->local_sock_name);
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Fine, "cef_csmgr_csmgr_connect_local(%s) failure, "
						"If you have customized the csmgrd port number, "
						"also check CSMGR_PORT_NUM in cefnetd.conf.\n",
					cs_stat->local_sock_name);
#endif // CefC_Debug
				cef_csmgr_stat_destroy (&cs_stat);
				return (NULL);
			}
		}

		/*###########*/
		{
		int flags;
		/* Create socket for communication between cefnetd and memory cache */
		if ( socketpair(AF_UNIX,SOCK_STREAM, 0, cs_stat->to_csmgrd_pipe_fd) == -1 ) {
			cef_csmgr_stat_destroy (&cs_stat);
			cef_log_write (CefC_Log_Error, "%s to_csmgrd pair socket creation error (%s)\n"
							, __func__, strerror(errno));
			return (NULL);
	  	}
		/* Set cefnetd side socket as non-blocking I/O */
		if ( (flags = fcntl(cs_stat->to_csmgrd_pipe_fd[0], F_GETFL, 0) ) < 0) {
			cef_log_write (CefC_Log_Error, "%s fcntl error (%s)\n"
							, __func__, strerror(errno));
			return (NULL);
		}
		flags |= O_NONBLOCK;
		if (fcntl(cs_stat->to_csmgrd_pipe_fd[0], F_SETFL, flags) < 0) {
			cef_log_write (CefC_Log_Error, "%s fcntl error (%s)\n"
							, __func__, strerror(errno));
			return (NULL);
		}
		pthread_t cef_csmgr_send_csmgrd_th;
		if (cef_pthread_create(&cef_csmgr_send_csmgrd_th, NULL
				, &cef_csmgr_send_to_csmgrd_thread, (cs_stat)) == -1) {
			cef_csmgr_stat_destroy (&cs_stat);
				cef_log_write (CefC_Log_Error
							, "%s Failed to create the new thread(cef_csmgr_send_to_csmgrd_thread)\n"
							, __func__);
			return (NULL);
		}
		}
		/*###########*/
	}
#ifdef CefC_Conpub
	else
	if (cs_stat->cache_type == CefC_Cache_Type_ExConpub) {
		if ((strcmp (cs_stat->peer_id_str, "localhost")) &&
			(strcmp (cs_stat->peer_id_str, "127.0.0.1"))) {
			sprintf (port_str, "%d", cs_stat->tcp_port_num);
			cs_stat->tcp_sock
				= cef_csmgr_connect_tcp_to_csmgr (cs_stat->peer_id_str, port_str);
			if (cs_stat->tcp_sock < 0) {
				cef_log_write (CefC_Log_Error, "cef_csmgr_connect_tcp_to_csmgr(%s:%s) failure, "
						"If you have customized the conpubd port number, "
						"also check CSMGR_PORT_NUM in cefnetd.conf.\n",
					cs_stat->peer_id_str, port_str);
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Fine, "cef_csmgr_connect_tcp_to_csmgr(%s:%s) failure, "
						"If you have customized the conpubd port number, "
						"also check CSMGR_PORT_NUM in cefnetd.conf.\n",
					cs_stat->peer_id_str, port_str);
#endif // CefC_Debug
				cef_csmgr_stat_destroy (&cs_stat);
				return (NULL);
			}
		} else {
			cs_stat->local_sock = cef_csmgr_csmgr_connect_local (cs_stat);

			if (cs_stat->local_sock < 0) {
				cef_log_write (CefC_Log_Error, "cef_csmgr_csmgr_connect_local(%s) failure, "
						"If you have customized the conpubd port number, "
						"also check CSMGR_PORT_NUM in cefnetd.conf.\n",
					cs_stat->local_sock_name);
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Fine, "cef_csmgr_csmgr_connect_local(%s) failure, "
						"If you have customized the conpubd port number, "
						"also check CSMGR_PORT_NUM in cefnetd.conf.\n",
					cs_stat->local_sock_name);
#endif // CefC_Debug
				cef_csmgr_stat_destroy (&cs_stat);
				return (NULL);
			}
		}
	}
#endif //CefC_Conpub
#ifdef CefC_CefnetdCache
	else
	if (cs_stat->cache_type == CefC_Cache_Type_Localcache) {
		int flags;
		/* Create socket for communication between cednetd and memory cache */
		if ( socketpair(AF_UNIX,SOCK_DGRAM, 0, cs_stat->pipe_fd) == -1 ) {
			cef_csmgr_stat_destroy (&cs_stat);
			cef_log_write (CefC_Log_Error, "%s pair socket creation error (%s)\n"
							, __func__, strerror(errno));
			return (NULL);
	  	}
		/* Set cefnetd side socket as non-blocking I/O */
		if ( (flags = fcntl(cs_stat->pipe_fd[0], F_GETFL, 0) ) < 0) {
			cef_csmgr_stat_destroy (&cs_stat);
			cef_log_write (CefC_Log_Error, "%s fcntl error (%s)\n"
							, __func__, strerror(errno));
			return (NULL);
		}
		flags |= O_NONBLOCK;
		if (fcntl(cs_stat->pipe_fd[0], F_SETFL, flags) < 0) {
			cef_csmgr_stat_destroy (&cs_stat);
			cef_log_write (CefC_Log_Error, "%s fcntl error (%s)\n"
							, __func__, strerror(errno));
			return (NULL);
		}
	}
#endif

	/* Create memory cache */
	if (cs_stat->cache_type != CefC_Default_Cache_Type) {
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
		cef_dbg_write (CefC_Dbg_Fine, "CACHE_TYPE     != CefC_Default_Cache_Type\n");
		cef_dbg_write (CefC_Dbg_Fine, "CACHE_CAPACITY =  %u\n", cs_stat->cache_cap);
#endif // CefC_Debug

#ifdef	CefC_CefnetdCache
		if (cs_stat->cache_type != CefC_Cache_Type_Localcache) {
#endif  //CefC_CefnetdCache

			cs_stat->cob_table = (CefT_Hash_Handle) NULL;
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
					"The maximum number of cached Cobs is %u\n", cs_stat->cache_cap);
				/* create hash table for work buffer */
				cs_stat->cob_table = cef_hash_tbl_create_ext (
					(uint16_t) cs_stat->cache_cap + CefC_Csmgr_Max_Table_Margin, CefC_Hash_Coef_Cache);
				if (cs_stat->cob_table == (CefT_Hash_Handle) NULL) {
					cef_log_write (CefC_Log_Error, "%s (creation buffer)\n", __func__);
					cef_csmgr_stat_destroy (&cs_stat);
					return (NULL);
				}
			}
#ifdef	CefC_CefnetdCache
		} else
		if (cs_stat->cache_type == CefC_Cache_Type_Localcache) {
			pthread_t cef_mem_cache_put_th;
			pthread_t cef_mem_cache_clear_th;
			int rtc;
			rtc = cef_mem_cache_init (cs_stat->cache_cap);
			if(rtc != 0){
				cef_csmgr_stat_destroy (&cs_stat);
				cef_log_write (CefC_Log_Error
								, "%s Failed to initialize cefnetd on memory cache\n"
								, __func__);
				return (NULL);
			}
			if (cef_pthread_create(&cef_mem_cache_put_th, NULL
							, &cef_mem_cache_put_thread, &(cs_stat->pipe_fd[1])) == -1) {
				cef_csmgr_stat_destroy (&cs_stat);
				cef_log_write (CefC_Log_Error
								, "%s Failed to create the new thread(cef_mem_cache_put_thead)\n"
								, __func__);
				return (NULL);
			}
			if (cef_pthread_create(&cef_mem_cache_clear_th, NULL
								, &cef_mem_cache_clear_thread, &(cs_stat->local_cache_interval)) == -1) {
				cef_csmgr_stat_destroy (&cs_stat);
				cef_log_write (CefC_Log_Error
								, "%s Failed to create the new thread(cef_mem_cache_clear_thead)\n"
								, __func__);
				return (NULL);
			}
		}
#endif  //CefC_CefnetdCache
	}

	if (cefnetd_msg_buff) {
		free (cefnetd_msg_buff);
	}
	cefnetd_msg_buff = malloc (sizeof (unsigned char) * CefC_CsPipeBuffSize);
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
	Create the work buffer for csmgr
----------------------------------------------------------------------------------------*/
unsigned char*
cef_csmgr_buffer_init (
	void
) {
	if (work_msg_buff) {
		free (work_msg_buff);
	}
	work_msg_buff = malloc (sizeof (unsigned char) * CefC_CsPipeBuffSize);
	if (work_msg_buff == NULL) {
		return (NULL);
	}

	return (work_msg_buff);
}
/*--------------------------------------------------------------------------------------
	Destroy the work buffer for csmgr
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
	char	filepath[PATH_MAX+16];					/* file name						*/
	char	confdir_path[PATH_MAX];					/* dirctory path					*/

	char	param[4096] = {0};						/* parameter						*/
	char	param_buff[4096] = {0};					/* param buff						*/
	int		len;									/* read length						*/

	char*	option;									/* deny option						*/
	char*	value;									/* parameter						*/

	int		i, n;
	int64_t	res;

	char 	local_sock_id[CefC_LOCAL_SOCK_ID_SIZ+1] = {"0"};

	/* Obtains the directory path where the cefnetd's config file is located. */
	cef_client_config_dir_get (confdir_path);

	if (mkdir (confdir_path, 0777) != 0) {
		if (errno == ENOENT) {
			cef_log_write (CefC_Log_Error, "%s (mkdir %s)\n", __func__, confdir_path);
			return (-1);
		}
	}
	snprintf (filepath, sizeof(filepath), "%s/cefnetd.conf", confdir_path);

	/* Opens the cefnetd's config file. */
	fp = fopen (filepath, "r");
	if (fp == NULL) {
		fp = fopen (filepath, "w");
		if (fp == NULL) {
			cef_log_write (CefC_Log_Error, "%s (open cefnetd.conf)\n", __func__);
			return (-1);
		}
		fclose (fp);
		fp = fopen (filepath, "r");
	}

	/* Set default value */
	cs_stat->cache_type  	= CefC_Default_Cache_Type;
	cs_stat->def_rct		= CefC_Default_Def_Rct;
	cs_stat->cache_cap 		= CefC_Default_Cache_Capacity;
	cs_stat->tcp_port_num 	= CefC_Default_Tcp_Prot;
	strcpy (cs_stat->peer_id_str, CefC_Default_Node_Path);
#ifdef CefC_CefnetdCache
	cs_stat->local_cache_capacity = 65535;
	cs_stat->local_cache_interval = 60;
#endif //CefC_CefnetdCache

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
		if (strcmp (option, "CS_MODE") == 0) {
			res = cef_csmgr_config_get_value (option, value);
			cs_stat->cache_type = res;
		} else if (strcmp (option, "BUFFER_CAPACITY") == 0) {
			res = cef_csmgr_config_get_value (option, value);
			if ((res < 0) || (res > CefC_Csmgr_Max_Table_Num)) {
				cef_log_write (CefC_Log_Error,
					"BUFFER_CAPACITY must be higher than 0 and lower than 65536.\n");
				fclose (fp);
				return (-1);
			}
			cs_stat->cache_cap = res;
		} else if (strcmp (option, "CSMGR_NODE") == 0) {
			strcpy (cs_stat->peer_id_str, value);
		} else if (strcmp (option, "CSMGR_PORT_NUM") == 0) {
			res = cef_csmgr_config_get_value (option, value);
			if ((res < 1025) || (res > 65535)) {
				cef_log_write (CefC_Log_Error,
					"CSMGR_PORT_NUM must be higher than 1024 and lower than 65536.\n");
				fclose (fp);
				return (-1);
			}
			cs_stat->tcp_port_num = res;
		} else if (strcmp (option, CefC_ParamName_LocalSockId) == 0) {
			if (strlen (value) > CefC_LOCAL_SOCK_ID_SIZ) {
				cef_log_write (CefC_Log_Error,
					"%s must be shorter than %d.\n",
						CefC_ParamName_LocalSockId, CefC_LOCAL_SOCK_ID_SIZ);
				fclose (fp);
				return (-1);
			}
			strcpy (local_sock_id, value);
		}
		else if (strcmp (option, "LOCAL_CACHE_DEFAULT_RCT") == 0) {
			res = cef_csmgr_config_get_value (option, value);
			if ((res < 1) || (res > 3600)) {
				cef_log_write (CefC_Log_Error,
				"LOCAL_CACHE_DEFAULT_RCT must be higher than 1 and lower than 3600.\n");
				fclose (fp);
				return (-1);
			}
			cs_stat->def_rct = (uint32_t)(res * 1000000llu);
		}
#ifdef CefC_CefnetdCache
		else if (strcmp (option, "LOCAL_CACHE_CAPACITY") == 0) {
			res = cef_csmgr_config_get_value (option, value);
			if ((res <= 1) || (res > 8000000)) {
				cef_log_write (CefC_Log_Error,
					"LOCAL_CACHE_CAPACITY must be greater than 1 and less than or equal to 8,000,000.\n");
				fclose (fp);
				return (-1);
			}
			cs_stat->local_cache_capacity = res;
		}
		else if (strcmp (option, "LOCAL_CACHE_INTERVAL") == 0) {
			res = cef_csmgr_config_get_value (option, value);
			if ((res <= 1) || (res >= 86400)) {
				cef_log_write (CefC_Log_Error,
					"LOCAL_CACHE_INTERVAL must be higher than 1 and lower than 86400.\n");
				fclose (fp);
				return (-1);
			}
			cs_stat->local_cache_interval = res;
		}
#endif //CefC_CefnetdCache
		else {
			/* NOP */;
		}
	}
#ifdef CefC_CefnetdCache
	if(cs_stat->cache_type == CefC_Cache_Type_Localcache) {
		cef_log_write (CefC_Log_Info, "Local cache expire check interval: %u\n", cs_stat->local_cache_interval);
	}
#endif //CefC_CefnetdCache
	fclose (fp);
#ifdef CefC_CefnetdCache
	if(cs_stat->cache_type == CefC_Cache_Type_Localcache) {
		cs_stat->cache_cap = cs_stat->local_cache_capacity;
	}
#endif //CefC_CefnetdCache

	if (cs_stat->cache_type == CefC_Cache_Type_Excache) {
		sprintf (cs_stat->local_sock_name,
			"/tmp/csmgr_%d.%s", cs_stat->tcp_port_num, local_sock_id);

#if 0
	snprintf (filepath, sizeof(filepath), "%s/csmgrd.conf", confdir_path);

	fp = fopen (filepath, "r");
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
				cef_log_write (CefC_Log_Error,
				"CACHE_DEFAULT_RCT must be higher than 1000 and lower than 3600000.\n");
				fclose (fp);
				return (-1);
			}
			cs_stat->def_rct = (uint32_t)(res * 1000);
		} else {
			/* NOP */;
		}
	}
	fclose (fp);
#endif
  }

	return (0);
}

/*--------------------------------------------------------------------------------------
	Reads the config file for conpub
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_csmgr_config_read_for_conpub (
	CefT_Cs_Stat* cs_stat					/* Content Store Status						*/
) {
	FILE*	fp = NULL;								/* file pointer						*/
	char	filepath[PATH_MAX+16];					/* file name						*/
	char	confdir_path[PATH_MAX];					/* dirctory path					*/

	char	param[4096] = {0};						/* parameter						*/
	char	param_buff[4096] = {0};					/* param buff						*/
	int		len;									/* read length						*/

	char*	option;									/* deny option						*/
	char*	value;									/* parameter						*/

	int		i, n;
	int64_t	res;

	char 	local_sock_id[CefC_LOCAL_SOCK_ID_SIZ+1] = {"0"};

	/* Obtains the directory path where the cefnetd's config file is located. */
	cef_client_config_dir_get (confdir_path);

	if (mkdir (confdir_path, 0777) != 0) {
		if (errno == ENOENT) {
			cef_log_write (CefC_Log_Error, "%s (mkdir)\n", __func__);
			return (-1);
		}
	}
	snprintf (filepath, sizeof(filepath), "%s/cefnetd.conf", confdir_path);

	/* Opens the cefnetd's config file. */
	fp = fopen (filepath, "r");
	if (fp == NULL) {
		fp = fopen (filepath, "w");
		if (fp == NULL) {
			cef_log_write (CefC_Log_Error, "%s (open cefnetd.conf)\n", __func__);
			return (-1);
		}
		fclose (fp);
		fp = fopen (filepath, "r");
	}

	/* Set default value */
	cs_stat->cache_type  	= CefC_Cache_Type_Excache;
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

		if (strcmp (option, "CS_MODE") == 0) {
			res = cef_csmgr_config_get_value (option, value);
			if (!(0 <= res && res <= 3)) {
				cef_log_write (CefC_Log_Error, "CS_MODE must be a value between 0 and 3.\n");
				fclose (fp);
				return (-1);
			}
			cs_stat->cache_type = res;
		} else
		if (strcmp (option, "BUFFER_CAPACITY") == 0) {
			res = cef_csmgr_config_get_value (option, value);
			if ((res < 0) || (res > CefC_Csmgr_Max_Table_Num)) {
				cef_log_write (CefC_Log_Warn,
					"BUFFER_CAPACITY must be higher than 0 and lower than 65536.\n");
				fclose (fp);
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
				fclose (fp);
				return (-1);
			}
			cs_stat->tcp_port_num = res;
		} else if (strcmp (option, CefC_ParamName_LocalSockId) == 0) {
			if (strlen (value) > CefC_LOCAL_SOCK_ID_SIZ) {
				cef_log_write (CefC_Log_Warn,
					"%s must be shorter than %d.\n",
						CefC_ParamName_LocalSockId, CefC_LOCAL_SOCK_ID_SIZ);
				fclose (fp);
				return (-1);
			}
			strcpy (local_sock_id, value);
		}
		else if (strcmp (option, "LOCAL_CACHE_DEFAULT_RCT") == 0) {
			res = cef_csmgr_config_get_value (option, value);
			if ((res < 1) || (res > 3600)) {
				cef_log_write (CefC_Log_Warn,
				"LOCAL_CACHE_DEFAULT_RCT must be higher than 1 and lower than 3600.\n");
				return (-1);
			}
			cs_stat->def_rct = (uint32_t)(res * 1000000llu);
		} else {
			/* NOP */;
		}
	}
	fclose (fp);
	sprintf (cs_stat->local_sock_name,
		"/tmp/conpub_%d.%s", cs_stat->tcp_port_num, local_sock_id);

#if 0
	snprintf (filepath, sizeof(filepath), "%s/conpubd.conf", confdir_path);

	fp = fopen (filepath, "r");
	if (fp == NULL) {
		cef_log_write (CefC_Log_Error, "%s (open conpubd.conf)\n", __func__);
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
			if ((res < 1) || (res > 3600)) {
				cef_log_write (CefC_Log_Warn,
					"CACHE_DEFAULT_RCT must be higher than 1 and lower than 3600 (secs).\n");
				fclose (fp);
				return (-1);
			}
			cs_stat->def_rct = (uint32_t)(res * 1000000llu);
		} else {
			/* NOP */;
		}
	}
	fclose (fp);
#endif

	return (0);
}
/*--------------------------------------------------------------------------------------
	Connect csmgr local socket
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_csmgr_csmgr_connect_local (
	CefT_Cs_Stat* cs_stat					/* Content Store Status						*/
) {
	struct sockaddr_un saddr;
	size_t saddr_len;
	int sock;
	int flag;

	if ((sock = socket (AF_UNIX, SOCK_STREAM, 0)) < 0) {
		return (-1);
	}

	/* initialize sockaddr_un */
	memset (&saddr, 0, sizeof (saddr));
	saddr.sun_family = AF_UNIX;
	strcpy (saddr.sun_path, cs_stat->local_sock_name);

	/* prepares a source socket */
#ifdef __APPLE__
	saddr.sun_len = sizeof (saddr);
	saddr_len = SUN_LEN (&saddr);
#else // __APPLE__
	saddr_len = sizeof (saddr.sun_family) + strlen (cs_stat->local_sock_name);
#endif // __APPLE__

	for ( int i = 0; i < CefC_Connect_Retries; ){
		errno = 0;
		if (connect (sock, (struct sockaddr *)&saddr, saddr_len) < 0) {
			switch ( errno ){
			case ETIMEDOUT :		// #60
			case ECONNREFUSED :		// #61
			case EADDRINUSE :		// #98
			case EADDRNOTAVAIL :	// #99
				usleep(++i*1000);
				continue;
			default:
				break;
			}
		}
		// no retry.
		break;
	}
	if ( errno ){
		cef_log_write (CefC_Log_Error, "%s(%s) (connect:%s)\n",
			__func__, cs_stat->local_sock_name, strerror(errno));
		close (sock);
		return (-1);
	}

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

	if (stat->cache_type != CefC_Cache_Type_None) {
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
#ifdef CefC_CefnetdCache
		if(stat->cache_type == CefC_Cache_Type_Localcache){
			cef_mem_cache_destroy ();
			if(stat->pipe_fd[0] != -1){
				close(stat->pipe_fd[0]);
			}
			if(stat->pipe_fd[1] != -1){
				close(stat->pipe_fd[1]);
			}
		}
#endif //CefC_CefnetdCache
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
	CefT_CcnMsg_MsgBdy* pm,					/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh,				/* Parsed Option Header						*/
	CefT_Pit_Entry* pe,						/* PIT entry								*/
	unsigned char** cob
) {
	CefT_Cob_Entry* cob_entry = NULL;
	uint64_t nowt;

	*cob = NULL;
	/* If the Interest is longlife or bulk, process is left to csmgrd 	*/
	if (pm->org.symbolic_f) {
		return (-1);
	}
	/* If the Interest is ACK, process is left to csmgrd 	*/
	if (pm->org.csact.csact_f || pm->org.csact.csact_alg_f) {
		return (-1);
	}


	if (cs_stat->cache_type == CefC_Cache_Type_Excache){
		/* Searches content entry 	*/
		if (cs_stat->cob_table) {
			cob_entry = (CefT_Cob_Entry*)
				cef_hash_tbl_item_get_prg (cs_stat->cob_table, pm->name, pm->name_len);
		}
		if (cob_entry) {
			nowt = cef_client_present_timeus_get ();

			if ((nowt < cob_entry->cache_time) && (nowt < cob_entry->expiry)) {
				if (pm->chunk_num_f) {
					cef_csmgr_excache_access_increment (
						cs_stat, pm->name, pm->name_len, pm->chunk_num);
				}
				*cob = cob_entry->msg;
				return (1);
			}
		}

	}
#ifdef CefC_CefnetdCache
	else if (cs_stat->cache_type == CefC_Cache_Type_Localcache){
		CefMemCacheT_Content_Mem_Entry* entry;
		entry = cef_mem_cache_item_get (pm->name, pm->name_len);
		if (entry) {
			nowt = cef_client_present_timeus_get ();

			if ((nowt < entry->cache_time) && (nowt < entry->expiry)) {
				*cob = entry->msg;
				return (1);
			}
		}
	}
#endif //CefC_CefnetdCache


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
	CefT_CcnMsg_MsgBdy* pm,					/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh					/* Parsed Option Header						*/
) {
	uint64_t nowt;
	CefT_Cob_Entry* new_entry;
	CefT_Cob_Entry* old_entry;

	if (cs_stat->cache_type == CefC_Cache_Type_Excache){
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
		//0.8.3c S
		/* Checks the expiry */
		if (pm->expiry_f) {
			if (pm->expiry == 0) {
				return;
			}
		}
		//0.8.3c E

		/* Create new cob entry */
		new_entry = (CefT_Cob_Entry*) cef_mpool_alloc (cs_stat->cs_cob_entry_mp);
		if (new_entry == NULL) {
			return;
		}
		new_entry->msg = (unsigned char*)malloc( sizeof(unsigned char)*msg_len);	//20210823
		if ( new_entry->msg == NULL ) {												//20210823
			return;																	//20210823
		}																			//20210823
		memcpy (new_entry->msg, msg, msg_len);										//20210823
		new_entry->msg_len = msg_len;
		new_entry->chunk_num = pm->chunk_num;
		new_entry->cache_time = nowt + cs_stat->buffer_cache_time;
		if ( 0 < poh->cachetime && poh->cachetime < new_entry->cache_time )
			new_entry->cache_time = poh->cachetime;
		new_entry->expiry = nowt + cs_stat->buffer_cache_time;
		if ( 0 < pm->expiry && (pm->expiry < new_entry->expiry) )
			new_entry->expiry = pm->expiry;

		/* Insert Cob Table and delete old entry */
		old_entry = (CefT_Cob_Entry*) cef_hash_tbl_item_set_prg (
				cs_stat->cob_table, pm->name, pm->name_len, new_entry);
		if (old_entry) {
			free( old_entry->msg );	//20210823
			old_entry->msg = NULL;	//20210823
			cef_mpool_free (cs_stat->cs_cob_entry_mp, old_entry);
		}
	}
#ifdef	CefC_CefnetdCache
	else if (cs_stat->cache_type == CefC_Cache_Type_Localcache){
		int		write_len = 0;
		/* Send to Local cache write thread */
		for ( int i = 0; i < CefC_PipeWrite_RetryMax; i++ ){
			int		ret = 0;

			ret = write(cs_stat->pipe_fd[0], &msg[write_len], msg_len-write_len);
cef_dbg_write (CefC_Dbg_Finest, "i=%d, msg_len=%d, write_len=%d, ret=%d\n", i, msg_len, write_len, ret);

			if ( 0 < ret ){
				write_len += ret;
				if ( msg_len <= write_len ){
					/* normal return */
					return;
				}
			}
			if (0 < errno && (errno != EAGAIN) && (errno != EWOULDBLOCK)) {
				cef_log_write (CefC_Log_Warn, "%s:%d socket write failed, err=%d:%s\n",
					__func__, __LINE__, errno, strerror(errno));
				break;
			}
			CefC_PipeWrite_RetryWait(i);
		}
		cef_log_write (CefC_Log_Warn, "%s:%d Send to cef_mem_cache_put_thread failed, write_len=%d\n",
			__func__, __LINE__, write_len);
cef_dbg_write (CefC_Dbg_Fine, "Failure:write_len=%d\n", write_len);
	}
#endif	//CefC_CefnetdCache

	return;
}
/*--------------------------------------------------------------------------------------
	Send message from csmgr to cefnetd
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_csmgr_send_msg (
	int fd,									/* socket fd								*/
	unsigned char* msg,						/* send message								*/
	int msg_len								/* message length							*/
) {
	int res;
	res = send (fd, msg, msg_len, 0);
	if (res < 0) {
		if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
			return (-1);
		}
	}
	return (res);
}
/*--------------------------------------------------------------------------------------
	Send message from cefnetd to csmgr
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
cef_csmgr_send_msg_to_csmgr (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	unsigned char* msg,						/* send message								*/
	int msg_len								/* message length							*/
) {
	int		write_len = 0;

	/* Send to csmgrd */
	for ( int i = 0; i < CefC_PipeWrite_RetryMax; i++ ){
		int		ret = 0;

		ret = write(cs_stat->to_csmgrd_pipe_fd[0], &msg[write_len], msg_len-write_len);
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finest, "i=%d, msg_len=%d, write_len=%d, ret=%d\n", i, msg_len, write_len, ret);
#endif // CefC_Debug

		if ( 0 < ret ){
			write_len += ret;
			if ( msg_len <= write_len ){
				/* normal return */
				return (msg_len);
			}
		}
		if (0 < errno && (errno != EAGAIN) && (errno != EWOULDBLOCK)) {
			break;
		}
		CefC_PipeWrite_RetryWait(i);
	}
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Fine, "Failure:write_len=%d\n", write_len);
#endif // CefC_Debug

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
	CefT_CcnMsg_MsgBdy* pm,				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh				/* Parsed Option header						*/
) {
	unsigned char buff[CefC_Max_Length];
	uint16_t index = 0;
	uint16_t value16;
	uint32_t value32;
	uint64_t value64;
	int chunk_field_len = CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum;
	uint16_t value16_namelen;
	struct in_addr node;
	CefT_Face* face = NULL;
	CefT_Sock* sock = NULL;
	CefT_Hash_Handle* sock_tbl = NULL;
	uint64_t nowt = cef_client_present_timeus_get ();

	/* Checks cache time 		*/
	if (poh->cachetime_f) {
		if (poh->cachetime < nowt) {
			poh->cachetime = nowt + cs_stat->def_rct;
		}
	} else {
		poh->cachetime = nowt + cs_stat->def_rct;
	}
	if (pm->expiry_f) {
		if (pm->expiry > 0) {
			if (pm->expiry > poh->cachetime) {
				pm->expiry = poh->cachetime;
			} else {
				poh->cachetime = pm->expiry;
			}
		} else {
			return;
		}
	}
	/* Can be extended indefinitely if there is no ExpiryTime */

	/* Inserts the Cob into temporary/local cache 	*/
	cef_csmgr_cache_insert (cs_stat, msg, msg_len, pm, poh);

	if (cs_stat->cache_type == CefC_Cache_Type_Excache) {
		/* Read Only ? */
		if ( cs_stat->csmgr_access != CefC_Default_CSMGR_ACCESS_RW ) {
			return;
		}

		/* Creates Upload Request message 		*/
		/* set header */
		buff[CefC_O_Fix_Ver]  = CefC_Version;
		buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_UpReq;
		index += CefC_Csmgr_Msg_HeaderLen;
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest, "CefC_Version:%d, CefC_Csmgr_Msg_Type_UpReq:%d\n", buff[CefC_O_Fix_Ver], buff[CefC_O_Fix_Type]);
#endif // CefC_Debug

		/* set payload length */
		value16 = htons (pm->payload_len);
		memcpy (buff + index, &value16, CefC_S_Length);
		index += CefC_S_Length;
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest, "len:%d, %d, %p, %p\n", pm->payload_len, value16, buff + index, buff + index + 1);
#endif // CefC_Debug

		/* set cob message */
		value16 = htons (msg_len);
		memcpy (buff + index, &value16, CefC_S_Length);
		memcpy (buff + index + CefC_S_Length, msg, msg_len);
		index += CefC_S_Length + msg_len;

		/* set cob name */
		if (pm->chunk_num_f) {
			value16_namelen = pm->name_len - chunk_field_len;
			value16 = htons (value16_namelen);
			memcpy (buff + index, &value16, CefC_S_Length);
			memcpy (buff + index + CefC_S_Length, pm->name, value16_namelen);
			index += CefC_S_Length + value16_namelen;
		} else {
			return;
		}


		/* set chunk num */
		value32 = htonl (pm->chunk_num);
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

		/* set Length
		value16 = htons (index);
		memcpy (buff + CefC_O_Fix_PacketLength, &value16, CefC_S_Length);
		*/
		/* ADD MAGIC */
		buff[index++] = 0x63;
		buff[index++] = 0x6f;
		buff[index++] = 0x62;
		value16 = htons (index);
		memcpy (&buff[CefC_O_Fix_PacketLength], &value16, CefC_S_Length);

		/* The message buffer is full, so send it to csmgrd */
		if(CefC_CsPipeBuffSize <= (cefnetd_msg_buff_index + index)){
			cef_csmgr_send_msg_to_csmgr (
					cs_stat, cefnetd_msg_buff, cefnetd_msg_buff_index);
			cefnetd_msg_buff_index = 0;
		}

		memcpy (&cefnetd_msg_buff[cefnetd_msg_buff_index], buff, index);
		cefnetd_msg_buff_index += index;

		/* If it is an end chunk, forcefully send it. */
		if((pm->end_chunk_num_f && pm->end_chunk_num <= pm->chunk_num) ){
			cef_csmgr_send_msg_to_csmgr (
					cs_stat, cefnetd_msg_buff, cefnetd_msg_buff_index);
			cefnetd_msg_buff_index = 0;
		}
	}

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
		cef_csmgr_send_msg_to_csmgr (cs_stat, cefnetd_msg_buff, cefnetd_msg_buff_index);
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
	CefT_CcnMsg_MsgBdy* pm,				/* Parsed CEFORE message					*/
	CefT_CcnMsg_OptHdr* poh,				/* Parsed Option Header						*/
	CefT_Pit_Entry* pe						/* PIT entry								*/
) {
	unsigned char buff[CefC_Max_Length];
	uint16_t index = 0;
	int res;

	if (pm->org.symbolic_f) {
		return;
	}
#ifdef	CefC_CefnetdCache
	if (cs_stat->cache_type == CefC_Cache_Type_Localcache){
		return;
	}
#endif	//CefC_CefnetdCache

	if (pm->org.csact.csact_f != 0
		&& pm->org.csact.csact_alg_f == 0) {
		cef_log_write (CefC_Log_Warn, "Signature verification failed. (unknown type)\n");
		return;
	}

	/* Create Interest message 		*/
	cef_csmgr_interest_msg_create (buff, &index, poh, pm);

	/* Send messages 				*/
	res = cef_csmgr_send_msg_to_csmgr (cs_stat, buff, index);
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
	memcpy (&value16, &buff[CefC_O_Fix_PacketLength], CefC_S_Length);
	len = ntohs (value16);

	/* check message length */
	if ((len <= CefC_Csmgr_Msg_HeaderLen)) {
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
	uint32_t chunk_num							/* Chunk Number of content				*/
) {
	uint16_t name_len;
	uint16_t name_off;
	uint16_t pay_len;
	uint16_t pay_off;

	/* send content object */
	if (cef_face_check_active (faceid) > 0) {

		if (cef_face_is_local_face (faceid)) {
			cef_frame_payload_parse (
				msg, msg_len, &name_off, &name_len, &pay_off, &pay_len);
			if (pay_len != 0) {
				cef_face_frame_send_iflocal (faceid, msg, msg_len);
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
	if (CefC_NAME_MAXLEN < (*name_len)) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "%s(%d) too large name_len=%u\n", __func__, __LINE__, (*name_len));
#endif // CefC_Debug
		return (-1);
	}
	*index += CefC_S_Length;
	if ((buff_len - (*index) - (*name_len)) < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "%s(%d) message parse error.\n", __func__, __LINE__);
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
	Incoming pre-ccninfoo message
----------------------------------------------------------------------------------------*/
int									/* The return value is negative if an error occurs	*/
cef_csmgr_excache_item_check_for_ccninfo (
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

#ifdef CefC_CefnetdCache
	if (cs_stat->cache_type == CefC_Cache_Type_Localcache){
		return 0;
	}
#endif //CefC_CefnetdCache

	/*----------------------------------------------------
		Sends the PreCcninfo request message
	------------------------------------------------------*/
	/* Creates the socket to csmgr with TCP 		*/
	sprintf (port_str, "%d", cs_stat->tcp_port_num);
	tmp_sock = cef_csmgr_connect_tcp_to_csmgr (cs_stat->peer_id_str, port_str);
	if (tmp_sock < 0) {
		return (-1);
	}

	/* Creates the Ping Request message 		*/
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_PreCcninfo;
	index += CefC_Csmgr_Msg_HeaderLen;

	memcpy (buff + index, name, name_len);
	index += name_len;

	value16 = htons (index);
	memcpy (&buff[CefC_O_Fix_PacketLength], &value16, CefC_S_Length);

	/* Sends the created message 		*/
	res = write (tmp_sock, buff, index);
	if (res < 0) {
		close (tmp_sock);
		return (-1);
	}

	/*----------------------------------------------------
		Receives the PreCcninfo response message
	------------------------------------------------------*/
	fds[0].fd = tmp_sock;
	fds[0].events = POLLIN | POLLERR;
	memset (buff, 0, sizeof (buff));

	res = poll (fds, 1, CefC_Csmgr_Max_Wait_Response);
	if (res <= 0) {
		goto DO_CLOSE;
	}
	if (fds[0].revents & (POLLERR | POLLNVAL | POLLHUP)) {
		goto DO_CLOSE;
	}

	len = recv (fds[0].fd, buff, CefC_Max_Length, 0);

	if (len > 0) {
		/* Parses the received message 		*/
		len = csmgr_frame_get (buff, len, buff, &buff_size, &type);
		if (buff_size > 0) {
			if (type != CefC_Csmgr_Msg_Type_PreCcninfo) {
				goto DO_CLOSE;
			}
			/* Checks the result 		*/
			if (buff[0] == CefC_Csmgr_Cob_Exist) {
				close (tmp_sock);
				return (1);
			}
		}
	}

DO_CLOSE:
	close (tmp_sock);
	return (-1);
}
/*--------------------------------------------------------------------------------------
	Incoming Ccninfo message
----------------------------------------------------------------------------------------*/
int											/* length of Cache Information				*/
cef_csmgr_excache_info_get (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	unsigned char* name,					/* Content URI								*/
	uint16_t name_len,						/* Length of Content URI					*/
	unsigned char* info,					/* cache information from csmgr 			*/
	uint16_t ccninfo_flag					/* Ccninfo Trace Flag 						*/
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
		Sends the ccninfo request message
	------------------------------------------------------*/
	/* Creates the socket to csmgr with TCP 		*/
	sprintf (port_str, "%d", cs_stat->tcp_port_num);
	tmp_sock = cef_csmgr_connect_tcp_to_csmgr (cs_stat->peer_id_str, port_str);
	if (tmp_sock < 0) {
		return (-1);
	}

	/* Creates the ccninfo request message 		*/
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_Ccninfo;
	index += CefC_Csmgr_Msg_HeaderLen;

	if (ccninfo_flag != 0) {
		buff[index] = 1;
	} else {
		buff[index] = 0;
	}
	index++;

	memcpy (buff + index, name, name_len);
	index += name_len;

	value16 = htons (index);
	memcpy (&buff[CefC_O_Fix_PacketLength], &value16, CefC_S_Length);

	/* Sends the created message 		*/
	res = write (tmp_sock, buff, index);
	if (res < 0) {
		close (tmp_sock);
		return (-1);
	}

	/*----------------------------------------------------
		Receives the ccninfo response message
	------------------------------------------------------*/
	fds[0].fd = tmp_sock;
	fds[0].events = POLLIN | POLLERR;
	memset (buff, 0, sizeof (buff));

	res = poll (fds, 1, CefC_Csmgr_Max_Wait_Response);
	if (res <= 0) {
		goto CCNINFOREQ_POST;
	}
	if (fds[0].revents & (POLLERR | POLLNVAL | POLLHUP)) {
		goto CCNINFOREQ_POST;
	}

	len = recv (fds[0].fd, buff, CefC_Max_Length, 0);

	if (len > CefC_S_TLF) {
		memcpy (info, buff, len);
		close (tmp_sock);
		return (len);
	}

CCNINFOREQ_POST:
	close (tmp_sock);
	return (-1);
}
#ifdef CefC_CefnetdCache
/*--------------------------------------------------------------------------------------
	Incoming Ccninfo message for cefnetd local cache
----------------------------------------------------------------------------------------*/
int											/* length of Cache Information				*/
cef_csmgr_locache_info_get (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	unsigned char* name,					/* Content URI								*/
	uint16_t name_len,						/* Length of Content URI					*/
	unsigned char* info,					/* cache information from csmgr 			*/
	uint16_t ccninfo_flag					/* Ccninfo Trace Flag 						*/
) {
	uint16_t tmp_klen;
	uint32_t seqno;
	CefMemCacheT_Ccninfo info_p;
	int res;
	struct ccninfo_rep_block rep_blk;
	struct tlv_hdr rply_tlv_hdr;
	struct tlv_hdr name_tlv_hdr;
	int index = 0;

	tmp_klen = cef_frame_get_name_without_chunkno (name, name_len, &seqno);
	if (tmp_klen == 0) {
		/* no chunk number */
		res = cef_mem_cache_mstat_get (name, name_len, &info_p);
		if (res < 0) {
			return (-1);
		}
		if (info_p.con_size / 1024 > UINT32_MAX) {
			rep_blk.cont_size 	= htonl (UINT32_MAX);
		} else {
			rep_blk.cont_size 	= htonl ((uint32_t)info_p.con_size / 1024);
		}

		rep_blk.cont_cnt 	= htonl (info_p.con_num);
		if (info_p.ac_cnt > UINT32_MAX) {
			rep_blk.rcv_int 	= htonl (UINT32_MAX);
		} else {
			rep_blk.rcv_int 	= htonl (info_p.ac_cnt);
		}
		/* Min and Max are the values when first inserted into the localcache, */
		/* and when it overflows from the localcache, it is not maintained.    */
		rep_blk.first_seq 	= htonl (info_p.min_seq);
		rep_blk.last_seq 	= htonl (info_p.max_seq);
		//rep_blk.first_seq 	= htonl ((uint32_t) 0);
		//rep_blk.last_seq 	= htonl ((uint32_t) 0);
	} else {
		/* include chunk number */
		CefMemCacheT_Content_Mem_Entry* entry;
		uint64_t nowt;
		entry = cef_mem_cache_item_get (name, name_len);
		if (entry) {
			nowt = cef_client_present_timeus_get ();
			if ((nowt < entry->cache_time) && (nowt < entry->expiry)) {
				res = cef_mem_cache_mstat_get (name, tmp_klen, &info_p);
				if (res < 0) {
					return (-1);
				}

				if (info_p.con_size / 1024 > UINT32_MAX) {
					rep_blk.cont_size 	= htonl (UINT32_MAX);
				} else {
					rep_blk.cont_size 	= htonl ((uint32_t)info_p.con_size / 1024);
				}
				rep_blk.cont_cnt 	= htonl ((uint32_t) 1);
				rep_blk.rcv_int 	= htonl ((uint32_t) 0);
				rep_blk.first_seq 	= htonl ((uint32_t) seqno);
				rep_blk.last_seq 	= htonl ((uint32_t) seqno);
			}
		} else {
			return (-1);
		}
	}
	/* ExactMatch */
	index = CefC_S_TLF;

	/* Reply block							*/
	rep_blk.cache_time	= htonl ((uint32_t) 0);
	rep_blk.remain_time	= htonl ((uint32_t) 0);
	memcpy (&info[index], &rep_blk, sizeof (struct ccninfo_rep_block));
	index += sizeof (struct ccninfo_rep_block);

	/* Name 								*/
	name_tlv_hdr.type   = htons (CefC_T_NAME);
	name_tlv_hdr.length = htons (name_len);
	memcpy (&info[index], &name_tlv_hdr, sizeof (struct tlv_hdr));
	memcpy (&info[index + CefC_S_TLF], name, name_len);
	index += CefC_S_TLF + name_len;

	/* Sets the header of Reply Block 		*/
	rply_tlv_hdr.type = htons (CefC_T_DISC_CONTENT);
	rply_tlv_hdr.length = htons (index - CefC_S_TLF);
	memcpy (&info[0], &rply_tlv_hdr, sizeof (struct tlv_hdr));

	return (index);
}
#endif //CefC_CefnetdCache
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

/*--------------------------------------------------------------------------------------
	Increment Access Count in excache
----------------------------------------------------------------------------------------*/
static void
cef_csmgr_excache_access_increment (
	CefT_Cs_Stat* cs_stat,					/* Content Store status						*/
	const unsigned char* key,				/* Content name								*/
	uint32_t klen,							/* Content name length						*/
	uint32_t chunk_num						/* Content Chunk Number 					*/
) {
	unsigned char buff[CefC_Max_Length] = {0};
	uint16_t index = 0;
	uint16_t value16;
	uint32_t value32;
	int res;

#ifdef CefC_CefnetdCache
	if (cs_stat->cache_type == CefC_Cache_Type_Localcache){
		return;
	}
#endif //CefC_CefnetdCache

	/* Create Upload Request message */
	/* set header */
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_Increment;
	index += CefC_Csmgr_Msg_HeaderLen;

	/* set chunk number 	*/
	value32 = htonl (chunk_num);
	memcpy (buff + index, &value32, sizeof (uint32_t));
	index += sizeof (uint32_t);

	/* set cob name */
	value16 = htons ((uint16_t)klen);
	memcpy (buff + index, &value16, CefC_S_Length);
	memcpy (buff + index + CefC_S_Length, key, (uint16_t)klen);
	index += CefC_S_Length + (uint16_t)klen;

	/* set Length */
	value16 = htons (index);
	memcpy (&buff[CefC_O_Fix_PacketLength], &value16, CefC_S_Length);

	/* send message */
	res = cef_csmgr_send_msg_to_csmgr (cs_stat, buff, index);
	if (res < 0) {
		cef_log_write (CefC_Log_Warn, "%s (%s)\n", __func__, strerror (errno));
	}

	return;
}

/*--------------------------------------------------------------------------------------
	Create Interest message for csmgr
----------------------------------------------------------------------------------------*/
static void
cef_csmgr_interest_msg_create (
	unsigned char buff[],					/* Interest message							*/
	uint16_t* index,						/* Length of message						*/
	CefT_CcnMsg_OptHdr* poh,				/* Parsed Option Header						*/
	CefT_CcnMsg_MsgBdy* pm					/* Parsed CEFORE message					*/
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
	if (pm->chunk_num_f) {
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
	if (pm->chunk_num_f) {
		value32_nw = htonl (pm->chunk_num);
		memcpy (buff + *index, &value32_nw, CefC_S_ChunkNum);
		*index += CefC_S_ChunkNum;
	}

	uint16_t keyid_restr_len = 0;
	uint16_t keyid_restr_offset = *index;
	*index += CefC_S_Length;

	/* Sets KeyID Restriction */
	if (pm->KeyIdRestr_f != 0
			&& pm->KeyIdRestr_len != 0) {
		/* Sets KeyID Length */
		value16 = htons (pm->KeyIdRestr_len);
		memcpy (buff + *index, &value16, sizeof (uint16_t));
		keyid_restr_len += CefC_S_Length;
		*index += CefC_S_Length;

		/* Sets KeyID */
		memcpy (buff + *index, &pm->KeyIdRestr, pm->KeyIdRestr_len);
		keyid_restr_len += pm->KeyIdRestr_len;
		*index += pm->KeyIdRestr_len;
	}

	/* Sets KeyID Restriction Length */
	keyid_restr_len = htons(keyid_restr_len);
	memcpy (buff + keyid_restr_offset, &keyid_restr_len, sizeof (uint16_t));

	/* Sets CobHash Restriction Length */
	if (pm->ObjHashRestr_f) {
		value16 = htons (pm->ObjHashRestr_len);
	} else {
		value16 = 0;
	}
	memcpy (buff + *index, &value16, sizeof (uint16_t));
	*index += CefC_S_Length;

	/* Sets CobHash Restriction */
	if (pm->ObjHashRestr_f != 0
		&& pm->ObjHashRestr_len != 0) {
		memcpy (buff + *index, &pm->ObjHashRestr, pm->ObjHashRestr_len);
		*index += pm->ObjHashRestr_len;
	}

	/* Sets Plain Text Length */
	if (pm->org.csact.csact_f) {
		value16 = htons (pm->org.csact.csact_len);
	} else {
		value16 = 0;
	}
	memcpy (buff + *index, &value16, sizeof (uint16_t));
	*index += CefC_S_Length;

	/* Sets Plain Text */
	if (pm->org.csact.csact_f != 0
		&& pm->org.csact.csact_len != 0) {
		memcpy (buff + *index, pm->org.csact.csact_val, pm->org.csact.csact_len);
		*index += pm->org.csact.csact_len;
	}

	/* Sets signature Length */
	if (pm->org.csact.csact_alg_f) {
		value16 = htons (pm->org.csact.signature_len);
	} else {
		value16 = 0;
	}
	memcpy (buff + *index, &value16, sizeof (uint16_t));
	*index += CefC_S_Length;

	/* Sets signature */
	if (pm->org.csact.csact_alg_f != 0
		&& pm->org.csact.signature_len != 0) {
		memcpy (buff + *index, pm->org.csact.signature_val, pm->org.csact.signature_len);
		*index += pm->org.csact.signature_len;
	}

	/* set Length */
	value16_nw = htons (*index);
	memcpy (&buff[CefC_O_Fix_PacketLength], &value16_nw, CefC_S_Length);

	return;
}
/*--------------------------------------------------------------------------------------
	Connect csmgr with TCP socket
----------------------------------------------------------------------------------------*/
int											/* created socket							*/
cef_csmgr_connect_tcp_to_csmgr (
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
		fprintf (stderr, "ERROR : connect_tcp_to_csmgr (getaddrinfo)\n");
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
		/**** connect ****/
		for ( int i = 0; i < CefC_Connect_Retries; ){
			errno = 0;
			if (connect (sock, cres->ai_addr, cres->ai_addrlen) < 0) {
				// retry case.
				switch ( errno ){
				case ETIMEDOUT :		// #60
				case ECONNREFUSED :		// #61
				case EADDRINUSE :		// #98
				case EADDRNOTAVAIL :	// #99
					usleep(++i*1000);
					continue;
				default:
					break;
				}
			}
			// no retry.
			break;
		}
		// O_NONBLOCK may result in EINPROGRESS
		if ( 0 < errno && errno != EINPROGRESS ){
			cef_log_write (CefC_Log_Error, "%s (connect:%s)\n", __func__, strerror(errno));
			close (sock);
			free (cres);
			continue;
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
					/* NOP */;
				}
			}
		}
		freeaddrinfo (res);
		return (sock);
	}
	return (-1);
}

/*#####################################################*/
void *
cef_csmgr_send_to_csmgrd_thread (
	void *p
){

	CefT_Cs_Stat*				cs_stat;
	int 						read_fd = -1;
	struct pollfd 				poll_fds[1];
	unsigned char				msg[CefC_Max_Length*2];
	int							msg_len;

	cs_stat = (CefT_Cs_Stat*)p;

	read_fd = cs_stat->to_csmgrd_pipe_fd[1];

	pthread_t self_thread = pthread_self();
	pthread_detach(self_thread);

	memset(&poll_fds, 0, sizeof(poll_fds));
	poll_fds[0].fd = read_fd;
	poll_fds[0].events = POLLIN | POLLERR;

	while (1){
	    poll(poll_fds, 1, 1);
	    if (poll_fds[0].revents & POLLIN) {
			if((msg_len = read(read_fd, msg, sizeof(msg))) < 1){
				continue;
			}
			/*###########*/
			int res;
			char port_str[NI_MAXSERV];

			if (cs_stat->local_sock != -1) {
				int	send_count = 0;
				res = 0;
    			unsigned char* mp = msg;
    			int len = msg_len;
				fd_set fds, writefds;
				int n;
				struct timeval timeout;

		   		res = send( cs_stat->local_sock, mp, len,  MSG_DONTWAIT);
				if ( res <= 0 ) {
#ifdef	__DEV_CEF_CSMGR_SEND__
					fprintf(stderr, "[%s](res <=0): ###########(1) ERROR(%d)=%s send_count:%d\n", __FUNCTION__, errno, strerror (errno), send_count);
#endif
					if ( errno == EAGAIN ) {
						usleep(CEF_CSMGR_SEND_USLEEP);
					}
					continue;
				}
				len -= res;
				mp += res;
				send_count++;

				while( len > 0 ){
					timeout.tv_sec  = 0;
					timeout.tv_usec = CEF_CSMGR_SEND_TIMEOUT;
					FD_ZERO (&writefds);
					FD_SET (cs_stat->local_sock, &writefds);
					memcpy (&fds, &writefds, sizeof (fds));
					n = select(cs_stat->local_sock+1, NULL, &fds, NULL, &timeout);
					if (n > 0) {
						if (FD_ISSET (cs_stat->local_sock, &fds)) {
				    		res = send( cs_stat->local_sock, mp, len,  MSG_DONTWAIT);
							if(res > 0) {
								len -= res;
								mp += res;
							} else {
#ifdef	__DEV_CEF_CSMGR_SEND__
								fprintf(stderr, "[%s](res <=0): ###########(2) ERROR(%d)=%s \n", __FUNCTION__, errno, strerror (errno));
#endif
								if ( errno == EAGAIN ) {
									usleep(CEF_CSMGR_SEND_USLEEP);
								}
							}
							send_count++;
							if ( send_count > DEMO_RETRY_NUM ) {
								break;
							}
						}
					} else {
						if ( send_count == 0 ) {
							break;
						} else if ( send_count > DEMO_RETRY_NUM ) {
#ifdef	__DEV_CEF_CSMGR_SEND__
							fprintf(stderr, "[%s](%d): ########### n:%d   send_count:%d   len:%d   %s\n",
										__FUNCTION__, __LINE__, n, send_count, len, strerror (errno));
#endif
							break;
						}
						send_count++;
						if ( errno == EAGAIN ) {
							usleep(CEF_CSMGR_SEND_USLEEP);
						}
					}
				}
				continue;
			}

			if (cs_stat->tcp_sock == -1) {
				sprintf (port_str, "%d", cs_stat->tcp_port_num);
				cs_stat->tcp_sock
						= cef_csmgr_connect_tcp_to_csmgr (cs_stat->peer_id_str, port_str);
			}
			if (cs_stat->tcp_sock != -1) {
				int	send_count = 0;
				res = 0;
    			unsigned char* mp = msg;
    			int len = msg_len;
				fd_set fds, writefds;
				int n;
				struct timeval timeout;

				res = send( cs_stat->tcp_sock, mp, len, MSG_DONTWAIT );
				if ( res <= 0 ) {
#ifdef	__DEV_CEF_CSMGR_SEND__
					fprintf(stderr, "[%s](res <=0): ###########(3) ERROR(%d)=%s send_count:%d\n", __FUNCTION__, errno, strerror (errno), send_count);
#endif
					if ( errno == EAGAIN ) {
						usleep(CEF_CSMGR_SEND_USLEEP);
					}
					continue;
				}
				len -= res;
				mp += res;
				send_count++;

				while( len > 0 ){
					timeout.tv_sec  = 0;
					timeout.tv_usec = CEF_CSMGR_SEND_TIMEOUT;
					FD_ZERO (&writefds);
					FD_SET (cs_stat->tcp_sock, &writefds);
					memcpy (&fds, &writefds, sizeof (fds));
					n = select(cs_stat->tcp_sock+1, NULL, &fds, NULL, &timeout);
					if (n > 0) {
						if (FD_ISSET (cs_stat->tcp_sock, &fds)) {
							res = send( cs_stat->tcp_sock, mp, len, MSG_DONTWAIT );
								if(res > 0) {
								len -= res;
								mp += res;
							} else {
#ifdef	__DEV_CEF_CSMGR_SEND__
								fprintf(stderr, "[%s](res <=0): ###########(4) ERROR(%d)=%s \n", __FUNCTION__, errno, strerror (errno));
#endif
								if ( errno == EAGAIN ) {
									usleep(CEF_CSMGR_SEND_USLEEP);
								}
							}
							send_count++;
							if ( send_count > DEMO_RETRY_NUM ) {
								break;
							}
						}
					} else {
						if ( send_count == 0 ) {
							break;
						} else if ( send_count > DEMO_RETRY_NUM ) {
#ifdef	__DEV_CEF_CSMGR_SEND__
							fprintf(stderr, "[%s](%d): ########### n:%d   send_count:%d   len:%d   %s\n",
												__FUNCTION__, __LINE__, n, send_count, len, strerror (errno));
#endif
							break;
						}
						send_count++;
						if ( errno == EAGAIN ) {
							usleep(CEF_CSMGR_SEND_USLEEP);
						}
					}
				}
				continue;
			}
			/*###########*/
		}
	}

	pthread_exit (NULL);
	return 0;

}

int
cef_csmgr_content_info_get (
	CefT_Cs_Stat*	cs_stat,				/* Content Store status						*/
	char*			name,					/* Content name								*/
	uint16_t		name_len,				/* Name length								*/
	char*			range,					/* Cache Range								*/
	uint16_t		range_len,				/* Range length								*/
	char**			info
) {
	char			port_str[NI_MAXSERV];
	int				tmp_sock;
	unsigned char	buff[CefC_Max_Length] = {0};
	int				buff_size;
	uint16_t		index = 0;
	uint16_t		value16;
	int				res = 0;
	struct pollfd	fds[1];
	unsigned char	msg[CefC_Max_Length] = {0};
	uint8_t			type;
	int				len;
	unsigned char*	msg_wkp;

	if (cs_stat == NULL) {
		/* CS is not used */
		return (-1);
	}

	/* Creates the socket to csmgr with TCP */
	sprintf (port_str, "%d", cs_stat->tcp_port_num);
	tmp_sock = cef_csmgr_connect_tcp_to_csmgr (cs_stat->peer_id_str, port_str);
	if (tmp_sock < 0) {
		/* Connection Failed */
		return (-1);
	}

	/*------------------------------------------------------
		Creates the Contents Information Request message
	--------------------------------------------------------*/
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_ContInfo;
	index += CefC_Csmgr_Msg_HeaderLen;
	/* Set content name */
	value16 = htons (name_len);
	memcpy (buff + index, &value16, CefC_S_Length);
	memcpy (buff + index + sizeof (value16), name, name_len);
	index += sizeof (value16) + name_len;
	/* Set request range */
	value16 = htons (range_len);
	memcpy (buff + index, &value16, CefC_S_Length);
	memcpy (buff + index + sizeof (value16), range, range_len);
	index += sizeof (value16) + range_len;
	/* Set length */
	value16 = htons (index);
	memcpy (&buff[CefC_O_Fix_PacketLength], &value16, CefC_S_Length);

	/* Sends the created message */
	res = write (tmp_sock, buff, index);
	if (res < 0) {
		close (tmp_sock);
		return (-1);
	}

	/*------------------------------------------------------
		Receives the Contents Information Response message
	--------------------------------------------------------*/
	fds[0].fd = tmp_sock;
	fds[0].events = POLLIN | POLLERR;
	memset (buff, 0, sizeof (buff));
	res = poll (fds, 1, CefC_Csmgr_Max_Wait_Response);
	usleep (CEF_CSMGR_SEND_USLEEP);
	if ((res <= 0) || (fds[0].revents & (POLLERR | POLLNVAL | POLLHUP))) {
		close (tmp_sock);
		return (-1);
	}

	index = 0;
	len = recv (fds[0].fd, buff, CefC_Max_Length, 0);
	if (len > 0) {
		/* Parses the received message */
		len = csmgr_frame_get (buff, len, msg, &buff_size, &type);
		if (buff_size > 0) {
			if (type != CefC_Csmgr_Msg_Type_ContInfo) {
				res = -1;
				goto RETCEFNETD;
			}

			msg_wkp = msg;

			/* Checks the result */
			memcpy (&value16, msg_wkp, sizeof (value16));
			if (value16) {	/* Failed */
				res = -1;
				goto RETCEFNETD;
			}
			msg_wkp += 2;

			/* Checks the name */
			memcpy (&value16, msg_wkp, sizeof (value16));
			len = ntohs (value16);
			msg_wkp += 2;

			if (!(len == name_len &&
				memcmp (msg_wkp, name, len) == 0)) {
				res = -1;
				goto RETCEFNETD;
			}
			msg_wkp += len;

			/* Renge */
			memcpy (&value16, msg_wkp, sizeof (value16));
			len = ntohs (value16);
			msg_wkp += 2;
			if (len == 0) {
				res = 0;
				goto RETCEFNETD;
			}
			*info = (char*) malloc (sizeof(unsigned char) * len + 1);/* +1 is for terminator(0x00) */
			memcpy (*info, msg_wkp, len);
			msg_wkp += len;
			res = len;
		}
	}

RETCEFNETD:;

	close (tmp_sock);
	return (res);
}


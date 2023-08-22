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
 * csmgrd.c
 */

#define __CEF_CSMGRD_SOURCE__

//#define	__DB_IDX_DEBUG
//#define	__DB_IDX_DEB_STATUS
//#define	__DB_IDX_DEB_CONTINFO

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/statvfs.h>
#include <net/if.h>		///
#include <sys/ioctl.h>	///
#include <ifaddrs.h>	///

#include "csmgrd.h"
#include <csmgrd/csmgrd_plugin.h>
#include <cefore/cef_csmgr.h>
#include <cefore/cef_csmgr_stat.h>
#include <cefore/cef_client.h>
#include <cefore/cef_frame.h>
#include <cefore/cef_log.h>
#ifdef CefC_Ccore
#include <ccore/ccore_frame.h>
#endif // CefC_Ccore

#ifndef CefC_MACOS
#define ANA_DEAD_LOCK //@@@@@@@@@@
#ifdef ANA_DEAD_LOCK //@@@@@+++++ ANA DEAD LOCK
static int xpthread_mutex_lock (const char* pname, int pline, pthread_mutex_t *mutex)
{
	struct timespec to;
	int err;
	to.tv_sec = time(NULL) + 600;
	to.tv_nsec = 0;
	err = pthread_mutex_timedlock(mutex, &to);
	if (err != 0) {
    	fprintf(stderr, "[%s(%d)]: ------ DETECT DEAD LOCK: %s -----\n", pname, pline, strerror(err));
		exit (1);
	}
	return (0);
}
#define pthread_mutex_lock(a) xpthread_mutex_lock(__FUNCTION__, __LINE__, a)
#endif //@@@@@+++++ ANA DEAD LOCK
#endif //CefC_MACOS

/****************************************************************************************
 Macros
 ****************************************************************************************/
#define CSMGR_MAXIMUM_MEM_USAGE_FOR_MEM				80
#define CSMGR_THRSHLD_MEM_USAGE_FOR_MEM				60
#define CSMGR_MAXIMUM_MEM_USAGE_FOR_DB				80
#define CSMGR_THRSHLD_MEM_USAGE_FOR_DB				60
#define CSMGR_MAXIMUM_MEM_USAGE_FOR_FILE			60
#define CSMGR_THRSHLD_MEM_USAGE_FOR_FILE			40
#define CSMGR_MAXIMUM_FILE_USAGE_FOR_FILE			80
#define CSMGR_THRSHLD_FILE_USAGE_FOR_FILE 			60
/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/


/****************************************************************************************
 State Variables
 ****************************************************************************************/

static uint8_t 				csmgrd_running_f = 0;
static char 				csmgr_conf_dir[PATH_MAX] = {"/usr/local/cefore"};
static char 				root_user_name[CefC_Csmgr_User_Len] = {"root"};
static char 				csmgr_local_sock_name[PATH_MAX] = {0};

static pthread_mutex_t 		csmgr_comn_buff_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t 		csmgr_main_cob_buff_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t		csmgr_comn_buff_cond = PTHREAD_COND_INITIALIZER;

static unsigned char* 		csmgr_main_cob_buff 		= NULL;
static int 					csmgr_main_cob_buff_idx 	= 0;
static unsigned char* 		csmgr_comn_cob_buff 		= NULL;
static int 					csmgr_comn_cob_buff_idx 	= 0;
static unsigned char* 		csmgr_proc_cob_buff 		= NULL;
static int 					csmgr_proc_cob_buff_idx 	= 0;
static uint64_t				csmgr_wait_time 			= 2000000;
static CsmgrT_Stat_Handle 	stat_hdl = CsmgrC_Invalid;

static int	Lack_of_M_resources = 1;
static int	Lack_of_F_resources = 1;
static pthread_mutex_t 		csmgr_Lack_of_resources_mutex = PTHREAD_MUTEX_INITIALIZER;

static CsmgrT_Stat* stat_for_PM[CsmgrT_Stat_Max];



/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Main function
----------------------------------------------------------------------------------------*/
int
main (
	int argc,
	char* argv[]
);
/*--------------------------------------------------------------------------------------
	Create csmgr daemon handle
----------------------------------------------------------------------------------------*/
static CefT_Csmgrd_Handle*			/* The return value is null if an error occurs		*/
csmgrd_handle_create (
	void
);
/*--------------------------------------------------------------------------------------
	Destroy csmgr daemon handle
----------------------------------------------------------------------------------------*/
static void
csmgrd_handle_destroy (
	CefT_Csmgrd_Handle** csmgrd_hdl				/* CS Manager Handle					*/
);
/*--------------------------------------------------------------------------------------
	Read config file
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
csmgrd_config_read (
	CsmgrT_Config_Param* conf_param				/* parameter of config					*/
);
/*--------------------------------------------------------------------------------------
	Create local socket
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
csmgrd_local_sock_create (
	void
);
/*--------------------------------------------------------------------------------------
	Check accept from local socket
----------------------------------------------------------------------------------------*/
static void
csmgrd_local_sock_check (
	CefT_Csmgrd_Handle* hdl						/* CS Manager Handle					*/
);
/*--------------------------------------------------------------------------------------
	Change string to value
----------------------------------------------------------------------------------------*/
static int64_t						/* The return value is negative if an error occurs	*/
csmgrd_config_value_get (
	char* option,								/* csmgrd option						*/
	char* value									/* String								*/
);
/*--------------------------------------------------------------------------------------
	Load plugin
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
csmgrd_plugin_load (
	CefT_Csmgrd_Handle* hdl						/* csmgr daemon handle					*/
);
/*--------------------------------------------------------------------------------------
	Check plugin
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
csmgrd_plugin_check (
	CefT_Csmgrd_Handle* hdl						/* csmgr daemon handle					*/
);
/*--------------------------------------------------------------------------------------
	Sets the path of csmgrd.conf
----------------------------------------------------------------------------------------*/
static int
csmgrd_plugin_config_dir_set (
	const char* config_file_dir
);
/*--------------------------------------------------------------------------------------
	Main Loop Function
----------------------------------------------------------------------------------------*/
static void
csmgrd_event_dispatch (
	CefT_Csmgrd_Handle* hdl						/* csmgr daemon handle					*/
);
/*--------------------------------------------------------------------------------------
	Prepares the Control sockets to be polled
----------------------------------------------------------------------------------------*/
static int
csmgrd_poll_socket_prepare (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	struct pollfd fds[],
	int fds_index[]
);
/*--------------------------------------------------------------------------------------
	Handles the received message(s)
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
csmgrd_input_message_process (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* msg,							/* receive message						*/
	int msg_len,								/* message length						*/
	uint8_t type								/* message type							*/
);
/*--------------------------------------------------------------------------------------
	Incoming Interest Message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_interest (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len,								/* receive message length				*/
	uint8_t type								/* receive message type					*/
);
/*--------------------------------------------------------------------------------------
	Parse Interest message
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
cef_csmgr_interest_msg_parse (
	unsigned char buff[],						/* receive message						*/
	int buff_len,								/* receive message length				*/
	uint8_t* int_type,							/* Interest type						*/
	unsigned char name[],						/* Content Name							*/
	uint16_t* name_len,							/* Length of content name				*/
	uint32_t* chunk_num,							/* Chunk number							*/
	unsigned char op_data[],					/* Optional Data Field					*/
	uint16_t* op_data_len,						/* Length of Optional Data Field		*/
	unsigned char ver[],						/* Content Version						*/
	uint16_t* ver_len							/* Length of content version			*/
);
/*--------------------------------------------------------------------------------------
	Incoming Get Status Message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_status_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
);
/*--------------------------------------------------------------------------------------
	Incoming Ccninfo Message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_ccninfo_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
);
/*--------------------------------------------------------------------------------------
	Incoming pre-Ccninfo message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_pre_ccninfo_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
);
/*--------------------------------------------------------------------------------------
	Send pre-Ccninfo response message
----------------------------------------------------------------------------------------*/
static void
csmgrd_pre_ccninfo_response_send (
	int sock,									/* recv socket							*/
	uint8_t result								/* result								*/
);

/*--------------------------------------------------------------------------------------
	Receive Increment Access Count message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_increment_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
);
/*--------------------------------------------------------------------------------------
	Receive Echo message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_echo_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
);
/*--------------------------------------------------------------------------------------
	Read white list
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
csmgrd_ext_white_list_read (
	CefT_Csmgrd_Handle* hdl						/* csmgr daemon handle					*/
);
/*--------------------------------------------------------------------------------------
	Get list of host address
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
csmgrd_ext_white_list_get (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	char* value									/* parameter							*/
);
/*--------------------------------------------------------------------------------------
	Add entry to white list
----------------------------------------------------------------------------------------*/
static int 							/* The return value is negative if an error occurs	*/
csmgrd_ext_white_list_entry_add (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	struct addrinfo* addrinfo,					/* address info							*/
	int addr_len
);
/*--------------------------------------------------------------------------------------
	Check registered address in white list
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
csmgrd_white_list_reg_check (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	struct sockaddr_storage* ss					/* socket addr							*/
);
#ifdef CefC_Ccore
/*--------------------------------------------------------------------------------------
	Incoming retrieve cache capacity message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_rcap_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock									/* recv socket							*/
);
/*--------------------------------------------------------------------------------------
	Send retrieve cache response message
----------------------------------------------------------------------------------------*/
static void
csmgrd_rcap_response_send (
	int sock,									/* recv socket							*/
	uint8_t result,								/* result								*/
	uint64_t cap								/* Capacity								*/
);
/*--------------------------------------------------------------------------------------
	Incoming set cache capacity message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_scap_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
);
/*--------------------------------------------------------------------------------------
	Send retrieve cache response message
----------------------------------------------------------------------------------------*/
static void
csmgrd_scap_response_send (
	int sock,									/* recv socket							*/
	uint8_t result								/* result								*/
);
/*--------------------------------------------------------------------------------------
	Incoming Retrieve Content Lifetime message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_rclt_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
);
/*--------------------------------------------------------------------------------------
	Send Retrieve Content Lifetime response message
----------------------------------------------------------------------------------------*/
static void
csmgrd_rclt_response_send (
	int sock,									/* recv socket							*/
	uint8_t result,								/* result								*/
	uint64_t lifetime							/* Lifetime								*/
);
/*--------------------------------------------------------------------------------------
	Incoming Set Content Lifetime message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_sclt_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
);
/*--------------------------------------------------------------------------------------
	Send Set Content Lifetime response message
----------------------------------------------------------------------------------------*/
static void
csmgrd_sclt_response_send (
	int sock,									/* recv socket							*/
	uint8_t result								/* result								*/
);
/*--------------------------------------------------------------------------------------
	Incoming Retrieve Cache Chunk message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_rcch_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
);
/*--------------------------------------------------------------------------------------
	Send Retrieve Cache Chunk response message
----------------------------------------------------------------------------------------*/
static void
csmgrd_rcch_response_send (
	int sock,									/* recv socket							*/
	uint8_t result,								/* result								*/
	unsigned char* info							/* chunk range							*/
);
/*--------------------------------------------------------------------------------------
	Incoming Delete Cache message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_scdl_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
);
/*--------------------------------------------------------------------------------------
	Send Delete Cache response message
----------------------------------------------------------------------------------------*/
static void
csmgrd_scdl_response_send (
	int sock,									/* recv socket							*/
	uint8_t result								/* result								*/
);
#endif // CefC_Ccore
/*--------------------------------------------------------------------------------------
	In the case of START:END, check the validity of the numerical value.
----------------------------------------------------------------------------------------*/
static int
csmgrd_start_end_num_get (
	char* buff,
	int* start,
	int* end
);
/*--------------------------------------------------------------------------------------
	Post process
----------------------------------------------------------------------------------------*/
static void
csmgrd_post_process (
	CefT_Csmgrd_Handle* hdl						/* csmgr daemon handle					*/
);
/*--------------------------------------------------------------------------------------
	Sigcatch Function
----------------------------------------------------------------------------------------*/
static void
csmgrd_sigcatch (
	int sig										/* caught signal						*/
);
/*--------------------------------------------------------------------------------------
	Creates the listening TCP socket with the specified port
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
csmgrd_tcp_sock_create (
	CefT_Csmgrd_Handle* hdl,				/* csmgr daemon handle						*/
	uint16_t 		port_num				/* Port Number that cefnetd listens			*/
);
/*--------------------------------------------------------------------------------------
	Accepts the TCP socket
----------------------------------------------------------------------------------------*/
void
csmgrd_tcp_connect_accept (
	CefT_Csmgrd_Handle* hdl					/* csmgr daemon handle						*/
);
/*--------------------------------------------------------------------------------------
	Search free tcp socket index
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
csmgrd_free_sock_index_search (
	CefT_Csmgrd_Handle* hdl						/* csmgr daemon handle					*/
);

/*--------------------------------------------------------------------------------------
	function for processing the received message
----------------------------------------------------------------------------------------*/
static void*
csmgrd_msg_process_thread (
	void* arg
);
/*--------------------------------------------------------------------------------------
	function for processing the expire check
----------------------------------------------------------------------------------------*/
static void*
csmgrd_expire_check_thread (
	void* arg
);
/*--------------------------------------------------------------------------------------
	function for processing buffering messages
----------------------------------------------------------------------------------------*/
static void*
push_bytes_process_thread (
	void* arg
);
/*--------------------------------------------------------------------------------------
	Get frame from received message
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
csmgr_input_bytes_process (
	CefT_Csmgrd_Handle* hdl,				/* CS Manager Handle						*/
	int peer_fd,
	unsigned char* buff,					/* receive message							*/
	int buff_len							/* message length							*/
);
/*--------------------------------------------------------------------------------------
	Push the buffered messages to proc thread buffer
----------------------------------------------------------------------------------------*/
static void
csmgr_push_bytes_process (
	void
);

/***** 0.8.3c S *****/
#ifdef	CefC_DB_INDEX
static void
csmgrd_node_id_get (
	CefT_Csmgrd_Handle* hdl						/* csmgrd handle						*/
);
#endif
/***** 0.8.3c E *****/



/*---------------------------------------------------------------------------------------
	memory/file Resource monitoring thread & functions
----------------------------------------------------------------------------------------*/
static void*
csmgrd_resource_mon_thread (
	void* arg
);
static int
get_mem_info (
	unsigned char cs_type,
	int* m_total,
		int* m_avaliable,
		uint64_t* m_cob_info
);
static int
get_filesystem_info (
	char *filepath,
	uint64_t *total_blocks,
	uint64_t *avail_blocls
);

/*--------------------------------------------------------------------------------------
	Incoming Contents Information Request message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_continfo_msg(
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
);

/*---------------------------------------------------------------------------------------
	"Upload Request" frame check functions
----------------------------------------------------------------------------------------*/
static int
cef_csmgr_frame_check (
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* message length						*/
);

/****************************************************************************************
 ****************************************************************************************/
/*--------------------------------------------------------------------------------------
	Main function
----------------------------------------------------------------------------------------*/
int
main (
	int argc,
	char* argv[]
) {
	CefT_Csmgrd_Handle* hdl;
	int res;
	int i;
	int dir_path_f 		= 0;

	char*	work_arg;
	char file_path[PATH_MAX] = {0};

	/* Init logging 	*/
	cef_log_init ("csmgrd", 1);

	/* Obtains options 		*/
	for (i = 1 ; i < argc ; i++) {

		work_arg = argv[i];
		if (work_arg == NULL || work_arg[0] == 0) {
			break;
		}

		if (strcmp (work_arg, "-d") == 0) {
			if (dir_path_f) {
				cef_log_write (CefC_Log_Error, "[-d] is specified more than once\n");
			}
			if (i + 1 == argc) {
				cef_log_write (CefC_Log_Error, "[-d] has no parameter.\n");
				return (-1);
			}
			//202108
			if (strlen(argv[i + 1]) > PATH_MAX) {
				cef_log_write (CefC_Log_Error, "[-d] parameter is too long.\n");
				return (-1);
			}
			strcpy (file_path, argv[i + 1]);
			dir_path_f++;
			i++;
		} else {
			cef_log_write (CefC_Log_Error, "unknown option is specified.\n");
			return (-1);
		}
	}
	cef_log_init2 (file_path, 0 /* for CSMGRD */);
#ifdef CefC_Debug
	cef_dbg_init ("csmgrd", file_path, 0);
#endif

	/* Creation the local socket name 	*/
	res = csmgrd_plugin_config_dir_set (file_path);
	if (res < 0) {
		cef_log_write (CefC_Log_Error, "Failed to read csmgrd.conf.\n");
		return (-1);
	}

	//0.8.3c S
#ifdef CefC_DB_INDEX
	res = csmgr_stat_cefore_dir_set_db(file_path);
	if ( res < 0 ) {
		cef_log_write (CefC_Log_Error, "Failed to read dbindexing.conf.\n");
		return (-1);
	}
#endif
	//0.8.3c E

	/* create csmgrd handle */
	hdl = csmgrd_handle_create ();
	if (hdl == NULL) {
		cef_log_write (CefC_Log_Error, "Unable to create csmgrd handle.\n");
		if (strlen (csmgr_local_sock_name) != 0) {
			unlink (csmgr_local_sock_name);
		}
		return (-1);
	}
	cef_frame_init ();

	/* start main process */
	csmgrd_event_dispatch (hdl);

	return (0);
}
/*--------------------------------------------------------------------------------------
	Create csmgr daemon handle
----------------------------------------------------------------------------------------*/
static CefT_Csmgrd_Handle*			/* The return value is null if an error occurs		*/
csmgrd_handle_create (
	void
) {
	CefT_Csmgrd_Handle* hdl = NULL;
	CsmgrT_Config_Param conf_param;
	int i;
	char*	envp;

	/* create handle */
	hdl = (CefT_Csmgrd_Handle*) malloc (sizeof (CefT_Csmgrd_Handle));
	if (hdl == NULL) {
		cef_log_write (CefC_Log_Error, "Failed to get memory required for startup.\n");
		return (NULL);
	}
	/* initialize handle */
	memset (hdl, 0, sizeof (CefT_Csmgrd_Handle));
	hdl->tcp_listen_fd 		= -1;
	hdl->local_listen_fd 	= -1;
	hdl->local_peer_sock 	= -1;

	/* Records the user which launched cefnetd 		*/
	envp = getenv ("USER");
	if (envp == NULL) {
		free (hdl);
		cef_log_write (CefC_Log_Error,
			"Failed to obtain $USER launched cefnetd\n");
		return (NULL);
	}
	memset (hdl->launched_user_name, 0, CefC_Csmgr_User_Len);
	strcpy (hdl->launched_user_name, envp);

	for (i = 0 ; i < CsmgrdC_Max_Sock_Num ; i++) {
		hdl->tcp_buff[i] =
			(unsigned char*) malloc (sizeof (unsigned char) * CefC_Cefnetd_Buff_Max);
	}


#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Loading the config file.\n");
#endif // CefC_Debug
	/* Load config */
	if (csmgrd_config_read (&(conf_param)) < 0) {
		cef_log_write (CefC_Log_Error, "Failed to load the %s\n", CefC_Csmgrd_Conf_Name);
		free (hdl);
		return (NULL);
	}
	hdl->interval = conf_param.interval;

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Create the listen socket.\n");
#endif // CefC_Debug

	/* Creates the local listen socket 		*/
	hdl->local_listen_fd = csmgrd_local_sock_create ();
	if (hdl->local_listen_fd < 0) {
		cef_log_write (CefC_Log_Error, "Fail to create the local listen socket.\n");
		csmgrd_handle_destroy (&hdl);
		return (NULL);
	}

	/* Create tcp listen socket 	*/
	hdl->tcp_listen_fd = csmgrd_tcp_sock_create (hdl, conf_param.port_num);
	if (hdl->tcp_listen_fd < 0) {
		cef_log_write (CefC_Log_Error, "Fail to create the TCP listen socket.\n");
		csmgrd_handle_destroy (&hdl);
		return (NULL);
	}
	hdl->port_num = conf_param.port_num;
	for (i = 0 ; i < CsmgrdC_Max_Sock_Num ; i++) {
		hdl->tcp_fds[i] 	= -1;
		hdl->tcp_index[i] 	= 0;
	}
	cef_log_write (CefC_Log_Info, "Creation the TCP listen socket ... OK\n");

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Create plugin interface.\n");
#endif // CefC_Debug
	/* Create plugin interface */
	hdl->cs_mod_int =
	 				(CsmgrdT_Plugin_Interface*)malloc (sizeof (CsmgrdT_Plugin_Interface));
	if (hdl->cs_mod_int == NULL) {
		cef_log_write (CefC_Log_Error, "Failed to get memory required for startup.\n");
		csmgrd_handle_destroy (&hdl);
		return (NULL);
	}
	memset (hdl->cs_mod_int, 0, sizeof (CsmgrdT_Plugin_Interface));
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Load plugin.\n");
#endif // CefC_Debug
	/* Load plugin */
	strcpy (hdl->cs_mod_name, conf_param.cs_mod_name);
	strcpy (hdl->fsc_cache_path, conf_param.fsc_cache_path);

	if (csmgrd_plugin_load (hdl) < 0) {
		cef_log_write (CefC_Log_Error, "Load plugin error.\n");
		csmgrd_handle_destroy (&hdl);
		return (NULL);
	}

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Check plugin.\n");
#endif // CefC_Debug
	/* Check plugin */
	if (csmgrd_plugin_check (hdl) < 0) {
		cef_log_write (CefC_Log_Error, "Required function is not implemented.\n");
		csmgrd_handle_destroy (&hdl);
		return (NULL);
	}

	//0.8.3c S
#ifdef CefC_DB_INDEX
	{
	int	res;
	csmgrd_node_id_get(hdl);
#ifdef	__DB_IDX_DEBUG
	fprintf( stderr, "After csmgrd_node_id_get() %s \n", hdl->My_Node_Id );
#endif
	res = csmgrd_stat_other_csmgrd_check(hdl->top_nodeid, hdl->top_nodeid_len);
	if (res < 0 ) {
		/* error */
		cef_log_write (CefC_Log_Error, "Failed csmgr_stat_other_csmgrd_check().\n");
		csmgrd_handle_destroy (&hdl);
		return (NULL);
	}
	hdl->First_Node_f = res;
#ifdef	__DB_IDX_DEBUG
	fprintf( stderr, "hdl->First_Node_f %d \n",hdl->First_Node_f );
#endif
	}
#else	//CefC_DB_INDEX
	hdl->First_Node_f = 1;
#endif
	//0.8.3c E

	/* Initialize plugin */
	if (hdl->cs_mod_int->init != NULL) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Initialize plugin.\n");
#endif // CefC_Debug

#ifdef	CefC_DB_INDEX
		{
		CsmgrT_Stat_Table* tbl;
		//0.8.3c
		if ( hdl->First_Node_f == 1 ) {
			stat_hdl = csmgrd_stat_handle_create ();
		} else {
			tbl = (CsmgrT_Stat_Table*) malloc (sizeof (CsmgrT_Stat_Table));
			if ( tbl == NULL ) {
				stat_hdl = CsmgrC_Invalid;
			} else {
				memset (tbl, 0, sizeof (CsmgrT_Stat_Table));
				stat_hdl = (CsmgrT_Stat_Handle)tbl;
			}
		}
		}
#else	//CefC_DB_INDEX
		stat_hdl = csmgrd_stat_handle_create ();
#endif
//0.8.3c		stat_hdl = csmgrd_stat_handle_create ();
		if (stat_hdl == CsmgrC_Invalid) {
			cef_log_write (CefC_Log_Error, "Failed to create csmgrd stat handle.\n");
			csmgrd_handle_destroy (&hdl);
			return (NULL);
		}
//0.8.3c		if (hdl->cs_mod_int->init (stat_hdl) < 0) {
		if (hdl->cs_mod_int->init (stat_hdl, hdl->First_Node_f) < 0) {		//0.8.3c
			cef_log_write (CefC_Log_Error, "Failed to initialize cache plugin.\n");
			csmgrd_handle_destroy (&hdl);
			return (NULL);
		}
		cef_log_write (CefC_Log_Info, "Initialization the cache plugin ... OK\n");
	} else {
		csmgrd_handle_destroy (&hdl);
		cef_log_write (CefC_Log_Info, "Failed to call INIT API.\n");
		return (NULL);
	}

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Read whitelist.\n");
#endif // CefC_Debug
	/* Read whitelist */
	if (csmgrd_ext_white_list_read (hdl) < 0) {
		cef_log_write (CefC_Log_Error, "Failed to read the white list\n");
		csmgrd_handle_destroy (&hdl);
		return (NULL);
	}
	cef_log_write (CefC_Log_Info, "Loading %s ... OK\n", CefC_Csmgrd_Conf_Name);

	csmgr_main_cob_buff =
		(unsigned char*) malloc (sizeof (unsigned char) * CsmgrC_Buff_Size);
	if (csmgr_main_cob_buff == NULL) {
		cef_log_write (CefC_Log_Error, "Failed to allocation cob buffer\n");
		csmgrd_handle_destroy (&hdl);
		return (NULL);
	}
	csmgr_main_cob_buff_idx = 0;

	csmgr_comn_cob_buff =
		(unsigned char*) malloc (sizeof (unsigned char) * CsmgrC_Buff_Size);
	if (csmgr_comn_cob_buff == NULL) {
		cef_log_write (CefC_Log_Error, "Failed to allocation common cob buffer\n");
		csmgrd_handle_destroy (&hdl);
		return (NULL);
	}
	csmgr_comn_cob_buff_idx = 0;

	csmgr_proc_cob_buff =
		(unsigned char*) malloc (sizeof (unsigned char) * CsmgrC_Buff_Max);
	if (csmgr_proc_cob_buff == NULL) {
		cef_log_write (CefC_Log_Error, "Failed to allocation process cob buffer\n");
		csmgrd_handle_destroy (&hdl);
		return (NULL);
	}
	csmgr_proc_cob_buff_idx = 0;

#ifdef CefC_Debug
	/* Show config value */
	cef_dbg_write (CefC_Dbg_Fine, "CACHE_INTERVAL = %lu\n", hdl->interval);
	cef_dbg_write (CefC_Dbg_Fine, "CACHE_TYPE = %s\n", hdl->cs_mod_name);
	cef_dbg_write (CefC_Dbg_Fine, "PORT_NUM = %u\n", hdl->port_num);
	int x;
	char addr[64];
	int len;
	CsmgrT_White_List* wp = hdl->white_list;
	while (wp) {
		len = 0;
		for (x = 0; x < wp->host_addr_len; x++) {
			len = len + sprintf (addr + len, "%02X ", wp->host_addr[x]);
		}
		cef_dbg_write (CefC_Dbg_Fine, "Whitelist node = %s\n", addr);
		wp = wp->next;
	}
#endif // CefC_Debug

	return (hdl);
}
/*--------------------------------------------------------------------------------------
	Main Loop Function
----------------------------------------------------------------------------------------*/
static void
csmgrd_event_dispatch (
	CefT_Csmgrd_Handle* hdl						/* csmgr daemon handle					*/
) {
	struct pollfd fds[CsmgrdC_Max_Sock_Num];
	int fdnum;
	int fds_index[CsmgrdC_Max_Sock_Num];
	int len;
	int res;
	int i;

	pthread_t		csmgrd_msg_process_th;
	pthread_t		csmgrd_expire_check_th;
	pthread_t		push_bytes_process_th;
	pthread_t		csmgrd_resource_mon_th;
	void*			status;

	/* running flag on */
	csmgrd_running_f = 1;

	/* Set signal */
	if (SIG_ERR == signal (SIGINT, csmgrd_sigcatch)) {
		cef_log_write (CefC_Log_Error, "sig_num(%d) is invalid.\n", SIGINT);
		csmgrd_running_f = 0;
	}
	if (SIG_ERR == signal (SIGTERM, csmgrd_sigcatch)) {
		cef_log_write (CefC_Log_Error, "sig_num(%d) is invalid.\n", SIGTERM);
		csmgrd_running_f = 0;
	}

	signal (SIGPIPE, SIG_IGN);

	cef_log_write (CefC_Log_Info, "Running\n");

	if (pthread_create (&csmgrd_msg_process_th, NULL, csmgrd_msg_process_thread, hdl) == -1) {
		cef_log_write (CefC_Log_Error,
						"Failed to create the new thread(csmgrd_msg_process_thread)\n");
		csmgrd_running_f = 0;
	}

	if (pthread_create (&csmgrd_expire_check_th, NULL, csmgrd_expire_check_thread, hdl) == -1) {
		cef_log_write (CefC_Log_Error,
						"Failed to create the new thread(csmgrd_expire_check_thread)\n");
		csmgrd_running_f = 0;
	}

		if (pthread_create (&push_bytes_process_th, NULL, push_bytes_process_thread, hdl) == -1) {
		cef_log_write (CefC_Log_Error,
						"Failed to create the new thread(push_bytes_process_thread)\n");
		csmgrd_running_f = 0;
	}
	if (pthread_create (&csmgrd_resource_mon_th, NULL, csmgrd_resource_mon_thread, hdl) == -1) {
		cef_log_write (CefC_Log_Error,
						"Failed to create the new thread\n");
		csmgrd_running_f = 0;
	}

	/* Main loop */
	while (csmgrd_running_f) {

		/* check accept */
		csmgrd_local_sock_check (hdl);

		/* Checks socket accept 			*/
		csmgrd_tcp_connect_accept (hdl);

		/* Sets fds to be polled 			*/
		fdnum = csmgrd_poll_socket_prepare (hdl, fds, fds_index);
		res = poll (fds, fdnum, 1);
		if (res < 0) {
			/* poll error */
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finer, "poll error (%s)\n", strerror (errno));
#endif // CefC_Debug
			continue;
		}
		if (res == 0) {
			/* poll time out */
			continue;
		}

		/* Checks whether frame(s) arrivals from the active local faces */
		for (i = 0 ; res > 0 && i < CsmgrdC_Max_Sock_Num - 1 ; i++) {
			if (fds[i].revents & (POLLERR | POLLNVAL | POLLHUP)) {
				/* Error occurs, so close this socket 	*/
#ifdef CefC_Debug
				if (fds[i].revents & POLLERR) {
					cef_dbg_write (CefC_Dbg_Fine, "poll events POLLERR\n");
				} else if (fds[i].revents & POLLNVAL) {
					cef_dbg_write (CefC_Dbg_Fine, "poll events POLLNVAL\n");
				} else {
					cef_dbg_write (CefC_Dbg_Fine, "poll events POLLHUP\n");
				}
#endif // CefC_Debug
				if ((hdl->local_peer_sock != -1) && (fds[i].fd == hdl->local_peer_sock)) {
					/* Close Local socket */
					close (hdl->local_peer_sock);
					hdl->local_peer_sock = -1;
					cef_log_write (CefC_Log_Info, "Close Local peer\n");
				} else {
					/* Close TCP socket */
					if (hdl->tcp_fds[fds_index[i]] != -1) {
						close (hdl->tcp_fds[fds_index[i]]);
						hdl->tcp_fds[fds_index[i]] = -1;
						cef_log_write (CefC_Log_Info, "Close TCP peer: %s:%s\n",
							hdl->peer_id_str[fds_index[i]],
							hdl->peer_sv_str[fds_index[i]]);
						hdl->peer_num--;
					}
					/* Reset buffer */
					hdl->tcp_index[fds_index[i]] = 0;
				}
				res--;
				continue;
			}

			if (fds[i].revents & POLLIN) {
				res--;
				len = recv (fds[i].fd,
					&hdl->tcp_buff[fds_index[i]][hdl->tcp_index[fds_index[i]]],
					CefC_Cefnetd_Buff_Max - hdl->tcp_index[fds_index[i]], 0);
				if (len > 0) {
					/* receive message */
					len += hdl->tcp_index[fds_index[i]];

					len = csmgr_input_bytes_process (
							hdl, fds[i].fd,
							&hdl->tcp_buff[fds_index[i]][0], len);

					/* set index */
					if (len > 0) {
						hdl->tcp_index[fds_index[i]] = len;
					} else {
						hdl->tcp_index[fds_index[i]] = 0;
					}
				} else if (len == 0) {
					if ((hdl->local_peer_sock != -1) &&
						(fds[i].fd == hdl->local_peer_sock)) {
						/* Close Local socket */
						close (hdl->local_peer_sock);
						hdl->local_peer_sock = -1;
						cef_log_write (CefC_Log_Info, "Close Local peer\n");
					} else {
						/* Close TCP socket */
						if (hdl->tcp_fds[fds_index[i]] != -1) {
							close (hdl->tcp_fds[fds_index[i]]);
							hdl->tcp_fds[fds_index[i]] = -1;
							cef_log_write (CefC_Log_Info, "Close TCP peer: %s:%s\n",
								hdl->peer_id_str[fds_index[i]],
								hdl->peer_sv_str[fds_index[i]]);
							hdl->peer_num--;
						}
						/* Reset buffer */
						hdl->tcp_index[fds_index[i]] = 0;
					}
				} else {
					if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
						/* Error occurs, so close this socket 	*/
						if ((hdl->local_peer_sock != -1) &&
							(fds[i].fd == hdl->local_peer_sock)) {
							/* Close Local socket */
							cef_log_write (CefC_Log_Warn,
								"Receive error (%d) . Close Local socket\n", errno);
							close (hdl->local_peer_sock);
							hdl->local_peer_sock = -1;
							cef_log_write (CefC_Log_Info, "Close Local peer\n");
						} else {
							/* Close TCP socket */
							cef_log_write (CefC_Log_Warn,
								"Receive error (%d) . Close tcp socket\n", errno);
							cef_log_write (CefC_Log_Warn, "%s\n", strerror (errno));
							if (hdl->tcp_fds[fds_index[i]] != -1) {
								cef_log_write (CefC_Log_Warn, "Close TCP peer: %s:%s\n",
									hdl->peer_id_str[fds_index[i]],
									hdl->peer_sv_str[fds_index[i]]);
								close (hdl->tcp_fds[fds_index[i]]);
								hdl->tcp_fds[fds_index[i]] = -1;
								hdl->peer_num--;
							}
							/* Reset buffer */
							hdl->tcp_index[fds_index[i]] = 0;
						}
					}
				}
			}
		}
	}
	pthread_cond_signal (&csmgr_comn_buff_cond);		/* To avoid deadlock */
	pthread_join (csmgrd_msg_process_th, &status);
	pthread_join (csmgrd_expire_check_th, &status);
	pthread_join (push_bytes_process_th, &status);
	pthread_cond_destroy (&csmgr_comn_buff_cond);

	/* post process */
	csmgrd_post_process (hdl);
	cef_log_write (CefC_Log_Info, "Stop\n");



	return;
}

/*--------------------------------------------------------------------------------------
	function for processing the received message
----------------------------------------------------------------------------------------*/
static void*
csmgrd_msg_process_thread (
	void* arg
) {
	CefT_Csmgrd_Handle* hdl = (CefT_Csmgrd_Handle*) arg;

	while (csmgrd_running_f) {
		pthread_mutex_lock (&csmgr_comn_buff_mutex);
		pthread_cond_wait (&csmgr_comn_buff_cond, &csmgr_comn_buff_mutex);

		if (csmgr_comn_cob_buff_idx > 0) {
			if (CsmgrC_Buff_Max - csmgr_proc_cob_buff_idx >
				csmgr_comn_cob_buff_idx) {

				memcpy (
					&csmgr_proc_cob_buff[csmgr_proc_cob_buff_idx],
					&csmgr_comn_cob_buff[0],
					csmgr_comn_cob_buff_idx);
				csmgr_proc_cob_buff_idx += csmgr_comn_cob_buff_idx;
			}
			csmgr_comn_cob_buff_idx = 0;
		}
		pthread_mutex_unlock (&csmgr_comn_buff_mutex);

		if (csmgr_proc_cob_buff_idx > 0) {
			hdl->cs_mod_int->cache_item_puts (
							csmgr_proc_cob_buff, csmgr_proc_cob_buff_idx);
			csmgr_proc_cob_buff_idx = 0;
		}
	}

	pthread_exit (NULL);

	return ((void*) NULL);
}
/*--------------------------------------------------------------------------------------
	function for processing the expire check
----------------------------------------------------------------------------------------*/
static void*
csmgrd_expire_check_thread (
	void* arg
) {

	CefT_Csmgrd_Handle* hdl = (CefT_Csmgrd_Handle*) arg;
	uint64_t interval = (uint64_t) hdl->interval * 1000;
	uint64_t nowt = cef_client_present_timeus_calc ();
	uint64_t expire_check_time = nowt + interval;

	while (csmgrd_running_f) {
		sleep (1);
		nowt = cef_client_present_timeus_calc ();
		/* Checks content expire 			*/
		if ((interval != 0) && (nowt > expire_check_time)) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finer, "Checks for expired contents.\n");
#endif // CefC_Debug
			hdl->cs_mod_int->expire_check ();
			/* set interval */
			expire_check_time = nowt + interval;
		}
	}

	pthread_exit (NULL);

	return ((void*) NULL);
}
/*--------------------------------------------------------------------------------------
	function for processing buffering messages
----------------------------------------------------------------------------------------*/
static void*
push_bytes_process_thread (
	void* arg
) {

	while (csmgrd_running_f) {
		usleep (csmgr_wait_time);
		csmgr_push_bytes_process ();
	}

	pthread_exit (NULL);

	return ((void*) NULL);
}
/*--------------------------------------------------------------------------------------
	Get frame from received message
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
csmgr_input_bytes_process (
	CefT_Csmgrd_Handle* hdl,				/* CS Manager Handle						*/
	int peer_fd,
	unsigned char* buff,					/* receive message							*/
	int buff_len							/* message length							*/
) {
	int index = 0;
	uint16_t len;
	uint16_t value16;
	int rec_buff_len = buff_len;
	int res;

	while (buff_len > CefC_Csmgr_Msg_HeaderLen) {
		/* searches the top of massage 		*/
		if ((buff[index + CefC_O_Fix_Ver] != CefC_Version) ||
			(buff[index + CefC_O_Fix_Type] >= CefC_Csmgr_Msg_Type_Num) ||
			(buff[index + CefC_O_Fix_Type] == CefC_Csmgr_Msg_Type_Invalid)) {

			buff_len--;
			index++;

			while (buff_len > CefC_Csmgr_Msg_HeaderLen) {

				if ((buff[index + CefC_O_Fix_Ver] != CefC_Version) ||
					(buff[index + CefC_O_Fix_Type] >= CefC_Csmgr_Msg_Type_Num) ||
					(buff[index + CefC_O_Fix_Type] == CefC_Csmgr_Msg_Type_Invalid)) {

					buff_len--;
					index++;
				} else {
					break;
				}
			}
			if (buff_len <= CefC_Csmgr_Msg_HeaderLen) {
				break;
			}
		}

		/* obtains the length of message 		*/
		memcpy (&value16, &buff[index + CefC_O_Length], CefC_S_Length);
		len = ntohs (value16);

		if (len > buff_len) {
			break;
		}

		/* check the type of message 			*/
		if (buff[index + CefC_O_Fix_Type] != CefC_Csmgr_Msg_Type_UpReq) {
			res = csmgrd_input_message_process (hdl, peer_fd,
				&buff[index + CefC_Csmgr_Msg_HeaderLen], len - CefC_Csmgr_Msg_HeaderLen,
				buff[index + CefC_O_Fix_Type]);
			if (res < 0) {
				return (0);
			}
		} else {
			int cstat;
			cstat = cef_csmgr_frame_check (&buff[index], len);
			if (cstat < 0) {
//@@@@@fprintf(stderr, "[%s]: [------ goto SKIP; [cstat < 0] -----\n", __FUNCTION__);
				goto SKIP;
			}
			pthread_mutex_lock (&csmgr_Lack_of_resources_mutex);
			if (Lack_of_F_resources == 1) {
				pthread_mutex_unlock (&csmgr_Lack_of_resources_mutex);
				goto SKIP;
			}
			if (Lack_of_M_resources == 1) {
				pthread_mutex_unlock (&csmgr_Lack_of_resources_mutex);
				goto SKIP;
			}
			pthread_mutex_unlock (&csmgr_Lack_of_resources_mutex);
			if (pthread_mutex_trylock (&csmgr_main_cob_buff_mutex) != 0) {
				goto SKIP;
			}
			if (csmgr_main_cob_buff_idx + len > CsmgrC_Buff_Size) {
				pthread_mutex_lock (&csmgr_comn_buff_mutex);

				memcpy (
					csmgr_comn_cob_buff,
					csmgr_main_cob_buff,
					csmgr_main_cob_buff_idx);
				csmgr_comn_cob_buff_idx = csmgr_main_cob_buff_idx;
				csmgr_main_cob_buff_idx = 0;

				pthread_cond_signal (&csmgr_comn_buff_cond);
				pthread_mutex_unlock (&csmgr_comn_buff_mutex);
			}
			memcpy (
				&csmgr_main_cob_buff[csmgr_main_cob_buff_idx],
				&buff[index], len);

			csmgr_main_cob_buff_idx += len;
			pthread_mutex_unlock (&csmgr_main_cob_buff_mutex);
		}

SKIP:;
		buff_len -= len;
		index += len;
	}

	if (index < rec_buff_len) {
		memmove (&buff[0], &buff[index], buff_len);
	}
	return (buff_len);
}
/*--------------------------------------------------------------------------------------
	Push the buffered messages to proc thread buffer
----------------------------------------------------------------------------------------*/
static void
csmgr_push_bytes_process (
	void
) {
	pthread_mutex_lock (&csmgr_main_cob_buff_mutex);

	if (csmgr_main_cob_buff_idx > 0) {

		pthread_mutex_lock (&csmgr_comn_buff_mutex);

		if (csmgr_main_cob_buff_idx  > 0) {
			memcpy (
				csmgr_comn_cob_buff,
				csmgr_main_cob_buff,
				csmgr_main_cob_buff_idx);

			csmgr_comn_cob_buff_idx = csmgr_main_cob_buff_idx;
			csmgr_main_cob_buff_idx = 0;
		}

		pthread_cond_signal (&csmgr_comn_buff_cond);
		pthread_mutex_unlock (&csmgr_comn_buff_mutex);
	}
	pthread_mutex_unlock (&csmgr_main_cob_buff_mutex);

	return;
}
/*--------------------------------------------------------------------------------------
	Create local socket
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
csmgrd_local_sock_create (
	void
) {
	int sock = -1;
	struct sockaddr_un saddr;
	int flag;
	size_t len;

	/* init socket */
	if ((sock = socket (AF_UNIX, SOCK_STREAM, 0)) < 0) {
		return (-1);
	}
	/* init sockaddr_un */
	memset (&saddr, 0, sizeof (saddr));
	saddr.sun_family = AF_UNIX;

	len = strlen (csmgr_local_sock_name);
	if (len == 0) {
		close (sock);
		return (-1);
	}
	strcpy (saddr.sun_path, csmgr_local_sock_name);
	unlink (csmgr_local_sock_name);

	/* Prepares a source socket */
#ifdef __APPLE__
	saddr.sun_len = sizeof (saddr);

	if (bind (sock, (struct sockaddr*)&saddr, SUN_LEN (&saddr)) < 0) {
		return (-1);
	}
#else // __APPLE__
	if (bind (sock, (struct sockaddr*)&saddr , sizeof (saddr.sun_family) + len) < 0) {
		return (-1);
	}
#endif // __APPLE__

	/* check error */
	if (sock < 0) {
		return (-1);
	}

	/* listen socket */
	if (listen (sock, 16) < 0) {
		close (sock);
		return (-1);
	}
	/* set non blocking */
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
	Check accept from local socket
----------------------------------------------------------------------------------------*/
static void
csmgrd_local_sock_check (
	CefT_Csmgrd_Handle* hdl						/* CS Manager Handle					*/
) {
	int sock;
	int flag;
	struct sockaddr_storage peeraddr;
	socklen_t addrlen = (socklen_t)sizeof (peeraddr);

	/* Accepts the interrupt from local process */
	if ((sock =
			accept (hdl->local_listen_fd, (struct sockaddr*)&peeraddr, &addrlen)) > 0) {
		flag = fcntl (sock, F_GETFL, 0);
		if (flag < 0) {
			return;
		} else {
			if (fcntl (sock, F_SETFL, flag | O_NONBLOCK) < 0) {
				return;
			}
		}
		if (hdl->local_peer_sock != -1) {
			close (hdl->local_peer_sock);
		}
		hdl->local_peer_sock = sock;
	}

	return;
}
/*--------------------------------------------------------------------------------------
	Destroy csmgr daemon handle
----------------------------------------------------------------------------------------*/
static void
csmgrd_handle_destroy (
	CefT_Csmgrd_Handle** csmgrd_hdl				/* CS Manager Handle					*/
) {
	CefT_Csmgrd_Handle* hdl = *csmgrd_hdl;
	int i;
	int		Last_Node_f = 0;

	/* Check handle */
	if (hdl == NULL) {
		/* Unlink local sock */
		if (strlen (csmgr_local_sock_name) != 0) {
			unlink (csmgr_local_sock_name);
		}
		return;
	}
	/* Close local listen socket */
	if (hdl->local_listen_fd != -1) {
		close (hdl->local_listen_fd);
		hdl->local_listen_fd = -1;
	}
	if (hdl->local_peer_sock != -1) {
		close (hdl->local_peer_sock);
		hdl->local_peer_sock = -1;
	}

	/* Close Tcp listen socket */
	if (hdl->tcp_listen_fd != -1) {

		for (i = 1 ; i < CsmgrdC_Max_Sock_Num ; i++) {
			if (hdl->tcp_fds[i] > 0) {
				close (hdl->tcp_fds[i]);
			}
		}
		close (hdl->tcp_listen_fd);
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine,
				"Close TCP listen sock #%d ... OK\n", hdl->tcp_listen_fd);
#endif // CefC_Debug
		hdl->tcp_listen_fd = -1;
	}

	//0.8.3c S
#ifdef CefC_DB_INDEX
	{
	int	res;
	res = csmgrd_stat_last_csmgrd_check(hdl->top_nodeid, hdl->top_nodeid_len);
	if (res < 0 ) {
		res = 0;
	}
	Last_Node_f = res;
//	fprintf( stderr, "Last_Node_f %d \n", Last_Node_f );
	}
#else	//CefC_DB_INDEX
	Last_Node_f = 0;
#endif
	//0.8.3c E


	/* Close library */
	if (hdl->cs_mod_int != NULL) {
		/* Destroy plugin */
		if (hdl->cs_mod_int->destroy != NULL) {
//0.8.3c			hdl->cs_mod_int->destroy ();
			hdl->cs_mod_int->destroy ( Last_Node_f );	//0.8.3c
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Destroy plugin ... OK\n");
#endif // CefC_Debug
		}
		free (hdl->cs_mod_int);
		hdl->cs_mod_int = NULL;
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Free cs_mod_int ... OK\n");
#endif // CefC_Debug
	}
	if (hdl->mod_lib != NULL) {
		if (dlclose (hdl->mod_lib) == 0) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "dlclose Cache Plugin ... OK\n");
#endif // CefC_Debug
		} else {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "dlclose Cache Plugin ... NG\n");
#endif // CefC_Debug
		}
	}

	/* Delete white list */
	if (hdl->white_list != NULL) {
		CsmgrT_White_List* next;
		while (hdl->white_list != NULL) {
			next = hdl->white_list->next;
			free (hdl->white_list);
			hdl->white_list = next;
		}
	}

	/* Unlink local sock */
	if (strlen (csmgr_local_sock_name) != 0) {
		unlink (csmgr_local_sock_name);
	}
	if (csmgr_main_cob_buff) {
		free (csmgr_main_cob_buff);
	}
	if (csmgr_comn_cob_buff) {
		free (csmgr_comn_cob_buff);
	}
	free (hdl);
	*csmgrd_hdl = NULL;

	//0.8.3c S
	if ( Last_Node_f == 0 ) {
		csmgrd_stat_handle_destroy (stat_hdl);
	}
//	csmgrd_stat_handle_destroy (stat_hdl);
	//0.8.3c E
	/* Unlink local sock */
	if (strlen (csmgr_local_sock_name) != 0) {
		unlink (csmgr_local_sock_name);
	}

	return;
}
/*--------------------------------------------------------------------------------------
	Read config file
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
csmgrd_config_read (
	CsmgrT_Config_Param* conf_param				/* parameter of config					*/
) {
	FILE*	fp = NULL;								/* file pointer						*/
	char	file_name[1024];						/* file name						*/
	char	param[4096] = {0};						/* parameter						*/
	char	param_buff[4096] = {0};					/* param buff						*/
	int		len;									/* read length						*/
	char*	option;									/* deny option						*/
	char*	value;									/* parameter						*/
	int		i, n;
	int64_t	res;

	/* Obtains the directory path where the csmgrd's config file is located. */
#if 0 //+++++ GCC v9 +++++
	sprintf (file_name, "%s/%s", csmgr_conf_dir, CefC_Csmgrd_Conf_Name);
#else
	int		rc;
	rc = snprintf (file_name, sizeof(file_name), "%s/%s", csmgr_conf_dir, CefC_Csmgrd_Conf_Name);
	if (rc < 0) {
		cef_log_write (CefC_Log_Error, "Config file dir path too long(%s)\n", csmgr_conf_dir);
		return (-1);
	}
#endif //----- GCC v9 -----

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, "csmgrd config path = %s\n", file_name);
#endif // CefC_Debug

	/* Opens the csmgr's config file. */
	fp = fopen (file_name, "r");
	if (fp == NULL) {
		cef_log_write (CefC_Log_Error, "%s\n", strerror (errno));
		return (-1);
	}

	/* Set default value */
	conf_param->interval	= CefC_Default_Int_Check_Cache;
	strcpy (conf_param->cs_mod_name, "filesystem");
	strcpy (conf_param->fsc_cache_path, csmgr_conf_dir);
	conf_param->port_num 	= CefC_Default_Tcp_Prot;
	strcpy (conf_param->local_sock_id, "0");

	/* get parameter */
	while (fgets (param_buff, sizeof (param_buff), fp) != NULL) {
		len = strlen (param_buff);
		/* check comment and newline character */
		if ((param_buff[0] == '#') || (param_buff[0] == '\n') || (len == 0)) {
			continue;
		}
		if (param_buff[len - 1] == '\n') {
			param_buff[len - 1] = '\0';
		}
		/* remove blank */
		for (i = 0, n = 0; i < len; i++) {
			if (param_buff[i] != ' ') {
				param[n] = param_buff[i];
				n++;
			}
		}
		/* get option */
		value = param;
		option = strsep (&value, "=");
		if (value == NULL) {
			cef_log_write (CefC_Log_Warn, "Read invalid config value (%s).\n", option);
			continue;
		}

		if (strcmp (option, "CACHE_INTERVAL") == 0) {
			res = csmgrd_config_value_get (option, value);
			if ((res < 1000) || (res > 86400000/* 24 hours */)) {
				cef_log_write (CefC_Log_Error,
					"CACHE_INTERVAL value must be higher than or equal to "
					"1000 and lower than 86400000 (24 hours).\n");
				fclose (fp);
				return (-1);
			}
			conf_param->interval = res;
		} else if (strcmp (option, "CACHE_TYPE") == 0) {
			res = strlen (value);
			if (res > CsmgrdC_Max_Plugin_Name_Len) {
				cef_log_write (CefC_Log_Error,
					"EXCACHE_PLUGIN (Invalid value %s=%s)\n", option, value);
				fclose (fp);
				return (-1);
			}
			strcpy (conf_param->cs_mod_name, value);
			if (!(strcmp (conf_param->cs_mod_name, "filesystem") == 0
				    ||
				  strcmp (conf_param->cs_mod_name, "memory") == 0
#ifdef CefC_Db
				    ||
				  strcmp (conf_param->cs_mod_name, "db") == 0
#endif //DCefC_Db
			     )) {
				cef_log_write (CefC_Log_Error,
					"EXCACHE_PLUGIN (Invalid value CACHE_TYPE=%s)\n", conf_param->cs_mod_name);
				fclose (fp);
				return (-1);
			}
		} else if (strcmp (option, "CACHE_PATH") == 0) {
			res = strlen (value);
			if (res > CefC_Csmgr_File_Path_Length) {
				cef_log_write (CefC_Log_Error,
					"EXCACHE_PLUGIN (Invalid value %s=%s)\n", option, value);
				fclose (fp);
				return (-1);
			}
			strcpy (conf_param->fsc_cache_path, value);
		} else if (strcmp (option, "PORT_NUM") == 0) {
			res = csmgrd_config_value_get (option, value);
			if ((res < 1025) || (res > 65535)) {
				cef_log_write (CefC_Log_Error,
					"PORT_NUM must be higher than 1024 and lower than 65536.\n");
				fclose (fp);
				return (-1);
			}
			conf_param->port_num = res;
		} else if (strcmp (option, "LOCAL_SOCK_ID") == 0) {
			if (strlen (value) > 1024) {
				cef_log_write (CefC_Log_Error,
					"LOCAL_SOCK_ID must be shorter than 1024.\n");
				fclose (fp);
				return (-1);
			}
			strcpy (conf_param->local_sock_id, value);
		} else {
			continue;
		}
	}

	if (strcmp (conf_param->cs_mod_name, "filesystem") == 0) {
		if (!(    access (conf_param->fsc_cache_path, F_OK) == 0
			   && access (conf_param->fsc_cache_path, R_OK) == 0
	   		   && access (conf_param->fsc_cache_path, W_OK) == 0
	   		   && access (conf_param->fsc_cache_path, X_OK) == 0)) {
			cef_log_write (CefC_Log_Error,
				"EXCACHE_PLUGIN (Invalid value CACHE_PATH=%s) - %s\n", conf_param->fsc_cache_path, strerror (errno));
			fclose (fp);
			return (-1);
	    }
	}


	sprintf (csmgr_local_sock_name,
		"/tmp/csmgr_%d.%s", conf_param->port_num, conf_param->local_sock_id);

	fclose (fp);

	return (0);
}
/*--------------------------------------------------------------------------------------
	Change str to value
----------------------------------------------------------------------------------------*/
static int64_t						/* The return value is negative if an error occurs	*/
csmgrd_config_value_get (
	char* option,								/* csmgrd option						*/
	char* value									/* String								*/
) {
	int i;
	uint64_t res;
	/* Check num */
	for (i = 0; value[i]; i++) {
		if (isdigit (value[i]) == 0) {
			return (-1);
		}
	}
	/* Change str */
	res = (uint64_t)strtoull (value, NULL, 10);
	if (res == ULLONG_MAX) {
		if (errno == ERANGE) {
			/* Overflow */
			return (-1);
		}
	}
	/* Check num */
	if (res > UINT32_MAX) {
		return (-1);
	}
	return (res);
}
/*--------------------------------------------------------------------------------------
	Load plugin
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
csmgrd_plugin_load (
	CefT_Csmgrd_Handle* hdl						/* csmgr daemon handle					*/
) {
	int (*func)(CsmgrdT_Plugin_Interface*, const char*);
	char func_name[256] = {0};

	/* Open library */
	hdl->mod_lib = dlopen (CsmgrdC_Plugin_Library_Name, RTLD_LAZY);
	if (hdl->mod_lib == NULL) {
		cef_log_write (CefC_Log_Error, "%s\n", dlerror ());
		return (-1);
	}

	/* Load plugin */
	sprintf (func_name, "csmgrd_%s_plugin_load", hdl->cs_mod_name);
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Plugin name = %s.\n", func_name);
#endif // CefC_Debug
	func = dlsym (hdl->mod_lib, (const char*)func_name);
	if (func == NULL) {
		cef_log_write (CefC_Log_Error, "%s\n", dlerror ());
		/* close library */
		dlclose (hdl->mod_lib);
		return (-1);
	}

	/* Load functions */
	if ((func) (hdl->cs_mod_int, csmgr_conf_dir) != 0) {
		cef_log_write (CefC_Log_Error, "Initialize function is not set.\n");
		dlclose (hdl->mod_lib);
		return (-1);
	}

	return (0);
}
/*--------------------------------------------------------------------------------------
	Check plugin
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
csmgrd_plugin_check (
	CefT_Csmgrd_Handle* hdl						/* csmgr daemon handle					*/
) {
	if (hdl->cs_mod_int->cache_item_get == NULL) {
		cef_log_write (
			CefC_Log_Error, "Load cache plugin (cache_item_get is not set)\n");
		return (-1);
	}
	if (hdl->cs_mod_int->cache_item_puts == NULL) {
		cef_log_write (
			CefC_Log_Error, "Load cache plugin (cache_item_puts is not set)\n");
		return (-1);
	}
	if (hdl->cs_mod_int->expire_check == NULL) {
		cef_log_write (
			CefC_Log_Error, "Load cache plugin (expire_check is not set)\n");
		return (-1);
	}
	return (0);
}
/*--------------------------------------------------------------------------------------
	Sets the path of csmgrd.conf
----------------------------------------------------------------------------------------*/
static int
csmgrd_plugin_config_dir_set (
	const char* config_file_dir
) {
	FILE* 	fp;
 	char	file_path[PATH_MAX];
	char*	wp;

	if (config_file_dir[0] != 0x00) {
#if 0 //+++++ GCC v9 +++++
		sprintf (file_path, "%s/csmgrd.conf", config_file_dir);
#else
		int		rc;
		rc = snprintf (file_path, sizeof(file_path), "%s/csmgrd.conf", config_file_dir);
		if (rc < 0) {
			cef_log_write (CefC_Log_Error, "Config file dir path too long(%s)\n", config_file_dir);
			return (-1);
		}
#endif //----- GCC v9 -----
		strcpy (csmgr_conf_dir, config_file_dir);
	} else {
		wp = getenv (CefC_CEFORE_DIR);
		if (wp != NULL && wp[0] != 0) {
			sprintf (file_path, "%s/cefore/csmgrd.conf", wp);
			sprintf (csmgr_conf_dir, "%s/cefore", wp);
		} else {
			sprintf (file_path, "%s/csmgrd.conf", CefC_CEFORE_DIR_DEF);
			strcpy (csmgr_conf_dir, CefC_CEFORE_DIR_DEF);
		}
	}

	fp = fopen (file_path, "r");
	if (fp == NULL) {
		cef_log_write (CefC_Log_Error, "Failed to open %s\n", file_path);
		return (-1);
	}
	fclose (fp);
	cef_log_write (CefC_Log_Info, "Config directory is %s.\n", csmgr_conf_dir);

	return (1);
}
/*--------------------------------------------------------------------------------------
	Search free tcp socket index
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
csmgrd_free_sock_index_search (
	CefT_Csmgrd_Handle* hdl						/* csmgr daemon handle					*/
) {
	int i;
	for (i = 1 ; i < CsmgrdC_Max_Sock_Num; i++) {
		if (hdl->tcp_fds[i] == -1) {
			return (i);
		}
	}
	return (-1);
}
/*--------------------------------------------------------------------------------------
	Creates the listening TCP socket with the specified port
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
csmgrd_tcp_sock_create (
	CefT_Csmgrd_Handle* hdl,				/* csmgr daemon handle						*/
	uint16_t 		port_num				/* Port Number that cefnetd listens			*/
) {
	struct addrinfo hints;
	struct addrinfo* res;
	struct addrinfo* cres;
	int err;
	char port_str[32];
	int sock;
	int create_sock_f = 0;
	int reuse_f = 1;
	int flag;

	/* Creates the hint 		*/
	memset (&hints, 0, sizeof (hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	sprintf (port_str, "%d", port_num);

	/* Obtains the addrinfo 		*/
	if ((err = getaddrinfo (NULL, port_str, &hints, &res)) != 0) {
		cef_log_write (CefC_Log_Error,
			"Could not create the TCP listen socket. : %s\n", gai_strerror (err));
		return (-1);
	}

	for (cres = res; cres != NULL; cres = cres->ai_next) {
		sock = socket (cres->ai_family, cres->ai_socktype, 0);
		if (sock < 0) {
			cef_log_write (CefC_Log_Warn,
				"Could not create the TCP listen socket. : %s\n", strerror (errno));
			continue;
		}
		setsockopt (sock,
			SOL_SOCKET, SO_REUSEADDR, &reuse_f, sizeof (reuse_f));

		switch (cres->ai_family) {
			case AF_INET: {
				create_sock_f = 1;
				hdl->ai_addr 		= cres->ai_addr;
				hdl->ai_addrlen 	= cres->ai_addrlen;
				hdl->tcp_listen_fd 	= sock;
				break;
			}
			case AF_INET6: {
				create_sock_f = 1;
				hdl->ai_addr 		= cres->ai_addr;
				hdl->ai_addrlen 	= cres->ai_addrlen;
				hdl->tcp_listen_fd 	= sock;
				break;
			}
			default: {
				/* NOP */
				cef_log_write (CefC_Log_Warn,
					"Unknown socket family : %d\n", cres->ai_family);
				break;
			}
		}
		if (create_sock_f) {
			break;
		}
	}

	if (create_sock_f) {

		if (bind (hdl->tcp_listen_fd, hdl->ai_addr, hdl->ai_addrlen) < 0) {
			close (hdl->tcp_listen_fd);
			cef_log_write (CefC_Log_Error,
				"Could not create the TCP listen socket. : %s\n", strerror (errno));
			return (-1);
		}
		if (listen (hdl->tcp_listen_fd, CsmgrdC_Max_Sock_Num) < 0) {
			cef_log_write (CefC_Log_Error,
				"Could not create the TCP listen socket. : %s\n", strerror (errno));
			return (-1);
		}
		flag = fcntl (hdl->tcp_listen_fd, F_GETFL, 0);
		if (flag < 0) {
			cef_log_write (CefC_Log_Error,
				"Could not create the TCP listen socket. : %s\n", strerror (errno));
			return (-1);
		}
		if (fcntl (hdl->tcp_listen_fd, F_SETFL, flag | O_NONBLOCK) < 0) {
			cef_log_write (CefC_Log_Error,
				"Could not create the TCP listen socket. : %s\n", strerror (errno));
			return (-1);
		}

		return (hdl->tcp_listen_fd);
	}

	return (-1);
}
/*--------------------------------------------------------------------------------------
	Accepts the TCP socket
----------------------------------------------------------------------------------------*/
void
csmgrd_tcp_connect_accept (
	CefT_Csmgrd_Handle* hdl					/* csmgr daemon handle						*/
) {
	struct sockaddr_storage sa;
	socklen_t sa_len = sizeof (struct sockaddr_storage);
	int cs;
	int flag;
	char ip_str[NI_MAXHOST];
	char port_str[NI_MAXSERV];
	int i;
	int new_accept_f = 1;
	int err;

	/* Accepts the TCP SYN 		*/
	memset (&sa, 0, sizeof (struct sockaddr_storage));
	cs = accept (hdl->tcp_listen_fd, (struct sockaddr*) &sa, &sa_len);
	if (cs < 0) {
		return;
	}

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine,
		"Received the new connection request. Check whitelist\n");
#endif // CefC_Debug
	/* Check address */
	if (csmgrd_white_list_reg_check (hdl, &sa) < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Could not find the node in the whitelist.\n");
		if (getnameinfo ((struct sockaddr*) &sa, sa_len, ip_str, sizeof (ip_str),
				port_str, sizeof (port_str), NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
			cef_dbg_write (CefC_Dbg_Fine, "rejected node = %s:%s\n", ip_str, port_str);
		}
#endif // CefC_Debug
		goto POST_ACCEPT;
	}
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Find the node in the whitelist.\n");
#endif // CefC_Debug

	flag = fcntl (cs, F_GETFL, 0);
	if (flag < 0) {
		cef_log_write (CefC_Log_Warn,
			"Failed to create new tcp connection : %s\n", strerror (errno));
		goto POST_ACCEPT;
	}
	if (fcntl (cs, F_SETFL, flag | O_NONBLOCK) < 0) {
		cef_log_write (CefC_Log_Warn,
			"Failed to create new tcp connection : %s\n", strerror (errno));
		goto POST_ACCEPT;
	}
	if ((err = getnameinfo ((struct sockaddr*) &sa, sa_len, ip_str, sizeof (ip_str),
			port_str, sizeof (port_str), NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
		cef_log_write (CefC_Log_Warn,
			"Failed to create new tcp connection : %s\n", gai_strerror (err));
		goto POST_ACCEPT;
	}

	/* Looks up the source node's information from the source table 	*/
	for (i = 1 ; i < CsmgrdC_Max_Sock_Num ; i++) {
		if ((strcmp (hdl->peer_id_str[i], ip_str) == 0) &&
			(strcmp (hdl->peer_sv_str[i], port_str) == 0)) {
			if (hdl->tcp_fds[i] != -1) {
				cef_log_write (CefC_Log_Info, "Close TCP peer: [%d] %s:%s, socket : %d\n",
					i, hdl->peer_id_str[i], hdl->peer_sv_str[i], hdl->tcp_fds[i]);
				close (hdl->tcp_fds[i]);
				hdl->tcp_fds[i] 	= -1;
				hdl->tcp_index[i] 	= 0;
				hdl->peer_num--;
				new_accept_f = 0;
			}
			break;
		}
	}

	/* Records the new accepted socket 		*/
	if (new_accept_f) {
		i = csmgrd_free_sock_index_search (hdl);

		if (i > -1) {
			strcpy (hdl->peer_id_str[i], ip_str);
			strcpy (hdl->peer_sv_str[i], port_str);
			cef_log_write (CefC_Log_Info, "Open TCP peer: %s:%s, socket : %d\n",
				hdl->peer_id_str[i], hdl->peer_sv_str[i], cs);
			hdl->peer_num++;
			hdl->tcp_fds[i] 	= cs;
			hdl->tcp_index[i] 	= 0;

			cef_csmgr_send_msg (hdl->tcp_fds[i],
				(unsigned char*) CefC_Csmgr_Cmd_ConnOK, strlen (CefC_Csmgr_Cmd_ConnOK));
		} else {
			cef_log_write (CefC_Log_Warn,
				"TCP socket num is full. Could not find the free socket.\n");
			goto POST_ACCEPT;
		}
	} else {
		cef_log_write (CefC_Log_Info, "Open TCP peer: %s:%s, socket : %d\n",
			hdl->peer_id_str[i], hdl->peer_sv_str[i], cs);
		hdl->peer_num++;
		hdl->tcp_fds[i] 	= cs;
		hdl->tcp_index[i] 	= 0;

		cef_csmgr_send_msg (hdl->tcp_fds[i],
			(unsigned char*) CefC_Csmgr_Cmd_ConnOK, strlen (CefC_Csmgr_Cmd_ConnOK));
	}
	return;

POST_ACCEPT:
	close (cs);
	return;
}

/*--------------------------------------------------------------------------------------
	Prepares the Control sockets to be polled
----------------------------------------------------------------------------------------*/
static int
csmgrd_poll_socket_prepare (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	struct pollfd fds[],
	int fds_index[]
) {
	int set_num = 0;
	int i;

	if (hdl->local_peer_sock != -1) {
		fds[set_num].fd     = hdl->local_peer_sock;
		fds[set_num].events = POLLIN | POLLERR;
		fds_index[set_num]  = 0;
		set_num++;
	}

	for (i = 1 ; i < CsmgrdC_Max_Sock_Num ; i++) {
		if (hdl->tcp_fds[i] != -1) {
			fds[set_num].fd     = hdl->tcp_fds[i];
			fds[set_num].events = POLLIN | POLLERR;
			fds_index[set_num]  = i;
			set_num++;
		}
	}

	return (set_num);
}
/*--------------------------------------------------------------------------------------
	Handles the received message(s)
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
csmgrd_input_message_process (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* msg,							/* receive message						*/
	int msg_len,								/* message length						*/
	uint8_t type								/* message type							*/
) {
	switch (type) {
		case CefC_Csmgr_Msg_Type_Interest: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Interest Message\n");
#endif // CefC_Debug
			csmgrd_incoming_interest (hdl, sock, msg, msg_len, type);
			break;
		}

		case CefC_Csmgr_Msg_Type_Ccninfo: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Ccninfo Message\n");
#endif // CefC_Debug
			csmgrd_incoming_ccninfo_msg (hdl, sock, msg, msg_len);
			break;
		}
		case CefC_Csmgr_Msg_Type_PreCcninfo: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the pre-Ccninfo Message\n");
#endif // CefC_Debug
			csmgrd_incoming_pre_ccninfo_msg (hdl, sock, msg, msg_len);
			break;
		}

		case CefC_Csmgr_Msg_Type_Status: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Get Status Message\n");
#endif // CefC_Debug
			csmgrd_incoming_status_msg (hdl, sock, msg, msg_len);
			break;
		}
		case CefC_Csmgr_Msg_Type_Increment: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest,
				"Receive the Increment Access Count Message\n");
#endif // CefC_Debug
			csmgrd_incoming_increment_msg (hdl, msg, msg_len);
			break;
		}
		case CefC_Csmgr_Msg_Type_Echo: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Echo Message\n");
#endif // CefC_Debug
			csmgrd_incoming_echo_msg (hdl, sock, msg, msg_len);
			break;
		}
		case CefC_Csmgr_Msg_Type_Kill: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Kill Command\n");
#endif // CefC_Debug
			if ((memcmp (msg, root_user_name, CefC_Csmgr_User_Len) == 0) ||
				(memcmp (msg, hdl->launched_user_name, CefC_Csmgr_User_Len) == 0)) {
				csmgrd_running_f = 0;
				cef_log_write (CefC_Log_Info, "csmgrdstop from %s\n", msg);
				return (-1);
			} else {
				cef_log_write (CefC_Log_Info,
					"Permission denied (csmgrdstop from %s)\n", msg);
			}
			break;
		}
#ifdef CefC_Ccore
		case CefC_Csmgr_Msg_Type_RCap: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Retrieve capacity message\n");
#endif // CefC_Debug
			csmgrd_incoming_rcap_msg (hdl, sock);
			break;
		}
		case CefC_Csmgr_Msg_Type_SCap: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Set capacity message\n");
#endif // CefC_Debug
			csmgrd_incoming_scap_msg (hdl, sock, msg, msg_len);
			break;
		}
		case CefC_Csmgr_Msg_Type_RCLT: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Content Lifetime message\n");
#endif // CefC_Debug
			csmgrd_incoming_rclt_msg (hdl, sock, msg, msg_len);
			break;
		}
		case CefC_Csmgr_Msg_Type_SCLT: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Content Lifetime message\n");
#endif // CefC_Debug
			csmgrd_incoming_sclt_msg (hdl, sock, msg, msg_len);
			break;
		}
		case CefC_Csmgr_Msg_Type_RCCH: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Retrieve Cache Chunk message\n");
#endif // CefC_Debug
			csmgrd_incoming_rcch_msg (hdl, sock, msg, msg_len);
			break;
		}
		case CefC_Csmgr_Msg_Type_SCDL: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Delete Cache message\n");
#endif // CefC_Debug
			csmgrd_incoming_scdl_msg (hdl, sock, msg, msg_len);
			break;
		}
#endif // CefC_Ccore
		case CefC_Csmgr_Msg_Type_ContInfo: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Contents Information Request message\n");
#endif // CefC_Debug
			csmgrd_incoming_continfo_msg (hdl, sock, msg, msg_len);
			break;
		}
		default: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Unknown Message\n");
#endif // CefC_Debug
			break;
		}
	}

	return (0);
}
/*--------------------------------------------------------------------------------------
	Incoming Interest Message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_interest (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len,								/* receive message length				*/
	uint8_t type								/* receive message type					*/
) {
	int res;
	unsigned char name[CefC_Max_Msg_Size] = {0};
	uint16_t name_len;
	uint32_t chunk_num = 0;
	uint8_t int_type;
	unsigned char op_data[CefC_Max_Msg_Size] = {0};
	uint16_t op_data_len = 0;
	unsigned char ver[CefC_Max_Msg_Size] = {0};
	uint16_t ver_len = 0;

	/* Parses the csmgr Interest message */
	res = cef_csmgr_interest_msg_parse (
			buff, buff_len, &int_type, name, &name_len, &chunk_num, op_data, &op_data_len, ver, &ver_len);

	if (res < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Parse message error (interest)\n");
#endif // CefC_Debug
		return;
	}

	/* Checks Interest Type */
	switch (int_type) {
		case CefC_Csmgr_Interest_Type_Normal: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Call cache plugin (cache_item_get)\n");
#endif // CefC_Debug
			csmgrd_stat_request_count_update (stat_hdl, name, name_len);

			/* Searches and sends a Cob */
			hdl->cs_mod_int->cache_item_get (name, name_len, chunk_num, sock, ver, ver_len);
			break;
		}
		default: {
			break;
		}
	}

	return;
}
/*--------------------------------------------------------------------------------------
	Parse Interest message
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
cef_csmgr_interest_msg_parse (
	unsigned char buff[],						/* receive message						*/
	int buff_len,								/* receive message length				*/
	uint8_t* int_type,							/* Interest type						*/
	unsigned char name[],						/* Content Name							*/
	uint16_t* name_len,							/* Length of content name				*/
	uint32_t* chunk_num,							/* Chunk number							*/
	unsigned char op_data[],					/* Optional Data Field					*/
	uint16_t* op_data_len,						/* Length of Optional Data Field		*/
	unsigned char ver[],						/* Content Version						*/
	uint16_t* ver_len							/* Length of content version			*/
) {
	int res;
	uint16_t index = 0;
	uint8_t chunk_num_f;
	uint32_t value32;
	uint16_t value16;

	/* get Interest Type */
	*int_type = buff[index];
	index += sizeof (uint8_t);
	if ((*int_type == CefC_Csmgr_Interest_Type_Invalid) ||
		(*int_type >= CefC_Csmgr_Interest_Type_Num)) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Interest type is invalid\n");
#endif // CefC_Debug
		return (-1);
	}

	/* get chunk num flag */
	chunk_num_f = buff[index];
	index += sizeof (uint8_t);
	if (chunk_num_f > 1) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Interest chunk num flag is invalid\n");
#endif // CefC_Debug
		return (-1);
	}

	/* get cob name */
	res = cef_csmgr_cob_name_parse (buff, buff_len, &index, name, &(*name_len));
	if ((res < 0) || (*name_len == 0)) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Cob name parse error\n");
#endif // CefC_Debug
		return (-1);
	}

	/* get chunk num */
	if (chunk_num_f == CefC_Csmgr_Interest_ChunkNum_Exist) {
		if ((buff_len - index - CefC_S_ChunkNum) < 0) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Chunk number parse error\n");
#endif // CefC_Debug
			return (-1);
		}
		memcpy (&value32, buff + index, CefC_S_ChunkNum);
		*chunk_num = ntohl (value32);
		index += CefC_S_ChunkNum;
	}
	/* get version length */
	memcpy (&value16, buff + index, sizeof (uint16_t));
	*ver_len = ntohs (value16);
	index += sizeof (uint16_t);

	/* get version */
	if (*ver_len) {
		memcpy (ver, buff + index, *ver_len);
		index += *ver_len;
	}

	return (0);
}

/*--------------------------------------------------------------------------------------
	Incoming Get Status Message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_status_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
) {
#ifdef	CefC_DB_INDEX
	CsmgrT_Stat* stat[CsmgrT_Stat_Max];
	int res, i;
	uint64_t nowt;
	struct timeval tv;
	unsigned char *wbuf;
	uint32_t wbuf_size;
	unsigned char* key = NULL;
	uint32_t index;
	uint16_t klen;
	uint64_t value64;
	struct CefT_Csmgr_Status_Hdr stat_hdr;
	struct CefT_Csmgr_Status_Rep stat_rep;
	uint32_t value32;
	struct pollfd fds[1];
	uint32_t 		con_num = 0;
	uint8_t option_f = CefC_Csmgr_Stat_Opt_None;

	uint32_t	buff_idx = 0;
	int32_t		stt_num = 0;
	int32_t		out_num = 0;
	unsigned char buff_x;

#ifdef	__DB_IDX_DEB_STATUS
	fprintf( stderr, "[%s] IN \n", __func__ );
#endif
	wbuf = calloc (1, CefC_Csmgr_Stat_Mtu);
	if (wbuf == NULL) {
		return;
	}
	wbuf_size = CefC_Csmgr_Stat_Mtu;

	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;

	/* Obtain parameters from request message 		*/
#if 0
	option_f = (uint8_t)buff[0];
	klen = buff_len - 1 - 1;
	buff_x = buff[1];
	if ((buff[1]) && (klen > 0)) {
		key = &buff[2];
	}
#else
	option_f = (uint8_t)buff[buff_idx];
	buff_idx += sizeof(uint8_t);

	memcpy( &stt_num, &buff[buff_idx], sizeof(int32_t) );
	buff_idx += sizeof(int32_t);
	memcpy( &out_num, &buff[buff_idx], sizeof(int32_t) );
	buff_idx += sizeof(int32_t);
	klen = buff_len - 1 - 1 - sizeof(int32_t) - sizeof(int32_t);
	buff_x = buff[buff_idx];
	if ((buff[buff_idx]) && (klen > 0)) {
		key = &buff[buff_idx+1];
	}

#endif
	/* Creates the response 		*/
	wbuf[CefC_O_Fix_Ver]  = CefC_Version;
	wbuf[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_Status;
	index = CefC_Csmgr_Msg_HeaderLen + 2; /*** Added 2 bytes to extend the total frame length to 4 bytes ***/

	index += sizeof (struct CefT_Csmgr_Status_Hdr);

	if (buff_x) {
		res = csmgrd_stat_content_info_gets (stat_hdl, key, klen, 1, stat);
		if (con_num == 0) {
			con_num = res;
		}
		for (i = 0 ; i < res ; i++) {
			if (i == 0 ) {
				if ( stt_num > res) {
					goto SKIP_RESPONSE;
				}
				if (stt_num == -1){
					stt_num = 0;
					out_num = res - 1;
				} else {
					stt_num--;
					out_num += stt_num - 1;
					if (out_num >= res ) {
						out_num = res - 1;
					}
				}
			}
			if ((i < stt_num) || (i > out_num)) {
				continue;
			}
			if (index+stat[i]->name_len+sizeof (struct CefT_Csmgr_Status_Rep) > wbuf_size) {
				void *new = realloc (wbuf, wbuf_size+CefC_Csmgr_Stat_Mtu);
				if (new == NULL) {
					free (wbuf);
					return;
				}
				wbuf = new;
				wbuf_size += CefC_Csmgr_Stat_Mtu;
			}
			stat_rep.name_len 	= htons (stat[i]->name_len);
			stat_rep.con_size 	= cef_client_htonb (stat[i]->con_size);
			if(option_f & CefC_Csmgr_Stat_Opt_Clear) {
				csmgrd_stat_count_clear( stat_hdl, stat[i]->name_db, stat[i]->name_len );
				stat[i]->access = 0;
				stat[i]->req_count = 0;
			}
			stat_rep.access 	= cef_client_htonb (stat[i]->access);
			stat_rep.req_count 	= cef_client_htonb (stat[i]->req_count);

			value64 = (stat[i]->expiry - nowt) / 1000000;
			stat_rep.freshness = cef_client_htonb (value64);

			value64 = (nowt - stat[i]->cached_time) / 1000000;
			stat_rep.elapsed_time 	= cef_client_htonb (value64);

			memcpy (&wbuf[index], &stat_rep, sizeof (struct CefT_Csmgr_Status_Rep));
			index += sizeof (struct CefT_Csmgr_Status_Rep);
			memcpy (&wbuf[index], stat[i]->name_db, stat[i]->name_len);
			index += stat[i]->name_len;
		}
	}
SKIP_RESPONSE:;
	stat_hdr.node_num = htons ((uint16_t) hdl->peer_num);
	stat_hdr.con_num  = htonl (con_num);
	memcpy (&wbuf[CefC_Csmgr_Msg_HeaderLen+2/* To extend length from 2 bytes to 4 bytes */], &stat_hdr, sizeof (struct CefT_Csmgr_Status_Hdr));

	value32 = htonl (index);
	memcpy (&wbuf[CefC_O_Length], &value32, sizeof (value32));

	{
		int	fblocks;
		int rem_size;
		int counter;
		fblocks = index / CefC_Csmgr_Stat_Mtu;
		rem_size = index % CefC_Csmgr_Stat_Mtu;
		int flag;
		flag = fcntl (sock, F_GETFL, 0);
		fcntl (sock, F_SETFL, flag & ~O_NONBLOCK);
		for (counter=0; counter<fblocks; counter++) {
			/* Send message 		*/
			fds[0].fd = sock;
			fds[0].events = POLLOUT | POLLERR;
			res = poll (fds, 1, 1000);
			if (res < 1) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Failed to poll (response status message).\n");
#endif // CefC_Debug
#ifdef	__DB_IDX_DEB_STATUS
				fprintf( stderr, "[%s] OUT Failed to poll (response status message).\n", __func__ );
#endif
				free (wbuf);
				return;
			}
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Send status response(len = %u).\n", CefC_Csmgr_Stat_Mtu);
#endif // CefC_Debug
#ifdef	__DB_IDX_DEB_STATUS
			fprintf( stderr, "[%s] OUT Send status response(len = %u).\n", __func__, CefC_Csmgr_Stat_Mtu );
#endif
			res = cef_csmgr_send_msg (sock, &wbuf[counter*CefC_Csmgr_Stat_Mtu], CefC_Csmgr_Stat_Mtu);
#ifdef CefC_Debug
			if (res < 0) {
				cef_dbg_write (CefC_Dbg_Fine, "Failed to send response message(status).\n");
			}
#endif // CefC_Debug
		}
		if (rem_size != 0) {
			/* Send message 		*/
			fds[0].fd = sock;
			fds[0].events = POLLOUT | POLLERR;
			res = poll (fds, 1, 1000);
			if (res < 1) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Failed to poll (response status message).\n");
#endif // CefC_Debug
#ifdef	__DB_IDX_DEB_STATUS
			fprintf( stderr, "[%s] OUT Failed to poll (response status message)..\n", __func__ );
#endif
				free (wbuf);
				return;
			}
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Send status response(len = %u).\n", rem_size);
#endif // CefC_Debug
			res = cef_csmgr_send_msg (sock, &wbuf[fblocks*CefC_Csmgr_Stat_Mtu], rem_size);
#ifdef CefC_Debug
			if (res < 0) {
				cef_dbg_write (CefC_Dbg_Fine, "Failed to send response message(status).\n");
			}
#endif // CefC_Debug
		}
	}

	free (wbuf);
#ifdef	__DB_IDX_DEB_STATUS
	fprintf( stderr, "[%s] Reurn \n", __func__ );
#endif

	return;

#else
	CsmgrT_Stat* stat[CsmgrT_Stat_Max];
	int res, i;
	uint64_t nowt;
	struct timeval tv;
	unsigned char *wbuf;
	uint32_t wbuf_size;
	unsigned char* key = NULL;
	uint32_t index;
	uint16_t klen;
	uint64_t value64;
	struct CefT_Csmgr_Status_Hdr stat_hdr;
	struct CefT_Csmgr_Status_Rep stat_rep;
	uint32_t value32;
	struct pollfd fds[1];
	uint32_t 		con_num = 0;
	uint8_t option_f = CefC_Csmgr_Stat_Opt_None;

	uint32_t	buff_idx = 0;
	int32_t		stt_num = 0;
	int32_t		out_num = 0;
	unsigned char buff_x;

	wbuf = calloc (1, CefC_Csmgr_Stat_Mtu);
	if (wbuf == NULL) {
		return;
	}
	wbuf_size = CefC_Csmgr_Stat_Mtu;

	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;

	/* Obtain parameters from request message 		*/
	/* buff[0]:option flag, buff[1]:uri flag */

#if 0
	option_f = (uint8_t)buff[0];
	klen = buff_len - 1 - 1;
	buff_x = buff[1];
	if ((buff[1]) && (klen > 0)) {
		key = &buff[2];
	}
#else
	option_f = (uint8_t)buff[buff_idx];
	buff_idx += sizeof(uint8_t);

	memcpy( &stt_num, &buff[buff_idx], sizeof(int32_t) );
	buff_idx += sizeof(int32_t);
	memcpy( &out_num, &buff[buff_idx], sizeof(int32_t) );
	buff_idx += sizeof(int32_t);
	klen = buff_len - 1 - 1 - sizeof(int32_t) - sizeof(int32_t);
	buff_x = buff[buff_idx];
	if ((buff[buff_idx]) && (klen > 0)) {
		key = &buff[buff_idx+1];
	}

#endif

	/* Creates the response 		*/
	wbuf[CefC_O_Fix_Ver]  = CefC_Version;
	wbuf[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_Status;
	index = CefC_Csmgr_Msg_HeaderLen + 2; /*** Added 2 bytes to extend the total frame length to 4 bytes ***/

	index += sizeof (struct CefT_Csmgr_Status_Hdr);

	if (buff_x) {
		res = csmgrd_stat_content_info_gets (stat_hdl, key, klen, 1, stat);
		if (con_num == 0) {
			con_num = res;
		}

		for (i = 0 ; i < res ; i++) {
			if (i == 0 ) {
				if ( stt_num > res) {
					goto SKIP_RESPONSE;
				}
				if (stt_num == -1){
					stt_num = 0;
					out_num = res - 1;
				} else {
					stt_num--;
					out_num += stt_num - 1;
					if (out_num >= res ) {
						out_num = res - 1;
					}
				}
			}

			if ((i < stt_num) || (i > out_num)) {
				continue;
			}

			if (index+stat[i]->name_len+sizeof (struct CefT_Csmgr_Status_Rep)+stat[i]->ver_len > wbuf_size) {
				void *new = realloc (wbuf, wbuf_size+CefC_Csmgr_Stat_Mtu);
				if (new == NULL) {
					free (wbuf);
					return;
				}
				wbuf = new;
				wbuf_size += CefC_Csmgr_Stat_Mtu;
			}
			stat_rep.name_len 	= htons (stat[i]->name_len);
			stat_rep.con_size 	= cef_client_htonb (stat[i]->con_size);
			if(option_f & CefC_Csmgr_Stat_Opt_Clear) {
				stat[i]->access = 0;
				stat[i]->req_count = 0;
			}
			stat_rep.access 	= cef_client_htonb (stat[i]->access);
			stat_rep.req_count 	= cef_client_htonb (stat[i]->req_count);

			value64 = (stat[i]->expiry - nowt) / 1000000;
			stat_rep.freshness = cef_client_htonb (value64);

			value64 = (nowt - stat[i]->cached_time) / 1000000;
			stat_rep.elapsed_time 	= cef_client_htonb (value64);

			stat_rep.ver_len 	= htons (stat[i]->ver_len);

			memcpy (&wbuf[index], &stat_rep, sizeof (struct CefT_Csmgr_Status_Rep));
			index += sizeof (struct CefT_Csmgr_Status_Rep);
			memcpy (&wbuf[index], stat[i]->name, stat[i]->name_len);
			index += stat[i]->name_len;
			if (stat[i]->ver_len) {
				memcpy (&wbuf[index], stat[i]->version, stat[i]->ver_len);
				index += stat[i]->ver_len;
			}
		}
	}
SKIP_RESPONSE:;
	stat_hdr.node_num = htons ((uint16_t) hdl->peer_num);
	stat_hdr.con_num  = htonl (con_num);
	memcpy (&wbuf[CefC_Csmgr_Msg_HeaderLen+2/* To extend length from 2 bytes to 4 bytes */], &stat_hdr, sizeof (struct CefT_Csmgr_Status_Hdr));

	value32 = htonl (index);
	memcpy (&wbuf[CefC_O_Length], &value32, sizeof (value32));

	{
		int	fblocks;
		int rem_size;
		int counter;
		fblocks = index / CefC_Csmgr_Stat_Mtu;
		rem_size = index % CefC_Csmgr_Stat_Mtu;
		int flag;
		flag = fcntl (sock, F_GETFL, 0);
		fcntl (sock, F_SETFL, flag & ~O_NONBLOCK);
		for (counter=0; counter<fblocks; counter++) {
			/* Send message 		*/
			fds[0].fd = sock;
			fds[0].events = POLLOUT | POLLERR;
			res = poll (fds, 1, 1000);
			if (res < 1) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Failed to poll (response status message).\n");
#endif // CefC_Debug
				free (wbuf);
				return;
			}
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Send status response(len = %u).\n", CefC_Csmgr_Stat_Mtu);
#endif // CefC_Debug
			res = cef_csmgr_send_msg (sock, &wbuf[counter*CefC_Csmgr_Stat_Mtu], CefC_Csmgr_Stat_Mtu);
#ifdef CefC_Debug
			if (res < 0) {
				cef_dbg_write (CefC_Dbg_Fine, "Failed to send response message(status).\n");
			}
#endif // CefC_Debug
		}
		if (rem_size != 0) {
			/* Send message 		*/
			fds[0].fd = sock;
			fds[0].events = POLLOUT | POLLERR;
			res = poll (fds, 1, 1000);
			if (res < 1) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Failed to poll (response status message).\n");
#endif // CefC_Debug
				free (wbuf);
				return;
			}
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Send status response(len = %u).\n", rem_size);
#endif // CefC_Debug
			res = cef_csmgr_send_msg (sock, &wbuf[fblocks*CefC_Csmgr_Stat_Mtu], rem_size);
#ifdef CefC_Debug
			if (res < 0) {
				cef_dbg_write (CefC_Dbg_Fine, "Failed to send response message(status).\n");
			}
#endif // CefC_Debug
		}
	}

	free (wbuf);

	return;
#endif
}

/*--------------------------------------------------------------------------------------
	Incoming Ccninfo Message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_ccninfo_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
) {
#ifdef	CefC_DB_INDEX
	CsmgrT_Stat* stat[CsmgrT_Stat_Max];
	int res, i;
	unsigned char msg[CefC_Max_Length] = {0};
	unsigned char* key;
	uint16_t index = 0;
	uint16_t rec_index;
	uint8_t  partial_match_f;
	uint16_t klen;
	struct ccninfo_rep_block rep_blk;
	struct tlv_hdr rply_tlv_hdr;
	struct tlv_hdr name_tlv_hdr;
	CsmgrT_DB_COB_MAP*	cob_map = NULL;
	int					map_idx;

	uint64_t nowt;
	struct timeval tv;

	name_tlv_hdr.type = htons (CefC_T_NAME);

	/* Obtain parameters from request message 		*/
	partial_match_f = buff[0];
	klen = buff_len - 1;
	key = &buff[1];

	/* Obtain cached content information 			*/
	if (!partial_match_f) {
		/* The name contains a chunk number */
		uint16_t tmp_klen;
		uint32_t seqno;

		tmp_klen = cef_frame_get_name_without_chunkno (key, klen, &seqno);
		/* Queries without a chunk number(ExactMatch) */
		stat[0] = csmgrd_stat_content_info_is_exist(stat_hdl, key, tmp_klen, &cob_map);
		if (stat[0]) {
			/* Expiry Check */
			if ( stat[0]->expire_f == 1 ) {
				free( cob_map );
				free( stat[0] );
				goto NO_RESP;
			} else {
				gettimeofday (&tv, NULL);
				nowt = tv.tv_sec * 1000000llu + tv.tv_usec;
				if ( nowt > stat[0]->expiry ) {
					free( cob_map );
					free( stat[0] );
					goto NO_RESP;
				}
			}

			uint64_t mask = 1;
			uint32_t x;
			map_idx = seqno / CsmgrT_MAP_BASE;
			if ( map_idx > (stat[0]->map_num-1) ) {
				free( cob_map );
				free( stat[0] );
				goto NO_RESP;
			}
			x = (seqno - (CsmgrT_MAP_BASE * map_idx)) / 64;
			mask <<= (seqno % 64);
			/* There is a corresponding chunk number */
//			if ((stat[0]->map_num-1) >= x && stat[0]->cob_map[x] & mask) {
			if ( cob_map[map_idx].cob_map[x] & mask) {
				rec_index = index;
				index += CefC_S_TLF;
				{
					uint32_t con_size;
					if (stat[0]->con_size / 1024 > UINT32_MAX) {
						con_size = UINT32_MAX;
					} else {
						con_size = (uint32_t)(stat[0]->con_size / 1024);
					}
					rep_blk.cont_size 	= htonl (con_size);
				}
				rep_blk.cont_cnt 	= htonl ((uint32_t) 1);
				rep_blk.rcv_int 	= htonl ((uint32_t) 0);
				/* first seq and last seq = self seq */
				rep_blk.first_seq 	= htonl (seqno);
				rep_blk.last_seq 	= htonl (seqno);
				if ((hdl->cs_mod_int != NULL) &&
					(hdl->cs_mod_int->content_lifetime_get != NULL)) {
					uint32_t c_time = 0;
					uint32_t r_time = 0;
					int p_res = 0;
					p_res = hdl->cs_mod_int->content_lifetime_get
											(key, klen, &c_time, &r_time, 0);
					if (p_res < 0) {
						rep_blk.cache_time  = 0;
						rep_blk.remain_time = 0;
					} else {
						rep_blk.cache_time  = htonl (c_time);
						rep_blk.remain_time = htonl (r_time);
					}
				} else {
					rep_blk.cache_time  = 0;
					rep_blk.remain_time = 0;
				}

				memcpy (&msg[index], &rep_blk, sizeof (struct ccninfo_rep_block));
				index += sizeof (struct ccninfo_rep_block);
				/* Name 				*/
				name_tlv_hdr.length = htons (klen);
				memcpy (&msg[index], &name_tlv_hdr, sizeof (struct tlv_hdr));
				memcpy (&msg[index + CefC_S_TLF], key, klen);
				index += CefC_S_TLF + klen;

				/* Sets the header of Reply Block 		*/
				rply_tlv_hdr.type = htons (CefC_T_DISC_CONTENT);
				rply_tlv_hdr.length = htons (index - (rec_index + CefC_S_TLF));
				memcpy (&msg[rec_index], &rply_tlv_hdr, sizeof (struct tlv_hdr));
				free( cob_map );
				free( stat[0] );
			}
		}
	} else {
		/* The name doesn't contain a chunk number */
		res = csmgrd_stat_content_info_gets (
				stat_hdl, key, klen, (int) partial_match_f, stat);
		for (i = 0 ; i < res ; i++) {

			if (stat[i]->name_len != klen) {
				continue;
			} else {
//				if (memcmp (stat[i]->name, key, klen) != 0) {
				if (memcmp (stat[i]->name_db, key, klen) != 0) {
					continue;
				}
			}
			rec_index = index;
			index += CefC_S_TLF;
			{
				uint32_t con_size;
				if (stat[i]->con_size / 1024 > UINT32_MAX) {
					con_size = UINT32_MAX;
				} else {
					con_size = (uint32_t)(stat[i]->con_size / 1024);
				}
				rep_blk.cont_size 	= htonl (con_size);
			}

			if (stat[i]->cob_num > UINT32_MAX) {
				rep_blk.cont_cnt 	= htonl (UINT32_MAX);
			} else {
				rep_blk.cont_cnt 	= htonl ((uint32_t) stat[i]->cob_num);
			}
			if (stat[i]->access > UINT32_MAX) {
				rep_blk.rcv_int 	= htonl (UINT32_MAX);
			} else {
				rep_blk.rcv_int 	= htonl ((uint32_t) stat[i]->access);
			}
			rep_blk.first_seq 	= htonl (stat[i]->min_seq);
			rep_blk.last_seq 	= htonl (stat[i]->max_seq);

			if ((hdl->cs_mod_int != NULL) &&
				(hdl->cs_mod_int->content_lifetime_get != NULL)) {
				uint32_t c_time = 0;
				uint32_t r_time = 0;
				int p_res = 0;
				p_res = hdl->cs_mod_int->content_lifetime_get
//										(stat[i]->name, stat[i]->name_len, &c_time, &r_time, partial_match_f);
										(stat[i]->name_db, stat[i]->name_len, &c_time, &r_time, partial_match_f);
				if (p_res < 0) {
					rep_blk.cache_time  = 0;
					rep_blk.remain_time = 0;
				} else {
					rep_blk.cache_time  = htonl (c_time);
					rep_blk.remain_time = htonl (r_time);
				}
			} else {
				rep_blk.cache_time  = 0;
				rep_blk.remain_time = 0;
			}

			memcpy (&msg[index], &rep_blk, sizeof (struct ccninfo_rep_block));
			index += sizeof (struct ccninfo_rep_block);
			/* Name 				*/
			name_tlv_hdr.length = htons (klen);
			memcpy (&msg[index], &name_tlv_hdr, sizeof (struct tlv_hdr));
			memcpy (&msg[index + CefC_S_TLF], key, klen);
			index += CefC_S_TLF + klen;

			/* Sets the header of Reply Block 		*/
			rply_tlv_hdr.type = htons (CefC_T_DISC_CONTENT);
			rply_tlv_hdr.length = htons (index - (rec_index + CefC_S_TLF));
			memcpy (&msg[rec_index], &rply_tlv_hdr, sizeof (struct tlv_hdr));
		}
		for (i = 0 ; i < res ; i++) {
			free( stat[i] );
		}
	}

NO_RESP:;

	if (index > 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Send the ccninfo response (len = %u).\n", index);
		cef_dbg_buff_write (CefC_Dbg_Finest, msg, index);
#endif // CefC_Debug
		res = cef_csmgr_send_msg (sock, msg, index);
		if (res < 0) {
			/* send error */
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Failed to send the ccninfo response\n");
#endif // CefC_Debug
		}
	} else {
		cef_csmgr_send_msg (sock, msg, CefC_S_TLF);
	}

	return;

#else
	CsmgrT_Stat* stat[CsmgrT_Stat_Max];
	int res, i;
	unsigned char msg[CefC_Max_Length] = {0};
	unsigned char* key;
	uint16_t index = 0;
	uint16_t rec_index;
	uint8_t  partial_match_f;
	uint16_t klen;
	struct ccninfo_rep_block rep_blk;
	struct tlv_hdr rply_tlv_hdr;
	struct tlv_hdr name_tlv_hdr;

	name_tlv_hdr.type = htons (CefC_T_NAME);

	/* Obtain parameters from request message 		*/
	partial_match_f = buff[0];
	klen = buff_len - 1;
	key = &buff[1];

	/* Obtain cached content information 			*/
	if (!partial_match_f) {
		/* The name contains a chunk number */
		uint16_t tmp_klen;
		uint32_t seqno;

		tmp_klen = cef_frame_get_name_without_chunkno (key, klen, &seqno);
		/* Queries without a chunk number(ExactMatch) */
		stat[0] = csmgrd_stat_content_info_get (stat_hdl, key, tmp_klen);	//0.8.3c
		if (stat[0]) {
			uint64_t mask = 1;
			uint32_t x;
			x = seqno / 64;
			mask <<= (seqno % 64);
			/* There is a corresponding chunk number */
			if ((stat[0]->map_max-1) >= x && stat[0]->cob_map[x] & mask) {
				rec_index = index;
				index += CefC_S_TLF;
				{
					uint32_t con_size;
					if (stat[0]->con_size / 1024 > UINT32_MAX) {
						con_size = UINT32_MAX;
					} else {
						con_size = (uint32_t)(stat[0]->con_size / 1024);
					}
					rep_blk.cont_size 	= htonl (con_size);
				}
				rep_blk.cont_cnt 	= htonl ((uint32_t) 1);
				rep_blk.rcv_int 	= htonl ((uint32_t) 0);
				/* first seq and last seq = self seq */
				rep_blk.first_seq 	= htonl (seqno);
				rep_blk.last_seq 	= htonl (seqno);
				if ((hdl->cs_mod_int != NULL) &&
					(hdl->cs_mod_int->content_lifetime_get != NULL)) {
					uint32_t c_time = 0;
					uint32_t r_time = 0;
					int p_res = 0;
					p_res = hdl->cs_mod_int->content_lifetime_get
											(key, klen, &c_time, &r_time, 0);
					if (p_res < 0) {
						rep_blk.cache_time  = 0;
						rep_blk.remain_time = 0;
					} else {
						rep_blk.cache_time  = htonl (c_time);
						rep_blk.remain_time = htonl (r_time);
					}
				} else {
					rep_blk.cache_time  = 0;
					rep_blk.remain_time = 0;
				}

				memcpy (&msg[index], &rep_blk, sizeof (struct ccninfo_rep_block));
				index += sizeof (struct ccninfo_rep_block);
				/* Name 				*/
				name_tlv_hdr.length = htons (klen);
				memcpy (&msg[index], &name_tlv_hdr, sizeof (struct tlv_hdr));
				memcpy (&msg[index + CefC_S_TLF], key, klen);
				index += CefC_S_TLF + klen;

				/* Sets the header of Reply Block 		*/
				rply_tlv_hdr.type = htons (CefC_T_DISC_CONTENT);
				rply_tlv_hdr.length = htons (index - (rec_index + CefC_S_TLF));
				memcpy (&msg[rec_index], &rply_tlv_hdr, sizeof (struct tlv_hdr));
			}
		}
	} else {
		/* The name doesn't contain a chunk number */
		res = csmgrd_stat_content_info_gets (
				stat_hdl, key, klen, (int) partial_match_f, stat);
		for (i = 0 ; i < res ; i++) {

			if (stat[i]->name_len != klen) {
				continue;
			} else {
				if (memcmp (stat[i]->name, key, klen) != 0) {
					continue;
				}
			}
			rec_index = index;
			index += CefC_S_TLF;
			{
				uint32_t con_size;
				if (stat[i]->con_size / 1024 > UINT32_MAX) {
					con_size = UINT32_MAX;
				} else {
					con_size = (uint32_t)(stat[i]->con_size / 1024);
				}
				rep_blk.cont_size 	= htonl (con_size);
			}

			if (stat[i]->cob_num > UINT32_MAX) {
				rep_blk.cont_cnt 	= htonl (UINT32_MAX);
			} else {
				rep_blk.cont_cnt 	= htonl ((uint32_t) stat[i]->cob_num);
			}
			if (stat[i]->access > UINT32_MAX) {
				rep_blk.rcv_int 	= htonl (UINT32_MAX);
			} else {
				rep_blk.rcv_int 	= htonl ((uint32_t) stat[i]->access);
			}
			rep_blk.first_seq 	= htonl (stat[i]->min_seq);
			rep_blk.last_seq 	= htonl (stat[i]->max_seq);

			if ((hdl->cs_mod_int != NULL) &&
				(hdl->cs_mod_int->content_lifetime_get != NULL)) {
				uint32_t c_time = 0;
				uint32_t r_time = 0;
				int p_res = 0;
				p_res = hdl->cs_mod_int->content_lifetime_get
										(stat[i]->name, stat[i]->name_len, &c_time, &r_time, partial_match_f);
				if (p_res < 0) {
					rep_blk.cache_time  = 0;
					rep_blk.remain_time = 0;
				} else {
					rep_blk.cache_time  = htonl (c_time);
					rep_blk.remain_time = htonl (r_time);
				}
			} else {
				rep_blk.cache_time  = 0;
				rep_blk.remain_time = 0;
			}

			memcpy (&msg[index], &rep_blk, sizeof (struct ccninfo_rep_block));
			index += sizeof (struct ccninfo_rep_block);
			/* Name 				*/
			name_tlv_hdr.length = htons (klen);
			memcpy (&msg[index], &name_tlv_hdr, sizeof (struct tlv_hdr));
			memcpy (&msg[index + CefC_S_TLF], key, klen);
			index += CefC_S_TLF + klen;

			/* Sets the header of Reply Block 		*/
			rply_tlv_hdr.type = htons (CefC_T_DISC_CONTENT);
			rply_tlv_hdr.length = htons (index - (rec_index + CefC_S_TLF));
			memcpy (&msg[rec_index], &rply_tlv_hdr, sizeof (struct tlv_hdr));
		}
	}

	if (index > 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Send the ccninfo response (len = %u).\n", index);
		cef_dbg_buff_write (CefC_Dbg_Finest, msg, index);
#endif // CefC_Debug
		res = cef_csmgr_send_msg (sock, msg, index);
		if (res < 0) {
			/* send error */
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Failed to send the ccninfo response\n");
#endif // CefC_Debug
		}
	} else {
		cef_csmgr_send_msg (sock, msg, CefC_S_TLF);
	}

	return;
#endif
}
/*--------------------------------------------------------------------------------------
	Incoming pre-Ccninfo message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_pre_ccninfo_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
) {

#ifdef	CefC_DB_INDEX
	CsmgrT_Stat* stat[CsmgrT_Stat_Max];
	int res;

	/* Obtain cached content information 			*/
	res = csmgrd_stat_content_info_gets (stat_hdl, buff, buff_len, 0, stat);

	if (res > 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest, "Cob is exist.\n");
#endif // CefC_Debug
		/* Content is exist */
		csmgrd_pre_ccninfo_response_send (sock, CefC_Csmgr_Cob_Exist);

		for ( int32_t i = 0; i < res; i++ ) {
			free( stat[i] ) ;
		}

	} else {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest, "Cob is not exist.\n");
#endif // CefC_Debug
		/* Content is not exist */
		csmgrd_pre_ccninfo_response_send (sock, CefC_Csmgr_Cob_NotExist);
	}

#else
	CsmgrT_Stat* stat[CsmgrT_Stat_Max];
	int res;

	/* Obtain cached content information 			*/
	res = csmgrd_stat_content_info_gets (stat_hdl, buff, buff_len, 0, stat);

	if (res > 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest, "Cob is exist.\n");
#endif // CefC_Debug
		/* Content is exist */
		csmgrd_pre_ccninfo_response_send (sock, CefC_Csmgr_Cob_Exist);
	} else {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest, "Cob is not exist.\n");
#endif // CefC_Debug
		/* Content is not exist */
		csmgrd_pre_ccninfo_response_send (sock, CefC_Csmgr_Cob_NotExist);
	}
#endif
	return;
}
/*--------------------------------------------------------------------------------------
	Send pre-Ccninfo response message
----------------------------------------------------------------------------------------*/
static void
csmgrd_pre_ccninfo_response_send (
	int sock,									/* recv socket							*/
	uint8_t result								/* result								*/
) {
	unsigned char buff[CefC_Max_Length] = {0};
	int res;
	uint16_t index = 0;
	uint16_t value16;

	/* Create Upload Request message */
	/* Set header */
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_PreCcninfo;
	index += CefC_Csmgr_Msg_HeaderLen;

	/* Set result */
	memcpy (buff + index, &result, sizeof (uint8_t));
	index += sizeof (uint8_t);

	/* Set Length */
	value16 = htons (index);
	memcpy (buff + CefC_O_Length, &value16, CefC_S_Length);

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Send the pre-Ccninfo response(len = %u).\n", index);
	cef_dbg_buff_write (CefC_Dbg_Finest, buff, index);
#endif // CefC_Debug
	/* Send a response to source node */
	res = cef_csmgr_send_msg (sock, buff, index);

	if (res < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Failed to send the pre-Ccninfo response\n");
#endif // CefC_Debug
	}

	return;
}

/*--------------------------------------------------------------------------------------
	Receive Increment Access Count message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_increment_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
) {
	uint16_t index = 0;
	int res;
	unsigned char name[CefC_Max_Msg_Size] = {0};
	uint16_t name_len;
	uint32_t value32;
	uint32_t chunk_num;

	if (hdl->cs_mod_int->ac_cnt_inc == NULL) {
#ifdef CefC_Debug
		cef_dbg_write (
			CefC_Dbg_Finest, "Cache plugin has no function(increment access count).\n");
#endif // CefC_Debug
	}

	if (buff_len < sizeof (uint32_t)) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine,
			"Parse error (increment access count message)\n");
#endif // CefC_Debug
		return;
	}

	/* Get chunk number		*/
	memcpy (&value32, buff, sizeof (uint32_t));
	chunk_num = ntohl (value32);
	index += sizeof (uint32_t);

	/* Get cob name	*/
	res = cef_csmgr_cob_name_parse (buff, buff_len, &index, name, &name_len);
	if ((res < 0) || (name_len == 0)) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine,
			"Parse error (increment access count message)\n");
#endif // CefC_Debug
		return;
	}

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Call cache plugin (ac_cnt_inc)\n");
#endif // CefC_Debug
	/* Increment access count */
	hdl->cs_mod_int->ac_cnt_inc (name, name_len, chunk_num);

	return;
}
/*--------------------------------------------------------------------------------------
	Receive Echo message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_echo_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
) {
	unsigned char ret_buff[CefC_Max_Length] = {0};
	uint16_t index = 0;
	uint16_t value16;

	/* Create message */
	/* Set header */
	ret_buff[CefC_O_Fix_Ver]  = CefC_Version;
	ret_buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_Echo;
	index += CefC_Csmgr_Msg_HeaderLen;

	memcpy (ret_buff + index, buff, buff_len);
	index += buff_len;

	/* Set Length */
	value16 = htons (index);
	memcpy (ret_buff + CefC_O_Length, &value16, CefC_S_Length);

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Send the echo response(len = %u).\n", index);
	cef_dbg_buff_write (CefC_Dbg_Finest, ret_buff, index);
#endif // CefC_Debug
	/* Send response */
	cef_csmgr_send_msg (sock, ret_buff, index);
	return;
}
/*--------------------------------------------------------------------------------------
	Read white list
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
csmgrd_ext_white_list_read (
	CefT_Csmgrd_Handle* hdl						/* csmgr daemon handle					*/
) {
	FILE*	fp = NULL;								/* file pointer						*/
	char	file_name[1024];						/* file name						*/
	char	param[4096] = {0};						/* parameter						*/
	char	param_buff[4096] = {0};					/* param buff						*/
	int		len;									/* read length						*/
	char*	option;									/* deny option						*/
	char*	value;									/* parameter						*/
	int		i, n;
	int64_t	res;
	CsmgrT_White_List* wl_entry;
	CsmgrT_White_List* wk_entry;

	/* Set default value */
	hdl->white_list  = NULL;
	hdl->allow_all_f = 0;

	/* Obtains the directory path where the csmgrd's config file is located. */
#if 0 //+++++ GCC v9 +++++
	sprintf (file_name, "%s/%s", csmgr_conf_dir, CefC_Csmgrd_Conf_Name);
#else
	int		rc;
	rc = snprintf (file_name, sizeof(file_name), "%s/%s", csmgr_conf_dir, CefC_Csmgrd_Conf_Name);
	if (rc < 0) {
		cef_log_write (CefC_Log_Error, "Config file dir path too long(%s)\n", csmgr_conf_dir);
		return (-1);
	}
#endif //----- GCC v9 -----

	/* Opens the csmgr's config file. */
	fp = fopen (file_name, "r");
	if (fp == NULL) {
		fp = fopen (file_name, "w");
		if (fp == NULL) {
			cef_log_write (CefC_Log_Error, "%s\n", strerror (errno));
			return (-1);
		}
		fclose (fp);
		fp = fopen (file_name, "r");
	}

	/* Inits the white list */
	wl_entry = (CsmgrT_White_List*) malloc (sizeof (CsmgrT_White_List));
	if (wl_entry) {
		hdl->white_list = wl_entry;
		wl_entry->host_addr[0] = 0x7F;
		wl_entry->host_addr[1] = 0x00;
		wl_entry->host_addr[2] = 0x00;
		wl_entry->host_addr[3] = 0x01;
		wl_entry->host_addr_len = 4;
		wl_entry->next = NULL;
	} else {
		cef_log_write (CefC_Log_Error, "Failed to get memory required for startup.\n");
		if (fp != NULL) {
			fclose (fp);
		}
		return (-1);
	}
	wk_entry = (CsmgrT_White_List*) malloc (sizeof (CsmgrT_White_List));
	if (wk_entry) {
		wl_entry->next = wk_entry;
		memset (wk_entry, 0, sizeof (CsmgrT_White_List));
		wk_entry->host_addr[10] = 0xFF;
		wk_entry->host_addr[11] = 0xFF;
		wk_entry->host_addr[12] = 0x7F;
		wk_entry->host_addr[13] = 0x00;
		wk_entry->host_addr[14] = 0x00;
		wk_entry->host_addr[15] = 0x01;
		wk_entry->host_addr_len = 16;
		wk_entry->next = NULL;
	} else {
		cef_log_write (CefC_Log_Error, "Failed to get memory required for startup.\n");
		if (fp != NULL) {
			fclose (fp);
		}
		return (-1);
	}

	/* Get parameter */
	while (fgets (param_buff, sizeof (param_buff), fp) != NULL) {
		len = strlen (param_buff);
		/* Check comment and newline character */
		if ((param_buff[0] == '#') || (param_buff[0] == '\n') || (len == 0)) {
			continue;
		}
		if (param_buff[len - 1] == '\n') {
			param_buff[len - 1] = '\0';
		}
		/* Remove blank */
		for (i = 0, n = 0; i < len; i++) {
			if (param_buff[i] != ' ') {
				param[n] = param_buff[i];
				n++;
			}
		}
		/* Get option */
		value = param;
		option = strsep (&value, "=");
		if (value == NULL) {
			continue;
		}

		/* Creates the white list */
		if (strcmp (option, "ALLOW_NODE") == 0) {
			/* Reads the list of hosts */
			res = csmgrd_ext_white_list_get (hdl, value);
			if (res < 0) {
				cef_log_write (CefC_Log_Error, "Invalid value (%s=%s)\n", option, value);
				fclose (fp);
				return (-1);
			}
		} else {
			continue;
		}
	}
	fclose (fp);

	return (0);
}
/*--------------------------------------------------------------------------------------
	Get list of host address
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
csmgrd_ext_white_list_get (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	char* value									/* parameter							*/
) {
	struct addrinfo hints;
	struct addrinfo* res;
	struct addrinfo* cres;
	char port_str[NI_MAXSERV];
	int ret;
	char list[4096];
	char* work;
	char* addr;
	char* host_addr;
	char* mask_addr;
	int addr_len;

	/* Init hint */
	memset (&hints, 0, sizeof (hints));
	hints.ai_family 	= AF_UNSPEC;
	hints.ai_socktype 	= SOCK_STREAM;
	hints.ai_flags 		= AI_NUMERICSERV;

	/* Get port num */
	sprintf (port_str, "%d", hdl->port_num);
	/* Get value */
	sprintf (list, "%s", value);
	work = list;

	/* Get parameter */
	while (1) {
		/* Get address str */
		addr = strsep (&work, ",");
		if (addr == NULL) {
			break;
		}
		if (strcmp (addr, "ALL") == 0) {
			hdl->allow_all_f = 1;
			return (0);
		}

		/* Get address information */
		addr_len = 32;
		work = addr;
		host_addr = strsep (&work, "/");
		if (host_addr) {
			mask_addr = strsep (&work, "/");
			if (mask_addr) {
				addr_len = atoi (mask_addr);
				if ((addr_len > 32) || (addr_len < 8)) {
					return (-1);
				}
				mask_addr = strsep (&work, "/");
				if (mask_addr) {
					return (-1);
				}
			} else {
				host_addr = addr;
			}
		} else {
			return (-1);
		}

		if ((ret = getaddrinfo (host_addr, port_str, &hints, &res)) != 0) {
			cef_log_write (CefC_Log_Error,
				"Invalid address (%s) : %s\n", host_addr, gai_strerror (ret));
			return (-1);
		}
		for (cres = res ; cres != NULL ; cres = cres->ai_next) {
			/* Add entry */
			if (csmgrd_ext_white_list_entry_add (hdl, cres, addr_len) < 0) {
				freeaddrinfo (res);
				return (-1);
			}
		}
		freeaddrinfo (res);
	}

	return (0);
}
/*--------------------------------------------------------------------------------------
	Add entry to white list
----------------------------------------------------------------------------------------*/
static int 							/* The return value is negative if an error occurs	*/
csmgrd_ext_white_list_entry_add (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	struct addrinfo* addrinfo,					/* address info							*/
	int addr_len
) {
	CsmgrT_White_List* entry;
	CsmgrT_White_List* wp;
	unsigned char host_addr[16] = {0};
	int length_bytes = addr_len / 8;

	if (addrinfo->ai_family == AF_INET6) {
		memcpy (&host_addr[0],
			&((struct sockaddr_in6*)(addrinfo->ai_addr))->sin6_addr, 16);
	} else if (addrinfo->ai_family == AF_INET) {
		memcpy (&host_addr[0],
			&((struct sockaddr_in*)(addrinfo->ai_addr))->sin_addr, 4);
	} else {
		/* Ignore */
		return (1);
	}

	/* Checks the white list */
	if (hdl->white_list) {
		entry = hdl->white_list;

		while (entry) {
			if ((entry->host_addr_len == length_bytes) &&
				(memcmp (&entry->host_addr[0], host_addr, length_bytes) == 0)) {
				/* Duplicate */
				return (1);
			}
			entry = entry->next;
		}
	}

	/* Creates the new entry 		*/
	entry = (CsmgrT_White_List*) malloc (sizeof (CsmgrT_White_List));
	if (entry == NULL) {
		cef_log_write (CefC_Log_Error, "Failed to get memory required for startup.\n");
		return (-1);
	}
	memcpy (&entry->host_addr[0], &host_addr[0], length_bytes);
	entry->host_addr_len = length_bytes;
	entry->next = NULL;

	if (hdl->white_list) {
		wp = hdl->white_list;
		while (wp->next) {
			wp = wp->next;
		}
		wp->next = entry;
	}

	return (1);
}
/*--------------------------------------------------------------------------------------
	Check registered address in white list
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
csmgrd_white_list_reg_check (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	struct sockaddr_storage* ss					/* socket addr							*/
) {
	CsmgrT_White_List* wp = hdl->white_list;
	unsigned char host_addr[16] = {0};

	if (hdl->allow_all_f) {
		return (1);
	}

	if (hdl->white_list) {

		if (ss->ss_family == AF_INET6) {
			memcpy (&host_addr[0],
				&((struct sockaddr_in6*)ss)->sin6_addr, 16);
#ifdef CefC_Debug
			int x;
			char addr[64];
			int len = 0;
			for (x = 0; x < 16; x++) {
				len = len + sprintf (addr + len, "%02X ", host_addr[x]);
			}
			cef_dbg_write (CefC_Dbg_Fine, "IPv6: %s\n", addr);
#endif // CefC_Debug
		} else if (ss->ss_family == AF_INET) {
			memcpy (&host_addr[0],
				&((struct sockaddr_in*)ss)->sin_addr, 4);
#ifdef CefC_Debug
			int x;
			char addr[64];
			int len = 0;
			for (x = 0; x < 16; x++) {
				len = len + sprintf (addr + len, "%02X ", host_addr[x]);
			}
			cef_dbg_write (CefC_Dbg_Fine, "IPv4: %s\n", addr);
#endif // CefC_Debug
		} else {
			/* Ignore */
			return (-1);
		}

		while (wp) {
			if (memcmp (&wp->host_addr[0], &host_addr[0], wp->host_addr_len) == 0) {
				return (1);
			}
			wp = wp->next;
		}
	}
	return (-1);
}
#ifdef CefC_Ccore
/*--------------------------------------------------------------------------------------
	Incoming retrieve cache capacity message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_rcap_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock									/* recv socket							*/
) {
	uint64_t cap;

	cap = csmgrd_stat_cache_capacity_get (stat_hdl);

	if (cap > 0) {
		csmgrd_rcap_response_send (sock, CcoreC_Success, cap);
	} else {
		csmgrd_rcap_response_send (sock, CcoreC_Failed, 0);
	}

	return;
}
/*--------------------------------------------------------------------------------------
	Send retrieve cache response message
----------------------------------------------------------------------------------------*/
static void
csmgrd_rcap_response_send (
	int sock,									/* recv socket							*/
	uint8_t result,								/* result								*/
	uint64_t cap								/* Capacity								*/
) {
	unsigned char buff[CefC_Max_Length] = {0};
	int res;
	uint16_t index = 0;
	uint16_t value16;
	uint64_t value64;

	/* Create Upload Request message */
	/* Set header */
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_RCap;
	index += CefC_Csmgr_Msg_HeaderLen;

	/* Set result */
	memcpy (buff + index, &result, sizeof (uint8_t));
	index += sizeof (uint8_t);
	value64 = cef_client_htonb (cap);
	memcpy (buff + index, &value64, sizeof (uint64_t));
	index += sizeof (uint64_t);

	/* Set Length */
	value16 = htons (index);
	memcpy (buff + CefC_O_Length, &value16, CefC_S_Length);

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Send the cefping response(len = %u).\n", index);
	cef_dbg_buff_write (CefC_Dbg_Finest, buff, index);
#endif // CefC_Debug
	/* Send a response to source node */
	res = cef_csmgr_send_msg (sock, buff, index);

	if (res < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Failed to send the cefping response\n");
#endif // CefC_Debug
	}

	return;
}
/*--------------------------------------------------------------------------------------
	Incoming set cache capacity message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_scap_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
) {
	uint64_t cap;
	uint64_t value64;
	/* Check support */
	if (hdl->cs_mod_int->cache_cap_set == NULL) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Cache plugin has no scap function.\n");
#endif // CefC_Debug
		csmgrd_scap_response_send (sock, CcoreC_Failed);
		return;
	}

	if (buff_len != sizeof (uint64_t)) {
		/* too short */
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
		csmgrd_scap_response_send (sock, CcoreC_Failed);
		return;
	}

	memcpy (&value64, buff, buff_len);
	cap = cef_client_ntohb (value64);
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Call cache plugin (cache_cap_set)\n");
#endif // CefC_Debug
	if (hdl->cs_mod_int->cache_cap_set (cap) < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest, "Set capacity error\n");
#endif // CefC_Debug
		csmgrd_scap_response_send (sock, CcoreC_Failed);
	} else {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest, "Set cache capacity.\n");
#endif // CefC_Debug
		csmgrd_scap_response_send (sock, CcoreC_Success);
	}

	return;
}
/*--------------------------------------------------------------------------------------
	Send retrieve cache response message
----------------------------------------------------------------------------------------*/
static void
csmgrd_scap_response_send (
	int sock,									/* recv socket							*/
	uint8_t result								/* result								*/
) {
	unsigned char buff[CefC_Max_Length] = {0};
	int res;
	uint16_t index = 0;
	uint16_t value16;

	/* Create Upload Request message */
	/* Set header */
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_SCap;
	index += CefC_Csmgr_Msg_HeaderLen;

	/* Set result */
	memcpy (buff + index, &result, sizeof (uint8_t));
	index += sizeof (uint8_t);

	/* Set Length */
	value16 = htons (index);
	memcpy (buff + CefC_O_Length, &value16, CefC_S_Length);

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Send the scap response(len = %u).\n", index);
	cef_dbg_buff_write (CefC_Dbg_Finest, buff, index);
#endif // CefC_Debug
	/* Send a response to source node */
	res = cef_csmgr_send_msg (sock, buff, index);

	if (res < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Failed to send the scap response\n");
#endif // CefC_Debug
	}

	return;
}
/*--------------------------------------------------------------------------------------
	Incoming Retrieve Content Lifetime message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_rclt_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
) {
	CsmgrT_Stat* stat = NULL;
	uint16_t value16;
	unsigned char name[CefC_Max_Length] = {0};
	uint16_t name_len;
	uint64_t nowt;
	struct timeval tv;

	/* Check length */
	if (buff_len < sizeof (uint16_t)) {
		csmgrd_rclt_response_send (sock, CcoreC_Failed, 0);
		return;
	}

	/* Get name */
	memcpy (&value16, buff, sizeof (value16));
	name_len = ntohs (value16);

	if (buff_len < sizeof (uint16_t) + name_len) {
		csmgrd_rclt_response_send (sock, CcoreC_Failed, 0);
		return;
	}
	memcpy (name, buff + sizeof (value16), name_len);

	/* Obtain cached content information 			*/
	stat = csmgrd_stat_content_info_get (stat_hdl, name, name_len);

	if (stat) {
		gettimeofday (&tv, NULL);
		nowt = tv.tv_sec * 1000000llu + tv.tv_usec;
		csmgrd_rclt_response_send (sock, CcoreC_Success, stat->expiry - nowt);
#ifdef	CefC_DB_INDEX
		free( stat );
#endif
	} else {
		csmgrd_rclt_response_send (sock, CcoreC_Failed, 0);
	}

	return;
}
/*--------------------------------------------------------------------------------------
	Send Retrieve Content Lifetime response message
----------------------------------------------------------------------------------------*/
static void
csmgrd_rclt_response_send (
	int sock,									/* recv socket							*/
	uint8_t result,								/* result								*/
	uint64_t lifetime							/* Lifetime								*/
) {
	unsigned char buff[CefC_Max_Length] = {0};
	int res;
	uint16_t index = 0;
	uint16_t value16;
	uint64_t value64;

	/* Create Upload Request message */
	/* Set header */
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_RCLT;
	index += CefC_Csmgr_Msg_HeaderLen;

	/* Set result */
	memcpy (buff + index, &result, sizeof (uint8_t));
	index += sizeof (uint8_t);
	value64 = cef_client_htonb (lifetime);
	memcpy (buff + index, &value64, sizeof (uint64_t));
	index += sizeof (uint64_t);

	/* Set Length */
	value16 = htons (index);
	memcpy (buff + CefC_O_Length, &value16, CefC_S_Length);

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine,
			"Send the Retrieve Content Lifetime response(len = %u).\n", index);
	cef_dbg_buff_write (CefC_Dbg_Finest, buff, index);
#endif // CefC_Debug
	/* Send a response to source node */
	res = cef_csmgr_send_msg (sock, buff, index);

	if (res < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine,
				"Failed to send the Retrieve Content Lifetime response\n");
#endif // CefC_Debug
	}
	return;
}
/*--------------------------------------------------------------------------------------
	Incoming Set Content Lifetime message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_sclt_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
) {
	uint16_t value16;
	uint64_t lifetime = 0;
	unsigned char name[CefC_Max_Length] = {0};
	uint16_t name_len;
	uint64_t value64;

	if (hdl->cs_mod_int->content_lifetime_set == NULL) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Cache plugin has no sclt function.\n");
#endif // CefC_Debug
		csmgrd_sclt_response_send (sock, CcoreC_Failed);
		return;
	}

	/* Check length */
	if (buff_len < sizeof (uint16_t)) {
		/* too short */
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
		csmgrd_sclt_response_send (sock, CcoreC_Failed);
		return;
	}
	memcpy (&value16, buff, sizeof (value16));
	name_len = ntohs (value16);
	if ((buff_len - sizeof (uint16_t)) < name_len) {
		/* too short */
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
		csmgrd_sclt_response_send (sock, CcoreC_Failed);
		return;
	}
	/* Get name */
	memcpy (name, buff + sizeof (value16), name_len);
	/* Get Lifetime */
	if ((buff_len - sizeof (uint16_t) - name_len) < sizeof (value64)) {
		/* too short */
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
		csmgrd_sclt_response_send (sock, CcoreC_Failed);
		return;
	}
	memcpy (&value64, buff + sizeof (value16) + name_len, sizeof (value64));
	lifetime = cef_client_ntohb (value64);

	if (hdl->cs_mod_int->content_lifetime_set (name, name_len, lifetime) < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest, "Get Content lifetime error\n");
#endif // CefC_Debug
		csmgrd_sclt_response_send (sock, CcoreC_Failed);
	} else {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest, "Get Content lifetime success\n");
#endif // CefC_Debug
		csmgrd_sclt_response_send (sock, CcoreC_Success);
	}
	return;
}
/*--------------------------------------------------------------------------------------
	Send Set Content Lifetime response message
----------------------------------------------------------------------------------------*/
static void
csmgrd_sclt_response_send (
	int sock,									/* recv socket							*/
	uint8_t result								/* result								*/
) {
	unsigned char buff[CefC_Max_Length] = {0};
	int res;
	uint16_t index = 0;
	uint16_t value16;

	/* Create Upload Request message */
	/* Set header */
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_RCLT;
	index += CefC_Csmgr_Msg_HeaderLen;

	/* Set result */
	memcpy (buff + index, &result, sizeof (uint8_t));
	index += sizeof (uint8_t);

	/* Set Length */
	value16 = htons (index);
	memcpy (buff + CefC_O_Length, &value16, CefC_S_Length);

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine,
			"Send the Set Content Lifetime response(len = %u).\n", index);
	cef_dbg_buff_write (CefC_Dbg_Finest, buff, index);
#endif // CefC_Debug
	/* Send a response to source node */
	res = cef_csmgr_send_msg (sock, buff, index);

	if (res < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine,
				"Failed to send the Set Content Lifetime response\n");
#endif // CefC_Debug
	}
	return;
}
/*--------------------------------------------------------------------------------------
	Incoming Retrieve Cache Chunk message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_rcch_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
) {

#ifdef	CefC_DB_INDEX
	CsmgrT_Stat* rcd = NULL;
	uint16_t value16;
	unsigned char name[CefC_Max_Length] = {0};
	uint16_t name_len;
	unsigned char range[1024] = {0};
	uint16_t range_len;
	int s_val, e_val, val, sidx, eidx, i, n, st, ed;
	uint64_t mask;
	int find_f = 0;
	char info[CefC_Max_Length] = {0};
	int info_rem_size = sizeof (info) - 1; /* -1 for EOS */
	char tmp_str[32] = {0};
	char* wp = info;
	size_t len;
	CsmgrT_DB_COB_MAP*	cob_map = NULL;
	int					map_idx;

	/* Check length */
	if (buff_len < sizeof (uint16_t)) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
		csmgrd_rcch_response_send (sock, CcoreC_Failed, NULL);
		return;
	}

	/* Get name */
	memcpy (&value16, buff, sizeof (value16));
	name_len = ntohs (value16);

	if (buff_len < sizeof (uint16_t) + name_len) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
		csmgrd_rcch_response_send (sock, CcoreC_Failed, NULL);
		return;
	}
	memcpy (name, buff + sizeof (value16), name_len);

	/* Obtain cached content information 			*/
//	rcd = csmgrd_stat_content_info_get (stat_hdl, name, name_len);	//0.8.3c
	rcd = csmgrd_stat_content_info_is_exist (stat_hdl, name, name_len, &cob_map);
	{
	if (rcd) {
		/* Expiry Check */
		uint64_t nowt;
		struct timeval tv;

		if ( rcd->expire_f == 1 ) {
			free( cob_map );
			free( rcd );
			rcd = NULL;
		} else {
			gettimeofday (&tv, NULL);
			nowt = tv.tv_sec * 1000000llu + tv.tv_usec;
			if ( nowt > rcd->expiry ) {
				free( cob_map );
				free( rcd );
				rcd = NULL;
			}
		}
	}
	}

	if (rcd) {
		/* Get Range */
		if ((buff_len - sizeof (uint16_t) - name_len) < sizeof (value16)) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
			csmgrd_rcch_response_send (sock, CcoreC_Failed, NULL);
			/* Fail Free */
			free( cob_map );
			free( rcd );
			return;
		}
		memcpy (&value16, buff + sizeof (value16) + name_len, sizeof (value16));
		range_len = ntohs (value16);

		if (buff_len < sizeof (uint16_t) + name_len + range_len) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
			csmgrd_rcch_response_send (sock, CcoreC_Failed, NULL);
			/* Fail Free */
			free( cob_map );
			free( rcd );
			return;
		}
		memcpy (range, buff + sizeof (value16) + name_len + sizeof (uint16_t), range_len);
		if (csmgrd_start_end_num_get ((char*)range, &s_val, &e_val) < 0) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Range is invalid.\n");
#endif // CefC_Debug
			csmgrd_rcch_response_send (sock, CcoreC_Failed, NULL);
			/* Fail Free */
			free( cob_map );
			free( rcd );
			return;
		}
		if (s_val != -1) {
			if (s_val > rcd->max_seq) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Range is invalid.\n");
#endif // CefC_Debug
				sprintf (info, "The Maximum sequence number that is stored is %d.", rcd->max_seq);
				csmgrd_rcch_response_send (sock, CcoreC_Failed, (unsigned char*)info);
				/* Fail Free */
				free( cob_map );
				free( rcd );
				return;
			} else if (s_val < rcd->min_seq) {
				s_val = rcd->min_seq;
			}
			sidx = s_val / 64;
		} else {
			sidx = rcd->min_seq / 64;
			s_val = rcd->min_seq;
		}
		if (e_val != -1) {
			if (e_val < rcd->min_seq) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Range is incalid.\n");
#endif // CefC_Debug
				sprintf (info, "The Minimum sequence number that is stored is %d.", rcd->min_seq);
				csmgrd_rcch_response_send (sock, CcoreC_Failed, (unsigned char*)info);
				/* Fail Free */
				free( cob_map );
				free( rcd );
				return;
			} else if (e_val > rcd->max_seq) {
//				eidx = rcd->max_seq;	//20211213
				e_val = rcd->max_seq;
			}
			eidx = (e_val / 64) + 1;
		} else {
			eidx = (rcd->max_seq / 64) + 1;
			e_val = rcd->max_seq;
		}
		st = ed = s_val;
		{
		/* Convert db_cob_map to org_cob_map */
			uint32_t map_bsize;
			char*	 ptr;
			map_bsize = rcd->map_num * CsmgrT_Add_Maps;
			ptr = (char*)calloc (1, sizeof (uint64_t) * map_bsize);
			if (ptr == NULL) {
				/* Fail Free */
				free( cob_map );
				free( rcd );
				return;
			}
			rcd->cob_map = (uint64_t *)ptr;
			for ( map_idx = 0; map_idx < rcd->map_num; map_idx++ ) {
				memcpy (ptr, cob_map[map_idx].cob_map, sizeof (uint64_t) * CsmgrT_Add_Maps);
				ptr += (sizeof (uint64_t) * CsmgrT_Add_Maps);
			}
			rcd->map_max = map_bsize;
		}

		for (i = sidx; i < eidx; i++) {
			if ((rcd->map_max-1) >= i /*&& rcd->cob_map[i]*/) {
				mask = 0x0000000000000001;
				for (n = 0 ; n < 64 ; n++) {
					val = i * 64 + n;
					if (rcd->cob_map[i] & mask &&
						(s_val <= val && val <= e_val)) {
						if (find_f == 0) {
							find_f = 1;
							st = val;
							sprintf (tmp_str, "%d", st);
							len = strlen ((char*)tmp_str);
							info_rem_size -= (int)len;
							if (info_rem_size < 0) {
								goto OUT_COBMAP_LOOP;
							}
							memcpy (wp, tmp_str, len);
							wp = wp + len;
						}
					} else {
						if (find_f == 1) {
							find_f = 0;
							ed = val - 1;
							if (st < ed)
								sprintf (tmp_str, ":%d,", ed);
							else
								sprintf (tmp_str, ",");
							len = strlen ((char*)tmp_str);
							info_rem_size -= (int)len;
							if (info_rem_size < 0) {
								goto OUT_COBMAP_LOOP;
							}
							memcpy (wp, tmp_str, len);
							wp = wp + len;
						}
						if (val > e_val)
							goto OUT_COBMAP_LOOP;
					}
					mask <<= 1;
				}
			}
		}
OUT_COBMAP_LOOP:
		if (find_f == 1) {
			if (st < e_val)
				sprintf (tmp_str, ":%d,", e_val);
			else
				sprintf (tmp_str, ",");
			len = strlen ((char*)tmp_str);
			info_rem_size -= (int)len;
			if (info_rem_size >= 0) {
				memcpy (wp, tmp_str, len);
			}
		}
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Retrieve Cache Chunk.\n");
#endif // CefC_Debug
		csmgrd_rcch_response_send (sock, CcoreC_Success, (unsigned char*)info);
		/* Free */
		free( cob_map );
		free( rcd->cob_map );
		free( rcd );
	} else {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "No entry.\n");
#endif // CefC_Debug
		sprintf (info, "No entry.");
		csmgrd_rcch_response_send (sock, CcoreC_Failed, (unsigned char*)info);
	}

#else
	CsmgrT_Stat* rcd = NULL;
	uint16_t value16;
	unsigned char name[CefC_Max_Length] = {0};
	uint16_t name_len;
	unsigned char range[1024] = {0};
	uint16_t range_len;
	int s_val, e_val, val, sidx, eidx, i, n, st, ed;
	uint64_t mask;
	int find_f = 0;
	char info[CefC_Max_Length] = {0};
	int info_rem_size = sizeof (info) - 1; /* -1 for EOS */
	char tmp_str[32] = {0};
	char* wp = info;
	size_t len;

	/* Check length */
	if (buff_len < sizeof (uint16_t)) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
		csmgrd_rcch_response_send (sock, CcoreC_Failed, NULL);
		return;
	}

	/* Get name */
	memcpy (&value16, buff, sizeof (value16));
	name_len = ntohs (value16);

	if (buff_len < sizeof (uint16_t) + name_len) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
		csmgrd_rcch_response_send (sock, CcoreC_Failed, NULL);
		return;
	}
	memcpy (name, buff + sizeof (value16), name_len);

	/* Obtain cached content information 			*/
//0.8.3c	rcd = csmgr_stat_content_info_get (stat_hdl, name, name_len);
	rcd = csmgrd_stat_content_info_get (stat_hdl, name, name_len);	//0.8.3c
	if (rcd) {
		/* Get Range */
		if ((buff_len - sizeof (uint16_t) - name_len) < sizeof (value16)) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
			csmgrd_rcch_response_send (sock, CcoreC_Failed, NULL);
			return;
		}
		memcpy (&value16, buff + sizeof (value16) + name_len, sizeof (value16));
		range_len = ntohs (value16);

		if (buff_len < sizeof (uint16_t) + name_len + range_len) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
			csmgrd_rcch_response_send (sock, CcoreC_Failed, NULL);
			return;
		}
		memcpy (range, buff + sizeof (value16) + name_len + sizeof (uint16_t), range_len);
		if (csmgrd_start_end_num_get ((char*)range, &s_val, &e_val) < 0) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Range is invalid.\n");
#endif // CefC_Debug
			csmgrd_rcch_response_send (sock, CcoreC_Failed, NULL);
			return;
		}
		if (s_val != -1) {
			if (s_val > rcd->max_seq) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Range is invalid.\n");
#endif // CefC_Debug
				sprintf (info, "The Maximum sequence number that is stored is %d.", rcd->max_seq);
				csmgrd_rcch_response_send (sock, CcoreC_Failed, (unsigned char*)info);
				return;
			} else if (s_val < rcd->min_seq) {
				s_val = rcd->min_seq;
			}
			sidx = s_val / 64;
		} else {
			sidx = rcd->min_seq / 64;
			s_val = rcd->min_seq;
		}
		if (e_val != -1) {
			if (e_val < rcd->min_seq) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Range is incalid.\n");
#endif // CefC_Debug
				sprintf (info, "The Minimum sequence number that is stored is %d.", rcd->min_seq);
				csmgrd_rcch_response_send (sock, CcoreC_Failed, (unsigned char*)info);
				return;
			} else if (e_val > rcd->max_seq) {
				eidx = rcd->max_seq;
			}
			eidx = (e_val / 64) + 1;
		} else {
			eidx = (rcd->max_seq / 64) + 1;
			e_val = rcd->max_seq;
		}
		st = ed = s_val;
		for (i = sidx; i < eidx; i++) {
			if ((rcd->map_max-1) >= i /*&& rcd->cob_map[i]*/) {
				mask = 0x0000000000000001;
				for (n = 0 ; n < 64 ; n++) {
					val = i * 64 + n;
					if (rcd->cob_map[i] & mask &&
						(s_val <= val && val <= e_val)) {
						if (find_f == 0) {
							find_f = 1;
							st = val;
							sprintf (tmp_str, "%d", st);
							len = strlen ((char*)tmp_str);
							info_rem_size -= (int)len;
							if (info_rem_size < 0) {
								goto OUT_COBMAP_LOOP;
							}
							memcpy (wp, tmp_str, len);
							wp = wp + len;
						}
					} else {
						if (find_f == 1) {
							find_f = 0;
							ed = val - 1;
							if (st < ed)
								sprintf (tmp_str, ":%d,", ed);
							else
								sprintf (tmp_str, ",");
							len = strlen ((char*)tmp_str);
							info_rem_size -= (int)len;
							if (info_rem_size < 0) {
								goto OUT_COBMAP_LOOP;
							}
							memcpy (wp, tmp_str, len);
							wp = wp + len;
						}
						if (val > e_val)
							goto OUT_COBMAP_LOOP;
					}
					mask <<= 1;
				}
			}
		}
OUT_COBMAP_LOOP:
		if (find_f == 1) {
			if (st < e_val)
				sprintf (tmp_str, ":%d,", e_val);
			else
				sprintf (tmp_str, ",");
			len = strlen ((char*)tmp_str);
			info_rem_size -= (int)len;
			if (info_rem_size >= 0) {
				memcpy (wp, tmp_str, len);
			}
		}
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Retrieve Cache Chunk.\n");
#endif // CefC_Debug
		csmgrd_rcch_response_send (sock, CcoreC_Success, (unsigned char*)info);
	} else {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "No entry.\n");
#endif // CefC_Debug
		sprintf (info, "No entry.");
		csmgrd_rcch_response_send (sock, CcoreC_Failed, (unsigned char*)info);
	}
#endif
	return;
}
/*--------------------------------------------------------------------------------------
	Send Retrieve Cache Chunk response message
----------------------------------------------------------------------------------------*/
static void
csmgrd_rcch_response_send (
	int sock,									/* recv socket							*/
	uint8_t result,								/* result								*/
	unsigned char* info							/* chunk range							*/
) {
	unsigned char buff[CefC_Max_Length] = {0};
	int res;
	uint16_t index = 0;
	uint16_t value16;
	uint16_t len;

	/* Create Retrieve Cache Chunk response message */
	/* Set header */
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_RCCH;
	index += CefC_Csmgr_Msg_HeaderLen;

	/* Set result */
	memcpy (buff + index, &result, sizeof (uint8_t));
	index += sizeof (uint8_t);

	/* Set Info */
	if (info == NULL) {
		value16 = htons (index);
		memcpy (buff + index, &value16, CefC_S_Length);
		index += sizeof (uint16_t);
	} else {
		len = strlen ((char*)info);
		if ((index+sizeof (uint16_t)+len) > CefC_Max_Length) {
			len = len - ((index+sizeof (uint16_t)+len) - CefC_Max_Length);
		}
		value16 = htons (len);
		memcpy (buff + index, &value16, CefC_S_Length);
		index += sizeof (uint16_t);
		memcpy (buff + index, info, len);
		index += len;
	}

	/* Set Length */
	value16 = htons (index);
	memcpy (buff + CefC_O_Length, &value16, CefC_S_Length);

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine,
			"Send the Retrieve Cache Chunk response (len = %u).\n", index);
	cef_dbg_buff_write (CefC_Dbg_Finest, buff, index);
#endif // CefC_Debug
	/* Send a response to source node */
	res = cef_csmgr_send_msg (sock, buff, index);

	if (res < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine,
				"Failed to send the Retrieve Cache Chunk response\n");
#endif // CefC_Debug
	}
	return;
}
/*--------------------------------------------------------------------------------------
	Incoming Delete Cache message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_scdl_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
) {
#ifdef	CefC_DB_INDEX
	CsmgrT_Stat* rcd = NULL;
	uint16_t value16;
	unsigned char name[CefC_Max_Length] = {0};
	uint16_t name_len;
	unsigned char range[1024] = {0};
	uint16_t range_len;
	int s_val, e_val, i;

	if (hdl->cs_mod_int->content_cache_del == NULL) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Cache plugin has no scdl function.\n");
#endif // CefC_Debug
		csmgrd_scdl_response_send (sock, CcoreC_Failed);
		return;
	}

	/* Check length */
	if (buff_len < sizeof (uint16_t)) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
		csmgrd_scdl_response_send (sock, CcoreC_Failed);
		return;
	}

	/* Get name */
	memcpy (&value16, buff, sizeof (value16));
	name_len = ntohs (value16);

	if (buff_len < sizeof (uint16_t) + name_len) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
		csmgrd_scdl_response_send (sock, CcoreC_Failed);
		return;
	}
	memcpy (name, buff + sizeof (value16), name_len);

	/* Obtain cached content information 			*/
//0.8.3c	rcd = csmgr_stat_content_info_get (stat_hdl, name, name_len);
	rcd = csmgrd_stat_content_info_get (stat_hdl, name, name_len);	//0.8.3c
	if (rcd) {
		/* Get Range */
		if ((buff_len - sizeof (uint16_t) - name_len) < sizeof (value16)) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
			csmgrd_scdl_response_send (sock, CcoreC_Failed);
			/* Fail Free */
			free( rcd );
			return;
		}
		memcpy (&value16, buff + sizeof (value16) + name_len, sizeof (value16));
		range_len = ntohs (value16);

		if (buff_len < sizeof (uint16_t) + name_len + range_len) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
			csmgrd_scdl_response_send (sock, CcoreC_Failed);
			/* Fail Free */
			free( rcd );
			return;
		}
		memcpy (range, buff + sizeof (value16) + name_len + sizeof (uint16_t), range_len);
		if (csmgrd_start_end_num_get ((char*)range, &s_val, &e_val) < 0) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Range is invalid.\n");
#endif // CefC_Debug
			csmgrd_scdl_response_send (sock, CcoreC_Failed);
			/* Fail Free */
			free( rcd );
			return;
		}

		if (s_val != -1) {
			if (s_val > rcd->max_seq) {
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine, "There is no cache in the requested range.\n");
#endif // CefC_Debug
				csmgrd_scdl_response_send (sock, CcoreC_Success);
				/* Free */
				free( rcd );
				return;
			} else if (s_val < rcd->min_seq) {
				s_val = rcd->min_seq;
			}
		} else {
			s_val = rcd->min_seq;
		}
		if (e_val != -1) {
			if (e_val < rcd->min_seq) {
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine, "There is no cache in the requested range.\n");
#endif // CefC_Debug
				csmgrd_scdl_response_send (sock, CcoreC_Success);
				/* Free */
				free( rcd );
				return;
			} else if (e_val > rcd->max_seq) {
				e_val = rcd->max_seq;
			}
		} else {
			e_val = rcd->max_seq;
		}

		for (i = s_val; i <= e_val; i++) {

			if (hdl->cs_mod_int->content_cache_del (name, name_len, i) < 0) {
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Finest, "Delete Content Cache error.\n");
#endif // CefC_Debug
				csmgrd_scdl_response_send (sock, CcoreC_Failed);
				/* Fail Free */
				free( rcd );
				return;
			}
		}
	} else {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "No entry.\n");
#endif // CefC_Debug
		csmgrd_scdl_response_send (sock, CcoreC_Success);
		return;
	}

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, "Delete Content Cache success.\n");
#endif // CefC_Debug
	csmgrd_scdl_response_send (sock, CcoreC_Success);

	if ( rcd != NULL ) {
		/* Free */
		free( rcd );
	}

	return;

#else
	CsmgrT_Stat* rcd = NULL;
	uint16_t value16;
	unsigned char name[CefC_Max_Length] = {0};
	uint16_t name_len;
	unsigned char range[1024] = {0};
	uint16_t range_len;
	int s_val, e_val, i;

	if (hdl->cs_mod_int->content_cache_del == NULL) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Cache plugin has no scdl function.\n");
#endif // CefC_Debug
		csmgrd_scdl_response_send (sock, CcoreC_Failed);
		return;
	}

	/* Check length */
	if (buff_len < sizeof (uint16_t)) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
		csmgrd_scdl_response_send (sock, CcoreC_Failed);
		return;
	}

	/* Get name */
	memcpy (&value16, buff, sizeof (value16));
	name_len = ntohs (value16);

	if (buff_len < sizeof (uint16_t) + name_len) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
		csmgrd_scdl_response_send (sock, CcoreC_Failed);
		return;
	}
	memcpy (name, buff + sizeof (value16), name_len);

	/* Obtain cached content information 			*/
//0.8.3c	rcd = csmgr_stat_content_info_get (stat_hdl, name, name_len);
	rcd = csmgrd_stat_content_info_get (stat_hdl, name, name_len);	//0.8.3c
	if (rcd) {
		/* Get Range */
		if ((buff_len - sizeof (uint16_t) - name_len) < sizeof (value16)) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
			csmgrd_scdl_response_send (sock, CcoreC_Failed);
			return;
		}
		memcpy (&value16, buff + sizeof (value16) + name_len, sizeof (value16));
		range_len = ntohs (value16);

		if (buff_len < sizeof (uint16_t) + name_len + range_len) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
			csmgrd_scdl_response_send (sock, CcoreC_Failed);
			return;
		}
		memcpy (range, buff + sizeof (value16) + name_len + sizeof (uint16_t), range_len);
		if (csmgrd_start_end_num_get ((char*)range, &s_val, &e_val) < 0) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Range is invalid.\n");
#endif // CefC_Debug
			csmgrd_scdl_response_send (sock, CcoreC_Failed);
			return;
		}

		if (s_val != -1) {
			if (s_val > rcd->max_seq) {
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine, "There is no cache in the requested range.\n");
#endif // CefC_Debug
				csmgrd_scdl_response_send (sock, CcoreC_Success);
				return;
			} else if (s_val < rcd->min_seq) {
				s_val = rcd->min_seq;
			}
		} else {
			s_val = rcd->min_seq;
		}
		if (e_val != -1) {
			if (e_val < rcd->min_seq) {
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine, "There is no cache in the requested range.\n");
#endif // CefC_Debug
				csmgrd_scdl_response_send (sock, CcoreC_Success);
				return;
			} else if (e_val > rcd->max_seq) {
				e_val = rcd->max_seq;
			}
		} else {
			e_val = rcd->max_seq;
		}

		for (i = s_val; i <= e_val; i++) {

			if (hdl->cs_mod_int->content_cache_del (name, name_len, i) < 0) {
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Finest, "Delete Content Cache error.\n");
#endif // CefC_Debug
				csmgrd_scdl_response_send (sock, CcoreC_Failed);
				return;
			}
		}
	} else {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "No entry.\n");
#endif // CefC_Debug
		csmgrd_scdl_response_send (sock, CcoreC_Success);
		return;
	}

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, "Delete Content Cache success.\n");
#endif // CefC_Debug
	csmgrd_scdl_response_send (sock, CcoreC_Success);

	return;
#endif
}
/*--------------------------------------------------------------------------------------
	Send Delete Cache response message
----------------------------------------------------------------------------------------*/
static void
csmgrd_scdl_response_send (
	int sock,									/* recv socket							*/
	uint8_t result								/* result								*/
) {
	unsigned char buff[CefC_Max_Length] = {0};
	int res;
	uint16_t index = 0;
	uint16_t value16;

	/* Create Delete Cache response message */
	/* Set header */
	buff[CefC_O_Fix_Ver]  = CefC_Version;
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_SCDL;
	index += CefC_Csmgr_Msg_HeaderLen;

	/* Set result */
	memcpy (buff + index, &result, sizeof (uint8_t));
	index += sizeof (uint8_t);

	/* Set Length */
	value16 = htons (index);
	memcpy (buff + CefC_O_Length, &value16, CefC_S_Length);

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Send the scdl response (len = %u).\n", index);
	cef_dbg_buff_write (CefC_Dbg_Finest, buff, index);
#endif // CefC_Debug
	/* Send a response to source node */
	res = cef_csmgr_send_msg (sock, buff, index);

	if (res < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Failed to send the scdl response\n");
#endif // CefC_Debug
	}

	return;
}
#endif // CefC_Ccore
/*--------------------------------------------------------------------------------------
	In the case of START:END, check the validity of the numerical value.
----------------------------------------------------------------------------------------*/
static int
csmgrd_start_end_num_get (
	char* buff,
	int* start,
	int* end
) {
	char *wp, *sp, *ep;
	int i, wplen;
	int sval, eval;
	uint32_t ui32_eval;

	wp = buff;
	if (wp[0] == 0x3a) {	/* : */
		sp = NULL;
		if (strlen (wp) == 1) {
			ep = NULL;
		} else {
			ep = &wp[1];
			eval = atoi (ep);
			if (eval <= 0) {
				return (-1);
			}
		}
	} else {
		sp = &wp[0];
		wplen = strlen (wp);
		for (i = 1; i < wplen;i++) {
			if (wp[i] == 0x3a)
				break;
		}
		if (i == wplen) {
			fprintf (stderr, "ERROR : Invalid STARTNO:ENDNO\n");
			return (-1);
		}
		if (i == wplen - 1) {
			ep = NULL;
		} else {
			ep = &wp[i+1];
		}
		sval = atoi (sp);
		if (sval < 0) {
			return (-1);
		}
		if (ep != NULL) {
			//eval = atoi (ep);
			ui32_eval = strtoul(ep, NULL, 10);
			if (ui32_eval == UINT32_MAX) {
				eval = INT_MAX;
			} else if (ui32_eval <= INT_MAX) {
				eval = (int)ui32_eval;
			} else {
				eval = -1;
			}
			if (eval < 0 || eval < sval) {
				return (-1);
			}
		}
	}
	if (sp == NULL)
		*start = -1;
	else
		*start = sval;
	if (ep == NULL)
		*end = -1;
	else
		*end = eval;
	return (1);
}
/*--------------------------------------------------------------------------------------
	Post process
----------------------------------------------------------------------------------------*/
static void
csmgrd_post_process (
	CefT_Csmgrd_Handle* hdl						/* csmgr daemon handle					*/
) {
	csmgrd_handle_destroy (&hdl);
	return;
}
/*--------------------------------------------------------------------------------------
	Sigcatch Function
----------------------------------------------------------------------------------------*/
static void
csmgrd_sigcatch (
	int sig										/* caught signal						*/
) {
	if ((sig == SIGINT) || (sig == SIGTERM)) {
		csmgrd_running_f = 0;
	}
	return;
}
/*---------------------------------------------------------------------------------------
	memory/file Resource monitoring thread & functions
----------------------------------------------------------------------------------------*/
static void*
csmgrd_resource_mon_thread (
	void* arg
) {

	int m_total;
	int m_avaliable;
	uint64_t f_total_blocks;
	uint64_t f_avail_blocls;
	uint64_t m_cob_info;
	static uint64_t m_cob_info_max = 0;
	int m_used;
	int f_used;
	int c_used;
	static uint64_t max_cob_limit = 0;
	static int file_out = 0;
	int rc;
	static int mectr = -1;
	static int fectr = -1;
	pthread_t self_thread = pthread_self ();
	pthread_detach (self_thread);
	unsigned char cs_type;

	sleep (3);
	pthread_mutex_lock (&csmgr_Lack_of_resources_mutex);
	Lack_of_M_resources = 0;
	Lack_of_F_resources = 0;
	pthread_mutex_unlock (&csmgr_Lack_of_resources_mutex);


	CefT_Csmgrd_Handle* hdl = (CefT_Csmgrd_Handle*) arg;

	if (strcmp (hdl->cs_mod_name, "memory") == 0) {
		cs_type = 'M';
	} else if (strcmp (hdl->cs_mod_name, "filesystem") == 0) {
		cs_type = 'F';
	} else if (strcmp (hdl->cs_mod_name, "db") == 0) {
		cs_type = 'D';
	} else {
		cs_type = 'M';
	}

	while (csmgrd_running_f) {
		rc = get_mem_info (cs_type, &m_total, &m_avaliable, &m_cob_info);
		if (rc != 0) {
			cef_log_write (CefC_Log_Error, "%s(%d): Could not get memory information.\n", __FUNCTION__, __LINE__);
			break;
		}
		if (m_cob_info > m_cob_info_max) {
			m_cob_info_max = m_cob_info;
		}
//@@@fprintf(stderr, "[%s]: ----- m_cob_info="FMTU64" m_cob_info_max="FMTU64" -----\n", __FUNCTION__, m_cob_info, m_cob_info_max);
		rc = get_filesystem_info (hdl->fsc_cache_path, &f_total_blocks, &f_avail_blocls);
		if (rc != 0) {
			cef_log_write (CefC_Log_Error, "%s(%d): Could not get file information.\n", __FUNCTION__, __LINE__);
			sleep (30);
		}
		m_used = 100 - (int)((float)m_avaliable / m_total * 100);
//@@@fprintf(stderr, "[%s]: ----- m_used=%d -----\n", __FUNCTION__, m_used);
		f_used = 100 - (int)((float)f_avail_blocls / f_total_blocks * 100);
		if (max_cob_limit == 0) {
			c_used = -1;
		} else {
			if (m_cob_info > max_cob_limit) {
				c_used = 100;
			} else {
				c_used = 100 - (int)((float)(max_cob_limit - m_cob_info) / max_cob_limit * 100);
			}
		}
//@@@fprintf(stderr, "[%s]: ----- c_used=%d -----\n", __FUNCTION__, c_used);
		pthread_mutex_lock (&csmgr_Lack_of_resources_mutex);
		if (strcmp (hdl->cs_mod_name, "memory") == 0) {
			if (max_cob_limit == 0) {
				if (m_used > CSMGR_MAXIMUM_MEM_USAGE_FOR_MEM) {
					Lack_of_M_resources = 1;
//@@@fprintf(stderr, "[%s(%d)]: ----- Lack_of_M_resources = 1 -----\n", __FUNCTION__, __LINE__);
					max_cob_limit = m_cob_info_max;
				}
			} else {
				if (c_used != -1) {
					if (Lack_of_M_resources == 1) {
						if (c_used <= CSMGR_THRSHLD_MEM_USAGE_FOR_MEM) {
							Lack_of_M_resources = 0;
//@@@fprintf(stderr, "[%s(%d)]: ----- Lack_of_M_resources = 0 -----\n", __FUNCTION__, __LINE__);
						}
					} else { // (Lack_of_M_resources == 0)
						if (c_used > CSMGR_MAXIMUM_MEM_USAGE_FOR_MEM) {
							Lack_of_M_resources = 1;
//@@@fprintf(stderr, "[%s(%d)]: ----- Lack_of_M_resources = 1 -----\n", __FUNCTION__, __LINE__);
						}
					}
				}
			}
//@@@fprintf(stderr, "[%s(%d)]: ===== Lack_of_M_resources = %d ======\n", __FUNCTION__, __LINE__, Lack_of_M_resources);
		}
		else if (strcmp (hdl->cs_mod_name, "db") == 0) {
			if (max_cob_limit == 0) {
				if (m_used > CSMGR_MAXIMUM_MEM_USAGE_FOR_DB) {
					Lack_of_M_resources = 1;
//@@@fprintf(stderr, "[%s(%d)]: ----- Lack_of_M_resources = 1 -----\n", __FUNCTION__, __LINE__);
					max_cob_limit = m_cob_info_max;
				}
			} else {
				if (c_used != -1) {
					if (Lack_of_M_resources == 1) {
						if (c_used <= CSMGR_THRSHLD_MEM_USAGE_FOR_DB) {
							Lack_of_M_resources = 0;
						}
					} else { // (Lack_of_M_resources == 0)
						if (c_used > CSMGR_MAXIMUM_MEM_USAGE_FOR_DB) {
							Lack_of_M_resources = 1;
						}
					}
				}
			}
		}
		else if (strcmp (hdl->cs_mod_name, "filesystem") == 0) {
			if (max_cob_limit == 0) {
				if (m_used > CSMGR_MAXIMUM_MEM_USAGE_FOR_FILE) {
					Lack_of_M_resources = 1;
					max_cob_limit = m_cob_info_max;
				}
			} else {
				if (c_used != -1) {
					if (Lack_of_M_resources == 1) {
						if (c_used <= CSMGR_THRSHLD_MEM_USAGE_FOR_FILE) {
							Lack_of_M_resources = 0;
						}
					} else { // (Lack_of_M_resources == 0)
						if (c_used > CSMGR_MAXIMUM_MEM_USAGE_FOR_FILE) {
							Lack_of_M_resources = 1;
						}
					}
				}
			}

			if (f_used > CSMGR_MAXIMUM_FILE_USAGE_FOR_FILE) {
				Lack_of_F_resources = 1;
				file_out = 1;
			} else {
				if (file_out == 1) {
					if (f_used <= CSMGR_THRSHLD_FILE_USAGE_FOR_FILE) {
						Lack_of_F_resources = 0;
					}
				}
			}
		}
		else {
			abort ();
		}
		if (mectr != Lack_of_M_resources) {
			if (Lack_of_M_resources == 1) {
				if (strcmp (hdl->cs_mod_name, "db") != 0) {
					cef_log_write (CefC_Log_Error,
								"[RM] Stop caching due to memory usage reached to the max threshold. "
								"Restart csmgrd after CACHE_CAPACITY value in csmgrd.conf is reduced.\n");
				} else {
					cef_log_write (CefC_Log_Error,
								"[RM] Stop caching due to memory usage reached to the max threshold. "
								"Restart csmgrd after CACHE_CAPACITY value in db_cache.conf is reduced.\n");
				}
			} else {
				if (mectr != -1) {
					cef_log_write (CefC_Log_Error,
								"[RM-CLEAR] Restart caching because memory usage is below the threshold.\n");
				}
			}
			mectr = Lack_of_M_resources;
		}
		if (fectr != Lack_of_F_resources) {
			if (Lack_of_F_resources == 1) {
				cef_log_write (CefC_Log_Error,
								"[RM] Stop caching due to filesystem usage reached to the max threshold. "
								"Restart csmgrd after CACHE_CAPACITY value in csmgrd.conf is reduced.\n");
			} else {
				if (fectr != -1) {
					cef_log_write (CefC_Log_Error,
								"[RM-CLEAR] Restart caching because filesystem usage is below the threshold.\n");
				}
			}
			fectr = Lack_of_F_resources;
		}
		pthread_mutex_unlock (&csmgr_Lack_of_resources_mutex);

		sleep (1);
	}

	pthread_exit (NULL);

	return ((void*) NULL);
}
static int
get_mem_info (
		unsigned char cs_type,
		int* m_total,
		int* m_avaliable,
		uint64_t* m_cob_info
) {

	static int total_mega = 0;
	int free_mega = 0;
	uint64_t cob_info = 0;
	int res, i;
#ifndef CefC_MACOS
	/************************************************************************************/
	/* [/proc/meminfo format]															*/
	/*		MemTotal:        8167616 kB													*/
	/*		MemFree:         7130204 kB													*/
	/*		MemAvailable:    7717896 kB													*/
	/*		...																			*/
	/************************************************************************************/
	FILE* fp;
	char buf[1024];
	char* key = "MemAvailable:";
	char* meminfo = "/proc/meminfo";
	int avaliable;
	if ((fp = fopen (meminfo, "r")) == NULL) {
		cef_log_write (CefC_Log_Critical, "%s(%d): Could not open %s to get memory information.\n", __FUNCTION__, __LINE__, meminfo);
	}
	avaliable = 0;
	while (fgets (buf, sizeof (buf), fp) != NULL) {
		if (strncmp (buf, key, strlen (key)) == 0) {
			sscanf (&buf[strlen (key)], "%d", &avaliable);
			avaliable = avaliable / 1024;
			if (total_mega == 0) {
				total_mega = avaliable;
			}
			free_mega = avaliable;
			if (free_mega > total_mega) {
				free_mega = total_mega;
			}
			break;
		}
	}
	if (avaliable == 0) {
		cef_log_write (CefC_Log_Critical, "%s(%d): Could not find keyword(%s) to get memory information\n", __FUNCTION__, __LINE__, key);
	}
	if (fp != NULL) {
		fclose (fp);
	}
#else // CefC_MACOS
	/************************************************************************************/
	/* ["top -l 1 | grep -e PhysMem: -e csmgrd" format]									*/
	/*	PhysMem: 7272M used (1075M wired), 919M unused.		or							*/
	/*	PhysMem: 8028M used (1167M wired, 142M compressor), 7632M unused.				*/
	/*	85341  csmgrd           0.0  00:00.10 6     0   25     28M   0B    0B ..		*/
	/*														   ^^^						*/
	/************************************************************************************/
	FILE* fp;
	char buf[1024];
	char* cmd = "top -l 1 | grep -e PhysMem: -e csmgrd";
	char* tag = "PhysMem:";
	char* pname = "csmgrd";
	int	 used = -1, unused = -1;
	int  csused = -1;
	char fld01[128], fld02[128], fld03[128], fld04[128],
		 fld05[128], fld06[128], fld07[128], fld08[128];
	char unit;

	if ((fp = popen (cmd, "r")) != NULL) {
		while (fgets (buf, sizeof (buf), fp) != NULL) {
			if (strstr (buf, tag) != NULL) {
				char* token = NULL;
				char* token1 = NULL;
				char* saveptr = NULL;
				token = strtok_r (buf, " ", &saveptr);
				while (token) {
					token = strtok_r (NULL, " ", &saveptr);
					if (token == NULL) {
						break;
					}
					token1 = token;
					token = strtok_r (NULL, " ", &saveptr);
					if (token == NULL) {
						break;
					}

					if (strcmp (token, "used") == 0) {
						sscanf (token1, "%d%c", &used, &unit);
						if (unit == 'G') {
							used *= 1024;
						} else if (unit != 'M') {
							used = 0;
						}
					} else if (strncmp (token, "unused.", strlen("unused.")) == 0) {
						sscanf (token1, "%d%c", &unused, &unit);
						if (unit == 'G') {
							unused *= 1024;
						} else if (unit != 'M') {
							unused = 0;
						}
					}
				}
			} else {
				if (strstr (buf, pname) != NULL) {
					sscanf (buf, "%s %s %s %s %s %s %s %s",
							fld01, fld02, fld03, fld04,
							fld05, fld06, fld07, fld08);
					sscanf (fld08, "%d%c", &csused, &unit);
					if (unit == 'G') {
						csused *= 1024;
					} else if (unit != 'M') {
						csused = 0;
					}
				}
			}
		}
		pclose (fp);
	} else {
		cef_log_write (CefC_Log_Critical, "%s(%d): Could not get memory information.\n", __FUNCTION__, __LINE__);
	}
	if (used == -1 || unused == -1) {
		cef_log_write (CefC_Log_Critical, "%s(%d): Could not find keyword(%s) to get memory information\n",
					__FUNCTION__, __LINE__, tag);
		return (-1);
	}
	if (csused == -1) {
		cef_log_write (CefC_Log_Critical, "%s(%d): Could not find keyword(%s) to get memory information\n",
					__FUNCTION__, __LINE__, pname);
		return (-1);
	}
	if (total_mega == 0) {
		total_mega = unused;
	}
	if (total_mega < csused) {
		free_mega = total_mega;
	} else {
		free_mega = total_mega - csused;
	}
#endif // CefC_MACOS

	res = csmgrd_stat_content_info_gets_for_RM (stat_hdl, (const unsigned char *)"", 0, stat_for_PM);
	uint64_t name_len, cob_size, cob_num;
	for (i = 0 ; i < res ; i++) {
		name_len = stat_for_PM[i]->name_len;
		cob_size = stat_for_PM[i]->cob_size;
		cob_num = stat_for_PM[i]->cob_num;

		cob_info += (name_len * 2 + cob_size + 255) * cob_num;
	}
#ifdef	CefC_DB_INDEX
	for (i = 0 ; i < res ; i++) {
		free( stat_for_PM[i] );
	}
#endif
	if (total_mega == 0) {
		*m_total = 1;
		*m_avaliable = 0;
		cef_log_write (CefC_Log_Critical, "%s(%d): Could not get memory information.\n", __FUNCTION__, __LINE__);
	} else {
		*m_total = total_mega;
		*m_avaliable = free_mega;
		if (*m_avaliable < 0) {
			*m_avaliable = 0;
		}
	}
	*m_cob_info = cob_info;
	return (0);
}

static int
get_filesystem_info (
		char *filepath,
		uint64_t *total_blocks,
		uint64_t *avail_blocls
) {
	int rc = 0;
	struct statvfs buf = {0};

	rc = statvfs (filepath, &buf);
	if (rc < 0) {
		cef_log_write (CefC_Log_Error, "%s: statvfs(%s) - %s\n", __FUNCTION__, filepath, strerror (errno));
		*total_blocks = 1;
		*avail_blocls = buf.f_bavail;
		return (-1);
	}
	*total_blocks = buf.f_blocks;
	*avail_blocls = buf.f_bavail;

	return (0);
}
/*---------------------------------------------------------------------------------------
	"Upload Request" frame check functions
----------------------------------------------------------------------------------------*/
static int
cef_csmgr_frame_check (
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* message length						*/
) {
	uint16_t index, len;
	uint16_t pay_len, msg_len, name_len;
	uint16_t value16;


	/* check message size */
	if (buff_len <= CefC_Csmgr_Msg_HeaderLen) {
		return (-1);
	}

	/* check header */
	if ((buff[CefC_O_Fix_Ver]  != CefC_Version) ||
		(buff[CefC_O_Fix_Type] >= CefC_Csmgr_Msg_Type_Num) ||
		(buff[CefC_O_Fix_Type] == CefC_Csmgr_Msg_Type_Invalid)) {
//@@@@@fprintf(stderr, "[%s]: ------ retern(%d) -----\n", __FUNCTION__, __LINE__);
		return (-1);
	}
	memcpy (&value16, &buff[CefC_O_Length], CefC_S_Length);
	len = ntohs (value16);

	/* check MAGIC number */
	if (!(buff[len-3] == 0x63 && buff[len-2] == 0x6f && buff[len-1] == 0x62)) {
//@@@@@fprintf(stderr, "[%s]: ------ retern(%d) -----\n", __FUNCTION__, __LINE__);
//@@@@@fprintf(stderr, "[%s]: ------ buff[len-3]=%x buff[len-2]=%x buff[len-1]=%x -----\n", __FUNCTION__, buff[len-3], buff[len-2], buff[len-1]);
		return (-1);
	}

	/* check message length */
	if ((len <= CefC_Csmgr_Msg_HeaderLen) ||
		(len > buff_len)) {
//@@@@@fprintf(stderr, "[%s]: ------ retern(%d) -----\n", __FUNCTION__, __LINE__);
		return (-1);
	}
	index = CefC_Csmgr_Msg_HeaderLen;

	/* Get payload length */
	memcpy (&value16, &buff[index], CefC_S_Length);
	pay_len = ntohs (value16);

	if (pay_len > len) {
//@@@@@fprintf(stderr, "[%s]: ------ retern(%d) -----\n", __FUNCTION__, __LINE__);
		return (-1);
	}
	index += CefC_S_Length;

	/* Get cob message */
	memcpy (&value16, &buff[index], CefC_S_Length);
	msg_len = ntohs (value16);
	if (pay_len > msg_len) {
//@@@@@fprintf(stderr, "[%s]: ------ retern(%d) -----\n", __FUNCTION__, __LINE__);
		return (-1);
	}
	if (msg_len > len) {
//@@@@@fprintf(stderr, "[%s]: ------ retern(%d) -----\n", __FUNCTION__, __LINE__);
		return (-1);
	}
	index += CefC_S_Length;
	index += msg_len;

	/* Get cob name */
	memcpy (&value16, &buff[index], CefC_S_Length);
	name_len = ntohs (value16);
	if (name_len > msg_len) {
//@@@@@fprintf(stderr, "[%s]: ------ retern(%d) -----\n", __FUNCTION__, __LINE__);
		return (-1);
	}
	index += CefC_S_Length;
	if (!(buff[index] == 0x00 && buff[index+1] == 0x01)) {
//@@@@@fprintf(stderr, "[%s]: ------ retern(%d) -----\n", __FUNCTION__, __LINE__);
		return (-1);
	}
	return (0);
}
/*--------------------------------------------------------------------------------------
	Incoming Contents Information Request message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_continfo_msg(
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
) {
#ifdef CefC_DB_INDEX
	uint16_t			failed_f = 1;
	uint16_t			value16;
	uint16_t			name_len;
	unsigned char		name[CefC_Max_Length] = {0};
	CsmgrT_Stat*		rcd = NULL;
	uint16_t			range_len;
	unsigned char		range[1024] = {0};
	int					s_val, e_val, val, sidx, eidx, i, n, st, ed;
	uint64_t			mask;
	int					find_f = 0;
	char				info[CefC_Max_Length] = {0};
	int					info_rem_size = sizeof (info) - 1; /* -1 for EOS */
	char				tmp_str[32] = {0};
	char*				wp = info;
	size_t				len;
	unsigned char		snd_buff[CefC_Max_Length] = {0};
	uint16_t			index = 0;
	int					msg_failed_f = 0;
	CsmgrT_DB_COB_MAP*	cob_map = NULL;
	int					map_idx;
	char*				ptr = NULL;

#ifdef	__DB_IDX_DEB_CONTINFO
	fprintf( stderr, "[%s] IN \n", __func__ );
#endif
	/* Check length */
	if (buff_len < sizeof (uint16_t)) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
		return;
	}

	/* Get name */
	memcpy (&value16, buff, sizeof (value16));
	name_len = ntohs (value16);

	if (buff_len < sizeof (uint16_t) + name_len) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
		return;
	}
	memcpy (name, buff + sizeof (value16), name_len);

	/* Obtain cached content information */
//	rcd = csmgrd_stat_content_info_get (stat_hdl, name, name_len);
#ifdef	__DB_IDX_DEB_CONTINFO
	fprintf( stderr, "[%s] CKP-000 \n", __func__ );
#endif
	rcd = csmgrd_stat_content_info_is_exist (stat_hdl, name, name_len, &cob_map);
#ifdef	__DB_IDX_DEB_CONTINFO
	fprintf( stderr, "[%s] CKP-001 \n", __func__ );
#endif
if (!rcd) {
#ifdef	__DB_IDX_DEB_CONTINFO
		fprintf( stderr, "[%s] CKP-002 Fail \n", __func__ );
#endif
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "No entry.\n");
#endif // CefC_Debug
		failed_f = 0;
		msg_failed_f = 1;
		goto RESPSEND;
	}

	/* Get Range */
	if ((buff_len - sizeof (uint16_t) - name_len) < sizeof (value16)) {
#ifdef	__DB_IDX_DEB_CONTINFO
		fprintf( stderr, "[%s] CKP-003 Fail \n", __func__ );
#endif
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
		free( cob_map );
		free( rcd );
		rcd = NULL;
		msg_failed_f = 1;
		goto RESPSEND;
	}
	memcpy (&value16, buff + sizeof (value16) + name_len, sizeof (value16));
	range_len = ntohs (value16);
#ifdef	__DB_IDX_DEB_CONTINFO
	fprintf( stderr, "[%s] CKP-004 \n", __func__ );
#endif

	if (buff_len < sizeof (uint16_t) + name_len + range_len) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message is too short..\n");
#endif // CefC_Debug
#ifdef	__DB_IDX_DEB_CONTINFO
		fprintf( stderr, "[%s] CKP-005 Fail \n", __func__ );
#endif
		free( cob_map );
		free( rcd );
		rcd = NULL;
		msg_failed_f = 1;
		goto RESPSEND;
	}
	memcpy (range, buff + sizeof (value16) + name_len + sizeof (uint16_t), range_len);
#ifdef	__DB_IDX_DEB_CONTINFO
		fprintf( stderr, "[%s] CKP-006 \n", __func__ );
#endif

	/* Check start and end */
	if (csmgrd_start_end_num_get ((char*)range, &s_val, &e_val) < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Range is invalid.\n");
#endif // CefC_Debug
#ifdef	__DB_IDX_DEB_CONTINFO
		fprintf( stderr, "[%s] CKP-007 Fail \n", __func__ );
#endif
		free( cob_map );
		free( rcd );
		rcd = NULL;
		msg_failed_f = 1;
		goto RESPSEND;
	}

	/* Check range */
	if (s_val > rcd->max_seq) {
		s_val = rcd->max_seq;
	} else if (s_val < rcd->min_seq) {
		s_val = rcd->min_seq;
	}
	sidx = s_val / 64;
	if (e_val < rcd->min_seq) {
//		eidx = rcd->min_seq;
		e_val = rcd->min_seq;
	} else if (e_val > rcd->max_seq) {
//		eidx = rcd->max_seq;
		e_val = rcd->max_seq;
	}
	eidx = (e_val / 64) + 1;

#ifdef	__DB_IDX_DEB_CONTINFO
	fprintf( stderr, "[%s] CKP-008 \n", __func__ );
	fprintf( stderr, "[%s] s_val=%d sidx=%d e_val=%d eidx=%d \n", __func__, s_val, sidx, e_val, eidx );
	fprintf( stderr, "[%s] rcd->map_num=%d \n", __func__, rcd->map_num );
#endif
	/* Convert db_cob_map to org_cob_map */
		uint32_t map_bsize;
//		char*	 ptr;
		map_bsize = rcd->map_num * CsmgrT_Add_Maps;
		ptr = (char*)calloc (1, sizeof (uint64_t) * map_bsize);
		if (ptr == NULL) {
			/* Fail Free */
			free( cob_map );
			free( rcd );
			return;
		}
		rcd->cob_map = (uint64_t *)ptr;
		for ( map_idx = 0; map_idx < rcd->map_num; map_idx++ ) {
			memcpy (ptr, cob_map[map_idx].cob_map, sizeof (uint64_t) * CsmgrT_Add_Maps);
			ptr += (sizeof (uint64_t) * CsmgrT_Add_Maps);
		}
		rcd->map_max = map_bsize;
#ifdef	__DB_IDX_DEB_CONTINFO
	fprintf( stderr, "[%s] CKP-009 map_bsize:%d \n", __func__, map_bsize );
#endif

	/* Set start position */
	st = ed = s_val;
#ifdef	__DB_IDX_DEB_CONTINFO
	fprintf( stderr, "[%s] CKP-00A rcd->map_max:%d st:%d ed:%d \n", __func__, rcd->map_max, st, ed );
#endif


	/* Check */
	for (i = sidx; i < eidx; i++) {
		if ((rcd->map_max-1) >= i /*&& rcd->cob_map[i]*/) {
			mask = 0x0000000000000001;
			for (n = 0 ; n < 64 ; n++) {
				val = i * 64 + n;
				if (rcd->cob_map[i] & mask &&
					(s_val <= val && val <= e_val)) {
					if (find_f == 0) {
						find_f = 1;
						st = val;
						sprintf (tmp_str, "%d", st);
						len = strlen ((char*)tmp_str);
						info_rem_size -= (int)len;
						if (info_rem_size < 0) {
							goto OUT_COBMAPCHECK_LOOP;
						}
						memcpy (wp, tmp_str, len);
						wp = wp + len;
					}
				} else {
					if (find_f == 1) {
						find_f = 0;
						ed = val - 1;
						if (st < ed)
							sprintf (tmp_str, ":%d,", ed);
						else
							sprintf (tmp_str, ",");
						len = strlen ((char*)tmp_str);
						info_rem_size -= (int)len;
						if (info_rem_size < 0) {
							goto OUT_COBMAPCHECK_LOOP;
						}
						memcpy (wp, tmp_str, len);
						wp = wp + len;
					}
					if (val > e_val)
						goto OUT_COBMAPCHECK_LOOP;
				}
				mask <<= 1;
			}
		}
	}
OUT_COBMAPCHECK_LOOP:;
#ifdef	__DB_IDX_DEB_CONTINFO
	fprintf( stderr, "[%s] CKP-00B \n", __func__ );
#endif
	if (find_f == 1) {
		if (st < e_val)
			sprintf (tmp_str, ":%d,", e_val);
		else
			sprintf (tmp_str, ",");
		len = strlen ((char*)tmp_str);
		info_rem_size -= (int)len;
		if (info_rem_size >= 0) {
			memcpy (wp, tmp_str, len);
		}
	}
	failed_f = 0;

RESPSEND:;
#ifdef	__DB_IDX_DEB_CONTINFO
	fprintf( stderr, "[%s] CKP-00C \n", __func__ );
#endif

	/* Create and send Contents Information Response message */
	/* Set header */
	snd_buff[CefC_O_Fix_Ver]  = CefC_Version;
	snd_buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_ContInfo;
	index += CefC_Csmgr_Msg_HeaderLen;

	/* Set result */
	memcpy (snd_buff + index, &failed_f, sizeof (uint16_t));
	index += 2;

	/* Set Name */
	value16 = htons (name_len);
	memcpy (snd_buff + index, &value16, CefC_S_Length);
	index += 2;
	memcpy (snd_buff + index, name, name_len);
	index += name_len;

	/* Set Range */
	if (msg_failed_f) {
		value16 = 0x00;
		memcpy (snd_buff + index, &value16, CefC_S_Length);
		index += 2;
	} else {
#ifdef	__DB_IDX_DEB_CONTINFO
	fprintf( stderr, "[%s] CKP-00D info:%s \n", __func__, info );
#endif
		len = strlen (info);
		if ((index+2+len) > CefC_Max_Length) {
			len = len - ((index+2+len) - CefC_Max_Length);
		}
		value16 = htons (len);
		memcpy (snd_buff + index, &value16, CefC_S_Length);
		index += 2;
		memcpy (snd_buff + index, info, len);
		index += len;
	}

	/* Set Length */
	value16 = htons (index);
	memcpy (snd_buff + CefC_O_Length, &value16, CefC_S_Length);

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine,
			"Send the Contents Information response (len = %u).\n", index);
	cef_dbg_buff_write (CefC_Dbg_Finest, snd_buff, index);
#endif // CefC_Debug
	/* Send a response to source node */
	if (cef_csmgr_send_msg (sock, snd_buff, index) < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine,
			"Failed to send the Contents Information response\n");
#endif // CefC_Debug
	}

	/* Free */
	free( cob_map );
	free( rcd->cob_map );
	free( rcd );

#ifdef	__DB_IDX_DEB_CONTINFO
	fprintf( stderr, "[%s] CKP-OUT \n", __func__ );
#endif
#else //CefC_DB_INDEX
	uint16_t			failed_f = 1;
	uint16_t			value16;
	uint16_t			name_len;
	unsigned char		name[CefC_Max_Length] = {0};
	CsmgrT_Stat*		rcd = NULL;
	uint16_t			range_len;
	unsigned char		range[1024] = {0};
	int					s_val, e_val, val, sidx, eidx, i, n, st, ed;
	uint64_t			mask;
	int					find_f = 0;
	char				info[CefC_Max_Length] = {0};
	int					info_rem_size = sizeof (info) - 1; /* -1 for EOS */
	char				tmp_str[32] = {0};
	char*				wp = info;
	size_t				len;
	unsigned char		snd_buff[CefC_Max_Length] = {0};
	uint16_t			index = 0;
	int					msg_failed_f = 0;

	/* Check length */
	if (buff_len < sizeof (uint16_t)) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
		return;
	}

	/* Get name */
	memcpy (&value16, buff, sizeof (value16));
	name_len = ntohs (value16);

	if (buff_len < sizeof (uint16_t) + name_len) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
		return;
	}
	memcpy (name, buff + sizeof (value16), name_len);

	/* Obtain cached content information */
	rcd = csmgrd_stat_content_info_get (stat_hdl, name, name_len);
	if (!rcd) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "No entry.\n");
#endif // CefC_Debug
		failed_f = 0;
		msg_failed_f = 1;
		goto RESPSEND;
	}

	/* Get Range */
	if ((buff_len - sizeof (uint16_t) - name_len) < sizeof (value16)) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message is too short.\n");
#endif // CefC_Debug
		msg_failed_f = 1;
		goto RESPSEND;
	}
	memcpy (&value16, buff + sizeof (value16) + name_len, sizeof (value16));
	range_len = ntohs (value16);

	if (buff_len < sizeof (uint16_t) + name_len + range_len) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message is too short..\n");
#endif // CefC_Debug
		msg_failed_f = 1;
		goto RESPSEND;
	}
	memcpy (range, buff + sizeof (value16) + name_len + sizeof (uint16_t), range_len);

	/* Check start and end */
	if (csmgrd_start_end_num_get ((char*)range, &s_val, &e_val) < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Range is invalid.\n");
#endif // CefC_Debug
		msg_failed_f = 1;
		goto RESPSEND;
	}

	/* Check range */
	if (s_val > rcd->max_seq) {
		s_val = rcd->max_seq;
	} else if (s_val < rcd->min_seq) {
		s_val = rcd->min_seq;
	}
	sidx = s_val / 64;
	if (e_val < rcd->min_seq) {
		e_val = rcd->min_seq;
	} else if (e_val > rcd->max_seq) {
		e_val = rcd->max_seq;
	}
	eidx = (e_val / 64) + 1;

	/* Set start position */
	st = ed = s_val;

	/* Check */
	for (i = sidx; i < eidx; i++) {
		if ((rcd->map_max-1) >= i /*&& rcd->cob_map[i]*/) {
			mask = 0x0000000000000001;
			for (n = 0 ; n < 64 ; n++) {
				val = i * 64 + n;
				if (rcd->cob_map[i] & mask &&
					(s_val <= val && val <= e_val)) {
					if (find_f == 0) {
						find_f = 1;
						st = val;
						sprintf (tmp_str, "%d", st);
						len = strlen ((char*)tmp_str);
						info_rem_size -= (int)len;
						if (info_rem_size < 0) {
							goto OUT_COBMAPCHECK_LOOP;
						}
						memcpy (wp, tmp_str, len);
						wp = wp + len;
					}
				} else {
					if (find_f == 1) {
						find_f = 0;
						ed = val - 1;
						if (st < ed)
							sprintf (tmp_str, ":%d,", ed);
						else
							sprintf (tmp_str, ",");
						len = strlen ((char*)tmp_str);
						info_rem_size -= (int)len;
						if (info_rem_size < 0) {
							goto OUT_COBMAPCHECK_LOOP;
						}
						memcpy (wp, tmp_str, len);
						wp = wp + len;
					}
					if (val > e_val)
						goto OUT_COBMAPCHECK_LOOP;
				}
				mask <<= 1;
			}
		}
	}
OUT_COBMAPCHECK_LOOP:;
	if (find_f == 1) {
		if (st < e_val)
			sprintf (tmp_str, ":%d,", e_val);
		else
			sprintf (tmp_str, ",");
		len = strlen ((char*)tmp_str);
		info_rem_size -= (int)len;
		if (info_rem_size >= 0) {
			memcpy (wp, tmp_str, len);
		}
	}
	failed_f = 0;

RESPSEND:;

	/* Create and send Contents Information Response message */
	/* Set header */
	snd_buff[CefC_O_Fix_Ver]  = CefC_Version;
	snd_buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_ContInfo;
	index += CefC_Csmgr_Msg_HeaderLen;

	/* Set result */
	memcpy (snd_buff + index, &failed_f, sizeof (uint16_t));
	index += 2;

	/* Set Name */
	value16 = htons (name_len);
	memcpy (snd_buff + index, &value16, CefC_S_Length);
	index += 2;
	memcpy (snd_buff + index, name, name_len);
	index += name_len;

	/* Set Range */
	if (msg_failed_f) {
		value16 = 0x00;
		memcpy (snd_buff + index, &value16, CefC_S_Length);
		index += 2;
	} else {
		len = strlen (info);
		if ((index+2+len) > CefC_Max_Length) {
			len = len - ((index+2+len) - CefC_Max_Length);
		}
		value16 = htons (len);
		memcpy (snd_buff + index, &value16, CefC_S_Length);
		index += 2;
		memcpy (snd_buff + index, info, len);
		index += len;
	}

	/* Set Length */
	value16 = htons (index);
	memcpy (snd_buff + CefC_O_Length, &value16, CefC_S_Length);

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine,
			"Send the Contents Information response (len = %u).\n", index);
	cef_dbg_buff_write (CefC_Dbg_Finest, snd_buff, index);
#endif // CefC_Debug
	/* Send a response to source node */
	if (cef_csmgr_send_msg (sock, snd_buff, index) < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine,
			"Failed to send the Contents Information response\n");
#endif // CefC_Debug
	}
#endif
	return;
}


/***** 0.8.3c S *****/
#ifdef	CefC_DB_INDEX
static void
csmgrd_node_id_get (
	CefT_Csmgrd_Handle* hdl						/* csmgrd handle						*/
) {
	struct ifaddrs *ifa_list;
	struct ifaddrs *ifa;
	int n;

	unsigned char** 	nodeid4;
	unsigned char** 	nodeid16;
	int 				nodeid4_num = 0;
	int 				nodeid16_num = 0;


	n = getifaddrs (&ifa_list);
	if (n != 0) {
		return;
	}

	for(ifa = ifa_list ; ifa != NULL ; ifa=ifa->ifa_next) {

		if (ifa->ifa_addr == NULL) {
			continue;
		}

		if (ifa->ifa_addr->sa_family == AF_INET) {
			if (ifa->ifa_flags & IFF_LOOPBACK) {
				continue;
			}
			nodeid4_num++;
		} else if (ifa->ifa_addr->sa_family == AF_INET6) {
			if (ifa->ifa_flags & IFF_LOOPBACK) {
				continue;
			}
			nodeid16_num++;
		} else {
			/* NOP */;
		}
	}
	nodeid4 =
		(unsigned char**) calloc (nodeid4_num, sizeof (unsigned char*));

	for (n = 0 ; n < nodeid4_num ; n++) {
		nodeid4[n] = (unsigned char*) calloc (4, 1);
	}

	nodeid16 =
		(unsigned char**) calloc (nodeid16_num, sizeof (unsigned char*));
	for (n = 0 ; n < nodeid16_num ; n++) {
		nodeid16[n] = (unsigned char*) calloc (16, 1);
	}

	nodeid4_num 	= 0;
	nodeid16_num 	= 0;

	for (ifa = ifa_list ; ifa != NULL ; ifa=ifa->ifa_next) {

		if (ifa->ifa_addr == NULL) {
			continue;
		}

		if (ifa->ifa_addr->sa_family == AF_INET) {
			if (ifa->ifa_flags & IFF_LOOPBACK) {
				continue;
			}
			memcpy (&nodeid4[nodeid4_num][0],
				&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, 4);
			nodeid4_num++;
		} else if (ifa->ifa_addr->sa_family == AF_INET6) {
			if (ifa->ifa_flags & IFF_LOOPBACK) {
				continue;
			}
			memcpy (&nodeid16[nodeid16_num][0],
				&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, 16);
			nodeid16_num++;
		} else {
			/* NOP */;
		}
	}
	freeifaddrs (ifa_list);

	if (nodeid4_num > 0) {
		memcpy (hdl->top_nodeid, nodeid4[0], 4);
		hdl->top_nodeid_len = 4;
	} else if (nodeid16_num > 0) {
		memcpy (hdl->top_nodeid, nodeid16[0], 16);
		hdl->top_nodeid_len = 16;
	} else {
		hdl->top_nodeid[0] = 0x7F;
		hdl->top_nodeid[1] = 0x00;
		hdl->top_nodeid[2] = 0x00;
		hdl->top_nodeid[3] = 0x01;
		hdl->top_nodeid_len = 4;
	}

	for (n = 0 ; n < nodeid4_num ; n++) {
		free(nodeid4[n]);
	}
	free(nodeid4);

	for (n = 0 ; n < nodeid16_num ; n++) {
		free(nodeid16[n]);
	}
	free(nodeid16);

	char		addrstr[256];
	if ( hdl->top_nodeid_len == 4 ) {
		inet_ntop (AF_INET, hdl->top_nodeid, addrstr, sizeof (addrstr));
	} else if ( hdl->top_nodeid_len == 16 ) {
		inet_ntop (AF_INET6, hdl->top_nodeid, addrstr, sizeof (addrstr));
	}

	hdl->My_Node_Id = malloc( sizeof(char) * strlen(addrstr) + 1 );
	strcpy( hdl->My_Node_Id, addrstr );

	return;
}
#endif
/***** 0.8.3c E *****/


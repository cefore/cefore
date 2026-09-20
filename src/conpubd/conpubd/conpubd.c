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
 * conpubd.c
 */

#define __CEF_CONPUBD_SOURCE__

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
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <openssl/sha.h>
#include <sys/wait.h>
#include <sys/statvfs.h>

#include <conpubd.h>
#include <conpubd/conpubd_plugin.h>
#include <cefore/cef_csmgr.h>
#include <cefore/cef_csmgr_stat.h>
#include <cefore/cef_client.h>
#include <cefore/cef_frame.h>
#include <cefore/cef_log.h>
#include <cefore/cef_define.h>
#include <cefore/cef_valid.h>
#include <cefore/cef_pthread.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

/* Macros used in resource management processing */
#define CefC_Cpub_CS_Init_Mem_Utilization_Factor 0.9
#define CefC_Cpub_Memory_Usage_Correction_Factor 1.5
#define CefC_Cpub_Reserved_Disk_Mega 			 1000

#define CefC_Cpub_InconsistentVersion			-1000


/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

/****************************************************************************************
 State Variables
 ****************************************************************************************/

static int 	duplicate_flag = 0;

static CefT_Cpubcnt_Hdl Cpubcnthdl;						/* Content management entry */
static CsmgrT_Stat_Handle 	stat_hdl = CsmgrC_Invalid;	/* CS stat handle			*/
static int					conpubd_cntent_load_stat = 0;
														/* content load stat			*/
static int 					conpubd_running_f 	= 1;
static char 				conpub_conf_dir[PATH_MAX] = {"/usr/local/cefore"};
static char 				conpub_contdef_dir[PATH_MAX] = {"/usr/local/cefore"};
static char 				root_user_name[CefC_Csmgr_User_Len] = {"root"};
static char 				conpub_local_sock_name[PATH_MAX] = {0};
static pthread_mutex_t 		conpub_cnt_mutex = PTHREAD_MUTEX_INITIALIZER;

static uint64_t Intial_free_mem_mega = 0;

static char 				conpub_contdef_path[PATH_MAX] = {"/usr/local/cefore/conpubcont.def"};

/* Work areas */
static CefT_CcnMsg_MsgBdy* Cob_prames_p = NULL;
static unsigned char* 		Cob_msg_p = NULL;
static unsigned char* 		Name_buff_p = NULL;
static char* 				Uri_buff_p = NULL;
static CsmgrT_Stat** 		Stat_p = NULL;

#ifdef CefC_Debug
	static char workstr[CefC_Max_Length];
#endif
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
	Create conpub daemon handle
----------------------------------------------------------------------------------------*/
static CefT_Conpubd_Handle*			/* The return value is null if an error occurs		*/
conpubd_handle_create (
	void
);
/*--------------------------------------------------------------------------------------
	Destroy conpub daemon handle
----------------------------------------------------------------------------------------*/
static void
conpubd_handle_destroy (
	CefT_Conpubd_Handle** conpubd_hdl				/* CS Manager Handle					*/
);
/*--------------------------------------------------------------------------------------
	Read config file
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
conpubd_config_read (
	ConpubT_Config_Param* conf_param				/* parameter of config					*/
);
/*--------------------------------------------------------------------------------------
	Create local socket
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
conpubd_local_sock_create (
	void
);
/*--------------------------------------------------------------------------------------
	Check accept from local socket
----------------------------------------------------------------------------------------*/
static void
conpubd_local_sock_check (
	CefT_Conpubd_Handle* hdl					/* conpub daemon handle					*/
);
/*--------------------------------------------------------------------------------------
	Change string to value
----------------------------------------------------------------------------------------*/
static int64_t						/* The return value is negative if an error occurs	*/
conpubd_config_value_get (
	char* option,								/* conpubd option						*/
	char* value									/* String								*/
);
/*--------------------------------------------------------------------------------------
	Load plugin
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
conpubd_plugin_load (
	CefT_Conpubd_Handle* hdl					/* conpub daemon handle					*/
);
/*--------------------------------------------------------------------------------------
	Check plugin
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
conpubd_plugin_check (
	CefT_Conpubd_Handle* hdl					/* conpub daemon handle					*/
);
/*--------------------------------------------------------------------------------------
	Sets the path of conpubd.conf
----------------------------------------------------------------------------------------*/
static int
conpubd_plugin_config_dir_set (
	const char* config_file_dir
);
/*--------------------------------------------------------------------------------------
	Sets the path of conpubcont.def
----------------------------------------------------------------------------------------*/
static int
conpubd_contdef_dir_set (
	const char* contdef_file_dir
);
/*--------------------------------------------------------------------------------------
	Main Loop Function
----------------------------------------------------------------------------------------*/
static void
conpubd_event_dispatch (
	CefT_Conpubd_Handle* hdl					/* conpub daemon handle					*/
);
/*--------------------------------------------------------------------------------------
	Prepares the Control sockets to be polled
----------------------------------------------------------------------------------------*/
static int
conpubd_poll_socket_prepare (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	struct pollfd fds[],
	int fds_index[]
);
/*--------------------------------------------------------------------------------------
	Handles the received message(s)
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
conpubd_input_message_process (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* msg,							/* receive message						*/
	int msg_len,								/* message length						*/
	uint8_t type								/* message type							*/
);
#if 0 /* Don't delete for future */
/*--------------------------------------------------------------------------------------
	Incoming Get Status Message
----------------------------------------------------------------------------------------*/
static void
conpubd_incoming_status_msg (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
);
#endif /* Don't delete for future */

/*--------------------------------------------------------------------------------------
	Incoming Ccninfo Message
----------------------------------------------------------------------------------------*/
static void
conpubd_incoming_ccninfo_msg (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
);

/*--------------------------------------------------------------------------------------
	Receive Increment Access Count message
----------------------------------------------------------------------------------------*/
static void
conpubd_incoming_increment_msg (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
);
/*--------------------------------------------------------------------------------------
	Receive the Get Conpub Status Message
----------------------------------------------------------------------------------------*/
static void
conpubd_incoming_cnpbstatus_msg (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
);
/*--------------------------------------------------------------------------------------
	Receive the Reload Conpub Contents Message
----------------------------------------------------------------------------------------*/
static void
conpubd_incoming_cnpbrload_msg (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
);
/*--------------------------------------------------------------------------------------
	Reload Conpub Contents thread
----------------------------------------------------------------------------------------*/
static void*
conpubd_content_load_thread (
	void* arg
);
/*--------------------------------------------------------------------------------------
	Post process
----------------------------------------------------------------------------------------*/
static void
conpubd_post_process (
	CefT_Conpubd_Handle* hdl					/* conpub daemon handle					*/
);
/*--------------------------------------------------------------------------------------
	Sigcatch Function
----------------------------------------------------------------------------------------*/
static void
conpubd_sigcatch (
	int sig										/* caught signal						*/
);
/*--------------------------------------------------------------------------------------
	Creates the listening TCP socket with the specified port
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
conpubd_tcp_sock_create (
	CefT_Conpubd_Handle* hdl,				/* conpub daemon handle						*/
	uint16_t 		port_num				/* Port Number that cefnetd listens			*/
);
/*--------------------------------------------------------------------------------------
	Accepts the TCP socket
----------------------------------------------------------------------------------------*/
void
conpubd_tcp_connect_accept (
	CefT_Conpubd_Handle* hdl				/* conpub daemon handle						*/
);
/*--------------------------------------------------------------------------------------
	Search free tcp socket index
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
conpubd_free_sock_index_search (
	CefT_Conpubd_Handle* hdl					/* conpub daemon handle					*/
);
/*--------------------------------------------------------------------------------------
	function for processing the expire check
----------------------------------------------------------------------------------------*/
static void*
conpubd_expire_check_thread (
	void* arg
);
/*--------------------------------------------------------------------------------------
	Get frame from received message
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
conpub_input_bytes_process (
	CefT_Conpubd_Handle* hdl,				/* conpub daemon handle						*/
	int peer_fd,
	unsigned char* buff,					/* receive message							*/
	int buff_len							/* message length							*/
);
/*--------------------------------------------------------------------------------------
	Read the content definition file
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
conpub_contdef_read (
	CefT_Conpubd_Handle* hdl,				/* conpub daemon handle						*/
	CefT_Cpubcnt_Hdl* cnthdl
);
/*--------------------------------------------------------------------------------------
	Triming a line read from a file
----------------------------------------------------------------------------------------*/
static int
conpub_trim_line_string (
	const char* p, 								/* target string for trimming 			*/
	char* uri, 									/* URI string after trimming			*/
	char* path,									/* Path string after trimming			*/
	char* date,									/* Date string after trimming			*/
	char* time,
	char* t_pending								/* pending_timer string after trimming	*/
);
/*--------------------------------------------------------------------------------------
	Checks the file path
----------------------------------------------------------------------------------------*/
int
conpub_check_file_path (
	const char* path 							/* file path 							*/
);
/*--------------------------------------------------------------------------------------
	Checks the date
----------------------------------------------------------------------------------------*/
int
conpub_parse_date (
	const char* date_str, 						/* date string (e.g. 2017-1-28) 		*/
	const char* time_str, 						/* time string (e.g. 15:45) 			*/
	struct tm* date								/* variable to set the parsed result 	*/
);
/*--------------------------------------------------------------------------------------
	Inits cefcontentserver
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
conpubd_init (
	const char* conf_path
);
/*--------------------------------------------------------------------------------------
	Post Process of cefcontentserver
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
conpubd_destroy (
	void
);
/*--------------------------------------------------------------------------------------
	Creates the Cobs
----------------------------------------------------------------------------------------*/
static int
conpubd_publish_content_create (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	CefT_Cpubcnt_Hdl* entry,
	time_t now_time
);
/*--------------------------------------------------------------------------------------
	Deletes the Cobs
----------------------------------------------------------------------------------------*/
static int
conpubd_publish_content_delete (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	CefT_Cpubcnt_Hdl* entry
);
/*--------------------------------------------------------------------------------------
	Content registration check
----------------------------------------------------------------------------------------*/
static CefT_Cpubcnt_Hdl*
conpubd_content_reg_check (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	unsigned char* name,
	uint16_t       name_len
);
/*--------------------------------------------------------------------------------------
	Connection to cefnetd and App registration
----------------------------------------------------------------------------------------*/
static void
conpubd_connect_conpubd_and_regApp (
	CefT_Conpubd_Handle* hdl
);
/*--------------------------------------------------------------------------------------
	Connect to conpubd with TCP socket
----------------------------------------------------------------------------------------*/
static int
conpub_connect_tcp_to_cefnetd (
	uint16_t    myport,
	const char* dest,
	const char* port
);
/*--------------------------------------------------------------------------------------
	Get free memory size
----------------------------------------------------------------------------------------*/
static int
conpubd_free_memsize_get (
	uint64_t* free_mem_mega
);
/*--------------------------------------------------------------------------------------
	Get free disk size
----------------------------------------------------------------------------------------*/
static int
get_filesystem_info (
		char *filepath,
		uint64_t* free_file_mega
);

#ifdef CefC_Debug
static void
conpubd_dbg_convert_name_to_str_put_workstr (
	unsigned char* name_p,
	int name_len
);
#endif //CefC_Debug

/*--------------------------------------------------------------------------------------
	Receive the Conpub Contents Delete Message
----------------------------------------------------------------------------------------*/
static void
conpubd_incoming_cont_del_msg (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
);

/*--------------------------------------------------------------------------------------
	Convert string to binary
----------------------------------------------------------------------------------------*/
static void
conpubd_str2byte (
	char *str,									/* string to convert					*/
	char *data,									/* Area to store converted binary		*/
	size_t len									/* Size of area to store binaries		*/
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
	CefT_Conpubd_Handle* hdl;
	int res;
	int i;
	int dir_path_f 		= 0;
	int rtc;
	uint64_t free_mem_mega;

	char*	work_arg;
	char file_path[PATH_MAX] = {0};

	/* Get intial free memory size */
	conpubd_free_memsize_get (&free_mem_mega);
	Intial_free_mem_mega = free_mem_mega;

	/* set running flag */
	conpubd_running_f = 1;
	/* Set signal */
	if (SIG_ERR == signal (SIGINT, conpubd_sigcatch)) {
		cef_log_write (CefC_Log_Error, "sig_num(%d) is invalid.\n", SIGINT);
		conpubd_running_f = 0;
	}
	if (SIG_ERR == signal (SIGTERM, conpubd_sigcatch)) {
		cef_log_write (CefC_Log_Error, "sig_num(%d) is invalid.\n", SIGTERM);
		conpubd_running_f = 0;
	}

	signal (SIGPIPE, SIG_IGN);
	/* Init logging 	*/
	cef_log_init ("conpubd", 1);

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
	cef_log_init2 (file_path, 2 /* for CONPUBD */);
	cef_log_fopen (CefC_CnpbDefault_Tcp_Prot);
#ifdef CefC_Debug
	cef_dbg_init ("conpubd", file_path, 2);
#endif
	cef_client_init (0, "");

	/* 	Sets the path of conpubd.conf*/
	res = conpubd_plugin_config_dir_set (file_path);
	if (res < 0) {
		cef_log_write (CefC_Log_Error, "Failed to read conpubd.conf.\n");
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) Failed to read conpubd.conf.\n", __func__, __LINE__);
#endif //CefC_Debug
		return (-1);
	}
	/* 	Sets the path of conpubcont.def*/
	res = conpubd_contdef_dir_set (file_path);
	if (res < 0) {
		cef_log_write (CefC_Log_Error, "Failed to read conpubcont.def.\n");
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) Failed to read conpubcont.def.\n", __func__, __LINE__);
#endif //CefC_Debug
		return (-1);
	}
	/* Create conpubd handle */
	hdl = conpubd_handle_create ();
	if (hdl == NULL) {
		cef_log_write (CefC_Log_Error, "Unable to create conpubd handle.\n");
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) Unable to create conpubd handle.\n", __func__, __LINE__);
#endif //CefC_Debug
		conpubd_post_process (hdl);
		return (-1);
	}
	/* Get free memory size */
	conpubd_free_memsize_get (&free_mem_mega);
	if (strcmp(hdl->cache_type, CefC_Cnpb_memory_Cache_Type) == 0
		  &&
		free_mem_mega < Intial_free_mem_mega * CefC_Cpub_CS_Init_Mem_Utilization_Factor) {
		char	buff[BUFSIZ];
		snprintf(buff, sizeof(buff),
		    "The memory content hash table is too large.\n"
			"Decrease the value of the parameter (CONTENTS_CAPACITY).\n"
			"	(Detected Intial Free Memory Size="FMTU64"MB\n"
			"	 Current Free Memory Size="FMTU64"MB)",
			Intial_free_mem_mega,
			free_mem_mega);
		cef_log_write (CefC_Log_Error, "%s\n", buff);
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) %s\n", __func__, __LINE__, buff);
#endif //CefC_Debug
		conpubd_post_process (hdl);
		return (-1);
	}

	/* Create work areas */
	if ((Cob_prames_p = calloc (1, sizeof (CefT_CcnMsg_MsgBdy))) == NULL) {
		cef_log_write (CefC_Log_Error, "Unable to create woek area (Cob_prames_p).\n");
		conpubd_post_process (hdl);
		return (-1);
	}
	if ((Cob_msg_p = calloc (1, CefC_Max_Length)) == NULL) {
		cef_log_write (CefC_Log_Error, "Unable to create woek area (Cob_msg_p).\n");
		conpubd_post_process (hdl);
		return (-1);
	}


	if ((Name_buff_p = calloc (1, CefC_Max_Length)) == NULL) {
		cef_log_write (CefC_Log_Error, "Unable to create woek area (Name_buff_p).\n");
		conpubd_post_process (hdl);
		return (-1);
	}
	if ((Uri_buff_p = calloc (1, CefC_NAME_MAXLEN)) == NULL) {
		cef_log_write (CefC_Log_Error, "Unable to create woek area (Uri_buff_p).\n");
		conpubd_post_process (hdl);
		return (-1);
	}
	if ((Stat_p = (CsmgrT_Stat**)calloc (sizeof (CsmgrT_Stat*), CsmgrT_Stat_Max)) == NULL) {
		cef_log_write (CefC_Log_Error, "Unable to create woek area (Stat_p).\n");
		conpubd_post_process (hdl);
		return (-1);
	}

	/* Inits cefcontentserver */
	rtc = conpubd_init (conpub_conf_dir);
	if (rtc < 0) {
		cef_log_write (CefC_Log_Error, "Failed to Init conpubd.\n");
		conpubd_post_process (hdl);
		return (-1);
	}

	if ( conpubd_cntent_load_stat == 0) {
		pthread_t th;
		if (cef_pthread_create (&th, NULL, conpubd_content_load_thread, hdl) == -1) {
			cef_log_write (CefC_Log_Error, "Failed to create the new thread\n");
			return(-1);
		}
	}

	/* start main process */
	conpubd_event_dispatch (hdl);
	return (0);
}
/*--------------------------------------------------------------------------------------
	Create conpub daemon handle
----------------------------------------------------------------------------------------*/
static CefT_Conpubd_Handle*			/* The return value is null if an error occurs		*/
conpubd_handle_create (
	void
) {
	CefT_Conpubd_Handle* hdl = NULL;
	ConpubT_Config_Param conf_param;
	int i;
	char*	envp;

	/* create handle */
	hdl = (CefT_Conpubd_Handle*) malloc (sizeof (CefT_Conpubd_Handle));
	if (hdl == NULL) {
		cef_log_write (CefC_Log_Error, "Failed to get memory required for startup.\n");
		return (NULL);
	}
	/* initialize handle */
	memset (hdl, 0, sizeof (CefT_Conpubd_Handle));
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

	for (i = 0 ; i < ConpubdC_Max_Sock_Num ; i++) {
		hdl->tcp_buff[i] =
			(unsigned char*) malloc (sizeof (unsigned char) * CefC_CsPipeBuffSize);
	}


#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Loading the config file.\n");
#endif // CefC_Debug
	/* Load config */
	if (conpubd_config_read (&(conf_param)) < 0) {
		cef_log_write (CefC_Log_Error, "Failed to load the %s\n", CefC_Conpub_Conf_Name);

		free (hdl);
		return (NULL);
	}

	if (cef_valid_init (conpub_conf_dir) != 1) {
		cef_log_write (CefC_Log_Error, "Failed to read the Encryption key file.\n");
		return (NULL);
	}

	/* Parameter value setting for conpubd handler */
	hdl->contents_num = conf_param.contents_num;
	hdl->contents_capacity = conf_param.contents_capacity;
	strcpy (hdl->cache_path, conf_param.cache_path);
	hdl->purge_interval = conf_param.purge_interval  * 1000000llu;
																/* Convert sec to micro-sec				*/
																/* , which is internal processing time	*/
	hdl->cache_default_rct = conf_param.cache_default_rct;
	hdl->valid_type = (uint16_t)cef_valid_type_get (conf_param.Valid_Alg);
	hdl->block_size = conf_param.block_size;
	hdl->t_pending = conf_param.t_pending;
	memcpy (hdl->publisher_id, conf_param.publisher_id, SHA512_DIGEST_LENGTH);
	strcpy (hdl->restore_path, conf_param.restore_path);
	strcpy (hdl->restore_fname, conf_param.restore_fname);

	/********** Published info.  ***********/
	hdl->published_contents_num = 0;

	/* Set APP FIB registration socket information */
	memset (hdl->cefnetd_id, 0, sizeof (hdl->cefnetd_id));
	strcpy (hdl->cefnetd_id, conf_param.cefnetd_node);
	memset (hdl->cefnetd_port_str, 0, sizeof (hdl->cefnetd_port_str));
	sprintf (hdl->cefnetd_port_str, "%d", conf_param.cefnetd_port);
	hdl->cefnetd_sock = -1;
	uint64_t nowt = cef_client_present_timeus_calc ();
	hdl->cefnetd_reconnect_time = nowt + 5000000;

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Create the listen socket.\n");
#endif // CefC_Debug

	/* Creates the local listen socket 		*/
	hdl->local_listen_fd = conpubd_local_sock_create ();
	if (hdl->local_listen_fd < 0) {
		cef_log_write (CefC_Log_Error, "Fail to create the local listen socket.\n");
		return (NULL);
	}

	/* Create tcp listen socket 	*/
	hdl->tcp_listen_fd = conpubd_tcp_sock_create (hdl, conf_param.port_num);
	if (hdl->tcp_listen_fd < 0) {
		cef_log_write (CefC_Log_Error, "Fail to create the TCP listen socket.\n");
		return (NULL);
	}
	hdl->port_num = conf_param.port_num;
	for (i = 0 ; i < ConpubdC_Max_Sock_Num ; i++) {
		hdl->tcp_fds[i] 	= -1;
		hdl->tcp_index[i] 	= 0;
	}
	cef_log_write (CefC_Log_Info, "Creation the TCP listen socket ... OK\n");

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Create plugin interface.\n");
#endif // CefC_Debug
	/* Create plugin interface */
	hdl->cs_mod_int =
	 				(ConpubdT_Plugin_Interface*)malloc (sizeof (ConpubdT_Plugin_Interface));
	if (hdl->cs_mod_int == NULL) {
		cef_log_write (CefC_Log_Error, "Failed to get memory required for startup.\n");
		return (NULL);
	}
	memset (hdl->cs_mod_int, 0, sizeof (ConpubdT_Plugin_Interface));
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Load plugin.\n");
#endif // CefC_Debug
	/* Load plugin */
	strcpy (hdl->cache_type, conf_param.cache_type);
	if (conpubd_plugin_load (hdl) < 0) {
		cef_log_write (CefC_Log_Error, "Load plugin error.\n");
		return (NULL);
	}

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Check plugin.\n");
#endif // CefC_Debug
	/* Check plugin */
	if (conpubd_plugin_check (hdl) < 0) {
		cef_log_write (CefC_Log_Error, "Required function is not implemented.\n");
		return (NULL);
	}

	/* Initialize plugin */
	if (hdl->cs_mod_int->init != NULL) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Initialize plugin.\n");
#endif // CefC_Debug
		stat_hdl = conpubd_stat_handle_create ();
		if (stat_hdl == CsmgrC_Invalid) {
			cef_log_write (CefC_Log_Error, "Failed to create conpubd stat handle.\n");
			return (NULL);
		}
		if (hdl->cs_mod_int->init (stat_hdl) < 0) {
			cef_log_write (CefC_Log_Error, "Failed to initialize cache plugin.\n");
			return (NULL);
		}
		cef_log_write (CefC_Log_Info, "Initialization the cache plugin ... OK\n");

	} else {
		cef_log_write (CefC_Log_Info, "Failed to call INIT API.\n");
		return (NULL);
	}

	cef_log_write (CefC_Log_Info, "Loading %s ... OK\n", CefC_Conpub_Conf_Name);

#ifdef CefC_Debug
	/* Show config value */
	cef_dbg_write (CefC_Dbg_Fine, "PURGE_INTERVAL = %u\n", hdl->purge_interval);
	cef_dbg_write (CefC_Dbg_Fine, "CACHE_TYPE = %s\n", hdl->cache_type);
	cef_dbg_write (CefC_Dbg_Fine, "PORT_NUM = %u\n", hdl->port_num);
#endif // CefC_Debug

	return (hdl);
}
/*--------------------------------------------------------------------------------------
	Main Loop Function
----------------------------------------------------------------------------------------*/
static void conpub_register_queue_init(void);
static void conpubd_register_workers_start(void);
static void conpubd_delete_workers_start(void);

static void
conpubd_event_dispatch (
	CefT_Conpubd_Handle* hdl					/* conpub daemon handle					*/
) {
	struct pollfd fds[ConpubdC_Max_Sock_Num];
	int fdnum;
	int fds_index[ConpubdC_Max_Sock_Num];
	int len;
	int res;
	int i;
	pthread_t		conpubd_expire_check_th;
	void*			status;

	conpub_register_queue_init();
	conpubd_register_workers_start();
	conpubd_delete_workers_start();

	cef_log_write (CefC_Log_Info, "Running\n");

	if (cef_pthread_create (&conpubd_expire_check_th, NULL, conpubd_expire_check_thread, hdl) == -1) {
		cef_log_write (CefC_Log_Error, "Failed to create the new thread\n");
		conpubd_running_f = 0;
	}

	/* Main loop */
	while (conpubd_running_f) {

		/* connect to cefnetd */
		conpubd_connect_conpubd_and_regApp (hdl);

		/* check accept */
		conpubd_local_sock_check (hdl);
		/* Checks socket accept 			*/
		conpubd_tcp_connect_accept (hdl);
		/* Sets fds to be polled 			*/
		fdnum = conpubd_poll_socket_prepare (hdl, fds, fds_index);
		res = poll (fds, fdnum, 1);
		if (res < 0) {
			/* poll error */
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "poll error (%s)\n", strerror (errno));
#endif // CefC_Debug
			continue;
		}
		if (res == 0) {
			/* poll time out */
			continue;
		}
		/* Checks whether frame(s) arrivals from the active local faces */
		for (i = 0 ; res > 0 && i < ConpubdC_Max_Sock_Num - 1 ; i++) {
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
						/* CONtoCEFNETD */
						if (hdl->tcp_fds[fds_index[i]] == hdl->cefnetd_sock) {
							hdl->cefnetd_sock = -1;
						}
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
					CefC_CsPipeBuffSize - hdl->tcp_index[fds_index[i]], 0);
				if (len > 0) {
					/* receive message */
					len += hdl->tcp_index[fds_index[i]];
					if (fds[i].fd != hdl->cefnetd_sock) {
						len = conpub_input_bytes_process (
								hdl, fds[i].fd,
								&hdl->tcp_buff[fds_index[i]][0], len);
						if (len < 0) {
							/* socket ownership transferred to recv thread */
							if (hdl->tcp_fds[fds_index[i]] != -1) {
								if (hdl->tcp_fds[fds_index[i]] == hdl->cefnetd_sock) {
									hdl->cefnetd_sock = -1;
								}
								hdl->tcp_fds[fds_index[i]] = -1;
								hdl->peer_num--;
							}
							hdl->tcp_index[fds_index[i]] = 0;
							continue;
						}
						/* set index */
						if (len > 0) {
							hdl->tcp_index[fds_index[i]] = len;
						} else {
							hdl->tcp_index[fds_index[i]] = 0;
						}
					}
					else {
						struct cef_app_request app_request;
						do {
							len = cef_client_request_get_with_info (hdl->tcp_buff[fds_index[i]], len, &app_request);
							if (app_request.version == CefC_App_Version) {
#ifdef CefC_Debug
								cef_dbg_write (CefC_Dbg_Finest, "Receive the Interest Message\n");
#endif // CefC_Debug

								if ( !conpubd_content_reg_check (hdl, app_request.name, app_request.total_segs_len) ) {
									/* Don't have requested contents */
									break;
								}

								/* Searches and sends a Cob */
								hdl->cs_mod_int->cache_item_get
													(app_request.name, app_request.total_segs_len, app_request.chunk_num, fds[i].fd);
							}
							else {
								break;
							}
						} while (len > 0);
						/* set index */
						if (len > 0) {
							hdl->tcp_index[fds_index[i]] = len;
						} else {
							hdl->tcp_index[fds_index[i]] = 0;
						}
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
							if (hdl->tcp_fds[fds_index[i]] == hdl->cefnetd_sock) {
								hdl->cefnetd_sock = -1;
							}
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
								if (hdl->tcp_fds[fds_index[i]] == hdl->cefnetd_sock) {
									hdl->cefnetd_sock = -1;
								}
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
	pthread_join (conpubd_expire_check_th, &status);

	/* post process */
	conpubd_post_process (hdl);
	cef_log_write (CefC_Log_Info, "Stop\n");

	return;
}

/*--------------------------------------------------------------------------------------
	A function that registers or unregisters content names with cefnetd.
----------------------------------------------------------------------------------------*/
static void
conpubd_appreg_api(
	int		cefnetd_sock,
	int		operation,
	unsigned char	*name,
	int		name_len
) {
	CefT_Connect connect = { 0 };
	CefT_Client_Handle fhdl = (CefT_Client_Handle) &connect;

	if ((cefnetd_sock < 0) || name_len < 1 || !name)
		return;

	connect.sock = cefnetd_sock;
	cef_client_prefix_reg (fhdl, operation, name, name_len);
}

static void
conpubd_appreg_entry(
	int	sock,
	CefT_Cpubcnt_Hdl *entry
) {
	if ((sock < 0) || !entry)
		return;

	conpubd_appreg_api (sock, CefC_T_OPT_APP_REG, entry->name, entry->name_len);
}

static void
conpubd_unreg_entry(
	int	sock,
	CefT_Cpubcnt_Hdl *entry
) {
	if ((sock < 0) || !entry)
		return;

	conpubd_appreg_api (sock, CefC_T_OPT_APP_DEREG, entry->name, entry->name_len);
}

/*--------------------------------------------------------------------------------------
	function for processing the expire check
----------------------------------------------------------------------------------------*/
#define	CefC_T_Expire_Delay		3			//	The timelag between expiration and deletion.
static	uint64_t expire_check_time;
static void*
conpubd_expire_check_thread (
	void* arg
) {

	CefT_Conpubd_Handle* hdl = (CefT_Conpubd_Handle*) arg;
	uint64_t interval = (uint64_t) hdl->purge_interval;
	uint64_t nowt = cef_client_present_timeus_calc ();
	uint64_t nowtsec = nowt / 1000000llu;

	expire_check_time = nowt + interval;

	while (conpubd_running_f) {
		sleep (1);
		cef_log_flush();
		nowt = cef_client_present_timeus_calc ();
		nowtsec = nowt / 1000000llu;
		/* Checks content expire 			*/
		if ((interval != 0) && (nowt > expire_check_time)) {
			{
				CefT_Cpubcnt_Hdl* bwk;
				CefT_Cpubcnt_Hdl* wk;

				pthread_mutex_lock (&conpub_cnt_mutex);
				bwk = &Cpubcnthdl;
				wk = Cpubcnthdl.next;
				while (wk) {
					char uri[CefC_NAME_MAXLEN];

					if (wk->expiry < (time_t)nowtsec) {
#ifdef	CefC_T_Expire_Delay
			/*-------------------------------------------------------*
				First, immediately execute APP_DEREG and
				then execute content_delete after T_Expire_Delay.
			 *-------------------------------------------------------*/
						conpubd_unreg_entry(hdl->cefnetd_sock, wk);	/* CefC_T_OPT_APP_DEREG */
					}
					if ((wk->expiry + CefC_T_Expire_Delay) < (time_t)nowtsec) {
#endif	// CefC_T_Expire_Delay
						cef_frame_conversion_name_to_uri (wk->name, wk->name_len, uri);
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) Delete the expired content = %s\n",
		__func__, __LINE__, uri);
#endif // CefC_Debug
						cef_log_write (CefC_Log_Info, "Deleted(expired) %s \n", uri);
						if (conpubd_publish_content_delete (hdl, wk) != 0) {
							;
						}
						bwk->next = wk->next;
						free (wk);
						wk = bwk;
						wk = wk->next;
					} else {
						bwk = wk;
						wk = wk->next;
					}
				}
				pthread_mutex_unlock (&conpub_cnt_mutex);
			}
			/* set interval */
			expire_check_time = nowt + interval;
		}
	}

	pthread_exit (NULL);

	return ((void*) NULL);
}
/*--------------------------------------------------------------------------------------
	Get frame from received message
----------------------------------------------------------------------------------------*/
typedef struct {
	CefT_Conpubd_Handle* hdl;

	unsigned char name[CefC_NAME_MAXLEN];
	uint16_t name_len;

	char filepath[PATH_MAX];

	char pubkey_path[PATH_MAX];		// for UCINC
	uint64_t t_pending;				// for UCINC

	uint64_t expiry;
} ConpubRegisterJob;

typedef struct ConpubDelJob {
	CefT_Conpubd_Handle* hdl;
	int sock;
	unsigned char name[CefC_NAME_MAXLEN];
	uint16_t name_len;
	char uri[CefC_NAME_MAXLEN];
	struct ConpubDelJob* next;
} ConpubDelJob;

static void
conpubd_start_cont_recv_thread (
	CefT_Conpubd_Handle* hdl,
	int sock,
	uint8_t msg_type,
	unsigned char* msg,
	int msg_len,
	unsigned char* payload,
	int payload_len
);

static void* conpubd_register_job_execute(ConpubRegisterJob* job);
static void* conpubd_cont_recv_thread ( void* arg );

static int							/* The return value is negative if an error occurs	*/
conpub_input_bytes_process (
	CefT_Conpubd_Handle* hdl,				/* conpub daemon handle						*/
	int peer_fd, 							/* Peer fd									*/
	unsigned char* buff,					/* receive message							*/
	int buff_len							/* message length							*/
) {
	int index = 0;
	uint16_t len;
	uint16_t value16;
	int rec_buff_len = buff_len;

	while (buff_len >= CefC_Csmgr_Msg_HeaderLen) {

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
		if (len > buff_len)
			break;

		uint8_t type = buff[index + CefC_O_Fix_Type];
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "%s(%d) peer_fd=%d, type=0x%02x, len=%d\n", __func__, __LINE__, peer_fd, type, len);
#endif // CefC_Debug
		if (type == CefC_Csmgr_Msg_Type_CnpbCntAdd
#ifdef	CefC_Csmgr_Msg_Type_CnpbUcincAdd
			|| type == CefC_Csmgr_Msg_Type_CnpbUcincAdd
#endif	// CefC_Csmgr_Msg_Type_CnpbUcincAdd
				) {

			unsigned char* msg_body =
				&buff[index + CefC_Csmgr_Msg_HeaderLen];
			int msg_len =
				len - CefC_Csmgr_Msg_HeaderLen;

			unsigned char* rest =
				&buff[index + len];
			int rest_len =
				buff_len - len;

			/* wakeup cont_add / ucinc_add receive thread */
			conpubd_start_cont_recv_thread(
				hdl,
				peer_fd,
				buff[index + CefC_O_Fix_Type],
				msg_body,
				msg_len,
				rest,
				rest_len
			);

			return -1;
		}

		conpubd_input_message_process(
			hdl,
			peer_fd,
			&buff[index + CefC_Csmgr_Msg_HeaderLen],
			len - CefC_Csmgr_Msg_HeaderLen,
			buff[index + CefC_O_Fix_Type]
		);

		buff_len -= len;
		index += len;
	}

	if (index < rec_buff_len) {
		memmove (&buff[0], &buff[index], buff_len);
	}
	return (buff_len);
}
/*--------------------------------------------------------------------------------------
	Create local socket
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
conpubd_local_sock_create (
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

	len = strlen (conpub_local_sock_name);
	if (len == 0) {
		close (sock);
		return (-1);
	}
	{
		struct stat st;
		if (stat(conpub_local_sock_name, &st) == 0) {
#ifdef	CefC_Debug
conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) Cannot double boot conpubd, Local socket file (%s) exists.\n",
		__func__, __LINE__, conpub_local_sock_name);
#endif // CefC_Debug
			cef_log_write (CefC_Log_Error,
				"Cannot double boot conpubd, Local socket file (%s) exists.\n", conpub_local_sock_name);
			close (sock);
			duplicate_flag = 1;
			return (-1);
		}
	}
	strcpy (saddr.sun_path, conpub_local_sock_name);
	unlink (conpub_local_sock_name);

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
conpubd_local_sock_check (
	CefT_Conpubd_Handle* hdl				/* conpub daemon handle						*/
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
	Destroy conpub daemon handle
----------------------------------------------------------------------------------------*/
static void
conpubd_handle_destroy (
	CefT_Conpubd_Handle** conpubd_hdl		/* conpub daemon handle						*/
) {
	CefT_Conpubd_Handle* hdl = *conpubd_hdl;
	int i;

	/* Check handle */
	if (hdl == NULL) {
		/* Unlink local sock */
		if (duplicate_flag == 0) {
			if (strlen (conpub_local_sock_name) != 0) {
				unlink (conpub_local_sock_name);
			}
		}
		return;
	}

	CefT_Cpubcnt_Hdl* bwk;
	CefT_Cpubcnt_Hdl* wk;
	bwk = &Cpubcnthdl;
	wk = Cpubcnthdl.next;
	while (wk) {
#ifdef CefC_Debug
char uri[CefC_NAME_MAXLEN];
cef_frame_conversion_name_to_uri (wk->name, wk->name_len, uri);
conpubd_dbg_write (CefC_Dbg_Finer, "%s(%d) Delete the expired content = %s\n",
		__func__, __LINE__, uri);
#endif // CefC_Debug
			if (conpubd_publish_content_delete (hdl, wk) != 0) {
				;
			}
		bwk->next = wk->next;
		free (wk);
		wk = bwk;
		wk = wk->next;
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

		for (i = 1 ; i < ConpubdC_Max_Sock_Num ; i++) {
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

	/* Close library */
	if (hdl->cs_mod_int != NULL) {
		/* Destroy plugin */
		if (hdl->cs_mod_int->destroy != NULL) {
			hdl->cs_mod_int->destroy ();
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

	free (hdl);
	*conpubd_hdl = NULL;

	conpubd_stat_handle_destroy (stat_hdl);

	conpubd_destroy ();

	/* Destroy work areas */
	if (Cob_prames_p != NULL) {
		free (Cob_prames_p);
	}
	if (Cob_msg_p != NULL) {
		free (Cob_msg_p);
	}
	if (Name_buff_p != NULL) {
		free (Name_buff_p);
	}
	if (Uri_buff_p != NULL) {
		free (Uri_buff_p);
	}
	if (Stat_p != NULL) {
		free (Stat_p);
	}
	/* Unlink local sock */
	if (duplicate_flag == 0) {
		if (strlen (conpub_local_sock_name) != 0) {
			unlink (conpub_local_sock_name);
		}
	}

	return;
}
/*--------------------------------------------------------------------------------------
	Read config file
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
conpubd_config_read (
	ConpubT_Config_Param* conf_param				/* parameter of config				*/
) {
	FILE*	fp = NULL;								/* file pointer						*/
	char	file_name[PATH_MAX];					/* file name						*/
	char	param[BUFSIZ_4K] = {0};					/* parameter						*/
	char	param_buff[BUFSIZ_4K] = {0};			/* param buff						*/
	int		len;									/* read length						*/
	char*	option;									/* deny option						*/
	char*	value;									/* parameter						*/
	int		i, n;
	int64_t	res;
	int		app_fib_max_size;

	/* Obtains the directory path where the conpubd's config file is located. */
#if 0 //+++++ GCC v9 +++++
	sprintf (file_name, "%s/%s", conpub_conf_dir, CefC_Conpub_Conf_Name);
#else
	int rc;
	rc = snprintf (file_name, sizeof(file_name), "%s/%s", conpub_conf_dir, CefC_Conpub_Conf_Name);
	if (rc < 0){
		cef_log_write (CefC_Log_Error, "Config file dir path too long(%s)\n", conpub_conf_dir);
		return (-1);
	}
#endif //----- GCC v9 -----

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "conpubd config path = %s\n", file_name);
#endif // CefC_Debug

	/* Opens the conpub's config file. */
	fp = fopen (file_name, "r");
	if (fp == NULL) {
		cef_log_write (CefC_Log_Error, "%s\n", strerror (errno));
		return (-1);
	}

	/* Set default value */
	conf_param->port_num			= CefC_CnpbDefault_Tcp_Prot;
	strcpy(conf_param->local_sock_id, CefC_CnpbDefault_Local_Sock_Id);
	strcpy(conf_param->cache_type, 	  CefC_Cnpb_filesystem_Cache_Type);
	strcpy(conf_param->cache_path, 	  conpub_conf_dir);
	conf_param->purge_interval		= CefC_CnpbDefault_Purge_Interval;;
	conf_param->cache_default_rct	= CefC_CnpbDefault_Cache_Default_Rct;
	strcpy(conf_param->Valid_Alg,     CefC_CnpbDefault_Valid_Alg);
	conf_param->contents_num		= CefC_CnpbDefault_Contents_num;
	conf_param->contents_capacity	= CefC_CnpbDefault_Contents_Capacity;
	conf_param->block_size			= CefC_CnpbDefault_Block_Size;
	strcpy(conf_param->cefnetd_node,  CefC_CnpbDefault_Node_Path);
	conf_param->cefnetd_port		= CefC_CnpbDefault_Cefnetd_Port;
	conf_param->t_pending			= CefC_CnpbDefault_Pending_Timer;
	memset (conf_param->publisher_id, 0x00, SHA512_DIGEST_LENGTH);

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
		if (strcmp (option, "PORT_NUM") == 0) {
			res = conpubd_config_value_get (option, value);
			if ((res < 1025) || (res > 65535)) {
				cef_log_write (CefC_Log_Error,
					"PORT_NUM must be higher than 1024 and lower than 65536.\n");
				fclose (fp);
				return (-1);
			}
			conf_param->port_num = res;
			cef_log_fopen (res);
		} else
		if (strcmp (option, CefC_ParamName_LocalSockId) == 0) {
			if (strlen (value) > CefC_LOCAL_SOCK_ID_SIZ) {
				cef_log_write (CefC_Log_Error,
					"%s must be less than or equal to %d.\n",
						CefC_ParamName_LocalSockId, CefC_LOCAL_SOCK_ID_SIZ);
				fclose (fp);
				return (-1);
			}
			strcpy (conf_param->local_sock_id, value);
		} else
		if (strcmp (option, "CACHE_TYPE") == 0) {
			if (strcmp (value, CefC_Cnpb_memory_Cache_Type) != 0
					&&
			    strcmp (value, CefC_Cnpb_filesystem_Cache_Type) != 0
			    ) {
				cef_log_write (CefC_Log_Error,
					"CACHE_TYPE is invalid. (Invalid value %s=%s)\n", option, value);
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine,
					"CACHE_TYPE is invalid. (Invalid value %s=%s)\n", option, value);
#endif // CefC_Debug
				fclose (fp);
				return (-1);
			}
			strcpy (conf_param->cache_type, value);
		} else
		if (strcmp (option, "CACHE_PATH") == 0) {
			res = strlen (value);
			if (res > CefC_Csmgr_File_Path_Length) {
				cef_log_write (CefC_Log_Error,
					"EXCACHE_PLUGIN (Invalid value %s=%s)\n", option, value);
				fclose (fp);
				return (-1);
			}
			strcpy (conf_param->cache_path, value);
		} else
		if (strcmp (option, "PURGE_INTERVAL") == 0) {
			res = conpubd_config_value_get (option, value);
			if (!(60 <= res && res < 86400)) {
				cef_log_write (CefC_Log_Error,
					"PURGE_INTERVAL value must be greater than or equal to 60 "
					"and less than 86400 (24 hours).\n");
				fclose (fp);
				return (-1);
			}
			conf_param->purge_interval = res;
		} else
		if (strcmp (option, "CACHE_DEFAULT_RCT") == 0) {
			res = conpubd_config_value_get (option, value);
			if (!(1 < res && res < 3600)) {
				cef_log_write (CefC_Log_Error,
					"CACHE_DEFAULT_RCT value must be higher than 1 and lower than 3600 (secs).\n");
				fclose (fp);
				return (-1);
			}
			conf_param->cache_default_rct = res;
		} else
		if (strcmp (option, "VALID_ALG") == 0) {
			if (strcmp (value, CefC_CnpbDefault_Valid_Alg) != 0 /* NONE */
					&&
				strcmp (value, CefC_ValidTypeStr_RSA256) != 0
					&&
				strcmp (value, CefC_ValidTypeStr_CRC32C) != 0
			) {
				cef_log_write (CefC_Log_Error,
					"VALID_ALG must be \"NONE\", \"%s\" or \"%s\" "
					"(Invalid value %s=%s)\n", CefC_ValidTypeStr_CRC32C, CefC_ValidTypeStr_RSA256, option, value);
				fclose (fp);
				return (-1);
			}
			strcpy (conf_param->Valid_Alg, value);
		} else
		if (strcmp (option, "CONTENTS_NUM") == 0) {
			res = conpubd_config_value_get (option, value);
			if (!(1 <= res && res <= 1000000)) {
				cef_log_write (CefC_Log_Error,
				"CONTENTS_NUM value must be greater than or equal to 1 "
				"and less than or equal to 1000000.\n");
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine,
					"CONTENTS_NUM value must be greater than or equal to 1 "
					"and less than or equal to 1000000.\n");
#endif // CefC_Debug
				fclose (fp);
				return (-1);
			}
			conf_param->contents_num = res;
		} else
		if (strcmp (option, "CONTENTS_CAPACITY") == 0) {
			char *endptr = "";
			conf_param->contents_capacity = strtoul (value, &endptr, 0);
			if (strcmp (endptr, "") != 0) {
				cef_log_write (
					CefC_Log_Error, "[%s] Invalid value %s=%s\n", __func__, option, value);
				fclose (fp);
				return (-1);
			}
			if (!(1 <= conf_param->contents_capacity
					&&
				  conf_param->contents_capacity <= 0xFFFFFFFFF)) {
				cef_log_write (CefC_Log_Error,
				"CONTENTS_CAPACITY value must be greater than  or equal to 1 "
				"and less than or equal to 68,719,476,735(0xFFFFFFFFF).\n");
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine,
					"CONTENTS_CAPACITY value must be greater than  or equal to 1 "
					"and less than or equal to 68,719,476,735(0xFFFFFFFFF).\n");
#endif // CefC_Debug
				fclose (fp);
				return (-1);
			}
		} else
		if (strcmp (option, "BLOCK_SIZE") == 0) {
			res = conpubd_config_value_get (option, value);
			if (!(CefC_Min_Block <= res && res <= CefC_Max_Block)) {
				cef_log_write (CefC_Log_Error,
					"BLOCK_SIZE="FMTU64" is out of range, must be greater than or equal to %d "
					"and less than or equal to %d.\n", res, CefC_Min_Block, CefC_Max_Block);
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine,
					"BLOCK_SIZE="FMTU64" is out of range, must be greater than or equal to %d "
					"and less than or equal to %d.\n", res, CefC_Min_Block, CefC_Max_Block);
#endif // CefC_Debug
				fclose (fp);
				return (-1);
			}
			conf_param->block_size = res;
		} else
		if (strcmp (option, "CEFNETD_NODE") == 0) {
			if (strlen (value) > sizeof (conf_param->cefnetd_node)-1) {
				cef_log_write (CefC_Log_Error,
					"CEFNETD_NODE must be less than or equal to 128.\n");
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine,
					"CEFNETD_NODE must be less than or equal to 128.\n");
#endif // CefC_Debug
				fclose (fp);
				return (-1);
			}
			strcpy (conf_param->cefnetd_node, value);
		} else
		if (strcmp (option, "CEFNETD_PORT_NUM") == 0) {
			res = conpubd_config_value_get (option, value);
			if ((res < 1025) || (res > 65535)) {
				cef_log_write (CefC_Log_Error,
					"CEFNETD_PORT_NUM must be higher than 1024 and lower than 65536.\n");
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine,
					"CEFNETD_PORT_NUM must be higher than 1024 and lower than 65536.\n");
#endif // CefC_Debug
				fclose (fp);
				return (-1);
			}
			conf_param->cefnetd_port = res;
		} else
		if (strcmp (option, "UCINC_PENDING_TIMER") == 0) {
			res = conpubd_config_value_get (option, value);
			if ((res < CefC_CnpbMin_Pending_Timer) || (res > CefC_CnpbMax_Pending_Timer)) {
				cef_log_write (CefC_Log_Error,
					"UCINC_PENDING_TIMER must be higher than %d and lower than %d.\n", CefC_CnpbMin_Pending_Timer, CefC_CnpbMax_Pending_Timer);
				fclose (fp);
				return (-1);
			}
			conf_param->t_pending = res;
		} else
		if (strcmp (option, "PUBLISHER_ID") == 0) {
			conpubd_str2byte (value, conf_param->publisher_id, SHA512_DIGEST_LENGTH);
		} else {
			continue;
		}
	}
	sprintf (conpub_local_sock_name,
		"/tmp/conpub_%d.%s", conf_param->port_num, conf_param->local_sock_id);

	fclose (fp);

	if (strcmp (conf_param->cache_type, CefC_Cnpb_filesystem_Cache_Type) == 0) {
		if (!(    access (conf_param->cache_path, F_OK) == 0
		   && access (conf_param->cache_path, R_OK) == 0
   		   && access (conf_param->cache_path, W_OK) == 0
   		   && access (conf_param->cache_path, X_OK) == 0)) {
			cef_log_write (CefC_Log_Error,
				"EXCACHE_PLUGIN (Invalid value CACHE_PATH=%s) - %s\n", conf_param->cache_path, strerror (errno));
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine,
					"EXCACHE_PLUGIN (Invalid value CACHE_PATH=%s) - %s\n", conf_param->cache_path, strerror (errno));
#endif // CefC_Debug
			return (-1);
	    }
	}


#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "conf_param->port_num=%d\n", conf_param->port_num);
	cef_dbg_write (CefC_Dbg_Fine, "conf_param->local_sock_id=%s\n", conf_param->local_sock_id);
	cef_dbg_write (CefC_Dbg_Fine, "conf_param->cache_type=%s\n", conf_param->cache_type);
	cef_dbg_write (CefC_Dbg_Fine, "conf_param->cache_path=%s\n", conf_param->cache_path);
	cef_dbg_write (CefC_Dbg_Fine, "conf_param->purge_interval=%u\n", conf_param->purge_interval);
	cef_dbg_write (CefC_Dbg_Fine, "conf_param->cache_default_rct=%u\n", conf_param->cache_default_rct);
	cef_dbg_write (CefC_Dbg_Fine, "conf_param->Valid_Alg=%s\n", conf_param->Valid_Alg);
	cef_dbg_write (CefC_Dbg_Fine, "conf_param->contents_num=%d\n", conf_param->contents_num);
	cef_dbg_write (CefC_Dbg_Fine, "conf_param->contents_capacity="FMTU64"\n", conf_param->contents_capacity);
	cef_dbg_write (CefC_Dbg_Fine, "conf_param->block_size=%d\n", conf_param->block_size);
	cef_dbg_write (CefC_Dbg_Fine, "conf_param->cefnetd_node=%s\n", conf_param->cefnetd_node);
	cef_dbg_write (CefC_Dbg_Fine, "conf_param->cefnetd_port=%d\n", conf_param->cefnetd_port);
	cef_dbg_write (CefC_Dbg_Fine, "conf_param->t_pending=%d\n", conf_param->t_pending);
	cef_dbg_write (CefC_Dbg_Fine, "conf_param->publisher_id=0x%02hhx, 0x%02hhx, 0x%02hhx, 0x%02hhx... 0x%02hhx\n",
		conf_param->publisher_id[0], conf_param->publisher_id[1], conf_param->publisher_id[2], conf_param->publisher_id[3],
		conf_param->publisher_id[SHA512_DIGEST_LENGTH-1]);
#endif // CefC_Debug

	/* Check FIB_SIZE_APP setting in the cefnetd.conf */
	{
		char 	wconfig_dir[PATH_MAX];
		char 	wconfig_path[PATH_MAX];
		int		rc;
		app_fib_max_size = CefC_Default_FibAppSize;
		cef_client_config_dir_get (wconfig_dir);
		rc = snprintf (wconfig_path, sizeof(wconfig_path), "%s/cefnetd.conf", wconfig_dir);
		if (rc < 0) {
			cef_log_write (CefC_Log_Error, "Config file dir path too long(%s)\n", wconfig_dir);
			return (-1);
		}
		fp = fopen (wconfig_path, "r");
	}
	if (fp == NULL) {
		cef_log_write (CefC_Log_Error, "%s\n", strerror (errno));
		return (-1);
	}
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
		if (strcasecmp (option, CefC_ParamName_FibSize_App) == 0) {
			res = conpubd_config_value_get (option, value);
			if ( res < 1 ) {
				cef_log_write (CefC_Log_Warn, "FIB_SIZE_APP must be higher than 0.\n");
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine,
					"FIB_SIZE_APP must be higher than 0.\n");
#endif // CefC_Debug
				fclose (fp);
				return (-1);
			}
			if (res >= CefC_FibAppSize_MAX) {
				cef_log_write (CefC_Log_Warn, "FIB_SIZE_APP must be lower than 1024000.\n");
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine,
					"FIB_SIZE_APP must be lower than 1024000.\n");
#endif // CefC_Debug
				fclose (fp);
				return (-1);
			}
			app_fib_max_size = res;
		}
		else {
			/* NOP */;
		}
	}
	fclose (fp);
	if (app_fib_max_size < conf_param->contents_num) {
		cef_log_write (CefC_Log_Warn,
			"FIB_SIZE_APP setting in the cefnetd.conf must be greater than or equal to CONTENTS_NUM setting.\n"
			"	(FIB_SIZE_APP=%d, CONTENTS_NUM=%d)\n",
			app_fib_max_size, conf_param->contents_num);
	}

	return (0);
}
/*--------------------------------------------------------------------------------------
	Change str to value
----------------------------------------------------------------------------------------*/
static int64_t						/* The return value is negative if an error occurs	*/
conpubd_config_value_get (
	char* option,								/* conpubd option						*/
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
	if (res > INT64_MAX) {
		return (-1);
	}
	return (res);
}
/*--------------------------------------------------------------------------------------
	Load plugin
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
conpubd_plugin_load (
	CefT_Conpubd_Handle* hdl					/* conpub daemon handle					*/
) {
	int (*func)(ConpubdT_Plugin_Interface*, const char*);
	char func_name[256] = {0};

	/* Open library */
	hdl->mod_lib = dlopen (ConpubdC_Plugin_Library_Name, RTLD_LAZY);
	if (hdl->mod_lib == NULL) {
		cef_log_write (CefC_Log_Error, "%s\n", dlerror ());
		return (-1);
	}

	/* Load plugin */
	sprintf (func_name, "conpubd_%s_plugin_load", hdl->cache_type);
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
	if ((func) (hdl->cs_mod_int, conpub_conf_dir) != 0) {
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
conpubd_plugin_check (
	CefT_Conpubd_Handle* hdl					/* conpub daemon handle					*/
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
	Sets the path of conpubd.conf
----------------------------------------------------------------------------------------*/
static int
conpubd_plugin_config_dir_set (
	const char* config_file_dir
) {
	FILE* 	fp;
	char 	file_path[PATH_MAX];
	char*	wp;

	if (config_file_dir[0] != 0x00) {
#if 0 //+++++ GCC v9 +++++
		sprintf (file_path, "%s/conpubd.conf", config_file_dir);
#else
		int rc;
		rc = snprintf (file_path, sizeof(file_path), "%s/conpubd.conf", config_file_dir);
		if (rc < 0) {
			cef_log_write (CefC_Log_Error, "Config file dir path too long(%s)\n", config_file_dir);
			return (-1);
		}
#endif //----- GCC v9 -----
		strcpy (conpub_conf_dir, config_file_dir);
	} else {
		wp = getenv (CefC_CEFORE_DIR);
		if (wp != NULL && wp[0] != 0) {
			sprintf (file_path, "%s/cefore/conpubd.conf", wp);
			sprintf (conpub_conf_dir, "%s/cefore", wp);
		} else {
			sprintf (file_path, "%s/conpubd.conf", CefC_CEFORE_DIR_DEF);
			strcpy (conpub_conf_dir, CefC_CEFORE_DIR_DEF);
		}
	}

	fp = fopen (file_path, "r");
	if (fp == NULL) {
		cef_log_write (CefC_Log_Error, "Failed to open %s\n", file_path);
		return (-1);
	}
	fclose (fp);
	cef_log_write (CefC_Log_Info, "Config directory is %s.\n", conpub_conf_dir);

	return (1);
}
/*--------------------------------------------------------------------------------------
	Sets the path of conpubcont.def
----------------------------------------------------------------------------------------*/
static int
conpubd_contdef_dir_set (
	const char* contdef_file_dir
) {
	FILE* 	fp;
	char 	file_path[PATH_MAX];
	char*	wp;

	if (contdef_file_dir[0] != 0x00) {
#if 0 //+++++ GCC v9 +++++
		sprintf (file_path, "%s/conpubcont.def", contdef_file_dir);
#else
		int rc;
		rc = snprintf (file_path, sizeof(file_path), "%s/conpubcont.def", contdef_file_dir);

		if (rc < 0) {
			cef_log_write (CefC_Log_Error, "conpubcont.def dir path too long(%s)\n", contdef_file_dir);
			return (-1);
		}
#endif //----- GCC v9 -----
		strcpy (conpub_contdef_dir, contdef_file_dir);
	} else {
		wp = getenv (CefC_CEFORE_DIR);
		if (wp != NULL && wp[0] != 0) {
			sprintf (file_path, "%s/cefore/conpubcont.def", wp);
			sprintf (conpub_contdef_dir, "%s/cefore", wp);
		} else {
			sprintf (file_path, "%s/conpubcont.def", CefC_CEFORE_DIR_DEF);
			strcpy (conpub_contdef_dir, CefC_CEFORE_DIR_DEF);
		}
	}

	fp = fopen (file_path, "r");
	if (fp == NULL) {
		cef_log_write (CefC_Log_Error, "Failed to open %s\n", file_path);
		return (-1);
	}
	fclose (fp);
	cef_log_write (CefC_Log_Info, "Contents defintion directory is %s.\n", conpub_contdef_dir);

	return (1);
}

/*--------------------------------------------------------------------------------------
	Search free tcp socket index
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
conpubd_free_sock_index_search (
	CefT_Conpubd_Handle* hdl					/* conpub daemon handle					*/
) {
	int i;
	for (i = 1 ; i < ConpubdC_Max_Sock_Num; i++) {
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
conpubd_tcp_sock_create (
	CefT_Conpubd_Handle* hdl,				/* conpub daemon handle						*/
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
{
		int optval = 1;
		if (setsockopt (sock, SOL_SOCKET, SO_REUSEPORT, (const char *)&optval, sizeof (optval)) < 0) {
			cef_log_write (CefC_Log_Error, "[%s] (setsockopt:%s)\n", __func__, strerror (errno));
			close (sock);
			continue;
		}
}

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
		if (listen (hdl->tcp_listen_fd, ConpubdC_Max_Sock_Num) < 0) {
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
conpubd_tcp_connect_accept (
	CefT_Conpubd_Handle* hdl				/* conpub daemon handle						*/
) {
	struct sockaddr_storage  sa;
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
	for (i = 1 ; i < ConpubdC_Max_Sock_Num ; i++) {
		if ((strcmp (hdl->peer_id_str[i], ip_str) == 0) &&
			(strcmp (hdl->peer_sv_str[i], port_str) == 0)) {
			cef_log_write (CefC_Log_Info, "Close TCP peer: [%d] %s:%s\n",
				i, hdl->peer_id_str[i], hdl->peer_sv_str[i]);
			close (hdl->tcp_fds[i]);
			hdl->tcp_fds[i] 	= -1;
			hdl->tcp_index[i] 	= 0;
			new_accept_f = 0;
			break;
		}
	}

	/* Records the new accepted socket 		*/
	if (new_accept_f) {
		i = conpubd_free_sock_index_search (hdl);

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
conpubd_poll_socket_prepare (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
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

	for (i = 1 ; i < ConpubdC_Max_Sock_Num ; i++) {
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
typedef struct {
	CefT_Conpubd_Handle* hdl;
	int peer_fd;

	uint8_t msg_type;

	unsigned char recv_name[CefC_NAME_MAXLEN];
	uint16_t recv_name_len;

	uint64_t file_size;

	/* ucinc 用 */
	uint64_t recv_expiry;
	uint64_t recv_t_pending;
	uint16_t recv_pubkey_len;
	unsigned char* recv_pubkey;

	unsigned char* recv_payload;
	uint64_t recv_payload_len;
} ConpubRecvJob;

static int							/* The return value is negative if an error occurs	*/
conpubd_input_message_process (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* msg,							/* receive message						*/
	int msg_len,								/* message length						*/
	uint8_t type								/* message type							*/
) {
#ifdef CefC_Debug
cef_dbg_write (CefC_Dbg_Finer, "%s(%d) sock=%d, type=0x%02x, msg_len=%d\n", __func__, __LINE__, sock, type, msg_len);
#endif // CefC_Debug

	switch (type) {

		case CefC_Csmgr_Msg_Type_Ccninfo: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Ccninfo Message\n");
#endif // CefC_Debug
			conpubd_incoming_ccninfo_msg (hdl, sock, msg, msg_len);
			break;
		}

#if 0 /* Don't delete for future */
		case CefC_Csmgr_Msg_Type_Status: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Get Status Message\n");
#endif // CefC_Debug
			conpubd_incoming_status_msg (hdl, sock, msg, msg_len);
			break;
		}
#endif
		case CefC_Csmgr_Msg_Type_Increment: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest,
				"Receive the Increment Access Count Message\n");
#endif // CefC_Debug
			conpubd_incoming_increment_msg (hdl, msg, msg_len);
			break;
		}
		case CefC_Csmgr_Msg_Type_Kill: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Receive the Kill Command\n");
#endif // CefC_Debug
			if ((memcmp (msg, root_user_name, CefC_Csmgr_User_Len) == 0) ||
				(memcmp (msg, hdl->launched_user_name, CefC_Csmgr_User_Len) == 0)) {
				conpubd_running_f = 0;
				cef_log_write (CefC_Log_Info, "conpubdstop from %s\n", msg);
				return (-1);
			} else {
				cef_log_write (CefC_Log_Info,
					"Permission denied (conpubdstop from %s)\n", msg);
			}
			break;
		}
		case CefC_Csmgr_Msg_Type_CnpbStatus: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Get Conpub Status Message\n");
#endif // CefC_Debug
			conpubd_incoming_cnpbstatus_msg (hdl, sock, msg, msg_len);
			break;
		}
		case CefC_Csmgr_Msg_Type_CnpbRload: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Reload Conpub Contents Message\n");
#endif // CefC_Debug
			conpubd_incoming_cnpbrload_msg (hdl, sock, msg, msg_len);
			break;
		}
		case CefC_Csmgr_Msg_Type_CnpbCntDel: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Conpub Contents Delete Message\n");
#endif // CefC_Debug
			conpubd_incoming_cont_del_msg (hdl, sock, msg, msg_len);
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

#if 0 /* Don't delete for future */
/*--------------------------------------------------------------------------------------
	Incoming Get Status Message
----------------------------------------------------------------------------------------*/
static void
conpubd_incoming_status_msg (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
) {
	int res, i;
	uint64_t nowt;
	struct timeval tv;
	unsigned char *wbuf;
	uint32_t wbuf_size;
	unsigned char* key = NULL;
	uint32_t index;
	uint16_t klen;
	uint64_t value64;
	struct CefT_Conpub_Status_Hdr stat_hdr;
	struct CefT_Conpub_Status_Rep stat_rep;
	uint32_t value32;
	struct pollfd fds[1];
	uint32_t 		con_num = 0;

	wbuf = calloc (1, CefC_Csmgr_Stat_Mtu);
	if (wbuf == NULL) {
		return;
	}
	wbuf_size = CefC_Csmgr_Stat_Mtu;

	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;

	/* Obtain parameters from request message 		*/
	klen = buff_len - 1;
	if ((buff[0]) && (klen > 0)) {
		key = &buff[1];
	}

	/* Creates the response 		*/
	wbuf[CefC_O_Fix_Ver]  = CefC_Version;
	wbuf[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_Status;
	index = CefC_Csmgr_Msg_HeaderLen + 2; /*** Added 2 bytes to extend the total frame length to 4 bytes ***/

	index += sizeof (struct CefT_Conpub_Status_Hdr);

	if (buff[0]) {
		res = conpubd_stat_content_info_gets (stat_hdl, key, klen, 1, Stat_p);
		for (i = 0 ; i < res ; i++) {
			if (index+Stat_p[i]->name_len+sizeof (struct CefT_Conpub_Status_Rep) > wbuf_size) {
				void *new = realloc (wbuf, wbuf_size+CefC_Csmgr_Stat_Mtu);
				if (new == NULL) {
					free (wbuf);
					return;
				}
				wbuf = new;
				wbuf_size += CefC_Csmgr_Stat_Mtu;
			}
			con_num ++;
			stat_rep.name_len 	= htons (Stat_p[i]->name_len);
			stat_rep.con_size 	= cef_client_htonb (Stat_p[i]->con_size);
			stat_rep.access 	= cef_client_htonb (Stat_p[i]->access);

			value64 = (Stat_p[i]->expiry - nowt) / 1000000;
			stat_rep.freshness = cef_client_htonb (value64);

			value64 = (nowt - Stat_p[i]->cached_time) / 1000000;
			stat_rep.elapsed_time 	= cef_client_htonb (value64);

			memcpy (&wbuf[index], &stat_rep, sizeof (struct CefT_Conpub_Status_Rep));
			index += sizeof (struct CefT_Conpub_Status_Rep);
			memcpy (&wbuf[index], Stat_p[i]->name, Stat_p[i]->name_len);
			index += Stat_p[i]->name_len;
		}
	}
	stat_hdr.node_num = htons ((uint16_t) hdl->peer_num);
	stat_hdr.con_num  = htonl (con_num);
	memcpy (&wbuf[CefC_Csmgr_Msg_HeaderLen + 2/* To extend length from 2 bytes to 4 bytes */], &stat_hdr, sizeof (struct CefT_Conpub_Status_Hdr));

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
}
#endif /* Don't delete for future */

/*--------------------------------------------------------------------------------------
	Incoming Ccninfo Message
----------------------------------------------------------------------------------------*/
static void
conpubd_incoming_ccninfo_msg (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
) {
	int res, i;
	uint64_t nowt;
	struct timeval tv;
	unsigned char* key;
	uint16_t index = 0;
	uint16_t rec_index;
	uint8_t  partial_match_f;
	uint16_t klen;
	struct ccninfo_rep_block rep_blk;
	struct tlv_hdr rply_tlv_hdr;
	struct tlv_hdr name_tlv_hdr;
	uint64_t value64;

	name_tlv_hdr.type = htons (CefC_T_NAME);
	gettimeofday (&tv, NULL);
	nowt = tv.tv_sec * 1000000llu + tv.tv_usec;

	/* Obtain parameters from request message 		*/
	partial_match_f = buff[0];
	klen = buff_len - 1;
	key = &buff[1];

	/* Obtain cached content information 			*/
	res = conpubd_stat_content_info_gets (
			stat_hdl, key, klen, (int) partial_match_f, Stat_p);
	for (i = 0 ; i < res ; i++) {

		rec_index = index;
		index += CefC_S_TLF;

		if (Stat_p[i]->con_size / 1024 > UINT32_MAX) {
			rep_blk.cont_size 	= htonl (UINT32_MAX);
		} else {
			rep_blk.cont_size 	= htonl ((uint32_t) (Stat_p[i]->con_size / 1024));
		}
		if (Stat_p[i]->cob_num  > UINT32_MAX) {
			rep_blk.cont_cnt 	= htonl (UINT32_MAX);
		} else {
			rep_blk.cont_cnt 	= htonl ((uint32_t) Stat_p[i]->cob_num);
		}
		if (Stat_p[i]->access  > UINT32_MAX) {
			rep_blk.rcv_int 	= htonl (UINT32_MAX);
		} else {
			rep_blk.rcv_int 	= htonl ((uint32_t) Stat_p[i]->access);
		}
		rep_blk.first_seq 	= htonl (Stat_p[i]->min_seq);
		rep_blk.last_seq 	= htonl (Stat_p[i]->max_seq);

		value64 = (nowt - Stat_p[i]->cached_time) / 1000000;
		rep_blk.cache_time 	= cef_client_htonb (value64);

		value64 = (Stat_p[i]->expiry - nowt) / 1000000;
		rep_blk.remain_time	= cef_client_htonb (value64);

		memcpy (&Cob_msg_p[index], &rep_blk, sizeof (struct ccninfo_rep_block));
		index += sizeof (struct ccninfo_rep_block);

		/* Name 				*/
		name_tlv_hdr.length = htons (Stat_p[i]->name_len);
		memcpy (&Cob_msg_p[index], &name_tlv_hdr, sizeof (struct tlv_hdr));
		memcpy (&Cob_msg_p[index + CefC_S_TLF], Stat_p[i]->name, Stat_p[i]->name_len);
		index += CefC_S_TLF + Stat_p[i]->name_len;

		/* Sets the header of Reply Block 		*/
		rply_tlv_hdr.type = htons (CefC_T_DISC_CONTENT_OWNER);
		rply_tlv_hdr.length = htons (index - (rec_index + CefC_S_TLF));
		memcpy (&Cob_msg_p[rec_index], &rply_tlv_hdr, sizeof (struct tlv_hdr));
	}

	if (index > 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Send the ccninfo response (len = %u).\n", index);
		cef_dbg_buff_write (CefC_Dbg_Finest, Cob_msg_p, index);
#endif // CefC_Debug
		res = cef_csmgr_send_msg (sock, Cob_msg_p, index);
		if (res < 0) {
			/* send error */
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Failed to send the ccninfo response\n");
#endif // CefC_Debug
		}
	} else {
		cef_csmgr_send_msg (sock, Cob_msg_p, CefC_S_TLF);
	}

	return;
}

/*--------------------------------------------------------------------------------------
	Receive Increment Access Count message
----------------------------------------------------------------------------------------*/
static void
conpubd_incoming_increment_msg (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
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
		return;
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
	Receive the Get Conpub Status Message
----------------------------------------------------------------------------------------*/
static void
conpubd_incoming_cnpbstatus_msg (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
) {
	unsigned char *ret_buff;
	uint32_t ret_buff_size;
	uint32_t index = 0;
	struct pollfd fds[1];
	int res;
	CefT_Cpubcnt_Hdl* work;
	struct CefT_Csmgr_CnpbStatus_TL rsp_hdr;
	uint16_t length;
	uint64_t value64;
	uint32_t value32;
	uint64_t nowt;
	uint64_t nowtsec;

	ret_buff = calloc (1, CefC_Max_Length);
	if (ret_buff == NULL) {
		return;
	}
	ret_buff_size = CefC_Max_Length;

	/* Create message */
	/* Set header */
	ret_buff[CefC_O_Fix_Ver]  = CefC_Version;
	ret_buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_CnpbStatus;
	index = CefC_Csmgr_Msg_HeaderLen + 2; /*** Added 2 bytes to extend the total frame length to 4 bytes ***/

	/*--------------------------------------------------------
		Creates a response message
	----------------------------------------------------------*/
	work = Cpubcnthdl.next;
	nowt = cef_client_present_timeus_calc ();
	nowtsec = nowt / 1000000llu;

	while (work) {
		if (work->expiry < (time_t)nowtsec) {
			work = work->next;
			continue;
		}
		length =
			sizeof (struct CefT_Csmgr_CnpbStatus_TL) + work->name_len +
			sizeof (struct CefT_Csmgr_CnpbStatus_TL) + (uint16_t) strlen (work->file_path) +
			sizeof (struct CefT_Csmgr_CnpbStatus_TL) + sizeof (time_t) +
			sizeof (struct CefT_Csmgr_CnpbStatus_TL) + sizeof (time_t) +
			sizeof (struct CefT_Csmgr_CnpbStatus_TL) + sizeof (time_t) +
			sizeof (struct CefT_Csmgr_CnpbStatus_TL) + sizeof (uint32_t);

		if ((index + length) > ret_buff_size) {
			void *new = realloc (ret_buff, ret_buff_size+CefC_Max_Length);
			if (new == NULL) {
				free (ret_buff);
				return;
			}
			ret_buff = new;
			ret_buff_size += CefC_Max_Length;
		}

		/* Sets Name 			*/
		length = (uint16_t) work->name_len;
		rsp_hdr.type   = htons (CefC_CnpbStatus_Name);
		rsp_hdr.length = htons (length);
		memcpy (&ret_buff[index], &rsp_hdr, sizeof (struct CefT_Csmgr_CnpbStatus_TL));
		index += sizeof (struct CefT_Csmgr_CnpbStatus_TL);
		memcpy (&ret_buff[index], work->name, length);
		index += length;

		/* Sets Path 			*/
		length = (uint16_t) strlen (work->file_path);
		rsp_hdr.type   = htons (CefC_CnpbStatus_Path);
		rsp_hdr.length = htons (length);
		memcpy (&ret_buff[index], &rsp_hdr, sizeof (struct CefT_Csmgr_CnpbStatus_TL));
		index += sizeof (struct CefT_Csmgr_CnpbStatus_TL);
		memcpy (&ret_buff[index], work->file_path, length);
		index += length;

		/* Sets Date 			*/
		length = sizeof (time_t);
		value64  = cef_client_htonb (work->date);
		rsp_hdr.type   = htons (CefC_CnpbStatus_Date);
		rsp_hdr.length = htons (length);
		memcpy (&ret_buff[index], &rsp_hdr, sizeof (struct CefT_Csmgr_CnpbStatus_TL));
		index += sizeof (struct CefT_Csmgr_CnpbStatus_TL);
		memcpy (&ret_buff[index], &value64, length);
		index += length;

		/* Sets Expiry 			*/
		length = sizeof (time_t);
		value64  = cef_client_htonb (work->expiry);
		rsp_hdr.type   = htons (CefC_CnpbStatus_Expiry);
		rsp_hdr.length = htons (length);
		memcpy (&ret_buff[index], &rsp_hdr, sizeof (struct CefT_Csmgr_CnpbStatus_TL));
		index += sizeof (struct CefT_Csmgr_CnpbStatus_TL);
		memcpy (&ret_buff[index], &value64, length);
		index += length;

		/* Sets Pending timer 			*/
		length = sizeof (time_t);
		value64  = cef_client_htonb (work->t_pending);
		rsp_hdr.type   = htons (CefC_CnpbStatus_Pending);
		rsp_hdr.length = htons (length);
		memcpy (&ret_buff[index], &rsp_hdr, sizeof (struct CefT_Csmgr_CnpbStatus_TL));
		index += sizeof (struct CefT_Csmgr_CnpbStatus_TL);
		memcpy (&ret_buff[index], &value64, length);
		index += length;

		/* Sets Interests 		*/
		length = sizeof (uint64_t);
		value64  = cef_client_htonb (work->interests);
		rsp_hdr.type   = htons (CefC_CnpbStatus_Interest);
		rsp_hdr.length = htons (length);
		memcpy (&ret_buff[index], &rsp_hdr, sizeof (struct CefT_Csmgr_CnpbStatus_TL));
		index += sizeof (struct CefT_Csmgr_CnpbStatus_TL);
		memcpy (&ret_buff[index], &value64, length);
		index += length;

		work = work->next;
	}

	if (index == CefC_Csmgr_Msg_HeaderLen) {
		char *rspmsg = "NONE";
		strcpy ((char*)(ret_buff + index), rspmsg);
		index += strlen (rspmsg)+1;
	}

	/* Set Length */
	value32 = htonl (index);
	memcpy (ret_buff + CefC_O_Length, &value32, sizeof (value32));

	{
		int	fblocks;
		int rem_size;
		int counter;
		int flag;
		flag = fcntl (sock, F_GETFL, 0);
		fcntl (sock, F_SETFL, flag & ~O_NONBLOCK);
		fblocks = index / CefC_Max_Length;
		rem_size = index % CefC_Max_Length;
		for (counter=0; counter<fblocks; counter++) {
			/* Send message 		*/
			fds[0].fd = sock;
			fds[0].events = POLLOUT | POLLERR;
			res = poll (fds, 1, 100);
			if (res < 1) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Failed to poll (response status message).\n");
#endif // CefC_Debug
				free (ret_buff);
				return;
			}
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Send the Get Conpub Status response(len = %u).\n", CefC_Max_Length);
#endif // CefC_Debug
			res = cef_csmgr_send_msg (sock, &ret_buff[counter*CefC_Max_Length], CefC_Max_Length);
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
			res = poll (fds, 1, 100);
			if (res < 1) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Failed to poll (response status message).\n");
#endif // CefC_Debug
				free (ret_buff);
				return;
			}
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Send the Get Conpub Status response(len = %u).\n", rem_size);
#endif // CefC_Debug
			res = cef_csmgr_send_msg (sock, &ret_buff[fblocks*CefC_Max_Length], rem_size);
#ifdef CefC_Debug
			if (res < 0) {
				cef_dbg_write (CefC_Dbg_Fine, "Failed to send response message(status).\n");
			}
#endif // CefC_Debug
		}
	}
	free (ret_buff);
	return;
}
/*--------------------------------------------------------------------------------------
	Receive the Reload Conpub Contents Message
----------------------------------------------------------------------------------------*/
static void
conpubd_incoming_cnpbrload_msg (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
) {
	unsigned char *ret_buff;
	uint16_t index = 0;
	uint16_t value16;
	char* rspmsg;

	ret_buff = calloc (1, CefC_Max_Length);
	if (ret_buff == NULL) {
		cef_log_write(CefC_Log_Warn, "%s(%d), calloc failure.\n", __func__, __LINE__);
		return;
	}

	/* Create message */
	/* Set header */
	ret_buff[CefC_O_Fix_Ver]  = CefC_Version;
	ret_buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_CnpbRload;
	index += CefC_Csmgr_Msg_HeaderLen;

	memcpy (ret_buff + index, buff, buff_len);
	index += buff_len;

	if (conpubd_cntent_load_stat == 0) {
		 rspmsg = "Reload request accepted.";
	} else {
		rspmsg = "Since the content is being loaded, the request was not accepted.";
	}
	strcpy ((char*)(ret_buff + index), rspmsg);
	index += strlen (rspmsg)+1;

	/* Set Length */
	value16 = htons (index);
	memcpy (ret_buff + CefC_O_Length, &value16, CefC_S_Length);

	/* Send message 		*/
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Send the Reload Conpub Contents response(len = %u).\n", index);
	cef_dbg_buff_write (CefC_Dbg_Finest, ret_buff, index);
#endif // CefC_Debug
	/* Send response */
	cef_csmgr_send_msg (sock, ret_buff, index);

	if ( conpubd_cntent_load_stat == 0) {
		pthread_t th;
		if (cef_pthread_create (&th, NULL, conpubd_content_load_thread, hdl) == -1) {
			cef_log_write (CefC_Log_Error, "Failed to create the new thread\n");
			return;
		}
	}
	free (ret_buff);

	return;
}
/*--------------------------------------------------------------------------------------
	Reload Conpub Contents thread
----------------------------------------------------------------------------------------*/
static void*
conpubd_content_load_thread (
	void* arg
) {
	CefT_Cpubcnt_Hdl Cpubreloadhdl;
	CefT_Cpubcnt_Hdl delcnthdl;

	CefT_Conpubd_Handle* hdl = (CefT_Conpubd_Handle*) arg;
	pthread_t self_thread = pthread_self ();
	pthread_detach (self_thread);

	pthread_mutex_lock (&conpub_cnt_mutex);
	conpubd_cntent_load_stat = 1;

	memset (&delcnthdl, 0, sizeof (CefT_Cpubcnt_Hdl));
	/* Execute load processing */
	{
		CefT_Cpubcnt_Hdl* cnt_bp;
		CefT_Cpubcnt_Hdl* cnt_wk;
		CefT_Cpubcnt_Hdl* rld_bp;
		CefT_Cpubcnt_Hdl* rld_wk;
		int	foundf;
		CefT_Cpubcnt_Hdl* del_wk;

		memset (&Cpubreloadhdl, 0, sizeof (CefT_Cpubcnt_Hdl));
		conpub_contdef_read (hdl, &Cpubreloadhdl);

		del_wk = &delcnthdl;
		cnt_bp = &Cpubcnthdl;
		cnt_wk = Cpubcnthdl.next;

		while (cnt_wk) {
#ifdef CefC_Debug
char uri[CefC_NAME_MAXLEN];
cef_frame_conversion_name_to_uri (cnt_wk->name, cnt_wk->name_len, uri);
#endif // CefC_Debug
			foundf = 0;
			rld_bp = &Cpubreloadhdl;
			rld_wk = Cpubreloadhdl.next;
			while (rld_wk) {
				if ((cnt_wk->name_len == rld_wk->name_len)
					&& (memcmp (cnt_wk->name, rld_wk->name, rld_wk->name_len) == 0)) {
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Finer, "%s(%d) %s, cnt_wk->expiry=%llu, rld_wk->expiry=%llu\n",
		__func__, __LINE__, uri, cnt_wk->expiry, rld_wk->expiry);
#endif // CefC_Debug
					/* Same name */
					if (cnt_wk->expiry == rld_wk->expiry) {
						/* Same date */
						foundf = 1; /* Don't re-create Cob */
						/* Delete from content reload list */
						rld_bp->next = rld_wk->next;
						free (rld_wk);
						break;
					} else {
						break; /* re-create Cob */
					}
				}
				rld_bp = rld_wk;
				rld_wk = rld_wk->next;
			}
			if (foundf == 0) {
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) Delete listing content = %s\n",
		__func__, __LINE__, uri);
#endif // CefC_Debug
				/* Move from content list to delete list */
				del_wk->next = cnt_wk;
				del_wk = del_wk->next;
				cnt_bp->next = cnt_wk->next;
				cnt_wk->next = 0;
				cnt_wk = cnt_bp;
			}
			cnt_bp = cnt_wk;
			cnt_wk = cnt_wk->next;
		}
	}

	/* Delete contnts from delete list */
	{
		CefT_Cpubcnt_Hdl* bwk;
		CefT_Cpubcnt_Hdl* wk;

		bwk = &delcnthdl;
		wk = delcnthdl.next;
		while (wk) {
			char uri[CefC_NAME_MAXLEN];
			cef_frame_conversion_name_to_uri (wk->name, wk->name_len, uri);
			cef_log_write (CefC_Log_Info, "Deleted(reload) %s \n", uri);
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) Delete the expired content = %s\n",
		__func__, __LINE__, uri);
#endif // CefC_Debug
			if (conpubd_publish_content_delete (hdl, wk) != 0) {
				;
			}
			bwk->next = wk->next;
			free (wk);
			wk = bwk;
			wk = wk->next;
		}
	}

	/* Add contnts from reload list */
	{
		time_t now_time;
		time_t timer;
		struct tm* local;
		CefT_Cpubcnt_Hdl* bwk;
		CefT_Cpubcnt_Hdl* wk;
		int rtc;

		timer = time (NULL);
		local = localtime (&timer);
		now_time = mktime (local);

		wk = Cpubreloadhdl.next;
		while (wk) {
			Cpubreloadhdl.next = wk->next;
			if (conpubd_running_f != 0) {
				rtc = conpubd_publish_content_create (hdl, wk, now_time);
			} else {
				rtc = 0;
			}
			if	(rtc < 0) {
				free (wk);
			} else {
				/* Insert reload entry at top of content list */
				bwk = Cpubcnthdl.next;
				Cpubcnthdl.next = wk;
				wk->next = bwk;
			}
			wk = Cpubreloadhdl.next;
		}
	}

#ifdef CefC_Debug
{
	CefT_Cpubcnt_Hdl* work;
	work = Cpubcnthdl.next;
	struct tm* timeptr;
	char date_str[256];
	cef_dbg_write (CefC_Dbg_Fine, "----- Contents -----\n");
	while (work) {
		/* Name 			*/
		conpubd_dbg_convert_name_to_str_put_workstr (work->name, work->name_len);
		cef_dbg_write (CefC_Dbg_Fine, "Name=%s\n", workstr);
		/* Path 			*/
		cef_dbg_write (CefC_Dbg_Fine, "    Path=%s\n", work->file_path);
		/* Date 			*/
		cef_dbg_write (CefC_Dbg_Fine, "    PutDate=%ld\n", work->date);
		timeptr = localtime (&work->date);
		strftime (date_str, 64, "%Y-%m-%d %H:%M", timeptr);
		cef_dbg_write (CefC_Dbg_Fine, "    PutDate=%s\n", date_str);
		/* Expiry 			*/
		cef_dbg_write (CefC_Dbg_Fine, "    Expiry=%ld\n", work->expiry);
		timeptr = localtime (&work->expiry);
		strftime (date_str, 64, "%Y-%m-%d %H:%M", timeptr);
		cef_dbg_write (CefC_Dbg_Fine, "    Expiry=%s\n", date_str);
		cef_dbg_write (CefC_Dbg_Fine, "    PendingTimer=%d\n", work->t_pending);
		work = work->next;
	}
	cef_dbg_write (CefC_Dbg_Fine, "--------------------\n");
}
#endif //CefC_Debug


	conpubd_cntent_load_stat = 0;
	pthread_mutex_unlock (&conpub_cnt_mutex);
	cef_log_write (CefC_Log_Info, "The load processing is completed.\n");
	pthread_exit (NULL);
	return ((void*) NULL);
}
/*--------------------------------------------------------------------------------------
	Post process
----------------------------------------------------------------------------------------*/
static void
conpubd_post_process (
	CefT_Conpubd_Handle* hdl					/* conpub daemon handle					*/
) {
	conpubd_handle_destroy (&hdl);

	pthread_mutex_destroy (&conpub_cnt_mutex);
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) program terminated.\n", __func__, __LINE__);
#endif //CefC_Debug

	return;
}
/*--------------------------------------------------------------------------------------
	Sigcatch Function
----------------------------------------------------------------------------------------*/
static void
conpubd_sigcatch (
	int sig										/* caught signal						*/
) {
	if ((sig == SIGINT) || (sig == SIGTERM)) {
		conpubd_running_f = 0;
	}
	return;
}
/*--------------------------------------------------------------------------------------
	Read the content definition file
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
conpub_contdef_read (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	CefT_Cpubcnt_Hdl* cnthdl
) {
	FILE*	fp = NULL;
	char 	buff[BUFSIZ_4K];
	char 	uri[CefC_NAME_MAXLEN];
	size_t 	uri_len;
	char 	path[PATH_MAX];
	char 	date_str[BUFSIZ_64];
	char 	time_str[BUFSIZ_64];
	char	t_pending_str[BUFSIZ_64];
	uint16_t t_pending;
	int 	res;
	unsigned char 		name[CefC_NAME_MAXLEN];
	int 				name_len;
	time_t 				expiry;
	uint64_t			cob_num;
	struct tm t;
	time_t now;
	time_t timer;
	struct tm *local;
	size_t buff_len = 0;
	int		line_no = 0;

#ifdef CefC_Debug
	conpubd_dbg_write (CefC_Dbg_Fine, "Reading conpubcont.def ...\n");
#endif // CefC_Debug
	cef_log_write (CefC_Log_Info, "Reading conpubcont.def ...\n");

	CefT_Cpubcnt_Hdl* work = (CefT_Cpubcnt_Hdl*) cnthdl;

#if 0 //+++++ GCC v9 +++++
	sprintf (conpub_contdef_path, "%s/%s", conpub_contdef_dir, CefC_Conpub_ContDef_Name);
#else
	int rc;
	rc = snprintf (conpub_contdef_path, sizeof(conpub_contdef_path), "%s/%s", conpub_contdef_dir, CefC_Conpub_ContDef_Name);
	if (rc < 0){
		cef_log_write (CefC_Log_Error, "conpubcont.def file dir path too long(%s)\n", conpub_contdef_dir);
		return (-1);
	}

#endif //----- GCC v9 -----

	/*--------------------------------------------------------
		Open content definition file
	----------------------------------------------------------*/
	fp = fopen (conpub_contdef_path, "r");
	if (fp == NULL) {
#ifdef CefC_Debug
	conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) Fail to open %s\n", __func__, __LINE__, conpub_contdef_path);
#endif // CefC_Debug
		cef_log_write (CefC_Log_Error, "Fail to open %s\n", conpub_contdef_path);
		return (-1);
	}

	/*--------------------------------------------------------
		Read content definitionfile
	----------------------------------------------------------*/
	buff_len = sizeof (buff) - 1;
	while (fgets (buff, buff_len, fp) != NULL) {

		/* for warning message */
		line_no++;

		if (conpubd_running_f == 0) {
			return (-1);
		}

		buff[buff_len] = 0;

		if (buff[0] == '#') {
			continue;
		}
		if (isspace (buff[0])) {
			continue;
		}
		res = conpub_trim_line_string (buff, uri, path, date_str, time_str, t_pending_str);
		if (res < 0) {
			buff[strlen (buff)-1] = 0;
			cef_log_write (CefC_Log_Warn, "<%d> Invalid record (%s)\n", line_no, buff);
			continue;
		}
#ifdef	CefC_Debug
conpubd_dbg_write (CefC_Dbg_Finer, "%s(%d) uri=%s, path=%s, date=%s, time=%s, t_pending=%s\n",
		__func__, __LINE__, uri, path, date_str, time_str, t_pending_str);
#endif	// CefC_Debug

		/* Get file path 		*/
		res = conpub_check_file_path (path);
		if (res < 0) {
			cef_log_write (CefC_Log_Error, "<%d> Fail to open %s\n", line_no, path);
			continue;
		}

		/* Get the expiry 			*/
		memset (&t, 0, sizeof (struct tm));
		res = conpub_parse_date (date_str, time_str, &t);
		if (res < 0) {
			cef_log_write (CefC_Log_Warn, "<%d> Invalid Date/Time (%s %s)\n", line_no, date_str, time_str);
			continue;
		}
		expiry = mktime (&t);
		if (expiry == -1) {
			cef_log_write (CefC_Log_Warn, "<%d> Invalid Expiry (%s %s)\n", line_no, date_str, time_str);
			continue;
		}

		name_len = cef_frame_conversion_uri_to_name (uri, name);
		if (name_len < 0) {
			cef_log_write (CefC_Log_Warn, "<%d> Invalid URI (%s) specified.\n", line_no, uri);
			continue;
		}
		if (name_len > CefC_NAME_MAXLEN) {
			cef_log_write (CefC_Log_Warn, "<%d> The converted name is too long (%s) specified.\n", line_no, uri);
			continue;
		}

		uri_len = strlen (uri);
		if (uri_len && (uri[uri_len-1]=='/')) {
#ifdef CefC_Debug
			conpubd_dbg_write (CefC_Dbg_Fine, "<%d> Invalid URI (%s) specified. It is illegal for a URI to end with /.\n", line_no, uri);
#endif // CefC_Debug
			cef_log_write (CefC_Log_Warn, "<%d> Invalid URI (%s) specified. It is illegal for a URI to end with /.\n", line_no, uri);
			continue;
		}

		timer = time (NULL);
		local = localtime (&timer);
		now = mktime (local);

		if (expiry < now) {
#ifdef CefC_Debug
			conpubd_dbg_write (CefC_Dbg_Fine, "<%d> Invalid Expiry (%s: %s %s) specified.\n", line_no, uri, date_str, time_str);
#endif // CefC_Debug
			cef_log_write (CefC_Log_Warn, "<%d> Invalid Expiry (%s: %s %s) specified.\n", line_no, uri, date_str, time_str);
			continue;
		}

		/* Calculates number of cobs */
		{
		    struct stat statBuf;
			if (stat (path, &statBuf) == 0) {
				cob_num = statBuf.st_size / hdl->block_size;
				if (statBuf.st_size % hdl->block_size != 0) {
					cob_num++;
				}
			} else {
				cef_log_write (CefC_Log_Error, "<%d> Error in accessing content file. (%s)\n"
								, line_no , path);
				continue;
			}
		}
		if (cob_num > (uint64_t)UINT32_MAX + 1) {
			cef_log_write (CefC_Log_Error, "<%d> Error in accessing content file. (%s) - chunk_num over\n"
								, line_no, path);
			continue;
		}
		/* Check URI duplicate definition */
		{
			CefT_Cpubcnt_Hdl* dwk;
			dwk = cnthdl->next;
			while (dwk) {
				if ( (dwk->name_len == name_len)
					&& memcmp (dwk->name, name, name_len) == 0) {
					char uri[CefC_NAME_MAXLEN];
					cef_frame_conversion_name_to_uri (name, name_len, uri);
					cef_log_write (CefC_Log_Warn, "<%d> Duplicate URI (%s) specified.\n", line_no, uri);
					break;
				}
				dwk = dwk->next;
			}
			if (dwk != NULL) {
				continue;
			}
		}

		work->next = (CefT_Cpubcnt_Hdl*) malloc (sizeof (CefT_Cpubcnt_Hdl));
		if (work->next == NULL) {
			cef_log_write (CefC_Log_Error, "malloc error(Cpubcnt)\n");
			return (-1);
		}

		work = work->next;
		memset (work, 0, sizeof (CefT_Cpubcnt_Hdl));
		strcpy (work->file_path, path);
		memcpy (work->name, name, name_len);
		work->name_len 	= name_len;
		work->expiry = expiry;
		work->date = now;
		work->cob_num = cob_num;
		work->line_no = line_no;
		t_pending = atoi(t_pending_str);
		if (t_pending) {
			work->t_pending = t_pending;
		} else {
			work->t_pending = hdl->t_pending;
		}
	}

	fclose (fp);
#ifdef CefC_Debug
	conpubd_dbg_write (CefC_Dbg_Fine, "Finished reading conpubcont.def. \n");
#endif // CefC_Debug
	cef_log_write (CefC_Log_Info, "Finished reading conpubcont.def. \n");
	return (0);
}
/*--------------------------------------------------------------------------------------
	Triming a line read from a file
----------------------------------------------------------------------------------------*/
static int
conpub_trim_line_string (
	const char* p, 								/* target string for trimming 			*/
	char* uri, 									/* URI string after trimming			*/
	char* path,									/* Path string after trimming			*/
	char* date,									/* Date string after trimming			*/
	char* time,
	char* t_pending								/* pending_timer string after trimming	*/
) {
	int param_num, opt_num;
	int YY, MM, DD;
	int H, M;
	int i;
	uint16_t t_pending_uint = 0;
	char option_str[3][BUFSIZ_64] = {0};

	strcpy (uri, "");
	strcpy (path, "");
	strcpy (date, "");
	strcpy (time, "");
    strcpy (t_pending, "");

	while (*p) {
		if ((*p == 0x0D) || (*p == 0x0A)) {
			return (-1);
		}
		if ((*p == 0x20) || (*p == 0x09)) {
			p++;
			continue;
		}
		break;
	}
	param_num = sscanf (p, "%s %s %s %s %s", uri, path, option_str[0], option_str[1], option_str[2]);
	opt_num = (param_num - 2);
	if (opt_num < 0) {		// uri & path is mandatory
		return (param_num);
	}

	for (i = 0; i < opt_num; i++) {
		if (sscanf (option_str[i], "%d-%d-%d", &YY, &MM, &DD) == 3) {
			int yy, mm, dd;

			yy = YY;
			mm = MM;
			dd = DD;
			if (yy < 2000 || !(1 <= mm && mm <= 12) || !(1 <= dd && dd <= 31)) {
				cef_log_write (CefC_Log_Warn, "%s Expiration date is incorrect, %s.\n",
					uri, option_str[i]);
				return (-1);
			}
			strcpy (date, option_str[i]);
		} else if (sscanf (option_str[i], "%d:%d", &H, &M) == 2) {
			int h, m;

			h = H;
			m = M;
			if (!(0 <= h && h <= 23) || !(0 <= m && m <= 59)) {
				cef_log_write (CefC_Log_Warn, "%s Expiration time is incorrect, %s.\n",
					uri, option_str[i]);
				return (-1);
			}
			strcpy (time, option_str[i]);
		} else if(!*t_pending) {
			if (strtoul (option_str[i], NULL, 10) <= UINT16_MAX) {
	 			sscanf (option_str[i], "%hd", &t_pending_uint);
 				strcpy (t_pending, option_str[i]);
			}
			if (!(CefC_CnpbMin_Pending_Timer <= t_pending_uint && t_pending_uint <= CefC_CnpbMax_Pending_Timer)) {
				cef_log_write (CefC_Log_Warn, "Pending_Timer (%s) must be higher than %d and lower than %d.\n",
					t_pending, CefC_CnpbMin_Pending_Timer, CefC_CnpbMax_Pending_Timer);
				return (-1);
			}
		} else {
			return (-1);
		}
	}

	return (param_num);
}
/*--------------------------------------------------------------------------------------
	Checks the file path
----------------------------------------------------------------------------------------*/
int
conpub_check_file_path (
	const char* path 							/* file path 							*/
) {
	FILE*	fp = NULL;

	fp = fopen (path, "r");
	if (fp == NULL) {
		return (-1);
	}
	fclose (fp);

	return (1);
}
/*--------------------------------------------------------------------------------------
	Checks the date
----------------------------------------------------------------------------------------*/
int
conpub_parse_date (
	const char* date_str, 						/* date string (e.g. 2017-1-28) 		*/
	const char* time_str, 						/* time string (e.g. 15:45) 			*/
	struct tm* date								/* variable to set the parsed result 	*/
) {
	char* d = (char*) date_str;
	char* t = (char*) time_str;

	int parame;
	char work[1024];
	int i;

	memset (date, 0, sizeof (struct tm));
	if (*d) {
		parame 	= 0;
		i 		= 0;

		while (*d) {
			if (*d == '-') {
				work[i] = 0;
				switch (parame) {
					case 0: {
						date->tm_year = atoi (work) - 1900;
						break;
					}
					case 1: {
						date->tm_mon = atoi (work) - 1;
						break;
					}
					default: {
						/* NOP */;
						break;
					}
				}
				i = 0;
				parame++;
				d++;
				continue;
			}

			work[i] = *d;
			i++;
			d++;
		}
		if (parame != 2) {
			return (-1);
		}
		work[i] = 0;
		date->tm_mday = atoi (work);
	} else {
		date->tm_year	= 2037 - 1900;
		date->tm_mon	= 12 - 1;
		date->tm_mday	= 31;
	}

	if (*t) {
		parame 	= 0;
		i 		= 0;

		while (*t) {
			if (*t == ':') {
				work[i] = 0;

				switch (parame) {
					case 0: {
						date->tm_hour = atoi (work);
						break;
					}
					default: {
						/* NOP */;
						break;
					}
				}
				i = 0;
				parame++;
				t++;
				continue;
			}

			work[i] = *t;
			i++;
			t++;
		}
		if (parame != 1) {
			return (-1);
		}
		work[i] = 0;
		date->tm_min = atoi (work);
	} else {
		date->tm_hour	= 23;
		date->tm_min	= 59;
	}
	date->tm_isdst = -1;

	return (1);
}

/*--------------------------------------------------------------------------------------
	Inits cefcontentserver
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
conpubd_init (
	const char* conf_path
) {

	cef_log_write (CefC_Log_Info, "Initialization ...\n");

	/*--------------------------------------------------------
		Inits the handle
	----------------------------------------------------------*/
	memset (&Cpubcnthdl, 0, sizeof (CefT_Cpubcnt_Hdl));
	cef_frame_init ();

	return (1);
}
/*--------------------------------------------------------------------------------------
	Post Process of cefcontentserver
----------------------------------------------------------------------------------------*/
static int									/* Returns a negative value if it fails 	*/
conpubd_destroy (
	void
) {
	CefT_Cpubcnt_Hdl* bwk;
	CefT_Cpubcnt_Hdl* wk;

	bwk = &Cpubcnthdl;
	wk = Cpubcnthdl.next;
	while (wk) {
		bwk->next = wk->next;
		free (wk);
		wk = bwk;
		wk = wk->next;
	}

	return (0);
}

/*--------------------------------------------------------------------------------------
	Creates the Cobs
----------------------------------------------------------------------------------------*/
static int
conpubd_publish_content_create (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	CefT_Cpubcnt_Hdl* entry,
	time_t now_time
) {
	FILE* fp;
	FILE* key_fp;
	char key_file_path[PATH_MAX+0x10];
	int16_t key_len;
	char padding_file_path[PATH_MAX+0x10];
	FILE* padding_fp;
	size_t padding_len;
	int padding = 0;
	char padding_str[32] = {0};
	uint32_t seqnum = 0;
	int res;
	unsigned char buff[CefC_Max_Length];
	unsigned char cobbuff[CefC_Max_Length];

	int len;
	int rtc = 0;
	ConpubdT_Content_Entry cont_entry;
	int first_cob_f = 0;
	uint64_t free_mem_mega = 0;
	uint64_t estimated_mem_mega = 0;
	uint64_t free_file_mega = 0;
	uint64_t estimated_file_mega = 0;
	CefT_CcnMsg_OptHdr	opt;

	struct timespec ts_start, ts_end;
	clock_gettime(CLOCK_MONOTONIC, &ts_start);

	/* Check Content num  */
	if (hdl->published_contents_num >= hdl->contents_num) {
		cef_frame_conversion_name_to_uri (entry->name, entry->name_len, Uri_buff_p);
		cef_log_write (CefC_Log_Warn
						, "CONTENTS CAPACITY over : %s, Publishied contents=%d\n"
						, Uri_buff_p, hdl->contents_num);
		return (-99);
	}
	/* Check capacity */
	{
		uint64_t capacity;
		uint64_t cobs;

		capacity = csmgr_stat_cache_capacity_get (stat_hdl);
		cobs = hdl->cs_mod_int->cached_cobs();
		if ((capacity - cobs) < entry->cob_num) {
			cef_frame_conversion_name_to_uri (entry->name, entry->name_len, Uri_buff_p);
			cef_log_write (CefC_Log_Warn
							, "CAPACITY over : %s,  capacity="FMTU64",  used cobs="FMTU64",  set cobs="FMTU64"\n"
							, Uri_buff_p, capacity, cobs, entry->cob_num);
			return (-99);
		}
	}

	/* Creates and inputs the Cobs 	*/

	fp = fopen (entry->file_path, "rb");
	if (fp == NULL) {
		return (-1);
	}
	strcpy (key_file_path, entry->file_path);
	strcat (key_file_path, ".pubkey");
	key_fp = fopen (key_file_path, "rb");

	/* Inits the parameters 		*/
	memset (&opt, 0, sizeof (CefT_CcnMsg_OptHdr));
	memset (Cob_prames_p, 0, sizeof (CefT_CcnMsg_MsgBdy));
	/* Sets the name */
	memcpy (Cob_prames_p->name, entry->name, entry->name_len);
	Cob_prames_p->name_len = entry->name_len;
	/* Sets Expiry TIme */
	Cob_prames_p->expiry = entry->expiry * 1000;
	/* Sets Cache TIme */
	opt.cachetime_f = 1;
	opt.cachetime = Cob_prames_p->expiry;
	/* Sets chunk flag */
	Cob_prames_p->chunk_num_f = 1;
	/* Sets end chunk */
	Cob_prames_p->end_chunk_num_f =1;
	Cob_prames_p->end_chunk_num = entry->cob_num-1;
	/* Sets validation info */
	Cob_prames_p->alg.valid_type = hdl->valid_type;

	if(key_fp != NULL) {
		Cob_prames_p->org.pending_val = entry->t_pending;
		opt.cachetime_f = 0;

		strcpy (padding_file_path, entry->file_path);
		strcat (padding_file_path, ".padding");
		padding_fp = fopen (padding_file_path, "r");
		if (NULL != padding_fp) {
			fclose (padding_fp);
			Cob_prames_p->org.encryptalg.encryptalg_f = 1;
			Cob_prames_p->org.encryptalg.type = CefC_T_EA_CPABE;
			Cob_prames_p->org.orgkeyid.hash_type = CefC_T_SHA_512;
			memcpy (Cob_prames_p->org.orgkeyid.hash_value, hdl->publisher_id, SHA512_DIGEST_LENGTH);
			Cob_prames_p->org.orgkeyid.hash_length = SHA512_DIGEST_LENGTH;
		}
	} else {
		entry->t_pending = 0;
	}

	cef_frame_conversion_name_to_uri (entry->name, entry->name_len, Uri_buff_p);
	while (conpubd_running_f) {
		res = fread (buff, sizeof (unsigned char), hdl->block_size, fp);
		if (res > 0) {
			if (key_fp != NULL) {
				if (feof(fp) != 0) {
					key_len = fread (Cob_prames_p->org.csact.publickey_val, sizeof (unsigned char), CefC_S_PUBLICKEY, key_fp);
					if (key_len > 0) {
						Cob_prames_p->org.csact.publickey_len = key_len;
						Cob_prames_p->org.csact.csact_alg_f = 1;
						Cob_prames_p->org.csact.csact_type = CefC_T_EC_SECP_384R1;
						Cob_prames_p->org_len = 0;
					} else {
						cef_log_write (CefC_Log_Warn,"T_ECDSA_KEY length equals 0.\n");
					}

					padding_fp = fopen (padding_file_path, "r");
					if (NULL != padding_fp) {
						padding_len = fread (padding_str, sizeof (unsigned char), sizeof (padding_str), padding_fp);
						if (0 < padding_len) {
							padding = atoi (padding_str);
							Cob_prames_p->org.encryptalg.encryptalg_f = 1;
							Cob_prames_p->org.encryptalg.type = CefC_T_EA_CPABE;
							Cob_prames_p->org.encryptalg.padding = padding;
							Cob_prames_p->org_len = 0;
						}
						fclose (padding_fp);
					}
				}
			}
			memcpy (Cob_prames_p->payload, buff, res);
			Cob_prames_p->payload_len = (uint16_t) res;
			Cob_prames_p->chunk_num = seqnum;

			len = cef_frame_object_create (cobbuff, &opt, Cob_prames_p);
			if (first_cob_f == 0) {
				if (strcmp(hdl->cache_type, CefC_Cnpb_memory_Cache_Type) == 0) {
					/* Get free mem size */
					conpubd_free_memsize_get (&free_mem_mega);
					estimated_mem_mega = ( 64 /* size of ConpubdT_Content_Mem_Entry */
											+ Cob_prames_p->name_len
											+ (len+3/* for chunk# */)
											+ (40/* size of CefT_Mem_Hash_Cell */
											+ (Cob_prames_p->name_len+8/* for hush KEY */))
										) * entry->cob_num / 1024 /1024;
					estimated_mem_mega = estimated_mem_mega * CefC_Cpub_Memory_Usage_Correction_Factor;
					if (estimated_mem_mega > free_mem_mega) {
						cef_log_write (CefC_Log_Warn,
							"Skipping content(%s) registration due to lack of memory.\n"
							"	free memory="FMTU64"(MB), estimated memory usage="FMTU64"(MB)\n",
							Uri_buff_p, free_mem_mega, estimated_mem_mega);
						fclose (fp);
						if (key_fp != NULL) {
							fclose(key_fp);
						}
						return (-99);
					} else {
							cef_log_write (CefC_Log_Info,
								"Publishing %s \n"
								"	free memory="FMTU64"(MB), estimated memory usage="FMTU64"(MB)\n",
							Uri_buff_p, free_mem_mega, estimated_mem_mega);
					}
				} else { //CefC_Cnpb_filesystem_Cache_Type
					/* Get initial free fisk size */
					get_filesystem_info (hdl->cache_path, &free_file_mega);
					estimated_file_mega = (sizeof(uint16_t)+len+3)  * entry->cob_num / 1024 /1024;
					if (estimated_file_mega > free_file_mega - CefC_Cpub_Reserved_Disk_Mega) {
						cef_log_write (CefC_Log_Warn,
							"Skipping content(%s) registration due to lack of disk.\n"
							"	free disk="FMTU64"(MB), estimated disk usage="FMTU64"(MB)\n"
							"	(Use %dMB as free reserve)\n",
							Uri_buff_p, free_file_mega, estimated_file_mega,
							CefC_Cpub_Reserved_Disk_Mega);
						fclose (fp);
						if (key_fp != NULL) {
							fclose(key_fp);
						}
						return (-99);
					} else {
						cef_log_write (CefC_Log_Info, "Publishing %s \n"
							"	free disk="FMTU64"(MB), estimated disk usage="FMTU64"(MB)\n"
							"	(Use %dMB as free reserve)\n",
							Uri_buff_p, free_file_mega, estimated_file_mega,
							CefC_Cpub_Reserved_Disk_Mega);
					}
				}
				first_cob_f = 1;
			}
			if (len > 0) {
				/*----------------------------------------------------------------------------------*/
				/* [filesystem cache]                                                               */
				/* "msg" and "name" are released after copying to the cache memory resource         */
				/* in the cache program.                                                            */
				/* [memory cache]                                                                   */
				/* In the cache program, "msg" and "name" are reused even after being copied        */
				/* to the memory resource of the cache, and are released when the cache is deleted. */
				/*----------------------------------------------------------------------------------*/
				if ((cont_entry.msg = calloc (1, len)) == NULL) {
					cef_log_write (CefC_Log_Critical, "Failed to alloc memory\n");
					conpubd_running_f = 0;
					fclose (fp);
					if (key_fp != NULL) {
						fclose(key_fp);
					}
					return (-1);
				}
				memcpy (cont_entry.msg, cobbuff, len);
				cont_entry.msg_len = len;
				if ( 0 < Cob_prames_p->name_len )
					memcpy (cont_entry.name, Cob_prames_p->name, Cob_prames_p->name_len);
				cont_entry.name_len = Cob_prames_p->name_len;
				cont_entry.pay_len = Cob_prames_p->payload_len;
				cont_entry.chunk_num = Cob_prames_p->chunk_num;
				cont_entry.expiry = Cob_prames_p->expiry * 1000;
				cont_entry.rct = (uint64_t)hdl->cache_default_rct;
				/* cont_entry.node does not care */
				rtc = hdl->cs_mod_int->cache_item_puts (&cont_entry, sizeof (cont_entry), NULL);
				if (rtc < 0) {
					cef_log_write (CefC_Log_Critical, "Failed to publish %s (cache_item_puts)\n", Uri_buff_p);
					conpubd_running_f = 0;
					fclose (fp);
					if (key_fp != NULL) {
						fclose(key_fp);
					}
					hdl->cs_mod_int->cache_item_puts (NULL, 0, NULL);
					return (-1);
				}
			}
			seqnum++;
		} else {
			if (feof (fp) == 0 || ferror (fp) != 0) {
				cef_log_write (CefC_Log_Critical, "Failed to publish %s (Read Error)\n", Uri_buff_p);
				conpubd_running_f = 0;
				fclose (fp);
				if (key_fp != NULL) {
					fclose(key_fp);
				}
				hdl->cs_mod_int->cache_item_puts (NULL, 0, NULL);
				return (-1);
			}
			break;
		}
	}

	hdl->cs_mod_int->cache_item_puts (NULL, 0, NULL);
	fclose (fp);
	if (key_fp != NULL) {
		fclose(key_fp);
	}

	clock_gettime(CLOCK_MONOTONIC, &ts_end);
	long elapsed_ms =
		(ts_end.tv_sec  - ts_start.tv_sec)  * 1000 +
		(ts_end.tv_nsec - ts_start.tv_nsec) / 1000000;

	cef_log_write( CefC_Log_Info, "Published %s (time=%ld ms)\n", Uri_buff_p,  elapsed_ms );

	conpubd_appreg_entry(hdl->cefnetd_sock, entry);	/* CefC_T_OPT_APP_REG */

	hdl->published_contents_num ++;

   	return (rtc);
}
/*--------------------------------------------------------------------------------------
	Deletes the Cobs
----------------------------------------------------------------------------------------*/
static int
conpubd_publish_content_delete (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	CefT_Cpubcnt_Hdl* entry
) {
	int 			name_len;
	int				rtc = 0;
	char			uri[CefC_NAME_MAXLEN];

	cef_frame_conversion_name_to_uri (entry->name, entry->name_len, uri);

#ifdef CefC_Debug
	conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) Delete the expired content = %s\n",
		__func__, __LINE__, uri);
#endif // CefC_Debug
	if (hdl->cs_mod_int->content_del == NULL) {
		cef_log_write (CefC_Log_Critical, "Failed to delete %s (no content_del plugin)\n", uri);
		conpubd_running_f = 0;
		rtc = -1;
		return (rtc);
	}

	hdl->published_contents_num --;

	conpubd_unreg_entry(hdl->cefnetd_sock, entry);	/* CefC_T_OPT_APP_DEREG */

	memcpy (Name_buff_p, entry->name, entry->name_len);
	name_len = entry->name_len;

	rtc = hdl->cs_mod_int->content_del (Name_buff_p, name_len, entry->cob_num);
#ifdef CefC_Debug
	conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) content_del(%s)=%d\n",
		__func__, __LINE__, uri, rtc);
#endif // CefC_Debug
	if (rtc < 0) {
		cef_log_write (CefC_Log_Warn, "Failed to delete %s (content_cache_del:%d)\n", uri, rtc);
	}
	return (rtc);
}

/*--------------------------------------------------------------------------------------
	Content registration check
----------------------------------------------------------------------------------------*/
static CefT_Cpubcnt_Hdl*
conpubd_content_reg_check (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	unsigned char* name,
	uint16_t       name_len
) {

	CefT_Cpubcnt_Hdl* work;
	CefT_Cpubcnt_Hdl* bwork;
	bwork = &Cpubcnthdl;
	work = Cpubcnthdl.next;
	uint64_t 		nowtsec;
	struct timeval 	tv;

	gettimeofday (&tv, NULL);
	nowtsec = tv.tv_sec;
#ifdef	CefC_T_Expire_Delay
	nowtsec -= CefC_T_Expire_Delay;		//	The timelag between expiration and deletion.
#endif	// CefC_T_Expire_Delay

	while (work) {
		if ((work->name_len == name_len)
			&& (memcmp (work->name, name, name_len) == 0)) {
			if (nowtsec > work->expiry) {
				char uri[CefC_NAME_MAXLEN];
 				pthread_mutex_lock (&conpub_cnt_mutex);
				cef_frame_conversion_name_to_uri (work->name, work->name_len, uri);
				cef_log_write (CefC_Log_Info, "Deleted(expired) %s \n", uri);
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) Delete the expired content = %s\n",
		__func__, __LINE__, uri);
#endif // CefC_Debug
				if (conpubd_publish_content_delete (hdl, work) != 0) {
					;
				}
				bwork->next = work->next;
				free (work);
				work = bwork;
				work = work->next;
				pthread_mutex_unlock (&conpub_cnt_mutex);
				return (NULL);
			}
			work->interests++;
			return (work);
		}
		bwork = work;
		work = work->next;
	}

	return (NULL);
}

/*--------------------------------------------------------------------------------------
	Connection to cefnetd and App registration
----------------------------------------------------------------------------------------*/
static void
conpubd_connect_conpubd_and_regApp (
	CefT_Conpubd_Handle* hdl				/* conpub daemon handle						*/
) {
	/* connect to cefnetd 		*/
	if ((hdl->cefnetd_sock == -1) &&
		(cef_client_present_timeus_calc () > hdl->cefnetd_reconnect_time)) {
		cef_log_write (CefC_Log_Info,
				"conpubd is trying to connect with cefnetd ...\n");
		hdl->cefnetd_sock =
			conpub_connect_tcp_to_cefnetd (
					hdl->port_num, hdl->cefnetd_id, hdl->cefnetd_port_str);
		if (hdl->cefnetd_sock != -1) {
			cef_log_write (CefC_Log_Info,
				"conpubd connects to that cefnetd\n");
			hdl->cefnetd_reconnect_time = 0;

			int i = conpubd_free_sock_index_search (hdl);
			if (i > -1) {
				strcpy (hdl->peer_id_str[i], hdl->cefnetd_id);
				strcpy (hdl->peer_sv_str[i], hdl->cefnetd_port_str);
				cef_log_write (CefC_Log_Info, "Open TCP peer: %s:%s, socket : %d\n",
					hdl->peer_id_str[i], hdl->peer_sv_str[i], hdl->cefnetd_sock);
				hdl->tcp_fds[i] 	= hdl->cefnetd_sock;
				hdl->tcp_index[i] 	= 0;
			}

			/* App_Reg */
			CefT_Cpubcnt_Hdl *work = Cpubcnthdl.next;
			while (work) {
				conpubd_appreg_entry(hdl->cefnetd_sock, work);	/* CefC_T_OPT_APP_REG */
				work = work->next;
			}
		} else {
			cef_log_write (CefC_Log_Info,
				"conpubd failed to connect with cefnetd\n");
			hdl->cefnetd_reconnect_time = cef_client_present_timeus_calc () + 5000000;

		}
	}
}

/*--------------------------------------------------------------------------------------
	Connect to conpubd with TCP socket
----------------------------------------------------------------------------------------*/
static int											/* created socket							*/
conpub_connect_tcp_to_cefnetd (
	uint16_t    myport,
	const char* dest,
	const char* port
) {
	struct addrinfo hints;
	struct addrinfo* res;
	struct addrinfo* cres;
	int err;
	int sock;
	int flag;
	int optval = 1;
	int rtry_count;
	struct sockaddr_in myname;

	/* Creates the hint 		*/
	memset (&hints, 0, sizeof (hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;

	/* Obtains the addrinfo 	*/
	if ((err = getaddrinfo (dest, port, &hints, &res)) != 0) {
		fprintf (stderr, "ERROR : conpub_connect_tcp_to_cefnetd (getaddrinfo)\n");
		return (-1);
	}

	for (cres = res ; cres != NULL ; cres = cres->ai_next) {
		rtry_count = 0;
		sock = socket (cres->ai_family, cres->ai_socktype, cres->ai_protocol);

		if (sock < 0) {
			continue;
		}

		flag = fcntl (sock, F_GETFL, 0);
		if (flag < 0) {
			close (sock);
			continue;
		}
		if (setsockopt (sock, SOL_SOCKET, SO_REUSEPORT, (const char *)&optval, sizeof (optval)) < 0) {
			cef_log_write (CefC_Log_Error, "[%s] (setsockopt:%s)\n", __func__, strerror (errno));
			close (sock);
			continue;
		}
		memset (&myname, 0, sizeof (myname));
		myname.sin_family = cres->ai_family;
		myname.sin_addr.s_addr = INADDR_ANY;
		myname.sin_port = htons (myport);
		if (bind (sock, (struct sockaddr *)&myname, sizeof (myname)) < 0) {
			cef_log_write (CefC_Log_Error, "[%s] (bind:%s)\n", __func__, strerror (errno));
			close (sock);
			continue;
		}
RETRY:;
		if (connect (sock, cres->ai_addr, cres->ai_addrlen) < 0) {
			close (sock);
#ifdef __APPLE__
				int retry_errno = EADDRINUSE;
#else // __APPLE__
				int retry_errno = EADDRNOTAVAIL;
#endif // __APPLE__
			if (errno == retry_errno) {
				usleep (1000);
				rtry_count++;
				if (rtry_count > 10) {
					cef_log_write (CefC_Log_Error, "[face] Failed to connect (%s)\n", strerror (errno));
					close (sock);
					continue;
			    }
				goto RETRY;
			}
			continue;
		}
		return (sock);
	}
	freeaddrinfo (res);
	return (-1);
}

/*--------------------------------------------------------------------------------------
	Get free memory size
----------------------------------------------------------------------------------------*/
static int
conpubd_free_memsize_get (
	uint64_t* free_mem_mega
) {
	char buf[64] = {0};

	int ret = 0;
	char* wp = NULL;

	/* get free memory size */
	FILE *fp = popen(CefC_GET_MEMORY_INFO_SH, "r");
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, "fp:%p\n", fp);
#endif // CefC_Debug
	if (fp == NULL) {
		cef_log_write (CefC_Log_Critical, "%s(%d): Could not get memory information.\n", __FUNCTION__, __LINE__);
	} else {
		wp = fgets (buf, sizeof (buf), fp);
		while ( wp ) {
			ret = atoi (buf);
			if (ret != -1) {
				char* token = NULL;
				char* saveptr = NULL;
				token = strtok_r (buf, ",", &saveptr);
				if (token == NULL) {
					break;
				}
				token = strtok_r (NULL, ",", &saveptr);
				if (token == NULL) {
					break;
				}
				ret = atoi (token);
				if (ret != -1) {
					*free_mem_mega = ret;
#ifdef CefC_Debug
					cef_dbg_write (CefC_Dbg_Finest, "free_mem_mega:"FMTU64"\n", *free_mem_mega);
#endif // CefC_Debug
				}
			}
			break;
		}
		pclose(fp);
	}

	if (free_mem_mega == 0) {
		cef_log_write (CefC_Log_Critical, "%s(%d): Could not find keyword to get memory information\n",
						__FUNCTION__, __LINE__);
		return (-1);
	}

	return (0);
}
/*--------------------------------------------------------------------------------------
	Get free disk size
----------------------------------------------------------------------------------------*/
static int
get_filesystem_info (
		char *filepath,
		uint64_t* free_file_mega
) {
	int rc = 0;
	struct statvfs buf = {0};

	rc = statvfs (filepath, &buf);
	if (rc < 0) {
		cef_log_write (CefC_Log_Error, "%s: statvfs(%s) - %s\n", __FUNCTION__, filepath, strerror (errno));
		return (-1);
	}

	*free_file_mega = buf.f_frsize * buf.f_bavail / 1024 / 1024;

	return (0);
}

#ifdef CefC_Debug
static void
conpubd_dbg_convert_name_to_str_put_workstr (
	unsigned char* name_p,
	int name_len
) {
	int		ii;
	char	xstr[32];

	memset (workstr, 0, sizeof (workstr));
	for (ii = 0; ii < name_len; ii++) {
		if (isprint (name_p[ii])) {
			sprintf (xstr, ".%c", name_p[ii]);
		} else {
			sprintf (xstr, "%02X", name_p[ii]);
		}
		strcat (workstr, xstr);
	}

	return;
}
#endif //CefC_Debug

/*--------------------------------------------------------------------------------------
	Convert string to binary
----------------------------------------------------------------------------------------*/
static void
conpubd_str2byte (
	char *str,									/* string to convert					*/
	char *data,									/* Area to store converted binary		*/
	size_t len									/* Size of area to store binaries		*/
) {
	size_t str_len = strlen (str);
	size_t data_len = len * 2;
	size_t i;
	char *wp = data;

	for (i=0; i<data_len; i+=2) {
		if (i >= str_len) {
			memset (wp, 0x00, 1);
		} else if (i + 1 == str_len) {
			sscanf((char *)(str + i), "%01hhx", wp);
			*wp = (*wp << 4) & 0xf0;
		} else {
			sscanf((char *)(str + i), "%02hhx", wp);
		}
		wp ++;
	}
}

/*--------------------------------------------------------------------------------------
	Receive the Conpub Contents Add Message
----------------------------------------------------------------------------------------*/

typedef struct ConpubRegisterJobNode {
	ConpubRegisterJob* job;
	struct ConpubRegisterJobNode* next;
} ConpubRegisterJobNode;

typedef struct {
	ConpubRegisterJobNode* head;
	ConpubRegisterJobNode* tail;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
} ConpubRegisterQueue;

static ConpubRegisterQueue conpub_reg_queue;
#define CONPUB_CHUNK_SIZE 65536
#define CONPUB_REGISTER_WORKER_NUM 1

static void
conpub_register_queue_init(void)
{
	memset(&conpub_reg_queue, 0, sizeof(conpub_reg_queue));
	pthread_mutex_init(&conpub_reg_queue.mutex, NULL);
	pthread_cond_init(&conpub_reg_queue.cond, NULL);
}

static void
conpub_register_queue_push(ConpubRegisterJob* job)
{
	ConpubRegisterJobNode* node;

	node = malloc(sizeof(*node));
	if (!node) {
		return;
	}

	node->job = job;
	node->next = NULL;

	pthread_mutex_lock(&conpub_reg_queue.mutex);

	if (conpub_reg_queue.tail) {
		conpub_reg_queue.tail->next = node;
	} else {
		conpub_reg_queue.head = node;
	}
	conpub_reg_queue.tail = node;

	pthread_cond_signal(&conpub_reg_queue.cond);
	pthread_mutex_unlock(&conpub_reg_queue.mutex);
}

static ConpubRegisterJob*
conpub_register_queue_pop(void)
{
	ConpubRegisterJobNode* node;
	ConpubRegisterJob* job;

	pthread_mutex_lock(&conpub_reg_queue.mutex);

	while (!conpub_reg_queue.head) {
		pthread_cond_wait(&conpub_reg_queue.cond, &conpub_reg_queue.mutex);
	}

	node = conpub_reg_queue.head;
	conpub_reg_queue.head = node->next;
	if (!conpub_reg_queue.head) {
		conpub_reg_queue.tail = NULL;
	}

	pthread_mutex_unlock(&conpub_reg_queue.mutex);

	job = node->job;
	free(node);
	return job;
}

/* =============================================================================
 * Background thread to add content
 * ========================================================================== */
static void*
conpubd_register_worker_thread(void* arg)
{
	(void)arg;

	for (;;) {
		ConpubRegisterJob* job;

		job = conpub_register_queue_pop();
		if (!job) {
			continue;
		}

		/*--------------------------------------------------------------*
			In conpubd, the expiration time is managed with a precision
			of days, hours, and minutes (with seconds fixed at 0).
		 *--------------------------------------------------------------*/
		time_t t_exp = job->expiry;
		struct tm tm_exp = *localtime(&t_exp);
		tm_exp.tm_sec = 0;      // set seconds to 0
		job->expiry = mktime(&tm_exp);

		conpubd_register_job_execute(job);
	}
	return NULL;
}

static void
conpubd_register_workers_start(void)
{
	int i;
	pthread_t tid;

	for (i = 0; i < CONPUB_REGISTER_WORKER_NUM; i++) {
		pthread_create(&tid, NULL,
			conpubd_register_worker_thread, NULL);
		pthread_detach(tid);
	}
	cef_log_write(CefC_Log_Info,
	"conpub register worker started (%d threads)\n",
	CONPUB_REGISTER_WORKER_NUM);

}

static void*
conpubd_register_job_execute(ConpubRegisterJob* reg_job)
{
	time_t now_time;
	time_t timer;
	struct tm* local;
	CefT_Cpubcnt_Hdl* add_cont = NULL;
	uint64_t cob_num = 0;
	int res = 0;
	int success = 0;
	char Uri_buff_p[CefC_NAME_MAXLEN] = {0};

	if (!reg_job || !reg_job->hdl) {
		goto END;
	}

	timer = time (NULL);
	local = localtime (&timer);
	now_time = mktime (local);

	cef_frame_conversion_name_to_uri(
		reg_job->name,
		(reg_job->name_len > CefC_NAME_MAXLEN ? CefC_NAME_MAXLEN : reg_job->name_len),
		Uri_buff_p
	);

#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Finer, "%s(%d) entry, %s, expiry="FMTU64", t_pending="FMTU64"\n",
	__func__, __LINE__, Uri_buff_p, reg_job->expiry, reg_job->t_pending);
#endif // CefC_Debug
	/* ---------- check file path ---------- */
	res = conpub_check_file_path(reg_job->filepath);
	if (res < 0) {
		cef_log_write(CefC_Log_Warn,
			"%s, Fail to open %s\n", Uri_buff_p, reg_job->filepath);
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) error, %s\n",
		__func__, __LINE__, Uri_buff_p);
#endif // CefC_Debug
		goto END;
	}

	/* ---------- calculate cob_num ---------- */
	{
		struct stat statBuf;
		if (stat(reg_job->filepath, &statBuf) != 0) {
			cef_log_write(CefC_Log_Warn,
				"stat error %s\n", reg_job->filepath);
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) error, %s\n",
		__func__, __LINE__, Uri_buff_p);
#endif // CefC_Debug
			goto END;
		}

		if (reg_job->hdl->block_size == 0) {
			cef_log_write(CefC_Log_Warn,
				"block_size is zero\n");
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) error, %s\n",
		__func__, __LINE__, Uri_buff_p);
#endif // CefC_Debug
			goto END;
		}

		cob_num = statBuf.st_size / reg_job->hdl->block_size;
		if (statBuf.st_size % reg_job->hdl->block_size != 0) {
			cob_num++;
		}
	}

	/* ---------- allocate handle ---------- */
	add_cont = calloc(1, sizeof(CefT_Cpubcnt_Hdl));
	if (!add_cont) {
		cef_log_write(CefC_Log_Warn, "%s(%d), calloc failure\n", __func__, __LINE__);
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) error, %s\n",
		__func__, __LINE__, Uri_buff_p);
#endif // CefC_Debug
		goto END;
	}

	/* ---------- file path ---------- */
	snprintf(add_cont->file_path,
		sizeof(add_cont->file_path),
		"%s",
		reg_job->filepath);

	/* ---------- name ---------- */
	if (reg_job->name_len == 0 ||
		reg_job->name_len > sizeof(add_cont->name)) {

		cef_log_write(CefC_Log_Warn,
			"name_len overflow (%u > %zu)\n",
			reg_job->name_len,
			sizeof(add_cont->name));
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) error, %s\n",
		__func__, __LINE__, Uri_buff_p);
#endif // CefC_Debug
		goto END;
	}

	memcpy(add_cont->name, reg_job->name, reg_job->name_len);
	add_cont->name_len = reg_job->name_len;

	/* ---------- metadata ---------- */
	add_cont->expiry    = reg_job->expiry;
	add_cont->date      = time(NULL);
	add_cont->cob_num   = cob_num;
	add_cont->line_no   = -99;
	add_cont->t_pending = reg_job->t_pending;

	/* ---------- store into cache ---------- */
	res = conpubd_publish_content_create (reg_job->hdl, add_cont, now_time);
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Finer, "%s(%d) conpubd_publish_content_create(%s)=%d\n",
		__func__, __LINE__, Uri_buff_p, res);
#endif // CefC_Debug

	if (res < 0) {
		cef_log_write (CefC_Log_Warn, "Failed to conpubd_publish_content_create(%s)=%d\n", Uri_buff_p, res);
		goto END;
	}

	/* ---------- update linked list ---------- */
	pthread_mutex_lock(&conpub_cnt_mutex);
	{
		CefT_Cpubcnt_Hdl* work = &Cpubcnthdl;
		while (work->next) {
			work = work->next;
		}
		work->next = add_cont;
#ifdef CefC_Db
		conpubd_cnthdl_save(reg_job->hdl, &Cpubcnthdl);
#endif // CefC_Db
	}
	pthread_mutex_unlock(&conpub_cnt_mutex);

	reg_job->hdl->published_contents_num++;
	success = 1;

END:
	/* ---------- conpubcont.def append ---------- */
	if (success) {
		char datebuf[BUFSIZ_32];
		char timebuf[BUFSIZ_32];
		struct tm tmbuf;
		time_t tt = (time_t)reg_job->expiry;
		FILE* fp;

		localtime_r(&tt, &tmbuf);
		strftime(datebuf, sizeof(datebuf), "%Y-%m-%d", &tmbuf);
		strftime(timebuf, sizeof(timebuf), "%H:%M", &tmbuf);

		pthread_mutex_lock(&conpub_cnt_mutex);

		fp = fopen(conpub_contdef_path, "a");
		if (fp) {
			fprintf(fp,
				"%s %s %s %s",
				Uri_buff_p,
				reg_job->filepath,
				datebuf,
				timebuf);
			if (reg_job->t_pending > 0) {
				fprintf(fp, " "FMTU64, reg_job->t_pending);
			}
			fprintf(fp, "\n");

			fflush(fp);
			fsync(fileno(fp));
			fclose(fp);
		}
		pthread_mutex_unlock(&conpub_cnt_mutex);

		conpubd_appreg_api(reg_job->hdl->cefnetd_sock, CefC_T_OPT_APP_REG, reg_job->name, reg_job->name_len);
	}

	if (!success && add_cont) {
		free(add_cont);
	}
	free(reg_job);

	return NULL;
}

static void
conpubd_start_cont_recv_thread (
	CefT_Conpubd_Handle* hdl,
	int sock,
	uint8_t msg_type,
	unsigned char* msg,
	int msg_len,
	unsigned char* payload,
	int payload_len
) {
	ConpubRecvJob* recv_job;
	pthread_t th;
	uint16_t index = 0;
	uint64_t value64;
	uint16_t value16;
	char uri[CefC_NAME_MAXLEN];

#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Finer, "%s(%d) sock=%d, msg_type=0x%02x, msg_len=%d, payload_len=%d\n",
	__func__, __LINE__, sock, msg_type, msg_len, payload_len);
#endif // CefC_Debug

	recv_job = calloc(1, sizeof(ConpubRecvJob));
	if (!recv_job) {
		cef_log_write(CefC_Log_Warn, "%s(%d), calloc failure\n", __func__, __LINE__);
		close(sock);
		return;
	}

	recv_job->hdl = hdl;
	recv_job->peer_fd = sock;
	recv_job->msg_type = msg_type;

	/* ===== Expiry ===== */
	memcpy(&value64, msg + index, sizeof(uint64_t));
	recv_job->recv_expiry = cef_client_ntohb(value64);
	index += sizeof(uint64_t);

#ifdef	CefC_Csmgr_Msg_Type_CnpbUcincAdd
	/* ===== PendingTimer (ucinc only) ===== */
	if (msg_type == CefC_Csmgr_Msg_Type_CnpbUcincAdd) {
		memcpy(&value64, msg + index, sizeof(uint64_t));
		recv_job->recv_t_pending = cef_client_ntohb(value64);
		index += sizeof(uint64_t);
	}
#else	// CefC_Csmgr_Msg_Type_CnpbUcincAdd
	recv_job->recv_t_pending = 0UL;
#endif	// CefC_Csmgr_Msg_Type_CnpbUcincAdd

#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Finer, "%s(%d) recv_expiry="FMTU64", recv_t_pending="FMTU64"\n",
	__func__, __LINE__, recv_job->recv_expiry, recv_job->recv_t_pending);
#endif // CefC_Debug

	/* ===== Name ===== */
	memcpy(&value16, msg + index, sizeof(uint16_t));
	recv_job->recv_name_len = ntohs(value16);
	index += sizeof(uint16_t);

	if (recv_job->recv_name_len == 0 || recv_job->recv_name_len > sizeof(recv_job->recv_name)) {
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) recv_name_len=%d\n",
	__func__, __LINE__, recv_job->recv_name_len);
#endif // CefC_Debug
		cef_log_write(CefC_Log_Warn, "%s(%d) Illegal name length. (%d)\n",
			__func__, __LINE__, recv_job->recv_name_len);
		free(recv_job);
		close(sock);
		return;
	}

	memcpy(recv_job->recv_name, msg + index, recv_job->recv_name_len);
	index += recv_job->recv_name_len;
	cef_frame_conversion_name_to_uri (recv_job->recv_name, recv_job->recv_name_len, uri);

	/* ===== Check URI duplicate ===== */
	int f = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, f & ~O_NONBLOCK);

	pthread_mutex_lock(&conpub_cnt_mutex);
	CefT_Cpubcnt_Hdl *work = Cpubcnthdl.next;
	while (work) {
		if ( (work->name_len == recv_job->recv_name_len)
			&& memcmp (work->name, recv_job->recv_name, recv_job->recv_name_len) == 0) {
			int	ret;
			char msgbuff[BUFSIZ], uri[CefC_NAME_MAXLEN];
			cef_frame_conversion_name_to_uri (recv_job->recv_name, recv_job->recv_name_len, uri);
			snprintf(msgbuff, sizeof(msgbuff), "%s is already registered\n", uri);
			cef_csmgr_send_msg(sock, (unsigned char *)msgbuff, strlen(msgbuff));
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) %s\n",
	__func__, __LINE__, msgbuff);
#endif // CefC_Debug
			cef_log_write (CefC_Log_Warn, "%s", msgbuff);
			while ( 0 < (ret = read(sock, msgbuff, sizeof(msgbuff))) );		// Suck up and discard
			close(sock);
			free(recv_job);
			pthread_mutex_unlock(&conpub_cnt_mutex);
			return;
		}
		work = work->next;
	}
	pthread_mutex_unlock(&conpub_cnt_mutex);

	/* ===== FileSize ===== */
	memcpy(&value64, msg + index, sizeof(uint64_t));
	recv_job->file_size = cef_client_ntohb(value64);
	index += sizeof(uint64_t);

#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Finest, "%s(%d) add content uri=%s, file_size="FMTU64"\n",
		__func__, __LINE__, uri, recv_job->file_size);
#endif // CefC_Debug

#ifdef	CefC_Csmgr_Msg_Type_CnpbUcincAdd
	/* ===== PublicKey (ucinc only) ===== */
	if (msg_type == CefC_Csmgr_Msg_Type_CnpbUcincAdd) {
		memcpy(&value16, msg + index, sizeof(uint16_t));
		recv_job->recv_pubkey_len = ntohs(value16);
		index += sizeof(uint16_t);

		if (recv_job->recv_pubkey_len > 0) {
			recv_job->recv_pubkey = malloc(recv_job->recv_pubkey_len);
			memcpy(recv_job->recv_pubkey, msg + index, recv_job->recv_pubkey_len);
			index += recv_job->recv_pubkey_len;
		}
	}
#else	// CefC_Csmgr_Msg_Type_CnpbUcincAdd
	recv_job->recv_pubkey = NULL;
	recv_job->recv_pubkey_len = 0UL;
#endif	// CefC_Csmgr_Msg_Type_CnpbUcincAdd

	/* ===== first payload ===== */
	if (payload_len > 0) {
		if ((uint64_t)payload_len > recv_job->file_size)
			payload_len = recv_job->file_size;

		recv_job->recv_payload = malloc(payload_len);
		if (recv_job->recv_payload) {
			memcpy(recv_job->recv_payload, payload, payload_len);
			recv_job->recv_payload_len = payload_len;
		}
	}

	pthread_create(&th, NULL, conpubd_cont_recv_thread, recv_job);
	pthread_detach(th);
}

static void*
conpubd_cont_recv_thread (void* arg)
{
	ConpubRecvJob *recv_job = arg;
	ConpubRegisterJob *reg_job;
	char poolfile_path[PATH_MAX];
	char pubkey_path[PATH_MAX];
	int fd = -1;
	int kfd = -1;
	uint64_t left;
	ssize_t w;
	unsigned char buf[CONPUB_CHUNK_SIZE];
	char uri[CefC_NAME_MAXLEN];

	if ( !recv_job || !recv_job->hdl ){
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) Failed to start.\n",
		__func__, __LINE__);
#endif // CefC_Debug
		return NULL;
	}

	cef_frame_conversion_name_to_uri (recv_job->recv_name, recv_job->recv_name_len, uri);

	/* pool file path (avoid collision) */
	snprintf(poolfile_path, sizeof(poolfile_path),
		"%s/conpubcont_%ld_%d",
		recv_job->hdl->cache_path, time(NULL), recv_job->peer_fd);

	cef_log_write(CefC_Log_Info, "%s(%s) "FMTU64" bytes\n", __func__, uri, recv_job->file_size);

#ifdef CefC_Debug
conpubd_dbg_write(CefC_Dbg_Fine, "%s(%d) %s ("FMTU64" bytes)\n",
		__func__, __LINE__, uri, recv_job->file_size);
conpubd_dbg_write(CefC_Dbg_Fine, "%s(%d) write a temporary file %s\n",
		__func__, __LINE__,  poolfile_path);
#endif // CefC_Debug

#define	Conpubd_FilePermission	0666
	fd = open(poolfile_path, O_CREAT | O_WRONLY | O_TRUNC, Conpubd_FilePermission);
	if (fd < 0){
		cef_log_write(CefC_Log_Warn, "Failed to create a temporary file. (%s)\n", poolfile_path);
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) Failed to create a temporary file. (%s)\n",
		__func__, __LINE__, poolfile_path);
#endif // CefC_Debug
		goto out;
	}

	/* write public key (ucinc only) */
	if (recv_job->recv_pubkey_len > 0 && recv_job->recv_pubkey != NULL) {
		int len = snprintf(pubkey_path, sizeof(pubkey_path),
			"%s.pubkey", poolfile_path);
		if (len < 0 || len >= sizeof(pubkey_path)) {
			cef_log_write(CefC_Log_Warn, "Failed to create a pubkey file. (%s)\n", pubkey_path);
			goto out;
		}
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) create a temporary pubkey file. (%s)\n",
		__func__, __LINE__, pubkey_path);
#endif // CefC_Debug

		kfd = open(pubkey_path, O_CREAT | O_WRONLY | O_TRUNC, Conpubd_FilePermission);
		if (kfd >= 0) {
			w = write(kfd, recv_job->recv_pubkey, recv_job->recv_pubkey_len);
			if ( w != recv_job->recv_pubkey_len ){
				cef_log_write(CefC_Log_Warn, "Failed to write a pubkey file. (%s)\n", pubkey_path);
			}
			close(kfd);
			kfd = -1;
		} else {
			cef_log_write(CefC_Log_Warn, "Failed to open a pubkey file. (%s)\n", pubkey_path);
		}
	}

	left = recv_job->file_size;

	/* write first payload already received */
	if (recv_job->recv_payload_len > 0 && recv_job->recv_payload != NULL) {
		w = write(fd, recv_job->recv_payload, recv_job->recv_payload_len);
		if ( w != recv_job->recv_payload_len ){
			cef_log_write(CefC_Log_Warn, "Failed to write a recv_payload. (write_len=%zd)\n", w);
		}
		left -= recv_job->recv_payload_len;
	}

#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Finest, "%s(%d) left="FMTU64"\n",
		__func__, __LINE__, left);
#endif // CefC_Debug

	/* receive remaining content */
	while (left > 0) {
		ssize_t r = recv(recv_job->peer_fd, buf,
			(left > CONPUB_CHUNK_SIZE) ? CONPUB_CHUNK_SIZE : left,
			0);
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Finest, "%s(%d) recv()=%zd\n",
		__func__, __LINE__, r);
#endif // CefC_Debug
		if (r <= 0)
			break;

		w = write(fd, buf, r);
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Finest, "%s(%d) write()=%zd\n",
		__func__, __LINE__, w);
#endif // CefC_Debug
		left -= r;
	}

	if ( 0 < left ){
		cef_log_write(CefC_Log_Warn, "Failed to write a temporary file. (left="FMTU64")\n", left);
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) Failed to write a temporary file. (left="FMTU64")\n",
		__func__, __LINE__, left);
#endif // CefC_Debug
	}

	fsync(fd);
	close(fd);
	fd = -1;

	/* enqueue register recv_job */
	reg_job = calloc(1, sizeof(ConpubRegisterJob));
	if ( reg_job ){
		reg_job->hdl = recv_job->hdl;

		memcpy(reg_job->name, recv_job->recv_name, recv_job->recv_name_len);
		reg_job->name_len = recv_job->recv_name_len;

		snprintf(reg_job->filepath,
			sizeof(reg_job->filepath),
			"%s", poolfile_path);

		/* ucinc only */
		if (recv_job->recv_pubkey_len > 0) {
			int len = snprintf(reg_job->pubkey_path,
				sizeof(reg_job->pubkey_path),
				"%s.pubkey", poolfile_path);
			if (len < 0 || len >= sizeof(pubkey_path)) {
				goto out;
			}
		} else {
			reg_job->pubkey_path[0] = '\0';
		}
		reg_job->expiry = recv_job->recv_expiry;
		reg_job->t_pending = recv_job->recv_t_pending;

		conpub_register_queue_push(reg_job);
	} else {
		cef_log_write(CefC_Log_Warn, "%s(%s), calloc failure\n", __func__, uri);
	}

out:
	if (fd >= 0)
		close(fd);
	if (kfd >= 0)
		close(kfd);

	if (recv_job->peer_fd >= 0)
		close(recv_job->peer_fd);

	if ( recv_job->recv_payload )
		free(recv_job->recv_payload);
	if ( recv_job->recv_pubkey )
		free(recv_job->recv_pubkey);
	free(recv_job);

	return NULL;
}
/*--------------------------------------------------------------------------------------
	Receive the Conpub Contents Delete Message
----------------------------------------------------------------------------------------*/
static ConpubDelJob* delq_head = NULL;
static ConpubDelJob* delq_tail = NULL;
static pthread_mutex_t conpub_def_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t delq_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  delq_cond  = PTHREAD_COND_INITIALIZER;
static void* conpubd_cont_del_worker(void* arg);
#define CONPUB_DELETE_WORKER_NUM 1

static void
conpubd_delete_workers_start(void)
{
	int i;
	pthread_t tid;

	for (i = 0; i < CONPUB_DELETE_WORKER_NUM; i++) {
		pthread_create(&tid, NULL,
			conpubd_cont_del_worker, NULL);
		pthread_detach(tid);
	}

	cef_log_write(CefC_Log_Info,
		"conpub delete worker started (%d threads)\n",
		CONPUB_DELETE_WORKER_NUM);
}

static int
conpubd_remove_def_line_and_tmp (
	const char* req_uri
) {
	FILE* fp = NULL;
	char line[BUFSIZ_8K];
	char uri[CefC_NAME_MAXLEN];
	char tmpfile[PATH_MAX-BUFSIZ_64];
	char pubkeyfile[PATH_MAX];
	char datebuf[BUFSIZ_32];
	char timebuf[BUFSIZ_32];

	char* newbuf = NULL;
	size_t newlen = 0;
	size_t newcap = 0;

	int found = 0;
	int ret = -1;
	int len = 0;

	pthread_mutex_lock(&conpub_def_mutex);

#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Finer, "%s(%d) req_uri=%s\n",
		__func__, __LINE__, req_uri);
#endif // CefC_Debug

	fp = fopen(conpub_contdef_path, "r+");
	if (!fp) {
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Finer, "%s(%d) Failed to open, %s\n", __func__, __LINE__, conpub_contdef_path);
#endif // CefC_Debug
		cef_log_write(CefC_Log_Warn, "Failed to open, %s\n", conpub_contdef_path);
		perror("fopen def");
		goto out;
	}

	while (fgets(line, sizeof(line), fp)) {

		if (line[0] != '#'
			&& sscanf(
				line,
				"%1023s %959s %31s %31s",		/* 1024-64=960 for MacOS */
				uri, tmpfile, datebuf, timebuf
			) == 4) {

			if (strcmp(uri, req_uri) == 0) {
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Finer, "%s(%d) unlink, %s\n", __func__, __LINE__, tmpfile);
#endif // CefC_Debug
				if (unlink(tmpfile) != 0) {
					char buff[BUFSIZ];
					sprintf(buff, "unlink %s, error=%d:%s", tmpfile, errno, strerror(errno));
					cef_log_write(CefC_Log_Warn, "%s\n", buff);
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) %s\n", __func__, __LINE__, buff);
#endif // CefC_Debug
				}

				len = snprintf(pubkeyfile, sizeof(pubkeyfile),
					"%s.pubkey", tmpfile);
				if (len < 0 || len >= sizeof(pubkeyfile)) {
					cef_log_write(CefC_Log_Warn, "pubkeyfile path too long, %s\n", pubkeyfile);
					return -1;
				}
				if (access(pubkeyfile, F_OK) == 0) {
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Finer, "%s(%d) unlink, %s\n", __func__, __LINE__, pubkeyfile);
#endif // CefC_Debug
					if (unlink(pubkeyfile) != 0) {
					char buff[BUFSIZ];
					sprintf(buff, "unlink %s, error=%d:%s", pubkeyfile, errno, strerror(errno));
					cef_log_write(CefC_Log_Warn, "%s\n", buff);
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) %s\n", __func__, __LINE__, buff);
#endif // CefC_Debug
					}
				}

				found = 1;
				continue;
			}
		}

		size_t len = strlen(line);
		if (newlen + len + 1 > newcap) {
			newcap = (newcap == 0) ? 4096 : newcap * 2;
			newbuf = realloc(newbuf, newcap);
			if (!newbuf) {
				perror("realloc");
				goto out;
			}
		}
		memcpy(newbuf + newlen, line, len);
		newlen += len;
	}

	if (!found) {
		goto out;
	}

	rewind(fp);
	if (ftruncate(fileno(fp), 0) != 0) {
		perror("ftruncate");
		goto out;
	}

	if (newlen > 0) {
		fwrite(newbuf, 1, newlen, fp);
	}

	fflush(fp);
	fsync(fileno(fp));

	ret = 0;

out:
	if (fp) {
		fclose(fp);
	}
	free(newbuf);

	pthread_mutex_unlock(&conpub_def_mutex);
	return ret;
}

static void*
conpubd_cont_del_worker (void* arg)
{
	for (;;) {
		ConpubDelJob* job = NULL;

		pthread_mutex_lock(&delq_mutex);
		while (delq_head == NULL) {
			pthread_cond_wait(&delq_cond, &delq_mutex);
		}
		job = delq_head;
		delq_head = job->next;
		if (delq_head == NULL)
			delq_tail = NULL;
		pthread_mutex_unlock(&delq_mutex);

		unsigned char ret_buff[BUFSIZ_8K];
		uint16_t index = 0;
		uint16_t value16;
		char* rspmsg;

		/* Header */
		ret_buff[CefC_O_Fix_Ver]  = CefC_Version;
		ret_buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_CnpbCntDel;
		index += CefC_Csmgr_Msg_HeaderLen;

		int find_f = 0;
		CefT_Cpubcnt_Hdl* work;
		//CefT_Cpubcnt_Hdl* bwork;

		pthread_mutex_lock(&conpub_cnt_mutex);

		//bwork = &Cpubcnthdl;
		work  = Cpubcnthdl.next;

		while (work) {
			if (work->name_len == job->name_len &&
			    memcmp(work->name, job->name, job->name_len) == 0) {

				find_f = 1;
				break;
			}
			//bwork = work;
			work = work->next;
		}

		if (find_f) {
			time_t now = time(NULL);
			work->expiry = now;
			conpubd_stat_content_lifetime_update(
				stat_hdl, job->name, job->name_len, now);

			// do conpubd_expire_check_thread !!
			expire_check_time = cef_client_present_timeus_calc () + 1000000llu;
#ifdef	CefC_T_Expire_Delay
			expire_check_time += (CefC_T_Expire_Delay * 1000000llu);
#endif	// CefC_T_Expire_Delay
#ifdef CefC_Debug
conpubd_dbg_write (CefC_Dbg_Fine, "%s(%d) %s, expire_check_time="FMTU64"\n", __func__, __LINE__, job->uri, expire_check_time);
#endif // CefC_Debug

			conpubd_remove_def_line_and_tmp(
				job->uri
			);

			rspmsg = "Content Delete request accepted.";
		} else {
			rspmsg = "There is no content with the specified name.";
		}

		pthread_mutex_unlock(&conpub_cnt_mutex);

		strcpy((char*)(ret_buff + index), rspmsg);
		index += strlen(rspmsg) + 1;

		value16 = htons(index);
		memcpy(ret_buff + CefC_O_Length, &value16, CefC_S_Length);

		cef_csmgr_send_msg(job->sock, ret_buff, index);
		close(job->sock);
	}
	return NULL;
}

static void
conpubd_incoming_cont_del_msg (
	CefT_Conpubd_Handle* hdl,
	int sock,
	unsigned char* buff,
	int buff_len
) {
	uint32_t idx = 0;
	uint16_t v16;

	ConpubDelJob* job = calloc(1, sizeof(ConpubDelJob));
	job->hdl  = hdl;
	job->sock = sock;

	memcpy(&v16, buff + idx, sizeof(uint16_t));
	job->name_len = ntohs(v16);
	idx += sizeof(uint16_t);

	memcpy(job->name, buff + idx, job->name_len);
	idx += job->name_len;

	cef_frame_conversion_name_to_uri (job->name, job->name_len, job->uri);

	/* enqueue */
	pthread_mutex_lock(&delq_mutex);
	if (delq_tail)
		delq_tail->next = job;
	else
		delq_head = job;
	delq_tail = job;
	pthread_cond_signal(&delq_cond);
	pthread_mutex_unlock(&delq_mutex);
}


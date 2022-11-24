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

/****************************************************************************************
 Macros
 ****************************************************************************************/

#define CefC_Name_Max_Length	2048

/* Macros used in resource management processing */
#define CefC_Cpub_CS_Init_Mem_Utilization_Factor 0.9
#define CefC_Cpub_Memory_Usage_Correction_Factor 1.5
#define CefC_Cpub_Reserved_Disk_Mega 			 1000

#define CefC_Cpub_InconsistentVersion			-1000


/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

/* Content management entry */
typedef struct _CefT_Cpubcnt_Hdl {
	
	unsigned char 		name[CefC_Name_Max_Length];
	int 				name_len;
	unsigned char 		version[CefC_Name_Max_Length];
	int 				version_len;
	char 				file_path[PATH_MAX];
	time_t 				date;					/* date of upload */
	time_t 				expiry;
	uint64_t 			interests;
	uint64_t			cob_num;
	int					line_no;
	struct _CefT_Cpubcnt_Hdl* next;
	
} CefT_Cpubcnt_Hdl;

/* Catalog Data entry */
typedef struct _CefT_Cpubctlg_Hdl {
	
	unsigned char*		name;
	int 				name_len;
	unsigned char*		version;
	int 				version_len;
	
	struct _CefT_Cpubctlg_Hdl* next;
} CefT_Cpubctlg_Hdl;

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

static CefT_Cpubctlg_Hdl Cpbctlghdl;					/* Catalog Data entry */

/* Work areas */
static CefT_Object_TLVs* 	Cob_prames_p = NULL;
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
#ifdef CefC_Ccninfo
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
#endif // CefC_Ccninfo
/*--------------------------------------------------------------------------------------
	Receive Increment Access Count message
----------------------------------------------------------------------------------------*/
static void
conpubd_incoming_increment_msg (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
);
#if defined (CefC_Cefping) || defined (CefC_Ccninfo)
/*--------------------------------------------------------------------------------------
	Incoming cefping message
----------------------------------------------------------------------------------------*/
static void
conpubd_incoming_cefping_msg (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
);
/*--------------------------------------------------------------------------------------
	Send cefping response message
----------------------------------------------------------------------------------------*/
static void
conpubd_cefping_response_send (
	int sock,									/* recv socket							*/
	uint8_t result								/* result								*/
);
#endif // (CefC_Cefping || CefC_Ccninfo)
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
	char* ver,									/* Version string after trimming		*/
	char* path,									/* Path string after trimming			*/
	char* date,									/* Date string after trimming			*/
	char* time
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
	Creates SHA256 from the specified file 
----------------------------------------------------------------------------------------*/
static int
conpubd_check_version_char (
	char* ver
);
/*--------------------------------------------------------------------------------------
	Compare ver1 and ver2
----------------------------------------------------------------------------------------*/
static int
conpubd_version_compare (
	unsigned char* ver1,
	uint32_t vlen1,
	unsigned char* ver2,
	uint32_t vlen2
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
	Respond with public identifier
----------------------------------------------------------------------------------------*/
static void 
conpubd_version_respond (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	CefT_Cpubcnt_Hdl* 	entry,
	int 				sock
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
/*--------------------------------------------------------
	Inits Catalog Data
----------------------------------------------------------*/
static void
conpubd_catalog_data_init (
	void
);
/*--------------------------------------------------------
	Destroy Catalog Data
----------------------------------------------------------*/
static void
conpubd_catalog_data_destory (
	void
);
/*--------------------------------------------------------
	Create Catalog Data
----------------------------------------------------------*/
static void
conpubd_catalog_data_create (
	void
);

#ifdef CefC_Debug
static void
conpubd_dbg_convert_name_to_str_put_workstr (
	unsigned char* name_p,
	int name_len
);
#endif //CefC_Debug

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
#ifdef CefC_Debug
	cef_dbg_init ("conpubd", file_path, 2);
#endif
	
	/* 	Sets the path of conpubd.conf*/
	res = conpubd_plugin_config_dir_set (file_path);
	if (res < 0) {
		cef_log_write (CefC_Log_Error, "Failed to read conpubd.conf.\n");
		return (-1);
	}
	/* 	Sets the path of conpubcont.def*/
	res = conpubd_contdef_dir_set (file_path);
	if (res < 0) {
		cef_log_write (CefC_Log_Error, "Failed to read conpubcont.def.\n");
		return (-1);
	}
	/* Create conpubd handle */
	hdl = conpubd_handle_create ();
	if (hdl == NULL) {
		cef_log_write (CefC_Log_Error, "Unable to create conpubd handle.\n");
		conpubd_post_process (hdl);
		return (-1);
	}
	/* Get free memory size */
	conpubd_free_memsize_get (&free_mem_mega);
	if (strcmp(hdl->cache_type, CefC_Cnpb_memory_Cache_Type) == 0
		  &&
		free_mem_mega < Intial_free_mem_mega * CefC_Cpub_CS_Init_Mem_Utilization_Factor) {
		cef_log_write (CefC_Log_Error, 
		    "The memory content hash table is too large.\n"
			"Decrease the value of the parameter (CONTENTS_CAPACITY).\n"
			"	(Detected Intial Free Memory Size="FMTU64"MB\n"
			"	 Current Free Memory Size="FMTU64"MB)\n",
			Intial_free_mem_mega,
			free_mem_mega);
		conpubd_post_process (hdl);
		return (-1);
	}
	
	/* Create work areas */
	if ((Cob_prames_p = calloc (1, sizeof (CefT_Object_TLVs))) == NULL) {
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
	if ((Uri_buff_p = calloc (1, CefC_Name_Max_Length)) == NULL) {
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
		if (pthread_create (&th, NULL, conpubd_content_load_thread, hdl) == -1) {
			cef_log_write (CefC_Log_Error, "Failed to create the new thread\n");
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
			(unsigned char*) malloc (sizeof (unsigned char) * CefC_Cefnetd_Buff_Max);
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
		
	cef_log_write (CefC_Log_Info, "Running\n");
	
	if (pthread_create (&conpubd_expire_check_th, NULL, conpubd_expire_check_thread, hdl) == -1) {
		cef_log_write (CefC_Log_Error, "Failed to create the new thread\n");
		conpubd_running_f = 0;
	}
	
	/* Main loop */
	cef_client_init (0, "");
	
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
					CefC_Cefnetd_Buff_Max - hdl->tcp_index[fds_index[i]], 0);
				if (len > 0) {
					/* receive message */
					len += hdl->tcp_index[fds_index[i]];
					if (fds[i].fd != hdl->cefnetd_sock) {
						len = conpub_input_bytes_process (
								hdl, fds[i].fd, 
								&hdl->tcp_buff[fds_index[i]][0], len);
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
								/* Version Request: Version response necessity check for management content */
								if (app_request.version_f == 1 && app_request.ver_len == 0) {
									CefT_Cpubcnt_Hdl* exist;
#ifdef CefC_Debug
									cef_dbg_write (CefC_Dbg_Finest, "    (Version Request)\n");
#endif // CefC_Debug
									if ((exist=conpubd_content_reg_check (hdl, app_request.name, app_request.total_segs_len)) != NULL) {
										/* Respond with version */
										conpubd_version_respond (hdl, exist, fds[i].fd);
										break;
									}
								}
								
								{
									CefT_Cpubcnt_Hdl* exist;
									if ((exist=conpubd_content_reg_check (hdl, app_request.name, app_request.total_segs_len)) != NULL) {
										if (app_request.version_f == 0 ||
											(app_request.ver_len == exist->version_len &&
											memcmp(app_request.ver_value, exist->version, app_request.ver_len) == 0)) {
											;/* exist */
										} else {
											/* Don't have requested version */
											break;
										}
									} else {
										break;
									}
								}
								
								/* Searches and sends a Cob */
								hdl->cs_mod_int->cache_item_get 
													(app_request.name, app_request.total_segs_len, app_request.chunk_num, fds[i].fd, app_request.ver_value, app_request.ver_len);
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
	function for processing the expire check
----------------------------------------------------------------------------------------*/
static void* 
conpubd_expire_check_thread (
	void* arg
) {

	CefT_Conpubd_Handle* hdl = (CefT_Conpubd_Handle*) arg;
	uint64_t interval = (uint64_t) hdl->purge_interval;
	uint64_t nowt = cef_client_present_timeus_calc ();
	uint64_t expire_check_time = nowt + interval;
	uint64_t nowtsec = nowt / 1000000llu;
	
	while (conpubd_running_f) {
		sleep (1);
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
					if (wk->expiry < (time_t)nowtsec) {
						{
							char uri[CefC_Name_Max_Length];
							cef_frame_conversion_name_to_string (wk->name, wk->name_len, uri, "ccn");
							cef_log_write (CefC_Log_Info, "Deleted(expired) %s \n", uri);
						}
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
	int res;
	
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
		if (len > buff_len) {
			break;
		}
		/* check the type of message 			*/
		if (buff[index + CefC_O_Fix_Type] != CefC_Csmgr_Msg_Type_UpReq) {
			res = conpubd_input_message_process (hdl, peer_fd, 
				&buff[index + CefC_Csmgr_Msg_HeaderLen], len - CefC_Csmgr_Msg_HeaderLen, 
				buff[index + CefC_O_Fix_Type]);
			if (res < 0) {
				return (0);
			}
		} else {
			; /* NOP */
		}
		
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
			cef_log_write (CefC_Log_Error,
				"Cannot double boot conpubd.(Local socket file (conpub_xxxx.y) exists.)\n");
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
	char	file_name[PATH_MAX];						/* file name						*/
	char	param[4096] = {0};						/* parameter						*/
	char	param_buff[4096] = {0};					/* param buff						*/
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
	strcpy(conf_param->cache_type, 		  CefC_Cnpb_filesystem_Cache_Type);
	strcpy(conf_param->cache_path, 		  conpub_conf_dir);
	conf_param->purge_interval			= CefC_CnpbDefault_Purge_Interval;;
	conf_param->cache_default_rct	= CefC_CnpbDefault_Cache_Default_Rct;
	strcpy(conf_param->Valid_Alg,     CefC_CnpbDefault_Valid_Alg);
	conf_param->contents_num			= CefC_CnpbDefault_Contents_num;
	conf_param->contents_capacity	= CefC_CnpbDefault_Contents_Capacity;
	conf_param->block_size			= CefC_CnpbDefault_Block_Size;
	strcpy(conf_param->cefnetd_node,  CefC_CnpbDefault_Node_Path);
	conf_param->cefnetd_port		= CefC_CnpbDefault_Cefnetd_Port;
	
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
		} else 
		if (strcmp (option, "LOCAL_SOCK_ID") == 0) {
			if (strlen (value) > sizeof (conf_param->local_sock_id)-1) {
				cef_log_write (CefC_Log_Error, 
					"LOCAL_SOCK_ID must be less than or equal to 64.\n");
				fclose (fp);
				return (-1);
			}
			strcpy (conf_param->local_sock_id, value);
		} else 
		if (strcmp (option, "CACHE_TYPE") == 0) {
			if (strcmp (value, CefC_Cnpb_memory_Cache_Type) != 0
					&&
			    strcmp (value, CefC_Cnpb_filesystem_Cache_Type) != 0) {
				cef_log_write (CefC_Log_Error,
					"CACHE_TYPE is ivalid. (Invalid value %s=%s)\n", option, value);
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
				strcmp (value, "sha256") != 0
					&&
				strcmp (value, "crc32") != 0
			) {
				cef_log_write (CefC_Log_Error,
					"VALID_ALG must be \"NONE\", \"sha256\" or \"crc32\" "
					"(Invalid value %s=%s)\n", option, value);
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
				fclose (fp);
				return (-1);
			}
		} else 
		if (strcmp (option, "BLOCK_SIZE") == 0) {
			res = conpubd_config_value_get (option, value);
			if (!(1024 <= res && res <= 57344)) {
				cef_log_write (CefC_Log_Error, 
				"BLOCK_SIZE value must be greater than or equal to 1024 "
				"and less than or equal to 57344.\n");
				fclose (fp);
				return (-1);
			}
			conf_param->block_size = res;
		} else 
		if (strcmp (option, "CEFNETD_NODE") == 0) {
			if (strlen (value) > sizeof (conf_param->cefnetd_node)-1) {
				cef_log_write (CefC_Log_Error, 
					"CEFNETD_NODE must be less than or equal to 128.\n");
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
				fclose (fp);
				return (-1);
			}
			conf_param->cefnetd_port = res;
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
#endif // CefC_Debug

	/* Check FIB_SIZE_APP setting in the cefnetd.conf */
#if 0 //+++++ GCC v9 ++++
	char 	ws[1024];
	app_fib_max_size = CefC_Default_FibAppSize;
	cef_client_config_dir_get (ws);
	sprintf (ws, "%s/cefnetd.conf", ws);
	fp = fopen (ws, "r");
#else
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
#endif //----- GCC v9 ---
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
				fclose (fp);
				return (-1);
			}
			if (res >= CefC_FibAppSize_MAX) {
				cef_log_write (CefC_Log_Warn, "FIB_SIZE_APP must be lower than 1024000.\n");
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
		cef_log_write (CefC_Log_Error,
			"FIB_SIZE_APP setting in the cefnetd.conf must be greater than or equal to CONTENTS_NUM setting.\n"
			"	(FIB_SIZE_APP=%d, CONTENTS_NUM=%d)\n",
			app_fib_max_size, conf_param->contents_num);
		return (-1);
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
	struct sockaddr_storage* sa;
	socklen_t len = sizeof (struct sockaddr_storage);
	int cs;
	int flag;
	char ip_str[NI_MAXHOST];
	char port_str[NI_MAXSERV];
	int i;
	int new_accept_f = 1;
	int err;

	/* Accepts the TCP SYN 		*/
	sa = (struct sockaddr_storage*) malloc (sizeof (struct sockaddr_storage));
	memset (sa, 0, sizeof (struct sockaddr_storage));
	cs = accept (hdl->tcp_listen_fd, (struct sockaddr*) sa, &len);
	if (cs < 0) {
		free (sa);
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
	if ((err = getnameinfo ((struct sockaddr*) sa, len, ip_str, sizeof (ip_str),
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
	if (sa) {
		free (sa);
	}
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
static int							/* The return value is negative if an error occurs	*/
conpubd_input_message_process (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* msg,							/* receive message						*/
	int msg_len,								/* message length						*/
	uint8_t type								/* message type							*/
) {

	switch (type) {
		
#ifdef CefC_Ccninfo
		case CefC_Csmgr_Msg_Type_Ccninfo: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Ccninfo Message\n");
#endif // CefC_Debug
			conpubd_incoming_ccninfo_msg (hdl, sock, msg, msg_len);
			break;
		}
#endif // CefC_Ccninfo
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
#if defined (CefC_Cefping) || defined (CefC_Ccninfo)
		case CefC_Csmgr_Msg_Type_Cefping: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Cefping Message\n");
#endif // CefC_Debug
			conpubd_incoming_cefping_msg (hdl, sock, msg, msg_len);
			break;
		}
#endif // (CefC_Cefping || CefC_Ccninfo)
		case CefC_Csmgr_Msg_Type_Kill: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Kill Command\n");
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
#ifdef CefC_Ccninfo
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
#endif // CefC_Ccninfo
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
	uint32_t chnk_num;

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
	chnk_num = ntohl (value32);
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
	hdl->cs_mod_int->ac_cnt_inc (name, name_len, chnk_num);

	return;
}
#if defined (CefC_Cefping) || defined (CefC_Ccninfo)
/*--------------------------------------------------------------------------------------
	Incoming cefping message
----------------------------------------------------------------------------------------*/
static void
conpubd_incoming_cefping_msg (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
) {
	int res;
	
	/* Obtain cached content information 			*/
	res = conpubd_stat_content_info_gets (stat_hdl, buff, buff_len, 1, Stat_p);
	
	if (res > 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest, "Cob is exist.\n");
#endif // CefC_Debug
		/* Content is exist */
		conpubd_cefping_response_send (sock, CefC_Csmgr_Cob_Exist);
	} else {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest, "Cob is not exist.\n");
#endif // CefC_Debug
		/* Content is not exist */
		conpubd_cefping_response_send (sock, CefC_Csmgr_Cob_NotExist);
	}
	
	return;
}
/*--------------------------------------------------------------------------------------
	Send cefping response message
----------------------------------------------------------------------------------------*/
static void
conpubd_cefping_response_send (
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
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_Cefping;
	index += CefC_Csmgr_Msg_HeaderLen;

	/* Set result */
	memcpy (buff + index, &result, sizeof (uint8_t));
	index += sizeof (uint8_t);

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
#endif // (CefC_Cefping) || (CefC_Ccninfo)
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
			sizeof (struct CefT_Csmgr_CnpbStatus_TL) + work->version_len + 
			sizeof (struct CefT_Csmgr_CnpbStatus_TL) + (uint16_t) strlen (work->file_path) + 
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
		
		if (work->version_len == 0) {
			length = (uint16_t) 4;
			rsp_hdr.type   = htons (CefC_CnpbStatus_Version);
			rsp_hdr.length = htons (length);
			memcpy (&ret_buff[index], &rsp_hdr, sizeof (struct CefT_Csmgr_CnpbStatus_TL));
			index += sizeof (struct CefT_Csmgr_CnpbStatus_TL);
			memcpy (&ret_buff[index], "None", length);
		} else {
			length = (uint16_t) work->version_len;
			rsp_hdr.type   = htons (CefC_CnpbStatus_Version);
			rsp_hdr.length = htons (length);
			memcpy (&ret_buff[index], &rsp_hdr, sizeof (struct CefT_Csmgr_CnpbStatus_TL));
			index += sizeof (struct CefT_Csmgr_CnpbStatus_TL);
			memcpy (&ret_buff[index], work->version, length);
		}
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
		if (pthread_create (&th, NULL, conpubd_content_load_thread, hdl) == -1) {
			cef_log_write (CefC_Log_Error, "Failed to create the new thread\n");
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
	
	/* Reset Catalog Data */
	conpubd_catalog_data_destory ();
	
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
			foundf = 0;
			rld_bp = &Cpubreloadhdl;
			rld_wk = Cpubreloadhdl.next;
			while (rld_wk) {
				if ((cnt_wk->name_len == rld_wk->name_len)
					&& (memcmp (cnt_wk->name, rld_wk->name, rld_wk->name_len) == 0)) {
					/* Same name */
					int cmpver;
					cmpver = conpubd_version_compare (
								cnt_wk->version, cnt_wk->version_len, 
								rld_wk->version, rld_wk->version_len);
					if (cmpver == 0) {
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
					} else {
						if (cmpver == CefC_Cpub_InconsistentVersion) {
							char 	uri[CefC_Name_Max_Length];
							cef_frame_conversion_name_to_string (cnt_wk->name, cnt_wk->name_len, uri, "ccn");
							cef_log_write (CefC_Log_Warn
								, "<%d> Inconsistent version number used for URI (%s).\n"
								, rld_wk->line_no
								, uri);
							if (cnt_wk->version_len) {
								cef_log_write (CefC_Log_Warn, "        uploaded      : %s\n", cnt_wk->version);
							} else {
								cef_log_write (CefC_Log_Warn, "        uploaded      : None\n");
							}
							if (rld_wk->version_len) {
								cef_log_write (CefC_Log_Warn, "        conpubcont.def: %s\n", rld_wk->version);
							} else {
								cef_log_write (CefC_Log_Warn, "        conpubcont.def: None\n");
							}
							foundf = 1;
							/* Delete from content reload list */
							rld_bp->next = rld_wk->next;
							free (rld_wk);
							break;
						}
						if (cmpver > 0) {
							char 	uri[CefC_Name_Max_Length];
							cef_frame_conversion_name_to_string (cnt_wk->name, cnt_wk->name_len, uri, "ccn");
							cef_log_write (CefC_Log_Warn
								, "<%d> Old version number used for URI (%s).\n"
								, rld_wk->line_no
								, uri);
							cef_log_write (CefC_Log_Warn
								, "        uploaded: %s, conpubcont.def: %s\n"
								, cnt_wk->version
								, rld_wk->version);
							foundf = 1;
							/* Delete from content reload list */
							rld_bp->next = rld_wk->next;
							free (rld_wk);
							break;
						} else {
							break; /* re-create Co */
						}
					}
				}
				rld_bp = rld_wk;
				rld_wk = rld_wk->next;
			}
			if (foundf == 0) {
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
			{
				char uri[CefC_Name_Max_Length];
				cef_frame_conversion_name_to_string (wk->name, wk->name_len, uri, "ccn");
				cef_log_write (CefC_Log_Info, "Deleted(reload) %s, %s \n", uri, wk->version);
			}
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

	/* Create Catalog Data */
	conpubd_catalog_data_create ();

#ifdef CefC_Debug
{
	CefT_Cpubcnt_Hdl* work;
	work = Cpubcnthdl.next;
	struct tm* timeptr;
	char date_str[256];
	CefT_Cpubctlg_Hdl*	wk;
	cef_dbg_write (CefC_Dbg_Fine, "----- Contents -----\n");
	while (work) {
		/* Name 			*/
		conpubd_dbg_convert_name_to_str_put_workstr (work->name, work->name_len);
		cef_dbg_write (CefC_Dbg_Fine, "Name=%s\n", workstr);
		if (work->version_len != 0)
			cef_dbg_write (CefC_Dbg_Fine, "    Version=%s\n", work->version);
		else
			cef_dbg_write (CefC_Dbg_Fine, "    Version=None\n");
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
		work = work->next;
	}
	cef_dbg_write (CefC_Dbg_Fine, "----- Catalog -----\n");
	wk = Cpbctlghdl.next;
	while (wk) {
		/* Name 			*/
		conpubd_dbg_convert_name_to_str_put_workstr (wk->name, wk->name_len);
		cef_dbg_write (CefC_Dbg_Fine, "Name=%s\n", workstr);
		if (wk->version_len != 0)
			cef_dbg_write (CefC_Dbg_Fine, "    Version=%s\n", wk->version);
		else
			cef_dbg_write (CefC_Dbg_Fine, "    Version=None\n");
		wk = wk->next;
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
	char 	ws[PATH_MAX];
	FILE*	fp = NULL;
	char 	buff[4096];
	char 	uri[CefC_Name_Max_Length];
	char	ver[CefC_Name_Max_Length];
	char 	path[PATH_MAX];
	char 	date_str[1024];
	char 	time_str[1024];
	int 	res;
	unsigned char 		name[CefC_Name_Max_Length];
	int 				name_len;
	time_t 				expiry;
	uint64_t			cob_num;
	struct tm t;
	time_t now;
	time_t timer;
	struct tm *local;
	size_t buff_len = 0;
	int		line_no = 0;
	int		ver_len = 0;
	
	cef_log_write (CefC_Log_Info, "Reading conpubcont.def ...\n");

	CefT_Cpubcnt_Hdl* work = (CefT_Cpubcnt_Hdl*) cnthdl;

#if 0 //+++++ GCC v9 +++++
	sprintf (ws, "%s/%s", conpub_contdef_dir, CefC_Conpub_ContDef_Name);
#else
	int rc;
	rc = snprintf (ws, sizeof(ws), "%s/%s", conpub_contdef_dir, CefC_Conpub_ContDef_Name);
	if (rc < 0){
		cef_log_write (CefC_Log_Error, "conpubcont.def file dir path too long(%s)\n", conpub_contdef_dir);
		return (-1);
	}
	
#endif //----- GCC v9 -----
	
	/*--------------------------------------------------------
		Open content definition file
	----------------------------------------------------------*/
	fp = fopen (ws, "r");
	if (fp == NULL) {
		cef_log_write (CefC_Log_Error, "Fail to open %s\n", ws);
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
		res = conpub_trim_line_string (buff, uri, ver, path, date_str, time_str);
		if (res < 0) {
			buff[strlen (buff)-1] = 0;
			cef_log_write (CefC_Log_Warn, "<%d> Invalid record (%s)\n", line_no, buff);
			continue;
		}
		
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
		
		/* Check character of version */
		ver_len = conpubd_check_version_char (ver);
		if (ver_len <= 0) {
			cef_log_write (CefC_Log_Warn, "<%d> Invalid Version number (%s) specified.\n", line_no, ver);
			continue;
		}
		
		timer = time (NULL);
		local = localtime (&timer);
		now = mktime (local);
		
		if (expiry < now) {
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
					char uri[CefC_Name_Max_Length];
					cef_frame_conversion_name_to_string (name, name_len, uri, "ccn");
					cef_log_write (CefC_Log_Warn, "<%d> Duplicate URI (%s, %s) specified.\n", line_no, uri, ver);
					if (ver_len == 4 && strcasecmp (ver, "None") == 0) {
						if (dwk->version_len > 0) {
							cef_log_write (CefC_Log_Warn, "<%d> Inconsistent version number specified for URI.\n", line_no);
						}
					} else {
						if (dwk->version_len == 0) {
							cef_log_write (CefC_Log_Warn, "<%d> Inconsistent version number specified for URI.\n", line_no);
						} else if (memcmp (dwk->version, ver, ver_len) != 0) {
							cef_log_write (CefC_Log_Warn, "<%d> Different version number specified for URI.\n", line_no);
						}
					}
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
			cef_log_write (CefC_Log_Error, "malloc error(Cpubcnt)\n", ws);
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
		if (strcasecmp (ver, "None") == 0) {
			work->version[0] = 0x00;
			work->version_len = 0;
		} else {
			memcpy (work->version, ver, ver_len);
			work->version_len = ver_len;
		}
		work->line_no = line_no;
	}
	
	fclose (fp);
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
	char* ver,									/* Version string after trimming		*/
	char* path,									/* Path string after trimming			*/
	char* date,									/* Date string after trimming			*/
	char* time
) {
	int num;
	int yy, mm, dd;
	int h, m;
	int datef = 0;
	int timef = 0;
	strcpy (uri, "");
	strcpy (path, "");
	strcpy (date, "");
	strcpy (time, "");
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
	num = sscanf (p, "%s %s %s %s %s", uri, ver, path, date, time);
	if (num < 3) {
		return (-1);
	} else if (num == 3) {
		strcpy (date, "");
		strcpy (time, "");
	} else if (num == 4) {
		if (sscanf (date, "%d:%d", &h, &m) == 2) {
			strcpy (time, date);
			strcpy (date, "");
			timef = 1;
		} else {
			if (sscanf (date, "%d-%d-%d", &yy, &mm, &dd) != 3) {
				return (-1);
			}
			datef = 1;
		}
	} else if (num == 5) {
		if (sscanf (date, "%d-%d-%d", &yy, &mm, &dd) != 3) {
			return (-1);
		}
		if (sscanf (time, "%d:%d", &h, &m) != 2) {
			return (-1);
		}
		datef = 1;
		timef = 1;
		
	}
	if (datef == 1) {
		if (!(1900 <= yy && yy <= 2037)) {
			return (-1);
		}
		if (!(1 <= mm && mm <= 12)) {
			return (-1);
		}
		if (!(1 <= dd && dd <= 31)) {
			return (-1);
		}
	}
	if (timef == 1) {
		if (!(0 <= h && h <= 23)) {
			return (-1);
		}
		if (!(0 <= m && m <= 59)) {
			return (-1);
		}
	}
		
	return (num);

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
	Check character of version
----------------------------------------------------------------------------------------*/
static int
conpubd_check_version_char (
	char* ver
) {
	unsigned char*	wp = (unsigned char*) ver;
	int				ver_len = 0;
	
	while (*wp) {
		if((*wp < 0x30) ||							/* NOT 0~9,A~Z,a~z */
			((*wp > 0x39) && (*wp < 0x41)) ||
			((*wp > 0x5a) && (*wp < 0x61)) ||
			(*wp > 0x7a)) {
			
			if(*wp != 0x2d &&						/* - */
				*wp != 0x2e &&						/* . */
				*wp != 0x5f &&						/* _ */
				*wp != 0x7e) {						/* ~ */
				return(-1);
			}
		}
		wp++;
		ver_len++;
	}
	
	return (ver_len);
}

/*--------------------------------------------------------------------------------------
	Compare ver1 and ver2
		ver1 > ver2 : return 1  : ver1 newer than ver2
		ver1 = ver2 : return 0  : same
		ver1 < ver2 : return -1 : ver1 older than ver2
----------------------------------------------------------------------------------------*/
static int
conpubd_version_compare (
	unsigned char* ver1,
	uint32_t vlen1,
	unsigned char* ver2,
	uint32_t vlen2
) {
	uint32_t long_klen;
	
	if ((vlen1 == 0 && vlen2 != 0) || 
		(vlen1 != 0 && vlen2 == 0)) {
		return (CefC_Cpub_InconsistentVersion);
	}
	
	if (vlen1 == vlen2 && 
		memcmp (ver1, ver2, vlen1) == 0) {
		return (0);
	}
	
	long_klen = (vlen1 > vlen2 ? vlen1 : vlen2);
	if (memcmp (ver1, ver2, long_klen) > 0) {
		return (1);
	}
	return (-1);
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
	int res = cef_valid_init (conf_path);
	if (res < 0) {
		cef_log_write (CefC_Log_Error, "Failed to read the cefnetd.key\n");
		return (-1);
	}
	
	conpubd_catalog_data_init ();
	
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
	
	conpubd_catalog_data_destory ();
	
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
	uint32_t seqnum = 0;
	int res;
	unsigned char buff[CefC_Max_Length];
	unsigned char cobbuff[CefC_Max_Length];
	
	int len;
	int rtc = 0;
	ConpubdT_Content_Entry cont_entry;	
	time_t wtime_s = 0;
	int first_cob_f = 0;
	uint64_t free_mem_mega = 0;
	uint64_t estimated_mem_mega = 0; 
	uint64_t free_file_mega = 0;
	uint64_t estimated_file_mega = 0; 

	/* Check Content num  */
	if (hdl->published_contents_num >= hdl->contents_num) {
		cef_frame_conversion_name_to_string (entry->name, entry->name_len, Uri_buff_p, "ccn");
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
			cef_frame_conversion_name_to_string (entry->name, entry->name_len, Uri_buff_p, "ccn");
			cef_log_write (CefC_Log_Warn
							, "CAPACITY over : %s,  capacity="FMTU64",  used cobs="FMTU64",  set cobs="FMTU64"\n"
							, Uri_buff_p, capacity, cobs, entry->cob_num);
			return (-99);
		}
	}
	
	/* Creates and inputs the Cobs 	*/
	wtime_s = time (NULL);
	fp = fopen (entry->file_path, "rb");
	if (fp == NULL) {
		return (-1);
	}

	/* Inits the parameters 		*/
	memset (Cob_prames_p, 0, sizeof (CefT_Object_TLVs));
	/* Sets the name */
	memcpy (Cob_prames_p->name, entry->name, entry->name_len);
	Cob_prames_p->name_len = entry->name_len;
	/* Sets Expiry TIme */
	Cob_prames_p->expiry = entry->expiry * 1000;
	/* Sets Cache TIme */
	Cob_prames_p->opt.cachetime_f = 1;
	Cob_prames_p->opt.cachetime = Cob_prames_p->expiry;
	/* Sets chunk flag */
	Cob_prames_p->chnk_num_f = 1;
	/* Sen end chunk */
	Cob_prames_p->end_chunk_num_f =1;
	Cob_prames_p->end_chunk_num = entry->cob_num-1;
	/* Sets validation info */
	Cob_prames_p->alg.valid_type = hdl->valid_type;
	
	/* Sets Version */
	if (entry->version_len) {
		Cob_prames_p->opt.version_f = 1;
		memcpy (Cob_prames_p->opt.version, entry->version, entry->version_len);
	}
	Cob_prames_p->opt.ver_len = (uint16_t)entry->version_len;
	
	cef_frame_conversion_name_to_string (entry->name, entry->name_len, Uri_buff_p, "ccn");
	while (conpubd_running_f) {
		res = fread (buff, sizeof (unsigned char), hdl->block_size, fp);
		if (res > 0) {
			memcpy (Cob_prames_p->payload, buff, res);
			Cob_prames_p->payload_len = (uint16_t) res;
			Cob_prames_p->chnk_num = seqnum;
			
			len = cef_frame_object_create (cobbuff, Cob_prames_p);
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
					return (-1);
				}
				memcpy (cont_entry.msg, cobbuff, len);
				cont_entry.msg_len = len;
				if ((cont_entry.name = calloc (1, Cob_prames_p->name_len)) == NULL) {
					cef_log_write (CefC_Log_Critical, "Failed to alloc memory\n");
					conpubd_running_f = 0;
					fclose (fp);
					return (-1);
				}
				memcpy (cont_entry.name, Cob_prames_p->name, Cob_prames_p->name_len);
				cont_entry.name_len = Cob_prames_p->name_len;
				cont_entry.pay_len = Cob_prames_p->payload_len;
				cont_entry.chnk_num = Cob_prames_p->chnk_num;
				cont_entry.expiry = Cob_prames_p->expiry * 1000;
				cont_entry.rct = (uint64_t)hdl->cache_default_rct;
				/* cont_entry.node does not care */
				rtc = hdl->cs_mod_int->cache_item_puts (&cont_entry, sizeof (cont_entry));
				if (rtc < 0) {
					cef_log_write (CefC_Log_Critical, "Failed to publish %s (cache_item_puts)\n", Uri_buff_p);
					conpubd_running_f = 0;
					fclose (fp);
					hdl->cs_mod_int->cache_item_puts (NULL, 0);
					return (-1);
				}
			}
			seqnum++;
		} else {
			if (feof (fp) == 0 || ferror (fp) != 0) {
				cef_log_write (CefC_Log_Critical, "Failed to publish %s (Read Error)\n", Uri_buff_p);
				conpubd_running_f = 0;
				fclose (fp);
				hdl->cs_mod_int->cache_item_puts (NULL, 0);
				return (-1);
			}
			break;
		}
	}

	hdl->cs_mod_int->cache_item_puts (NULL, 0);
	fclose (fp);
	cef_log_write (CefC_Log_Info, "Published %s (time=%ld) \n", Uri_buff_p, time (NULL) - wtime_s);
	/* CefC_App_Reg */
	{
		CefT_Connect connect;
		connect.ai = 0;
		connect.sock = hdl->cefnetd_sock;
		CefT_Client_Handle fhdl;
		fhdl = (CefT_Client_Handle) &connect;
		if (connect.sock != -1) {
			cef_client_prefix_reg (fhdl, CefC_App_Reg, entry->name, entry->name_len);
		}
	}
	
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

	if (hdl->cs_mod_int->content_del == NULL) {
		char uri[CefC_Name_Max_Length];
		cef_frame_conversion_name_to_string (entry->name, entry->name_len, uri, "ccn");
		cef_log_write (CefC_Log_Critical, "Failed to delete %s \n", uri);
		conpubd_running_f = 0;
		rtc = -1;
		return (rtc);
	}

	hdl->published_contents_num --;

	{
		CefT_Connect connect;
		connect.ai = 0;
		connect.sock = hdl->cefnetd_sock;
		CefT_Client_Handle fhdl;
		fhdl = (CefT_Client_Handle) &connect;
		if (connect.sock != -1) {
			cef_client_prefix_reg (fhdl, CefC_App_DeReg, entry->name, entry->name_len);
		}
	}

	memcpy (Name_buff_p, entry->name, entry->name_len);
	name_len = entry->name_len;
	
	if (hdl->cs_mod_int->content_del (Name_buff_p, name_len, entry->cob_num) < 0) {
			cef_frame_conversion_name_to_string (entry->name, entry->name_len, Uri_buff_p, "ccn");
		cef_log_write (CefC_Log_Error, "Failed to delete %s (content_cache_del)\n", Uri_buff_p);
			conpubd_running_f = 0;
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

	while (work) {
		if ((work->name_len == name_len)
			&& (memcmp (work->name, name, name_len) == 0)) {
			if (nowtsec > work->expiry) {
 				pthread_mutex_lock (&conpub_cnt_mutex);
				{
					char uri[CefC_Name_Max_Length];
					cef_frame_conversion_name_to_string (work->name, work->name_len, uri, "ccn");
					cef_log_write (CefC_Log_Info, "Deleted(expired) %s \n", uri);
				}
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
	Respond with version
----------------------------------------------------------------------------------------*/
static void 
conpubd_version_respond (
	CefT_Conpubd_Handle* hdl,					/* conpub daemon handle					*/
	CefT_Cpubcnt_Hdl* 	entry,
	int 				sock
) {
	int msg_len;
	
	/* Creates the response 		*/
	/* Sets name */
	memset (Cob_prames_p, 0, sizeof (CefT_Object_TLVs));
	memcpy (Cob_prames_p->name, entry->name, entry->name_len);
	Cob_prames_p->name_len = entry->name_len;
	/* Sets Expiry TIme */
	Cob_prames_p->expiry = 0;	/* To prevent caching */
	/* Sets Version(VerReq) */
	Cob_prames_p->opt.version_f = 1;
	Cob_prames_p->opt.ver_len = 0;
	/* Sets Version at payload */
	memcpy (Cob_prames_p->payload, entry->version, entry->version_len);
	Cob_prames_p->payload_len = (uint16_t) entry->version_len;
	/* Sets Varidation */
	Cob_prames_p->alg.valid_type = hdl->valid_type;
	
	msg_len = cef_frame_object_create (Cob_msg_p, Cob_prames_p);
	
	/* Sends Version */
	{
		struct pollfd fds[1];
		fds[0].fd  = sock;
		fds[0].events = POLLOUT | POLLERR;
		if (poll (fds, 1, 100) < 1) {
			; /* NOP */
		}
		/* send Cob message */
		int res = send (fds[0].fd, Cob_msg_p, msg_len, 0);
		if (res  < 1) {
			/* send error */
			if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
				cef_log_write (CefC_Log_Error, "Send error (%s)\n", strerror (errno));
				return;
			}
		}
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Send Version(len = %u).\n", msg_len);
	cef_dbg_buff_write (CefC_Dbg_Finest, Cob_msg_p, msg_len);
#endif // CefC_Debug
	}
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
			{
				int i;
				i = conpubd_free_sock_index_search (hdl);
				if (i > -1) {
					strcpy (hdl->peer_id_str[i], hdl->cefnetd_id);
					strcpy (hdl->peer_sv_str[i], hdl->cefnetd_port_str);
					cef_log_write (CefC_Log_Info, "Open TCP peer: %s:%s, socket : %d\n",
						hdl->peer_id_str[i], hdl->peer_sv_str[i], hdl->cefnetd_sock);
					hdl->tcp_fds[i] 	= hdl->cefnetd_sock;
					hdl->tcp_index[i] 	= 0;
				}
				/* App_Reg */
				{
					CefT_Connect connect;
					connect.ai = 0;
					connect.sock = hdl->cefnetd_sock;
					CefT_Client_Handle fhdl;
					fhdl = (CefT_Client_Handle) &connect;
					
					{
						CefT_Cpubcnt_Hdl* work;
						work = Cpubcnthdl.next;
						while (work) {
							cef_client_prefix_reg (fhdl, CefC_App_Reg, work->name, work->name_len);
							work = work->next;
						}
					}
					
				}
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
	FILE* fp;
	
	/* get free memory size */
#ifndef CefC_MACOS
	/************************************************************************************/
	/* [/proc/meminfo format]															*/
	/*		MemTotal:        8167616 kB													*/
	/*		MemFree:         7130204 kB													*/
	/*		MemAvailable:    7717896 kB													*/
	/*		...																			*/
	/************************************************************************************/
	char buf[1024];
	char* key_free = "MemFree:";
	char* meminfo = "/proc/meminfo";
	int val;
	if ((fp = fopen (meminfo, "r")) == NULL) {
		cef_log_write (CefC_Log_Critical, "%s(%d): Could not open %s to get memory information.\n", __FUNCTION__, meminfo);
		return (-1);
	}
	while (fgets (buf, sizeof (buf), fp) != NULL) {
		if (strncmp (buf, key_free, strlen (key_free)) == 0) {
			sscanf (&buf[strlen (key_free)], "%d", &val);
			*free_mem_mega = val / 1024;
		}
	}
	if (free_mem_mega == 0) {
		cef_log_write (CefC_Log_Critical, "%s(%d): Could not find keyword(%s) to get memory information\n", 
						__FUNCTION__, key_free);
		return (-1);
	}
	fclose (fp);
#else // CefC_MACOS
	/************************************************************************************/
	/* ["top -l 1 | grep PhysMem:" format]												*/
	/*		PhysMem: 7080M used (1078M wired), 1109M unused.							*/
	/************************************************************************************/
	char buf[1024];
	char* cmd = "top -l 1 | grep PhysMem:";
	char* tag = "PhysMem:"; 
	int	 used = 0, unused = 0;
	if ((fp = popen (cmd, "r")) != NULL) {
		while (fgets (buf, sizeof (buf), fp) != NULL) {
			if (strstr (buf, tag) != NULL) {
				char* pos = strchr (buf, ' ');
				sscanf (pos, "%d", &used);
				pos = strchr (pos, ',');
				sscanf (pos+1, "%d", &unused);
			} 
		}
		pclose (fp);
	} else {
		cef_log_write (CefC_Log_Critical, "%s(%d): Could not get memory information.\n", __FUNCTION__, __LINE__);
		return (-1);
	}		
	if (unused == 0 || used == 0) {
		cef_log_write (CefC_Log_Critical, "%s(%d): Could not find keyword(%s) to get memory information\n", 
					__FUNCTION__, tag);
		return (-1);
	}
	*free_mem_mega = unused;
#endif // CefC_MACOS

//@@@@@fprintf(stderr, "[%s]: ---- free_mem_mega="FMTU64"\n", __FUNCTION__, *free_mem_mega);

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

/*--------------------------------------------------------
	Inits Catalog Data
----------------------------------------------------------*/
static void
conpubd_catalog_data_init (
	void
) {
	memset (&Cpbctlghdl, 0, sizeof (CefT_Cpubctlg_Hdl));
	return;
}

/*--------------------------------------------------------
	Destroy Catalog Data
----------------------------------------------------------*/
static void
conpubd_catalog_data_destory (
	void
) {
	CefT_Cpubctlg_Hdl* bwk;
	CefT_Cpubctlg_Hdl* wk;
	
	bwk = &Cpbctlghdl;
	wk = Cpbctlghdl.next;
	while (wk) {
		bwk->next = wk->next;
		free (wk);
		wk = bwk;
		wk = wk->next;
	}
	
	return;
}

/*--------------------------------------------------------
	Create Catalog Data
----------------------------------------------------------*/
static void
conpubd_catalog_data_create (
	void
) {
	CefT_Cpubctlg_Hdl*	wk;
	CefT_Cpubcnt_Hdl*	work;
	
	wk = &Cpbctlghdl;
	
	work = Cpubcnthdl.next;
	
	while (work) {
		
		wk->next = (CefT_Cpubctlg_Hdl*) malloc (sizeof (CefT_Cpubctlg_Hdl));
		memset (wk->next, 0, sizeof (CefT_Cpubctlg_Hdl));
		wk = wk->next;
		wk->name_len    = work->name_len;
		wk->name        = work->name;
		wk->version_len = work->version_len;
		wk->version     = work->version;
		
		work = work->next;
	}
	
	return;
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

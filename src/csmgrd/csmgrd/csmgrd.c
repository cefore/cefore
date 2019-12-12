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
 * csmgrd.c
 */

#define __CEF_CSMGRD_SOURCE__

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

#include "csmgrd.h"
#include <csmgrd/csmgrd_plugin.h>
#include <cefore/cef_csmgr.h>
#include <cefore/cef_client.h>
#include <cefore/cef_frame.h>
#include <cefore/cef_log.h>



/****************************************************************************************
 Macros
 ****************************************************************************************/


/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/


/****************************************************************************************
 State Variables
 ****************************************************************************************/
char* CSMGRD_PROGRAM_ID = "csmgrd";
static uint8_t csmgrd_running_f = 0;
static char csmgr_conf_dir[PATH_MAX] = {"/usr/local/cefore"};
static char root_user_name[CefC_Csmgr_User_Len] = {"root"};

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
	uint32_t* chnk_num,							/* Chunk number							*/
	unsigned char op_data[],					/* Optional Data Field					*/
	uint16_t* op_data_len						/* Length of Optional Data Field		*/
);
/*--------------------------------------------------------------------------------------
	Incoming Upload Request Message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_upload_request (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* message length						*/
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
	set "cache" status
----------------------------------------------------------------------------------------*/
static uint16_t										/* Length of field					*/
csmgrd_cache_info_set (
	unsigned char* sp, 								/* start address of buffer			*/
	unsigned char* ep, 								/* end address of buffer			*/
	int name_num,									/* number of information 			*/
	char uris[CefC_Csmgr_Stat_MaxUri][265], 		/* cache information to set			*/
	int msg_len,									/* length of all name				*/
	CefT_Csmgrd_Stat_Cache* stat					/* cache statuses					*/
);
#ifdef CefC_Contrace
/*--------------------------------------------------------------------------------------
	Incoming Contrace Message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_contrace_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
);
#endif // CefC_Contrace
/*--------------------------------------------------------------------------------------
	Receive Increment Access Cnount message
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
#if defined (CefC_Conping) || defined (CefC_Contrace)
/*--------------------------------------------------------------------------------------
	Incoming conping message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_conping_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
);
/*--------------------------------------------------------------------------------------
	Send conping response message
----------------------------------------------------------------------------------------*/
static void
csmgrd_conping_response_send (
	int sock,									/* recv socket							*/
	uint8_t result								/* result								*/
);
#endif // (CefC_Conping || CefC_Contrace)
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
	Output Content Manager Message
----------------------------------------------------------------------------------------*/
// static void
// csmgrd_print (
// 	const char* fmt, 								/* output format					*/
// 	...												/* parameters						*/
// );
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
	cef_log_init ("csmgrd");
	
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
			strcpy (file_path, argv[i + 1]);
			dir_path_f++;
			i++;
		} else {
			cef_log_write (CefC_Log_Error, "unknown option is specified.\n");
			return (-1);
		}
	}
#ifdef CefC_Debug
	cef_dbg_init ("csmgrd", file_path, 0);
#endif
	
	/* Creation the local socket name 	*/
	res = csmgrd_plugin_config_dir_set (file_path);
	if (res < 0) {
		cef_log_write (CefC_Log_Error, "Failed to read csmgrd.conf.\n");
		return (-1);
	}
	
	/* create csmgrd handle */
	hdl = csmgrd_handle_create ();
	if (hdl == NULL) {
		cef_log_write (CefC_Log_Error, "Unable to create csmgrd handle.\n");
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
	
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Loading the config file.\n");
#endif // CefC_Debug
	/* Load config */
	if (csmgrd_config_read (&(conf_param)) < 0) {
		cef_log_write (CefC_Log_Error, "Failed to load the %s\n", CefC_Csmgr_Conf_Name);
		free (hdl);
		return (NULL);
	}
	hdl->interval = conf_param.interval;

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Create the listen socket.\n");
#endif // CefC_Debug
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

	/* Initialize plugin */
	if (hdl->cs_mod_int->init != NULL) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Initialize plugin.\n");
#endif // CefC_Debug
		if (hdl->cs_mod_int->init () < 0) {
			cef_log_write (CefC_Log_Error, "Failed to initialize cache plugin.\n");
			csmgrd_handle_destroy (&hdl);
			return (NULL);
		}
	}
	cef_log_write (CefC_Log_Info, "Initialization the cache plugin ... OK\n");

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Read whitelist.\n");
#endif // CefC_Debug
	/* Read whitelist */
	if (csmgrd_ext_white_list_read (hdl) < 0) {
		cef_log_write (CefC_Log_Error, "Failed to read the white list\n");
		csmgrd_handle_destroy (&hdl);
		return (NULL);
	}
	cef_log_write (CefC_Log_Info, "Loading %s ... OK\n", CefC_Csmgr_Conf_Name);

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
	Destroy csmgr daemon handle
----------------------------------------------------------------------------------------*/
static void
csmgrd_handle_destroy (
	CefT_Csmgrd_Handle** csmgrd_hdl				/* CS Manager Handle					*/
) {
	CefT_Csmgrd_Handle* hdl = *csmgrd_hdl;
	int i;

	/* Check handle */
	if (hdl == NULL) {
		return;
	}

	/* Close Tcp listen socket */
	if (hdl->tcp_listen_fd != -1) {

		for (i = 0 ; i < CsmgrdC_Max_Sock_Num ; i++) {
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

	/* Delete white list */
	if (hdl->white_list != NULL) {
		CsmgrT_White_List* next;
		while (hdl->white_list != NULL) {
			next = hdl->white_list->next;
			free (hdl->white_list);
			hdl->white_list = next;
		}
	}

	free (hdl);
	*csmgrd_hdl = NULL;

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

	/* Obtains the directory path where the cefnetd's config file is located. */
	sprintf (file_name, "%s/%s", csmgr_conf_dir, CefC_Csmgr_Conf_Name);
	
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
	conf_param->port_num 	= CefC_Default_Tcp_Prot;

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
				return (-1);
			}
			conf_param->interval = res;
		} else if (strcmp (option, "CACHE_TYPE") == 0) {
			res = strlen (value);
			if (res > CsmgrdC_Max_Plugin_Name_Len) {
				cef_log_write (CefC_Log_Error,
					"EXCACHE_PLUGIN (Invalid value %s=%s)\n", option, value);
				return (-1);
			}
			strcpy (conf_param->cs_mod_name, value);
		} else if (strcmp (option, "PORT_NUM") == 0) {
			res = csmgrd_config_value_get (option, value);
			if ((res < 1025) || (res > 65535)) {
				cef_log_write (CefC_Log_Error,
					"PORT_NUM must be higher than 1024 and lower than 65536.\n");
				return (-1);
			}
			conf_param->port_num = res;
		} else {
			continue;
		}
	}
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
		cef_log_write (CefC_Log_Error, "Initialise function is not set.\n");
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
	if (hdl->cs_mod_int->expire_check == NULL) {
		cef_log_write (CefC_Log_Warn, "Load cache plugin (expire_check is not set)\n");
		hdl->interval = 0;
	}
	if (hdl->cs_mod_int->cache_item_get == NULL) {
		cef_log_write (CefC_Log_Error, "Load cache plugin (cache_item_get is not set)\n");
		return (-1);
	}
	if (hdl->cs_mod_int->cache_item_put == NULL) {
		cef_log_write (CefC_Log_Error, "Load cache plugin (cache_item_put is not set)\n");
		return (-1);
	}
	if (hdl->cs_mod_int->status_get == NULL) {
		cef_log_write (CefC_Log_Warn, "Load cache plugin (status_get is not set)\n");
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
	char 	file_path[PATH_MAX];
	char*	wp;
	
	if (config_file_dir[0] != 0x00) {
		sprintf (file_path, "%s/csmgrd.conf", config_file_dir);
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

	/* Obtans the addrinfo 		*/
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

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, 
		"Received the new connection request. Check whitelist\n");
#endif // CefC_Debug
	/* Check address */
	if (csmgrd_white_list_reg_check (hdl, sa) < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Could not find the node in the whitelist.\n");
		if (getnameinfo ((struct sockaddr*) sa, len, ip_str, sizeof (ip_str),
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
	if ((err = getnameinfo ((struct sockaddr*) sa, len, ip_str, sizeof (ip_str),
			port_str, sizeof (port_str), NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
		cef_log_write (CefC_Log_Warn,
			"Failed to create new tcp connection : %s\n", gai_strerror (err));
		goto POST_ACCEPT;
	}

	/* Looks up the source node's information from the source table 	*/
	for (i = 0 ; i < CsmgrdC_Max_Sock_Num ; i++) {
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
	Search free tcp socket index
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
csmgrd_free_sock_index_search (
	CefT_Csmgrd_Handle* hdl						/* csmgr daemon handle					*/
) {
	int i;
	for (i = 0; i < CsmgrdC_Max_Sock_Num; i++) {
		if (hdl->tcp_fds[i] == -1) {
			return (i);
		}
	}
	return (-1);
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
	unsigned char frame[CefC_Max_Length] = {0};
	int len;
	int res;
	int frame_size;
	int i;
	uint8_t type = 0;

	/* set interval */
	uint64_t interval = (uint64_t) hdl->interval * 1000;
	uint64_t nowt = cef_client_present_timeus_calc ();
	uint64_t next = nowt + interval;

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
	cef_log_write (CefC_Log_Info, "Running\n");

	/* Main loop */
	while (csmgrd_running_f) {

		/* Calculates the present time 		*/
		nowt = cef_client_present_timeus_calc ();

		/* Checks content expire 			*/
		if ((interval != 0) && (nowt > next)) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finer, "Checks for expired contents.\n");
#endif // CefC_Debug
			hdl->cs_mod_int->expire_check ();
			/* set interval */
			next = nowt + interval;
		}

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
		for (i = 0 ; res > 0 && i < CsmgrdC_Max_Sock_Num ; i++) {
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
				if (hdl->tcp_fds[fds_index[i]] != -1) {
					close (hdl->tcp_fds[fds_index[i]]);
					hdl->tcp_fds[fds_index[i]] = -1;
					cef_log_write (CefC_Log_Info, "Close TCP peer: %s:%s\n",
						hdl->peer_id_str[fds_index[i]],
						hdl->peer_sv_str[fds_index[i]]);
					hdl->peer_num--;
				}
				hdl->tcp_index[fds_index[i]] = 0;
				res--;
				continue;
			}
			if (fds[i].revents & POLLIN) {
				res--;
				/* receive control message */
				len = recv (fds[i].fd,
					&(hdl->tcp_buff[fds_index[i]][0]) + hdl->tcp_index[fds_index[i]],
					CefC_Max_Length - hdl->tcp_index[fds_index[i]], 0);
				
				if (len > 0) {
					/* receive message */
					len += hdl->tcp_index[fds_index[i]];
					
					do {
#ifdef CefC_Debug
						cef_dbg_write (CefC_Dbg_Finer,
							"Receive message(s) (len = %d). Start parsing.\n", len);
#endif // CefC_Debug
						/* get frame */
						len = csmgr_frame_get (
							&(hdl->tcp_buff[fds_index[i]][0]), 
							len, frame, &frame_size, &type);
						if (frame_size > 0) {
#ifdef CefC_Debug
							cef_dbg_write (CefC_Dbg_Fine,
								"Process the csmgrd message (len = %d, fd = %d)\n",
								frame_size, fds[i].fd);
							cef_dbg_buff_write (CefC_Dbg_Finest, frame, frame_size);
#endif // CefC_Debug
							csmgrd_input_message_process (
											hdl, fds[i].fd, frame, frame_size, type);
						}
#ifdef CefC_Debug
						else {
							cef_dbg_write (CefC_Dbg_Finer, "Parse error\n");
						}
#endif // CefC_Debug
					} while ((frame_size > 0) && (len > 0));

					/* set index */
					if (len > 0) {
						hdl->tcp_index[fds_index[i]] = len;
					} else {
						hdl->tcp_index[fds_index[i]] = 0;
					}
				} else if (len == 0) {
					if (hdl->tcp_fds[fds_index[i]] != -1) {
						close (hdl->tcp_fds[fds_index[i]]);
						hdl->tcp_fds[fds_index[i]] = -1;
						cef_log_write (CefC_Log_Info, "Close TCP peer: %s:%s\n",
							hdl->peer_id_str[fds_index[i]],
							hdl->peer_sv_str[fds_index[i]]);
						hdl->peer_num--;
					}
					hdl->tcp_index[fds_index[i]] = 0;
				} else {
					if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
						/* Error occurs, so close this socket 	*/
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
						hdl->tcp_index[fds_index[i]] = 0;
					}
				}
			}
		}
	}

	/* post process */
	csmgrd_post_process (hdl);
	cef_log_write (CefC_Log_Info, "Stop\n");

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

	for (i = 0 ; i < CsmgrdC_Max_Sock_Num ; i++) {
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
		case CefC_Csmgr_Msg_Type_UpReq: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Upload Request Message\n");
#endif // CefC_Debug
			csmgrd_incoming_upload_request (hdl, msg, msg_len);
			break;
		}
#ifdef CefC_Contrace
		case CefC_Csmgr_Msg_Type_Contrace: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Contrace Message\n");
#endif // CefC_Debug
			csmgrd_incoming_contrace_msg (hdl, sock, msg, msg_len);
			break;
		}
#endif // CefC_Contrace
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
#if defined (CefC_Conping) || defined (CefC_Contrace)
		case CefC_Csmgr_Msg_Type_Conping: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Conping Message\n");
#endif // CefC_Debug
			csmgrd_incoming_conping_msg (hdl, sock, msg, msg_len);
			break;
		}
#endif // (CefC_Conping || CefC_Contrace)
		case CefC_Csmgr_Msg_Type_Kill: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Kill Command\n");
#endif // CefC_Debug
			if ((memcmp (msg, root_user_name, CefC_Csmgr_User_Len) == 0) ||
				(memcmp (msg, hdl->launched_user_name, CefC_Csmgr_User_Len) == 0)) {
				csmgrd_running_f = 0;
				cef_log_write (CefC_Log_Info, "csmgrdstop from %s\n", msg);
			} else {
				cef_log_write (CefC_Log_Info, 
					"Permission denied (csmgrdstop from %s)\n", msg);
			}
			break;
		}
		default: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the Unknown Message\n");
#endif // CefC_Debug
			return (-1);
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
	uint32_t chnk_num = 0;
	uint8_t int_type;
	unsigned char op_data[CefC_Max_Msg_Size] = {0};
	uint16_t op_data_len = 0;

	/* Parses the csmgr Interest message */
	res = cef_csmgr_interest_msg_parse (
			buff, buff_len, &int_type, name, &name_len, &chnk_num, op_data, &op_data_len);

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
			/* Searches and sends a Cob */
			hdl->cs_mod_int->cache_item_get (name, name_len, chnk_num, sock);
			break;
		}
		case CefC_Csmgr_Interest_Type_Bulk: {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Finest, "Receive the symbolic interest\n");
#endif // CefC_Debug
			if (hdl->cs_mod_int->cache_content_get == NULL) {
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Finest,
					"Cache plugin has no function(Symbolic interest).\n");
#endif // CefC_Debug
				break;
			}
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Call cache plugin (cache_content_get)\n");
#endif // CefC_Debug
			/* Searches Cobs */
			hdl->cs_mod_int->cache_content_get (name, name_len, chnk_num, sock);
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
	uint32_t* chnk_num,							/* Chunk number							*/
	unsigned char op_data[],					/* Optional Data Field					*/
	uint16_t* op_data_len						/* Length of Optional Data Field		*/
) {
	int res;
	uint16_t index = 0;
	uint8_t chunk_num_f;
	uint32_t value32;

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
		*chnk_num = ntohl (value32);
		index += CefC_S_ChunkNum;
	}

	return (0);
}
/*--------------------------------------------------------------------------------------
	Incoming Upload Request Message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_upload_request (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* message length						*/
) {
	uint16_t index = 0;
	CsmgrdT_Content_Entry content_entry;
	CsmgrdT_Content_Entry* entry = &content_entry;
	int res;
	uint16_t value16;
	uint32_t value32;
	uint64_t value64;

	/* Get payload length */
	if ((buff_len - index - CefC_S_Length) < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message parse error(payload length)\n");
#endif // CefC_Debug
		return;
	}
	memcpy (&value16, buff + index, CefC_S_Length);
	entry->pay_len = ntohs (value16);
	index += CefC_S_Length;

	/* Get cob message */
	if (((buff_len - index - CefC_S_Length) < 0) || (entry->pay_len == 0)) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message parse error(cob message)\n");
#endif // CefC_Debug
		return;
	}
	memcpy (&value16, buff + index, CefC_S_Length);
	entry->msg_len = ntohs (value16);
	index += CefC_S_Length;
	if (((buff_len - index - entry->msg_len) < 0) || (entry->msg_len == 0)) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message parse error(cob message)\n");
#endif // CefC_Debug
		return;
	}
	memcpy (entry->msg, buff + index, entry->msg_len);
	index += entry->msg_len;

	/* Get cob name */
	res = cef_csmgr_cob_name_parse (
					buff, buff_len, &index, entry->name, &(entry->name_len));
	if ((res < 0) || (entry->name_len == 0)) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message parse error(cob name)\n");
#endif // CefC_Debug
		return;
	}

	/* Get chunk num */
	if ((buff_len - index - CefC_S_ChunkNum) < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message parse error(chunk num)\n");
#endif // CefC_Debug
		return;
	}
	memcpy (&value32, buff + index, CefC_S_ChunkNum);
	entry->chnk_num = ntohl (value32);
	index += CefC_S_ChunkNum;
	
	/* Get cache time */
	if ((buff_len - index - CefC_S_Cachetime) < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message parse error(cache time)\n");
#endif // CefC_Debug
		return;
	}

	memcpy (&value64, buff + index, CefC_S_Cachetime);
	entry->cache_time = cef_client_ntohb (value64);
	index += CefC_S_Cachetime;

	/* get expiry */
	if ((buff_len - index - CefC_S_Expiry) < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message parse error(expiry)\n");
#endif // CefC_Debug
		return;
	}
	memcpy (&value64, buff + index, CefC_S_Expiry);
	entry->expiry = cef_client_ntohb (value64);
	index += CefC_S_Expiry;

	/* get address */
	if ((buff_len - index) < sizeof (struct in_addr)) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Message parse error(address)\n");
#endif // CefC_Debug
		return;
	}
	memcpy (&entry->node, buff + index, sizeof (struct in_addr));
	index += sizeof (struct in_addr);

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Call cache plugin (cache_item_put)\n");
#endif // CefC_Debug

	/* Put ContentObject into Content Store */
	hdl->cs_mod_int->cache_item_put (entry);

	return;
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
	CefT_Csmgrd_Stat_Cache cache[CefC_Csmgr_Stat_MaxUri] = {{0}};
	uint16_t cache_len 	= 0;
	uint16_t ret_len 	= 0;
	uint8_t cache_f 	= 0;
	char stat[CefC_Max_Length] = {0};
	char csmgr_stat[CefC_Max_Length] = {0};
	uint16_t stat_len = 0;
	uint16_t value16;
	char uris[CefC_Csmgr_Stat_MaxUri][265] = {{0}};
	unsigned char wbuf[CefC_Csmgr_Stat_Mtu] = {0};
	unsigned char* ep = wbuf + CefC_Csmgr_Stat_Mtu;
	uint16_t index = 0;
	int res, tmp_len;
	struct pollfd fds[1];

	/* Set header */
	wbuf[CefC_O_Fix_Ver]  = CefC_Version;
	wbuf[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_Status;
	index += CefC_Csmgr_Msg_HeaderLen;

	if (hdl->cs_mod_int->status_get == NULL) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Cache plugin has no status get function.\n");
#endif // CefC_Debug
		return;
	}
	/* Check cache_f */
	if (buff_len >= sizeof (uint8_t)) {
		cache_f = buff[0];
	}
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Call cache plugin (status_get)\n");
#endif // CefC_Debug
	res = hdl->cs_mod_int->status_get (stat, &stat_len, cache_f, uris, cache, &cache_len);
	if (res < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Get status error\n");
#endif // CefC_Debug
		return;
	}

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, "Set csmgrd status.\n");
#endif // CefC_Debug
	/* Set csmgrd status 		*/
	sprintf (csmgr_stat, "All Connection Num      : %d", hdl->peer_num);
	tmp_len = strlen (csmgr_stat);
	wbuf[index] = CefC_Csmgr_Stat_Msg_Type_Status;
	index++;
	value16 = htons (tmp_len);
	memcpy (wbuf + index, &value16, sizeof (uint16_t));
	index += sizeof (uint16_t);
	memcpy (wbuf + index, csmgr_stat, tmp_len);
	index += tmp_len;

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Finest, "Set plugin status.\n");
#endif // CefC_Debug
	/* Set plugin status 		*/
	wbuf[index] = CefC_Csmgr_Stat_Msg_Type_Status;
	index++;
	value16 = htons (stat_len);
	memcpy (wbuf + index, &value16, sizeof (uint16_t));
	index += sizeof (uint16_t);
	memcpy (wbuf + index, stat, stat_len);
	index += stat_len;
	if (res) {
		/* Set cache info */
		wbuf[index] = CefC_Csmgr_Stat_Msg_Type_Cache;
		index++;
		ret_len = csmgrd_cache_info_set (
						wbuf + index + sizeof (ret_len), ep, res, uris, cache_len, cache);
		if (ret_len) {
			value16 = htons (ret_len);
			memcpy (wbuf + index, &value16, sizeof (ret_len));
			index += sizeof (uint16_t) + ret_len;
		}
	}
	/* Set Length */
	value16 = htons (index);
	memcpy (wbuf + CefC_O_Length, &value16, CefC_S_Length);

	/* Send message */
	fds[0].fd = sock;
	fds[0].events = POLLOUT | POLLERR;
	res = poll (fds, 1, 100);
	if (res < 1) {
		/* Poll error */
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Failed to poll (response status message).\n");
#endif // CefC_Debug
		return;
	}
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Send status response(len = %u).\n", index);
	cef_dbg_buff_write (CefC_Dbg_Finest, wbuf, index);
#endif // CefC_Debug
	/* Send a response */
	res = cef_csmgr_send_msg (sock, wbuf, index);
#ifdef CefC_Debug
	if (res < 0) {
		/* send error */
		cef_dbg_write (CefC_Dbg_Fine, "Failed to send response message(status).\n");
	}
#endif // CefC_Debug

	return;
}
/*--------------------------------------------------------------------------------------
	set "cache" status
----------------------------------------------------------------------------------------*/
static uint16_t										/* Length of field					*/
csmgrd_cache_info_set (
	unsigned char* sp, 								/* start address of buffer			*/
	unsigned char* ep, 								/* end address of buffer			*/
	int name_num,									/* number of information 			*/
	char uris[CefC_Csmgr_Stat_MaxUri][265], 		/* cache information to set			*/
	int msg_len,									/* length of all name				*/
	CefT_Csmgrd_Stat_Cache* stat					/* cache statuses					*/
) {
	unsigned char* pwrite = sp;
	uint8_t 	fld_type;
	uint16_t 	fld_length;
	uint8_t 	name_length;
	uint16_t 	value16;
	uint32_t 	value32;
	uint64_t 	value64;
	size_t fst 	= sizeof (fld_type);
	size_t fsl	= sizeof (fld_length);
	size_t fstl = fst + fsl;
	size_t fsi	= sizeof (uint64_t) + sizeof (uint32_t) * 3;
	size_t fsn	= sizeof (name_length);

	int i;

	/* Check whether the size of this field is smaller than the rest */
	fld_length = fstl + sizeof (u_int8_t) + (fsn + fsi) * name_num + msg_len;
	if (sp + fld_length > ep) {
		return (0);
	}

	/* Write buffer for the response */
	fld_type = CefC_Csmgr_Stat_Type_Cache;

	memcpy (pwrite, &fld_type, fst);
	value32 = htonl ((uint32_t) name_num);
	memcpy (pwrite + fstl, &value32, sizeof (uint32_t));
	pwrite = sp + fstl + sizeof (uint32_t);

	for (i = 0 ; i < name_num ; i++) {
		value64 = cef_client_htonb (stat[i].size);
		memcpy (pwrite, &value64, sizeof (uint64_t));
		pwrite += sizeof (uint64_t);

		value32 = htonl ((uint32_t)(stat[i].freshness_sec));
		memcpy (pwrite, &value32, sizeof (uint32_t));
		pwrite += sizeof (uint32_t);

		value32 = htonl (stat[i].access_cnt);
		memcpy (pwrite, &value32, sizeof (uint32_t));
		pwrite += sizeof (uint32_t);

		value32 = htonl (stat[i].elapsed_time);
		memcpy (pwrite, &value32, sizeof (uint32_t));
		pwrite += sizeof (uint32_t);

		name_length = (uint8_t) strlen (&uris[i][0]);

		memcpy (pwrite, &name_length, fsn);
		memcpy (pwrite + fsn, &uris[i][0], name_length);
		pwrite += fsn + name_length;
	}

	fld_length = (uint16_t)(pwrite - sp);
	value16 = htons (fld_length);
	memcpy (sp + fst, &value16, fsl);

	return (fld_length);
}
#ifdef CefC_Contrace
/*--------------------------------------------------------------------------------------
	Incoming Contrace Message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_contrace_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
) {
	int res;
	char uris[CefstatC_MaxUri][265] = {{0}};
	CefstatT_Cache stat[CefstatC_MaxUri];
	unsigned char msg[CefC_Max_Length] = {0};
	unsigned char name[CefC_Max_Length];
	unsigned char* key;
	int total_name_len = 0;
	uint16_t index = 0;
	uint16_t rec_index;
	int i;
	uint16_t name_len;
	uint8_t  partial_match_f;
	uint16_t klen;
	uint64_t value_u64;
	struct trace_rep_block rep_blk;
	struct tlv_hdr rply_tlv_hdr;
	struct tlv_hdr name_tlv_hdr;

	/* check support */
	if (hdl->cs_mod_int->cache_info_get == NULL) {
#ifdef CefC_Debug
		cef_dbg_write (
			CefC_Dbg_Fine, "Cache plugin has no contrace function.\n");
#endif // CefC_Debug
		return;
	}
#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Call cache plugin (cache_info_get)\n");
#endif // CefC_Debug
	res = hdl->cs_mod_int->cache_info_get (&total_name_len, uris, stat);

	if (res > 0) {
		name_tlv_hdr.type = htons (CefC_T_NAME);

		partial_match_f = buff[0];
		klen = buff_len - 1;
		key = &buff[1];

		for (i = 0 ; i < res ; i++) {

			name_len = (uint16_t) cef_frame_conversion_uri_to_name (uris[i], name);
			if (name_len < 1) {
				break;
			}
			if (memcmp (key, name, klen) == 0) {
				if ((partial_match_f == 0) && (klen != name_len)) {
					continue;
				}
			} else {
				continue;
			}

			rec_index = index;
			index += CefC_S_TLF;

			rep_blk.cont_size 	= htonl ((uint32_t) stat[i].size / 1000);
			rep_blk.cont_cnt 	= htonl ((uint32_t) stat[i].cob_num);
			rep_blk.rcv_int 	= htonl ((uint32_t) stat[i].access_cnt);
			rep_blk.first_seq 	= htonl ((uint32_t) stat[i].min_seq_num);
			rep_blk.last_seq 	= htonl ((uint32_t) stat[i].max_seq_num);

			value_u64 = (uint64_t) stat[i].elapsed_time;
			rep_blk.cache_time 	= cef_client_htonb (value_u64);
			value_u64 = (uint64_t) stat[i].freshness_sec;
			rep_blk.remain_time	= cef_client_htonb (value_u64);

			memcpy (&msg[index], &rep_blk, sizeof (struct trace_rep_block));
			index += sizeof (struct trace_rep_block);

			/* Name 				*/
			name_tlv_hdr.length = htons (name_len);
			memcpy (&msg[index], &name_tlv_hdr, sizeof (struct tlv_hdr));
			memcpy (&msg[index + CefC_S_TLF], name, name_len);
			index += CefC_S_TLF + name_len;

			/* Sets the header of Reply Block 		*/
			rply_tlv_hdr.type = htons (CefC_T_TRACE_CONTENT);
			rply_tlv_hdr.length = htons (index - (rec_index + CefC_S_TLF));
			memcpy (&msg[rec_index], &rply_tlv_hdr, sizeof (struct tlv_hdr));
		}

#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Send the contrace response (len = %u).\n", index);
		cef_dbg_buff_write (CefC_Dbg_Finest, msg, index);
#endif // CefC_Debug
		/* send a response */
		if (index > 0) {
			res = cef_csmgr_send_msg (sock, msg, index);
			if (res < 0) {
				/* send error */
#ifdef CefC_Debug
				cef_dbg_write (CefC_Dbg_Fine, "Failed to send the contrace response\n");
#endif // CefC_Debug
			}
		} else {
			cef_csmgr_send_msg (sock, msg, CefC_S_TLF);
		}
	} else {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Send the contrace response(len = %u).\n", index);
		cef_dbg_buff_write (CefC_Dbg_Finest, msg, index);
#endif // CefC_Debug
		cef_csmgr_send_msg (sock, msg, CefC_S_TLF);
	}

	return;
}
#endif // CefC_Contrace
/*--------------------------------------------------------------------------------------
	Receive Increment Access Cnount message
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
	sprintf (file_name, "%s/%s", csmgr_conf_dir, CefC_Csmgr_Conf_Name);

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
#if defined (CefC_Conping) || defined (CefC_Contrace)
/*--------------------------------------------------------------------------------------
	Incoming conping message
----------------------------------------------------------------------------------------*/
static void
csmgrd_incoming_conping_msg (
	CefT_Csmgrd_Handle* hdl,					/* csmgr daemon handle					*/
	int sock,									/* recv socket							*/
	unsigned char* buff,						/* receive message						*/
	int buff_len								/* receive message length				*/
) {
	/* Check support */
	if (hdl->cs_mod_int->content_exist_check == NULL) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Cache plugin has no conping function.\n");
#endif // CefC_Debug
		/* Content is not exist */
		csmgrd_conping_response_send (sock, CefC_Csmgr_Cob_NotExist);
		return;
	}

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Call cache plugin (content_exist_check)\n");
#endif // CefC_Debug
	if (hdl->cs_mod_int->content_exist_check (buff, buff_len) == CefC_Csmgr_Cob_Exist) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest, "Cob is exist.\n");
#endif // CefC_Debug
		/* Content is exist */
		csmgrd_conping_response_send (sock, CefC_Csmgr_Cob_Exist);
	} else {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Finest, "Cob is not exist.\n");
#endif // CefC_Debug
		/* Content is not exist */
		csmgrd_conping_response_send (sock, CefC_Csmgr_Cob_NotExist);
	}

	return;
}
/*--------------------------------------------------------------------------------------
	Send conping response message
----------------------------------------------------------------------------------------*/
static void
csmgrd_conping_response_send (
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
	buff[CefC_O_Fix_Type] = CefC_Csmgr_Msg_Type_Conping;
	index += CefC_Csmgr_Msg_HeaderLen;

	/* Set result */
	memcpy (buff + index, &result, sizeof (uint8_t));
	index += sizeof (uint8_t);

	/* Set Length */
	value16 = htons (index);
	memcpy (buff + CefC_O_Length, &value16, CefC_S_Length);

#ifdef CefC_Debug
	cef_dbg_write (CefC_Dbg_Fine, "Send the conping response(len = %u).\n", index);
	cef_dbg_buff_write (CefC_Dbg_Finest, buff, index);
#endif // CefC_Debug
	/* Send a response to source node */
	res = cef_csmgr_send_msg (sock, buff, index);

	if (res < 0) {
#ifdef CefC_Debug
		cef_dbg_write (CefC_Dbg_Fine, "Failed to send the conping response\n");
#endif // CefC_Debug
	}

	return;
}
#endif // (CefC_Conping) || (CefC_Contrace)
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
/*--------------------------------------------------------------------------------------
	Output Content Manager Message
----------------------------------------------------------------------------------------*/
// static void
// csmgrd_print (
// 	const char* fmt, 								/* output format					*/
// 	...												/* parameters						*/
// ) {
// 	va_list arg;
// 	struct timeval nowt;

// 	va_start (arg, fmt);
// 	gettimeofday (&nowt, NULL);

// 	fprintf (stderr, "%ld.%06u [%s] "
// 		, nowt.tv_sec, (unsigned) nowt.tv_usec, CSMGRD_PROGRAM_ID);
// 	vfprintf (stderr, fmt, arg);

// 	va_end (arg);
// }

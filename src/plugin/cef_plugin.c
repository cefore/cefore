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
 * cef_plugin.c
 */

#define __CEF_PLUGIN_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>

#include <cefore/cef_client.h>
#include <cefore/cef_plugin.h>
#ifdef CefC_Android
#include <cefore/cef_android.h>
#endif // CefC_Android

/****************************************************************************************
 Macros
 ****************************************************************************************/


/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/


/****************************************************************************************
 State Variables
 ****************************************************************************************/

static CefT_Plugin_Tag plugin_tag; 				/* store parameters in plugin.conf 		*/

/* logging 		*/
static uint16_t plugin_log_lv = CefT_Log_None;	/* logging flag 						*/
static FILE* plugin_log_fp = NULL;

/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Trims the specified line
----------------------------------------------------------------------------------------*/
static void 
cef_plugin_line_trim (
	const char* p1, 								/* line to trim 					*/
	char* p2										/* trimmed line 					*/
);
/*--------------------------------------------------------------------------------------
	Inserts the data to the tail of list
----------------------------------------------------------------------------------------*/
static void
cef_plugin_list_insert (
	CefT_List* list_ptr,							/* list pointer 					*/
	void* element_ptr								/* data to insert 					*/
);

#ifndef CefC_Android
/*--------------------------------------------------------------------------------------
	Init log process for plugin
----------------------------------------------------------------------------------------*/
static void 
cef_plugin_log_init (
	void 
);
/*--------------------------------------------------------------------------------------
	Stops logging
----------------------------------------------------------------------------------------*/
static void 
cef_plugin_log_stop (
	void 
);
#endif // CefC_Android

/****************************************************************************************
 For Debug Trace
 ****************************************************************************************/


/****************************************************************************************
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Inits plugin
----------------------------------------------------------------------------------------*/
int
cef_plugin_init (
	CefT_Plugin_Handle* plgin_hdl					/* plugin handle 					*/
) {
	/* Reads the plugin.conf and stores values as the string 	*/
	cef_plugin_config_read ();
	
	/* Creates the tx buffer 									*/
	plgin_hdl->tx_que = cef_rngque_create (CefC_Tx_Que_Size);
	plgin_hdl->tx_que_mp 
		= cef_mpool_init ("CefTxMSF", sizeof (CefT_Tx_Elem), CefC_Tx_Que_Size);
	
#ifndef CefC_Android
	/* Init logging 		*/
	cef_plugin_log_init ();
	
	/* Output log 			*/
	cef_plugin_log_write (CefT_Log_General, "plugin", 
		"Initialization process is completed.");
	
#endif // CefC_Android
	
	return (1);
}

/*--------------------------------------------------------------------------------------
	Destroy plugin
----------------------------------------------------------------------------------------*/
int
cef_plugin_destroy (
	CefT_Plugin_Handle* plgin_hdl					/* plugin handle 					*/
) {
	
#ifndef CefC_Android
	/* Output log 			*/
	cef_plugin_log_write (CefT_Log_General, "plugin", 
		"Post process is completed.");
	
	/* Stop logging 		*/
	cef_plugin_log_stop ();
#endif // CefC_Android
	
	cef_rngque_destroy (plgin_hdl->tx_que);
	cef_mpool_destroy (plgin_hdl->tx_que_mp);
	
	return (1);
}

/*--------------------------------------------------------------------------------------
	Gets the size of the specified list
----------------------------------------------------------------------------------------*/
int 												/* size of the specified list 		*/
cef_plugin_list_size (
	CefT_List* list_ptr								/* list pointer 					*/
) {
	return (list_ptr->size);
}

/*--------------------------------------------------------------------------------------
	Gets the stored data which is listed in the specified position
----------------------------------------------------------------------------------------*/
void* 												/* pointer to the data which is 	*/
													/* listed in the specified position */
cef_plugin_list_access (
	CefT_List* list_ptr,							/* list pointer 					*/
	int pos_index									/* position in the list to access 	*/
) {
	int i;
	CefT_List_Elem* list_elem_ptr;
	
	/* Adjusts the specified position 		*/
	if (pos_index < 0) {
		return (list_ptr->head_ptr->elem_ptr);
	}
	if (pos_index > list_ptr->size) {
		return (list_ptr->tail_ptr->elem_ptr);
	}
	
	/* Gets the stored data which is listed in the specified position  */
	list_elem_ptr = list_ptr->head_ptr;
	
	for (i = 0 ; i < pos_index ; i++) {
		list_elem_ptr = list_elem_ptr->next;
	}
	
	return (list_elem_ptr->elem_ptr);
}

/*--------------------------------------------------------------------------------------
	Gets informations of specified tag
----------------------------------------------------------------------------------------*/
CefT_Plugin_Tag* 									/* tag informations					*/
cef_plugin_tag_get (
	const char* tag 								/* tag 								*/
) {
	CefT_Plugin_Tag* 	tp;
	
	tp = plugin_tag.next;
	
	while (tp) {
		
		if (strcmp (tag, tp->tag) == 0) {
			return (tp);
		}
		tp = tp->next;
	}
	return (NULL);
}

/*--------------------------------------------------------------------------------------
	Gets values of specified tag and parameter
----------------------------------------------------------------------------------------*/
CefT_List* 											/* listed parameters 				*/
cef_plugin_parameter_value_get (
	const char* tag, 								/* tag 								*/
	const char* parameter							/* parameter 						*/
) {
	CefT_Plugin_Tag* 	tp;
	CefT_Plugin_Param* 	pp;
	
	tp = plugin_tag.next;
	
	while (tp) {
		
		if (strcmp (tag, tp->tag) == 0) {
			pp = tp->params.next;
			
			while (pp) {
				if (strcasecmp (parameter, pp->param) == 0) {
					return (pp->values);
				}
				pp = pp->next;
			}
		}
		tp = tp->next;
	}
	return (NULL);
}

/*--------------------------------------------------------------------------------------
	Reads the plugin.conf and stores values as the string
----------------------------------------------------------------------------------------*/
void 
cef_plugin_config_read (
	void 
) {
	char 	ws[1024];
	char 	dirpath[1024];
	FILE*	fp;
	char 	buff[1032];
	char 	work[1032];
	char 	val[33];
	int 	len, i, n;
	char* 	vp;
	CefT_Plugin_Tag* 	tp;
	CefT_Plugin_Param* 	pp;
	
	/* Obtains the directory path where the plugin.conf file is located. */
#ifndef CefC_Android
	cef_client_config_dir_get (ws);
#else // CefC_Android
	/* Android local cache storage is data/data/package_name/	*/
	cef_android_conf_path_get (ws);
#endif // CefC_Android
	
	if (mkdir (ws, 0777) != 0) {
		if (errno == ENOENT) {
			return;
		}
	}
	
	sprintf (dirpath, "%s/plugin", ws);
	
	if (mkdir (dirpath, 0777) != 0) {
		if (errno == ENOENT) {
			return;
		}
	}
	
	sprintf (ws, "%s/plugin.conf", ws);

	/* Opens the cefnetd's config file. */
	fp = fopen (ws, "r");
	if (fp == NULL) {
		return;
	}
	
	/* Inits the structure to store the parameters of plugin 		*/
	memset (&plugin_tag, 0, sizeof (CefT_Plugin_Tag));
	tp = &plugin_tag;
	pp = &(plugin_tag.params);
	
	while (fgets (buff, 1024, fp) != NULL) {
		cef_plugin_line_trim (buff, work);
		
		if (work[0] == 0x00) {
			continue;
		}
		if (strchr (work, '[') && strchr (work, ']')) {
			
			tp->next = (CefT_Plugin_Tag*) malloc (sizeof (CefT_Plugin_Tag));
			tp = tp->next;
			memset (tp, 0, sizeof (CefT_Plugin_Tag));
			
			/* Sets the tag 			*/
			strncpy (tp->tag, &work[1], (int) strlen (work) - 1);
			tp->tag[strlen (work) - 2] = 0x00;
			
			pp = &(tp->params);
			
		} else {
			if (strchr (work, '=') == NULL) {
				continue;
			}
			
			pp->next = (CefT_Plugin_Param*) malloc (sizeof (CefT_Plugin_Param));
			pp = pp->next;
			memset (pp, 0, sizeof (CefT_Plugin_Param));
			tp->num++;
			
			pp->values = (CefT_List*) malloc (sizeof (CefT_List));
			pp->values->size = 0;
			pp->values->head_ptr = (CefT_List_Elem*) NULL;
			pp->values->tail_ptr = (CefT_List_Elem*) NULL;
			
			len = (int) strlen (work);
			
			for (i = 0 ; i < len ; i++) {
				if (work[i] == '=') {
					pp->param[i] = 0x00;
					i++;
					break;
				}
				pp->param[i] = work[i];
			}
			
			for (n = 0 ; i < len ; i++, n++) {
				if (work[i] == ',') {
					val[n] = 0x00;
					vp = (char*) malloc (sizeof (char) * (strlen (val) + 1));
					strcpy (vp, val);
					cef_plugin_list_insert (pp->values, vp);
					n = 0;
					i++;
				}
				val[n] = work[i];
			}
			val[n] = 0x00;
			vp = (char*) malloc (sizeof (char) * (strlen (val) + 1));
			strcpy (vp, val);
			cef_plugin_list_insert (pp->values, vp);
		}
	}
	
	fclose (fp);
	
	return;
}

/*--------------------------------------------------------------------------------------
	Inserts the data to the tail of list
----------------------------------------------------------------------------------------*/
static void
cef_plugin_list_insert (
	CefT_List* list_ptr,							/* list pointer 					*/
	void* element_ptr								/* data to insert 					*/
) {
	CefT_List_Elem* list_elem_ptr;
	
	list_elem_ptr = (CefT_List_Elem*) malloc (sizeof (CefT_List_Elem));
	list_elem_ptr->next     = (CefT_List_Elem*) NULL;
	list_elem_ptr->prev     = (CefT_List_Elem*) NULL;
	list_elem_ptr->elem_ptr = element_ptr;
	
	if (list_ptr->size != 0) {
		
		list_ptr->tail_ptr->next = list_elem_ptr;
		list_elem_ptr->prev = list_ptr->tail_ptr;
		list_ptr->tail_ptr = list_elem_ptr;
		
	} else {
		
		list_ptr->head_ptr = list_elem_ptr;
		list_ptr->tail_ptr = list_elem_ptr;
		
	}
	
	list_ptr->size++;
	
	return;
}

/*--------------------------------------------------------------------------------------
	Trims the specified line
----------------------------------------------------------------------------------------*/
static void 
cef_plugin_line_trim (
	const char* p1, 								/* line to trim 					*/
	char* p2										/* trimmed line 					*/
) {
	
	while (*p1) {
		if ((*p1 == 0x0d) || (*p1 == 0x0a)) {
			break;
		}
		
		if ((*p1 == 0x20) || (*p1 == 0x09)) {
			p1++;
			continue;
		} else {
			*p2 = *p1;
		}
		
		p1++;
		p2++;
	}
	*p2 = 0x00;
	
	return;
}

#ifndef CefC_Android

/*--------------------------------------------------------------------------------------
	Output log
----------------------------------------------------------------------------------------*/
void 
cef_plugin_log_write (
	uint16_t log_level, 
	const char* plugin, 
	const char* log
) {
	struct timeval t;
	uint64_t tus;
	
	if (log_level & plugin_log_lv) {
		gettimeofday (&t, NULL);
		tus = t.tv_sec * 1000000 + t.tv_usec;
		
		fprintf (plugin_log_fp, "["FMTU64"][%s] %s\n", tus, plugin, log);
	}
	
	return;
}

/*--------------------------------------------------------------------------------------
	Init log process for plugin
----------------------------------------------------------------------------------------*/
static void 
cef_plugin_log_init (
	void 
) {
	CefT_List* lp 		= NULL;
	char* value_str 	= NULL;
	char fname1[1024];
	char fname2[1024];
	char fpath[1024];
	int i;
	
	/* Obtains level of logging 			*/
	lp = cef_plugin_parameter_value_get ("COMMON", "log");
	
	if (lp) {
		value_str = (char*) cef_plugin_list_access (lp, 0);
		if (strcmp (value_str, "yes") == 0) {
			plugin_log_lv = CefT_Log_General;
		}
	}
	
	if (plugin_log_lv == CefT_Log_None) {
		return;
	}
	
	/* Obtains path to output log files		*/
	lp = cef_plugin_parameter_value_get ("COMMON", "logpath");
	
	if (lp) {
		value_str = (char*) cef_plugin_list_access (lp, 0);
		strcpy (fpath, value_str);
	} else {
		cef_client_config_dir_get (fpath);
	}
	
	/* Removes the most old log file  		*/
	sprintf (fname1, "%s/plugin5.log", fpath);
	remove (fname1);
	
	/* Renames the old log files 			*/
	for (i = 4 ; i > 0 ; i--) {
		sprintf (fname1, "%s/plugin%d.log", fpath, i + 1);
		sprintf (fname2, "%s/plugin%d.log", fpath, i);
		rename (fname2, fname1); 
	}
	sprintf (fname1, "%s/plugin1.log", fpath);
	sprintf (fname2, "%s/plugin.log", fpath);
	rename (fname2, fname1); 
	
	/* Creates the new log file 			*/
	plugin_log_fp = fopen (fname2, "w");
	if (plugin_log_fp == NULL) {
		plugin_log_lv = CefT_Log_None;
		return;
	}
	
	return;
}

/*--------------------------------------------------------------------------------------
	Stops logging
----------------------------------------------------------------------------------------*/
static void 
cef_plugin_log_stop (
	void 
) {
	
	if (plugin_log_fp) {
		fclose (plugin_log_fp);
	}
	
	return;
}
#endif // CefC_Android


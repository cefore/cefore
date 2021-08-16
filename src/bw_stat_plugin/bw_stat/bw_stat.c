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
 * bw_stat.c
 */

#define __CEFNETD_BW_STAT_SOURCE__

//#define		__BW_STAT_DEV__
//#define		__BW_STAT_PRINT__
//#define		__BW_THREAD_DEV__

/****************************************************************************************
 Include Files
 ****************************************************************************************/

#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>

#include <openssl/md5.h>

#include "bw_stat.h"
#include <cefore/cef_client.h>
#include <cefore/cef_frame.h>
#include <cefore/cef_plugin.h>


/****************************************************************************************
 Macros
 ****************************************************************************************/

#ifdef __APPLE__
#define CefnetdC_Library_Name	".dylib"
#else // __APPLE__
#define CefnetdC_Library_Name	".so"
#endif // __APPLE__


#define		BW_MEGA		1000000.0
#define		BW_SPEED_FNM	"/sys/class/net/%s/speed"
#define		BW_TX_BYTE_FNM	"/sys/class/net/%s/statistics/tx_bytes"

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/


/****************************************************************************************
 State Variables
 ****************************************************************************************/
 
static		bw_stat_tbl*	BW_stat_tbl_p = NULL;
static		bw_stat_tbl_t*	BW_stat_tbl   = NULL;
static		int				bw_util_calc_interval;
static		int				bw_calc_count = 0;

#if 0
static sem_t*					mem_comn_buff_sem;
static pthread_t				mem_thread_th;
static int 						mem_thread_f = 0;

static pthread_mutex_t 			mem_cs_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

static pthread_t				bw_stat_calc_thread_th;
static pthread_mutex_t 			bw_stat_calc_mutex = PTHREAD_MUTEX_INITIALIZER;
static int 						bw_stat_calc_thread_f = 0;


static void
bw_stat_tbl_entry_create( char* if_name, char* if_rate, int run_f );
static int
bw_stat_tbl_if_info_get( void );
static int
bw_stat_tbl_index_get( char* );
#ifdef	__BW_STAT_DEV__
static void
bw_stat_tbl_entry_print( void );
#endif
static void
bw_stat_list_to_tbl( void );


static void*
bw_stat_calc_thread( void* );


/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/
/*--------------------------------------------------------------------------------------
	Init API
----------------------------------------------------------------------------------------*/
static int							/* The return value is negative if an error occurs	*/
bw_stat_init (
	int		calc_interval
) {
    FILE*	fp;
    char	buf[1024];
    char	cmd_buf[128];
    int		res;
	int		rc = -1;

#ifdef	__BW_STAT_DEV__
	fprintf( stderr, "[%s] interval:%d\n", __func__, calc_interval );
#endif

	bw_util_calc_interval = calc_interval;
	
	BW_stat_tbl_p = (bw_stat_tbl*)malloc(sizeof(bw_stat_tbl));
	BW_stat_tbl_p->entry_num = 0;
	BW_stat_tbl_p->tbl_entry = NULL;
	BW_stat_tbl_p->tail_p = NULL;
	BW_stat_tbl = NULL;

#ifndef	CefC_MACOS
	char*	kw_mtu = "mtu";
	char*	kw_run = "RUNNING";
	char*	kw_ethernet = "(Ethernet)";
	char	if_name[128];
	int		mtu_f = 0;
	int		running_f = 0;
	
	char fld01[128], fld02[128], fld03[128], fld04[128];
	
	sprintf( cmd_buf, "ifconfig -a" );
    if ((fp = popen(cmd_buf, "r")) != NULL) {
        while (fgets(buf, sizeof(buf), fp) != NULL) {
			if ( strstr( buf, kw_mtu ) != NULL ) {
				mtu_f = 1;
#ifdef	__BW_STAT_DEV__
				printf( "detect mtu\n" );
#endif
				if ( strstr( buf, kw_run ) != NULL ) {
					running_f = 1;
#ifdef	__BW_STAT_DEV__
				printf( "detect RUNNING\n" );
#endif
				} else {
					running_f = 0;
				}
				sscanf (buf, "%s %s %s %s",
						fld01, fld02, fld03, fld04);
#ifdef	__BW_STAT_DEV__
				printf( "IF name:%s\n", fld01 );
#endif
				strcpy(if_name, fld01);
			} else if ( strstr( buf, kw_ethernet ) != NULL ) {
				if ( mtu_f == 1 ) {
#ifdef	__BW_STAT_DEV__
				printf( "call bw_stat_tbl_entry_create\n" );
#endif
					bw_stat_tbl_entry_create(if_name, NULL, running_f);
				}
				mtu_f = 0;
				running_f = 0;
			} else {
//				mtu_f = 0;
//				running_f = 0;
			}
        }
        pclose(fp);
		
		res = bw_stat_tbl_if_info_get();
#ifdef	__BW_STAT_DEV__
		fprintf( stderr, "[%s] res:%d = bw_stat_tbl_if_info_get()\n", __func__, res );
#endif
		if ( res < 0 ) {
			return( -1 );
		}
#ifdef	__BW_STAT_DEV__
		bw_stat_tbl_entry_print();
#endif
        rc = 0;
    }
#else
	char*	kw_mtu = "mtu";
	char*	kw_ethernet = "Ethernet";
	char*	kw_type = "type:";
	char*	kw_link_rate = "link rate:";
	int		mtu_f = 0;
	int		ether_f = 0;
	int		link_rate_f = 0;
	char	if_name[128];
	char	if_rate[128];
	char fld01[128], fld02[128], fld03[128], fld04[128],
		 fld05[128], fld06[128];

	sprintf( cmd_buf, "ifconfig -a -v" );
    if ((fp = popen(cmd_buf, "r")) != NULL) {
        while (fgets(buf, sizeof(buf), fp) != NULL) {
			if ( strstr( buf, kw_mtu ) != NULL ) {
				/* check */
				if ( (mtu_f == 1) && (ether_f == 1) && (link_rate_f == 1) ) {
					bw_stat_tbl_entry_create(if_name, if_rate, 1);
					mtu_f = 0;
					ether_f = 0;
					link_rate_f = 0;
				}
				mtu_f = 1;
				ether_f = 0;
				link_rate_f = 0;
				sscanf (buf, "%s %s %s %s %s %s",
						fld01, fld02, fld03, fld04, fld05, fld06);
#ifdef	__BW_STAT_DEV__
				printf( "IF name:%s\n", fld01 );
#endif
				strcpy(if_name, fld01);
			} else if ( strstr( buf, kw_type ) != NULL ) {
				sscanf (buf, "%s %s",
						fld01, fld02);
				if ( strncmp( fld02, kw_ethernet, 8 ) == 0 ) {
					ether_f = 1;
				}
			} else if ( strstr( buf, kw_link_rate ) != NULL ) {
				link_rate_f = 1;
				sscanf (buf, "%s %s %s %s",
						fld01, fld02, fld03, fld04);
#ifdef	__BW_STAT_DEV__
				printf( "IF rate:%s\n", fld03 );
#endif
				strcpy(if_rate, fld03);
				if ( (mtu_f == 1) && (ether_f == 1) && (link_rate_f == 1) ) {
					bw_stat_tbl_entry_create(if_name, if_rate, 1);
				}
				mtu_f = 0;
				ether_f = 0;
				link_rate_f = 0;
			} else {
//				mtu_f = 0;
//				ether_f = 0;
//				link_rate_f = 0;
			}
        }
 		/* check */
		if ( (mtu_f == 1) && (ether_f == 1) && (link_rate_f == 1) ) {
			bw_stat_tbl_entry_create(if_name, if_rate, 1);
			mtu_f = 0;
			ether_f = 0;
			link_rate_f = 0;
		}
		pclose(fp);

		res = bw_stat_tbl_if_info_get();
		if ( res < 0 ) {
			fprintf( stderr, "res:%d\n", res );
			return( -1 );
		}
#ifdef	__BW_STAT_DEV__
		bw_stat_tbl_entry_print();
#endif
        rc = 0;
    }
#endif

	/* List(tbl_p) to Tbl */
	bw_stat_list_to_tbl();

	/* Create bw_stat_calc_thread */
	if (pthread_create (&bw_stat_calc_thread_th, NULL, bw_stat_calc_thread, NULL) == -1) {
		return( -1 );
	}
	bw_stat_calc_thread_f = 1;
	rc = 0;



   return (rc);
}
/*--------------------------------------------------------------------------------------

----------------------------------------------------------------------------------------*/
static double						/* The return value is negative if an error occurs	*/
bw_stat_get (
	int if_idx
) {
	
	int			i;
	bw_stat_tbl_t*	entry;

#ifdef	__BW_STAT_DEV__
	fprintf( stderr, "%s\n", __func__ );
#endif

	if ( BW_stat_tbl_p->entry_num <= 0 ) {
		return( 0.0 );
	}

	entry = BW_stat_tbl_p->tbl_entry;

	for ( i = 0; i < BW_stat_tbl_p->entry_num; i++ ) {
		if ( entry->index == if_idx ) {
			return( entry->bw_utilization );
		}
		entry = entry->next;
	}

	return (0.0);
}

/*--------------------------------------------------------------------------------------
	Destroy content store
----------------------------------------------------------------------------------------*/
static void
bw_stat_destroy (
	void
) {
	int			i;
	bw_stat_tbl_t*	entry;
	bw_stat_tbl_t*	entry_next;
//	void* status;
	
#ifdef	__BW_STAT_DEV__
	fprintf( stderr, "%s\n", __func__ );
	fprintf( stderr, "\tBW_stat_tbl_p->entry_num:%d\n", BW_stat_tbl_p->entry_num );
#endif

	pthread_mutex_destroy (&bw_stat_calc_mutex);

	if ( bw_stat_calc_thread_f ) {
		bw_stat_calc_thread_f = 0;
//		pthread_join (bw_stat_calc_thread_th, &status);
	}

	if ( BW_stat_tbl_p == NULL ) {
		return;
	}
	if ( BW_stat_tbl_p->entry_num <= 0 ) {
		free( BW_stat_tbl_p );
		return;
	}

	if ( BW_stat_tbl != NULL ) {
		for ( i = 0; i < BW_stat_tbl_p->entry_num; i++ ) {
			free(BW_stat_tbl[i].if_name);
		}
		free(BW_stat_tbl);
	}
	

	entry = BW_stat_tbl_p->tbl_entry;
	
	for ( i = 0; i < BW_stat_tbl_p->entry_num; i++ ) {
		entry_next = entry->next;
		free( entry->if_name );
		free( entry );
		entry = entry_next;
	}
	free( BW_stat_tbl_p );
	
	return;
}

/*--------------------------------------------------------------------------------------
	Road the plugin
----------------------------------------------------------------------------------------*/
int
cefnetd_bw_stat_plugin_load (
	CefT_Plugin_Bw_Stat* cs_in
) {
	cs_in->init = bw_stat_init;
	cs_in->destroy = bw_stat_destroy;
	cs_in->stat_get = bw_stat_get;
	cs_in->stat_tbl_index_get = bw_stat_tbl_index_get;
	
	return (0);
}

static void
bw_stat_tbl_entry_create( char* if_name, char* if_rate, int run_f ) {
	
	bw_stat_tbl_t*	entry;
	int				if_name_len;

#ifdef	__BW_STAT_DEV__
	fprintf( stderr, "[%s] IN if_name:%s\n", __func__, if_name );
#endif
	
	entry = (bw_stat_tbl_t*)malloc(sizeof(bw_stat_tbl_t));
	if_name_len = strlen( if_name );
	entry->index = BW_stat_tbl_p->entry_num;
	entry->if_name = (char*)malloc(sizeof(char) * if_name_len);
	entry->is_running = run_f;
	memset( entry->if_name, 0, if_name_len );
	memcpy(entry->if_name, if_name, (if_name_len-1));
#ifndef	CefC_MACOS
	entry->if_speed = 0.0;
#else
	entry->if_speed = atof(if_rate);
	entry->if_speed *= BW_MEGA;
#endif
	entry->prev_tx_byte = 0;
	entry->bw_utilization = 0.0;
	entry->next = NULL;
	
	if ( BW_stat_tbl_p->tbl_entry == NULL ) {
		BW_stat_tbl_p->tbl_entry = entry;
		BW_stat_tbl_p->tail_p = entry;
	} else {
		BW_stat_tbl_p->tail_p->next = entry;
		BW_stat_tbl_p->tail_p = entry;
	}
	BW_stat_tbl_p->entry_num++;

#ifdef	__BW_STAT_DEV__
	fprintf( stderr, "[%s] OUT BW_stat_tbl_p->entry_num:%d\n", __func__, BW_stat_tbl_p->entry_num );
#endif

	
	return;
}

static int
bw_stat_tbl_if_info_get( void ) {

	int		i;
	bw_stat_tbl_t*	entry;
	FILE*	fp;

#ifdef	__BW_STAT_DEV__
	fprintf( stderr, "[%s] BW_stat_tbl_p->entry_num:%d\n", __func__, BW_stat_tbl_p->entry_num );
#endif

	if ( BW_stat_tbl_p->entry_num <= 0 ) {
		return( 0 );
	}

#ifndef	CefC_MACOS
	char	fname[1024];
	char	buf[128];

	entry = BW_stat_tbl_p->tbl_entry;
	
	for ( i = 0; i < BW_stat_tbl_p->entry_num; i++ ) {
		if ( entry->is_running == 0 ) {
			continue;
		}
		/* speed */
		sprintf( fname, BW_SPEED_FNM, entry->if_name );
    	char	cmd_buf[256];
		sprintf( cmd_buf, "cat %s", fname );
		fp = popen(cmd_buf, "r");
		if (fp == NULL) {
			fprintf( stderr, "File:%s popen error.\n", fname );
			return( -1 );
		}
		if (fgets(buf, sizeof(buf), fp) != NULL) {
			entry->if_speed = atof( buf );
			if ( entry->if_speed > 0 ) {
				entry->if_speed *= BW_MEGA;
			}
		}
		pclose(fp);
		/* tx_bytes */
		sprintf( fname, BW_TX_BYTE_FNM, entry->if_name );
		sprintf( cmd_buf, "cat %s", fname );
		fp = popen(cmd_buf, "r");
		if (fp == NULL) {
			fprintf( stderr, "File:%s popen error.\n", fname );
			return( -1 );
		}
		if (fgets(buf, sizeof(buf), fp) != NULL) {
			entry->prev_tx_byte = atoll( buf );
		}
		pclose(fp);
		entry = entry->next;
	}
#else
    char	buf[1024];
    char	cmd_buf[128];
	char fld01[128], fld02[128], fld03[128], fld04[128],
		 fld05[128], fld06[128], fld07[128], fld08[128],
		 fld09[128], fld10[128], fld11[128];

	entry = BW_stat_tbl_p->tbl_entry;

	sprintf( cmd_buf, "netstat -b -n -i" );
    if ((fp = popen(cmd_buf, "r")) != NULL) {
		for ( i = 0; i < BW_stat_tbl_p->entry_num; i++ ) {
	        while (fgets(buf, sizeof(buf), fp) != NULL) {
				sscanf (buf, "%s %s %s %s %s %s %s %s %s %s %s",
						fld01, fld02, fld03, fld04, fld05, fld06, fld07, fld08, fld09, fld10, fld11);
				if ( strcmp( fld01, entry->if_name ) == 0 ) {
					entry->prev_tx_byte = atoll(fld10);
					break;
				}
			}
			entry = entry->next;
		}
		pclose(fp);
	} else {
		return( -1 );
	}
#endif

	return(0);
}

static void
bw_stat_list_to_tbl( void )
{
	int		i;
	bw_stat_tbl_t*	entry;

	if ( BW_stat_tbl_p->entry_num <= 0 ) {
		return;
	}

	entry = BW_stat_tbl_p->tbl_entry;
	
	BW_stat_tbl = (bw_stat_tbl_t*)malloc(sizeof(bw_stat_tbl_t) * BW_stat_tbl_p->entry_num);
	
	for ( i = 0; i < BW_stat_tbl_p->entry_num; i++ ) {
		BW_stat_tbl[i].if_name = (char*)malloc(sizeof(char) * strlen(entry->if_name)+1);
		memset( BW_stat_tbl[i].if_name, 0, (sizeof(char) * strlen(entry->if_name)+1) );
		strcpy( BW_stat_tbl[i].if_name, entry->if_name );
		BW_stat_tbl[i].if_speed = entry->if_speed;
		BW_stat_tbl[i].prev_tx_byte = entry->prev_tx_byte;
		BW_stat_tbl[i].bw_utilization = entry->bw_utilization;
		BW_stat_tbl[i].next = NULL;

		entry = entry->next;
	}
	return;
}

static int
bw_stat_tbl_index_get( char* if_name ) {
	
	int		i;
	bw_stat_tbl_t*	entry;

	entry = BW_stat_tbl_p->tbl_entry;
	
	for ( i = 0; i < BW_stat_tbl_p->entry_num; i++ ) {
		if ( strcmp( entry->if_name, if_name ) == 0 ) {
			return(entry->index);
		}
		entry = entry->next;
	}
	return( -1 );
}
#ifdef	__BW_STAT_DEV__
static void
bw_stat_tbl_entry_print( void ) {

	int		i;
	bw_stat_tbl_t*	entry;

	entry = BW_stat_tbl_p->tbl_entry;

	for ( i = 0; i < BW_stat_tbl_p->entry_num; i++ ) {
		fprintf( stderr, "index:%d   if_name:%s   speed:%f   prev_tx_byte:"FMTU64"   util:%f\n",
				entry->index, entry->if_name, entry->if_speed, entry->prev_tx_byte, entry->bw_utilization );
		entry = entry->next;
	}

	return;
}
#endif

static void*
bw_stat_calc_thread( 
	void* arg
) {
	int		i;
	bw_stat_tbl_t*	entry;
	FILE*	fp;

	int64_t	now_tx_byte;
	int64_t	diff_tx_byte;
	double		bw_utilization;
	double		tx_average;
#ifdef	__BW_THREAD_DEV__
	fprintf( stderr, "%s IN\n", __func__ );
#endif


	pthread_t self_thread = pthread_self();
	pthread_detach(self_thread);
	
	while( bw_stat_calc_thread_f ) {
		bw_calc_count++;

		if ( bw_calc_count == bw_util_calc_interval ) {
#ifdef	__BW_THREAD_DEV__
		fprintf( stderr, "%s Calc\n", __func__ );
#endif

#ifndef	CefC_MACOS
			char	fname[1024];
			char	buf[128];
			double	now_speed;

			entry = BW_stat_tbl_p->tbl_entry;
	
			for ( i = 0; i < BW_stat_tbl_p->entry_num; i++ ) {
		    	char	cmd_buf[256];
				if ( entry->is_running == 0 ) {
					continue;
				}
				/* Speed */
				sprintf( fname, BW_SPEED_FNM, entry->if_name );
				sprintf( cmd_buf, "cat %s", fname );
				fp = popen(cmd_buf, "r");
				if (fp == NULL) {
					fprintf( stderr, "File:%s popen error.\n", fname );
				} else {
					if (fgets(buf, sizeof(buf), fp) != NULL) {
						now_speed = atof( buf );
						if ( now_speed > 0 ) {
							now_speed *= BW_MEGA;
						}
						entry->if_speed = now_speed;
						pclose(fp);
					}
				}
				bw_utilization = 0.0;
				/* tx_bytes */
				sprintf( fname, BW_TX_BYTE_FNM, entry->if_name );
				sprintf( cmd_buf, "cat %s", fname );
				fp = popen(cmd_buf, "r");
				if (fp == NULL) {
					fprintf( stderr, "File:%s popen error.\n", fname );
					entry = entry->next;
					continue;
				}
				if (fgets(buf, sizeof(buf), fp) != NULL) {
					now_tx_byte = atoll( buf );
					diff_tx_byte = now_tx_byte - entry->prev_tx_byte;
					if ( (entry->if_speed > 0.0) && (diff_tx_byte >= 0) ) {
						tx_average = (double)diff_tx_byte / (double)bw_util_calc_interval;
						bw_utilization = ((double)(tx_average*8)) / entry->if_speed;
						entry->bw_utilization = bw_utilization * 100.0;
#ifdef	__BW_STAT_PRINT__
	fprintf( stderr, "%s Util:%f\n", __func__, entry->bw_utilization );
#endif
					}
					entry->prev_tx_byte = now_tx_byte;
				}
				pclose(fp);
				entry = entry->next;
			}
			

#else	//CefC_MACOS
			char	buf[1024];
			char	cmd_buf[128];
			char fld01[128], fld02[128], fld03[128], fld04[128],
				 fld05[128], fld06[128], fld07[128], fld08[128],
				 fld09[128], fld10[128], fld11[128];

			entry = BW_stat_tbl_p->tbl_entry;

			sprintf( cmd_buf, "netstat -b -n -i" );
		    if ((fp = popen(cmd_buf, "r")) != NULL) {
				for ( i = 0; i < BW_stat_tbl_p->entry_num; i++ ) {
    			    while (fgets(buf, sizeof(buf), fp) != NULL) {
						sscanf (buf, "%s %s %s %s %s %s %s %s %s %s %s",
								fld01, fld02, fld03, fld04, fld05, fld06, fld07, fld08, fld09, fld10, fld11);
						if ( strcmp( fld01, entry->if_name ) == 0 ) {
							entry->prev_tx_byte = atoll(fld10);
							now_tx_byte = atoll( buf );
							diff_tx_byte = now_tx_byte - entry->prev_tx_byte;
							if ( (entry->if_speed > 0.0) && (diff_tx_byte >= 0) ) {
								tx_average = (double)diff_tx_byte / (double)bw_util_calc_interval;
								bw_utilization = ((double)(tx_average*8)) / entry->if_speed;
								entry->bw_utilization = bw_utilization * 100.0;
#ifdef	__BW_STAT_PRINT__
	fprintf( stderr, "%s Util:%f\n", __func__, entry->bw_utilization );
#endif
							}
							entry->prev_tx_byte = now_tx_byte;
							break;
						}
					}
					entry = entry->next;
				}
				pclose(fp);
			}
#endif

#ifdef	__BW_STAT_DEV__
			bw_stat_tbl_entry_print();
#endif

			bw_calc_count = 0;
		}
	
		sleep(1);
	}

#ifdef	__BW_THREAD_DEV__
	fprintf( stderr, "%s OUT\n", __func__ );
#endif
	
	pthread_exit (NULL);
	
	return ((void*) NULL);
	
}


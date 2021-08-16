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
 * bw_stat.h
 */
#ifndef __CEFNETD_BW_STAT_HEADER__
#define __CEFNETD_BW_STAT_HEADER__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdint.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <netinet/in.h>
#include <string.h>

#include <cefore/cef_face.h>
#include <cefore/cef_frame.h>

#include <cefore/cef_log.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

/*------------------------------------------------------------------
	Limitation
--------------------------------------------------------------------*/

/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/

typedef struct _bw_stat_tbl_t {
	int			index;
	char*		if_name;
	int			is_running;
	double		if_speed;
	int64_t		prev_tx_byte;
	double		bw_utilization;
	struct _bw_stat_tbl_t*	next;
} bw_stat_tbl_t;

typedef	struct _bw_stat_tbl {
	int				entry_num;
	bw_stat_tbl_t*	tbl_entry;
	bw_stat_tbl_t*	tail_p;
} bw_stat_tbl;

#endif // __CSMGRD_MEM_CACHE_HEADER__

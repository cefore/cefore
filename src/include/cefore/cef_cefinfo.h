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
 * cef_cefinfo.h
 */

#ifndef __CEFINFO_HEADER__
#define __CEFINFO_HEADER__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdint.h>
#include <arpa/inet.h>

#include <cefore/cef_csmgr.h>
#include <cefore/cef_define.h>
#include <cefore/cef_fib.h>
#include <cefore/cef_hash.h>



/****************************************************************************************
 Macros
 ****************************************************************************************/

#define CefstatC_MaxUri		128


/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/

/*------------------------------------------------------------------*/
/* for cache information field										*/
/*------------------------------------------------------------------*/
typedef struct {
	size_t size;									/* total size of a content			*/
	int cob_num;									/* number of Cob constituting a 	*/
													/* content							*/
	struct in_addr upaddr;							/* IP address of first arrival		*/
	unsigned int freshness_sec;						/* length of time until content is	*/
													/* expired							*/
	unsigned int access_cnt;						/* access-count of ContentObject	*/
	unsigned int elapsed_time;						/* elapsed time after content was	*/
													/* stored							*/
	u_int32_t min_seq_num;							/* sequence number					*/
	u_int32_t max_seq_num;							/* sequence number					*/
	
} CefstatT_Cache;


/****************************************************************************************
 Function Declarations
 ****************************************************************************************/


#endif // __CEFINFO_HEADER__

/*
 * Copyright (c) 2016-2019, National Institute of Information and Communications
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
 * cef_print.c
 */

#define __CEF_PRINT_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <sys/time.h>

#include <cefore/cef_define.h>
#include <cefore/cef_print.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/


/****************************************************************************************
 State Variables
 ****************************************************************************************/


/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

/****************************************************************************************
 For Debug Trace
 ****************************************************************************************/

char *CEF_PROGRAM_ID = "cefnetd";
#ifdef CefC_DebugOld
unsigned int CEF_DEBUG;
#endif // CefC_DebugOld

/****************************************************************************************
 ****************************************************************************************/
void
cef_print (
	const char* fmt, 								/* output format					*/
	...												/* parameters						*/
) {
	va_list arg;
	struct timeval nowt;

	va_start (arg, fmt);
	gettimeofday (&nowt, NULL);

	fprintf (stderr, "%ld.%06u [%s] "
		, nowt.tv_sec, (unsigned) nowt.tv_usec, CEF_PROGRAM_ID);
	vfprintf (stderr, fmt, arg);

	va_end (arg);
}
void
cef_buff_print (
	const unsigned char* buff,
	uint16_t len
) {
	int i;
	int n = 0;
	int s = 0;


	fprintf (stderr, "======================================================\n");
	fprintf (stderr, "      0  1  2  3  4  5  6  7    8  9  0  1  2  3  4  5\n");
	for (i = 0 ; i < len ; i++) {
		if (n == 0) {
			fprintf (stderr, "%3d: ", s);
			s++;
		}
		fprintf (stderr, "%02X ", buff[i]);

		if (n == 7) {
			fprintf (stderr, "  ");
		}
		n++;
		if (n > 15) {
			n = 0;
			fprintf (stderr, "\n");
		}
	}
	fprintf (stderr, "\n======================================================\n");
}

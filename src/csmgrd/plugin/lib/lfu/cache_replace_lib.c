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
 * lru.c
 */

/*
	lru.c is a primitive LRU implementation.
*/

/****************************************************************************************
 Include Files
 ****************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <cefore/cef_hash.h>
#include "cache_replace_lib.h"

/****************************************************************************************
 Macros
 ****************************************************************************************/

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

/****************************************************************************************
 State Variables
 ****************************************************************************************/

static CefT_Hash_Handle lookup_table;       /* hash-table to look-up cache entries      */
static int              count;              /* the number of entries in lookup table    */

/****************************************************************************************
 Function Declaration
 ****************************************************************************************/

/****************************************************************************************
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Functions for Lookup Table
----------------------------------------------------------------------------------------*/
static void* crlib_lookup_table_encode_val(int idx);
static int crlib_lookup_table_decode_val(void* val);

void crlib_lookup_table_init(int capacity) {
    lookup_table = cef_lhash_tbl_create(capacity);
    count = 0;
}

void crlib_lookup_table_destroy() {
    cef_lhash_tbl_destroy(lookup_table);
    count = 0;
}

static void* crlib_lookup_table_encode_val(int idx) {
    return NULL + (intptr_t)idx + 1;
}

static int crlib_lookup_table_decode_val(void* val) {
    return ((intptr_t)val) - 1;
}

int crlib_lookup_table_search(const unsigned char* key, int key_len) {
    void* val = cef_lhash_tbl_item_get(lookup_table, key, key_len);
    return crlib_lookup_table_decode_val(val);    
}

void crlib_lookup_table_add(const unsigned char* key, int key_len, int idx) {
    cef_lhash_tbl_item_set(
        lookup_table, key, key_len, crlib_lookup_table_encode_val(idx));  
    count++;
}

void* crlib_lookup_table_search_v(const unsigned char* key, int key_len) {
    void* val = cef_lhash_tbl_item_get(lookup_table, key, key_len);
    return val;
}

void crlib_lookup_table_add_v(const unsigned char* key, int key_len, void* value) {
    cef_lhash_tbl_item_set(lookup_table, key, key_len, value);
    count++;
}

void crlib_lookup_table_remove(const unsigned char* key, int key_len) {
    cef_lhash_tbl_item_remove(lookup_table, key, key_len);
    count--;
}

int crlib_lookup_table_count(const unsigned char* key, int key_len) {
    return count;    
}

/*--------------------------------------------------------------------------------------
	+ xx_hash (c.f. https://github.com/Cyan4973/xxHash/blob/dev/xxhash.c)
----------------------------------------------------------------------------------------*/

static const uint32_t PRIME32_1 = 2654435761U;
static const uint32_t PRIME32_2 = 2246822519U;
static const uint32_t PRIME32_3 = 3266489917U;
static const uint32_t PRIME32_4 =  668265263U;
static const uint32_t PRIME32_5 =  374761393U;

static uint32_t crlib_xhash_swapbit(uint32_t x, int shift);
static uint32_t crlib_xhash_pack_str(const unsigned char* str, int xhash_seed);
static uint32_t crlib_xhash_pack_str_n(const unsigned char* str, int n, int xhash_seed);

/* public functions */

uint32_t crlib_xhash_mask_max(int max) {
    int i;
    int mask = 0;
    for (i = max; i > 0; i >>= 1) {
        mask = (mask << 1) | 0x1;
    }
    return mask;
}

uint32_t crlib_xhash_mask_width(int width) {
    int i;
    int mask = 0;
    for (i = 0; i < width; i++) {
        mask = (mask << 1) | 0x1;
    }
    return mask;
}

uint32_t crlib_xhash_get(uint32_t value, int xhash_seed) {
    uint32_t hash;
    hash = xhash_seed + PRIME32_5;
    hash += value * PRIME32_1;
    hash = crlib_xhash_swapbit(hash, 11) * PRIME32_4;
    hash ^= hash >> 15;
    hash *= PRIME32_2;
    hash ^= hash >> 13;
    hash *= PRIME32_3;
    hash ^= hash >> 16;
    return hash;
}

uint32_t crlib_xhash_get_str(const unsigned char* str, int len, int xhash_seed) {
    int i;
    int npack = len / 4;
    int rest  = len % 4;
    uint32_t hash = crlib_xhash_get(len, xhash_seed);
    for (i = 0; i < npack; i++) {
        // xhash_64_param_idxs_0_current =
        //     xhash_64_parameters[(xhash_64_param_idx + i) % XhashC_Num_Parameters_64];
        hash ^= crlib_xhash_pack_str(str + i * 4, xhash_seed);
    }
    // xhash_64_param_idxs_0_current = xhash_64_parameters[xhash_64_param_idx];
    if (rest > 0) hash ^= crlib_xhash_pack_str_n(str + npack * 4, rest, xhash_seed);
    // if (len >= 8) printf("[%s][%lx]       ",str,hash);
    return hash;
}

/* private functions */

static uint32_t crlib_xhash_swapbit(uint32_t x, int shift) {
    return (x << shift) | (x >> (32 - shift));
}

static uint32_t crlib_xhash_pack_str(const unsigned char* str, int xhash_seed) {
    uint32_t ret;
    // memcpy(&ret, str, 8);
    ret = *((uint32_t*)str);
    return crlib_xhash_get(ret, xhash_seed);
}

static uint32_t crlib_xhash_pack_str_n(const unsigned char* str, int n, int xhash_seed) {
    uint32_t ret = 0;
    memcpy(&ret, str, n);
    return crlib_xhash_get(ret, xhash_seed);
}

/*--------------------------------------------------------------------------------------
	+ xorshift (c.f. http://www.jstatsoft.org/v08/i14/paper)
----------------------------------------------------------------------------------------*/

static uint32_t crlib_xorshift_current = 0;

void crlib_xorshift_set_seed(uint32_t seed) { crlib_xorshift_current = crlib_xhash_get(seed, 0); }

uint32_t crlib_xorshift_rand() {
    crlib_xorshift_current ^= (crlib_xorshift_current <<  2);
    crlib_xorshift_current ^= (crlib_xorshift_current >> 15);
    crlib_xorshift_current ^= (crlib_xorshift_current << 25);
    return crlib_xorshift_current;
}

/*--------------------------------------------------------------------------------------
	+ debug
----------------------------------------------------------------------------------------*/

void crlib_force_print_name(const unsigned char* name, uint16_t len) {
    int i, j, clen;
	char buf[4096];
	char *cur = buf;
	memset(buf, 0, len + 10);
    sprintf(cur, "[ccnx:"); cur += 6;
    if (len > 2) {
	i = 3;
	while (i < len) {
		*cur = '/'; cur++;
		clen = *(name + i); i++;
		for (j = 0; j < clen; j++) {
			*cur = *(name + i + j); cur++;
		}
		i += clen + 3;
	}
    uint32_t chunknum = htonl (*((uint32_t*)(name + len - 4)));
        sprintf(cur - 4, "][%d]", chunknum);
    } else {
        sprintf(cur, "%s]", name);
    }
    fprintf(stderr, "%s", buf);
}

void crlib_force_print_entry(CsmgrdT_Content_Entry* entry) {
    int i, j, clen;
    const unsigned char *name = entry->name;
    int len = entry->name_len;
    int chunk_num = entry->chnk_num;
	char buf[4096];
	char *cur = buf;
	memset(buf, 0, len + 10);
    sprintf(cur, "[%8d][ccnx:", len); cur += 16;
	i = 3;
	while (i < len) {
		*cur = '/'; cur++;
		clen = *(name + i); i++;
		for (j = 0; j < clen; j++) {
			*cur = *(name + i + j); cur++;
		}
		i += clen + 3;
	}
    sprintf(cur, "][%d]", chunk_num);
    fprintf(stderr, "%s", buf);
}

void crlib_force_print_name_wl(const unsigned char* name, uint16_t len) {
    int i, j, clen;
	char buf[4096];
	char *cur = buf;
	memset(buf, 0, len + 10);
    sprintf(cur, "[%05d][ccnx:", len); cur += 13;
    if (len > 2) {
	i = 3;
	while (i < len) {
		clen = *(name + i); i++;
        sprintf(cur, "/(%03d)", clen); cur += 6;
		for (j = 0; j < clen; j++) {
			*cur = *(name + i + j); cur++;
		}
		i += clen + 3;
	}
    uint32_t chunknum = htonl (*((uint32_t*)(name + len - 4)));
        sprintf(cur - 4, "][%d]", chunknum);
    } else {
        sprintf(cur, "%s]", name);
    }
    fprintf(stderr, "%s", buf);
}

#ifdef EmuC_Log
static char time_str[64];

static void emu_timestamp() {
	struct timeval t;
    gettimeofday (&t, NULL);
    sprintf(time_str, "%ld.%06u", t.tv_sec, (unsigned)t.tv_usec);
}

static void emu_force_print_name(const unsigned char* name, uint16_t len, const char* hm_status) {
    int i, j, clen;
	char buf[4096];
	char *cur = buf;
	memset(buf, 0, len + 10);
    sprintf(cur, "[ccnx:"); cur += 6;
	i = 3;
	while (i < len) {
		*cur = '/'; cur++;
		clen = *(name + i); i++;
		for (j = 0; j < clen; j++) {
			*cur = *(name + i + j); cur++;
		}
		i += clen + 3;
	}
    uint32_t chunknum = htonl (*((uint32_t*)(name + len - 4)));
    sprintf(cur - 5, "][%d]", chunknum);
    emu_timestamp();
    fprintf(stderr, "!___EMULOG_time:%s___EMULOG_hm:%s___EMULOG_name:%s\n", time_str, hm_status, buf);
}
#endif



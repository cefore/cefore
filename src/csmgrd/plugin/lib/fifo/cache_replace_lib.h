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
 * lru.h
 */

/****************************************************************************************
 Include Files
 ****************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <csmgrd/csmgrd_plugin.h>




/****************************************************************************************
 Function Declaration
 ****************************************************************************************/

/* lookup table (capsulation) */
void crlib_lookup_table_init(int capacity);
void crlib_lookup_table_destroy();
int crlib_lookup_table_search(const unsigned char* key, int key_len);
void* crlib_lookup_table_search_v(const unsigned char* key, int key_len);
void crlib_lookup_table_add(const unsigned char* key, int key_len, int index);
void crlib_lookup_table_add_v(const unsigned char* key, int key_len, void* value);
void crlib_lookup_table_remove(const unsigned char* key, int key_len);
int crlib_lookup_table_count(const unsigned char* key, int key_len);

/* xxHash */
uint32_t crlib_xhash_mask_max(int max);
uint32_t crlib_xhash_mask_width(int width);
uint32_t crlib_xhash_get(uint32_t value, int xhash_seed);
uint32_t crlib_xhash_get_str(const unsigned char* str, int len, int xhash_seed);

/* random */
void crlib_xorshift_set_seed(uint32_t seed);
uint32_t crlib_xorshift_rand();

/* debug */
void crlib_force_print_name(const unsigned char* key, uint16_t len);
void crlib_force_print_entry(CsmgrdT_Content_Entry* entry);
void crlib_force_print_name_wl(const unsigned char* key, uint16_t len);


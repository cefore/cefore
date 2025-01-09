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
 * cef_mpool.c
 */

#define __CEF_MPOOL_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <cefore/cef_mpool.h>
#include <errno.h>
#include <pthread.h>


/****************************************************************************************
 Macros
 ****************************************************************************************/
#define CefC_Mp_Block_Min			32
#define CefC_Mp_Block_UnitBytes		16
#define CefC_Mp_Max_Elem_Size		819200

/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

typedef struct CefT_Mp_Pool {
	unsigned char* 			head;
	unsigned char* 			tail;
	unsigned char* 			blocks;
} CefT_Mp_Pool;

/*
 * The information to manage a memory pool.
 */
typedef struct CefT_Mp_Mng {
	char* 					key;
	size_t					klen;

	size_t					size;			/* size of one memory block 				*/
	int						increment;		/* number of blocks to allocate at one time	*/

	CefT_Mp_Pool*			pool;			/* memory pool 		 						*/
	size_t 					pool_num;

	unsigned char**			free;
	size_t 					head;
	size_t 					tail;
	size_t 					block_num;		/* number of allocated memory blocked 		*/
	size_t 					mask;

	pthread_mutex_t 		mp_mutex_pt;	/* mutex for thread safe for Pthread 		*/

} CefT_Mp_Mng;

/****************************************************************************************
 State Variables
 ****************************************************************************************/


/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/
static CefT_Mp_Mng*
cef_mpool_handle_create (
	const char* 	key,
	size_t 			size,
	int 			increment
);

static int
cef_mpool_handle_update (
	CefT_Mp_Mng* mpmng
);

static void
cef_mpool_handle_destroy (
	CefT_Mp_Mng* mpmng
);

/****************************************************************************************
 ****************************************************************************************/

/*
 * If a memory pool corresponding to the input identifier does not exist, initialization
 * a new memory pool, and creating a handle to access the new memory pool.
 * If the memory pool already exists, returning a handle to access the memory pool.
 */
CefT_Mp_Handle 								/* Handle to access the memory pool.		*/
cef_mpool_init (
	const char* 	key, 					/* Key to identify the memory pool.			*/
	size_t 			size,					/* Size of 1 pooled memory block. 			*/
	int 			increment				/* memory block number that is pooled at 	*/
											/* one time.								*/
) {
	CefT_Mp_Mng* mpmng;

	/* Checking of the input parameters. 	*/
	if ((key == NULL) ||
		(size < 1) || (size > CefC_Mp_Max_Elem_Size) ||
		(increment < 1)) {
		fprintf (stderr, "[error] cef_mpool_init - parameter\n");
		return ((CefT_Mp_Handle) 0);
	}

	mpmng = cef_mpool_handle_create (key, size, increment);
	if (mpmng == NULL) {
		fprintf (stderr, "[error] cef_mpool_init - no more memory\n");
		return ((CefT_Mp_Handle) 0);
	}

	return ((CefT_Mp_Handle) mpmng);
}

void*
cef_mpool_alloc (
	CefT_Mp_Handle mph
) {
	CefT_Mp_Mng* mpmng = (CefT_Mp_Mng*) mph;
	size_t index;
	int res;

	while (1) {
		res = pthread_mutex_trylock (&mpmng->mp_mutex_pt);

		if (res != 0) {
			if (res == EBUSY) {
				const struct timespec ts_req = { 0, 1000000 };	/* 1 mili sec. */

				nanosleep(&ts_req, NULL);
				continue;
			}
			return (NULL);
		}
		break;
	}


	if (mpmng->tail != mpmng->head) {
		index = mpmng->head;
		mpmng->head = (mpmng->head + 1) & mpmng->mask;
		pthread_mutex_unlock (&mpmng->mp_mutex_pt);
		return ((void*) mpmng->free[index]);
	}

	res = cef_mpool_handle_update (mpmng);

	if (res > 0) {
		index = mpmng->head;
		mpmng->head = (mpmng->head + 1) & mpmng->mask;
		pthread_mutex_unlock (&mpmng->mp_mutex_pt);
		return ((void*) mpmng->free[index]);
	}

	pthread_mutex_unlock (&mpmng->mp_mutex_pt);

	return ((void*) NULL);
}

void
cef_mpool_free (
	CefT_Mp_Handle mph,
	void* ptr
) {
	CefT_Mp_Mng* mpmng = (CefT_Mp_Mng*) mph;
	int i = 0;
	int res;

	while (1) {
		res = pthread_mutex_trylock (&mpmng->mp_mutex_pt);

		if (res != 0) {
			if (res == EBUSY) {
				const struct timespec ts_req = { 0, 1000000 };	/* 1 mili sec. */

				nanosleep(&ts_req, NULL);
				continue;
			}
			return;
		}
		break;
	}

	while (i < mpmng->pool_num) {
		if (((unsigned char*) ptr > mpmng->pool[i].head) &&
			((unsigned char*) ptr < mpmng->pool[i].tail)) {
			mpmng->tail = (mpmng->tail + 1) & mpmng->mask;
			mpmng->free[mpmng->tail] = ptr;
			break;
		}
		i++;
	}

	pthread_mutex_unlock (&mpmng->mp_mutex_pt);

	return;
}

void
cef_mpool_destroy (
	CefT_Mp_Handle mph
) {
	CefT_Mp_Mng* mpmng = (CefT_Mp_Mng*) mph;

	if (mpmng) {
		pthread_mutex_destroy (&mpmng->mp_mutex_pt);
		cef_mpool_handle_destroy (mpmng);
	}
}

/*=======================================================================================
 =======================================================================================*/

static CefT_Mp_Mng* 						/* The information to manage a memory pool 	*/
											/* corresponding to the input key.			*/
cef_mpool_handle_create (
	const char* 	key, 					/* Key to identify the memory pool.			*/
	size_t 			size,					/* Size of 1 pooled memory block. 			*/
	int 			increment				/* memory block number that is pooled at 	*/
											/* one time.								*/
) {
	CefT_Mp_Mng* mpmng;
	size_t i;
	unsigned char* bp;

	int p;

	increment--;

	for (p = 0 ; increment != 0 ; increment >>= 1) {
		p = (p << 1) + 1;
	}
	increment = p + 1;

	/* allocation the memory for the new memory pool 	*/
	mpmng = (CefT_Mp_Mng*) malloc (sizeof (CefT_Mp_Mng));
	if (mpmng == NULL) {
		return (NULL);
	}
	memset (mpmng, 0, sizeof (CefT_Mp_Mng));


	if (key != NULL) {
		mpmng->klen = (size_t) strlen (key);
		mpmng->key  = (char*) malloc (sizeof (char) * (mpmng->klen + 1));
		if (mpmng->key == NULL) {
			cef_mpool_handle_destroy (mpmng);
			return (NULL);
		}
		strcpy (mpmng->key, key);
	}

	/* set the block size to a multiple of 16 for the alignment 	*/
	mpmng->size
		= ((size + CefC_Mp_Block_UnitBytes - 1) / CefC_Mp_Block_UnitBytes)
			* CefC_Mp_Block_UnitBytes;

	/* record the number of blocks to allocate at one time 		*/
	mpmng->increment = increment;
	if (mpmng->increment < CefC_Mp_Block_Min) {
		mpmng->increment = CefC_Mp_Block_Min;
	}

	/* allocate the memory pool 	*/
	mpmng->pool_num = 1;
	mpmng->pool = (CefT_Mp_Pool*) calloc (mpmng->pool_num, sizeof (CefT_Mp_Pool));

	if (mpmng->pool == NULL) {
		cef_mpool_handle_destroy (mpmng);
		return (NULL);
	}
	memset (mpmng->pool, 0, sizeof (CefT_Mp_Pool) * mpmng->pool_num);

	mpmng->pool[0].blocks
		= (unsigned char*) calloc (mpmng->increment, mpmng->size);
	if (mpmng->pool[0].blocks == NULL) {
		cef_mpool_handle_destroy (mpmng);
		return (NULL);
	}
	memset (mpmng->pool[0].blocks, 0, mpmng->increment * mpmng->size);

	mpmng->pool[0].head = mpmng->pool[0].blocks - 1;
	mpmng->pool[0].tail
		= mpmng->pool[0].blocks + mpmng->increment * (mpmng->size - 1) + 1;

	/* prepare management information 	*/
	mpmng->block_num = mpmng->increment;
	mpmng->mask = mpmng->block_num - 1;
	mpmng->free
		= (unsigned char**) malloc (sizeof (unsigned char*) * mpmng->block_num);
	if (mpmng->free == NULL) {
		cef_mpool_handle_destroy (mpmng);
		return (NULL);
	}
	mpmng->head = 0;
	mpmng->tail = mpmng->block_num - 1;

	bp = mpmng->pool[0].blocks;

	for (i = 0 ; i < mpmng->block_num ; i++) {
		mpmng->free[i] = bp;
		bp += mpmng->size;
	}
	pthread_mutex_init (&mpmng->mp_mutex_pt, NULL);

	return (mpmng);
}

static int
cef_mpool_handle_update (
	CefT_Mp_Mng* mpmng
) {
	CefT_Mp_Pool* new_pool;
	unsigned char** new_free;
	size_t new_block_num;
	size_t i;
	unsigned char* bp;

	/* allocate the memory pool 	*/
	new_pool = (CefT_Mp_Pool*) calloc (mpmng->pool_num + 1, sizeof (CefT_Mp_Pool));
	if (new_pool == NULL) {
		return (-1);
	}
	memset (new_pool, 0, sizeof (CefT_Mp_Pool) * (mpmng->pool_num + 1));

	for (i = 0 ; i < mpmng->pool_num ; i++) {
		new_pool[i].blocks 	= mpmng->pool[i].blocks;
		new_pool[i].head 	= mpmng->pool[i].head;
		new_pool[i].tail 	= mpmng->pool[i].tail;
	}
	new_pool[i].blocks = (unsigned char*) calloc (mpmng->increment, mpmng->size);
	if (new_pool[i].blocks == NULL) {
		free (new_pool);
		return (-1);
	}
	memset (new_pool[i].blocks, 0, mpmng->increment * mpmng->size);

	new_pool[i].head = new_pool[i].blocks - 1;
	new_pool[i].tail = new_pool[i].blocks + mpmng->increment * (mpmng->size - 1) + 1;


	free (mpmng->pool);
	mpmng->pool = new_pool;
	mpmng->pool_num++;

	/* prepare management information 	*/
	new_block_num = mpmng->block_num + mpmng->increment;
	new_free = (unsigned char**) malloc (sizeof (unsigned char*) * new_block_num);
	if (new_free == NULL) {
		mpmng->pool_num--;
		return (-1);
	}

	bp = mpmng->pool[i].blocks;
	for (i = mpmng->block_num ; i < new_block_num ; i++) {
		new_free[i] = bp;
		bp += mpmng->size;
	}
	for (i = 0 ; i < mpmng->block_num ; i++) {
		new_free[i] = mpmng->free[i];
	}
	free (mpmng->free);
	mpmng->free = new_free;

	mpmng->head = mpmng->block_num;
	mpmng->block_num = new_block_num;
	mpmng->mask = mpmng->block_num - 1;
	mpmng->tail = mpmng->block_num - 1;

	return (1);
}

static void
cef_mpool_handle_destroy (
	CefT_Mp_Mng* mpmng
) {
	int i;

	if (mpmng == NULL) {
		return;
	}

	if (mpmng->pool) {
		for (i = 0 ; i < mpmng->pool_num ; i++) {
			free (mpmng->pool[i].blocks);
		}
		free (mpmng->pool);
	}

	if (mpmng->key) {
		free (mpmng->key);
	}

	if (mpmng->free) {
		free (mpmng->free);
	}

	free (mpmng);

	return;
}

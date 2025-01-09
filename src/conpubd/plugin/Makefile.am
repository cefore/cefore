#
# Copyright (c) 2016-2023, National Institute of Information and Communications
# Technology (NICT). All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the NICT nor the names of its contributors may be
#    used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE NICT AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE NICT OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

# set include file directory
AM_CFLAGS = -I$(top_srcdir)/src/include -I$(top_srcdir)/src/conpubd/include

# set library directory
AM_LDFLAGS = -L$(top_srcdir)/src/lib/ -L$(top_srcdir)/src/conpubd/lib

# set automake option
AUTOMAKE_OPTIONS = subdir-objects

# set conpubd plugins directory
CONPUBD_PLUGINS_DIR = $(top_srcdir)/src/conpubd

# set noinst_LTLIBRARIES
noinst_LTLIBRARIES =

# set conpubd plugin cflags
CONPUBD_PLUGIN_CFLAGS = $(AM_CFLAGS)

# set conpubd plugin ldadd
CONPUBD_PLUGIN_LIBADD =

# check debug build
if CEFDBG_ENABLE
CONPUBD_PLUGIN_CFLAGS+=-DCefC_Debug -g
endif # CEFDBG_ENABLE



if CONPUB_ENABLE
CONPUBD_PLUGIN_CFLAGS+=-DCefC_Conpub
CONPUBD_PLUGIN_LIBADD+=-lconpub
endif # CONPUB_ENABLE


# lib conpubd plugins library
lib_LTLIBRARIES = libconpubd_plugin.la
libconpubd_plugin_la_CFLAGS = $(CONPUBD_PLUGIN_CFLAGS) -Wall -O2 -fPIC
libconpubd_plugin_la_SOURCES =
libconpubd_plugin_la_LIBADD =

# check mem cache
noinst_LTLIBRARIES += libmem_cache.la
libmem_cache_la_CFLAGS  = $(CONPUBD_PLUGIN_CFLAGS) -Wall -O2 -fPIC
libmem_cache_la_SOURCES = mem_cache/mem_cache.c mem_cache/mem_cache.h
libmem_cache_la_LDFLAGS = -lcefore -lconpub $(AM_LDFLAGS)
libconpubd_plugin_la_LIBADD += $(CONPUBD_PLUGIN_LIBADD) libmem_cache.la

# check filesystem
noinst_LTLIBRARIES += libfilesystem_cache.la
libfilesystem_cache_la_CFLAGS  = $(CONPUBD_PLUGIN_CFLAGS) -Wall -O2 -fPIC
libfilesystem_cache_la_SOURCES = filesystem_cache/filesystem_cache.c filesystem_cache/filesystem_cache.h
libfilesystem_cache_la_LDFLAGS = -lcefore -lconpub $(AM_LDFLAGS)
libconpubd_plugin_la_LIBADD += $(CONPUBD_PLUGIN_LIBADD) libfilesystem_cache.la


libdir=$(CEFORE_DIR_PATH)lib

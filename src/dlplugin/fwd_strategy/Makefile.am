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
AM_CFLAGS = -I$(top_srcdir)/src/include -Wall -O2 -fPIC

# set library directory
AM_LDFLAGS = -L$(top_srcdir)/src/lib/

# set automake option
AUTOMAKE_OPTIONS = subdir-objects

# set cefnetd fwd plugins directory
CEFNETD_FWD_PLUGINS_DIR = $(top_srcdir)/src/dlplugin

# set noinst_LTLIBRARIES
noinst_LTLIBRARIES =

# set cefnetd fwd plugin cflags
CEFNETD_FWD_PLUGIN_CFLAGS = $(AM_CFLAGS)

# set cefnetd fwd plugin ldadd
CEFNETD_FWD_PLUGIN_LIBADD =

# set EXTRA_DIST
EXTRA_DIST =

# check debug build
if CEFDBG_ENABLE
CEFNETD_FWD_PLUGIN_CFLAGS+=-DCefC_Debug -g
endif # CEFDBG_ENABLE

# lib cefnetd fwd plugins library
lib_LTLIBRARIES = libcefnetd_fwd_plugin.la
libcefnetd_fwd_plugin_la_CFLAGS = $(CEFNETD_FWD_PLUGIN_CFLAGS) -Wall -O2 -fPIC
libcefnetd_fwd_plugin_la_SOURCES =
libcefnetd_fwd_plugin_la_LIBADD =

# check flooding
noinst_LTLIBRARIES += libflooding.la
libflooding_la_CFLAGS  = $(CEFNETD_FWD_PLUGIN_CFLAGS) -Wall -O2 -fPIC
libflooding_la_SOURCES = flooding/flooding.c flooding/flooding.h
libflooding_la_LDFLAGS = -lcefore $(AM_LDFLAGS)
libcefnetd_fwd_plugin_la_LIBADD += $(CEFNETD_FWD_PLUGIN_LIBADD) libflooding.la

# check shortest_path
noinst_LTLIBRARIES += libshortest_path.la
libshortest_path_la_CFLAGS  = $(CEFNETD_FWD_PLUGIN_CFLAGS) -Wall -O2 -fPIC
libshortest_path_la_SOURCES = shortest_path/shortest_path.c shortest_path/shortest_path.h
libshortest_path_la_LDFLAGS = -lcefore $(AM_LDFLAGS)
libcefnetd_fwd_plugin_la_LIBADD += $(CEFNETD_FWD_PLUGIN_LIBADD) libshortest_path.la


libdir=$(CEFORE_DIR_PATH)lib

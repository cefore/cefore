#
# Copyright (c) 2016-2021, National Institute of Information and Communications
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
AM_CFLAGS = -I$(top_srcdir)/src/include

# set library directory
AM_LDFLAGS = -L$(top_srcdir)/src/lib/

# set automake option
AUTOMAKE_OPTIONS = subdir-objects

# set cefnetd plugin cflags
CEFNETD_PLUGIN_CFLAGS = $(AM_CFLAGS)

# set cefnetd plugin ldadd
CEFNETD_PLUGIN_LIBADD =


# set cefnetd plugins directory
CEFNETD_PLUGINS_DIR = $(top_srcdir)/src/cefnetd

# set noinst_LTLIBRARIES
noinst_LTLIBRARIES =

# check debug build
if CEFDBG_ENABLE
CEFNETD_PLUGIN_CFLAGS+=-DCefC_Debug -g
endif # CEFDBG_ENABLE

# lib cefnetd plugins library
lib_LTLIBRARIES = libcefnetd_plugin.la
libcefnetd_plugin_la_CFLAGS = $(CEFNETD_PLUGIN_CFLAGS) -Wall -O2 -fPIC
libcefnetd_plugin_la_SOURCES =
libcefnetd_plugin_la_LIBADD =

# check bw_stat cache
noinst_LTLIBRARIES += libbw_stat.la
libbw_stat_la_CFLAGS  = $(CEFNETD_PLUGIN_CFLAGS) -Wall -O2 -fPIC
libbw_stat_la_SOURCES = bw_stat/bw_stat.c bw_stat/bw_stat.h
libbw_stat_la_LDFLAGS = -lcefore $(AM_LDFLAGS)
libcefnetd_plugin_la_LIBADD += $(CEFNETD_PLUGIN_LIBADD) libbw_stat.la

#####
#SUBDIRS = lib

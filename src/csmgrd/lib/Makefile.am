#
# Copyright (c) 2016-2020, National Institute of Information and Communications
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
AM_CFLAGS=-I$(top_srcdir)/src/include -I$(top_srcdir)/src/csmgrd/include -Wall -O2 -fPIC

# set library directory
AM_LDFLAGS = -L$(top_srcdir)/src/lib/ -L$(top_srcdir)/src/csmgrd/lib
AM_CSOURCES = csmgrd_plugin.c

# set csmgrd lib cflags
CSMGRD_LIB_CFLAGS = $(AM_CFLAGS)

# check debug build
if CEFDBG_ENABLE
CSMGRD_LIB_CFLAGS+=-DCefC_Debug
endif # CEFDBG_ENABLE

lib_LTLIBRARIES = libcsmgr.la
libcsmgr_la_CFLAGS = $(CSMGRD_LIB_CFLAGS)
libcsmgr_la_LDFLAGS = -lcefore $(AM_LDFLAGS)
libcsmgr_la_SOURCES = $(AM_CSOURCES)

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

AM_CFLAGS=-I$(top_srcdir)/src/include -Wall -O2 -fPIC

bin_PROGRAMS=conpubstatus
conpubstatus_LDFLAGS=-L$(top_srcdir)/src/lib/
if LINUX
conpubstatus_LDFLAGS+=-pthread
endif # LINUX
conpubstatus_LDADD=-lcefore
if OPENSSL_STATIC
conpubstatus_LDADD+=-l:libssl.a -l:libcrypto.a
else  #OPENSSL_STATIC
conpubstatus_LDADD+=-lssl -lcrypto
endif #OPENSSL_STATIC
conpubstatus_LDADD += -lpthread -ldl

conpubstatus_CFLAGS=$(AM_CFLAGS)
conpubstatus_SOURCES=conpubstatus.c

# check debug build
if CEFDBG_ENABLE
conpubstatus_CFLAGS+=-DCefC_Debug
endif # CEFDBG_ENABLE

bin_PROGRAMS+=conpubreload
conpubreload_LDFLAGS=-L$(top_srcdir)/src/lib/
if LINUX
conpubreload_LDFLAGS+=-pthread -lpthread
endif # LINUX
conpubreload_LDADD=-lcefore
if OPENSSL_STATIC
conpubreload_LDADD+=-l:libssl.a -l:libcrypto.a
else  #OPENSSL_STATIC
conpubreload_LDADD+=-lssl -lcrypto
endif #OPENSSL_STATIC
conpubreload_LDADD += -lpthread -ldl

conpubreload_CFLAGS=$(AM_CFLAGS)
conpubreload_SOURCES=conpubreload.c

# check debug build
if CEFDBG_ENABLE
conpubreload_CFLAGS+=-DCefC_Debug
endif # CEFDBG_ENABLE

DESTDIR=$(CEFORE_DIR_PATH)
bindir=bin

###############################################################################################
###############################################################################################





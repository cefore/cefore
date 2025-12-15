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

AM_CFLAGS=-I$(top_srcdir)/src/include -Wall


bin_PROGRAMS=ccninfo
ccninfo_LDFLAGS=-L$(top_srcdir)/src/lib/
ccninfo_LDADD=-lcefore
if OPENSSL_STATIC
ccninfo_LDADD+=-l:libssl.a -l:libcrypto.a
else  #OPENSSL_STATIC
ccninfo_LDADD+=-lssl -lcrypto
endif #OPENSSL_STATIC
ccninfo_LDADD += -lpthread -ldl

ccninfo_CFLAGS=$(AM_CFLAGS) -DCefC_Ccninfo
ccninfo_SOURCES=ccninfo.c

# check debug build
if CEFDBG_ENABLE
ccninfo_CFLAGS+=-DCefC_Debug -g
endif # CEFDBG_ENABLE

DESTDIR=$(CEFORE_DIR_PATH)
bindir=bin

install-exec-hook:
	chmod +s $(DESTDIR)$(bindir)/$(bin_PROGRAMS)


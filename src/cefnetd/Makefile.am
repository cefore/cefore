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

# set
AM_CFLAGS=-I$(top_srcdir)/src/include -Wall
CEF_NETD_BIN_PROGRAM=cefnetd cefctrl
CEF_NETD_CFLAGS=$(AM_CFLAGS)

# check debug build
if CEFDBG_ENABLE
CEF_NETD_CFLAGS+=-DCefC_Debug -g
endif # CEFDBG_ENABLE

# check csmgr
if CSMGR_ENABLE
CEF_NETD_CFLAGS+=-DCefC_Csmgr
endif # CSMGR_ENABLE

# check cache
if CACHE_ENABLE
CEF_NETD_CFLAGS+=-DCefC_CefnetdCache
endif # CACHE_ENABLE


# set bin programs
bin_PROGRAMS=$(CEF_NETD_BIN_PROGRAM)

# set cefnetd option
cefnetd_LDFLAGS=-L$(top_srcdir)/src/lib/ -L$(top_srcdir)/src/plugin/ -L$(top_srcdir)/src/dlplugin/fwd_strategy/ -lpthread
if LINUX
cefnetd_LDFLAGS+=-pthread
endif # LINUX
cefnetd_LDADD=-lcef_plugin -lcefnetd_fwd_plugin -lcefore

if OPENSSL_STATIC
cefnetd_LDADD+=-l:libssl.a -l:libcrypto.a
else  #OPENSSL_STATIC
cefnetd_LDADD+=-lssl -lcrypto
endif #OPENSSL_STATIC

cefnetd_LDADD+=-ldl

cefnetd_CFLAGS=$(CEF_NETD_CFLAGS)
cefnetd_SOURCES=cef_main.c cef_node.c cef_sched.c cef_netd.c \
				cef_status.c cef_forward.c cefnet_fib.c \
				cef_netd.h cef_status.h


# check conpub
if CONPUB_ENABLE
CEF_NETD_CFLAGS+=-DCefC_Conpub
endif # CONPUB_ENABLE

# set cefctrl option
cefctrl_LDFLAGS=-L$(top_srcdir)/src/lib/
cefctrl_LDADD=-lcefore
if OPENSSL_STATIC
cefctrl_LDADD+=-l:libssl.a -l:libcrypto.a -lpthread -ldl
else  #OPENSSL_STATIC
cefctrl_LDADD+=-lssl -lcrypto
endif #OPENSSL_STATIC

cefctrl_CFLAGS=$(AM_CFLAGS)
cefctrl_SOURCES=cef_ctrl.c cef_netd.h

# check debug build
if CEFDBG_ENABLE
cefctrl_CFLAGS+=-DCefC_Debug
endif # CEFDBG_ENABLE

# check cache
if CACHE_ENABLE
cefctrl_CFLAGS+=-DCefC_CefnetdCache
endif # CACHE_ENABLE

# check interest return build
if INTEREST_RETURN_ENABLE
CEF_NETD_CFLAGS+=-DCefC_INTEREST_RETURN
endif # INTEREST_RETURN_ENABLE


DESTDIR=$(CEFORE_DIR_PATH)
bindir=sbin

install-exec-hook:
	chmod +s $(DESTDIR)$(bindir)/cefctrl

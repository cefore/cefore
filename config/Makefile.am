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

EXTRA_DIST=cefnetd.conf.def cefnetd.fib.def csmgrd.conf.def plugin.conf.def default-private-key.pem default-public-key.pem ccninfo_rt-private-key.pem ccninfo_rt-public-key.pem ccninfo_user-private-key.pem ccninfo_user-public-key.pem conpubd.conf.def 88-cefore.conf.def
CEF_CONF=cefnetd.conf cefnetd.fib csmgrd.conf plugin.conf default-private-key default-public-key ccninfo_rt-private-key ccninfo_rt-public-key ccninfo_user-private-key ccninfo_user-public-key conpubd.conf 88-cefore.conf
INSTALLDIR=$(CEFORE_DIR_PATH)cefore
CCNINFORTDIR=$(CEFORE_DIR_PATH)cefore/.ccninfo
CCNINFOUSERDIR=$(HOME)/.ccninfo
SYSCTLINSTALLDIR=/etc/sysctl.d

default all: $(CEF_CONF)

cefnetd.conf: cefnetd.conf.def
	@if [ -f $(@:=.def) ]; then \
		cat $(@:=.def) >> $@; \
		chmod 644 $@; \
	else \
		echo "***" You may need to rerun ./configure in the src directory. >&2; \
	fi

cefnetd.fib: cefnetd.fib.def
	@if [ -f $(@:=.def) ]; then \
		cat $(@:=.def) >> $@; \
		chmod 644 $@; \
	else \
		echo "***" You may need to rerun ./configure in the src directory. >&2; \
	fi

csmgrd.conf: csmgrd.conf.def
	@if [ -f $(@:=.def) ]; then \
		cat $(@:=.def) >> $@; \
		chmod 644 $@; \
	else \
		echo "***" You may need to rerun ./configure in the src directory. >&2; \
	fi

plugin.conf: plugin.conf.def
	@if [ -f $(@:=.def) ]; then \
		cat $(@:=.def) >> $@; \
		chmod 644 $@; \
	else \
		echo "***" You may need to rerun ./configure in the src directory. >&2; \
	fi

default-private-key: default-private-key.pem
	@if [ -f $(@:=.pem) ]; then \
		cat $(@:=.pem) >> $@; \
		chmod 644 $@; \
	else \
		echo "***" You may need to rerun ./configure in the src directory. >&2; \
	fi

conpubd.conf: conpubd.conf.def
	@if [ -f $(@:=.def) ]; then \
		cat $(@:=.def) >> $@; \
		chmod 644 $@; \
	else \
		echo "***" You may need to rerun ./configure in the src directory. >&2; \
	fi


default-public-key: default-public-key.pem
	@if [ -f $(@:=.pem) ]; then \
		cat $(@:=.pem) >> $@; \
		chmod 644 $@; \
	else \
		echo "***" You may need to rerun ./configure in the src directory. >&2; \
	fi

ccninfo_rt-private-key: ccninfo_rt-private-key.pem
	@if [ -f $(@:=.pem) ]; then \
		cat $(@:=.pem) >> $@; \
		chmod 644 $@; \
	else \
		echo "***" You may need to rerun ./configure in the src directory. >&2; \
	fi

ccninfo_rt-public-key: ccninfo_rt-public-key.pem
	@if [ -f $(@:=.pem) ]; then \
		cat $(@:=.pem) >> $@; \
		chmod 644 $@; \
	else \
		echo "***" You may need to rerun ./configure in the src directory. >&2; \
	fi

ccninfo_user-private-key: ccninfo_user-private-key.pem
	@if [ -f $(@:=.pem) ]; then \
		cat $(@:=.pem) >> $@; \
		chmod 644 $@; \
	else \
		echo "***" You may need to rerun ./configure in the src directory. >&2; \
	fi

ccninfo_user-public-key: ccninfo_user-public-key.pem
	@if [ -f $(@:=.pem) ]; then \
		cat $(@:=.pem) >> $@; \
		chmod 644 $@; \
	else \
		echo "***" You may need to rerun ./configure in the src directory. >&2; \
	fi

88-cefore.conf: 88-cefore.conf.def
	@if [ -f $(@:=.def) ]; then \
		cat $(@:=.def) >> $@; \
		chmod 644 $@; \
	else \
		echo "***" You may need to rerun ./configure in the src directory. >&2; \
	fi

install:
	@if [ ! -d $(INSTALLDIR) ]; then \
		mkdir $(INSTALLDIR); \
	fi

	@if [ ! -d $(CCNINFORTDIR) ]; then \
		mkdir $(CCNINFORTDIR); \
	fi

	@if [ ! -d $(CCNINFOUSERDIR) ]; then \
		mkdir $(CCNINFOUSERDIR); \
	fi

	@if [ ! -f $(INSTALLDIR)/cefnetd.conf ]; then \
		cp -p cefnetd.conf $(INSTALLDIR)/cefnetd.conf; \
	fi
	@if [ ! -f $(INSTALLDIR)/cefnetd.fib ]; then \
		cp -p cefnetd.fib $(INSTALLDIR)/cefnetd.fib; \
	fi
	@if [ ! -f $(INSTALLDIR)/csmgrd.conf ]; then \
		cp -p csmgrd.conf $(INSTALLDIR)/csmgrd.conf; \
	fi
	@if [ ! -f $(INSTALLDIR)/plugin.conf ]; then \
		cp -p plugin.conf $(INSTALLDIR)/plugin.conf; \
	fi
	@if [ ! -f $(INSTALLDIR)/default-public-key ]; then \
		cp -p default-public-key $(INSTALLDIR)/default-public-key; \
	fi
	@if [ ! -f $(INSTALLDIR)/default-private-key ]; then \
		cp -p default-private-key $(INSTALLDIR)/default-private-key; \
	fi
	@if [ ! -f $(CCNINFORTDIR)/ccninfo_rt-private-key ]; then \
		cp -p ccninfo_rt-private-key $(CCNINFORTDIR)/ccninfo_rt-private-key; \
	fi
	@if [ ! -f $(CCNINFORTDIR)/ccninfo_rt-public-key ]; then \
		cp -p ccninfo_rt-public-key $(CCNINFORTDIR)/ccninfo_rt-public-key; \
	fi
	@if [ ! -f $(CCNINFOUSERDIR)/$ccninfo_user-private-key ]; then \
		cp -p ccninfo_user-private-key $(CCNINFOUSERDIR)/ccninfo_user-private-key; \
	fi
	@if [ ! -f $(CCNINFOUSERDIR)/ccninfo_user-public-key ]; then \
		cp -p ccninfo_user-public-key $(CCNINFOUSERDIR)/ccninfo_user-public-key; \
	fi
	@if [ ! -f $(INSTALLDIR)/conpubd.conf ]; then \
		cp -p conpubd.conf $(INSTALLDIR)/conpubd.conf; \
	fi
	-@if [ ! -f $(SYSCTLINSTALLDIR)/88-cefore.conf ] && [ ! $(build_vendor) = apple ]; then \
		cp -p 88-cefore.conf $(SYSCTLINSTALLDIR)/88-cefore.conf; \
		sysctl -p $(SYSCTLINSTALLDIR)/88-cefore.conf; \
	fi


uninstall:
	for i in $(CEF_CONF) ""; do test -z "$$i" || rm -f $(CCNINFOUSERDIR)/$$i; done
	for i in $(CEF_CONF) ""; do test -z "$$i" || rm -f $(CCNINFORTDIR)/$$i; done
	for i in $(CEF_CONF) ""; do test -z "$$i" || rm -f $(INSTALLDIR)/$$i; done
	for i in $(CEF_CONF) ""; do test -z "$$i" || rm -f $(SYSCTLINSTALLDIR)/$$i; done

clean:
	rm -f $(CEF_CONF) *.bak


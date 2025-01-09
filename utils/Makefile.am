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

EXTRA_DIST=cefnetdstart.sh cefnetdstop.sh cefstatus.sh cefroute.sh get_memory_info.sh get_memory_info_macos.sh
SCRIPTSRC=cefnetdstart.sh cefnetdstop.sh cefstatus.sh cefroute.sh get_memory_info.sh get_memory_info_macos.sh
CEF_UTIL=cefnetdstart cefnetdstop cefstatus cefroute
CEF_MEM_UTIL = get_memory_info.sh
CEF_MEM_UTIL_MACOS = get_memory_info_macos.sh
SH=/bin/sh
INSTALLDIR=$(CEFORE_DIR_PATH)bin

# check csmgrd
if CSMGR_ENABLE
EXTRA_DIST+=csmgrdstart.sh csmgrdstop.sh
SCRIPTSRC+=csmgrdstart.sh csmgrdstop.sh
CEF_UTIL+=csmgrdstart csmgrdstop
endif # CSMGR_ENABLE

# check conpubd
if CONPUB_ENABLE
EXTRA_DIST+=conpubdstart.sh conpubdstop.sh
SCRIPTSRC+=conpubdstart.sh conpubdstop.sh
CEF_UTIL+=conpubdstart conpubdstop
endif # CONPUB_ENABLE

default all: $(CEF_UTIL)

cefnetdstart: cefnetdstart.sh
	@if [ -x $(SH) ] && [ -f $(@:=.sh) ]; then \
		echo "# !"$(SH) > $@; \
		cat $(@:=.sh) >> $@; \
		chmod +x $@; \
	else \
		echo "***" You may need to rerun ./configure in the src directory. >&2; \
	fi

cefnetdstop: cefnetdstop.sh
	@if [ -x $(SH) ] && [ -f $(@:=.sh) ]; then \
		echo "# !"$(SH) > $@; \
		cat $(@:=.sh) >> $@; \
		chmod +x $@; \
	else \
		echo "***" You may need to rerun ./configure in the src directory. >&2; \
	fi

cefstatus: cefstatus.sh
	@if [ -x $(SH) ] && [ -f $(@:=.sh) ]; then \
		echo "# !"$(SH) > $@; \
		cat $(@:=.sh) >> $@; \
		chmod +x $@; \
	else \
		echo "***" You may need to rerun ./configure in the src directory. >&2; \
	fi

cefroute: cefroute.sh
	@if [ -x $(SH) ] && [ -f $(@:=.sh) ]; then \
		echo "# !"$(SH) > $@; \
		cat $(@:=.sh) >> $@; \
		chmod +x $@; \
	else \
		echo "***" You may need to rerun ./configure in the src directory. >&2; \
	fi

if CSMGR_ENABLE
csmgrdstart: csmgrdstart.sh
	@if [ -x $(SH) ] && [ -f $(@:=.sh) ]; then \
		echo "# !"$(SH) > $@; \
		cat $(@:=.sh) >> $@; \
		chmod +x $@; \
	else \
		echo "***" You may need to rerun ./configure in the src directory. >&2; \
	fi

csmgrdstop: csmgrdstop.sh
	@if [ -x $(SH) ] && [ -f $(@:=.sh) ]; then \
		echo "# !"$(SH) > $@; \
		cat $(@:=.sh) >> $@; \
		chmod +x $@; \
	else \
		echo "***" You may need to rerun ./configure in the src directory. >&2; \
	fi
endif # CSMGR_ENABLE

if CONPUB_ENABLE
conpubdstart: conpubdstart.sh
	@if [ -x $(SH) ] && [ -f $(@:=.sh) ]; then \
		echo "# !"$(SH) > $@; \
		cat $(@:=.sh) >> $@; \
		chmod +x $@; \
	else \
		echo "***" You may need to rerun ./configure in the src directory. >&2; \
	fi

conpubdstop: conpubdstop.sh
	@if [ -x $(SH) ] && [ -f $(@:=.sh) ]; then \
		echo "# !"$(SH) > $@; \
		cat $(@:=.sh) >> $@; \
		chmod +x $@; \
	else \
		echo "***" You may need to rerun ./configure in the src directory. >&2; \
	fi
endif # CONPUB_ENABLE

install:
	for i in $(CEF_UTIL) $(CEF_BWSTAT_UTIL) ""; do test -z "$$i" || install $$i $(INSTALLDIR); done
	if [ $(build_vendor) = apple ]; then \
		test -z $(CEF_MEM_UTIL_MACOS) || install $(CEF_MEM_UTIL_MACOS) $(INSTALLDIR)/$(CEF_MEM_UTIL); \
	else \
		test -z $(CEF_MEM_UTIL) || install $(CEF_MEM_UTIL) $(INSTALLDIR); \
	fi

uninstall:
	for i in $(CEF_UTIL) $(CEF_BWSTAT_UTIL) ""; do test -z "$$i" || rm -f $(INSTALLDIR)/$$i; done
	test -z $(CEF_MEM_UTIL) || rm -f $(INSTALLDIR)/$(CEF_MEM_UTIL)

clean:
	rm -f $(CEF_UTIL) *.bak

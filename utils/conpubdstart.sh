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

# check the number of parameters 
if [ $# -gt 2 ]
then
	echo 'usage : conpubdstart [-d config_file_dir]'
	exit 1
fi

PATH_CONFIG=/usr/local/cefore
CS_MODE=0
if [ "$1" = "-d" ];
then
	PATH_CONFIG="$2";
elif [ "$CEFORE_DIR" != "" ];
then
	PATH_CONFIG="$CEFORE_DIR/cefore";
fi
LINE_CS_MODE=$(grep "^CS_MODE=" ${PATH_CONFIG}/cefnetd.conf);
if [ "${LINE_CS_MODE}" != "" ]
then
  CS_MODE=$(echo ${LINE_CS_MODE} | sed -e "s/^[^0-9]*\([0-9]*\).*$/\1/")
fi
if [ "${CS_MODE}" != "3" ]
then
  echo "Unable to start conpubd, Illegal CS_MODE=${CS_MODE}"
  exit 1;
fi;

export DYLD_LIBRARY_PATH=/usr/local/lib:$DYLD_LIBRARY_PATH

# start conpubd
conpubd $@ &

# Cefore

## 1. Overview

Cefore is a software platform that enables ICN-based communications using CCNx-1.0 messages defined in [RFC8569](https://www.rfc-editor.org/rfc/rfc8569.html) and [RFC8609](https://www.rfc-editor.org/rfc/rfc8609.html). Cefore consists of (1) "cefnetd" daemon, which implements the CCN's basic function such as CCN Interest/Data handling, and FIB and Pending Interest Table (PIT) management, (2) "csmgrd" daemon, which implements Content Store, (3) arbitrary plugin library implementations that extend cefnetd's or csmgrd's functionalities, and (4) network tools/commands and sample applications.   

### 1.1. Environments

 Cefore (ver. 0.9.0) can run on top of Linux (Ubuntu) and macOS as the following table. At least 4 GB of memory (RAM) and 4 CPU cores are required to run csmgrd (Content Store manager daemon).

### 1.2. Components

 Cefore consists of the functions listed in the following table. Some functions can be enabled or disabled during the build, and when starting the forwarding daemon. All components except "Standard" are referred to as "--enable-xxxxx" when running a configure command. Standard components are installed by default. See "2.1.2. Build" and other documents for more detail.

| Name/Item    | Type    | Option   | Description                                 |
| ------------ | ------- | -------- | ------------------------------------------- |
| cefnetd      | daemon  | Standard | Forwarding daemon                           |
| cefnetdstart | utility | Standard | Utility of starting cefnetd                 |
| cefnetdstop  | utility | Standard | Utility of stopping cefnetd                 |
| cefstatus    | utility | Standard | Utility of showing cefnetd status on stdout |
| cefroute     | utility | Standard | Utility of set up cefnetd FIB               |
| cefctrl      | tool    | Standard | Function called by cefnetdstop, cefstatus, and cefroute |
| cefgetchunk  | tool    | Standard | Obtain the specified Cob and show the payload on stdout |
| cefputfile   | tool    | Standard | Convert the file to Named Cobs and transmit them to Cefore |
| cefgetfile   | tool    | Standard | Create file from content received by Cefore |
| cefputstream | tool    | Standard | Convert the stream received from stdin to Named Cobs and transmit them to Cefore |
| cefgetstream | tool    | Standard | Display the stream received by Cefore on stdout |
| cefping      | tool    | cefping  | cefping                                     |
| cefinfo      | tool    | cefinfo  | cefinfo (aka ccninfo)                       |
| csmgrd       | daemon  | csmgr    | Content Store manager daemon                |
| csmgrdstart  | utility | csmgr    | Utility of starting csmgr daemon            |
| csmgrdstop   | utility | csmgr    | Utility of stopping csmgr daemon            |
| csmgrstatus  | utility | csmgr    | Utility of showing csmgrd status on stdout  |
| Sample Transport | plugin | samptp | Sample transport plugin library            |
| cefore.lua   | application | Standard | Wireshark's LUA script file             |


## 2. Installation

The installation procedure of Cefore is summarized as follows. Please replace "x.x.x" in this guide with the version of Cefore to be installed.  

### 2.1. Required libraries
Install the libraries required for the Cefore installation. For example, to install OpenSSL on Ubuntu:

`sudo apt-get install libssl-dev`

On macOS, OpenSSL is installed in a different location. If you are using homebrew, you will need to run "brew install openssl" and set the indicated path and flag when you run configure as in "2.1.2. Build".

`brew install openssl`


#### 2.1.1. Extract archive
After downloading the Cefore archive, "cefore-x.x.x.zip", from [Cefore home page](https://cefore.net), extract it to any directory you want and go to the "cefore-x.x.x" directory. Replace "x.x.x" in the text with the version of the Cefore you want to install.

`unzip cefore-x.x.x.zip`  
`cd cefore-x.x.x`

#### 2.1.2. Build
Run configure first. The following options are available for configure command:

| Option           | Description                                      |
|:---------------- |:------------------------------------------------ |
| --enable-csmgr   | Enable Content Store managed by csmgr daemon.    |
| --enable-cefinfo | Enable cefinfo tool (aka CCNinfo).               |
| --enable-cache   | Enable cefnetd's local cache.                    |
| --enable-debug   | Enable debug mode (Attn: show lots of messages). |

Specify the installation directory. The default installation directory is "$CEFORE_DIR/sbin" for daemons such as cefnetd, "$CEFORE_DIR/bin" for utilities such as cefnetdstart and tools such as cefgetfile, and "$CEFORE_DIR/cefore" for configuration files such as cefnetd.conf. The default for the environment variable CEFORE_DIR is "/usr/local." Set the installation directory to the environment variable, CEFORE_DIR, if you want to change the installation directory.

If you changed the CEFORE_DIR environment variable, run autoconf and automake.

`autoconf`  
`automake`

If autoconf is not installed, install automake. The automake package also includes autoconf.

`sudo apt-get install automake` (Ubuntu)  
`brew install automake` (macOS)

To build with minimal configuration, run configure without specifying options.

`./configure`

If you installed OpenSSL using homebrew on macOS, you need to run configure as follows.

`export PATH="/usr/local/opt/openssl/bin:$PATH"`

`./configure opssl_header_path=/usr/local/opt/openssl/include/ LDFLAGS='-L/usr/local/opt/openssl/lib' CPPFLAGS='-I/usr/local/opt/openssl/include'`

To build cefinfo (aka ccninfo) and csmgr daemon, you need to specify these options:  

`./configure --enable-cefinfo --enable-csmgr`

After the configure command completes successfully, run "make" and "make install". "make install" must be run with sudo.

`make`  
`sudo make install`

If csmgr daemon is installed, the shared libraries must be recognized. If /etc/ld.so.conf does not contain $CEFORE_DIR/lib, add the path and run ldconfig.

`sudo ldconfig`

That's all for the installation!


## 3. License

Copyright (c) 2016-2022, National Institute of Information and Communications Technology (NICT). All rights reserved.  

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
3. Neither the name of the NICT nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.  

THIS SOFTWARE IS PROVIDED BY THE NICT AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE NICT OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

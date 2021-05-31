# Cefore  
## About Cefore
---
Cefore is a software platform that enables CCN-like communications. Cefore consists of (1) "cefnetd" daemon, which implements the CCN's basic function such as CCN Interest/Data handling, and FIB and Pending Interest Table (PIT) management, (2) "csmgrd" daemon, which implements Content Store, (3) arbitrary plugin library implementations that extend cefnetd's or csmgrd's functionalities, and (4) network tools/commands and sample applications. Cefore can run on top of Ubuntu, Raspbian Jessie, macOS, and Android.   

## License
---  
Copyright (c) 2016-2021, National Institute of Information and Communications Technology (NICT). All rights reserved.  

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
3. Neither the name of the NICT nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.  

THIS SOFTWARE IS PROVIDED BY THE NICT AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE NICT OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.



## Installation
---  
The installation procedure of Cefore is summarized as follows. Please replace "x.x.x" in this guide with the version of Cefore to be installed.  

### Prerequisite library installation
Firstly, the prerequisite libraries for Cefore installation should be installed.E.g., to install OpenSSL on Ubuntu.  
> *sudo apt-get install libssl-dev*

#### Decompression of Cefore archive
Decompress the Cefore's archive "cefore-x.x.x.tar.gz" to an arbitrary directory. When you decompress it, "cefore-x.x.x" directory will be created. After extracting, please move to "cefore-x.x.x" directory.
> *unzip cefore-x.x.x.zip*  
> *cd cefore-x.x.x*

#### Build
Run configure command. The following options can be specified for the configuration.  
| Options | Descriptions |
|:--|:--|
| --enable-csmgr | Install csmgr daemon. |
| --enable-cefping | Install cefping tool. |
| --enable-cefinfo | Install cefinfo tool. |
| --enable-ndn | Install NDN plugin function. |
| --enable-samptp | Enable the sample transport plugin. |

Specify the installation directory. The default installation directory is "$CEFORE_DIR/sbin" for cefnetd and csmgrd, "$CEFORE_DIR/bin" for utilities such as cefnetdstart and tools such as cefgetfile. The default environment variable CEFORE_DIR is "/usr/local". If you use the default installation directory, you do not need to configure this environment variable. The installation directory in the environment variable CEFORE_DIR is only when you change the installation directory.

If you change the environment variable CEFORE_DIR, please execute autoconf and automake.  
> *autoconf*  
> *automake*  

If you are building with minimum configuration, run configure without specifying any options.  
> *./configure*  

To enable cefping and csmgr, run configure as follows.  
> *./configure --enable-cefping --enable-csmgr*  

After configure completes successfully, run make and install.  
> *make*  
> *sudo make install*  



## Test in a small-scale network
---

Cefore experiments can be done in a small-scale network as shown in the following figure. For this small network, however, at least three PCs/VMs should be set up to make them act as consumer, router, and publisher.  

<PC1 (consumer):10.0.1.1>===<PC2 (router):10.0.1.2>===<PC3 (publicher):10.0.1.3>  

### Prepare the configuration file
Prepare the configuration files. If you start cefnetd (by entering "cefnetdstart" command on the terminal) without any configuration file, the three default configuration files (cefnetd.conf, cefnetd.fib, and plugin.conf) will be created. If you build csmgrd as well, the default csmgrd.conf will be also created. These created configuration files are all with comment (# at the beginning of each line), and in this state, all parameters will set as the default. Delete the leftmost # character of the parameter and change the value if you want to change the default value. At least you may want to configure some cefnetd's parameters in cefnetd.conf, such as USE_CACHE and CSMGR_NODE, and configure csmgrd's parameters in csmgrd.conf if Content Store is used. In order to enable the CS function at PC3 (router), you usually need to configure CACHE_TYPE and ALLOW_NODE in its csmgrd.conf.

### Route setting
Before starting cefnetd, set up its FIB by creating the FIB configuration file (cefnetd.fib). The following examples are two cefnetd.fib files to set up PC1's FIB and PC2's FIB, respectively. Since PC3 does not send Interest to any node, PC3's FIB is not needed.

PC1 cefnetd.fib  
> *ccn:/example udp 10.0.1.2*

PC2 cefnetd.fib  
> *ccn:/example udp 10.0.1.3*

If you want to set up FIB manually after cefnetd's startup, it is also possible to set up FIB with the cefroute utility, such as,  
> *cefroute add ccn:/example udp 10.0.1.2*

### Tune kernel parameters
Before starting cefnetd, it is recommended to tune the several kernel parameters (for Linux and Raspbian) as follows.
> *sudo sysctl -w net.core.rmem_default=10000000*
> *sudo sysctl -w net.core.wmem_default=10000000*
> *sudo sysctl -w net.core.rmem_max=10000000*
> *sudo sysctl -w net.core.wmem_max=10000000*

For macOS, the following commands tune the kernel parameters to run cefnetd.
> *sudo sysctl -w net.local.stream.sendspace=2000000*
> *sudo sysctl -w net.local.stream.recvspace=2000000*

### Start cefnetd
Enter cefnetdstart at the terminal on each node to start cefnetd. Then enter cefstatus at the terminal to confirm whether it is running.  
> *cefnetdstart*

### Show cefnetd's status on standard-out
Enter cefstatus at the terminal.
> *cefstatus*

### Start csmgrd
Enter csmgrd (with "&" for background) at the terminal on PC3 and start csmgrd. Then enter csmgrstatus at the terminal and confirm whether it is running.  
> *csmgrd*

### Cache file at PC3 (publisher)
Cache a file in the PC3's content store. Enter cefputfile at PC3 terminal. The following is an example of the content with the URI of ccn:/example/file and the file to be cached as in.txt. 
> *cefputfile ccn:/example/file -f in.txt*

### Retrieve data from the cache with PC1 (publisher)
Confirm the content cached on PC3 at PC1. Enter cefgetfile at the terminal on PC1. The following is an example to retrieve the content whose URI is ccn:/example/file (same as the URI used for caching on PC 3).  

> *cefgetfile ccn:/example/file out.txt*

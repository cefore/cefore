# Cefore Daemons

## 1. cefnetd (Forwarding Daemon)

### 1.1. Startup Option for Daemons and Tools
Daemons such as cefnetd and tools such as cefgetfile can specify the port number for the startup option: If you start cefnetd with the "-p port_num" option, you must specify the same startup option to stop it.

`cefxxx [-p port_num]`

|Parameter | Description |
|--------- | --------- |
|port_num  | The port number to use for the connection. The default is PORT_NUM in cefnetd.conf. This parameter takes precedence over PORT_NUM in cefnetd.conf. Therefore, if this parameter is specified, PORT_NUM in cefnetd.conf is ignored.|

The daemons currently supporting these startup options are: cefnetd, cefnetdstart, cefnetdstop, cefstatus, cefroute, cefgetfile, cefgetchunk, cefputfile, cefgetstream, cefputstream, cefping, cefinfo (ccninfo), cefgetfile_sec, and cefputfile_sec.

### 1.2. Start/Stop cefnetd

To start or stop cefnetd, run the "cefnetdstart" or "cefnetdstop" utility from the terminal. It is recommended that you run them as a superuser although you can also run them as a non-superuser.

Use the "cefnetdstart" utility to launch cefnetd as follows:

`sudo cefnetdstart`

It is recommended that the TCP and UDP buffer sizes be tuned by the sysctl command before starting cefnetd. After tuning, restart daemons, including cefnetd.

Ubuntu: Change buffers to 10 Mbytes:

`sudo sysctl -w net.core.rmem_default=10000000`  
`sudo sysctl -w net.core.wmem_default=10000000`  
`sudo sysctl -w net.core.rmem_max=10000000`  
`sudo sysctl -w net.core.wmem_max=10000000`

macOS: Change buffers to 2 Mbytes:

`sudo sysctl -w net.local.stream.sendspace=2000000`  
`sudo sysctl -w net.local.stream.recvspace=2000000`

It is possible to specify the boot option described in "1.1. Startup Option for Daemons and Tools" for the cefnetdstart utility. For example, the following command starts cefnetd using the configuration file located in "/tmp/foo" with port 5678:

`sudo cefnetdstart -d /tmp/foo -p 5678`

Cefnetdstop utility was used to stop cefnetd. Only the user or super-user who started cefnetd can stop cefnetd.

`sudo cefnetdstop`

In addition to the cefnetdstart utility, cefnetdstop can also boot with the "-F" option:

`cefnetdstop [-F] [-d config_file_dir] [-p port_num]`

| Parameter | Description |
|--------- | --------- |
| -F        | Kill all running cefnetd and delete the UNIX domain socket created by cefnetd in /tmp.|


### 1.3. cefnetd Status

The "cefstatus" utility checks the cefnetd status. If the cefnetd has been started with the "-d config_file_dir" and "-p port_num" options, use the same startup options as in cefnetd to check the status.

`cefstatus [-v] [--version] [-d config_file_dir] [-p port_num]`

Below is the output of the "cefstatus" utility. "-v" and "--version" show the version number of cefnetd.

> *Version    : cefnetd's version number*  
*Port       : port number cefnetd is using*  
*Rx Frames  : number of the received frames after cefnetd is launched*  
*Tx Frames  : number of the transmitted frames after cefnetd is launched*  
*Cache Mode : cache type (None or External)*  
*Faces :  
  &emsp;Face information currently available on the node*  
*FIB(App) : num of the entries  
  &emsp;FIB entries for applications*  
*FIB : num of the entries  
  &emsp;FIB entries*  
*PIT(App) : num of the entries  
  &emsp;PIT entries for applications*  
*PIT : num of the entries  
  &emsp;PIT entries*


### 1.4. FIB Entry Management

Interest forwarded to FIB entries can be managed by;
(1)	Static management function and (2) Routing control by routing protocol.
For (1), see "1.4.2. Static Management of FIB Entries," while (2) is under development and disabled in this release.

#### 1.4.1. Permission of Deleting a FIB Entry

Depending on the method of adding the FIB entry, the permission for FIB deletion is determined by the bit field after the face number, in the FIB column of the cefstatus utility. The bit fields are, from left to right, the c bit (added by the controller, which is not included in this release), the s bit (statically added by the configuration of cefnet.fib and cefroute utility), and the d bit (dynamically added by the routing protocol). The permissions are in the order of c, s, and d. An example of this is shown below.

> *FIB :  
  &emsp;ccnx:/foo/bar/  
    &emsp;&emsp;Faces : 17 (-s-) 31 (csd)  
  &emsp;ccnx:/hoge/piyo/  
    &emsp;&emsp;Faces : 21 (c--) 37 (--d)*  

#### 1.4.2. Static Management of FIB Entries

There are two ways to statically manage FIB entries: (1) Write a destination in cefnetd.fib (see "2. cefnetd.fib" in Configuration document) before starting cefnetd, and (2) Add / remove statically configured FIB entries using the cefroute utility after start up. Statically configured FIB entries are not removed from the FIB unless the cefroute utility removes them. If cefnetd is started with the "-d config_file_dir" and "-p port_num" options, specify the same startup options as those of cefnetd for which you want to configure the FIB. In addition, only the user or super-user who starts cefnetd can interact with the FIB, that is, User-1, and the super-user can interact with the cefnetd FIB when User-1 starts up the cefnetd. Only the super-user can interact with cefnetd when the super-user starts up the cefnetd. The usage of the cefroute utility is shown below.

Add a FIB entry:

`cefroute add uri protocol host [-d config_file_dir] [-p port_num]`

Delete a FIB entry:

`cefroute del uri protocol host [-d config_file_dir] [-p port_num]`

Enable a FIB entry:

`cefroute enable uri protocol host [-d config_file_dir] [-p port_num]`

When using IPv6, enclose the IP address in brackets ([]).
For link-local addresses, the IP address must be followed (in []) by the "%" (percent) followed by the interface name used by the local node, and the port number must be followed by the ":" outside of [].

Note: When you add a port number to the IP address of cefroute add, you explicitly specify the port number that the IP address uses to connect to the peer, so the number specified in ":Port_number" is used (you explicitly specify the port to use for the uplink cefnetd listening port). Use -p with cefroute add if you want to specify your own cefnetd listening port to connect to.
Therefore, if you do not specify a ":Port_number," the port number specified in the cefnetd is used, assuming that the listening port of the uplink cefnetd is itself (the value of the "-p port_num" option or the "PORT_NUM" option in cefnetd.conf will be used. The value of the "-p port_num" option will override the "PORT_NUM" option in cefnetd.conf).

The above uri specifies the URI to add (e.g., ccnx:/news/today). The protocol specifies the protocol used for the connection. Specify udp for UDP connections or tcp for TCP connections Specify the host as the IP address of the upstream router to which you want to connect. You can specify multiple IP addresses for the upstream router, separated by spaces or tabs. If the URI is ccnx:/example, the destinations are 10.0.2.1 and 10.0.2.2, and the protocol is adding FIB entries with UDP, enter:

`cefroute add ccnx:/example udp 10.0.2.1 10.0.2.2`

In the above input example, the cefnetd of the router performs the cefroute and the upstream router connects using the boot option or the port number specified in cefnetd.conf. If the port number used for each destination is changed, the port number can be specified in the form "Destination_IP_address:Port_number" as follows.

`cefroute add ccnx:/example udp 10.0.2.1 10.0.2.2:9999 10.0.2.3:9998 10.0.2.4:9997`

If you are TCP-connected to an upstream router, you may lose the TCP connection because of a keep alive timeout, as the upstream cefnetd may stop or restart. A face that loses its TCP connection is not immediately removed from the FIB entry. First, the log information at the time the TCP face went down is output to the terminal that started the cefnetd, as shown in the following example (the date and face number are examples).
> *2022-02-16 11:27:24.038 [cefnetd] WARNING: Detected Face#24 (TCP) is down*

Next, the cefstatus utility shows the downed face status (#down marking). The downed face cannot be used for communications, but remains in the FIB entry until the face is removed.

> *cefstatus*  
>
> *Version    : 01  
Port       : 9695
Rx Frames  : 0  
Tx Frames  : 0  
Cache Mode : None  
Faces :  
  &emsp;faceid =   5 : IPv6 Listen face (udp)  
  &emsp;faceid =  24 : address = 172.16.6.184:9999 (tcp) # down  
  &emsp;faceid =   0 : Local face  
  &emsp;faceid =  26 : Local face  
  &emsp;faceid =   6 : IPv4 Listen face (tcp)  
  &emsp;faceid =   4 : IPv4 Listen face (udp)  
  &emsp;faceid =   7 : IPv6 Listen face (tcp)  
FIB(App) :  
  &emsp;Entry is empty  
FIB : 1  
  &emsp;ccnx:/test/  
    &emsp;&emsp;Faces : 24  
PIT(App) :  
  &emsp;Entry is empty  
PIT :  
  &emsp;Entry is empty*

To recover a face that is down, run the "enable" operation. Log information on the recovery result is output to the terminal. In addition, if the recovery is successful, one can run the cefstatus utility to check that there are no faces with #down marking.

`cefroute enable ccnx:/test tcp 172.16.6.184:9999`


### 1.5.	Logging and Debugging

For standard output of cefnetd and csmgrd logs, set CEF_LOG_LEVEL in the configuration file cefnetd.conf or csmgrd.conf before starting. The default value is 0.

| Level | Description                     | Default value    |
| ----- | ------------------------------- | ---------------- |
| INFO  | Information of normal behaviors | Appeared with 2. |
| WARNING |Warning messages.<br> e.g., tried to create FIB entry with TCP by the cefroute command, but the TCP session could not be established. | Appeared with the value more than 1.|
| ERROR | Error message (You need to stop the program) | Appeared with the value more than 0.|

The following is sample output, where the time is the local time:

> *2022-01-23 12:00:00.000 [cefnetd] INFO: [client] Local Socket Name is /tmp/cef_9896.0  
2022-01-23 12:00:00.001 [cefnetd] INFO: [client] Listen Port is 9695*

For standard output of cefnetd and csmgrd debug information, you must run the build with --enable-debug option for configure command, and set CEF_DEBUG_LEVEL in the configuration file cefnetd.conf or csmgrd.conf. The default value is 0.
You can also set the level from 1 to 3, the higher the value, the more detailed debug information is output (if 3 is set, the dump of received packets is also output).


## 2. csmgrd (Content Store Manager Daemon)

Here's how to use the csmgr : To use csmgr, you need to run the build with --enable-csmgr when you run configure.

### 2.1. Preparation

Before starting csmgrd, check the "4. csmgrd.conf" in Configuration document. Connect csmgrd and cefnetd using TCPs. If cefnetd and csmgrd are running on the same device, use a UNIX domain socket. In the example below, the cefnetd in the red box shares the cache of csmgrd.

Set the following parameters for cefnetd.conf before starting cefnetd, which connects to csmgrd. Use the csmgrstatus tool (see "2.3. csmgrd Status") to check if you can connect to csmgrd before starting cefnetd.

> *CS_MODE=2  
CSMGR_NODE=IP address of the node on which csmgrd runs  
CSMGR_PORT_NUM=TCP port number csmgrd uses*

If the CSMGR_NODE in cefnetd.conf is "localhost", cefnetd and csmgrd communicate over a UNIX domain socket. The UNIX domain socket used for communication is created in the /tmp directory. The created socket file name is "csmgr_PORT.ID". The communication with remote cefnetds is established over TCP.

### 2.2. Start/Stop csmgrd

Start csmgrd from the terminal If you want to start it as a daemon, run it in the background (i.e., run it with "&"). You can also use [-d config_file_dir] to specify the path of the configuration file that you want to read. You can start csmgrd with the csmgrdstart utility and stop it with the csmgrdstop utility. The user or super-user who started csmgrd can also stop csmgrd.

`csmgrd [-d config_file_dir]`

csmgrdstart and csmgrdstop parameters are shown below.

`csmgrdstart [-d config_file_dir]`  
`csmgrdstop [-F] [-d config_file_dir]`

| Parameter | Description                      |
| --------- | -------------------------------- |
| -F        | Stop all active csmgrd by force. |

It is recommended to tune the TCP and UDP buffer sizes before starting csmgrd. If you cannot send or receive all the frames to send or receive cefnetd, use the sysctl command to tune the buffer sizes. After tuning, the daemons are restarted, using csmgrd.

Example of changing the buffer size to 10 Mbytes at Ubuntu:

`sudo sysctl -w net.core.rmem_default=10000000`  
`sudo sysctl -w net.core.wmem_default=10000000`  
`sudo sysctl -w net.core.rmem_max=10000000`  
`sudo sysctl -w net.core.wmem_max=10000000`

Example of changing the buffer size to 2 Mbytes at macOS:

`sudo sysctl -w net.local.stream.sendspace=2000000`  
`sudo sysctl -w net.local.stream.recvspace=2000000`

### 2.3. csmgrd Status

Use the csmgrstatus utility to see if you can connect to the csmgrd or check the state of the csmgrd.

`csmgrstatus [uri] [-p port] [-h host]`

| Parameter | Description |
| --------- | ----------- |
| uri | Specifies the Prefix of the content to check.|
| port| The port number to use for the connection. Default value is 9799.|
| host | Specifies the host identifier (e.g., IP address) on which the connecting csmgrd is running. If omitted, connects to the local csmgrd.|

csmgrstatus displays the information as follows. Multiple contents can be displayed.

> *Connect to "host name csmgrd is running" ("port number")  
All Connection Num 		: Num. of connected nodes to csmgrd  
Number of Cached Contents  :*  
\* *Following information appeared only when content specified "uri" option is cached.  
  &emsp;Content Name  :  
  &emsp;Content Size  : (Bytes)  
  &emsp;Access Count  : Num of content access  
  &emsp;Freshness     : Remaining time of the content (Sec)  
  &emsp;Elapsed Time  : Elapsed time since cached (Sec)*

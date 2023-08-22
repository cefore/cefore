# Cefore Configurations

This document summarizes the configuration files used for Cefore. During the cefnetd installation, the sample configuration files (all commented out) are created in the path of "$CEFORE_DIR/cefore". The default for the environment variable CEFORE_DIR is "/usr/local". The configuration file is created only if the configuration file does not exist in the specified path. If the configuration file already exists in the specified path, that file is not changed.
Daemons such as cefnetd and tools such as cefgetfile can also specify the path where the configuration file is located at startup by using the "-d config_file_dir" option (See "1.1. Startup Option for Daemons and Tools" in Daemon document). This "-d config_file_dir" option takes precedence over the environment variable CEFORE_DIR. That is, daemons started with the "-d config_file_dir" option use the configuration file in the path specified by "-d config_file_dir".

## 1. cefnetd.conf
cefnetd.conf describes the cefnetd parameter settings. The parameters must be in the format, such as "Parameter=Default", on each line. If a parameter is not specified, the default value is used.

| Parameter | Description | Default |
| - | - | - |
| NODE_NAME     | Name of the node. <br> Specifies the name of your node in a string that can be used as a URI.| "" (null) |
| CEF_LOG_LEVEL | Specifies the log output type for the cefnetd.<br>      Range: 0 <= n <= 3 <br> See "1.5. Logging and Debugging" for more information.| 0 |
| PORT_NUM | Port number cefnetd uses. <br> Range: 1024 < p < 65536 <br> If the startup option "-p port_num" is used, the port number specified by the "-p port_num" option takes precedence over this parameter. See "1.1. Startup Option for Daemons and Tools" for more information | 9896 |
| PIT_SIZE | Max number of PIT entries. <br> Range: 1 < n < 65536 | 2048 |
| PIT_SIZE_APP | Max number of the registered PIT (APP). <br> Range: 1 < n < 1025 | 64 |
| FIB_SIZE | Max number of FIB entries. <br> Range: 1 < n < 65536 | 1024 |
| FIB_SIZE_APP | Max number of the registered FIB (APP). <br> Range: 1 < n < 10240000 | 64 |
| CS_MODE | ContentStore mode Cefore uses. <br>  | 0: No cache used <br> 1: cefnetd's local cache <br> 2: csmgrd (with the number of the buffers defined in BUFFER_CAPACITY) |
| BUFFER_CAPACITY | Max Cob buffer size. <br> Range: 0 <= n < 65536 | 30000 |
| LOCAL_CACHE_CAPACITY | Max number of Cobs to use for the local cache in cefnetd. <br> Range: 1 < n <= 8000000 <br> Approximate memory usage: Cob size * 2 * num. of Cobs. | 65535 |
| LOCAL_CACHE_INTERVAL | Interval to check expired content in cefnetd's local cache (sec). <br> Range: 1 < n < 86400 (=24 hours) | 60 |
| CSMGR_NODE | csmgrd's IP address | localhost |
| CSMGR_PORT_NUM | TCP port number used by csmgrd to connect cefnetd. <br> Range: 1024 < p < 65536 | 9799 |
| LOCAL_SOCK_ID | UNIX domain socket ID. <br> Usually it is not necessary to change it. | 0 |
| CCNINFO_ACCESS_POLICY | CCNinfo access policy <br> 0: Allow all <br> 1: Request/Reply message forward only <br> 2: Deny all | 0 |
| CCNINFO_FULL_DISCOVERY | Permission of "Full discovery request" <br> 0: Deny <br> 1: Allow <br> 2: Allow if approved <br> | 0 |
| CCNINFO_VALID_ALG | Validation algorithm to attach to CCNinfo Reply messages if requested. <br> Specify either crc32, sha256, or None. None means no validation attached to CCNinfo Reply messages. <br> If CCNINFO_VALID_ALG=sha256 is specified, both private and public keys are located in: <br> /usr/local/cefore/.ccninfo | crc32 |
| CCNINFO_SHA256_KEY_PRFX | Prefix name of secret/public keys. <br> Secret key name: specified prefix_name"-private-key" <br> Public key name: specified prefix_name"-public-key" | ccninfo_rt |
| CCNINFO_REPLY_TIMEOUT | PIT lifetime on "Full discovery request" (sec). <br> Range: 2 to 5 (sec.) | 4 |
| FORWARDING_INFO_STRATEGY | Forwarding strategy when sending Interest messages. <br> 0: Forward using one longest prefix match FIB entry <br> 1: Forward using all longest prefix match FIB entries | 0 |
| SYMBOLIC_INTEREST_MAX_LIFETIME | Symbolic Interest lifetime (sec). <br> Range: 1 <= x | 4 |
| REGULAR _INTEREST_MAX_LIFETIME | Regular Interest lifetime (sec). <br> Range: 1 <= x | 2 |
| CSMGR_ACCESS | Mode in which cefnetd accesses csmgrd <br> RW: read and write access <br> RO: read-only access | RW |
| BUFFER_CACHE_TIME | Interval cefnetd stores cache in its temporary buffer (msec). <br> Range: 0 <= x | 10000 |
| LOCAL_CACHE_DEFAULT_RCT | Cob's RCT (Recommended Cache Time) (sec). <br> This value is used if RCT is not specified in the Cob. <br> Range: 1 < n < 3600 (= 1 hour) | 600 |

## 2. cefnetd.fib
The cefnetd.fib is required only if you want to statically configure the FIB entry at cefnetd boot time. In the cefnetd.fib, describe each line in the format of "URI Protocol Destination_IP_address".
You can specify more than one IP address for each separating them by spaces or tabs. You can also specify the port number to use for each host by specifying "Destination_IP_address:Port_number". If no port number is specified, the connection is made with the port number specified in the boot option or cefnetd.conf.
When using IPv6, enclose the IP address in brackets ([]).
For link-local addresses, the IP address must be followed (in []) by the "%" (percent) followed by the interface name used by the local node, and the port number must be followed by the ":" outside of [].

> *ccnx:/news/today &nbsp;udp &nbsp;10.0.3.1 &nbsp;10.0.3.2:9876 &nbsp;10.0.3.3:8765*  
> *ccnx:/cinema/sf &nbsp;tcp &nbsp;10.0.2.1:9999 &nbsp;10.0.2.2:8888*  
> *ccnx:/weather/tokyo &nbsp;udp &nbsp;[fe80::fde:3f51:af6c:70cf%eth0]:12345*  
> *ccnx:/ &nbsp;udp &nbsp;10.0.1.1*

## 3. cefnetd.key
cefnetd.key specifies, for each URI, the public and private keys to use for the validation of the Interest and Content Objects in the form "URI Private_key Public_key". Both keys follow PEM format.
By default, only one line is provided to apply the pre-installed private and public keys to all URIs. These keys are prepared in the same path with the path of cefnetd.key. The matching between a URI and the URI described in the cefnetd.key is conducted by the longest prefix match same as FIB.

> *ccnx:/ &nbsp;/usr/local/cefore/default-private-key &nbsp;/usr/local/cefore/default-public-key*

The public and private keys distributed here are common to all cefore packages and do not make any sense in terms of Interest/Content Object validation. For this reason, it is recommended that you re-create the default private and public keys as needed and distribute the re-created or per-URI public keys to the communicating cefore nodes.
The following example shows how to specify the public and private keys to be used for each URI. The order of the URIs are not relevant with the processing. Internally, the content name and the prefix specified in cefnetd.key are matched with the longest forward match.

> *ccnx:/news/today &nbsp;xxx-private-key &nbsp;xxx-public-key*  
> *ccnx:/news/sports &nbsp;yyy-private-key &nbsp;yyy-public-key*  
> *ccnx:/news &nbsp;zzz-private-key &nbsp;zzz-public-key*  
> *ccnx:/ &nbsp;default-private-key &nbsp;default-public-key*


## 4. csmgrd.conf
csmgrd.conf describes the settings for the Content Store and csmgr. The parameters must be in the format "Parameter=Default" on each line. If a parameter is not specified, the default value is used.

| Parameter | Description | Default |
| --------- | ----------- | ------- |
|  CEF_LOG_LEVEL  | Specifies the log output level for the cefnetd.<br> Range: 0 <= n <= 3 <br> See "1.5. Logging and Debugging" in Daemon document for more information. | 0 |
|  PORT_NUM  | Port number used by csmgrd. <br> Range: 1024 < p < 65536 | 9799 |
|  CACHE_TYPE  | Plugin name used by csmgrd. <br> Currently, the following cache plugins are supported. <br> filesystem: cache located on UNIX filesystem <br> memory: cache located on memory (RAM) | filesystem |
|  CACHE_INTERVAL  | Csmgrd Expired Content Check Interval (ms) <br> Range: 1,000 < n < 86,400,000 (= 24 hours) | 10,000 |
|  CACHE_DEFAULT_RCT  | (In case of RCT unspecified) Cob's RCT (ms) <br> Range: 1,000 < n < 3,600,000 (= one hour)  | 600,000 |
|  ALLOW_NODE  | IP address of the host that is allowed to connect. <br> By default, only the localhost can connect; if you want to allow remote connections to the csmgrd, you must write the csmgrd's IP address. <br><br> Write "ALL" to allow all connections. <br> E.g., ALLOW_NODE=ALL <br><br> You can specify more than one by separating them with commas. <br> E.g., ALLOW_NODE=10.2.3.4,20.3.4.5 <br><br> You can specify multiple lines. <br> E.g.,<br> ALLOW_NODE=10.2.3.4 <br> ALLOW_NODE=20.3.4.5 <br><br> It can also be specified using a subnet, otherwise it will be an exact match comparison. <br> E.g., <br> ALLOW_NODE=10.2.3.0/24 <br> ALLOW_NODE=10.2.0.0/16 <br> | localhost |
|  CACHE_ALGORITHM  | Cache replacement algorithm library, e.g., libcsmgrd_lru <br> Specify the cache replacement algorithm library without a file extension (e.g., ".so"). If None is specified, the cache replacement algorithm library will not be used. | libcsmgrd_lru |
|  CACHE_PATH  | Directory used for filesystem cache. Only required to specify this value when filesystem cache is used. <br> Under this directory, csmgr_fsc_NNN sub-directory is created, and Cob is located in it. | $CEFORE_DIR/cefore |
|  CACHE_CAPACITY  | Max num. of the cached Cobs. <br> (819200 for lfu, and 2147483647 for other cache algorithms such as lru and fifo) <br> Range: 1 <= n <= 68,719,476,735 (=0xFFFFFFFFF) <br> Note specify either decimal value or hexadecimal value started with "0x". | 819200 |
|  CEF_DEBIG_LEVEL  | Specifies the debug output level for the cefnetd. <br> Range: 0 <= n <= 3 <br> See "1.5. Logging and Debugging" for more information. | 0 |
|  LOCAL_SOCK_ID  | UNIX domain socket ID. <br> Usually, it is not necessary to change it. | 0 |

## 5. plugin.conf
plugin.conf is required only when plug-in libraries are used. It must be placed in the plugin directory within the; default path of the configuration file. The parameters must be written in the format "Parameter=Default" on each line. If a parameter is not specified, the default value will be used.

| Tag       | Parameter | Description | Default |
| --------- | --------- | ----------- | ------- |
| COMMON    | log       | Logging of plugin. yes=enabled, no=disabled|no|
| TRANSPORT | samptp    | Sample transport plugin. yes=enabled, no=disabled|no|

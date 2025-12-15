# Cefore Tools

The following is a summary the tools in the Cefore package. If cefnetd is launched with the "-d config_file_dir" and "-p port_num" options, specify these startup options for the cefnetd you want to communicate with.

## 1. cefputfile

cefputfile is a tool that converts a specified file into a content object with a specified URI and transfers the file to  cefnetd.

`cefputfile uri -f path [-b block_size] [-r rate] [-e expiry] [-t cache_time] [-d config_file_dir] [-p port_num] [-v valid_algo]`

If the "-f" option is omitted, the last name of the specified URI becomes the input file name. For example, "cefputfile ccnx:/foo/bar/a.txt" has the same effect as the command with "-f a.txt" in the current directory where the cefputfile is executed.

| Parameter  | Description                                                   |
| ---------- | ------------------------------------------------------------- |
| uri        | URI. This parameter cannot be omited.                         |
| path       | Path to the file you enter. This parameter cannot be omitted. |
| block_size | Max length of the payload of Content Object (Byte)<br>Range: 60 <= block_size <= 57344 (default: 1024)    |
| rate       | Sending rate (Mbps) from the app (cefputfile) to the network stack (cefnetd). <br>If you enter more than four decimal places, the value will be rounded to three decimal places, and any digits beyond that will be ignored. <br>Range: 0.001 <= rate <= 10240.000 (default: 5) |
| expiry | Lifetime (s) of Content Object. Long value may improve the hit ratio, but it increases the risk of retaining outdated content objects. <br>Range: 1 <= expiry <= 86400 (default: 3600) |
| cache_time | Recommended cache time (RCT) (s) of the ContentObject packet for intermediate routers. <br>Range: 1 <= cache_time <= 65535 (default: 300) |
| valid_alg  | Validation algorithm used for the message. If no validation algorithm specified, validation will not be performed. In this version, validation algorithm must be either rsa-sha256 or crc32c. |


## 2. cefgetfile

cefgetfile is a tool that outputs the content of the specified URI from cefnetd. Enter Ctrl + C to exit. It will also exit automatically if more than two seconds have elapsed since the last content object was received. If you want to retrieve content on your cefgetfile, you must have already cached the content in a cache on your network.

`cefgetfile uri -f file [-o] [-m chunk] [-s pipeline] [-d config_file_dir] [-p port_num] [-v valid_algo]`

If the "-f" option is omitted, the last name of the specified URI becomes the input file name. For example, "cefgetfile ccnx:/foo/bar/a.txt" has the same effect as the command with "-f a.txt" in the current directory where the cefgetfile is executed.

| Parameter  | Description                                                   |
| ---------- | ------------------------------------------------------------- |
| uri        | URI. This parameter cannot be omited.                         |
| path       | Path to the file you enter. This parameter cannot be omitted. |
| -o         | Retrieve content directly from the publisher app instead of from the in-network router's cache. If the publisher is unknown (for example, the route is disconnected or the publisher is down), content cannot be retrieved. |
| chunk      | Specify the number of chunks to get. The application terminates when it receives the specified number of chunks.  |
| pipeline   | Specify the number of pipelines when sending interest. The default value is 4. |
| valid_alg  | Validation algorithm used for the message. If no validation algorithm specified, validation will not be performed. In this version, validation algorithm must be either rsa-sha256 or crc32c. |

If content was successfully downloaded with cefgetfile, "Complete" is displayed as shown in bold characters below. When "Incomplete" is displayed, a packet loss has occurred and there are chunks that could not be retrieved. Even though the interest was retransmitted, the content download was interrupted.
The "Duration" output is specified to three decimal places (rounded up to four decimal places).
The "Throughput" is calculated in real time, and the fractional part is truncated



## 3. cefgetchunk

cefgetchunk tool retrieves the content object and chunk number specified in the parameters. The payload of the retrieved content object is STDOUT. This command automatically terminates if the specified content object cannot be retrieved within three seconds of input.

`cefgetchunk uri -c chunknum [-d config_file_dir] [-p port_num]`

| Parameter  | Description                                                   |
| ---------- | ------------------------------------------------------------- |
| uri        | URI. This parameter cannot be omited.                         |
| chunknum   | Specify the chunk number of the Content Object you want to retrieve. This parameter cannot be omitted. |


## 4. cefputstream

cefputstream is a tool that converts stream content in STDIN into a content object with a specified URI and inputs it into cefnetd. Enter Ctrl-C to exit.

`cefputstream uri [-b block_size] [-r rate] [-e expiry] [-t cache_time] [-d config_file_dir] [-p port_num] [-v valid_algo]`

| Parameter  | Description                                                   |
| ---------- | ------------------------------------------------------------- |
| uri        | URI. This parameter cannot be omited.                         |
| block_size | Max length of the payload of Content Object (Byte)<br>Range: 60 <= block_size <= 57344 (default: 1024)    |
| rate       | Sending rate (Mbps) from the app (cefputstream) to the network stack (cefnetd). <br>Range: 1 <= rate <= 32 (default: 5) |
| expiry | Lifetime (s) of Content Object. Long value may improve the hit ratio, but it increases the risk of retaining outdated content objects. <br>Range: 1 <= expiry <= 86400 (default: 0) |
| cache_time | Recommended cache time (RCT) (s) of the ContentObject packet for intermediate routers. <br>Range: 1 <= cache_time <= 65535 (default: 0) |
| valid_alg  | Validation algorithm used for the message. If no validation algorithm specified, validation will not be performed. In this version, validation algorithm must be either rsa-sha256 or crc32c. |


## 5. cefgetstream

cefgetstream is a tool that shows the stream content of the specified URI retrieved from cefnetd. Enter Ctrl-C to exit.

`cefgetstream uri [-o] [-m chunk] [-s pipeline] [-d config_file_dir] [-p port_num] [-z lifetime] [-v valid_algo]`

| Parameter  | Description                                                   |
| ---------- | ------------------------------------------------------------- |
| uri        | URI. This parameter cannot be omited.                         |
| -o         | Retrieve content directly from the publisher app instead of from the in-network router's cache. If the publisher is unknown (for example, the route is disconnected or the publisher is down), content cannot be retrieved. |
| chunk      | Specify the number of chunks to get. The application terminates when it receives the specified number of chunks.|
| pipeline   | Specify the number of pipelines when sending interest (default: 4). |
| lifetime   | Specify lifetime interval inserted in Symbolic Interest (default: 4).<br>If this value is bigger than the value configured in cefnetd, it will be ignored, and the value configured in cefnetd will be used. |
| valid_alg  | Validation algorithm used for the message. If no validation algorithm specified, validation will not be performed. In this version, validation algorithm must be either rsa-sha256 or crc32c. |

## 6. cefinfo

cefinfo is a tool that identifies the cefnetd that caches the content for a specified prefix. cefinfo is known as CCNinfo whose specification is described in IRTF RFC 9344. It is possible to identify the responder (i.e., caching node) and to measure the RTT between the cefinfo performer and the respondents. Note that although the RTT is accurate, the latency between each cefnetd on the path is not accurate if the time on each cefnetd is not synchronized. If you start cefnetd with the "-d config_file_dir" and "-p port_num" options, you must specify the same startup options.

`cefinfo name_prefix [-c] [-o] [-f] [-r hop_count] [-s skip_hop] [-d config_file_dir] [-p port_num] [-V]`

| Parameter  | Description                                                   |
| ---------- | ------------------------------------------------------------- |
| name_prefix | Prefix of the content to be checked. This prefix is set to the name of the cefinfo request. Matching between the name and the cache of the content is a partial match, and matching between the name and the FIB is a longest match |
| -c | Specify this option if the cefinfo user requires the cache information and RTT between the cefinfo user and the content forwarder. |
| -f | This option enables "full discovery request", in which the router ignores the forwarding strategies and sends the cefinfo request to multiple upstream routers simultaneously. The cefinfo user can then retrieve all potential forwarding paths. Note that this requires all upstream routers allowing the full discovery requests by setting up the CCNINFO_FULL_DISCOVERY configuration. |
| hop_count |  The max number of traced routers (default: 32). For example, when the cefinfo user invokes the command with this option, such as "-r 3", only three routers along the path examine their path and cache information.<br>Range: 1 <= hop_limit <= 255 |
| skip_count | The number of skipped routers (default: 0). For example, when the cefinfo user invokes the command with this option, such as "-s 3", three upstream routers along the path only forward the Request message but do not append their Report blocks in the hop-by-hop header and do not send Reply messages despite having the corresponding cache.<br>Range: 0 <= hop_limit <= 15 |

cefinfo terminates when a single reply message is given back (the default behavior) or the process after the timeout value defined as CCNINFO_REPLY_TIMEOUT has elapsed (the full discovery behavior). When a response is received, the reply content is shown to the standard output as follows.

> *cefinfo to name_prefix with HopLimit=hop_limit, SkipHopCount=skip_hop, Flag=flag and Request ID=RequestID*
>
> *response from Responder: Result, time=Rtt ms*
> 
> *route information:<br>
  &emsp;1 Forwarder-1&emsp;&emsp;&emsp;&emsp;Delay ms<br>
  &emsp;2 Forwarder-2&emsp;&emsp;&emsp;&emsp;Delay ms<br>
    &emsp;&emsp;&emsp;&emsp;.<br>
    &emsp;&emsp;&emsp;&emsp;.<br>
  &emsp;N Responder&emsp;&emsp;&emsp;&emsp;Delay ms*
>
> *cache information:&emsp;&emsp;prefix&emsp;&emsp;size&emsp;&emsp;cobs&emsp;&emsp;interests&emsp;&emsp;start-end&emsp;&emsp;lifetime&emsp;&emsp;expire<br>
  &emsp;1 cache inforemation-1<br>
  &emsp;2 cache inforemation-2<br>
    &emsp;&emsp;&emsp;&emsp;.<br>
    &emsp;&emsp;&emsp;&emsp;.<br>
  &emsp;N cache information-N*


## 7. cefsubfile

cefsubfile is a tool that subscribes a file using Reflexive Forwarding. This tool sends Reflexive Interest to cefnetd upon receiving Trigger Interest with the specified URI, thereby retrieving Reflexive Data. After completing content retrieval, it sends Trigger Data to terminate subscription. To exit manually, press Ctrl + C.

`cefsubfile uri [-f output_path] [-s pipeline] [-v_RI valid_algo] [-v_TD valid_algo] [-d config_file_dir] [-p port_num]`

Retrieved content is output as a file named "RNP0x{RNP value}.out" to the path specified with the "-f" option. If the "-f" is omitted, output the file in the current directory. If "-f -" is specified, output to stdout instead of a file.

| Parameter  | Description                                                   |
| ---------- | ------------------------------------------------------------- |
| uri        | URI. This parameter cannot be omitted.                        |
| output_path| Path to output file. When "-" is specified, output to stdout. |
| pipeline   | Specify the number of pipelines when sending Reflexive Interest. <br>Range: 1 <= pipeline <= 10000 (default: 8) |
| valid_alg  | Validation algorithm used for the message. If no validation algorithm specified, validation will not be performed. In this version, validation algorithm must be either rsa-sha256 or crc32c. |

If content was successfully downloaded with cefsubfile, "Complete" is displayed. When "ERROR: Timeout" is displayed, a packet loss has occurred and there are chunks that could not be retrieved. Even though the interest was retransmitted, the content download was interrupted.


## 8. cefpubfile

cefpubfile is a tool used to publish a file using Reflexive Forwarding. The tool first sends a Trigger Interest for the specified URI and RNP to cefnetd. It then encapsulates the specified file into Reflexive Data using the generated RNP. If the file size exceeds a single packet, it is divided into chunks and transmitted with independent Reflexive Data packets. The Reflexive Data is transmitted to cefnetd. The process terminates when Trigger Data for the specified URI and RNP is received from cefnetd. To exit manually, press Ctrl + C.
Note that Content Store must be enabled on the node that executes cefpubfile.

`cefpubfile uri -f path [-r rate] [-b block_size] [-e expiry] [-t cache_time] [-l lifetime] [-m retry_limit] [-z target] [-v_TI valid_algo] [-v_RD valid_algo]`

The "-f path" option specifies the name of the file to be pushed. It is a mandatory parameter. The file name must be provided as a full path; otherwise, cefpubfile uses the specified file located in the current working directory.

| Parameter  | Description                                                   |
| ---------- | ------------------------------------------------------------- |
| uri        | URI. This parameter cannot be omitted.                        |
| path       | File name with path. This parameter cannot be omitted.        |
| rate       | Transfer rate from cefpubfile to cefnetd (Mbps)<br>Range: 0.001 <= rate <= 100000000 (default: 50)<br>You can specify up to three decimal places and ignore values less than three decimal places.  |
| block_size | Max length of the payload of Content Object (Byte)<br>Range: 1 <= block_size <= 65000 (default: 1024)    |
| expiry     | Reflexive Data lifetime (s). (Current time + expiry) is the effective time.<br>Range: 1 <= expiry <= 31536000 (default: 10) |
| cache_time | The number of seconds after which Reflexive Data is cached before it is deleted.<br>Range: 1 <= cache_time <= 31536000 (default: 10) |
| lifetime   | Specify the lifetime (s) of Trigger Interest. <br>Range: 0 <= lifetime <= 64 (default: 3) |
| retry_limit| Maximum number of transmitted Trigger Interests to extend t-PIT lifetime. <br>Range: 0 <= retry_limit <= 65535 (default: unlimited) |
| valid_alg  | Validation algorithm used for the message. If no validation algorithm specified, validation will not be performed. In this version, validation algorithm must be either rsa-sha256 or crc32c. |

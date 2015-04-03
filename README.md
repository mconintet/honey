##Why honey
Sometimes, we don't have a HTTP/HTTPS proxy when we need it. 
However we may have a Socks5 proxy is running at that time. 
So it will be useful if there is a program can wrap the socks5 proxy up to run as a HTTP/HTTPS proxy.
These are why is "honey" here.

##Notes
Since "honey" is a local wrapper, so it doesn't support the mechanism of HTTP/HTTPS proxy authentication.
There is no advanced technique been applied on persistent connections in "honey", just leave them alone, but if either of client
or server close the connection to "honey", "honey" will close the corresponding connections of them at next time when data transmitting.

##Usage

```
Usage of honey:
  -la="": local address, like :5678
  -pwd="": password
  -sa="": server address
  -un="": username
```

There are two ways to use "honey"

1. If you have a remote socks5 server, just run:

```
go run honey.go -la=":5678" -sa="149.174.107.97:1080" -un="honey" -pwd="honey_fly"
```

2. Or maybe you have a SSH account:

```
# open a socks5 tunnel first
ssh -qTfnN -D 7070 root@149.174.107.97

# then use "honey" to wrap the tunnel
go run *.go -la=":5678" -sa="127.0.0.1:7070"
```

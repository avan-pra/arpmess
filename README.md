# arpmess
Modify the default gateway harware address in arp table of other hosts in your network (thus denying them internet access) by performing an arp spoof attack.  

This tool was greatly inspired by [kickthemout](https://github.com/k4m4/kickthemout) from k4m4

# Installation & Run
```
$ make vendor
$ make
```

# Usage
```
Usage: arpmess [OPTION...] 
arpmess -- A kickthemout like rewrite in C

  -f, --nmapflag=-FLAG1 -FLAG2   Add flag to nmap command 
                             WARNING: don't play with this option unless you
                             know what you are doing
  -i, --interface=INTERFACE_NAME   Specify interface to use (ex: eth0)
                             IF_NAMESIZE max
  -n, --netmask=CIDR         Use netmask to look for hosts instead of the
                             network one IN CIDR NOTATION ex: `-n 24` for
                             255.255.255.0
  -p, --packets=PACKETPERMINUTE   Number of packets broadcasted per minute
                             (default: 12)
  -t, --target=IP1,IP2       Target list YET TO BE IMPLEMENTED
  -v, --verbose              Produce verbose output USELESS AS OF NOW
  -?, --help                 Give this help list
      --usage                Give a short usage message
```

# Example
![example usage](/img/example.png)

Please open an issue if you have any problem.  

# TODO
- finish handling -t target options
- handle selection of host
- allow a mitm attack

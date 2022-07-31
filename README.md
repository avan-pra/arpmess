# arpmess
Deny internet access and sniff your local network by performing arp spoofing attacks.  

This tool was greatly inspired by [kickthemout](https://github.com/k4m4/kickthemout) from k4m4

# Installation & Run
```
1 # apt install -y nmap
2 $ make vendor
3 $ make
4 # ./arpmess
```

- Replace `apt install -y` in step 1 by your favourite package manager install line, ie: `nmap` binary must be in path.
- Step 1 and 4 need to be run in a root shell.
- Step 2 is optional (useful to print info about mac vendors).

# Usage
```
Usage: arpmess [OPTION...] 
arpmess -- An arpspoofing software, all in one in C

  -f, --nmapflag=-FLAG1 -FLAG2   Add flag to nmap command 
                             WARNING: don't play with this option unless you
                             know what you are doing
  -i, --interface=INTERFACE_NAME   Specify interface to use ex: `-i eth0`
                             (IF_NAMESIZE max)
  -m, --mode=INTERACTIVE/KICK/SPOOF
                             Defaults to INTERACTIVE, if KICK/SPOOF is
                             selected, -t arguments MUST be specified,
                             ex: `-m KICK`
  -n, --netmask=CIDR         Use netmask to look for hosts instead of the
                             network one IN CIDR NOTATION ex: `-n 24` for
                             255.255.255.0
  -p, --packets=PACKETPERMINUTE   Number of packets broadcasted per minute ex:
                             `-p 24` (default: 12) WARNING: 0 for unlimited,
                             very resource intensive
  -t, --target=IP1,IP2       Target list (comma separated), only found target
                             will be used by the program
                             ex: `-t 192.168.43.10,192.168.43.152`
  -v, --verbose              Produce verbose output USELESS AS OF NOW
  -?, --help                 Give this help list
      --usage                Give a short usage message
```

# Example
![example usage](/img/example.png)

Please open an issue if you have any problem.  

# TODO
- on warning debug message change prompt color to orange and - to ~
- restore mode to restore arp table initial state after attack
- idk give me some ideas

# coscin-app-ryu
CoSciN RYU-Based Controller Using HP Custom Pipelines and OpenFlow 1.3

## The Problem

Genome researchers at Weill Medical transfer huge files, 10 TB in some cases, between the Ithaca
and New York City campuses.  Up until now, this process has been so slow, a week in some cases, that
it's faster to ship data on hard drives via the Cornell Campus-to-Campus bus.

Cornell Information Technologies has installed new fiber pathways between Ithaca and New York
City.  Unfortunately, as you might expect with newly-acquired bandwidth, it has quickly been
saturated with application traffic.  Disaster Recovery Backups, in particular, pour huge numbers
of packets on one fiber for horus at a time.  You don't want your genome transfer to be sharing
that fiber if the other two are idle.

Traditional network solution can't solve the problem adequately because their path
selection processes are too static.  And QoS queues are too heavyweight, especially for 
supporting only a few high-bandwidth customers.  

## SDN Enables WAN Dynamic Path Selection

WAN path selection is a perfect use case for SDN.  The application can be sensitive to
utilization changes and dynamically adjust paths for maximum usage.  Although there is a 
lot of industry buzz around SD-WAN, and there are companies who do nothing but that, we 
wanted to build an inexpensive, fault-tolerant SDN app that does just the required use case.
In the future, this app could be extended to make more complex policy decisions about 
bandwidth, allocating it based on time-of-day, customer, or other criteria.

The solution must also:

 * Work with the existing WAN.  It's not feasible to replace the entire router infrastructure with SDN switches (although it would
 make the app trivial to write!)  
 * Be non-disruptive to the rest of the network.  The genome transfer hosts should not need to be reconfigured. 
 * Coexist with other non-CoSciN traffic.
 
To do this, CIT proposed building Policy Based Routing along alternate fiber.   Each fiber route will be
represented by two different subnets, one on each side of the WAN.  For our testbed network, we 
simulated this with private IP addresses in the 192.168 space:

| Ithaca Real Subnet | Ithaca Virtual Subnets | NYC Virtual Subnets | NYC Real Subnet |
| --- | --- | --- | --- |
| 192.168.56.0/24 | 192.168.156.0/24 | 192.168.157.0/24 | 192.168.57.0/24 |
|  | 192.168.158.0/24 | 192.168.159.0/24 |  |
|  | 192.168.160.0/24 | 192.168.161.0/24 |  |

The virtual subnets, in effect, encode a path choice in them.  Packets always move in a straight line from one
virtual subnet on the Ithaca side to its corresponding virtual subnet on the NYC side.  For example, packets
from 192.168.158.0/24 always go to 192.168.159.0/24, representing virtual path 2.  PBR is used on the routers
to say things like "if the source is 192.168.158.0/24 and the destination is 192.168.159.0/24, use the fiber
going through the Lincoln tunnel"

Each host will continue to have one
"real" IP, the ones they are using now, but will also have three "virtual" IP's, one for each alternate route.
So currently, suppose an Ithaca host 192.168.56.100 wants to send data to an NYC host 192.168.57.100.
It can, instead, send the data to 192.168.161.100 (a synonym for 192.168.57.100), and it will travel along alternate path 3
to get to the same destination host.

However, the Ithaca and NYC hosts don't know about these new virtual IP's.  Furthermore, although you can assign
multiple IP's to a NIC in Linux, most network applications (including Globus GridFTP, their transfer software) get 
confused by this.  It would be much better to rewrite the IP source and destination in the middle of the CoSciN
network, then rewrite it back on the other side.  SDN switches can do this easily.

## The Best Path

Since the SDN switches are going to be rewriting IP's, we can also let it select the path.  So our desintation IP will give a hint to the switch:

 * If the destination is 192.168.57.100, use the "best path"
 * If the desintation is 192.168.157.100, use alternate path 1, no matter what
 * If the desintation is 192.168.159.100, use alternate path 2, no matter what
 * If the desintation is 192.168.161.100, use alternate path 3, no matter what

So by default, without changing anything on the genome servers, all transfers will go over the best path.  But how does
the switch know what the best path is?  That's where our SONIC hosts come in.  

SONIC network cards can measure network utilization in very fine-grained ways.  But for our intitial rollout, we'll be using standard
Intel 10Gb NIC's.  They will simply use Perfmon over communicate over the WAN to an identical SONIC server on the other side.
Let's say these SONIC servers are 192.168.56.200 in Ithaca and 192.168.57.200 in NYC.  Then every five minutes or so, the
Ithaca SONIC server will wake up and do three PERFMON runs: one to 192.168.157.200, one to 192.168.159.200, and one to 192.168.161.200.
This will give relative throughputs for the three alternate paths.  It can then send this data to the Ithaca switch, which 
then selects a best path and uses it for subsequent switching rules.

Note these two SONIC servers act independently, and that's OK.  The best path from Ithaca to NYC might be path 1, but the best
path from NYC to Ithaca might be path 3.  The CoSciN app should not make any assumptions here.  

## HP Switches and IP Rewriting

So CoSciN-bound packets rely on the switches to rewrite its IP addresses.  This is not a standard thing for switches or routers
to do.  Consequently, our HP 5406 switches, by default relegate these actions to software.  Like most OpenFlow switches, HP
switches can perform actions and matching in either hardware-based ASIC's, which are really, really fast, or with a standard
CPU and software, which is flexible bit really slow.

When we first wrote the CoSciN app in Frenetic, using OpenFlow 1.0 and HP's default OpenFlow processing, the performance was 
abysmal.  File transfers ran at 8.5 MB/sec, where we needed around 300 MB/sec for really decent processing.   

Fortunately, the 5406 switches have new, fast functionality to get around this.  It's called the Custom Pipeline mode, and it
allows many more actions and matches to be performed in hardware.  The catches were:

 * It requires OpenFlow 1.3, which Frenetic doesn't yet support
 * It is relatively new functionality, so there might be bugs, edge cases, etc. that we had yet to discover

The Custom Pipeline, despite its name, is fully OpenFlow 1.3 compliant.  By default, the tables match on these fields:

| Table 0 (Hash) | Table 1 (Hash) | Table 2 (Hash) | Table 3 (TCAM) |
| --- | --- | --- | --- |
| VLAN | VLAN | IP Src | Anything |
| Eth Src | Eth Dst | Ip Dst | |
| | | IP Protocol | |
| | | TCP/UDP Src Port | |
| | | TCP/UDP Dst Port | |

Intuitively, this is a pretty standard switch setup.  Tables 0 and 1 handle L2 MAC learning.  Table 2 does NAT or Firewall 
functions.  Table 3 is for any rules that don't fit.

Hash and TCAM tables have different purposes.  Hash tables are larger and faster, but don't support wildcards of any sort.  TCAM
tables are smaller and slightly slower (though still much faster than software), but support a wider range of matches, actions, 
and wildcards to boot.  Fortunately, table 2 supports IP rewriting, so is perfect for our needs.

The custom pipeline is reconfigurable - you can make different tables match different sets of fields - but for CoSciN, the default
is a good choice anyway.

TO BE CONTINUED.

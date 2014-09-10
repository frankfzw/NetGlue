NetGlue
=======
Capture the network traffice and reformat the packets into SCION-like packet

How does it work:

Image there are two NICs on your host, one is a virtual-nic and the default gateway as well. The application will first send packet to the fake virtual one. NetGlue will capture these traffic, and convert to SCION-style packet, and send it from another "real" nic which have a real ID in SCION network. In contrast, the incoming traffic will arrive at the "real" one first. NetGlue will capture these packets, and extract the payload which is a real Ethernet frame, change some message and push it to the virtal one. Then the virtual one will send it to the corresponding application.

In a word, the uplayyer application will never find out this trick. We don't have to modify our app or socket API to make our computer and app compatible with SCION network.

Ideally!

How To Use:

0. install libpcap, you can download the source code from here http://www.tcpdump.org

1. copy the lib folder from source code of SCION-infrastructure_new(I can't upload these codes yet)

2. ./buildLib.sh

3. make

4. ./capture nic1 nic2 direction

Since there is no multi thread in my code, you should run ./capture nic1 nic2 in and ./capture nic1 nic2 out manualy :(

Bugs: If the frame captured is too big, the socket statck will smash. Because I have to add a huge SCION head, another IP header and another Ethernet header. I haven't found out how to split the packet yet.

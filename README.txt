NETCONF Call Home Reference Implementation


Introduction
============

This software distribution contains a reference implementation 
for NETCONF Call Home, using the configuration described in 
draft-ietf-netconf-call-home-17.

The software includes code for both sides of the connection: 

  - the network-element     (written in C)
  - the management-server   (written in Java)

These language choices were selected only because they seemed
most common for this context.  Clients and servers can be
implemented in other languages as needed.




Warning
=======

This implementation uses X.509-based SSH host-keys, as per the
recommendation in draft-ietf-netconf-call-home.  However, the
only Java-based SSH library found supporting X.509 is a commercial
product called "J2SSH Maverick".  For testing purposes, you can
get a free 6-week eval license from their site (the installation
instructions herein describe exactly how to do that).  Further,
while it's for you to decide, the commericial license seems 
reasonably priced and hence not likely an impediment to production
use (disclaimer: I'm not affliated with SSHTOOLS in any way).

If you do NOT care about X.509 certificates, the management-server
code can be changed to use the 100% free "J2SSH" product, the 
predecsessor to the J2SSH Maverick product.  Further, if this 
strategy is taken, there is no need to patch OpenSSH with Roumen 
Petrov's patch, as your system's `sshd` would be then be sufficient.
Of course, you would then have to solve how to authenticate the 
device's host key without using a CA...     


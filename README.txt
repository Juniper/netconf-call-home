NETCONF Call-Home Reference Implementation


Introduction
============

This software distribution contains a reference implementation 
for NETCONF Call-Home, using the configuration described in 
draft-kwatsen-netconf-server-01.

The software includes code for both sides of the connection: 

  - the network-element     (written in C)
  - the management-server   (written in Java)

These language choices were selected only because they seemed
most common for this context.  Clients and servers can be
implemented in other languages as needed.




Warning
=======

This implementation uses X.509-based SSH host-keys, as per the
recommendation in draft-ietf-netconf-reverse-ssh.  However, the
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
Of course, you have to solve how to authenticate the device's
hostkey without using a CA.     


===== KENT - IS THE BELOW STILL TRUE?
One final comment regarding X.509 certificates.  As of the time of
this writing, both J2SSH Maverick and Roumen Petrov's OpenSSH patch
implement draft-saarenmaa-ssh-x509-00 (not RFC 6187).  That said,
when asked, both implementors said that supporting RFC 6187 was on
their TODO lists.  If your deployments require complete standards
compliance, waiting for these two packages to implement RFC 6187 is
likely the fastest option.  The good news is that this reference
implementation should be uneffected by the update to those packages.



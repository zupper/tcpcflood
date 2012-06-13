/* TCP Connect Flood                                                     */
/* Author: Dimitar Pavlov - dimitar at shadez dot info                   */
/*                                                                       */
/* This code is distributed under the GPL License. For more info check:  */
/* http://www.gnu.org/copyleft/gpl.html                                  */

tcpcflood
=========

-- TCP Established Flood Tool --

This is a proof of concept tool, used to perform TCP Established floods. This
tool was created as part of a research project looking into the feasibility of
a TCP Established attack.

For more information about the TCP Established attack, please refer to the
report for the project (report.pdf).

For more information about the tool, you will have to refer to the source code
itself, as I don't have the time to create a proper documentation right now.
However, the code is simple enough for programmers to understand (also quite
messy, but if you feel like contributing, communicate with me :)


-- Building --

The only prerequisite for compiing to code is libpcap, as that is used for
capturing the responses indiscriminately.

Compilation should be performed as follows:

$ make


-- Running the tool --

For the tool to work, you need to set up a firewall rule, which blocks the used
outgoing ports on the attacking host. This is needed, as the tool uses a raw
socket for transmitting packets and libpcap for capturing the responses. Using
a raw socket means that the kernel doesn't know about our sent packets and will
reply with a TCP RST when the SYN-ACK arrives (which is bad for our attack).

Currently, the tool uses ports 20000:65535 (hardcoded) as the source port for
generated packets.

Setting up the rule can be done as follows:

iptables -A INPUT -p tcp --destination-port 20000:65535 -j DROP


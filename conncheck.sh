#!/bin/sh
# This script is called by mrtg with the addresses configured in the Target field of the 
# mrtg configuration. For example:
#
# Target[jbytes]:  `/home/pi/traffic/conncheck.sh 192.168.2.5`
# or 
# Target[jbytes]:  `/home/pi/traffic/conncheck.sh Connections
# 
# It is called multiple in times and relies on the get_ip_conntrack.sh script
# to implement locking so that the data from the dd-wrt router is only gotten once 
# and does not overwrite itself. This script searches the summarized /proc/net/ip_conntrack 
# and outputs the count of input and output connections for the individual IP address 
# or if called with "Connections" gets the connection total for the router out of the 
# processed connection file.
#
# ============================= 
# mod: 04/30/14 - added to comments 
host=$1 

#Variables that are used in the "getter script " 
# CONTRACK_RAW=/tmp/ipconntrack.raw
CONTRACK_COOKED=/tmp/ipconntrack.out

#go get the file and build the output if needed 
/home/pi/traffic/get_ip_conntrack.sh

# now get the connections for this ip address 
### this need to check if a connection count fo a non esistant IP was found" 
grep $host $CONTRACK_COOKED | awk '{print $2 ;print $3 }'


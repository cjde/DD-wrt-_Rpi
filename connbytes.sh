#!/bin/sh
# This script is called by mrtg with the addresses configured in the Target field of the 
# mrtg configuration. For example:
#
# Target[jbytes]:  `/home/pi/traffic/connbytes.sh 192.168.2.5`
# 
# This script must be called after the ipconntrack.raw is pulled from the router and processed by the 
# CountConnections perl script. In that file are Summation lines indicating the total bytes 
# for all the open sessions and the delta bytes since last time the data was pulled from the router.
# This is the two values returened for the requested IPaddress. The Summary likes look like:
#
# Summary 192.168.2.13:cjdwork 	 Total  6609466 / 8129086  Delta  42081 / 47247
# Summary 192.168.2.15:CPhone 	 Total  8095 / 19619  Delta  3079 / 12213
#
# The perl scrip that is building the summary writes to /tmp/CountConnection.tmp and when 
# the task is complete it renames it to /tmp/CountConnection.out. Therefor if the 
# /tmp/CountConnection.tmp file exists then it is still processin and this script needs to
# wait for it to get removed before reading the output file  /tmp/CountConnection.tmp 
#
# ============================= 
# mod: 04/30/14 - added to comments 
# mod: 05/06/14 - Implements wait loop to get current data 
#
tmpoutfilename="/tmp/CountConnection.tmp";
outfilename="/tmp/CountConnection.out";

# wait for the processing to complete (if needed )
while [ -f $tmpoutfilename ] ; do sleep 5; done
if [ -f $outfilename ]  
then 

   # Line in the connections file that we are looking for :
   #   1             2            3         4    5   6      7       8     9   10
   #Summary 192.168.2.5:Jhdbig   Total  1802196 / 3967857  Delta  545706 / 658847
   # Divide by 5 because this is accumulated on the 5 minute interval.
   grep "Summary $1" $outfilename | awk 'BEGIN{cinterval=5};{print int(($8/cinterval)+0.5); print int(($10/cinterval)+0.5)}'
else 
   echo  "Lock file does not exist and neither does the data file...  must be starting up"
fi

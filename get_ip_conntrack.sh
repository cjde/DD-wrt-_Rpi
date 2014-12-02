#!/bin/sh -x 
# This script pulls the ip_conntrack from the router no more than once a minute.
# it checks the creation time on the file and if it was made in the last minute then it does not 
# get it again. It builds the /tmp/ipconntrack.out which contains the summary of the connections both
# inbound and outbound for each IP address that was in the /proc/net/ip_conntrack on the router.
#
# Note that this awk script requires gawk 1:4.0.1+dfsg-2.1
#
# ============================= 
# mod: 12/18/13 - gets the default router from netstat -rn 
# mod: 04/30/14 - added to comments  
#  
# 

RTR=`netstat -rn| awk '/^0.0.0.0/{print $2}'`

CONTRACK_TMP=/tmp/ipconntrack.tmp 
CONTRACK_RAW=/tmp/ipconntrack.raw  
DNSLOG_RAW=/tmp/dnslog.raw 
CONTRACK_COOKED=/tmp/ipconntrack.out 

# get the current time so we can get the file if it is older than a minute 
now=`date +%b%d_%H%M` 

# make sure the file is there otherwize you cant check the date! 
if [ ! -e $CONTRACK_RAW ] 
then
   lastcreate="firstime"
else 
   lastcreate=`ls -l --time-style=+%b%d_%H%M $CONTRACK_RAW | awk '{ print $6}'`
fi 

if [ $now != $lastcreate ]
then 
    if [ -f /tmp/getit.lock ] 
    then 
       # already getting it! just wait for the other script that made the lock to finish 
       sleep 15
    else 
       echo $$ $now >> /tmp/getit.lock 
       # Go get the file ( scp does not work !!) 
       ssh -q root@$RTR cat /proc/net/ip_conntrack > $CONTRACK_TMP 
       ssh -q root@$RTR cat /tmp/root/dnslog > $DNSLOG_RAW 
       # clear the DNS log file the we just pulled down back on the router
       ssh  root@$RTR ' > /tmp/root/dnslog' 2>/dev/null &  
       mv  $CONTRACK_TMP $CONTRACK_RAW 
       rm /tmp/getit.lock  
	 fi 

    # now that the file is here, we can process it into the number of ASSURED or Stale ( not ASSURED )

    # look for the address in the 5th location 
	# If the String ASSURED is present then the session as active ( count the active session ) ( these are TCP connections )
	# If the String UNREPLIED is present then the session is stale ( it will time out soon ( count the stale  session ) 
	# also keep track of how many total active and stale connections there are ... 
	# After we read the file then print out the total active and stale connections and 
	# the IPs and count of and active and stale socket  
	# Notice we add 0 to everything so that awk will convert the string "" ( in session[x][1] incase it does not get set ) 
	# to the value 0 
	
    cat $CONTRACK_RAW | \
       awk '\
       $5 ~ /src=/{host=substr($5,5,25) };
       /ASSURED/{  session[host][1]=session[host][1]+1; tot_act=tot_act + 1 };
       /UNREPLIED/{session[host][2]=session[host][2]+1; tot_stale=tot_stale + 1};
       END { 	printf("%-16s %3s %3s\n","Connections", tot_act, tot_stale);
				for (x in session) {
				session[x][1]=session[x][1] + 0  
				session[x][2]=session[x][2] + 0 
				printf("%-16s %3s %3s\n", x, session[x][1], session[x][2])
			}
		}
       ' > $CONTRACK_COOKED
fi 


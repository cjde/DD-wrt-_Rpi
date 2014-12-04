#!/usr/bin/perl

use strict;
use warnings;
use Data::Dumper;

# CONTRACK_RAW=/tmp/ipconntrack.raw
# CONTRACK_COOKED=/tmp/ipconntrack.out


my $dir   = '/tmp';
my $file ;
my $file2 = "$dir/ipconntrack.raw";
my $timestamp;
my $timestamp_old = 0;
my %sessions  = ();

while (1) {
#	opendir(DIR, $dir) or die $!;
#	while ( $file = readdir(DIR)) {

	# find the mofification time of the input file 
	$timestamp = (stat($file2))[9];

	# has the file been changed ? 
	if ( $timestamp eq $timestamp_old ){
		# file is unchanged, ignore it 
		sleep 30;
		next;
	}
	else {
		# file is updated, save the update time and process the file 
		$timestamp_old = $timestamp;
	}	


		#from web page ... format is
		#prot_name       1 Protocol name.
		#prot_num        2 Protocol number. (6 = TCP. 17 = UDP.)
		#expire          3 Seconds until this entry expires.
		#tcp_state       4 TCP only: TCP connection state.
		#src_orig        5 Source address of ¦original¦-side packets (packets from the side that initiated the connection).
		#des_orig        6 Destination address of original-side packets.
		#src_port_orig   7 Source port of original-side packets.
		#dst_port_orig   8 Destination port of original-side packets.
		#UNREPLIED       9 if this connection has not seen traffic in both directions. Otherwise not present.
		#sec_reply      10 Source address of ¦reply¦-side packets (packets from the side that received the connection).
		#dst_reply      11 Destination address of reply-side packets.
		#src_port_reply 12 Source port of reply-side packets.
		#dst_port_reply 13 Destination port of reply-side packets.
		#ASSURED        14 if this connection has seen traffic in both directions (for UDP) or 
		#                  an ACK in an ESTABLISHED connection (for TCP). Otherwise not present.
		#use            15 Use count of this connection structure.

		#Actual format is:
		# 1 tcp |  udp                                 /^tcp\s+
		# 2 6 | 17                                     \d+\s+
		# 3 52                                         \d+\s+
		# 4 TIME_WAIT ESTABLISHED SYN_SENT CLOSE_WAIT  \w+\s
		# 5 src=192.168.2.20                           src=(\d+\.\d+\.\d+.\d+)\s+
		# 6 dst=192.168.2.99                           dst=(\d+\.\d+\.\d+.\d+)\s+
		# 7 sport=57488                                sport=(\d+)\s
		# 8 dport=80                                   dport=(\d+)\s
		# 9 packets=6                                  packets=(\d+)\s
		# 10 bytes=759                                 bytes=(\d+)\s
		# [UNREPLIED]                                  .*
		# 11 src=192.168.2.99                          src=\d+\.\d+\.\d+.\d+\s+
		# 12 dst=192.168.2.20                          dst=\d+\.\d+\.\d+.\d+\s+
		# 13 sport=80                                  sport=\d+\s
		# 14 dport=57488                               dport=\d+\s
		# 15 packets=7                                 packets=\d+\s
		# 16 bytes=3492                                bytes=(\d+)\s
		# 17 [ASSURED]                                 .*/
		# 18 mark=0                                    mark=\d+\s+
		# 19 use=2                                     use=\d+\s+


		my $srcip;
		my $desip;
		my $sport;
		my $dport;
		my $sbytes;
		my $dbytes;
			
		print "$file2 : TIME STAMP --------- $timestamp ---------\n";
		open my $info, $file2 or die "Could not open $file2: $!";
			
		#pul in the entire ip_connecions file
		while( my $line = <$info>)  {
			chomp $line;
			if ($line =~ m/^tcp\s+\d+\s+\d+\s+\w+\ssrc=(\d+\.\d+\.\d+.\d+)\s+dst=(\d+\.\d+\.\d+.\d+)\s+sport=(\d+)\sdport=(\d+)\spackets=\d+\sbytes=(\d+)\s.*src=\d+\.\d+\.\d+.\d+\s+dst=\d+\.\d+\.\d+.\d+\s+sport=\d+\sdport=\d+\spackets=\d+\sbytes=(\d+)\s.*mark=\d+\s+use=\d+/ ) {

				$srcip = $1;
				$desip = $2;
				$sport = $3;
				$dport = $4;
				$sbytes= $5;
				$dbytes = $6 ;
				#print "$sport:$dport\t $srcip $desip $sbytes $dbytes\n";
	
				$sessions{ $srcip }{ $desip }{"$sport:$dport"}{count} += 1;
				# byte count for session
				$sessions{ $srcip }{ $desip }{"$sport:$dport"}{sbytes} = $sbytes;
				$sessions{ $srcip }{ $desip }{"$sport:$dport"}{dbytes} = $dbytes;
				$sessions{ $srcip }{ $desip }{"$sport:$dport"}{time}   = $timestamp;
			}
		}
		#print Dumper( \%sessions );

		open OUTFILE, ">", "/tmp/CountConnection.out"  or die "Error opening /tmp/CountConnection.out: $!";
		
		# Now that the ip_connections is linked into the existing connetions, Compare what we have
		# If timestamp on the session not the one we just put in then the connection was dropped or expired

		foreach my $srcip ( sort keys %sessions )  {
			my %hoh = %{$sessions{$srcip}};
			# keep track of bytes for all traffic from this source
			my $tot_sbytes = 0;
			my $tot_dbytes = 0;
			# for every destination that this source talked, count up the source and dest bytes
			foreach my $desip (sort keys %hoh ) {
				#print "   connected to $desip \n";
				# Count up the in and out bytes for active and closed sessions for each destination
				my $sbytes_act = 0;
				my $dbytes_act = 0;
				my $sbytes_cls = 0;
				my $dbytes_cls = 0;

				my %hohoh = %{$hoh{$desip}};
				# for evey session of this destination accumulate the in and out bytes
				foreach my $ports (sort keys %hohoh ) {
					my $c = $hohoh{$ports}{count};
					my $t = $hohoh{$ports}{time};
					my $sb = $hohoh{$ports}{sbytes};
					my $db = $hohoh{$ports}{dbytes};

					if ($t ne $timestamp ){
						# time stamp for this connection has not been updated,it has not
						# seen any triffic since the last tick
						#print "      ports $ports expired byte in/out $sb $db \n";
						$hohoh{$ports}{count} = 0;
						#print "$ srcip -> $desip $ports in $sb out $db \n";

						# count up the in out bytes for this destination that is now closed
						$sbytes_cls += $sb;
						$dbytes_cls += $db;

						# delete this expired session
						delete $sessions{$srcip}{$desip}{$ports};
					}
					else {
						# time stamp is current, session is active
						$sbytes_act += $sb;
						$dbytes_act += $db;
						#is this a new connection ?
	#                	if ( $c eq 1 ) {
	#                       print "      ports $ports new  \n";
	#                   }
	#                   else {
	#                     # time stamp is current  and we added bytes to the session
	#                     print "      ports $ports total byte in/out $sb $db \n";
	#                   }
					}

				}
				#ok we have counted all the active and closed sessoion for this dest for this time stamp
				### print  "$srcip -> $desip \tActive I/O: $sbytes_act/$dbytes_act \tClosed I/O: $sbytes_cls/$dbytes_cls\n";
				# delete the dest ip if there are no more sockets attached
				my $hs = keys( %{$sessions{$srcip}{$desip}} ) ;
				if ( $hs eq 0 ) {
					delete $sessions{$srcip}{$desip};
				}
				# add up all the bytes for this destination ipaddress
				$tot_sbytes += $sbytes_act + $sbytes_cls;
				$tot_dbytes += $dbytes_act + $dbytes_cls;
			}
			# Output the total bytes for this source to all of its destinations
			print  "$srcip \tTotal I/O: $tot_sbytes $tot_dbytes\n";
            print  OUTFILE "$srcip \tTotal I/O: $tot_sbytes $tot_dbytes\n";
		}
   close OUTFILE;
#	}
#	# print time;
#	closedir(DIR);
 #   sleep 30;
}
exit 0;

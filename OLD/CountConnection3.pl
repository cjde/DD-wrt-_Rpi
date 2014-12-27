#!/usr/bin/perl
# version 2 
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
my $outfilename = "$dir/CountConnection.out";
my %sessions  = ();

while (1) {
	# find the mofification time of the input file 
	$timestamp = (stat($file2))[9];

	# has the file been changed ? 
	if ( $timestamp eq $timestamp_old ){
		# file is unchanged, ignore it 
		sleep 30;
		next;
	}
	# file is updated, save the update time and process the file 
	$timestamp_old = $timestamp;

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
		#  1 tcp |  udp                                 /^tcp\s+
		#  2 6 | 17                                     \d+\s+
		#  3 52                                         \d+\s+
		#   4 TIME_WAIT ESTABLISHED SYN_SENT CLOSE_WAIT  \w+\s
		#  5 src=192.168.2.20                           src=(\d+\.\d+\.\d+.\d+)\s+   
		#  6 dst=192.168.2.99                           dst=(\d+\.\d+\.\d+.\d+)\s+
		#  7 sport=57488                                sport=(\d+)\s
		#  8 dport=80                                   dport=(\d+)\s
		#  9 packets=6                                  packets=(\d+)\s
		#  10 bytes=759                                 bytes=(\d+)\s
		#   [UNREPLIED]                                  .*
		#  11 src=192.168.2.99                          src=(\d+\.\d+\.\d+.\d+)\s+
		#  12 dst=192.168.2.20                          dst=(\d+\.\d+\.\d+.\d+\)s+
		#  13 sport=80                                  sport=(\d+)\s
		#  14 dport=57488                               dport=(\d+)\s
		#  15 packets=7                                 packets=\d+\s
		#  16 bytes=3492                                bytes=(\d+)\s
		#  17 [ASSURED]                                 .*/
		#  18 mark=0                                    mark=\d+\s+
		#  19 use=2                                     use=\d+\s+

		# sometime however the line looks like a inbound traffic and we get this instead ... So rearrange so that we ca log 
		# trafic inbound for that server. 
		# tcp 6 2 SYN_RECV src=74.86.158.107 dst=192.168.1.200 sport=21902 dport=80 packets=1 bytes=52 src=192.168.2.30 dst=74.86.158.107 sport=80 dport=21902 packets=3 bytes=156 mark=0 use=2

		my $state;
		my $srcip;
		my $desip;
		my $sport;
		my $dport;
		my $sbytes;
		my $srcip2;
		my $desip2;
		my $sport2;
		my $dport2;
		my $dbytes;
			
		# now open the ipconntrack file that has all the details for each session ( Src(x)-> dest(y)->session(x)-> tracffic 
		open my $info, $file2 or die "Could not open $file2: $!";

		# and the output file for  the MRTG scripts to look at 
		open OUTFILE, ">", $outfilename or die "Error opening $outfilename: $!";
		
		print "$file2 : TIME STAMP --------- $timestamp ---------\n";
		print  OUTFILE " --------- $timestamp ", scalar localtime( $timestamp ), "---------\n";
		
		#pul in the entire ip_connecions file
		while( my $line = <$info>)  {
			chomp $line;
			if ($line =~ m/^tcp\s+\d+\s+\d+\s+(\w+)\s+src=(\d+\.\d+\.\d+.\d+)\s+dst=(\d+\.\d+\.\d+.\d+)\s+sport=(\d+)\sdport=(\d+)\spackets=\d+\s+bytes=(\d+)			\s.*src=(\d+\.\d+\.\d+.\d+)\s+dst=(\d+\.\d+\.\d+.\d+)\s+sport=(\d+)\s+dport=(\d+)\s+packets=\d+\s+bytes=(\d+)\s.*mark=\d+\s+use=\d+/ ) {
				$state = $1;
				$srcip = $2;
				$desip = $3;
				$sport = $4;
				$dport = $5;
				$sbytes= $6;
				$srcip2 = $7;
				$desip2 = $8;
				$sport2 = $9;
				$dport2 = $10;				
				$dbytes = $11;
				# check id the srcip is in our subnet and if not then switch it around ( see note above ) 
				if ( $srcip !~ /192.168.2./ ) { 
					my $t1 = $srcip;
					my $t2 = $desip;
					my $t3 = $sport;
					my $t4 = $dport;
					my $t5 = $sbytes; 
					
					$srcip = $srcip2;
					$desip = $desip2;
					$sport = $sport2;
					$dport = $dport2;
					$sbytes= $dbytes;
					
					$srcip2 = $t1;
					$desip2 = $t2;
					$sport2 = $t3;
					$dport2 = $t4;
					$dbytes = $t5;
					print "Aha! \n $line"; 
				}			
					
				#print "$sport:$dport\t $srcip $desip $sbytes $dbytes\n";

				$sessions{ $srcip }{ $desip }{"$sport:$dport"}{count} += 1;
                  
				# byte count for session
				# the count here is some times static, the timeout could be an hour and this value will stay the same 
				# is still open with the same value time after time... 
 				# instead of saving the raw value we are calculatin the difference, 
 
				# if we have already collected ths session then compute the difference in bytes that have been observed  
				if ( exists $sessions{ $srcip }{ $desip }{"$sport:$dport"}{time}) {
                      $sessions{ $srcip }{ $desip }{"$sport:$dport"}{sbytes} = $sbytes - $sessions{ $srcip }{ $desip }{"$sport:$dport"}{sbytes};
                      $sessions{ $srcip }{ $desip }{"$sport:$dport"}{dbytes} = $dbytes - $sessions{ $srcip }{ $desip }{"$sport:$dport"}{dbytes};
				}
				else { 
                      $sessions{ $srcip }{ $desip }{"$sport:$dport"}{sbytes} = $sbytes;
                      $sessions{ $srcip }{ $desip }{"$sport:$dport"}{dbytes} = $dbytes;
				}
				# total bytes collected for this session 
				$sessions{ $srcip }{ $desip }{"$sport:$dport"}{Tsbytes} = $sbytes;
				$sessions{ $srcip }{ $desip }{"$sport:$dport"}{Tdbytes} = $dbytes;
				$sessions{ $srcip }{ $desip }{"$sport:$dport"}{time}    = $timestamp;
			}
		}
		

		#print Dumper( \%sessions );


		
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

					my $c  = $hohoh{$ports}{count};
					my $t  = $hohoh{$ports}{time};
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
						#### print "      session: ", $ports, " expired in/out: ",$sessions{ $srcip }{ $desip }{$ports}{Tsbytes}," ",$sessions{ $srcip }{ $desip }{$ports}{Tdbytes}, "\n";
						delete $sessions{$srcip}{$desip}{$ports};
					}
					else {
						# time stamp is current, session is active
						$sbytes_act += $sb;
						$dbytes_act += $db;

						#is this a new connection ?
						if ( $c eq 1 ) {
							#print "      ports $ports new bytes in/out $sb $db\n";
						}
						else {
							# time stamp is current  and we added bytes to the session
							#print "      ports $ports adding bytes in/out $sb $db \n";
						}
					}

				}
				#ok we have counted all the active and closed sessoion for this dest for this time stamp
				print  "$srcip -> $desip \tActive I/O: $sbytes_act/$dbytes_act \tClosed I/O: $sbytes_cls/$dbytes_cls\n";
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

			print  OUTFILE "$srcip \tTotal I/O: $tot_sbytes $tot_dbytes\n";
			print  "$srcip \tTotal I/O: $tot_sbytes $tot_dbytes\n";

 		}

   close OUTFILE;
}
exit 0;

#!/usr/bin/perl
# version 4 
use strict;
use warnings;
use Data::Dumper;
#BEGIN { push @INC, '.';}

require "./LoadAndResolve7.pl";


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
		sleep 10;
		next;
	}
    my $t1=$timestamp; 
	my $t2=$timestamp_old; 
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
		
		#tcp      6 40 SYN_RECV src=176.31.224.26 dst=192.168.1.200 sport=35089 dport=80 packets=1 bytes=40    src=192.168.2.30 dst=176.31.224.26 sport=80 dport=35089 packets=1 bytes=44 mark=0 use=2 
		#tcp      6 2 SYN_RECV src=74.86.158.107 dst=192.168.1.200 sport=21902 dport=80 packets=1 bytes=52     src=192.168.2.30 dst=74.86.158.107 sport=80 dport=21902 packets=3 bytes=156 mark=0 use=2
		#tcp      6 28 SYN_SENT src=192.168.2.30 dst=173.194.70.27 sport=41722 dport=25 packets=6 bytes=360 [UNREPLIED] src=173.194.70.27 dst=192.168.1.200 sport=25 dport=41722 packets=0 bytes=0 mark=0 use=2
		#tcp      6 89 TIME_WAIT src=66.249.74.8 dst=192.168.1.200 sport=64884 dport=80 packets=16 bytes=12    src=192.168.2.30 dst=66.249.74.8 sport=80 dport=64884 packets=14 bytes=15385 [ASSURED] mark=0 use=2
		#tcp      6 87 TIME_WAIT src=66.249.74.8 dst=192.168.1.200 sport=64078 dport=80 packets=6 bytes=585    src=192.168.2.30 dst=66.249.74.8 sport=80 dport=64078 packets=4 bytes=602 [ASSURED] mark=0 use=2
        # 111      2 33 444444444 555555555555555 66666666666666666 77777777777 88888888 999999999 101010101 .* 1111111111111111 1212121212121212 13131313 1414141414 151515151 161616161 171717171
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
		# 17 [ASSURED]                                 .*
		# 18 mark=0                                    mark=\d+\s+
		# 19 use=2                                     use=\d+\s+
		# 
		# an interesting point has been uncovered ... The origin_bytes and the reply bytes are values that always increase for a particular session. 
		# so if thre is one session open its origin bytes and reply bytes go up untill it is closed thne it returns to zero
		# if the session does not expire then tne byte count is the same for multiple samples. 
		# On the other hand if there are multiple sessions ( most likely ) then at any given time the amount of traffic at that instant is the delta of 
		# the origin and reply traffic since the last sample, summed together. This implies that we with multiple sessions in use we cannot report just this
		# this total amount per source/dest but should calc the delta origin, delta reply, and save the total origin and total reply
		
		my ($proto_name, $protonum,$expire, $tcp_state, $src_origin, $des_origin, $src_port_origin, $des_port_origin);
		my ($origin_packet, $origin_bytes, $src_reply, $des_reply, $src_port_reply, $des_port_reply, $reply_packet, $reply_bytes);



		my $state;
		my $srcip;
		my $desip;
		my $sport;
		my $dport;
		my $obytes;
		my $rbytes;
			
		# now open the ipconntrack file that has all the details for each session ( Src(x)-> dest(y)->session(x)-> tracffic 
		open my $info, $file2 or die "Could not open $file2: $!";

		# an the output file for  the MRTG scripts to look at 
		open OUTFILE, ">", $outfilename or die "Error opening $outfilename: $!";
		
		print  " --------- $timestamp ", scalar localtime( $timestamp ), "---- ts_old $t2-----\n";
		print  OUTFILE " --------- $timestamp ", scalar localtime( $timestamp ), "----ts_old $t2-----\n";
		
		#pul in the entire ip_connecions file
		while( my $line = <$info>)  {
			chomp $line;
			if ($line =~m/(^tcp)\s+(\d+)\s+(\d+)\s+(\w+)\s+src=(\d+\.\d+\.\d+.\d+)\s+dst=(\d+\.\d+\.\d+.\d+)\s+sport=(\d+)\sdport=(\d+)\spackets=(\d+)\s+bytes=(\d+)\s.*src=(\d+\.\d+\.\d+.\d+)\s+dst=(\d+\.\d+\.\d+.\d+)\s+sport=(\d+)\s+dport=(\d+)\s+packets=(\d+)\s+bytes=(\d+)\s.*mark=\d+\s+use=\d+/ ) {
				$proto_name		=$1;				$protonum		=$2;
				$expire			=$3;				$tcp_state		=$4;
				$src_origin		=$5;				$des_origin		=$6;
				$src_port_origin=$7;				$des_port_origin=$8;
				$origin_packet	=$9;				$origin_bytes	=$10;
				$src_reply		=$11;				$des_reply		=$12;
				$src_port_reply	=$13;				$des_port_reply	=$14;
				$reply_packet	=$15;				$reply_bytes	=$16;
				#print "proto_name, protonum, expire, tcp_state,  src_origin,  des_origin,  src_port_origin, des_port_origin \n";
				#print "$proto_name, $protonum,$expire, $tcp_state, $src_origin, $des_origin, $src_port_origin, $des_port_origin \n";
				#print "origin_packet, origin_bytes, src_reply, des_reply, src_port_reply, des_port_reply, reply_packet, reply_bytes\n";
				#print "$origin_packet, $origin_bytes, $src_reply, $des_reply, $src_port_reply, $des_port_reply, $reply_packet, $reply_bytes\n";
				
				$state = $tcp_state;
				$srcip = $src_origin;
				$desip = $des_origin;
				$sport = $src_port_origin;
				$dport = $des_port_origin;
				$obytes= $origin_bytes;
				$rbytes= $reply_bytes;
				#print "$sport:$dport\t $srcip $desip $sbytes $dbytes\n";
                  
				# byte count for session
				# the count here is some times static, the timeout could be an hour and this value will stay the same 
				# is still open with the same value time after time... 
 				# instead of saving the raw value we are calculatin the difference, 
 
				# if we have already collected ths session then compute the difference in bytes that have been observed  
				if ( exists $sessions{ $srcip }{ $desip }{"$sport:$dport"}{time}) {
					my $o_T_bytes = $sessions{ $srcip }{ $desip }{"$sport:$dport"}{o_T_bytes};
					my $r_T_bytes = $sessions{ $srcip }{ $desip }{"$sport:$dport"}{r_T_bytes};
					  
					# compute delta from last time 
					$sessions{ $srcip }{ $desip }{"$sport:$dport"}{o_delta_bytes} = $obytes - $o_T_bytes;
					$sessions{ $srcip }{ $desip }{"$sport:$dport"}{r_delta_bytes} = $rbytes - $r_T_bytes;
					  
					 # save the total bytes originated and replied for this session
					$sessions{ $srcip }{ $desip }{"$sport:$dport"}{o_T_bytes} = $obytes;
					$sessions{ $srcip }{ $desip }{"$sport:$dport"}{r_T_bytes} = $rbytes;
					  
				}
				else { 
					# this is a new session so save total bytes seen and the compute the delta, 
					# which for the first time will be the same as the total !
					$sessions{ $srcip }{ $desip }{"$sport:$dport"}{o_T_bytes} = $obytes;
					$sessions{ $srcip }{ $desip }{"$sport:$dport"}{r_T_bytes} = $rbytes;
					$sessions{ $srcip }{ $desip }{"$sport:$dport"}{o_delta_bytes} = $obytes;
					$sessions{ $srcip }{ $desip }{"$sport:$dport"}{r_delta_bytes} = $rbytes;

				}
				$sessions{ $srcip }{ $desip }{"$sport:$dport"}{time}    = $timestamp;
			}
		}
		

		#print Dumper( \%sessions );
		
		# go read up all the lates DNS records that were made duringthe last interval 
		LoadNames(); 
		print " resolving 98.136.166.106", ResolveIP( "98.136.166.106"), "\n";
		
		# Now that the ip_connections is linked into the existing connetions, Compare what we have
		# If timestamp on the session not the one we just put in then the connection was dropped or expired

		foreach my $srcip ( sort keys %sessions )  {
			# for every destination that this source talked, count up the origin  and reply bytes
			$sessions{ $srcip }{o_delta} = 0;
			$sessions{ $srcip }{r_delta} = 0;
			# this is total bytes for this Source for this instance in time 
			$sessions{ $srcip }{o_T_bytes} = 0;
			$sessions{ $srcip }{r_T_bytes} = 0;
			
			my $srcname = ResolveIP($srcip);
			print OUTFILE "Start $srcip / $srcname  \n";			
			print "Start $srcip / $srcname  \n";			
			my %hoh = %{$sessions{$srcip}};
			foreach my $desip (sort keys %hoh ) {
				# skip the accumulators 
				next if $desip =~ /o_delta/;
				next if $desip =~ /r_delta/;
				next if $desip =~ /o_T_bytes/;
				next if $desip =~ /r_T_bytes/;
			
				my $desname = ResolveIP($desip); 
				#print " $srcname connected to $desname \n";
				
				# for evey session of this destination accumulate the Delta origin and reply bytes
				# this is made up of two parts, the delta for the closed sessions ( which need to be removed ) 
				# PLUS the delta of the active sessions
				$sessions{ $srcip }{ $desip }{o_delta} = 0;
				$sessions{ $srcip }{ $desip }{r_delta} = 0;				
				$sessions{ $srcip }{ $desip }{o_T_bytes} = 0;
				$sessions{ $srcip }{ $desip }{r_T_bytes} = 0;
				
				my %hohoh = %{$hoh{$desip}};
				foreach my $ports (sort keys %hohoh ) {
					# skip the accumulators 
					next if $ports =~ /o_delta/;
					next if $ports =~ /r_delta/;
					next if $ports =~ /o_T_bytes/;
					next if $ports =~ /r_T_bytes/;


					my $sb = $hohoh{$ports}{o_T_bytes};
					my $db = $hohoh{$ports}{r_T_bytes};
					
					# accumulate the bytes for this dest IP for all the sessions 
					$sessions{ $srcip }{ $desip }{o_T_bytes} += $sb; 
					$sessions{ $srcip }{ $desip }{r_T_bytes} += $db; 
					
					# if time stamp for this connection has not been updated, that indicats that the 
					# last update did not have this session listed so it must have timeed out and closed 
					# We really cant determine the delta because there is no next sample for this session 
					# Bsides this last delta was used it the last sample report for this session 

					my $t = $hohoh{$ports}{time};
					
					if ($t ne $timestamp ){
						#print  OUTFILE "		Session Expired $desname $ports TOTAL byte previously reported $sb ", " / "," $db \n";
						#print  "		Session Expired $desname \n";
						delete $sessions{$srcip}{$desip}{$ports};
					}
					else {
						# time stamp is current, session is active ADD in the delta from this session to the 
						# total delta count for this destination ;						 
						$sessions{ $srcip }{ $desip }{o_delta} += $sessions{ $srcip }{ $desip }{$ports}{o_delta_bytes};
						$sessions{ $srcip }{ $desip }{r_delta} += $sessions{ $srcip }{ $desip }{$ports}{r_delta_bytes};
						print "$srcname ",$sessions{ $srcip }{ $desip }{o_delta}, " / $desname ", $sessions{ $srcip }{ $desip }{r_delta}, "\n";
					}
				}

				#Ok we have accumulated the delta for all the active sessions for this dest for this time stamp
				# before we work on the next destination add this delta to the accumulated delta for the oigin and reply byte count 
				# for the source addres   
				$sessions{ $srcip }{o_delta} += $sessions{ $srcip }{ $desip }{o_delta};
				$sessions{ $srcip }{r_delta} += $sessions{ $srcip }{ $desip }{r_delta};
				$sessions{ $srcip }{o_T_bytes} += $sessions{ $srcip }{ $desip }{o_T_bytes};
				$sessions{ $srcip }{r_T_bytes} += $sessions{ $srcip }{ $desip }{r_T_bytes};
				
				# total bytes for this dest 
				print  OUTFILE "	Reply $srcname / $desname \tTotal \t",$sessions{ $srcip }{ $desip }{o_T_bytes}, " / ", $sessions{ $srcip }{ $desip }{r_T_bytes};
				print  OUTFILE "  Delta  ",$sessions{ $srcip }{ $desip }{o_delta}, " / ", $sessions{ $srcip }{ $desip }{r_delta}, "\n"; 
 

				# before we look at the next destip for this source delete it if there are no more sessions open for it 
				my $hs = keys( %{$sessions{$srcip}{$desip}} ) ;
				if ( $hs eq 4 ) {
				    # Why 4? ... because the o_delta and r_delta are most likely there and ZERO! 
					print  OUTFILE "Timeout  $srcip -> $desname \n";
					#print Dumper( \%hohoh );
					delete $sessions{$srcip}{$desip};
				}
			}
			
			# Output the accmulated delta  bytes for this source to all of its destinations
			print  OUTFILE "Origin $srcip  \t Total  ",$sessions{ $srcip }{o_T_bytes}, " / ",  $sessions{ $srcip }{r_T_bytes};
			print  OUTFILE "  Delta  ",$sessions{ $srcip }{o_delta}, " / ",  $sessions{ $srcip }{r_delta}, "\n";

			print  "Summary $srcname \t Total  ",$sessions{ $srcip }{o_T_bytes}, " / ", $sessions{ $srcip }{r_T_bytes};
			print  "  Delta  ",$sessions{ $srcip }{o_delta}, " / ", $sessions{ $srcip }{r_delta}, "\n";
			
			# delete src ip if there are no more dest ips attached
			my $hs = keys( %{$sessions{$srcip}} ) ;
			if ( $hs eq 4 ) {
				print  OUTFILE "Delete source IP $srcip \n";
				#print Dumper( \%hoh );
				delete $sessions{$srcip};
			}
 		}
	close OUTFILE;
}
exit 0;

#!/usr/bin/perl
# version 1
# This script is to post process the CountConnection.out file and groups all the replies to/from the "same" 
# server together. There may be multiple addresses for the same host and that can not be detected until after the 
# name resolution process has replaced the different IPs with the same host name. Once this is done we can 
# collect all the traffic that is going to the "same" destination and add them together so that they appear 
# as one entry.
#
#=============================
# mod 12/18/13 - cjd - small data counts are not sorted correctly because they are truncated to 0!
#                      now sorting is done to .1% difference 

use strict;
use warnings;
use Data::Dumper;
my %summarize  = ();

my $dir   = '/tmp';
#my $dir   = '/home/CJDE';
#my $file ;
#my $file2 = "$dir/ipconntrack.raw";
#my $timestamp;
#my $timestamp_old 
my $infilename = "$dir/CountConnection.out";


# 
#/tmp/CountConnection.out  ( format is as follows ) 
# --------- 1384404014 Wed Nov 13 23:40:14 2013----ts_old 1384403714-----
#Start 192.168.2.13:cjdwork
# Reply 192.168.2.13:cjdwork / 16.238.58.12:g2w2358.americas.hpqcorp.net 	Total 	1064 / 0 Delta 456 / 0
# Reply 192.168.2.13:cjdwork / 16.238.58.10:g2w2358.americas.hpqcorp.net 	Total 	1064 / 0 Delta 456 / 0
# Reply 192.168.2.13:cjdwork / 16.238.58.23:g2w2358.americas.hpqcorp.net 	Total 	1064 / 0 Delta 456 / 0
# Reply 192.168.2.13:cjdwork / 16.238.58.24:g2w3653.americas.hpqcorp.net 	Total 	256 / 0 Delta 256 / 0
# Reply 192.168.2.13:cjdwork / 192.168.2.99:192.168.2.99 	                Total 	55191 / 51330 Delta 27915 / 25960
# Reply 192.168.2.13:cjdwork / 204.154.94.81:www.evernote.com 	            Total 	1355 / 5337 Delta 1355 / 5337
#Summary 192.168.2.13:cjdwork 	 Total  1384194 / 1848261  Delta  69304 / 63743





#  opent the file 
	open my $info, $infilename or die "Could not open $infilename: $!";
	my $k = "";
	my $timestamp;
	my $ticks;
	
	while( my $line = <$info>)  {
		
		chomp $line;
		
		# time stamp of the report 
		#--------- 1384404014 Wed Nov 13 23:40:14 2013----ts_old 1384403714-----
		if ( $line =~ /--------- (\d+) (.*)---------/ ){
            $ticks = $1;		
			$timestamp = $2;
			#Print header 
			header($ticks, $timestamp);
			}
		#Start of a new host 
		#       1              2 
		#Start 192.168.2.13:cjdwork
	    #                          1           2   	
		elsif ( $line =~ /.*Start\s+(\S+):(\S+)/ ) {
			#print "$line \n";
			next;
		}
		#         1           2                    3     4                            5     6               7     8 
		# Reply 192.168.2.13:cjdwork / 15.216.240.126:sipexternal.hp.com 	Total 	683236 / 1392052 Delta 9160 / 23196
		# 
		#                           1 :  2     /      3 : 4     Total      5     /    6     Delta       7    /     8
		elsif ($line =~ /Reply\s+(\S+):(\S+)\s+.\s+(\S+):(\S+)\s+Total\s+(\d+)\s+.\s+(\d+)\s+Delta\s+(\d+)\s+.\s+(\d+)/) {
			#print "$line <br>\n";
			my $origin_ip = $1;
			my $origin_nm = $2;
			my $reply_ip  = $3;
			my $reply_nm  = $4;
			my $tobytes = $5;
			my $trbytes = $6;
			my $dobytes = $7;
			my $drbytes = $8;
			if ( exists $summarize{$origin_nm}{$reply_nm} ) {
				#print "collapsing $origin_nm | $reply_nm \n";
				$summarize{$origin_nm}{$reply_nm}{to} += $tobytes;
				$summarize{$origin_nm}{$reply_nm}{tr} += $trbytes;
				$summarize{$origin_nm}{$reply_nm}{do} += $dobytes;
				$summarize{$origin_nm}{$reply_nm}{dr} += $drbytes;
				}
			else {
				$summarize{$origin_nm}{$reply_nm}{to} = $tobytes;
				$summarize{$origin_nm}{$reply_nm}{tr} = $trbytes;
				$summarize{$origin_nm}{$reply_nm}{do} = $dobytes;
				$summarize{$origin_nm}{$reply_nm}{dr} = $drbytes;
				$summarize{$origin_nm}{$reply_nm}{ip} = $reply_ip;
			}
		}
		# if every thing worked out then the sum of all the totals and all the deltas should be represented in this 
		# summary record. This is the total amount of traffic ( out/in ) for all active sessions for this device and the 
		# delta (out/in) since the last collection   
		#
		#                   1:2                  3          4              5       6 
		#Summary 192.168.2.13:cjdwork 	 Total  1384194 / 1848261  Delta  69304 / 63743
		#                         1   :  2                  3     /     4               5      /     6 
		elsif ( $line =~ /Summary\s+(\S+):(\S+)\s+Total\s+(\d+)\s+.\s+(\d+)\s+Delta\s+(\d+)\s+.\s+(\d+)/) {
			#print "$line <br>\n";			
			my $origin_ip = $1;
			my $origin_nm = $2;
			my $Tobytes = $3;
			my $Trbytes = $4;
			my $Dobytes = $5;
			my $Drbytes = $6;
			
			# this is the total bytes sent/rec by this origin to all the sites it is talking to 
			my $Combined_total = $Tobytes + $Trbytes; 

			# this is the increas in traffic that was see in the past interval (delta) for all the sites this origin is talking to  
			my $Combined_delta = $Dobytes + $Drbytes; 
							

			my @sessions = ();
			my @sortedsessions  = ();
			
			# print out the histogram for each session for this origin 
			foreach my $reply_nm (sort keys %{$summarize{$origin_nm}} ) {
				# make a list of these destination in order of increasing amount of total data xmit-ed and recvd 
				# it has to be proportional to the total amount transmitted ( in the past time interval )  
				my $o = $summarize{$origin_nm}{$reply_nm}{to};
				my $r = $summarize{$origin_nm}{$reply_nm}{tr};
				my $t = $o + $r; 
				# stuff the total ( padded out with zeros ) to the list 
				my $t_padded  = sprintf ( "%012d", $t);
				# build it all into an array so that we can sort it based on the total traffic for this origin  
				push ( @sessions, "$t_padded $reply_nm" ); 
				#print "$t_padded $reply_nm $to $tr \n"; 
			}

			
# Report generated looks like 
# 							     jtouchpad 
#       Sent   Rcv    
# Total 9326 20367   
# Delta  554  1163   
# 
# www.flickr.com 						63%	total	xxxxxxxxxxxx 	18740
# 										14%	delta   xxxxxxx 		  740
# 
# mobile-gtalk.l.google.com 			32%	total	xxxxxxxx 		 6369
# 										12%	delta 	xx				  453
# 									
# aco2wnn.push.gq.mobile.yahoo.com 		10.6 total	xxxxxx 			 3168
# 										 2%	 delta 	xx				   45
#
			# make the header of the table with the total and delta 
			starttable($origin_nm, $origin_ip, $Tobytes, $Trbytes, $Dobytes, $Drbytes);
			# now sort the traffic for this origin based on the total amount of traffic for this origin device 
			foreach my $s ( sort { $b cmp $a }  @sessions ) {
			    # so we should have a sorted list of all the replies in decreasing size by total bytes transmitted 
				# 18740 www.flickr.com
				#  6369 mobile-gtalk.l.google.com 
				#  3168 aco2wnn.push.gq.mobile.yahoo.com
				
				(my $t, my $reply_nm ) = split / /,$s;
				
				# the list of reply names is sorted in increasing order so ... 
				
				# get the total for this origin to this reply 
				# and use it to calculate the percentages this reply used out of the 
				# combined traffic amount for the origin 
				
				my $t_or = $summarize{$origin_nm}{$reply_nm}{to} + $summarize{$origin_nm}{$reply_nm}{tr};
				my $t_or_pct = 0.0;
				if ( $Combined_total != 0 ) {
					$t_or_pct = ($t_or * 1.0) / $Combined_total; 
				}

				# now do the same do the delta value get the  delta values for this origin to this reply 
				# and use it to calculate the percentages this reply used out of the 
				# combined traffic amount for the delta increase for the origin 

				my $d_or = $summarize{$origin_nm}{$reply_nm}{do} + $summarize{$origin_nm}{$reply_nm}{dr};
				my $d_or_pct = 0.0;
				if ( $Combined_delta != 0 ) {
					$d_or_pct = ($d_or * 1.0) /$Combined_delta ; 
				}
				my $reply_ip = $summarize{$origin_nm}{$reply_nm}{ip};
				dorow( $reply_nm, $reply_ip, $t_or_pct, $t_or, $d_or_pct, $d_or);

				# dorow($pct, $reply_nm, $len, $o + $r ); 
			}	
			endtable();
		}
	}
	endpage();
	#print Dumper( \%summarize );


sub  header{ 
	my ( $ticks, $t ) = @_;
	# redisplay the page 5 minutes after the time the page was created ( meaning in the future) 
	# so how long into the future must we wait? ( then add a couple sec just to make sure ) 
	my $refresh_in = ($ticks + (5 * 60 ) + 30 ) - time();
	print <<EOH
<html>
<head>
<meta http-equiv="refresh" content="$refresh_in" >
<title>Active Traffic for $t</title>
<h1>Active Traffic for $t</h1>
<style>
    table, th, td {
        border-collapse:collapse;
		align:left
    }
    th, td {
        padding:2px;
		text-align:left;
    }
</style>
</head>
<body>
EOH
}

sub starttable {
	my ($origin_nm, $origin_ip, $Tobytes, $Trbytes, $Dobytes, $Drbytes)  = @_;
	
#       Sent   Rcv    
# Total 9326 20367   
# Delta  554  1163 

	print <<EOST

<table width="50%" >
    <tr>
        <td rowspan="4" >
        <h1>$origin_nm</h1>
    	</td>
        <td rowspan="4" >
        <h3>$origin_ip</h3>
    	</td>
    </tr>
	<tr>
		<td></td>
		<th>Sent</th>
		<th> Rcv</th>
	</tr>
	<tr>
		<th>Total</th>
		<td>$Tobytes</td>
		<td>$Trbytes</td>
	</tr>
	<tr>
		<th>Delta</th>
		<td>$Dobytes</td>
		<td>$Drbytes</td>
	</tr>
</table>
<table width="100%"  border="1px">
EOST
}		



# www.flickr.com 	1.2.3.4	total			63%	xxxxxxxxxxxx 	18740
# 							delta			14%	xxxxxxx 		  740
sub dorow{
	my( $reply_nm,$reply_ip, $t_or_pct, $t_or, $d_or_pct, $d_or)  = @_;
    my $len_of_bar = 400;

	#format the percentage to a xx.x format 
	my $t_pct = sprintf( "%.1f", 100.0 * $t_or_pct );
	my $d_pct = sprintf( "%.1f", 100.0 * $d_or_pct );

	# compute the length of the bar 
	my $t_len = int ( $t_or_pct * $len_of_bar ) ; 
	my $d_len = int ( $d_or_pct * $len_of_bar ) ; 
	#print " in dorow t_pct:$t_pct  d_pct:$d_pct  t_len: $t_len  d_len:$d_len  \n";
	print <<EOR
<tr>
	<td rowspan="2" width="10%"><a href="http://$reply_nm">$reply_nm</a></td>
	<td rowspan="2" width="10%">$reply_ip</td>
	<td>total</td>
	<td>$t_pct %</td>
	<td ><img src="total.gif" alt="bar" width=$t_len height="20"> </td>
	<td>$t_or</td>
</tr>
<tr>
	<td >delta</td>
	<td>$d_pct %</td>
	<td width="40%"><img src="delta.gif" alt="bar" width=$d_len height="20"></td>
	<td>$d_or</td>
</tr>
EOR
}

sub endtable{
	print '</table><br>',"\n";
	}
	
sub endpage{
	print '</body>',"\n";
	}
	

sub starttable0{
	my ($name, $sent, $rcv) = @_; 
	print "<h2> <br><br>", $name, " Sent ", $sent, " Rcv ", $rcv, " </h2>\n";
	print '<table align="left" border="1" cellpadding="1" cellspacing="1" height="180" style="width: 100%; height: 40px" width="690">', "\n";
	#print '<caption>','Percent Name Graph Count</caption>',"\n";;
	print '<body>',"\n";
}

sub dorow0{
	
	my ($pct, $name, $len, $bytes) = @_; 
	print "<tr>\n";
	print '<td><span style="font-family:courier new,courier,monospace;">', $pct, "%</span></td>","\n";
	print "<td>",$name,"</td>","\n";
	print '<td><img src="block.gif" alt="bar" width=',$len,' height="20"> </td>',"\n";
	print "<td>", $bytes," </td>","\n";
	print "</tr>","\n";
}

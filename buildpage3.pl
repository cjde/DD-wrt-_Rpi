#!/usr/bin/perl
# version 1
# This script is to post process the CountConnection.out file and groups all the replies to/from the "same" 
# server together. There may be multiple addresses for the same host and that can not be detected until after the 
# name resolution process has replaced the different IPs wiht the same host name. Once this is done we can 
# collect all the traffic that is going to the "same" destination and add them together so that they appear 
# as one entry.
#=============================
# mod 12/18/13 - cjd - small data couts are not sorted correctly because they are truncated to 0!
#                      now sortign is done to .1% difference 

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

#BEGIN { push @INC, '.';}
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
	
	while( my $line = <$info>)  {
		
		chomp $line;
		
		# time stamp of the report 
		#--------- 1384404014 Wed Nov 13 23:40:14 2013----ts_old 1384403714-----
		if ( $line =~ /--------- \d+ (.*)---------/ ){
			$timestamp = $1;
			#Print header 
			header($timestamp);
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
			#print "$line \n";
			my $origin_ip = $1;
			my $origin_nm = $2;
			my $reply_ip  = $3;
			my $reply_nm  = $4;
			my $tobytes = $5;
			my $trbytes = $6;
			my $dobytes = $5;
			my $drbytes = $6;
			if ( exists $summarize{$origin_nm}{$reply_nm} ) {
				#print "colapsing $k\n";
				$summarize{$origin_nm}{$reply_nm}{o} += $tobytes;
				$summarize{$origin_nm}{$reply_nm}{r} += $trbytes;
			}
			else {
				$summarize{$origin_nm}{$reply_nm}{o} = $tobytes;
				$summarize{$origin_nm}{$reply_nm}{r} = $trbytes;
			}
		}
			
		#                   1:2                  3          4              5       6 
		#Summary 192.168.2.13:cjdwork 	 Total  1384194 / 1848261  Delta  69304 / 63743
		#                         1   :  2                  3     /     4               5      /     6 
		elsif ( $line =~ /Summary\s+(\S+):(\S+)\s+Total\s+(\d+)\s+.\s+(\d+)\s+Delta\s+(\d+)\s+.\s+(\d+)/) {
			#print "$line \n";			
			my $origin_nm = $2;
			my $Tobytes = $3;
			my $Trbytes = $4;
			my $Dobytes = $5;
			my $Drbytes = $6;
			starttable($origin_nm, $Tobytes, $Trbytes);
			
			# this is the total bytse sent/rec then scale everything to this 
			my $Combined_total = $Tobytes + $Trbytes; 
			my @sessions = ();
			my @sortedsessions  = ();

			# print out the histogram for each session for this origin 
			foreach my $reply_nm (sort keys %{$summarize{$origin_nm}} ) {
				# list these destination in order of increasing amount of data xmit-ed and recvd 
				# it has to be proportional to the total amount transmitted ( in the past time interval )  
				my $o = $summarize{$origin_nm}{$reply_nm}{o};
				my $r = $summarize{$origin_nm}{$reply_nm}{r};
				my $t = $o + $r; 
				# what percent of the total is this session ?
				my $t_pct = 0;
				# some of the percentages are so small that they dont sort right so 
				# make the percentage significant to three digit ( ie 1000=100.0% or  0465 = 46.5 % ) 
				if ( $Combined_total != 0 ) {
					$t_pct = int (1000 * ($t / $Combined_total )); 
				}
				# pad the number with spaces ( 456 => 0456 and 2 => 0002 ) 
				$t_pct=~s/(\d+)/substr"000$1",-3/eg;
				# build it all into an array so that we can sort it based on the percentage of total traffic for this origin  
				push ( @sessions, "$t_pct $reply_nm $o $r" ); 
				#print "$t_pct $reply_nm $o $r \n"; 
			}
			# now sort the traffic for this origin based on percent each session was of the total amount 
			foreach my $s ( sort { $b cmp $a }  @sessions ) {
			    # so we should have 0897 origname 1234 5678 all sorted like a string ) in decending order 
				(my $pct, my $reply_nm, my $o, my $r ) = split / /,$s ;
				# convert the percentages to number of pixles for the reaph 
				# in thei case the graph is 700 pixles wide max
				my $len = int($pct/1000 * 700) ; 
				$pct = $pct / 10.0;
				dorow($pct, $reply_nm, $len, $o + $r ); 
			}	
			endtable();
		}
	}
	#print Dumper( \%summarize );


sub  header{ 
	my ( $t ) = @_;
	print "<html>\n";
	print "<head>\n";
	print "<title>Active Traffic for ",$t,"</title>\n";
	print "<h1>Active Traffic for ",$t,"</h1>\n";
	print "</head>\n";
	print "<body>\n";
}


sub starttable{
	my ($name, $sent, $rcv) = @_; 
	print "<h2> <br><br>", $name, " Sent ", $sent, " Rcv ", $rcv, " </h2>\n";
	print '<table align="left" border="1" cellpadding="1" cellspacing="1" height="180" style="width: 100%; height: 40px" width="690">', "\n";
	#print '<caption>','Percent Name Graph Count</caption>',"\n";;
	print '<tbody>',"\n";
}

sub dorow{
	
	my ($pct, $name, $len, $bytes) = @_; 
	print "<tr>\n";
	print '<td><span style="font-family:courier new,courier,monospace;">', $pct, "%</span></td>","\n";
	print "<td>",$name,"</td>","\n";
	print '<td><img src="block.gif" alt="bar" width=',$len,' height="20"> </td>',"\n";
	print "<td>", $bytes," </td>","\n";
	print "</tr>","\n";
}

sub endtable{
	print '</tbody>',"\n";
	print '</table>',"\n";
	}

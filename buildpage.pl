#!/usr/bin/perl
# version 1
# This script is to post process the CountConnection.out file and groups all the replies to/from the "same" 
# server together. There may be multiple addresses for the same host and that can not be detected until after the 
# name resolution process has replaced the different IPs wiht the same host name. Once this is done we can 
# collect all the traffic that is going to the "same" destination and add them together so that they appear 
# as one entry.

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
		if ( $line =~ /---\s+(\d+)\s+\S+---/ ){
			$timestamp = $1;
			print scalar localtime( $timestamp )
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
			my $obytes = $5;
			my $rbytes = $6;
			$k = "$origin_nm $reply_nm";
			if ( exists $summarize{$k} ) {
				print "colapsing $k\n";
				$summarize{$k}{o} += $obytes;
				$summarize{$k}{r} += $rbytes;
			}
			else {
				$summarize{$k}{o} = $obytes;
				$summarize{$k}{r} = $rbytes;
			}
		}
			
		#                   1:2                  3          4              5       6 
		#Summary 192.168.2.13:cjdwork 	 Total  1384194 / 1848261  Delta  69304 / 63743
		#                         1   :  2                  3     /     4               5      /     6 
		elsif ( $line =~ /Summary\s+(\S+):(\S+)\s+Total\s+(\d+)\s+.\s+(\d+)\s+Delta\s+(\d+)\s+.\s+(\d+)/) {
			#print "$line \n";
			my $Torigin = $2;
			my $Tobytes = $4;
			my $Trbytes = $5;
			
		}
	}
	#print Dumper( \%summarize );

	# this is the end record so sort the names in ascending order and print traffic processed 
	foreach my $k (sort keys %summarize) {
		print $k, " Sent ", $summarize{$k}{o}, " Rcv ", $summarize{$k}{r},"\n";
	}

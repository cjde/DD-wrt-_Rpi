#!/usr/bin/perl
# This script take the dnslog that has been uploaded and builds a look up hostnames by Ip address. 
# it hast to realy look at hte dnslog file because there are several sceanerios that need attention
# They are  
#
# 1) local lookup 
#Oct 18 20:01:01 dnsmasq[5856]: query[A] peetapi from 192.168.2.30
#Oct 18 20:01:01 dnsmasq[5856]: /etc/hosts peetapi is 192.168.2.30
#
# 2) DHCP 
# Oct 18 20:01:55 dnsmasq-dhcp[5856]: DHCPREQUEST(br0) 192.168.2.30 b8:27:eb:81:53:06 
# Oct 18 20:01:55 dnsmasq-dhcp[5856]: DHCPACK(br0) 192.168.2.30 b8:27:eb:81:53:06 peetapi
#
# 3)  Cached name 
#Oct 18 20:02:16 dnsmasq[5856]: query[A] ad.tanzuki.net from 192.168.2.5
#Oct 18 20:02:16 dnsmasq[5856]: cached ad.tanzuki.net is <CNAME>
#Oct 18 20:02:16 dnsmasq[5856]: forwarded ad.tanzuki.net to 8.8.8.8
#Oct 18 20:02:16 dnsmasq[5856]: reply tanzuki-1967770324.us-west-2.elb.amazonaws.com is 50.112.95.0
#Oct 18 20:02:16 dnsmasq[5856]: reply tanzuki-1967770324.us-west-2.elb.amazonaws.com is 50.112.111.203
#Oct 18 20:02:16 dnsmasq[5856]: reply tanzuki-1967770324.us-west-2.elb.amazonaws.com is 50.112.253.26
#
# 4) Not cached 
#Oct 18 20:30:49 dnsmasq[5856]: query[A] webservices.continental.com from 192.168.2.10
#Oct 18 20:30:49 dnsmasq[5856]: forwarded webservices.continental.com to 8.8.8.8
#Oct 18 20:30:49 dnsmasq[5856]: reply webservices.continental.com is 216.136.1.38
#Oct 18 20:30:49 dnsmasq[5856]: reply webservices.continental.com is 12.169.195.38
#
# 5) Revers lookups  <<<<------new 
#
#Oct 23 23:19:07 dnsmasq[5856]: query[PTR] 116.37.194.173.in-addr.arpa from 192.168.2.18
#Oct 23 23:19:07 dnsmasq[5856]: forwarded 116.37.194.173.in-addr.arpa to 8.8.8.8
#Oct 23 23:19:07 dnsmasq[5856]: reply 173.194.37.116 is mia05s17-in-f20.1e100.net
#
# 6) Server? 
#Oct 18 20:21:00 dnsmasq[5856]: query[SRV] _ldap._tcp.Core-Site-DCC._sites.ldap.hp.com from 192.168.2.13
#Oct 18 20:21:00 dnsmasq[5856]: forwarded _ldap._tcp.Core-Site-DCC._sites.ldap.hp.com to 8.8.8.8
#
# 7) IPV6 queries 
#Oct 18 20:02:16 dnsmasq[5856]: query[AAAA] ???? 
#Oct 18 20:02:16 dnsmasq[5856]: cached ad.tanzuki.net is <CNAME>
#
# 8) Cached Ip address  
#Oct 19 23:04:01 dnsmasq[5856]: query[A] apple.com from 192.168.2.27
#Oct 19 23:04:01 dnsmasq[5856]: cached apple.com is 17.149.160.49
#Oct 19 23:04:01 dnsmasq[5856]: cached apple.com is 17.172.224.47
#Oct 19 23:04:01 dnsmasq[5856]: cached apple.com is 17.178.96.59
#
# 9) Not an address returned as a reply 
#Oct 20 21:25:55 dnsmasq[5856]: query[A] wpad.americas.hpqcorp.net from 192.168.2.13
#Oct 20 21:25:55 dnsmasq[5856]: forwarded wpad.americas.hpqcorp.net to 8.8.8.8
#Oct 20 21:25:55 dnsmasq[5856]: reply wpad.americas.hpqcorp.net is NXDOMAIN-IPv4
#
# Essentially we are looking to start with a query[A] and then link all the replied addresses to this name 
# until another query is encountered. 



use strict;
use warnings;
use Data::Dumper;


# CONTRACK_RAW=/tmp/ipconntrack.raw
# CONTRACK_COOKED=/tmp/ipconntrack.out

my %NAMES = ();

sub  LoadNames{ 
    
	my $dir   = '/tmp';
	my $file = "$dir/dnslog.raw";
	my $timestamp;
	my $outfilename = "$dir/dnslog.out";
	
	# clear the hash 
	%NAMES = ();

	# open the dsnlog file that has all the dns queries 
	open my $dnslog, $file or die "Could not open $file: $!";

	# when was it created ?
	$timestamp = (stat($file))[9];

	# an the log  file for debug 
	#open OUTFILE, ">", $outfilename or die "Error opening $outfilename: $!";

	#print  " --------- $timestamp ", scalar localtime( $timestamp ), "---------\n";
	#print  OUTFILE " --------- $timestamp ", scalar localtime( $timestamp ), "---------\n";

	my $name;
	my $line; 
	my $ip;
	my $requestor;
	#pull in the entire ip_connecions file and look for queries and replies to thoes queries 
	while( my $line = <$dnslog>)  {
		chomp $line;
		# so what do we have ? 
		if ( $line =~ /.*query.A. (.*) from (.*)/ )  {
			# ok we got a name ... and who asked for it 
			$name=$1;
			#print "name: $name\n"; 
			# not sure we need to know who requested it but... just in case 
			$requestor=$2;
		}
		elsif ( $line  =~ /.*reply (.*) is (.*)/ ) { 
			$ip = $2; 
			if ($ip =~ /\b(\d{1,3}(?:\.\d{1,3}){3})\b/){
				$NAMES{$ip} = $name;
			} else {
				print OUTFILE  "$ip - IS NOT A ADDRESS-> $line\n";
			}
		}
		elsif ( $line  =~ /.*cached (.*) is (.*)/ ) { 
			$ip = $2; 
			if ($ip =~ /\b(\d{1,3}(?:\.\d{1,3}){3})\b/){
				$NAMES{$ip} = $name;
			} else {
				print OUTFILE  "$ip - IS NOT A ADDRESS-> $line\n";
			}
		}
		elsif ( $line  =~ /.*.etc.hosts (.*) is (.*)/ ) { 
			$ip = $2; 
			$NAMES{$ip} = $name;
		}
	}
}
sub  ResolveIP{ 
	my ( $ip ) = @_;
	if ( exists $NAMES{$ip} ) {
		return $NAMES{$ip}
	}
	else {
		return $ip;
	}
}

sub DumpNames {
	my $ip;
	foreach my $ip (sort keys %NAMES) {
		print "$ip -> ", $NAMES{$ip}, "\n";
	}
}
sub Testresolver {
  LoadNames(); 
  print " resolving ", ResolveIP( "98.136.166.106"), "\n"; 
  DumpNames();
  #print Dumper( \%NAMES );
 }
 
1;
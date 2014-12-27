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
# 5) Server? 
#Oct 18 20:21:00 dnsmasq[5856]: query[SRV] _ldap._tcp.Core-Site-DCC._sites.ldap.hp.com from 192.168.2.13
#Oct 18 20:21:00 dnsmasq[5856]: forwarded _ldap._tcp.Core-Site-DCC._sites.ldap.hp.com to 8.8.8.8
#
# 6) IPV6 queries 
#Oct 18 20:02:16 dnsmasq[5856]: query[AAAA] ???? 
#Oct 18 20:02:16 dnsmasq[5856]: cached ad.tanzuki.net is <CNAME>
#
# 7) Cached Ip address  
#Oct 19 23:04:01 dnsmasq[5856]: query[A] apple.com from 192.168.2.27
#Oct 19 23:04:01 dnsmasq[5856]: cached apple.com is 17.149.160.49
#Oct 19 23:04:01 dnsmasq[5856]: cached apple.com is 17.172.224.47
#Oct 19 23:04:01 dnsmasq[5856]: cached apple.com is 17.178.96.59
#
# 8) Not an address returned as a reply 
#Oct 20 21:25:55 dnsmasq[5856]: query[A] wpad.americas.hpqcorp.net from 192.168.2.13
#Oct 20 21:25:55 dnsmasq[5856]: forwarded wpad.americas.hpqcorp.net to 8.8.8.8
#Oct 20 21:25:55 dnsmasq[5856]: reply wpad.americas.hpqcorp.net is NXDOMAIN-IPv4
#or
#Oct 24 11:32:59 dnsmasq[5856]: reply mediaserver-sv5-t2-1.pandora.com is NODATA-IPv6

#
# Essentially we are looking to start with a query[A] and then link all the replied addresses to this name 
# until another query is encountered. There are also the following that need special treatment

# Revers lookups 
#
#Oct 23 23:19:07 dnsmasq[5856]: query[PTR] 116.37.194.173.in-addr.arpa from 192.168.2.18
#Oct 23 23:19:07 dnsmasq[5856]: forwarded 116.37.194.173.in-addr.arpa to 8.8.8.8
#Oct 23 23:19:07 dnsmasq[5856]: reply 173.194.37.116 is mia05s17-in-f20.1e100.net
#
# Local IP addresses !!!
#Oct 24 11:09:37 dnsmasq-dhcp[5856]: DHCPACK(br0) 192.168.2.22 f4:ce:46:5f:23:47 printer
#Oct 24 11:13:33 dnsmasq-dhcp[5856]: DHCPACK(br0) 192.168.2.6 00:1d:fe:df:0e:b7 jtouchpad




use strict;
use warnings;
use Data::Dumper;


# CONTRACK_RAW=/tmp/ipconntrack.raw
# CONTRACK_COOKED=/tmp/ipconntrack.out
my $dir   = '/tmp';
my $namefile = "/var/tmp/resolve.out";
my %NAMES = ();

sub  LoadNames{    

	my $file = "$dir/dnslog.raw";
	my $timestamp;
	my $outfilename = "$dir/dnslog.out";
	
	# load up the hash if it is empty
	if (( keys %NAMES) < 1 ) {
	    print "Reloading name cache...\n";
		ReLoad();
	}

	# open the dsnlog file that has all the dns queries 
	open my $dnslog, $file or die "Could not open $file: $!";

	# when was it created ?
	$timestamp = (stat($file))[9];

	# an the log  file for debug 
#	# open OUTFILE, ">", $outfilename or die "Error opening $outfilename: $!";

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
				#print OUTFILE  "$ip - IS NOT A ADDRESS-> $line\n";
			}
		}
		elsif ( $line  =~ /.*cached (.*) is (.*)/ ) { 
			$ip = $2; 
			if ($ip =~ /\b(\d{1,3}(?:\.\d{1,3}){3})\b/){
				$NAMES{$ip} = $name;
			} else {
				#print OUTFILE  "$ip - IS NOT A ADDRESS-> $line\n";
			}
		}
		elsif ( $line  =~ /.*.etc.hosts (.*) is (.*)/ ) { 
			$ip = $2; 
			$NAMES{$ip} = $name;
		}
		#Oct 24 11:13:33 dnsmasq-dhcp[5856]: DHCPACK(br0) 192.168.2.6 00:1d:fe:df:0e:b7 jtouchpad
		# local DHCP requests!! 
		elsif ( $line  =~ /.*DHCPACK\S+\s+(\S+)\s+(\S+)\s+(\S+)/ ) {
			$ip = $1;
			$name = $3; 
			if ($ip =~ /\b(\d{1,3}(?:\.\d{1,3}){3})\b/){
				$NAMES{$ip} = $name;
			} else {
				#print OUTFILE  "$ip - IS NOT A ADDRESS-> $line\n";
			}
		}
	}
	#Just in case we have to restart jsave the names  that we have already loaded up
	print "Saving name cache \n";
	SaveNames(); 
}

# this is nte main pubblic function hat resolves name. 
sub  ResolveIP{ 
	my ( $ip ) = @_;
	if ( exists $NAMES{$ip} ) {
		return $NAMES{$ip}
	}
	else {
		return $ip;
	}
}


sub SaveNames {
	# this dumps the hash to a file so that if we have to restart we dont loose all the names
	# that we have already collected 

	# an the output file for  the MRTG scripts to look at 
	open NAMEFILE, ">", $namefile or die "Error opening to write $namefile: $!";
	foreach my $ip (keys %NAMES) {
		print NAMEFILE "$ip ";
		print NAMEFILE $NAMES{$ip};
		print NAMEFILE " \n";
	}
	close NAMEFILE;
}



sub ReLoad { 
# If we have restarted then this can be used to reload the the name resolve cache 

    if ( -e $namefile ) { 
		open NAMEFILE, "<", $namefile or die "Error opening for read $namefile: $!";
		while (<NAMEFILE> ) {
			if ( /(.*) (.*) / ) {
				#print $_; 
				chomp;			
				#print $1 , $2 , "\n";
				$NAMES{$1}=$2;
			}
			else {
				print "Error unexpected line in resolve cache $_\n";
			}
		}
	}
	else { 
		print "Missing $namefile.. skipping reload \n";
	}		
	
}
1;

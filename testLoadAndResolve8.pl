#!/usr/bin/perl

# version 4 
use strict;
use warnings;
use Data::Dumper;
#BEGIN { push @INC, '.';}

require "./LoadAndResolve8.pl";

my $dir   = '/tmp';
my $file ;
my $file2 = "$dir/ipconntrack.raw";
my $timestamp;

 
LoadNames(); 

test();
#ReLoad(); 

print "\n\n\n";

#SaveNames (); 
print "\n\n\n";

#ReLoad(); 



#LoadNames();
#SaveNames();
#ReLoad();

 


#!/usr/bin/perl
# Sort by keywork
# print  scalar localtime($b),$c, $d, $e, "  ",$a '

print <<EOH
 <!DOCTYPE html>
<html>
<head>
<style>
#customers {
    font-family: "Trebuchet MS", Arial, Helvetica, sans-serif;
    width: 100%;
    border-collapse: collapse;
}

#customers td, #customers th {
    font-size: 1em;
    border: 1px solid #98bf21;
    padding: 3px 7px 2px 7px;
}

#customers th {
    font-size: 1.1em;
    text-align: left;
    padding-top: 5px;
    padding-bottom: 4px;
    background-color: #A7C942;
    color: #ffffff;
}

#customers tr.alt td {
    color: #000000;
    background-color: #EAF2D3;
}
</style>
</head>
<body>

<table id="customers">
  <tr>
    <th>Date</th>
    <th>Source</th>
    <th>Access</th>
    <th>Name</th>
    <th>Address</th>
  </tr>
EOH
;

open ( FH1, 'grep -e "\.eu$"  -e "\.fr$" -e "\.de$" -e girl -e sex -e babes -e porn /var/tmp/resolve.out|grep -v -e essex -e nowaygirl -e exam -e exec -e zebragirl -e materialgirl | grep  -e 192.168.2.2[5789] -e 192.168.2.3[05] | sort -t: -k 2| ');

 print "<h1>Interesting Websites </h1>\n";

 while (<FH1>) {
	# print $_;
	($a,$b,$c,$d,$e)=split( /:\s/ );
	if ( $. % 2 ) {
		print "<tr>\n" ;
    }
	else {
		print '<tr class="alt">' . "\n";
	}
	$B  = scalar localtime($b);
	print <<EOR
   <td>$B</td>
   <td>$c</td>
   <td>$d</td>
   <td>$e</td>
   <td>$a</td>
   </tr>
EOR
}

print "</table> \n";


#Sort by date
print "<h1>Interesting late night activities</h1>\n";
print <<EOG
 <table id="customers">
  <tr>
    <th>Date</th>
    <th>Source</th>
    <th>Access</th>
    <th>Name</th>
    <th>Address</th>
  </tr>
EOG
;


open ( FH2, 'grep  -e 192.168.2.2[5789] -e 192.168.2.3[05] /var/tmp/resolve.out|grep -v -f /home/pi/traffic/petereport.exclude |  sort -t: -k 2| tail -750|');
my $linect=0;
 while (<FH2>) {
	#print $_;
	($a,$b,$c,$d,$e)=split( /:\s/ );
	$B  = scalar localtime($b);
	# what is the time of this entry >Mon Aug 18 08:23:09 2014<
	$B =~ /(\S*)\s(\S*)\s(\S*)\s(\d*):(\d*):(\d*)\s(\S*)/;
	#print $4, "\n";

	if (( $4 > 22 ) || ( $4 < 7 ) ) {
		$linect++;
		if ( $linect % 2 ) {
			print "<tr>\n" ;
		}
		else {
			print '<tr class="alt">' . "\n";
		}
		print "<td>$B</td> <td>$c</td> <td>$d</td>  <td>$e</td> <td>$a</td> </tr>\n"
	}
}

print "</table> </body> </html> \n";




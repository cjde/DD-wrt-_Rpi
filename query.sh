while ((1)); do 
grep "query\[A\]"  /tmp/dnslog.raw   | \
sed s/:...dnsmasq.*query.A.\ /\ / | \
grep -e 192.168.2.2[579] -e 192.168.2.3[5] | \
uniq  | \
sed -e s/192.168.2.25/right/ \
-e s/192.168.2.27/P2_ipod/ \
-e s/192.168.2.29/Peters-iPod/ \
-e s/192.168.2.30/PetaPi/ \
-e s/192.168.2.35/PeterPhone/ \
>> /var/www/ceeberry/p.txt 
sleep 300  
 done


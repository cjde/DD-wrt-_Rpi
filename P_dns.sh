today=`date "+%b %e"`
# For every hour in the day 
for j in 00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 ; do
    # for every 10 min in the hour 
    for i in 1 2 3 4 5 ;do 
       # print out the time 
       echo -n "--- ${j}:${i}0 ----";

       # for today look in the file 
       # at the given hour and the given Minute
       # and print out the queried name 
       # break the doman into the last two parts
       # and sort it into a file  
       grep "$today" /var/www/ceeberry/p.txt |\
       grep $j:$i | \
       awk '{ print $4 }' |\
       awk -F\. '{  print $(NF-1)"." $NF } ' | \
       sort > /tmp/stuff ;

       # count the number of unique domains 
       # and print it out with the time 

       wc -l /tmp/stuff| \
       awk '{print $1}';  

       # take the remaining domains and sort them into decending number of references a
       uniq -c /tmp/stuff | \
       sort -nr | head -20 ; 
    done ; 
 done 

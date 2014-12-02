#!/bin/sh
 ssh -q root@192.168.2.99 sh  /tmp/root/conncheck.sh > /home/pi/conncheck.txt 
 grep Connections /home/pi/conncheck.txt | awk '{ print $2; print $3}'
 


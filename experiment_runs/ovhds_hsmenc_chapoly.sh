#!/bin/bash

# HSM timing for 1.5GB x 10 steps
# Assumes req/res pairs names req1.dec/res1.enc etc... using a prefixed session key
# requires folder dataset_hsmenc and the hsmenc executable + lifrclone.so library
# Assuming all encrypted files were produced as follows:
#./hsmenc -lo -b 1024 -a enc < $1 > $1.enc 

echo "step,size,nano sec" > ovhds_hsmenc.csv

#repeat x10 
for ((i=1;i<=10;i++));
do
	echo ">>>>>>>>>>>>>step $i"
	echo

	echo ">>size $j"
	echo

	echo ">>encryption $j"
    echo > temp.txt


	#encrypt dataset requests
	for afile in dataset_hsmenc/req*.dec
	do
		#get next req and encrypt
		echo "processing $afile"
		cat $afile >>temp.txt
	done

	#start timer
	start1=`date +%s%N`
    ./hsmenc -lo -b 4096 -a enc  < temp.txt > dummy.out
    #stop timer
	stop1=`date +%s%N`

	echo ">>decryption $j"
    echo > temp.txt

	#decrypt dataset responses and first 10MB of download
	for afile in dataset_hsmenc/res*.enc
	do
		#get next req and encrypt
        echo "processing $afile"
		cat $afile >> temp.txt
	done

    #extend download resp (10MB) till 1.5GB (ie 1.5GB/10MB -1 steps): ASSUMING download req/resp is final one!
	for ((k=1;k<150;k++));
	do
		# decrypt encrypted resp
        cat $afile >> temp.txt
	done

	#start timer
	start2=`date +%s%N`
    ./hsmenc -lo -b 4096 -a dec  < temp.txt > dummy.out
    #stop timer
	stop2=`date +%s%N`

    
	timediff1=$(( $stop1-$start1 ))
	timediff2=$(( $stop2-$start2 ))
	timediff=$(( $timediff1+$timediff2 ))
    #append step,size,timediff	
	echo "$i,$j,$timediff" >> ovhds_hsmenc.csv

       
done

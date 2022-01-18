#!/bin/bash

# Baseline timings for a downoad session ranging from 15-150GB, with the whole thing repeated x10
# Assumes req/res pairs names req1.dec/res1.enc etc... using a prefixed session key
# requires folder dataset_hpenc_aes256 and the hpenc executable
# Assuming all encrypted files were produced as follows:
#./hpenc -a aes-256 psk
#Random key: x8mxgzgojmgiywt3j4ch5reupwhf8uw8fmrxwjfa6dwpoqkx9dob
key=x8mxgzgojmgiywt3j4ch5reupwhf8uw8fmrxwjfa6dwpoqkx9dob

echo "step,size,nano sec" > ovhds_hpenc_aes256.csv

#repeat x10 
for ((i=1;i<=10;i++));
do
	echo ">>>>>>>>>>>>>step $i"
	echo

	# For x10 steps - (1.5-15GB range)
	for ((j=15;j<=150;j+=15));
	do
		echo ">>size $j"
		echo

		echo ">>encryption $j"

		#start timer
    	start1=`date +%s%N`

		#encrypt dataset requests
		for afile in dataset_hpenc_aes256/req*.dec
		do
    		#get next req and encrypt
			echo "processing $afile"
            ./hpenc -a aes-256 -b 1M -k $key < $afile > dummy.out
		done


        #stop timer
		stop1=`date +%s%N`

		echo ">>decryption $j"
		#start timer
		start2=`date +%s%N`


		#decrypt dataset responses and first 10MB of download
		for afile in dataset_hpenc_aes256/res*.enc
		do
			# decrypt encrypted resp
            echo "processing $afile"
            ./hpenc -a aes-256  -b 1M -k $key -d < $afile > dummy.out
		done

        #extend download resp  for j*10 10MB steps -1: ASSUMING download req/resp is final one!
		for ((k=1;k<(j*10);k++));
		do
			# decrypt encrypted resp
            ./hpenc -a aes-256  -b 1M -k $key -d < $afile > dummy.out
		done

        #stop timer
		stop2=`date +%s%N`

        
		timediff1=$(( $stop1-$start1 ))
		timediff2=$(( $stop2-$start2 ))
		timediff=$(( $timediff1+$timediff2 ))
        #append step,size,timediff	s
		echo "$i,$j,$timediff" >> ovhds_hpenc_aes256.csv

        
	done
done

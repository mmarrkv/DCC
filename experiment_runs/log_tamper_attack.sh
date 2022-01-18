#!/bin/bash

# hsmenc audit run
# Assumes req/res pairs names req1.dec/res1.enc etc... using a prefixed session key
# requires folder dataset_hsmenc and the hsmenc executable + libfrclone.so library
# Assuming all encrypted files were produced as follows:
#./hsmenc -lo -b 1024 -a enc < $1 > $1.enc 


echo ">>>>>>>>>>hsmenc audit run"
echo

echo ">>>>>Generate log"
#encrypt dataset requests
echo > temp.txt
for afile in dataset_hsmenc/req*.dec
do
	#get next req and encrypt
	echo "processing $afile"
	cat $afile >>temp.txt
done

echo
echo ">>>>>Compute PCR value inside re-initialized HSM"
echo
./hsmenc -t
./hsmenc -lon
./hsmenc -lo -b 1024 -a enc  < temp.txt > dummy.out
./hsmenc -u

echo ">>>>>Tamper with log"
cat temp.txt | sed 's/1Xay4B/2Xay2B/g' > temp2.txt

echo ">>>>>Compute PCR value outside HSM"
echo
./hsmenc_audit -b 1024 < temp2.txt

echo ">>>>>Comparison + verdict"
echo


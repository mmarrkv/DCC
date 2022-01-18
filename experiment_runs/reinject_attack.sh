#!/bin/bash

# hsmenc audit run
# Assumes req/res pairs names req1.dec/res1.enc etc... using a prefixed session key
# requires folder dataset_hsmenc and the hsmenc executable + libfrclone.so library
# Assuming all encrypted files were produced as follows:
#./hsmenc -lo -b 1024 -a enc < $1 > $1.enc 


echo ">>>>>>>>>>re-inject attack"
echo

echo ">>>>>0. Init device"
./hsmenc -t
./hsmenc -lon
echo

echo ">>>>>1. Authenticate"
./hsmenc -lo -b 1024 -a enc  < dataset_hsmenc/req001.dec > dummy.out
./hsmenc -lo -b 1024 -a dec  < dataset_hsmenc/res001.enc > dummy.out
echo

echo ">>>>>2. Encrypt request"
./hsmenc -lo -b 1024 -a enc  < dataset_hsmenc/req003.dec > dummy.out
echo

echo ">>>>>3. Re-inject"
./hsmenc -lo -b 1024 -a dec  < dummy.out
echo

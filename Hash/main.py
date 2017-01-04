#!/usr/bin/env python
# -*- coding: utf-8 -*- 
from Crypto.Hash import MD5, SHA256
from binascii import hexlify, unhexlify
import sys
import argparse


def md5hash(args):
    hashh = MD5.new()
    hashh.update(args)
    return hashh.hexdigest()

def sha256hash(args):
    hashh = SHA256.new()
    hashh.update(args)
    return hashh.hexdigest()

files = []
files = sys.argv[1:]
option = '1'
while(option!='0'):
    option = raw_input("0. Exit from program\n1. Generate hash using MD5 \n2. Generate hash using SHA256: ")
    if(option=='1'):
        for arg in files:
            file = open("%s"%arg)
            argument = file.read()
            print "Text in file: %s"%argument
            print "Hash from file: %s"%md5hash(argument)
        
    elif(option=='2'):
        for arg in files:
            file = open("%s"%arg)
            argument = file.read()
            print "Text in file: %s"%argument
            print "Hash from file: %s"%sha256hash(argument)
    else:
        print "Incorrect Parametr!"
   

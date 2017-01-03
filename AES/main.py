#!/usr/bin/env python
# -*- coding: utf-8 -*- 
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter

BlockSize = 16
pad = lambda s: s + (BlockSize - len(s) % BlockSize) * chr(BlockSize - len(s) % BlockSize)
unpad = lambda s: s[0:-ord(s[-1])]

def genkey(): # Funkcja generuj�ca klucz 16 bajtowy.
    return Random.new().read(16)
def geniv():
    return Random.new().read(16)

def encryptECB(key,text): #Funcjon which encrypt message by AES algorithm with Electronic Codebook mode.
    text = pad(text)
    cipher = AES.new(key,AES.MODE_ECB)
    return (cipher.encrypt(text)).encode('hex')
    
def decryptECB(key,ciphertext): #Funcjon which decrypt message by AES algorithm with Electronic Codebook mode.
    cipher = AES.new(key,AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext))

def encryptCBC(key,text,iv):
    text = pad(text)
    cipher = AES.new(key,AES.MODE_CBC,iv)
    return cipher.encrypt(text).encode('hex')

def decryptCBC(key,ciphertext,iv):
    cipher = AES.new(key,AES.MODE_CBC,iv)
    return unpad(cipher.decrypt(ciphertext))

def genctr(iv):
    return Counter.new(128, initial_value=long(iv.encode('hex'),16))

def encryptCTR(key,text,ctr):
    #NIST sp800-38a contains information that, CTR doesn't need pad a plaintext before encrpyt process. 
    cipher = AES.new(key,AES.MODE_CTR, counter=ctr)
    return cipher.encrypt(text).encode('hex')

def decryptCTR(key,ciphertext,ctr):
    cipher = AES.new(key,AES.MODE_CTR,counter=ctr)
    return cipher.decrypt(ciphertext)

option = '1'

while(option!='0'):
    option = raw_input("1. AES with Electronic Block mode.\n2. AES with Cipher block chaining. \n3. AES with Counter mode : ")
   
    if(option=='1'):
        ecb = '1'
        while(ecb!=0):
            ecb = raw_input("Please choose what to you want to do: Press 1 to encrpyt message, Press 2 to decrypt ciphermessage, Press 0 to quit from console: ")
            
            if (ecb=='1'):
                genk = raw_input("1. I have a key. 2. I want generate random key: ")
                if (genk=='1'):
                    key = raw_input("Insert your key in hex: ")
                    print "Your key look like this: %s"%key
                    text = raw_input("Please type plaintext to encrypt: ")
                    ciphertext = encryptECB(key.decode('hex'), text)
                    print ("Your encrypted message is looks like this : %s")%ciphertext
                else:
                    key = genkey()
                    print "Your key look like this: %s"%key.encode('hex')
                    text = raw_input("Please type plaintext to encrypt: ")
                    ciphertext = encryptECB(key, text)
                    print ("Your encrypted message is looks like this : %s")%ciphertext
           
            elif(ecb=='2'):
                key = raw_input("Please insert your key in hex: ").decode('hex')
                ciphertext = raw_input("Please insert the ciphermessage to decrypt: ")
                plaintext = decryptECB(key, ciphertext.decode('hex'))
                print "Decrypted message is: %s"%plaintext
         
                
    elif(option=='2'):
            cbc = raw_input("Please choose what to you want to do: Press 1 to encrpyt message, Press 2 to decrypt ciphermessage, Press 0 to quit from console: ")
            
            if (cbc=='1'):
                genk = raw_input("1. I have a key and iv.\n 2. I want generate random key and iv: ") 
                if (genk=='1'):
                    key = raw_input("Insert your key in hex: ")
                    print "Your key look like this: %s"%key
                    iv = raw_input("Insert your iv in hex: ")
                    print "Your iv look like this: %s"%iv
                    text = raw_input("Please type plaintext to encrypt: ")
                    ciphertext = encryptCBC(key.decode('hex'),text, iv.decode('hex'))
                    print ("Your encrypted message is looks like this : %s")%ciphertext
                else:
                    key=genkey()
                    print "Your key look like this: %s"%key.encode('hex')
                    iv = geniv()
                    print "Your iv look like this: %s"%iv.encode('hex')
                    text = raw_input("Please type plaintext to encrypt: ")
                    ciphertext = encryptCBC(key, text, iv)
                    print ("Your encrypted message is looks like this : %s")%ciphertext
            
            else:
                key = raw_input("Please insert your key in hex: ").decode('hex')
                iv = raw_input("Please insert your iv in hex: ").decode('hex')
                ciphertext = raw_input("Please insert the ciphermessage to decrypt: ")
                plaintext = decryptCBC(key, ciphertext.decode('hex'), iv)
                print "Decrypted message is: %s"%plaintext
    elif(option=='3'):
            ctr = raw_input("Please choose what to you want to do: Press 1 to encrpyt message, Press 2 to decrypt ciphermessage, Press 0 to quit from console: ")  
            
            if(ctr=='1'):
                genk = raw_input("1. I have a key and iv. 2. I want generate random key and iv: ") 
                if (genk=='1'):
                    key = raw_input("Insert your key in hex: ")
                    print "Your key look like this: %s"%key
                    iv = raw_input("Insert your iv in hex: ")
                    print "Your iv look like this: %s"%iv
                    ctr = genctr(iv)
                    text = raw_input("Please type plaintext to encrypt: ")
                    ciphertext = encryptCTR(key, text, ctr)
                    print ("Your encrypted message is looks like this : %s")%ciphertext 
                else:
                    key=genkey()
                    print "Your key look like this: %s"%key.encode('hex')
                    iv = geniv()
                    ctr = genctr(iv)
                    print "Your iv look like this: %s"%iv.encode('hex')
                    text = raw_input("Please type plaintext to encrypt: ")
                    ciphertext = encryptCTR(key, text, ctr)
                    print ("Your encrypted message is looks like this : %s")%ciphertext
                     
            else:
                key = raw_input("Please insert your key in hex: ").decode('hex')
                iv = raw_input("Please insert your iv in hex: ").decode('hex')
                ctr = genctr(iv)
                print "%s"%ctr
                ciphertext = raw_input("Please insert the ciphermessage to decrypt: ")
                plaintext = decryptCTR(key, ciphertext.decode('hex'), ctr)
                print "Decrypted message is: %s"%plaintext
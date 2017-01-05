#!/usr/bin/env python
# -*- coding: utf-8 -*- 
from Crypto.PublicKey import RSA
from Crypto import Random

#generate key pair: 
random_gen = Random.new().read
key = RSA.generate(2048, random_gen)
pub = open('mykeypub.pem','w')
priv = open('mykeyprv.pem','w')
pub.write(key.publickey().exportKey()) #save public key to file
priv_key = priv.write(key.exportKey('PEM', passphrase=None, pkcs=8)) #save all parameters of key to file
pub.close()
priv.close()

#Read key from file
#key_file = open('mykeypub.pem','r')
#key = RSA.importKey(key_file.read())
#print key
#priv_file = open('mykeyprv.pem','r')
#key_prv = importKey(priv_file.read())
#print key_prv

key_file = open('olga.pem','r')
key = RSA.importKey(key_file.read())
print key
file_plaintext = open('text_to_encrypt.txt','r')
file_ciphertext = open('cipher_text_git.txt','w')
message = file_plaintext.read()
print message.encode('base64').encode('utf-8')
enc_message = key.encrypt(message, 32) #Encrypt file

enc_message = enc_message[0]
print enc_message.encode('hex')


#message = key_prv.decrypt(enc_message) #decrypt file
#print message



file_ciphertext.write(enc_message.encode('hex'))
file_plaintext.close()
file_ciphertext.close()
key_file.close()



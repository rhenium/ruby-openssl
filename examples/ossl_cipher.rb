#!/usr/bin/env ruby

require 'openssl'
include OpenSSL
include Cipher

p des = DES.new(EDE3, CBC) #Des3 CBC mode
p "ENCRYPT"
p des.encrypt("key")#, "iv12345678")
p cipher = des.update("abcdefghijklmnopqrstuvwxyz")
p cipher += des.cipher
p "DECRYPT"
p des.decrypt("key") #, "iv12345678")
p des.update(cipher) + des.cipher


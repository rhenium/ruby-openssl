#!/usr/bin/env ruby

require 'openssl'
include OpenSSL
include Cipher

p des = DES.new(EDE3, CBC) #Des3 CBC mode
p "ENCRYPT"
p des.encrypt("key") #, "initial_vector")
p cipher = des.update("data1")
#p cipher = des.encrypt("key", "initial_vector", "data")
p cipher += des.cipher
p "DECRYPT"
p des.decrypt("key")
#p des.decrypt("key", "initial_vector")
p des.update(cipher) + des.cipher


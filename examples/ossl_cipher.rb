#!/usr/bin/env ruby

require 'openssl'
include OpenSSL

text = "abcdefghijklmnopqrstuvwxyz"
key = "key"
alg = "DES-EDE3-CBC"
#alg = "AES-128-CBC"

puts "ClearText = \"#{text}\""
puts "SymmetricKey = \"#{key}\""
puts "CipherAlg = \"#{alg}\""

des = Cipher::Cipher.new(alg)
puts "--Encrypting with key--"
des.encrypt("key")#, "iv12345678")
cipher = des.update(text)
cipher += des.final
puts "EncryptedText = #{cipher.inspect}"
puts "--Decrypting with key--"
des.decrypt(key) #, "iv12345678")
out = des.update(cipher) + des.final
puts "DecryptedText = \"#{out}\""

puts "DONE."


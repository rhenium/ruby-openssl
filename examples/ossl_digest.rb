#!/usr/bin/env ruby

require 'digest/sha1'
require 'digest/md5'
require 'openssl'

str = "This is only bullshit! :-))"
md5 = Digest::MD5.new(str)
md5a = OpenSSL::Digest::MD5.new(str)
p md5.digest == md5a.digest
p md5.hexdigest == md5a.hexdigest

sha1 = OpenSSL::Digest::SHA1.new(str*2)
sha1a = Digest::SHA1.new(str*2)
p sha1.digest == sha1a.digest
p sha1.hexdigest == sha1a.hexdigest


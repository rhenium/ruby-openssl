#!/usr/bin/env ruby

raise "TO BE DROPPED???..."

require 'openssl'
include OpenSSL

p config = Config.new("./openssl.cnf")

p string = config.get_string("req", "x509_extensions")
p number = config.get_number("req", "default_bits")
p string = config.get_string("req", "distinguished_name")

p sect = config.get_section(string)
p ConfigSection.new


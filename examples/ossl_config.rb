#!/usr/bin/env ruby

require 'openssl'
include OpenSSL

p config = Config.load("./config.cnf")

p string = config.get_value("req", "x509_extensions")
p string = config.get_value("req", "default_bits")
p number = config.get_value("req", "default_bits").to_i
p string = config.get_value("req", "distinguished_name")
p config.get_section("req")

##
#DISABLED!
#p sect = config.get_section(string)
#p ConfigSection.new


#!/usr/bin/env ruby

require 'openssl'
include OpenSSL

config = Config.load("./config.cnf")

p string = config.value("req", "x509_extensions")
p string = config.value("req", "default_bits")
p number = config.value("req", "default_bits").to_i
p string = config.value("req", "distinguished_name")
p config["req"] # or config.section("req")


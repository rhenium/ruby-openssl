=begin
= $RCSfile$ -- Generator for Makefile

= Info
  'OpenSSL for Ruby 2' project
  Copyright (C) 2002  Michal Rokos <m.rokos@sh.cvut.cz>
  All rights reserved.

= Licence
  This program is licenced under the same licence as Ruby.
  (See the file 'LICENCE'.)

= Version
  $Id$
=end

require "mkmf"

if RUBY_PLATFORM =~ /mswin32/
  CRYPTOLIB="libeay32"
  SSLLIB="ssleay32"
else
  CRYPTOLIB="crypto"
  SSLLIB="ssl"
end

dir_config("openssl")

have_func("strptime", "time.h")

##
# Adds -Wall -DOSSL_DEBUG for compilation
# Use as --with-debug or --enable-debug
#
if with_config("debug") or enable_config("debug")
  $defs.push("-DOSSL_DEBUG") unless $defs.include? "-DOSSL_DEBUG"
  $CPPFLAGS += " " + "-Wall" unless $CPPFLAGS.split.include? "-Wall"
end


if have_header("openssl/crypto.h") and 
    have_library(CRYPTOLIB, nil) and
    have_library(SSLLIB, nil) #"SSLv23_method")
  create_makefile("openssl")
  puts "Done."
else
  puts "Makefile wasn't created."
end


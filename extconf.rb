=begin
$Id$
'OpenSSL for Ruby' project
Copyright (C) 2001 Michal Rokos <m.rokos@sh.cvut.cz>
All rights reserved.

This program is licenced under the same licence as Ruby.
(See the file 'LICENCE'.)
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

have_func("strncasecmp", "string.h")
have_func("strptime", "time.h")

if have_header("openssl/ssl.h")
	if have_library(CRYPTOLIB, nil) and have_library(SSLLIB, nil) #"SSLv23_method")
		create_makefile("openssl")
	end
end


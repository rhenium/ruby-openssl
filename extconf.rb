=begin
$Id$
'OpenSSL for Ruby' project
Copyright (C) 2001 Michal Rokos <m.rokos@sh.cvut.cz>
All rights reserved.

This program is licenced under the same licence as Ruby.
(See the file 'LICENCE'.)
=end

require "mkmf"

CRYPTOLIB="crypto"
SSLLIB="ssl"

dir_config("openssl")

if have_header("openssl/ssl.h")
	if have_library(CRYPTOLIB, nil) and have_library(SSLLIB, nil) #"SSLv23_method")
		create_makefile("openssl")
	end
end


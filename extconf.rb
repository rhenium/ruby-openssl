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

have_header("unistd.h")
have_header("sys/time.h")
have_func("strptime", "time.h")

##
# Adds -Wall -DOSSL_DEBUG for compilation and some more targets when GCC is used
# To turn it on, use: --with-debug or --enable-debug
#
if with_config("debug") or enable_config("debug")
  $defs.push("-DOSSL_DEBUG") unless $defs.include? "-DOSSL_DEBUG"
  $CPPFLAGS += " " + "-Wall" unless $CPPFLAGS.split.include? "-Wall"

  if CONFIG["CC"] =~ /gcc/
    srcs = []
    for f in Dir[File.join(".", "*.c")]
      srcs.push File.basename(f)
    end
    srcs = srcs.join(" ")
    
    File.open("depend", "w") {|f|
      f.print <<EOD
SRCS = #{srcs}

test-link:
	$(CC) $(DLDFLAGS) -o testlink $(OBJS) $(LIBS) $(LOCAL_LIBS)
	@$(RM) testlink
	@echo "Done."

dep:
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $(SRCS) -MM > dep

include dep
EOD
    }
  end
end

if have_header("openssl/crypto.h") and 
    have_library(CRYPTOLIB, "OpenSSL_add_all_algorithms") and 
    have_library(SSLLIB, "SSLv23_method")
  create_makefile("openssl")
  puts "Done."
else
  puts "Makefile wasn't created. Fix the errors above."
end


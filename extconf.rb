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

if !defined? message
  def message(*s)
    printf(*s)
    Logging::message(*s)
  end
end

includes, = dir_config("openssl")
includes ||= "/usr/include"

message "=== OpenSSL for Ruby configurator ===\n"
message "=== Checking for system dependent stuff... ===\n"
have_header("unistd.h")
have_header("sys/time.h")
message "=== Checking for system dependent stuff done. ===\n"


##
# Adds -Wall -DOSSL_DEBUG for compilation and some more targets when GCC is used
# To turn it on, use: --with-debug or --enable-debug
#
if with_config("debug") or enable_config("debug")
  $defs.push("-DOSSL_DEBUG") unless $defs.include? "-DOSSL_DEBUG"
  $CPPFLAGS += " -Wall" unless $CPPFLAGS.split.include? "-Wall"

  if CONFIG["CC"] =~ /gcc/
    srcs = []
    for f in Dir[File.join(".", "*.c")]
      srcs.push File.basename(f)
    end
    srcs = srcs.join(" ")
    
    $distcleanfiles << "dep" if defined? $distcleanfiles
    
    File.open("depend", "w") {|f|
      f.print <<EOD
SRCS = #{srcs}

test-link:
	$(CC) $(DLDFLAGS) -o .testlink $(OBJS) $(LIBPATH) $(LIBS) $(LOCAL_LIBS)
	@$(RM) .testlink
	@echo "Done."

dep:
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $(SRCS) -MM > dep

include dep
EOD
    }
  end
end


def have_openssl_097(inc_dir)
# FIXME:
#  checking_for("OpenSSL >= 0.9.7") do
  printf "Checking for OpenSSL >= 0.9.7..."
  File.open(inc_dir+"/openssl/opensslv.h") {|f|
    txt = f.read
    result = ((txt.grep(/#define SHLIB_VERSION_NUMBER/)[0].split '"')[1] < "0.9.7")
    puts result ? "no" : "yes"
    !result
  }
end

message "=== Checking for required stuff... ===\n"

result = have_header("openssl/crypto.h")
result &= have_library(CRYPTOLIB, "OPENSSL_load_builtin_modules")
result &= have_library(SSLLIB, "SSL_library_init")
result &= have_openssl_097(includes)

have_func("HMAC_CTX_copy")
have_func("X509_STORE_set_ex_data")

if result
  message "=== Checking for required stuff done. ===\n"
  create_makefile("openssl")
  message "Done.\n"
else
  message "=== Checking for required stuff failed. ===\n"
  message "Makefile wasn't created. Fix the errors above.\n"
end


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

def have_defined(macro, header=nil)
  checking_for "#{macro}" do
    if macro_defined?(macro, cpp_include(header))
      $defs.push(format("-DHAVE_%s", macro.upcase))
      true
    else
      false
    end
  end
end

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


##
# Adds -Wall -DOSSL_DEBUG for compilation and some more targets when GCC is used
# To turn it on, use: --with-debug or --enable-debug
#
if with_config("debug") or enable_config("debug")
  $defs.push("-DOSSL_DEBUG") unless $defs.include? "-DOSSL_DEBUG"
  $CPPFLAGS += " -Wall" unless $CPPFLAGS.split.include? "-Wall"

  if CONFIG["CC"] =~ /gcc/
    srcs = []
    for f in Dir[File.join($srcdir, "*.c")]
      srcs.push File.basename(f)
    end
    srcs = srcs.join(" ")
    
    $distcleanfiles << "dep" if defined? $distcleanfiles
    
    File.open(File.join($srcdir, "depend"), "w") {|f|
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
  printf "checking for OpenSSL version... "
  File.open(inc_dir+"/openssl/opensslv.h") {|f|
    txt = f.read
    puts (txt.grep(/#define SHLIB_VERSION_NUMBER/)[0].split '"')[1]
    true
  }
end

message "=== Checking for required stuff... ===\n"

result = have_header("openssl/crypto.h")
result &= have_library(CRYPTOLIB, "OpenSSL_add_all_digests")
result &= have_library(SSLLIB, "SSL_library_init")

if !result
  message "=== Checking for required stuff failed. ===\n"
  message "Makefile wasn't created. Fix the errors above.\n"
  exit 1
end

message "=== Checking for system dependent stuff... ===\n"
have_header("unistd.h")
have_header("sys/time.h")

message "=== Checking for OpenSSL features... ===\n"
have_openssl_097(includes)
have_defined("PEM_read_bio_DSAPublicKey", "openssl/pem.h")
have_defined("PEM_write_bio_DSAPublicKey", "openssl/pem.h")
have_defined("DSAPrivateKey_dup", "openssl/dsa.h")
have_defined("DSAPublicKey_dup", "openssl/dsa.h")
have_defined("X509_REVOKED_dup", "openssl/x509.h")
have_defined("PKCS7_SIGNER_INFO_dup", "openssl/pkcs7")
have_defined("PKCS7_RECIP_INFO_dup", "openssl/pkcs7")
have_func("HMAC_CTX_copy")
have_func("X509_STORE_get_ex_data")
have_func("X509_STORE_set_ex_data")
have_func("EVP_MD_CTX_create")
have_func("EVP_MD_CTX_cleanup")
have_func("EVP_MD_CTX_destroy")
have_func("PEM_def_callback")
have_defined("EVP_CIPHER_name", "openssl/evp.h")
have_defined("EVP_MD_name", "openssl/evp.h")
have_func("EVP_MD_CTX_init")
have_func("HMAC_CTX_init")
have_func("HMAC_CTX_cleanup")
have_defined("PKCS7_is_detached", "openssl/pkcs7.h")
have_defined("PKCS7_type_is_encrypted", "openssl/pkcs7.h")
have_func("X509_CRL_set_version")
have_func("X509_CRL_set_issuer_name")
have_func("X509_CRL_sort")
have_func("X509_CRL_add0_revoked")
have_struct_member("X509_STORE_CTX", "current_crl", "openssl/x509.h")
have_struct_member("X509_STORE", "flags", "openssl/x509.h")
have_struct_member("X509_STORE", "purpose", "openssl/x509.h")
have_struct_member("X509_STORE", "trust", "openssl/x509.h")
have_struct_member("EVP_CIPHER_CTX", "flags", "openssl/evp.h")
have_func("BN_mod_sqr")

message "=== Checking for Ruby features... ===\n"
have_func("rb_obj_init_copy", "ruby.h")

message "=== Checking done. ===\n"
create_makefile("openssl")
message "Done.\n"


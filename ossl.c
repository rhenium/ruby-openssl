/*
 * $Id$
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001-2002  Michal Rokos <m.rokos@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
/*
 * Surpress dumb warning about implicit declaration of strptime on Linux
 */
#if defined(__linux__) || defined(linux)
#  define _GNU_SOURCE
#endif

#include "ossl.h"

/*
 * On Windows platform there is no strptime function
 * implementation in strptime.c
 */
#if !defined(HAVE_STRPTIME)
#  include "./missing/strptime.c"
#endif

/*
 * Check Types
 */
void
ossl_check_kind(VALUE obj, VALUE klass)
{
	if (rb_obj_is_kind_of(obj, klass) == Qfalse) {
		rb_raise(rb_eTypeError, "wrong argument (%s)! (Expected kind of %s)",\
				rb_class2name(CLASS_OF(obj)), rb_class2name(klass));
	}
}

void
ossl_check_instance(VALUE obj, VALUE klass)
{
	if (rb_obj_is_instance_of(obj, klass) == Qfalse) {
		rb_raise(rb_eTypeError, "wrong argument (%s)! (Expected instance of %s)",\
				rb_class2name(CLASS_OF(obj)), rb_class2name(klass));
	}
}

/*
 * DATE conversion
 */
VALUE
asn1time_to_time(ASN1_UTCTIME *time)
{
	struct tm tm;

	switch(time->type) {
		case V_ASN1_UTCTIME:
			if (!strptime(time->data, "%y%m%d%H%M%SZ", &tm)) {
				rb_raise(rb_eTypeError, "bad UTCTIME format");
			}
			break;
		case V_ASN1_GENERALIZEDTIME:
			if (!strptime(time->data, "%Y%m%d%H%M%SZ", &tm)) {
				rb_raise(rb_eTypeError, "bad GENERALIZEDTIME format" );
			}
			break;
		default:
			rb_raise(rb_eTypeError, "unknown time format");
	}
	/*return rb_time_new(mktime(gmtime(mktime(&tm))), 0); * Is this correct? */
	return rb_time_new(mktime(&tm), 0); /* or this one? */
}

/*
 * This function is not exported in Ruby's *.h
 */
extern struct timeval rb_time_timeval(VALUE time);

time_t
time_to_time_t(VALUE time)
{
	struct timeval t;

	t = rb_time_timeval(time);
	
	return t.tv_sec;
}

/*
 * Modules
 */
VALUE mOSSL;
VALUE   mDigest;
VALUE   mNetscape;
VALUE   mPKCS7;
VALUE   mPKey;
VALUE   mRandom;
VALUE   mSSL;

/*
 * OpenSSLError < StandardError
 */
VALUE eOSSLError;

/*
 * OSSL library init
 */
void
Init_openssl()
{
#if defined(OSSL_DEBUG)
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
#endif
	
	/*
	 * Init all digests, ciphers
	 */
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	/*
	 * Universe of Modules
	 */
	mOSSL = rb_define_module("OpenSSL");
	mNetscape = rb_define_module_under(mOSSL, "Netscape");
	mPKCS7 = rb_define_module_under(mOSSL, "PKCS7");
	mPKey = rb_define_module_under(mOSSL, "PKey");
	mRandom = rb_define_module_under(mOSSL, "Random");
	mSSL = rb_define_module_under(mOSSL, "SSL");
	
	/*
	 * Constants
	 */
	rb_define_const(mOSSL, "VERSION", rb_str_new2(OSSL_VERSION));
	rb_define_const(mOSSL, "OPENSSL_VERSION", rb_str_new2(OPENSSL_VERSION_TEXT));

	/*
	 * Generic error,
	 * common for all classes under OpenSSL module
	 */
	eOSSLError = rb_define_class_under(mOSSL, "OpenSSLError", rb_eStandardError);
	
	/*
	 * Init components
	 */
	Init_ossl_bn();
	Init_ossl_cipher();
	Init_ossl_config(mOSSL);
	Init_ossl_digest();
	Init_ossl_hmac(mOSSL);
	Init_ossl_pkcs7(mPKCS7);
	Init_ossl_pkey(mPKey);
	Init_ossl_rand(mRandom);
	Init_ossl_spki(mNetscape);
	Init_ossl_ssl(mSSL);
	Init_ossl_x509();
}

#if defined(OSSL_DEBUG)
/*
 * Check if all symbols are OK with 'make LDSHARED=gcc all'
 */
int
main(int argc, char *argv[], char *env[])
{
	return 0;
}
#endif /* OSSL_DEBUG */


/*
 * $Id$
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001 Michal Rokos <m.rokos@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#include "ossl.h"

#ifdef WIN32
#  define strncasecmp _strnicmp
#endif

/*
 * On Windows platform there is no strptime function
 * implementation in strptime.c
 */
#ifndef HAVE_STRPTIME
#  include "./missing/strptime.c"
/*
#else
#  define _XOPEN_SOURCE * glibc2 needs this *
#  include <features.h>
#  include <time.h>
 */
#endif

/*
 * Check Types
 */
void
ossl_check_kind(VALUE obj, VALUE klass)
{
	if (rb_obj_is_kind_of(obj, klass) == Qfalse)
		rb_raise(rb_eTypeError, "wrong argument (%s)! (Expected kind of %s)",
				rb_class2name(CLASS_OF(obj)), rb_class2name(klass));
}

void
ossl_check_instance(VALUE obj, VALUE klass)
{
	if (rb_obj_is_instance_of(obj, klass) == Qfalse)
		rb_raise(rb_eTypeError, "wrong argument (%s)! (Expected instance of %s)",
				rb_class2name(CLASS_OF(obj)), rb_class2name(klass));
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
 * Modules
 */
VALUE mOSSL;
VALUE mX509;
VALUE mDigest;
VALUE mCipher;
VALUE mPKey;
VALUE mNetscape;
VALUE mSSL;
VALUE mPKCS7;
VALUE mRandom;

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
	mX509 = rb_define_module_under(mOSSL, "X509");
	mDigest = rb_define_module_under(mOSSL, "Digest");
	mPKey = rb_define_module_under(mOSSL, "PKey");
	mNetscape = rb_define_module_under(mOSSL, "Netscape");
	mCipher = rb_define_module_under(mOSSL, "Cipher");
	mSSL = rb_define_module_under(mOSSL, "SSL");
	mPKCS7 = rb_define_module_under(mOSSL, "PKCS7");
	mRandom = rb_define_module_under(mOSSL, "Random");
	
	/*
	 * Constants
	 */
	rb_define_const(mOSSL, "VERSION", rb_str_new2(OSSL_VERSION));
	rb_define_const(mOSSL, "OPENSSL_VERSION", rb_str_new2(OPENSSL_VERSION_TEXT));
	
	/*
	 * Components
	 */
	Init_ossl_config(mOSSL);
	Init_ossl_x509(mX509);
	Init_ossl_x509name(mX509);
	Init_ossl_x509revoked(mX509);
	Init_ossl_x509crl(mX509);
	Init_ossl_x509store(mX509);
	Init_ossl_digest(mDigest);
	Init_ossl_x509req(mX509);
	Init_ossl_x509ext(mX509);
	Init_ossl_x509attr(mX509);
	Init_ossl_spki(mNetscape);
	Init_ossl_cipher(mCipher);
	Init_ossl_rand(mRandom);
	Init_ossl_pkey(mPKey);
	Init_ssl(mSSL);
	Init_pkcs7(mPKCS7);
	Init_hmac(mOSSL);
	Init_bn(mOSSL);
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


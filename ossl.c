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
#include <openssl/err.h>
#include "ossl.h"

void ossl_check_type(VALUE obj, VALUE klass)
{
	if (rb_obj_is_kind_of(obj, klass) == Qfalse) {
		rb_raise(rb_eTypeError, "wrong argument (%s)! (Expected %s)",
		rb_class2name(CLASS_OF(obj)), rb_class2name(klass));
	}
}

char *ossl_error(void)
{
	return ERR_error_string(ERR_get_error(), NULL);
}

VALUE asn1time_to_time(ASN1_UTCTIME *time)
{
	struct tm tm;

	switch(time->type) {
		case V_ASN1_UTCTIME:
			if (!strptime(time->data, "%y%m%d%H%M%S", &tm)) {
				rb_raise(rb_eTypeError, "bad UTCTIME format");
			}
			break;
		case V_ASN1_GENERALIZEDTIME:
			if (!strptime(time->data, "%Y%m%d%H%M%S", &tm)) {
				rb_raise(rb_eTypeError, "bad GENERALIZEDTIME format" );
			}
			break;
		default:
			rb_raise(rb_eTypeError, "unknown time format");
	}
	
	return rb_time_new(mktime(&tm), 0);
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

/*
 * OSSL library init
 */
void Init_openssl()
{
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	/*
	 * Universe of Module
	 */
	mOSSL = rb_define_module("OpenSSL");
	mX509 = rb_define_module_under(mOSSL, "X509");
	mDigest = rb_define_module_under(mOSSL, "Digest");
	mPKey = rb_define_module_under(mOSSL, "PKey");
	mNetscape = rb_define_module_under(mOSSL, "Netscape");
	mCipher = rb_define_module_under(mOSSL, "Cipher");
	mSSL = rb_define_module_under(mOSSL, "SSL");
	mPKCS7 = rb_define_module_under(mOSSL, "PKCS7");
	
	/*
	 * Components
	 */
	/* Init_ossl_config(mOSSL); TO BE DROPPED OUT??? */
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
	Init_ossl_rand(mOSSL);
	Init_ossl_pkey(mPKey);
	Init_ssl(mSSL);
	Init_PKCS7(mPKCS7);
}


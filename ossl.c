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
#include <stdarg.h> /* for ossl_raise */

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
	if (rb_obj_is_kind_of(obj, klass) != Qtrue) {
		rb_raise(rb_eTypeError, "wrong argument (%s)! (Expected kind of %s)", \
				rb_class2name(CLASS_OF(obj)), rb_class2name(klass));
	}
}

void
ossl_check_instance(VALUE obj, VALUE klass)
{
	if (rb_obj_is_instance_of(obj, klass) != Qtrue) {
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
	/*
	 * QUESTION:
	 * return rb_time_new(mktime(gmtime(mktime(&tm))), 0);
	 * Is this better than following?
	 */
	return rb_time_new(mktime(&tm), 0);
}

/*
 * This function is not exported in Ruby's *.h
 */
extern struct timeval rb_time_timeval(VALUE time);

time_t
time_to_time_t(VALUE time)
{
	struct timeval t = rb_time_timeval(time);
	
	return t.tv_sec;
}

/*
 * String to HEXString conversion
 */
int
string2hex(char *buf, int buf_len, char **hexbuf, int *hexbuf_len)
{
	static const char hex[]="0123456789abcdef";
	int i, len = 2 * buf_len;

	if (buf_len < 0 || len < buf_len) { /* PARANOIA? */
		return -1;
	}
	if (!hexbuf) {
		if (hexbuf_len) {
			*hexbuf_len = len;
		}
		return len;
	}
	if (!(*hexbuf = OPENSSL_malloc(len + 1))) {
		return -1;
	}
	for (i = 0; i < buf_len; i++) {
		(*hexbuf)[2 * i] = hex[((unsigned char)buf[i]) >> 4];
		(*hexbuf)[2 * i + 1] = hex[buf[i] & 0x0f];
	}
	(*hexbuf)[2 * i] = '\0';
	
	if (hexbuf_len) {
		*hexbuf_len = len;
	}
	return len;
}

/*
 * main module
 */
VALUE mOSSL;

/*
 * OpenSSLError < StandardError
 */
VALUE eOSSLError;

/*
 * Errors
 */
void
ossl_raise(VALUE exc, const char *fmt, ...)
{
	va_list args;
	char buf[BUFSIZ];
	int len;
	long e = ERR_get_error();

	va_start(args, fmt);
	len = vsnprintf(buf, BUFSIZ, fmt, args);
	va_end(args);
	
	if (e) {
		if (dOSSL == Qtrue) { /* FULL INFO */
			len += snprintf(buf + len, BUFSIZ - len, "%s", ERR_error_string(e, NULL));
		} else {
			len += snprintf(buf + len, BUFSIZ - len, "%s", ERR_reason_error_string(e));
		}
	}
	rb_exc_raise(rb_exc_new(exc, buf, len));
}

/*
 * Debug
 */
VALUE dOSSL;

static VALUE
ossl_debug_get(VALUE self)
{
	return dOSSL;
}

static VALUE
ossl_debug_set(VALUE self, VALUE val)
{
	VALUE old = dOSSL;
	dOSSL = val;
	
	if (old != dOSSL) {
		if (dOSSL == Qtrue) {
			CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
			fprintf(stderr, "OSSL_DEBUG: IS NOW ON!\n");
		} else if (old == Qtrue) {
			CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_OFF);
			fprintf(stderr, "OSSL_DEBUG: IS NOW OFF!\n");
		}
	}
	return val;
}

/*
 * OSSL library init
 */
void
Init_openssl()
{
	/*
	 * Init all digests, ciphers
	 */
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	/*
	 * Init main module
	 */
	mOSSL = rb_define_module("OpenSSL");
	
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
	 * Init debug core
	 */
	dOSSL = Qfalse;
	rb_define_module_function(mOSSL, "debug", ossl_debug_get, 0);
	rb_define_module_function(mOSSL, "debug=", ossl_debug_set, 1);

	/*
	 * Init components
	 */
	Init_ossl_bn();
	Init_ossl_cipher();
	Init_ossl_config();
	Init_ossl_digest();
	Init_ossl_hmac();
	Init_ossl_ns_spki();
	Init_ossl_pkcs7();
	Init_ossl_pkey();
	Init_ossl_rand();
	Init_ossl_ssl();
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


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
#include "ossl.h"
#include <stdarg.h> /* for ossl_raise */

#if defined(HAVE_SYS_TIME_H)
#  include <sys/time.h>
#elif !defined(NT) && !defined(_WIN32)
struct timeval {
    long tv_sec;	/* seconds */
    long tv_usec;	/* and microseconds */
};
#endif

/*
 * DATE conversion
 */
VALUE
asn1time_to_time(ASN1_TIME *time)
{
    struct tm tm;
    VALUE argv[6];
    
    if (!time) {
	ossl_raise(rb_eTypeError, "ASN1_TIME is NULL!");
    }
    memset(&tm, 0, sizeof(struct tm));
	
    switch(time->type) {
    case V_ASN1_UTCTIME:
	if (sscanf(time->data, "%2d%2d%2d%2d%2d%2dZ", &tm.tm_year, &tm.tm_mon,
    		&tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6) {
	    ossl_raise(rb_eTypeError, "bad UTCTIME format");
	} 
	if (tm.tm_year < 69) {
	    tm.tm_year += 2000;
	} else {
	    tm.tm_year += 1900;
	}
	tm.tm_mon -= 1;
	break;
    case V_ASN1_GENERALIZEDTIME:
	if (sscanf(time->data, "%4d%2d%2d%2d%2d%2dZ", &tm.tm_year, &tm.tm_mon,
    		&tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6) {
	    ossl_raise(rb_eTypeError, "bad GENERALIZEDTIME format" );
	} 
	tm.tm_mon -= 1;
	break;
    default:
	ossl_raise(rb_eTypeError, "unknown time format");
    }
//    return rb_time_new(mktime(&tm) - timezone, 0);
    argv[0] = INT2NUM(tm.tm_year);
    argv[1] = INT2NUM(tm.tm_mon+1);
    argv[2] = INT2NUM(tm.tm_mday);
    argv[3] = INT2NUM(tm.tm_hour);
    argv[4] = INT2NUM(tm.tm_min);
    argv[5] = INT2NUM(tm.tm_sec);

    return rb_funcall2(rb_cTime, rb_intern("utc"), 6, argv);
}

/*
 * This function is not exported in Ruby's *.h
 */
extern struct timeval rb_time_timeval(VALUE);

time_t
time_to_time_t(VALUE time)
{
    struct timeval t = rb_time_timeval(time);
    return t.tv_sec;
}

/*
 * ASN1_INTEGER conversions
 * TODO: Make a decision what's the right way to do this.
 */
#define DO_IT_VIA_RUBY 0
VALUE
asn1integer_to_num(ASN1_INTEGER *ai)
{
    BIGNUM *bn;
#if DO_IT_VIA_RUBY
    char *txt;
#endif
    VALUE num;

    if (!ai) {
	ossl_raise(rb_eTypeError, "ASN1_INTEGER is NULL!");
    }
    if (!(bn = ASN1_INTEGER_to_BN(ai, NULL))) {
	ossl_raise(eOSSLError, "");
    }
#if DO_IT_VIA_RUBY
    if (!(txt = BN_bn2dec(bn))) {
	BN_free(bn);
	ossl_raise(eOSSLError, "");
    }
    num = rb_cstr_to_inum(txt, 10, Qtrue);
    OPENSSL_free(txt);
#else
    num = ossl_bn_new(bn);
#endif
    BN_free(bn);

    return num;
}

#if 0
ASN1_INTEGER *num_to_asn1integer(VALUE obj, ASN1_INTEGER *ai)
{
    BIGNUM *bn = NULL;

    if (RTEST(rb_obj_is_kind_of(obj, cBN))) {
	bn = GetBNPtr(obj);
    } else {
	obj = rb_String(obj);
	if (!BN_dec2bn(&bn, StringValuePtr(obj))) {
	    ossl_raise(eOSSLError, "");
	}
    }
    if (!(ai = BN_to_ASN1_INTEGER(bn, ai))) {
	BN_free(bn);
	ossl_raise(eOSSLError, "");
    }
    BN_free(bn);
    return ai;
}
#else
ASN1_INTEGER *num_to_asn1integer(VALUE obj, ASN1_INTEGER *ai)
{
    BIGNUM *bn = GetBNPtr(obj);
    
    if (!(ai = BN_to_ASN1_INTEGER(bn, ai))) {
	ossl_raise(eOSSLError, "");
    }
    return ai;
}
#endif

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
    if (!hexbuf) { /* if no buf, return calculated len */
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
	    len += snprintf(buf+len, BUFSIZ-len, "%s",
			    ERR_error_string(e, NULL));
	} else {
	    len += snprintf(buf + len, BUFSIZ - len, "%s",
			    ERR_reason_error_string(e));
	}
	ERR_clear_error();
    }
    rb_exc_raise(rb_exc_new(exc, buf, len));
}

/*
 * Debug
 */
VALUE dOSSL;

#if defined(NT) || defined(_WIN32)
void ossl_debug(const char *fmt, ...)
{
    va_list args;
	
    if (dOSSL == Qtrue) {
	fprintf(stderr, "OSSL_DEBUG: ");
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fprintf(stderr, " [CONTEXT N/A]\n");
    }
}
#endif

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
     * Init timezone info
     *
    tzset();
     */

    /*
     * Init all digests, ciphers
     */
/*    CRYPTO_malloc_init(); */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
/*    ENGINE_load_builtin_engines(); */
    /*
     * FIXME:
     * On unload do:
    CONF_modules_unload(1);
    destroy_ui_method();
    EVP_cleanup();
    ENGINE_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_state(0);
    ERR_free_strings();
     */

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


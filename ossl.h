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
#if !defined(_OSSL_H_)
#define _OSSL_H_

#if defined(__cplusplus)
extern "C" {
#endif

/*
 * Check the Ruby version and OpenSSL
 * The only supported are:
 * 	Ruby >= 1.7.2
 * 	OpenSSL >= 0.9.7
 */
#include <version.h>
#include <openssl/opensslv.h>

#if (OPENSSL_VERSION_NUMBER < 0x00907000L) && (RUBY_VERSION_CODE < 172)
#  error ! OSSL2 needs Ruby >= 1.7.2 and OpenSSL >= 0.9.7 its run.
#endif

#if defined(NT)
#  define OpenFile WINAPI_OpenFile
#endif
#include <errno.h>
#include <openssl/err.h>
#include <openssl/asn1_mac.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#if defined(NT)
#  undef OpenFile
#endif

/*
 * OpenSSL has defined RFILE and Ruby has defined RFILE - so undef it!
 */
#if defined(RFILE) /*&& !defined(OSSL_DEBUG)*/
#  undef RFILE
#endif
#include <ruby.h>

/*
 * Common Module
 */
extern VALUE mOSSL;

/*
 * Common Error Class
 */
extern VALUE eOSSLError;

/*
 * GetRealClass
 * 
#define RCLASS_OF(obj) rb_obj_class((obj))
 */

/*
 * CheckTypes
 */
#define OSSL_Check_Kind(obj, klass) ossl_check_kind(obj, klass)
void ossl_check_kind(VALUE, VALUE);
#define OSSL_Check_Instance(obj, klass) ossl_check_instance(obj, klass)
void ossl_check_instance(VALUE, VALUE);

/*
 * DATE conversion
 */
VALUE asn1time_to_time(ASN1_TIME *);
time_t time_to_time_t(VALUE);

/*
 * String to HEXString conversion
 */
int string2hex(char *, int, char **, int *);

/*
 * ERRor messages
 */
#define OSSL_ErrMsg() \
	ERR_reason_error_string(ERR_get_error())

void ossl_raise(VALUE, const char *, ...);

/*
 * Debug
 */
extern VALUE dOSSL;

#if !defined(NT)
#  define OSSL_Debug(fmt, ...) do { \
	if (dOSSL == Qtrue) { \
		fprintf(stderr, "OSSL_DEBUG: "); \
		fprintf(stderr, fmt, ##__VA_ARGS__); \
		fprintf(stderr, " [in %s (%s:%d)]\n", __func__, __FILE__, __LINE__); \
	} \
} while (0)
#else
void ossl_debug(const char *, ...);
#  define OSSL_Debug ossl_debug
#endif

/*
 * Include all parts
 */
#include "openssl_missing.h"
#include "ossl_bn.h"
#include "ossl_cipher.h"
#include "ossl_config.h"
#include "ossl_digest.h"
#include "ossl_hmac.h"
#include "ossl_ns_spki.h"
#include "ossl_pkcs7.h"
#include "ossl_pkey.h"
#include "ossl_rand.h"
#include "ossl_ssl.h"
#include "ossl_version.h"
#include "ossl_x509.h"

#if defined(__cplusplus)
}
#endif

#endif /* _OSSL_H_ */


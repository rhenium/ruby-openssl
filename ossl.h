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

#if (OPENSSL_VERSION_NUMBER < 0x00907000L)
#  error ! This version of OSSL needs OpenSSL >= 0.9.7 for its run!
#endif

#if defined(NT) || defined(_WIN32)
#  define OpenFile WINAPI_OpenFile
#endif
#include <errno.h>
#include <openssl/err.h>
#include <openssl/asn1_mac.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#if defined(NT) || defined(_WIN32)
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
 * CheckTypes
 */
#define OSSL_Check_Kind(obj, klass) do {\
  if (!rb_obj_is_kind_of(obj, klass)) {\
    ossl_raise(rb_eTypeError, "wrong argument (%s)! (Expected kind of %s)",\
               rb_obj_classname(obj), rb_class2name(klass));\
  }\
} while (0)

#define OSSL_Check_Instance(obj, klass) do {\
  if (!rb_obj_is_instance_of(obj, klass)) {\
    ossl_raise(rb_eTypeError, "wrong argument (%s)! (Expected instance of %s)",\
               rb_obj_classname(obj), rb_class2name(klass));\
  }\
} while (0)

#define OSSL_Check_Same_Class(obj1, obj2) do {\
  if (!rb_obj_is_instance_of(obj1, rb_obj_class(obj2))) {\
    ossl_raise(rb_eTypeError, "wrong argument type");\
  }\
} while (0)

/*
 * ASN1_DATE conversions
 */
VALUE asn1time_to_time(ASN1_TIME *);
time_t time_to_time_t(VALUE);

/*
 * ASN1_INTEGER conversions
 */
VALUE asn1integer_to_num(ASN1_INTEGER *);
ASN1_INTEGER *num_to_asn1integer(VALUE, ASN1_INTEGER *);

/*
 * String to HEXString conversion
 */
int string2hex(char *, int, char **, int *);

/*
 * our default PEM callback
 */
int ossl_pem_passwd_cb(char *, int, int, void *);

/*
 * ERRor messages
 */
#define OSSL_ErrMsg() ERR_reason_error_string(ERR_get_error())
void ossl_raise(VALUE, const char *, ...);

/*
 * Verify callback
 */
extern int ossl_verify_cb_idx;

struct ossl_verify_cb_args {
    VALUE proc;
    VALUE preverify_ok;
    VALUE store_ctx;
};

VALUE ossl_call_verify_cb_proc(struct ossl_verify_cb_args *);
int ossl_verify_cb(int, X509_STORE_CTX *);

/*
 * Debug
 */
extern VALUE dOSSL;

#if defined(__GNUC__) || __STDC_VERSION__ >= 199901L
#define OSSL_Debug(fmt, ...) do { \
  if (dOSSL == Qtrue) { \
    fprintf(stderr, "OSSL_DEBUG: "); \
    fprintf(stderr, fmt, ##__VA_ARGS__); \
    fprintf(stderr, " [in %s (%s:%d)]\n", __func__, __FILE__, __LINE__); \
  } \
} while (0)

#define OSSL_Warning(fmt, ...) do { \
  OSSL_Debug(fmt, ##__VA_ARGS__); \
  rb_warning(fmt, ##__VA_ARGS__); \
} while (0)

#define OSSL_Warn(fmt, ...) do { \
  OSSL_Debug(fmt, ##__VA_ARGS__); \
  rb_warn(fmt, ##__VA_ARGS__); \
} while (0)
#else
void ossl_debug(const char *, ...);
#define OSSL_Debug ossl_debug
#define OSSL_Warning rb_warning
#define OSSL_Warn rb_warn
#endif /* __GNUC__ || _STDC_VERSION__ >= 199901L */

/*
 * Include all parts
 */
#include "openssl_missing.h"
#include "ruby_missing.h"
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


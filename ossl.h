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
#include <openssl/bn_lcl.h>
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
extern VALUE   mNetscape;
extern VALUE   mPKCS7;
extern VALUE   mPKey;
extern VALUE   mRandom;
extern VALUE   mSSL;

/*
 * Common Error Class
 */
VALUE eOSSLError;

/*
 * Classes
 */
extern VALUE cSPKI;
extern VALUE eSPKIError;
extern VALUE eRandomError;
extern VALUE cSSLSocket;
extern VALUE eSSLError;
/* PKey */
extern ID id_private_q;
extern VALUE cPKey;
extern VALUE ePKeyError;
extern VALUE cRSA;
extern VALUE eRSAError;
extern VALUE cDSA;
extern VALUE eDSAError;
extern VALUE cDH;
extern VALUE eDHError;
/* PKCS7 */
extern VALUE cPKCS7;
extern VALUE cPKCS7SignerInfo;
extern VALUE ePKCS7Error;
/* HMAC */
extern VALUE cHMAC;
extern VALUE eHMACError;

/*
 * CheckTypes
 */
#define OSSL_Check_Kind(obj, klass) ossl_check_kind(obj, klass)
#define OSSL_Check_Type(obj, klass) ossl_check_kind(obj, klass)
void ossl_check_kind(VALUE, VALUE);
#define OSSL_Check_Instance(obj, klass) ossl_check_instance(obj, klass)
void ossl_check_instance(VALUE, VALUE);

/*
 * DATE conversion
 */
VALUE asn1time_to_time(ASN1_UTCTIME *);
time_t time_to_time_t(VALUE);

/*
 * ERRor messages
 */
#define OSSL_ErrMsg() \
	ERR_error_string(ERR_get_error(), NULL)

#if defined(OSSL_DEBUG)
#  define OSSL_Raise(klass, text) \
	rb_raise(klass, "%s%s [in '%s', ('%s':%d)]", \
			text, OSSL_ErrMsg(), __func__, __FILE__, __LINE__)
#  define OSSL_Warn(text) \
	rb_warn("%s%s [in '%s', ('%s':%d)]", \
			text, OSSL_ErrMsg(), __func__, __FILE__, __LINE__)
#  define OSSL_Warning(text) \
	rb_warning("%s%s [in '%s', ('%s':%d)]", \
			text, OSSL_ErrMsg(), __func__, __FILE__, __LINE__)
#else /* OSSL_DEBUG */
#  define OSSL_Raise(klass, text) \
	rb_raise(klass, "%s%s", text, OSSL_ErrMsg())
#  define OSSL_Warn(text) \
	rb_warn("%s%s", text, OSSL_ErrMsg())
#  define OSSL_Warning(text) \
	rb_warning("%s%s", text, OSSL_ErrMsg())
#endif /* OSSL_DEBUG */

/*
 * Netscape SPKI
 */
void Init_ossl_spki(VALUE);

/*
 * RAND - module methods only
 */
void Init_ossl_rand(VALUE);

/*
 * PKey
 */
VALUE ossl_pkey_new(EVP_PKEY *);
VALUE ossl_pkey_new_from_file(VALUE);
EVP_PKEY *ossl_pkey_get_EVP_PKEY(VALUE);
void Init_ossl_pkey(VALUE);

/*
 * RSA
 */
#if !defined(OPENSSL_NO_RSA)
VALUE ossl_rsa_new(RSA *);
RSA *ossl_rsa_get_RSA(VALUE);
EVP_PKEY *ossl_rsa_get_EVP_PKEY(VALUE);
#endif /* NO_RSA */
void Init_ossl_rsa(VALUE, VALUE, VALUE);

/*
 * DSA
 */
#if !defined(OPENSSL_NO_DSA)
VALUE ossl_dsa_new(DSA *);
DSA *ossl_dsa_get_DSA(VALUE);
EVP_PKEY *ossl_dsa_get_EVP_PKEY(VALUE);
#endif /* NO_DSA */
void Init_ossl_dsa(VALUE, VALUE, VALUE);

/*
 * DH
 */
#if !defined(OPENSSL_NO_DH)
VALUE ossl_dh_new(DH *);
DH *ossl_dh_get_DH(VALUE);
EVP_PKEY *ossl_dh_get_EVP_PKEY(VALUE);
#endif /* NO_DH */
void Init_ossl_dh(VALUE, VALUE, VALUE);

/*
 * SSL
 */
void Init_ossl_ssl(VALUE);

/*
 * PKCS7
 */
VALUE ossl_pkcs7si_new(PKCS7_SIGNER_INFO *);
PKCS7_SIGNER_INFO *ossl_pkcs7si_get_PKCS7_SIGNER_INFO(VALUE);
void Init_ossl_pkcs7(VALUE);

/*
 * HMAC
 */
void Init_ossl_hmac(VALUE);

#include "openssl_missing.h"
#include "ossl_bn.h"
#include "ossl_cipher.h"
#include "ossl_config.h"
#include "ossl_digest.h"
/*
 * TODO
#include "ossl_hmac.h"
#include "ossl_pkcs7.h"
#include "ossl_pkey.h"
#include "ossl_rand.h"
#include "ossl_spki.h"
#include "ossl_ssl.h"
 */
#include "ossl_version.h"
#include "ossl_x509.h"

#if defined(__cplusplus)
}
#endif

#endif /* _OSSL_H_ */


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
#ifndef _OSSL_H_
#define _OSSL_H_

#ifdef  __cplusplus
extern "C" {
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

#include "openssl_missing.h"
#include "ossl_version.h"

/*
 * OpenSSL has defined RFILE and Ruby has defined RFILE - so undef it!
 */
#if defined(RFILE) /*&& !defined(OSSL_DEBUG)*/
#  undef RFILE
#endif
#include <ruby.h>

/*
 * Modules
 */
extern VALUE mOSSL;
extern VALUE mX509;
extern VALUE mDigest;
extern VALUE mPKey;
extern VALUE mNetscape;
extern VALUE mCipher;
extern VALUE mSSL;
extern VALUE mPKCS7;
extern VALUE mRandom;

/*
 * Classes
 */
extern VALUE cX509Certificate;
extern VALUE eX509CertificateError;
extern VALUE cX509Attribute;
extern VALUE eX509AttributeError;
extern VALUE cX509CRL;
extern VALUE eX509CRLError;
extern VALUE cX509Extension;
extern VALUE cX509ExtensionFactory;
extern VALUE eX509ExtensionError;
extern VALUE cX509Name;
extern VALUE eX509NameError;
extern VALUE cX509Request;
extern VALUE eX509RequestError;
extern VALUE cX509Revoked;
extern VALUE eX509RevokedError;
extern VALUE cX509Store;
extern VALUE eX509StoreError;
extern VALUE cSPKI;
extern VALUE eSPKIError;
extern VALUE eRandomError;
extern VALUE cSSLSocket;
extern VALUE eSSLError;
/* Cipher */
extern VALUE cCipher;
extern VALUE eCipherError;
extern VALUE cDES, cRC4, cIdea, cRC2, cBlowFish, cCast5, cRC5, cAES;
/* Digest */
extern VALUE cDigest;
extern VALUE eDigestError;
extern VALUE cMD2, cMD4, cMD5, cMDC2, cRIPEMD160, cSHA, cSHA1, cDSS, cDSS1;
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
/* Conf */
extern VALUE cConfig;
extern VALUE eConfigError;
/* BN */
extern VALUE cBN;
extern VALUE eBNError;

/*
 * CheckTypes
 */
#define OSSL_Check_Kind(obj, klass) ossl_check_kind(obj, klass)
void ossl_check_kind(VALUE, VALUE);
#define OSSL_Check_Instance(obj, klass) ossl_check_instance(obj, klass)
void ossl_check_instance(VALUE, VALUE);
#define OSSL_Check_Type OSSL_Check_Kind /* COMPAT */

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
#  define OSSL_Raise(klass,text) \
	rb_raise(klass, "%s%s [in '%s', ('%s':%d)]", \
			text, OSSL_ErrMsg(), __func__, __FILE__, __LINE__)
#  define OSSL_Warn(text) \
	rb_warn("%s%s [in '%s', ('%s':%d)]", \
			text, OSSL_ErrMsg(), __func__, __FILE__, __LINE__)
#  define OSSL_Warning(text) \
	rb_warning("%s%s [in '%s', ('%s':%d)]", \
			text, OSSL_ErrMsg(), __func__, __FILE__, __LINE__)
#else /*OSSL_DEBUG*/
#  define OSSL_Raise(klass,text) \
	rb_raise(klass, "%s%s", text, OSSL_ErrMsg())
#  define OSSL_Warn(text) \
	rb_warn("%s%s", text, OSSL_ErrMsg())
#  define OSSL_Warning(text) \
	rb_warning("%s%s", text, OSSL_ErrMsg())
#endif /*OSSL_DEBUG*/

/*
 * Config
 */
void Init_ossl_config(VALUE);

/*
 * Digest
 */
int ossl_digest_get_NID(VALUE);
const EVP_MD *ossl_digest_get_EVP_MD(VALUE);
void Init_ossl_digest(VALUE);

/*
 * X509
 */
VALUE ossl_x509_new(X509 *);
VALUE ossl_x509_new_from_file(VALUE);
X509 *ossl_x509_get_X509(VALUE);
void Init_ossl_x509(VALUE);

/*
 * X509CRL
 */
X509_CRL *ossl_x509crl_get_X509_CRL(VALUE);
void Init_ossl_x509crl(VALUE);

/*
 * X509Name
 */
VALUE ossl_x509name_new(X509_NAME *);
X509_NAME *ossl_x509name_get_X509_NAME(VALUE);
void Init_ossl_x509name(VALUE);

/*
 * X509Request
 */
VALUE ossl_x509req_new(X509_REQ *);
X509_REQ *ossl_x509req_get_X509_REQ(VALUE);
void Init_ossl_x509req(VALUE);

/*
 * X509Revoked
 */
VALUE ossl_x509revoked_new(X509_REVOKED *);
X509_REVOKED *ossl_x509revoked_get_X509_REVOKED(VALUE);
void Init_ossl_x509revoked(VALUE);

/*
 * X509Store
 */
VALUE ossl_x509store_new(X509_STORE_CTX *);
X509_STORE *ossl_x509store_get_X509_STORE(VALUE);
void Init_ossl_x509store(VALUE);

/*
 * X509Extension
 */
VALUE ossl_x509ext_new(X509_EXTENSION *);
X509_EXTENSION *ossl_x509ext_get_X509_EXTENSION(VALUE);
void Init_ossl_x509ext(VALUE);

/*
 * X509Attribute
 */
VALUE ossl_x509attr_new(X509_ATTRIBUTE *);
X509_ATTRIBUTE *ossl_x509attr_get_X509_ATTRIBUTE(VALUE);
void Init_ossl_x509attr(VALUE);

/*
 * Netscape SPKI
 */
void Init_ossl_spki(VALUE);

/*
 * Ciphers
 */
int ossl_cipher_get_NID(VALUE);
const EVP_CIPHER *ossl_cipher_get_EVP_CIPHER(VALUE);
void Init_ossl_cipher(VALUE);

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
#if !defined(NO_RSA) && !defined(OPENSSL_NO_RSA)
VALUE ossl_rsa_new(RSA *);
RSA *ossl_rsa_get_RSA(VALUE);
EVP_PKEY *ossl_rsa_get_EVP_PKEY(VALUE);
#endif /* NO_RSA */
void Init_ossl_rsa(VALUE, VALUE, VALUE);

/*
 * DSA
 */
#if !defined(NO_DSA) && !defined(OPENSSL_NO_DSA)
VALUE ossl_dsa_new(DSA *);
DSA *ossl_dsa_get_DSA(VALUE);
EVP_PKEY *ossl_dsa_get_EVP_PKEY(VALUE);
#endif /* NO_DSA */
void Init_ossl_dsa(VALUE, VALUE, VALUE);

/*
 * DH
 */
#if !defined(NO_DH) && !defined(OPENSSL_NO_DH)
VALUE ossl_dh_new(DH *);
DH *ossl_dh_get_DH(VALUE);
EVP_PKEY *ossl_dh_get_EVP_PKEY(VALUE);
#endif /* NO_DH */
void Init_ossl_dh(VALUE, VALUE, VALUE);

/*
 * SSL
 */
void Init_ssl(VALUE);

/*
 * PKCS7
 */
VALUE ossl_pkcs7si_new(PKCS7_SIGNER_INFO *);
PKCS7_SIGNER_INFO *ossl_pkcs7si_get_PKCS7_SIGNER_INFO(VALUE);
void Init_pkcs7(VALUE);

/*
 * HMAC
 */
void Init_hmac(VALUE);

/*
 * BN
 */
VALUE ossl_bn_new(BIGNUM *);
BIGNUM *ossl_bn_get_BIGNUM(VALUE);
void Init_bn(VALUE);

#ifdef  __cplusplus
}
#endif

#endif /*_OSSL_H_*/


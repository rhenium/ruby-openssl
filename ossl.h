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
#ifndef _OSSL_H_
#define _OSSL_H_

#include <errno.h>
#include <openssl/asn1_mac.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "openssl_missing.h"
#include "ossl_version.h"

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * OpenSSL has defined RFILE and Ruby has defined RFILE - so undef it!
 */
#if !defined(OSSL_DEBUG) && defined(RFILE)
#  undef RFILE
#endif
#include <ruby.h>

/*
 * Modules
 */
EXTERN VALUE mOSSL;
EXTERN VALUE mX509;
EXTERN VALUE mDigest;
EXTERN VALUE mPKey;
EXTERN VALUE mNetscape;
EXTERN VALUE mCipher;
EXTERN VALUE mSSL;
EXTERN VALUE mPKCS7;

/*
 * Classes
 */
EXTERN VALUE cX509Certificate;
EXTERN VALUE eX509CertificateError;
EXTERN VALUE cX509Attribute;
EXTERN VALUE eX509AttributeError;
EXTERN VALUE cX509CRL;
EXTERN VALUE eX509CRLError;
EXTERN VALUE cX509Extension;
EXTERN VALUE cX509ExtensionFactory;
EXTERN VALUE eX509ExtensionError;
EXTERN VALUE cX509Name;
EXTERN VALUE eX509NameError;
EXTERN VALUE cX509Request;
EXTERN VALUE eX509RequestError;
EXTERN VALUE cX509Revoked;
EXTERN VALUE eX509RevokedError;
EXTERN VALUE cX509Store;
EXTERN VALUE eX509StoreError;
EXTERN VALUE cSPKI;
EXTERN VALUE eSPKIError;
EXTERN VALUE cCipher;
EXTERN VALUE eCipherError;
EXTERN VALUE cRandom;
EXTERN VALUE eRandomError;
EXTERN VALUE cSSLSocket;
EXTERN VALUE eSSLError;
/* Digest */
EXTERN VALUE cDigest;
EXTERN VALUE eDigestError;
EXTERN VALUE cMD2;
EXTERN VALUE cMD5;
EXTERN VALUE cMDC2;
EXTERN VALUE cRIPEMD160;
EXTERN VALUE cSHA;
EXTERN VALUE cSHA1;
EXTERN VALUE cDSS;
EXTERN VALUE cDSS1;
/* PKey */
EXTERN VALUE cPKey;
EXTERN VALUE ePKeyError;
EXTERN VALUE cRSA;
EXTERN VALUE eRSAError;
EXTERN VALUE cDSA;
/* PKCS7 */
EXTERN VALUE cPKCS7;
EXTERN VALUE cPKCS7SignerInfo;
EXTERN VALUE ePKCS7Error;
/* HMAC */
EXTERN VALUE cHMAC;
EXTERN VALUE eHMACError;
/* Conf */
EXTERN VALUE cConfig;
EXTERN VALUE eConfigError;
/* BN */
EXTERN VALUE cBN;
EXTERN VALUE eBNError;

/*
 * CheckTypes
 */
#define OSSL_Check_Type(obj, klass) ossl_check_type(obj, klass)
void ossl_check_type(VALUE, VALUE);

/*
 * DATE conversion
 */
VALUE asn1time_to_time(ASN1_UTCTIME *);

/*
 * ERRor messages
 */
char *ossl_error(void);

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
VALUE ossl_x509_new2(X509 *);
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
VALUE ossl_x509name_new2(X509_NAME *);
X509_NAME *ossl_x509name_get_X509_NAME(VALUE);
void Init_ossl_x509name(VALUE);

/*
 * X509Request
 */
VALUE ossl_x509req_new2(X509_REQ *);
X509_REQ *ossl_x509req_get_X509_REQ(VALUE);
void Init_ossl_x509req(VALUE);

/*
 * X509Revoked
 */
VALUE ossl_x509revoked_new2(X509_REVOKED *);
X509_REVOKED *ossl_x509revoked_get_X509_REVOKED(VALUE);
void Init_ossl_x509revoked(VALUE);

/*
 * X509Store
 */
VALUE ossl_x509store_new2(X509_STORE_CTX *);
X509_STORE *ossl_x509store_get_X509_STORE(VALUE);
void Init_ossl_x509store(VALUE);

/*
 * X509Extension
 */
VALUE ossl_x509ext_new2(X509_EXTENSION *);
X509_EXTENSION *ossl_x509ext_get_X509_EXTENSION(VALUE);
void Init_ossl_x509ext(VALUE);

/*
 * X509Attribute
 */
VALUE ossl_x509attr_new2(X509_ATTRIBUTE *);
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
VALUE ossl_rsa_new_null();
VALUE ossl_rsa_new(RSA *);
RSA *ossl_rsa_get_RSA(VALUE);
EVP_PKEY *ossl_rsa_get_EVP_PKEY(VALUE);
void Init_ossl_rsa(VALUE, VALUE, VALUE);

/*
 * DSA
 */
VALUE ossl_dsa_new_null();
VALUE ossl_dsa_new(DSA *);
DSA *ossl_dsa_get_DSA(VALUE);
EVP_PKEY *ossl_dsa_get_EVP_PKEY(VALUE);
void Init_ossl_dsa(VALUE, VALUE, VALUE);

/*
 * SSL
 */
void Init_ssl(VALUE);

/*
 * PKCS7
 */
VALUE ossl_pkcs7si_new_null(void);
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
VALUE ossl_bn_new_null(void);
VALUE ossl_bn_new(BIGNUM *);
BIGNUM *ossl_bn_get_BIGNUM(VALUE);
void Init_bn(VALUE);

#ifdef  __cplusplus
}
#endif

#endif


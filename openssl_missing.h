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
#ifndef _OPENSSL_MISSING_H_
#define _OPENSSL_MISSING_H_

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * These functions are not included in headers of OPENSSL <= 0.9.6b
 */

/* to pem.h */
#if !(NO_DSA) && !(OPENSSL_NO_DSA)
#define PEM_read_bio_DSAPublicKey(bp,x,cb,u) (DSA *)PEM_ASN1_read_bio( \
        (char *(*)())d2i_DSAPublicKey,PEM_STRING_DSA_PUBLIC,bp,(char **)x,cb,u)
#define PEM_write_bio_DSAPublicKey(bp,x) \
	PEM_ASN1_write_bio((int (*)())i2d_DSAPublicKey,\
		PEM_STRING_DSA_PUBLIC,\
		bp,(char *)x, NULL, NULL, 0, NULL, NULL)
#endif /* NO_DSA */

/* to x509.h */
#if !(NO_DSA) && !(OPENSSL_NO_DSA)
#define DSAPrivateKey_dup(dsa) (DSA *)ASN1_dup((int (*)())i2d_DSAPrivateKey, \
	(char *(*)())d2i_DSAPrivateKey,(char *)dsa)
#define DSAPublicKey_dup(dsa) (DSA *)ASN1_dup((int (*)())i2d_DSAPublicKey, \
	(char *(*)())d2i_DSAPublicKey,(char *)dsa)
#endif /* NO_DSA */
#define X509_REVOKED_dup(rev) (X509_REVOKED *)ASN1_dup((int (*)())i2d_X509_REVOKED, \
	(char *(*)())d2i_X509_REVOKED, (char *)rev)

/* to pkcs7.h */
#define PKCS7_SIGNER_INFO_dup(si) (PKCS7_SIGNER_INFO *)ASN1_dup((int (*)())i2d_PKCS7_SIGNER_INFO, \
	(char *(*)())d2i_PKCS7_SIGNER_INFO, (char *)si)
#define PKCS7_RECIP_INFO_dup(ri) (PKCS7_RECIP_INFO *)ASN1_dup((int (*)())i2d_PKCS7_RECIP_INFO, \
	(char *(*)())d2i_PKCS7_RECIP_INFO, (char *)ri)

/* to hmac.[ch] */
#if !defined(NO_HMAC) && !defined(OPENSSL_NO_HMAC)
int HMAC_CTX_copy(HMAC_CTX *out, HMAC_CTX *in);
#endif /* NO_HMAC */

#ifdef  __cplusplus
}
#endif

#endif /*_OPENSSL_MISSING_H_*/


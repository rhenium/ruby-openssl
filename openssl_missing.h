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
#ifndef _OPENSSL_MISSING_H_
#define _OPENSSL_MISSING_H_
/*
 * These functions are not included in headers of OPENSSL <= 0.9.6b
 */

/* to pem.h */
#define PEM_read_bio_DSAPublicKey(bp,x,cb,u) (DSA *)PEM_ASN1_read_bio( \
        (char *(*)())d2i_DSAPublicKey,PEM_STRING_DSA_PUBLIC,bp,(char **)x,cb,u)
#define PEM_write_bio_DSAPublicKey(bp,x) \
	PEM_ASN1_write_bio((int (*)())i2d_DSAPublicKey,\
		PEM_STRING_DSA_PUBLIC,\
		bp,(char *)x,NULL,NULL,0,NULL,NULL)

/* to x509.h */
#define DSAPrivateKey_dup(dsa) (DSA *)ASN1_dup((int (*)())i2d_DSAPrivateKey, \
	(char *(*)())d2i_DSAPrivateKey,(char *)dsa)
#define DSAPublicKey_dup(dsa) (DSA *)ASN1_dup((int (*)())i2d_DSAPublicKey, \
	(char *(*)())d2i_DSAPublicKey,(char *)dsa)

/* to pkcs7.h */
#define PKCS7_SIGNER_INFO_dup(si) (PKCS7_SIGNER_INFO *)ASN1_dup((int (*)())i2d_PKCS7_SIGNER_INFO, \
	(char *(*)())d2i_PKCS7_SIGNER_INFO,(char *)si)
#define PKCS7_RECIP_INFO_dup(ri) (PKCS7_RECIP_INFO *)ASN1_dup((int (*)())i2d_PKCS7_RECIP_INFO, \
	(char *(*)())d2i_PKCS7_RECIP_INFO,(char *)ri)

#endif


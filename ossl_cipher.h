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
#if !defined(_OSSL_CIPHER_H_)
#define _OSSL_CIPHER_H_

extern VALUE mCipher;
extern VALUE cCipher;
extern VALUE eCipherError;
extern VALUE cDES, cRC4, cIdea, cRC2, cBlowFish, cCast5, cRC5, cAES;

#define OSSLCipherValue(obj) OSSL_Check_Instance((obj), cCipher)
#define OSSLCipherValuePtr(obj) ossl_cipher_get_EVP_CIPHER((obj))

int ossl_cipher_get_NID(VALUE);
const EVP_CIPHER *ossl_cipher_get_EVP_CIPHER(VALUE);
void Init_ossl_cipher(void);

#endif /* _OSSL_DIGEST_H_ */


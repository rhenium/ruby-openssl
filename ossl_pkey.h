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
#ifndef _OSSL_PKEY_H_
#define _OSSL_PKEY_H_

/*
 * Struct
 */
typedef struct ossl_pkey_st {
	EVP_PKEY *(*get_EVP_PKEY)(VALUE);
} ossl_pkey;

#endif


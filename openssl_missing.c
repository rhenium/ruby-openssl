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
#include <openssl/hmac.h>
#include "openssl_missing.h"

/* to hmac.[ch] */
#ifndef NO_HMAC
int
HMAC_CTX_copy(HMAC_CTX *out, HMAC_CTX *in)
{
	if (in == NULL) {
        	/* HMACerr(HMAC_CTX_COPY,HMAC_R_INPUT_NOT_INITIALIZED); */
        	return 0;
    	}

	memcpy(out, in, sizeof(HMAC_CTX));

	return 1;
}
#endif


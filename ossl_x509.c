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
#include "ossl.h"

VALUE mX509;

void
Init_ossl_x509()
{
    mX509 = rb_define_module_under(mOSSL, "X509");

    Init_ossl_x509attr();
    Init_ossl_x509cert();
    Init_ossl_x509crl();
    Init_ossl_x509ext();
    Init_ossl_x509name();
    Init_ossl_x509req();
    Init_ossl_x509revoked();
    Init_ossl_x509store();
}


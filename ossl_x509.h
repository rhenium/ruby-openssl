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
#if !defined(_OSSL_X509_H_)
#define _OSSL_X509_H_

extern VALUE mX509;
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

void Init_ossl_x509(void);

/*
 * X509
 */
VALUE ossl_x509_new(X509 *);
VALUE ossl_x509_new_from_file(VALUE);
X509 *ossl_x509_get_X509(VALUE);
void Init_ossl_x509cert(VALUE);

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

#endif /* _OSSL_X509_H_ */


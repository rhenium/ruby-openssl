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

/*
 * X509 main module
 */
extern VALUE mX509;

void Init_ossl_x509(void);

/*
 * X509Attr
 */
extern VALUE cX509Attr;
extern VALUE eX509AttrError;

VALUE ossl_x509attr_new(X509_ATTRIBUTE *);
X509_ATTRIBUTE *ossl_x509attr_get_X509_ATTRIBUTE(VALUE);
void Init_ossl_x509attr(void);

/*
 * X509Cert
 */
extern VALUE cX509Cert;
extern VALUE eX509CertError;

VALUE ossl_x509_new(X509 *);
VALUE ossl_x509_new_from_file(VALUE);
X509 *GetX509CertPtr(VALUE);
X509 *DupX509CertPtr(VALUE);
void Init_ossl_x509cert(void);

/*
 * X509CRL
 */
extern VALUE cX509CRL;
extern VALUE eX509CRLError;

X509_CRL *ossl_x509crl_get_X509_CRL(VALUE);
void Init_ossl_x509crl(void);

/*
 * X509Extension
 */
extern VALUE cX509Ext;
extern VALUE cX509ExtFactory;
extern VALUE eX509ExtError;

VALUE ossl_x509ext_new(X509_EXTENSION *);
X509_EXTENSION *ossl_x509ext_get_X509_EXTENSION(VALUE);
void Init_ossl_x509ext(void);

/*
 * X509Name
 */
extern VALUE cX509Name;
extern VALUE eX509NameError;

VALUE ossl_x509name_new(X509_NAME *);
X509_NAME *GetX509NamePtr(VALUE);
void Init_ossl_x509name(void);

/*
 * X509Request
 */
extern VALUE cX509Req;
extern VALUE eX509ReqError;

VALUE ossl_x509req_new(X509_REQ *);
X509_REQ *ossl_x509req_get_X509_REQ(VALUE);
void Init_ossl_x509req(void);

/*
 * X509Revoked
 */
extern VALUE cX509Rev;
extern VALUE eX509RevError;

VALUE ossl_x509revoked_new(X509_REVOKED *);
X509_REVOKED *ossl_x509revoked_get_X509_REVOKED(VALUE);
void Init_ossl_x509revoked(void);

/*
 * X509Store
 */
extern VALUE cX509Store;
extern VALUE eX509StoreError;

VALUE ossl_x509store_new(X509_STORE_CTX *);
X509_STORE *ossl_x509store_get_X509_STORE(VALUE);
void Init_ossl_x509store(void);

#endif /* _OSSL_X509_H_ */


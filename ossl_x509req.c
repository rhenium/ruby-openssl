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

#define WrapX509Req(klass, obj, req) do { \
	if (!req) { \
		rb_raise(rb_eRuntimeError, "Req wasn't initialized!"); \
	} \
	obj = Data_Wrap_Struct(klass, 0, X509_REQ_free, req); \
} while (0)
#define GetX509Req(obj, req) do { \
	Data_Get_Struct(obj, X509_REQ, req); \
	if (!req) { \
		rb_raise(rb_eRuntimeError, "Req wasn't initialized!"); \
	} \
} while (0)
#define SafeGetX509Req(obj, req) do { \
	OSSL_Check_Kind(obj, cX509Req); \
	GetX509Req(obj, req); \
} while (0)

/*
 * Classes
 */
VALUE cX509Req;
VALUE eX509ReqError;

/*
 * Public functions
 */
VALUE
ossl_x509req_new(X509_REQ *req)
{
	X509_REQ *new;
	VALUE obj;

	if (!req) {
		new = X509_REQ_new();
	} else {
		new = X509_REQ_dup(req);
	}
	if (!new) {
		OSSL_Raise(eX509ReqError, "");
	}
	WrapX509Req(cX509Req, obj, new);

	return obj;
}

X509_REQ *
ossl_x509req_get_X509_REQ(VALUE obj)
{
	X509_REQ *req, *new;
	
	SafeGetX509Req(obj, req);
	
	if (!(new = X509_REQ_dup(req))) {
		OSSL_Raise(eX509ReqError, "");
	}
	return new;
}

/*
 * Private functions
 */
static VALUE 
ossl_x509req_s_allocate(VALUE klass)
{
	X509_REQ *req;
	VALUE obj;

	if (!(req = X509_REQ_new())) {
		OSSL_Raise(eX509ReqError, "");
	}
	WrapX509Req(klass, obj, req);

	return obj;
}

static VALUE 
ossl_x509req_initialize(int argc, VALUE *argv, VALUE self)
{
	BIO *in;
	VALUE buffer;

	if (rb_scan_args(argc, argv, "01", &buffer) == 0) {
		return self;
	}
	if (!(in = BIO_new_mem_buf(StringValuePtr(buffer), -1))) {
		OSSL_Raise(eX509ReqError, "");
	}
	/*
	 * TODO:
	 * Check if we should
	X509_REQ_free(DATA_PTR(self));
	 */
	if (!PEM_read_bio_X509_REQ(in, (X509_REQ **)&DATA_PTR(self), NULL, NULL)) {
		BIO_free(in);
		OSSL_Raise(eX509ReqError, "");
	}
	BIO_free(in);

	return self;
}

static VALUE 
ossl_x509req_to_pem(VALUE self)
{
	X509_REQ *req;
	BIO *out;
	BUF_MEM *buf;
	VALUE str;
	
	GetX509Req(self, req);

	if (!(out = BIO_new(BIO_s_mem()))) {
		OSSL_Raise(eX509ReqError, "");
	}
	if (!PEM_write_bio_X509_REQ(out, req)) {
		BIO_free(out);
		OSSL_Raise(eX509ReqError, "");
	}
	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);
	
	return str;
}

static VALUE 
ossl_x509req_to_text(VALUE self)
{
	X509_REQ *req;
	BIO *out;
	BUF_MEM *buf;
	VALUE str;
	
	GetX509Req(self, req);

	if (!(out = BIO_new(BIO_s_mem()))) {
		OSSL_Raise(eX509ReqError, "");
	}
	if (!X509_REQ_print(out, req)) {
		BIO_free(out);
		OSSL_Raise(eX509ReqError, "");
	}
	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);
	
	return str;
}

/*
 * Makes X509 from X509_REQuest
 *
static VALUE 
ossl_x509req_to_x509(VALUE self, VALUE days, VALUE key)
{
	X509_REQ *req;
	X509 *x509;
	
	GetX509Req(self, req);
	...
	if (!(x509 = X509_REQ_to_X509(req, d, pkey))) {
		OSSL_Raise(eX509ReqError, "");
	}
	return ossl_x509_new(x509);
}
 */

static VALUE 
ossl_x509req_get_version(VALUE self)
{
	X509_REQ *req;
	long version;

	GetX509Req(self, req);
	
	version = X509_REQ_get_version(req);

	return LONG2FIX(version);
}

static VALUE 
ossl_x509req_set_version(VALUE self, VALUE version)
{
	X509_REQ *req;
	long ver;

	GetX509Req(self, req);

	if ((ver = FIX2LONG(version)) < 0) {
		rb_raise(eX509ReqError, "version must be >= 0!");
	}
	if (!X509_REQ_set_version(req, ver)) {
		OSSL_Raise(eX509ReqError, "");
	}
	return version;
}

static VALUE 
ossl_x509req_get_subject(VALUE self)
{
	X509_REQ *req;
	X509_NAME *name;
	VALUE subject;
	
	GetX509Req(self, req);

	if (!(name = X509_REQ_get_subject_name(req))) {
		OSSL_Raise(eX509ReqError, "");
	}
	subject = ossl_x509name_new(name);
	/*X509_NAME_free(name);*/
	
	return subject;
}

static VALUE 
ossl_x509req_set_subject(VALUE self, VALUE subject)
{
	X509_REQ *req;
	X509_NAME *name;
	
	GetX509Req(self, req);

	name = ossl_x509name_get_X509_NAME(subject);

	if (!X509_REQ_set_subject_name(req, name)) {
		OSSL_Raise(eX509ReqError, "");
	}
	/*X509_NAME_free(name);*/

	return subject;
}

static VALUE 
ossl_x509req_get_public_key(VALUE self)
{
	X509_REQ *req;
	EVP_PKEY *pkey;
	VALUE key;

	GetX509Req(self, req);
	
	if (!(pkey = X509_REQ_get_pubkey(req))) {
		OSSL_Raise(eX509ReqError, "");
	}
	key = ossl_pkey_new(pkey);
	EVP_PKEY_free(pkey);

	return key;
}

static VALUE 
ossl_x509req_set_public_key(VALUE self, VALUE key)
{
	X509_REQ *req;
	EVP_PKEY *pkey;

	GetX509Req(self, req);
	
	pkey = ossl_pkey_get_EVP_PKEY(key);

	if (!X509_REQ_set_pubkey(req, pkey)) {
		EVP_PKEY_free(pkey);
		OSSL_Raise(eX509ReqError, "");
	}
	EVP_PKEY_free(pkey);

	return key;
}

static VALUE 
ossl_x509req_sign(VALUE self, VALUE key, VALUE digest)
{
	X509_REQ *req;
	EVP_PKEY *pkey;
	const EVP_MD *md;

	GetX509Req(self, req);
	
	md = ossl_digest_get_EVP_MD(digest);
	pkey = ossl_pkey_get_private_EVP_PKEY(key);

	if (!X509_REQ_sign(req, pkey, md)) {
		EVP_PKEY_free(pkey);
		OSSL_Raise(eX509ReqError, "");
	}
	EVP_PKEY_free(pkey);

	return self;
}

/*
 * Checks that cert signature is made with PRIVversion of this PUBLIC 'key'
 */
static VALUE 
ossl_x509req_verify(VALUE self, VALUE key)
{
	X509_REQ *req;
	EVP_PKEY *pkey;
	int i;

	GetX509Req(self, req);
	
	pkey = ossl_pkey_get_EVP_PKEY(key);
	
	i = X509_REQ_verify(req, pkey);
	EVP_PKEY_free(pkey);

	if (i < 0) {
		OSSL_Raise(eX509ReqError, "");
	} else if (i > 0) {
		return Qtrue;
	}
	return Qfalse;
}

static VALUE 
ossl_x509req_get_attributes(VALUE self)
{
	X509_REQ *req;
	int count, i;
	X509_ATTRIBUTE *attr;
	VALUE ary;
	
	GetX509Req(self, req);

	count = X509_REQ_get_attr_count(req);

	if (count < 0) {
		rb_warning("count < 0???");
		return rb_ary_new();
	}
	ary = rb_ary_new2(count);

	for (i=0; i<count; i++) {
		attr = X509_REQ_get_attr(req, i);
		rb_ary_push(ary, ossl_x509attr_new(attr));
	}
	return ary;
}

static VALUE 
ossl_x509req_set_attributes(VALUE self, VALUE ary)
{
	X509_REQ *req;
	X509_ATTRIBUTE *attr;
	int i;
	VALUE item;

	GetX509Req(self, req);

	Check_Type(ary, T_ARRAY);

	for (i=0;i<RARRAY(ary)->len; i++) {
		OSSL_Check_Type(RARRAY(ary)->ptr[i], cX509Attr);
	}

	sk_X509_ATTRIBUTE_pop_free(req->req_info->attributes, X509_ATTRIBUTE_free);
	req->req_info->attributes = NULL;
	
	for (i=0;i<RARRAY(ary)->len; i++) {
		item = RARRAY(ary)->ptr[i];

		attr = ossl_x509attr_get_X509_ATTRIBUTE(item);

		if (!X509_REQ_add1_attr(req, attr)) {
			OSSL_Raise(eX509ReqError, "");
		}
	}
	return ary;
}

static VALUE 
ossl_x509req_add_attribute(VALUE self, VALUE attr)
{
	X509_REQ *req = NULL;

	GetX509Req(self, req);

	if (!X509_REQ_add1_attr(req, ossl_x509attr_get_X509_ATTRIBUTE(attr))) {
		OSSL_Raise(eX509ReqError, "");
	}
	return attr;
}

/*
 * X509_REQUEST init
 */
void 
Init_ossl_x509req()
{
	eX509ReqError = rb_define_class_under(mX509, "RequestError", eOSSLError);
	
	cX509Req = rb_define_class_under(mX509, "Request", rb_cObject);
	
	rb_define_singleton_method(cX509Req, "allocate", ossl_x509req_s_allocate, 0);
	rb_define_method(cX509Req, "initialize", ossl_x509req_initialize, -1);
	
	rb_define_method(cX509Req, "to_pem", ossl_x509req_to_pem, 0);
	rb_define_alias(cX509Req, "to_s", "to_pem");
	rb_define_method(cX509Req, "to_text", ossl_x509req_to_text, 0);
	rb_define_method(cX509Req, "version", ossl_x509req_get_version, 0);
	rb_define_method(cX509Req, "version=", ossl_x509req_set_version, 1);
	rb_define_method(cX509Req, "subject", ossl_x509req_get_subject, 0);
	rb_define_method(cX509Req, "subject=", ossl_x509req_set_subject, 1);
	rb_define_method(cX509Req, "public_key", ossl_x509req_get_public_key, 0);
	rb_define_method(cX509Req, "public_key=", ossl_x509req_set_public_key, 1);
	rb_define_method(cX509Req, "sign", ossl_x509req_sign, 2);
	rb_define_method(cX509Req, "verify", ossl_x509req_verify, 1);
	rb_define_method(cX509Req, "attributes", ossl_x509req_get_attributes, 0);
	rb_define_method(cX509Req, "attributes=", ossl_x509req_set_attributes, 1);
	rb_define_method(cX509Req, "add_attribute", ossl_x509req_add_attribute, 1);
}


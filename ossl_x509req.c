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

#define WrapX509Req(obj, req) obj = Data_Wrap_Struct(cX509Request, 0, X509_REQ_free, req)
#define GetX509Req(obj, req) Data_Get_Struct(obj, X509_REQ, req)

/*
 * Classes
 */
VALUE cX509Request;
VALUE eX509RequestError;

/*
 * Public functions
 */
VALUE
ossl_x509req_new(X509_REQ *req)
{
	X509_REQ *new = NULL;
	VALUE self;

	if (!req)
		new = X509_REQ_new();
	else new = X509_REQ_dup(req);

	if (!new)
		OSSL_Raise(eX509RequestError, "");

	WrapX509Req(self, new);

	return self;
}

X509_REQ *
ossl_x509req_get_X509_REQ(VALUE obj)
{
	X509_REQ *req = NULL, *new;
	
	OSSL_Check_Type(obj, cX509Request);
	
	GetX509Req(obj, req);
	
	if (!(new = X509_REQ_dup(req))) {
		OSSL_Raise(eX509RequestError, "");
	}

	return new;
}

/*
 * Private functions
 */
static VALUE 
ossl_x509req_s_new(int argc, VALUE *argv, VALUE klass)
{
	VALUE obj;
	
	obj = ossl_x509req_new(NULL);
	
	rb_obj_call_init(obj, argc, argv);

	return obj;
}

static VALUE 
ossl_x509req_initialize(int argc, VALUE *argv, VALUE self)
{
	BIO *in = NULL;
	VALUE buffer;

	if (argc == 0)
		return self;

	buffer = rb_String(argv[0]);
	if (!(in = BIO_new_mem_buf(RSTRING(buffer)->ptr, -1))) {
		OSSL_Raise(eX509RequestError, "");
	}
	if (!PEM_read_bio_X509_REQ(in, (X509_REQ **)&DATA_PTR(self), NULL, NULL)) {
		BIO_free(in);
		OSSL_Raise(eX509RequestError, "");
	}
	BIO_free(in);

	return self;
}

static VALUE 
ossl_x509req_to_pem(VALUE self)
{
	X509_REQ *req = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	VALUE str;
	
	GetX509Req(self, req);

	if (!(out = BIO_new(BIO_s_mem()))) {
		OSSL_Raise(eX509RequestError, "");
	}
	if (!PEM_write_bio_X509_REQ(out, req)) {
		BIO_free(out);
		OSSL_Raise(eX509RequestError, "");
	}
	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);
	
	return str;
}

static VALUE 
ossl_x509req_to_text(VALUE self)
{
	X509_REQ *req = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	VALUE str;
	
	GetX509Req(self, req);

	if (!(out = BIO_new(BIO_s_mem()))) {
		OSSL_Raise(eX509RequestError, "");
	}
	if (!X509_REQ_print(out, req)) {
		BIO_free(out);
		OSSL_Raise(eX509RequestError, "");
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
	X509_REQ *req = NULL;
	X509 *x509 = NULL;
	
	GetX509Req(self, req);
	...
	if (!(x509 = X509_REQ_to_X509(req, d, pkey))) {
		OSSL_Raise(eX509RequestError, "");
	}

	return ossl_x509_new(x509);
}
 */

static VALUE 
ossl_x509req_get_version(VALUE self)
{
	X509_REQ *req = NULL;
	long version = 0;

	GetX509Req(self, req);
	
	version = X509_REQ_get_version(req);

	return INT2NUM(version);
}

static VALUE 
ossl_x509req_set_version(VALUE self, VALUE version)
{
	X509_REQ *req = NULL;
	long ver = 0;

	GetX509Req(self, req);

	if ((ver = NUM2INT(version)) < 0) {
		rb_raise(eX509RequestError, "version must be >= 0!");
	}
	if (!X509_REQ_set_version(req, ver)) {
		OSSL_Raise(eX509RequestError, "");
	}

	return version;
}

static VALUE 
ossl_x509req_get_subject(VALUE self)
{
	X509_REQ *req = NULL;
	X509_NAME *name = NULL;
	VALUE subject;
	
	GetX509Req(self, req);

	if (!(name = X509_REQ_get_subject_name(req))) {
		OSSL_Raise(eX509RequestError, "");
	}
	subject = ossl_x509name_new(name);
	/*X509_NAME_free(name);*/
	
	return subject;
}

static VALUE 
ossl_x509req_set_subject(VALUE self, VALUE subject)
{
	X509_REQ *req = NULL;
	X509_NAME *name = NULL;
	
	GetX509Req(self, req);

	name = ossl_x509name_get_X509_NAME(subject);

	if (!X509_REQ_set_subject_name(req, name)) {
		OSSL_Raise(eX509RequestError, "");
	}
	/*X509_NAME_free(name);*/

	return subject;
}

static VALUE 
ossl_x509req_get_public_key(VALUE self)
{
	X509_REQ *req = NULL;
	EVP_PKEY *pkey = NULL;
	VALUE pub_key;

	GetX509Req(self, req);
	
	if (!(pkey = X509_REQ_get_pubkey(req))) {
		OSSL_Raise(eX509RequestError, "");
	}
	pub_key = ossl_pkey_new(pkey);
	EVP_PKEY_free(pkey);

	return pub_key;
}

static VALUE 
ossl_x509req_set_public_key(VALUE self, VALUE pubk)
{
	X509_REQ *req = NULL;
	EVP_PKEY *pkey = NULL;

	GetX509Req(self, req);
	
	pkey = ossl_pkey_get_EVP_PKEY(pubk);

	if (!X509_REQ_set_pubkey(req, pkey)) {
		EVP_PKEY_free(pkey);
		OSSL_Raise(eX509RequestError, "");
	}
	EVP_PKEY_free(pkey);

	return pubk;
}

static VALUE 
ossl_x509req_sign(VALUE self, VALUE key, VALUE digest)
{
	X509_REQ *req = NULL;
	EVP_PKEY *pkey = NULL;
	const EVP_MD *md = NULL;

	GetX509Req(self, req);
	OSSL_Check_Type(key, cPKey);
	OSSL_Check_Type(digest, cDigest);
	
	if (rb_funcall(key, id_private_q, 0, NULL) == Qfalse) {
		rb_raise(eX509RequestError, "PRIVATE key needed to sign REQ!");
	}

	pkey = ossl_pkey_get_EVP_PKEY(key);
	md = ossl_digest_get_EVP_MD(digest);

	if (!X509_REQ_sign(req, pkey, md)) {
		EVP_PKEY_free(pkey);
		OSSL_Raise(eX509RequestError, "");
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
	X509_REQ *req = NULL;
	EVP_PKEY *pkey = NULL;
	int i = 0;

	GetX509Req(self, req);
	
	pkey = ossl_pkey_get_EVP_PKEY(key);
	
	i = X509_REQ_verify(req, pkey);
	EVP_PKEY_free(pkey);

	if (i < 0)
		OSSL_Raise(eX509RequestError, "");
	else if (i > 0)
		return Qtrue;

	return Qfalse;
}

static VALUE 
ossl_x509req_get_attributes(VALUE self)
{
	X509_REQ *req = NULL;
	int count = 0, i;
	X509_ATTRIBUTE *attr = NULL;
	VALUE ary;
	
	GetX509Req(self, req);

	count = X509_REQ_get_attr_count(req);

	if (count > 0)
		ary = rb_ary_new2(count);
	else 
		return rb_ary_new();

	for (i=0; i<count; i++) {
		attr = X509_REQ_get_attr(req, i);
		rb_ary_push(ary, ossl_x509attr_new(attr));
	}

	return ary;
}

static VALUE 
ossl_x509req_set_attributes(VALUE self, VALUE ary)
{
	X509_REQ *req = NULL;
	X509_ATTRIBUTE *attr = NULL;
	int i = 0;
	VALUE item;

	GetX509Req(self, req);

	Check_Type(ary, T_ARRAY);

	sk_X509_ATTRIBUTE_pop_free(req->req_info->attributes, X509_ATTRIBUTE_free);
	req->req_info->attributes = NULL;
	
	for (i=0;i<RARRAY(ary)->len; i++) {
		item = RARRAY(ary)->ptr[i];

		OSSL_Check_Type(item, cX509Attribute);

		attr = ossl_x509attr_get_X509_ATTRIBUTE(item);

		if (!X509_REQ_add1_attr(req, attr)) {
			OSSL_Raise(eX509RequestError, "");
		}
	}

	return ary;
}

static VALUE 
ossl_x509req_add_attribute(VALUE self, VALUE attr)
{
	X509_REQ *req = NULL;

	GetX509Req(self, req);

	OSSL_Check_Type(attr, cX509Attribute);

	if (!X509_REQ_add1_attr(req, ossl_x509attr_get_X509_ATTRIBUTE(attr))) {
		OSSL_Raise(eX509RequestError, "");
	}

	return attr;
}

/*
 * X509_REQUEST init
 */
void 
Init_ossl_x509req(VALUE module)
{
	eX509RequestError = rb_define_class_under(module, "RequestError", eOSSLError);
	
	cX509Request = rb_define_class_under(module, "Request", rb_cObject);
	rb_define_singleton_method(cX509Request, "new", ossl_x509req_s_new, -1);
	rb_define_method(cX509Request, "initialize", ossl_x509req_initialize, -1);
	rb_define_method(cX509Request, "to_pem", ossl_x509req_to_pem, 0);
	rb_define_alias(cX509Request, "to_s", "to_pem");
	rb_define_method(cX509Request, "to_text", ossl_x509req_to_text, 0);
	rb_define_method(cX509Request, "version", ossl_x509req_get_version, 0);
	rb_define_method(cX509Request, "version=", ossl_x509req_set_version, 1);
	rb_define_method(cX509Request, "subject", ossl_x509req_get_subject, 0);
	rb_define_method(cX509Request, "subject=", ossl_x509req_set_subject, 1);
	rb_define_method(cX509Request, "public_key", ossl_x509req_get_public_key, 0);
	rb_define_method(cX509Request, "public_key=", ossl_x509req_set_public_key, 1);
	rb_define_method(cX509Request, "sign", ossl_x509req_sign, 2);
	rb_define_method(cX509Request, "verify", ossl_x509req_verify, 1);
	rb_define_method(cX509Request, "attributes", ossl_x509req_get_attributes, 0);
	rb_define_method(cX509Request, "attributes=", ossl_x509req_set_attributes, 1);
	rb_define_method(cX509Request, "add_attribute", ossl_x509req_add_attribute, 1);
}


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

#define WrapX509Ext(obj, ext) \
	obj = Data_Wrap_Struct(cX509Extension, 0, X509_EXTENSION_free, ext)
#define GetX509Ext(obj, ext) \
	Data_Get_Struct(obj, X509_EXTENSION, ext)

#define MakeX509ExtFactory(obj, ctx) \
	obj = Data_Make_Struct(cX509ExtensionFactory, X509V3_CTX, 0, CRYPTO_free, ctx)
#define GetX509ExtFactory(obj, ctx) \
	Data_Get_Struct(obj, X509V3_CTX, ctx)

/*
 * Classes
 */
VALUE cX509Extension;
VALUE cX509ExtensionFactory;
VALUE eX509ExtensionError;

/*
 * Public
 */
VALUE 
ossl_x509ext_new(X509_EXTENSION *ext)
{
	X509_EXTENSION *new = NULL;
	VALUE obj;

	if (!ext)
		new = X509_EXTENSION_new();
	else new = X509_EXTENSION_dup(ext);

	if (!new)
		OSSL_Raise(eX509ExtensionError, "");
		
	WrapX509Ext(obj, new);
	
	return obj;
}

X509_EXTENSION *
ossl_x509ext_get_X509_EXTENSION(VALUE obj)
{
	X509_EXTENSION *ext = NULL, *new;

	OSSL_Check_Type(obj, cX509Extension);
	
	GetX509Ext(obj, ext);

	if (!(new = X509_EXTENSION_dup(ext))) {
		OSSL_Raise(eX509ExtensionError, "");
	}
	
	return new;
}

/*
 * Private
 */
/*
 * Extension factory
 */
static VALUE 
ossl_x509extfactory_s_new(int argc, VALUE *argv, VALUE klass)
{
	X509V3_CTX *ctx = NULL;
	VALUE obj;
	
	MakeX509ExtFactory(obj, ctx);

	rb_obj_call_init(obj, argc, argv);

	return obj;
}

static VALUE 
ossl_x509extfactory_set_issuer_cert(VALUE self, VALUE cert)
{
	X509V3_CTX *ctx = NULL;

	GetX509ExtFactory(self, ctx);

	ctx->issuer_cert = ossl_x509_get_X509(cert);

	return cert;
}

static VALUE 
ossl_x509extfactory_set_subject_cert(VALUE self, VALUE cert)
{
	X509V3_CTX *ctx = NULL;

	GetX509ExtFactory(self, ctx);

	ctx->subject_cert = ossl_x509_get_X509(cert);

	return cert;
}

static VALUE 
ossl_x509extfactory_set_subject_req(VALUE self, VALUE req)
{
	X509V3_CTX *ctx = NULL;

	GetX509ExtFactory(self, ctx);

	ctx->subject_req = ossl_x509req_get_X509_REQ(req);

	return req;
}

static VALUE 
ossl_x509extfactory_set_crl(VALUE self, VALUE crl)
{
	X509V3_CTX *ctx = NULL;

	GetX509ExtFactory(self, ctx);

	ctx->crl = ossl_x509crl_get_X509_CRL(crl);

	return crl;
}

static VALUE 
ossl_x509extfactory_initialize(int argc, VALUE *argv, VALUE self)
{
	/*X509V3_CTX *ctx = NULL;*/
	VALUE issuer_cert, subject_cert, subject_req, crl;
	
	/*GetX509ExtFactory(self, ctx);*/

	rb_scan_args(argc, argv, "04", &issuer_cert, &subject_cert, &subject_req, &crl);

	if (!NIL_P(issuer_cert)) {
		ossl_x509extfactory_set_issuer_cert(self, issuer_cert);
	}
	if (!NIL_P(subject_cert)) {
		ossl_x509extfactory_set_subject_cert(self, subject_cert);
	}
	if (!NIL_P(subject_req)) {
		ossl_x509extfactory_set_subject_req(self, subject_req);
	}
	if (!NIL_P(crl)) {
		ossl_x509extfactory_set_crl(self, crl);
	}
	
	return self;
}

/*
 * Array to X509_EXTENSION
 * Structure:
 * ["ln", "value", bool_critical] or
 * ["sn", "value", bool_critical] or
 * ["ln", "critical,value"] or the same for sn
 * ["ln", "value"] => not critical
 */
static VALUE 
ossl_x509extfactory_create_ext_from_array(VALUE self, VALUE ary)
{
	X509V3_CTX *ctx = NULL;
	X509_EXTENSION *ext = NULL;
	int nid = NID_undef;
	char *value = NULL;
	VALUE item, obj;
	
	GetX509ExtFactory(self, ctx);
	
	Check_Type(ary, T_ARRAY);

	if ((RARRAY(ary)->len) < 2 || (RARRAY(ary)->len > 3)) { /*2 or 3 allowed*/
		rb_raise(eX509ExtensionError, "unsupported structure");
	}

	/* key [0] */
	item = RARRAY(ary)->ptr[0];
	item = rb_String(item);
	if (!(nid = OBJ_ln2nid(RSTRING(item)->ptr)))
		if (!(nid = OBJ_sn2nid(RSTRING(item)->ptr))) {
			OSSL_Raise(eX509ExtensionError, "");
	}

	/* data [1] */
	item = RARRAY(ary)->ptr[1];
	item = rb_String(item);

	/* (optional) critical [2] */
	if (RARRAY(ary)->len == 3 && RARRAY(ary)->ptr[2] == Qtrue) {
		if (!(value = malloc(strlen("critical,")+(RSTRING(item)->len)+1))) {
			rb_raise(eX509ExtensionError, "malloc error");
		}
		strcpy(value, "critical,");
		strncat(value, RSTRING(item)->ptr, RSTRING(item)->len);
	} else
		value = strdup(RSTRING(item)->ptr);

	if (!(ext = X509V3_EXT_conf_nid(NULL, ctx, nid, value))) {
		free(value);
		OSSL_Raise(eX509ExtensionError, "");
	}
	free(value);
	
	WrapX509Ext(obj, ext);

	return obj;
}

/*
 * Extension
 */
static VALUE 
ossl_x509ext_to_a(VALUE obj)
{
	X509_EXTENSION *ext = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	int nid = NID_undef, critical;
	VALUE ary, value;

	GetX509Ext(obj, ext);

	ary = rb_ary_new2(3);

	nid = OBJ_obj2nid(X509_EXTENSION_get_object(ext));
	rb_ary_push(ary, rb_str_new2(OBJ_nid2sn(nid)));

	if (!(out = BIO_new(BIO_s_mem()))) {
		OSSL_Raise(eX509ExtensionError, "");
	}
	if (!X509V3_EXT_print(out, ext, 0, 0)) {
		BIO_free(out);
		OSSL_Raise(eX509ExtensionError, "");
	}
	BIO_get_mem_ptr(out, &buf);
	value = rb_str_new(buf->data, buf->length);
	BIO_free(out);

	rb_funcall(value, rb_intern("tr!"), 2, rb_str_new2("\n"), rb_str_new2(","));
	rb_ary_push(ary, value);
	
	critical = X509_EXTENSION_get_critical(ext);
	rb_ary_push(ary, (critical) ? Qtrue : Qfalse);

	return ary;
}

/*
 * INIT
 */
void
Init_ossl_x509ext(VALUE module)
{

	eX509ExtensionError = rb_define_class_under(module, "ExtensionError", eOSSLError);

	cX509ExtensionFactory = rb_define_class_under(module, "ExtensionFactory", rb_cObject);
	rb_define_singleton_method(cX509ExtensionFactory, "new", ossl_x509extfactory_s_new, -1);
	rb_define_method(cX509ExtensionFactory, "initialize", ossl_x509extfactory_initialize, -1);
	rb_define_method(cX509ExtensionFactory, "issuer_certificate=", ossl_x509extfactory_set_issuer_cert, 1);
	rb_define_method(cX509ExtensionFactory, "subject_certificate=", ossl_x509extfactory_set_subject_cert, 1);
	rb_define_method(cX509ExtensionFactory, "subject_request=", ossl_x509extfactory_set_subject_req, 1);
	rb_define_method(cX509ExtensionFactory, "crl=", ossl_x509extfactory_set_crl, 1);
	rb_define_method(cX509ExtensionFactory, "create_ext_from_array", ossl_x509extfactory_create_ext_from_array, 1);
	
	cX509Extension = rb_define_class_under(module, "Extension", rb_cObject);
	rb_undef_method(CLASS_OF(cX509Extension), "new");
/*
	rb_define_singleton_method(cX509Extension, "new", ossl_x509ext_s_new, -1);
	rb_define_method(cX509Extension, "initialize", ossl_x509ext_initialize, -1);
 */
	rb_define_method(cX509Extension, "to_a", ossl_x509ext_to_a, 0);
}


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
#include "ossl.h"

#define MakeX509Revoked(obj,revp) {\
	obj = Data_Make_Struct(cX509Revoked, ossl_x509revoked, 0, ossl_x509revoked_free, revp);\
}
#define GetX509Revoked_unsafe(obj, revp) Data_Get_Struct(obj, ossl_x509revoked, revp)
#define GetX509Revoked(obj, revp) {\
	GetX509Revoked_unsafe(obj, revp);\
	if (!revp->revoked) rb_raise(eX509RevokedError, "not initialized!");\
}

/*
 * Classes
 */
VALUE cX509Revoked;
VALUE eX509RevokedError;

/*
 * Struct
 */
typedef struct ossl_x509revoked_st {
	X509_REVOKED *revoked;
} ossl_x509revoked;

static void 
ossl_x509revoked_free(ossl_x509revoked *revp)
{
	if (revp) {
		if (revp->revoked) X509_REVOKED_free(revp->revoked);
		revp->revoked = NULL;
		free(revp);
	}
}

/*
 * PUBLIC
 */
VALUE 
ossl_x509revoked_new2(X509_REVOKED *rev)
{
	ossl_x509revoked *revp = NULL;
	X509_REVOKED *new = NULL;
	VALUE obj;

	if (!(new = X509_REVOKED_dup(rev))) {
		rb_raise(eX509RevokedError, "%s", ossl_error());
	}
	
	MakeX509Revoked(obj, revp);
	revp->revoked = new;
	
	return obj;
}

X509_REVOKED *
ossl_x509revoked_get_X509_REVOKED(VALUE self)
{
	ossl_x509revoked *revp = NULL;

	GetX509Revoked(self, revp);

	return X509_REVOKED_dup(revp->revoked);
}

/*
 * PRIVATE
 */
static VALUE 
ossl_x509revoked_s_new(int argc, VALUE *argv, VALUE klass)
{
	ossl_x509revoked *revp = NULL;
	VALUE obj;

	MakeX509Revoked(obj, revp);
	rb_obj_call_init(obj, argc, argv);

	return obj;
}

static VALUE 
ossl_x509revoked_initialize(int argc, VALUE *argv, VALUE obj)
{
	ossl_x509revoked *revp = NULL;
	X509_REVOKED *revoked = NULL;

	GetX509Revoked_unsafe(obj, revp);

	if (!(revoked = X509_REVOKED_new())) {
		rb_raise(eX509RevokedError, "%s", ossl_error());
	}
	revp->revoked = revoked;
	
	return obj;
}

static VALUE 
ossl_x509revoked_get_serial(VALUE obj)
{
	ossl_x509revoked *revp = NULL;

	GetX509Revoked(obj, revp);

	return INT2NUM(ASN1_INTEGER_get(revp->revoked->serialNumber));
}

static VALUE 
ossl_x509revoked_set_serial(VALUE obj, VALUE serial)
{
	ossl_x509revoked *revp = NULL;

	GetX509Revoked(obj, revp);

	if (!ASN1_INTEGER_set(revp->revoked->serialNumber, NUM2INT(serial))) {
		rb_raise(eX509RevokedError, "%s", ossl_error());
	}

	return serial;
}

static VALUE 
ossl_x509revoked_get_time(VALUE obj)
{
	ossl_x509revoked *revp = NULL;
	ASN1_UTCTIME *asn1time = NULL;
	
	GetX509Revoked(obj, revp);

	return asn1time_to_time(revp->revoked->revocationDate);
}

static VALUE 
ossl_x509revoked_set_time(VALUE obj, VALUE time)
{
	ossl_x509revoked *revp = NULL;
	VALUE sec;

	GetX509Revoked(obj, revp);

	OSSL_Check_Type(time, rb_cTime);
	sec = rb_funcall(time, rb_intern("to_i"), 0, NULL);
	
	if (!FIXNUM_P(sec))
		rb_raise(eX509RevokedError, "wierd time");
	if (!ASN1_UTCTIME_set(revp->revoked->revocationDate, FIX2INT(sec))) {
		rb_raise(eX509RevokedError, "%s", ossl_error());
	}

	return time;
}
/*
 * Gets X509v3 extensions as array of X509Ext objects
 */
static VALUE 
ossl_x509revoked_get_extensions(VALUE self)
{
	ossl_x509revoked *revp = NULL;
	int count = 0, i;
	X509_EXTENSION *ext = NULL;
	VALUE ary;

	GetX509Revoked(self, revp);

	count = X509_REVOKED_get_ext_count(revp->revoked);

	if (count > 0) ary = rb_ary_new2(count);
	else return rb_ary_new();

	for (i=0; i<count; i++) {
		ext = X509_REVOKED_get_ext(revp->revoked, i);
		rb_ary_push(ary, ossl_x509ext_new2(ext));
	}
	
	return ary;
}

/*
 * Sets X509_EXTENSIONs
 */
static VALUE 
ossl_x509revoked_set_extensions(VALUE self, VALUE ary)
{
	ossl_x509revoked *revp = NULL;
	X509_EXTENSION *ext = NULL;
	int i = 0;
	VALUE item;
	
	GetX509Revoked(self, revp);

	Check_Type(ary, T_ARRAY);

	sk_X509_EXTENSION_pop_free(revp->revoked->extensions, X509_EXTENSION_free);
	revp->revoked->extensions = NULL;
	
	for (i=0; i<RARRAY(ary)->len; i++) {
		item = RARRAY(ary)->ptr[i];
		OSSL_Check_Type(item, cX509Extension);
		ext = ossl_x509ext_get_X509_EXTENSION(item);
		if(!X509_REVOKED_add_ext(revp->revoked, ext, -1)) {
			rb_raise(eX509RevokedError, "%s", ossl_error());
		}
	}

	return ary;
}

static VALUE 
ossl_x509revoked_add_extension(VALUE self, VALUE ext)
{
	ossl_x509revoked *revp = NULL;
	
	GetX509Revoked(self, revp);

	OSSL_Check_Type(ext, cX509Extension);
	if(!X509_REVOKED_add_ext(revp->revoked, ossl_x509ext_get_X509_EXTENSION(ext), -1)) {
		rb_raise(eX509RevokedError, "%s", ossl_error());
	}

	return ext;
}

/*
 * INIT
 */
void 
Init_ossl_x509revoked(VALUE module)
{
	eX509RevokedError = rb_define_class_under(module, "RevokedError", rb_eStandardError);

	cX509Revoked = rb_define_class_under(module, "Revoked", rb_cObject);
	rb_define_singleton_method(cX509Revoked, "new", ossl_x509revoked_s_new, -1);
	rb_define_method(cX509Revoked, "initialize", ossl_x509revoked_initialize, -1);
	rb_define_method(cX509Revoked, "serial", ossl_x509revoked_get_serial, 0);
	rb_define_method(cX509Revoked, "serial=", ossl_x509revoked_set_serial, 1);
	rb_define_method(cX509Revoked, "time", ossl_x509revoked_get_time, 0);
	rb_define_method(cX509Revoked, "time=", ossl_x509revoked_set_time, 1);
	rb_define_method(cX509Revoked, "extensions", ossl_x509revoked_get_extensions, 0);
	rb_define_method(cX509Revoked, "extensions=", ossl_x509revoked_set_extensions, 1);
	rb_define_method(cX509Revoked, "add_extension", ossl_x509revoked_add_extension, 1);
}


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

#define WrapX509Revoked(obj, rev) obj = Data_Wrap_Struct(cX509Revoked, 0, X509_REVOKED_free, rev)
#define GetX509Revoked(obj, rev) Data_Get_Struct(obj, X509_REVOKED, rev)

/*
 * Classes
 */
VALUE cX509Revoked;
VALUE eX509RevokedError;

/*
 * PUBLIC
 */
VALUE 
ossl_x509revoked_new(X509_REVOKED *rev)
{
	X509_REVOKED *new = NULL;
	VALUE obj;

	if (!rev)
		new = X509_REVOKED_new();
	else new = X509_REVOKED_dup(rev);

	if (!new)
		OSSL_Raise(eX509RevokedError, "");
	
	WrapX509Revoked(obj, new);
	
	return obj;
}

X509_REVOKED *
ossl_x509revoked_get_X509_REVOKED(VALUE obj)
{
	X509_REVOKED *rev = NULL, *new;

	OSSL_Check_Type(obj, cX509Revoked);
	
	GetX509Revoked(obj, rev);

	if (!(new = X509_REVOKED_dup(rev))) {
		OSSL_Raise(eX509RevokedError, "");
	}
	return new;
}

/*
 * PRIVATE
 */
static VALUE 
ossl_x509revoked_s_new(int argc, VALUE *argv, VALUE klass)
{
	VALUE obj;

	obj = ossl_x509revoked_new(NULL);
	
	rb_obj_call_init(obj, argc, argv);

	return obj;
}

static VALUE 
ossl_x509revoked_initialize(int argc, VALUE *argv, VALUE self)
{
	/* EMPTY */
	return self;
}

static VALUE 
ossl_x509revoked_get_serial(VALUE self)
{
	X509_REVOKED *rev = NULL;

	GetX509Revoked(self, rev);

	return INT2NUM(ASN1_INTEGER_get(rev->serialNumber));
}

static VALUE 
ossl_x509revoked_set_serial(VALUE self, VALUE serial)
{
	X509_REVOKED *rev = NULL;

	GetX509Revoked(self, rev);

	if (!ASN1_INTEGER_set(rev->serialNumber, NUM2INT(serial))) {
		OSSL_Raise(eX509RevokedError, "");
	}

	return serial;
}

static VALUE 
ossl_x509revoked_get_time(VALUE self)
{
	X509_REVOKED *rev = NULL;
	
	GetX509Revoked(self, rev);

	return asn1time_to_time(rev->revocationDate);
}

static VALUE 
ossl_x509revoked_set_time(VALUE self, VALUE time)
{
	X509_REVOKED *rev = NULL;
	time_t sec;

	GetX509Revoked(self, rev);

	sec = time_to_time_t(time);
	
	if (!ASN1_UTCTIME_set(rev->revocationDate, sec)) {
		OSSL_Raise(eX509RevokedError, "");
	}

	return time;
}
/*
 * Gets X509v3 extensions as array of X509Ext objects
 */
static VALUE 
ossl_x509revoked_get_extensions(VALUE self)
{
	X509_REVOKED *rev = NULL;
	int count = 0, i;
	X509_EXTENSION *ext = NULL;
	VALUE ary;

	GetX509Revoked(self, rev);

	count = X509_REVOKED_get_ext_count(rev);

	if (count > 0)
		ary = rb_ary_new2(count);
	else
		return rb_ary_new();

	for (i=0; i<count; i++) {
		ext = X509_REVOKED_get_ext(rev, i);
		rb_ary_push(ary, ossl_x509ext_new(ext));
	}
	
	return ary;
}

/*
 * Sets X509_EXTENSIONs
 */
static VALUE 
ossl_x509revoked_set_extensions(VALUE self, VALUE ary)
{
	X509_REVOKED *rev = NULL;
	X509_EXTENSION *ext = NULL;
	int i = 0;
	VALUE item;
	
	GetX509Revoked(self, rev);

	Check_Type(ary, T_ARRAY);
	/*
	for (i=0; i<RARRAY(ary)->len; i++) {
		OSSL_Check_Type(RARRAY(ary)->ptr[i], cX509Extension);
	}
	*/
	sk_X509_EXTENSION_pop_free(rev->extensions, X509_EXTENSION_free);
	rev->extensions = NULL;
	
	for (i=0; i<RARRAY(ary)->len; i++) {
		item = RARRAY(ary)->ptr[i];

		OSSL_Check_Type(item, cX509Extension);

		ext = ossl_x509ext_get_X509_EXTENSION(item);

		if(!X509_REVOKED_add_ext(rev, ext, -1)) {
			OSSL_Raise(eX509RevokedError, "");
		}
	}

	return ary;
}

static VALUE
ossl_x509revoked_add_extension(VALUE self, VALUE ext)
{
	X509_REVOKED *rev = NULL;
	
	GetX509Revoked(self, rev);

	OSSL_Check_Type(ext, cX509Extension);

	if(!X509_REVOKED_add_ext(rev, ossl_x509ext_get_X509_EXTENSION(ext), -1)) {
		OSSL_Raise(eX509RevokedError, "");
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


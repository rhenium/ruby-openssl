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
#include "st.h" /* For st_foreach -- ST_CONTINUE */

#define WrapX509Name(klass, obj, name) do { \
	if (!name) { \
		ossl_raise(rb_eRuntimeError, "Name wasn't initialized."); \
	} \
	obj = Data_Wrap_Struct(klass, 0, X509_NAME_free, name); \
} while (0)
#define GetX509Name(obj, name) do { \
	Data_Get_Struct(obj, X509_NAME, name); \
	if (!name) { \
		ossl_raise(rb_eRuntimeError, "Name wasn't initialized."); \
	} \
} while (0)
#define SafeGetX509Name(obj, name) do { \
	OSSL_Check_Kind(obj, cX509Name); \
	GetX509Name(obj, name); \
} while (0)

/*
 * Classes
 */
VALUE cX509Name;
VALUE eX509NameError;

/*
 * Public
 */
VALUE 
ossl_x509name_new(X509_NAME *name)
{
	X509_NAME *new;
	VALUE obj;

	if (!name) {
		new = X509_NAME_new();
	} else {
		new = X509_NAME_dup(name);
	}
	if (!new) {
		ossl_raise(eX509NameError, "");
	}
	WrapX509Name(cX509Name, obj, new);

	return obj;
}

X509_NAME *
GetX509NamePtr(VALUE obj)
{
	X509_NAME *name;

	SafeGetX509Name(obj, name);

	return name;
}

/*
 * Private
 */
static VALUE
ossl_x509name_s_allocate(VALUE klass)
{
	X509_NAME *name;
	VALUE obj;
	
	if (!(name = X509_NAME_new())) {
		ossl_raise(eX509NameError, "");
	}
	WrapX509Name(klass, obj, name);

	return obj;
}

static VALUE
ossl_x509name_initialize(int argc, VALUE *argv, VALUE self)
{
	X509_NAME *name;
	int i, type;
	VALUE arg, item, key, value;
	
	GetX509Name(self, name);
	
	if (rb_scan_args(argc, argv, "01", &arg) == 0) {
		return self;
	}
	Check_Type(arg, T_ARRAY);

	for (i=0; i<RARRAY(arg)->len; i++) {
		item = RARRAY(arg)->ptr[i];
		
		Check_Type(item, T_ARRAY);
		
		if (RARRAY(item)->len != 2) {
			ossl_raise(rb_eArgError, "Unsupported structure.");
		}
		key = RARRAY(item)->ptr[0];
		value = RARRAY(item)->ptr[1];
		
		StringValue(key);
		StringValue(value);

		type = ASN1_PRINTABLE_type(RSTRING(value)->ptr, -1);
		
		if (!X509_NAME_add_entry_by_txt(name, RSTRING(key)->ptr, type, RSTRING(value)->ptr, RSTRING(value)->len, -1, 0)) {
			ossl_raise(eX509NameError, "");
		}
	}
	return self;
}

static VALUE
ossl_x509name_to_s(VALUE self)
{
	X509_NAME *name;

	GetX509Name(self, name);

	return rb_str_new2(X509_NAME_oneline(name, NULL, 0));
}

static VALUE 
ossl_x509name_to_a(VALUE self)
{
	X509_NAME *name;
	X509_NAME_ENTRY *entry;
	int i,entries;
	char long_name[512];
	const char *short_name;
	VALUE ary;
	
	GetX509Name(self, name);

	entries = X509_NAME_entry_count(name);

	if (entries < 0) {
		rb_warning("name entries < 0!");
		return rb_ary_new();
	}
	ary = rb_ary_new2(entries);

	for (i=0; i<entries; i++) {
		if (!(entry = X509_NAME_get_entry(name, i))) {
			ossl_raise(eX509NameError, "");
		}
		if (!i2t_ASN1_OBJECT(long_name, sizeof(long_name), entry->object)) {
			ossl_raise(eX509NameError, "");
		}
		short_name = OBJ_nid2sn(OBJ_ln2nid(long_name));

		rb_ary_push(ary, rb_assoc_new(rb_str_new2(short_name), rb_str_new(entry->value->data, entry->value->length)));
	}
	return ary;
}

/*
 * INIT
 */
void 
Init_ossl_x509name()
{
	eX509NameError = rb_define_class_under(mX509, "NameError", eOSSLError);

	cX509Name = rb_define_class_under(mX509, "Name", rb_cObject);
	
	rb_define_singleton_method(cX509Name, "allocate", ossl_x509name_s_allocate, 0);
	rb_define_method(cX509Name, "initialize", ossl_x509name_initialize, -1);
	
	rb_define_method(cX509Name, "to_s", ossl_x509name_to_s, 0);
	rb_define_method(cX509Name, "to_a", ossl_x509name_to_a, 0);
}


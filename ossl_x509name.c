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

#define MakeX509Name(obj, namep) {\
	obj = Data_Make_Struct(cX509Name, ossl_x509name, 0, ossl_x509name_free, namep);\
}
#define GetX509Name_unsafe(obj, namep) Data_Get_Struct(obj, ossl_x509name, namep)
#define GetX509Name(obj, namep) {\
	GetX509Name_unsafe(obj, namep);\
	if (!namep->name) rb_raise(eX509NameError, "not initialized!");\
}

/*
 * Classes
 */
VALUE cX509Name;
VALUE eX509NameError;

/*
 * Struct
 */
typedef struct ossl_x509name_st {
	X509_NAME *name;
} ossl_x509name;


static void 
ossl_x509name_free(ossl_x509name *namep)
{
	if (namep) {
		if (namep->name) X509_NAME_free(namep->name);
		namep->name = NULL;
		free(namep);
	}
}

/*
 * Public
 */
VALUE 
ossl_x509name_new2(X509_NAME *name)
{
	ossl_x509name *namep = NULL;
	X509_NAME *new = NULL;
	VALUE obj;

	MakeX509Name(obj, namep);
	if (!(new = X509_NAME_dup(name))) {
		rb_raise(eX509NameError, "%s", ossl_error());
	}
	namep->name = new;

	return obj;
}

X509_NAME *
ossl_x509name_get_X509_NAME(VALUE obj)
{
	ossl_x509name *namep = NULL;

	GetX509Name(obj, namep);

	return X509_NAME_dup(namep->name);
}

/*
 * Private
 */
static VALUE 
ossl_x509name_s_new(int argc, VALUE *argv, VALUE klass)
{
	ossl_x509name *namep = NULL;
	VALUE obj;
	
	MakeX509Name(obj, namep);
	rb_obj_call_init(obj, argc, argv);
	
	return obj;
}

static X509_NAME *
str_to_x509name(VALUE str)
{
	X509_NAME *name = NULL;

	/*
	 * TODO:
	 */
	rb_raise(eX509NameError, "TODO!");

	Check_Type(str, T_STRING);
	if (!(name = X509_NAME_new())) {
		rb_raise(eX509NameError, "%s", ossl_error());
	}

	return name;
}

static X509_NAME *
ary_to_x509name(VALUE ary)
{
	X509_NAME *name = NULL;
	long i,j;
	int id, type;
	VALUE item, key, value;

	Check_Type(ary, T_ARRAY);

	if (!(name = X509_NAME_new())) {
		rb_raise(eX509NameError, "%s", ossl_error());
	}
	for (i=0; i<RARRAY(ary)->len; i++) {
		item = RARRAY(ary)->ptr[i];
		if (TYPE(item) != T_ARRAY || RARRAY(item)->len != 2) {
			rb_raise(eX509NameError, "unsupported structure");
		}
		key = RARRAY(item)->ptr[0];
		value = RARRAY(item)->ptr[1];
		if (TYPE(key) != T_STRING || TYPE(value) != T_STRING) {
			rb_raise(eX509NameError, "unsupported structure");
		}
		if (!(id = OBJ_ln2nid(RSTRING(key)->ptr)))
			if (!(id = OBJ_sn2nid(RSTRING(key)->ptr))) {
				rb_raise(eX509NameError, "%s", ossl_error());
		}
		type = ASN1_PRINTABLE_type(RSTRING(value)->ptr, -1);
		
		if (!X509_NAME_add_entry_by_NID(name, id, type, RSTRING(value)->ptr, RSTRING(value)->len, -1, 0)) {
			rb_raise(eX509NameError, "%s", ossl_error());
		}
	}
	return name;
}

/*
static X509_NAME *
hash_to_x509name(VALUE ary)
{
	X509_NAME *name = NULL;
	long i,j;
	int id, type;
	VALUE item, key, value;

	Check_Type(ary, T_HASH);

	if (!(name = X509_NAME_new())) {
		rb_raise(eX509NameError, "%s", ossl_error());
	}
	for (i=0; i<RARRAY(ary)->len; i++) {
		item = RARRAY(ary)->ptr[i];
		if (TYPE(item) != T_ARRAY || RARRAY(item)->len != 2) {
			rb_raise(eX509NameError, "unsupported structure");
		}
		key = RARRAY(item)->ptr[0];
		value = RARRAY(item)->ptr[1];
		if (TYPE(key) != T_STRING || TYPE(value) != T_STRING) {
			rb_raise(eX509NameError, "unsupported structure");
		}
		if (!(id = OBJ_ln2nid(RSTRING(key)->ptr)))
			if (!(id = OBJ_sn2nid(RSTRING(key)->ptr))) {
				rb_raise(eX509NameError, "%s", ossl_error());
		}
		type = ASN1_PRINTABLE_type(RSTRING(value)->ptr, -1);
		
		if (!X509_NAME_add_entry_by_NID(name, id, type, RSTRING(value)->ptr, RSTRING(value)->len, -1, 0)) {
			rb_raise(eX509NameError, "%s", ossl_error());
		}
	}
	return name;
}
*/

static VALUE 
ossl_x509name_initialize(int argc, VALUE *argv, VALUE self)
{
	ossl_x509name *namep = NULL;
	X509_NAME *name = NULL;
	VALUE arg;
	
	GetX509Name_unsafe(self, namep);
	
	rb_scan_args(argc, argv, "01", &arg);

	switch (TYPE(arg)) {
		case T_NIL:
			name = X509_NAME_new();
			break;
		case T_STRING:
			name = str_to_x509name(arg);
			break;
		case T_ARRAY:
			name = ary_to_x509name(arg);
			break;
		default:
			rb_raise(rb_eTypeError, "unsupported type");
	}
	if (!name) {
		rb_raise(eX509NameError, "%s", ossl_error());
	}
	namep->name = name;

	return self;
}

static VALUE 
ossl_x509name_to_str(VALUE self)
{
	ossl_x509name *namep = NULL;
	char *name = NULL;
	
	GetX509Name(self, namep);

	/*
	 * TODO:
	 * User defined user format
	 */
	name = X509_NAME_oneline(namep->name, NULL, 0);

	return rb_str_new2(name);
}

static VALUE 
ossl_x509name_to_a(VALUE self)
{
	ossl_x509name *namep = NULL;
	X509_NAME_ENTRY *entry = NULL;
	int i,entries = 0;
	char *value=NULL, long_name[512];
	const char *short_name = NULL;
	VALUE ary;
	
	GetX509Name(self, namep);

	entries = X509_NAME_entry_count(namep->name);

	ary = rb_ary_new2(entries);

	for (i=0; i<entries; i++) {
		if (!(entry = X509_NAME_get_entry(namep->name, i))) {
			rb_raise(eX509NameError, "%s", ossl_error());
		}
		if (!i2t_ASN1_OBJECT(long_name, sizeof(long_name), entry->object)) {
			rb_raise(eX509NameError, "%s", ossl_error());
		}
		short_name = OBJ_nid2sn(OBJ_ln2nid(long_name));

		rb_ary_push(ary, rb_assoc_new(rb_str_new2(short_name), rb_str_new(entry->value->data, entry->value->length)));
	}

	return ary;
}

static VALUE 
ossl_x509name_to_h(VALUE self)
{
	ossl_x509name *namep = NULL;
	X509_NAME_ENTRY *entry = NULL;
	int i,entries = 0;
	char *value=NULL, long_name[512];
	const char *short_name = NULL;
	VALUE hash;
	
	GetX509Name(self, namep);

	entries = X509_NAME_entry_count(namep->name);

	hash = rb_hash_new();

	for (i=0; i<entries; i++) {
		if (!(entry = X509_NAME_get_entry(namep->name, i))) {
			rb_raise(eX509NameError, "%s", ossl_error());
		}
		if (!i2t_ASN1_OBJECT(long_name, sizeof(long_name), entry->object)) {
			rb_raise(eX509NameError, "%s", ossl_error());
		}
		short_name = OBJ_nid2sn(OBJ_ln2nid(long_name));

		rb_hash_aset(hash, rb_str_new2(short_name), rb_str_new(entry->value->data, entry->value->length));
	}

	return hash;
}

/*
 * INIT
 */
void 
Init_ossl_x509name(VALUE module)
{
	eX509NameError = rb_define_class_under(module, "NameError", rb_eStandardError);

	cX509Name = rb_define_class_under(module, "Name", rb_cObject);
	rb_define_singleton_method(cX509Name, "new", ossl_x509name_s_new, -1);
	rb_define_method(cX509Name, "initialize", ossl_x509name_initialize, -1);
	rb_define_method(cX509Name, "to_str", ossl_x509name_to_str, 0);
	rb_define_method(cX509Name, "to_a", ossl_x509name_to_a, 0);
	rb_define_method(cX509Name, "to_h", ossl_x509name_to_h, 0);
}


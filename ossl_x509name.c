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

#define WrapX509Name(obj, name) obj = Data_Wrap_Struct(cX509Name, 0, X509_NAME_free, name)
#define GetX509Name(obj, name) Data_Get_Struct(obj, X509_NAME, name)

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
	X509_NAME *new = NULL;
	VALUE obj;

	if (!name)
		new = X509_NAME_new();
	else new = X509_NAME_dup(name);
	
	if (!new)
		OSSL_Raise(eX509NameError, "");
	
	WrapX509Name(obj, new);

	return obj;
}

X509_NAME *
ossl_x509name_get_X509_NAME(VALUE obj)
{
	X509_NAME *name = NULL, *new;

	OSSL_Check_Type(obj, cX509Name);
	
	GetX509Name(obj, name);

	if (!(new = X509_NAME_dup(name))) {
		OSSL_Raise(eX509NameError, "");
	}
	
	return new;
}

/*
 * Private
 */
/*
 * Iterator for ossl_x509name_new_from_hash
 */
static int
ossl_x509name_hash_i(VALUE key, VALUE value, X509_NAME *name)
{
	int id, type;
	
	key = rb_String(key);
	value = rb_String(value);
	
	if (!(id = OBJ_ln2nid(RSTRING(key)->ptr)))
		if (!(id = OBJ_sn2nid(RSTRING(key)->ptr))) {
			X509_NAME_free(name);
			OSSL_Raise(eX509NameError, "OBJ_name2nid:");
		}

	type = ASN1_PRINTABLE_type(RSTRING(value)->ptr, -1);

	if (!X509_NAME_add_entry_by_NID(name, id, type, RSTRING(value)->ptr, RSTRING(value)->len, -1, 0)) {
		X509_NAME_free(name);
		OSSL_Raise(eX509NameError, "");
	}

	return ST_CONTINUE;
}

static VALUE 
ossl_x509name_s_new_from_hash(VALUE klass, VALUE hash)
{
	X509_NAME *name = NULL;
	VALUE obj;
	
	Check_Type(hash, T_HASH);

	if (!(name = X509_NAME_new()))
		OSSL_Raise(eX509NameError, "");

	st_foreach(RHASH(hash)->tbl, ossl_x509name_hash_i, name);

	WrapX509Name(obj, name);

	return obj;
}

static VALUE 
ossl_x509name_to_h(VALUE self)
{
	X509_NAME *name = NULL;
	X509_NAME_ENTRY *entry = NULL;
	int i,entries = 0;
	char long_name[512];
	const char *short_name = NULL;
	VALUE hash;
	
	GetX509Name(self, name);

	entries = X509_NAME_entry_count(name);

	hash = rb_hash_new();

	if (entries < 0) {
		rb_warning("name entries < 0!");
		return hash;
	}	

	for (i=0; i<entries; i++) {
		if (!(entry = X509_NAME_get_entry(name, i))) {
			OSSL_Raise(eX509NameError, "");
		}
		if (!i2t_ASN1_OBJECT(long_name, sizeof(long_name), entry->object)) {
			OSSL_Raise(eX509NameError, "");
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
	rb_define_singleton_method(cX509Name, "new_from_hash", ossl_x509name_s_new_from_hash, 1);
	rb_define_method(cX509Name, "to_h", ossl_x509name_to_h, 0);
}


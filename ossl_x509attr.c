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

#define MakeX509Attr(obj, attrp) {\
	obj = Data_Make_Struct(cX509Attribute, ossl_x509attr, 0, ossl_x509attr_free, attrp);\
}

#define GetX509Attr(obj, attrp) {\
	Data_Get_Struct(obj, ossl_x509attr, attrp);\
	if (!attrp->attribute) rb_raise(eX509AttributeError, "not initialized!");\
}

/*
 * Classes
 */
VALUE cX509Attribute;
VALUE eX509AttributeError;

/*
 * Struct
 */
typedef struct ossl_x509attr_st {
	X509_ATTRIBUTE *attribute;
} ossl_x509attr;


static void 
ossl_x509attr_free(ossl_x509attr *attrp)
{
	if (attrp) {
		if (attrp->attribute) X509_ATTRIBUTE_free(attrp->attribute);
		attrp->attribute = NULL;
		free(attrp);
	}
}

/*
 * public
 */
VALUE 
ossl_x509attr_new_null(void)
{
	ossl_x509attr *attrp = NULL;
	VALUE obj;

	MakeX509Attr(obj, attrp);

	if (!(attrp->attribute = X509_ATTRIBUTE_new()))
		OSSL_Raise(eX509AttributeError, "");

	return obj;
}

VALUE 
ossl_x509attr_new(X509_ATTRIBUTE *attr)
{
	ossl_x509attr *attrp = NULL;
	VALUE obj;

	if (!attr)
		return ossl_x509attr_new_null();
	
	MakeX509Attr(obj, attrp);

	if (!(attrp->attribute = X509_ATTRIBUTE_dup(attr)))
		OSSL_Raise(eX509AttributeError, "");

	return obj;
}

X509_ATTRIBUTE *
ossl_x509attr_get_X509_ATTRIBUTE(VALUE obj)
{
	ossl_x509attr *attrp = NULL;
	X509_ATTRIBUTE *attr = NULL;

	OSSL_Check_Type(obj, cX509Attribute);	
	GetX509Attr(obj, attrp);

	if (!(attr = X509_ATTRIBUTE_dup(attrp->attribute)))
		OSSL_Raise(eX509AttributeError, "");

	return attr;
}

/*
 * private
 */
static VALUE 
ossl_x509attr_s_new_from_array(VALUE klass, VALUE ary)
{
	ossl_x509attr *attrp = NULL;
	X509_ATTRIBUTE *attr = NULL;
	int nid = NID_undef;
	VALUE item, obj;

	Check_Type(ary, T_ARRAY);

	if (RARRAY(ary)->len != 2) {
		rb_raise(eX509AttributeError, "unsupported ary structure");
	}

	/* key [0] */
	item = RARRAY(ary)->ptr[0];
	Check_SafeStr(item);
	if (!(nid = OBJ_ln2nid(RSTRING(item)->ptr)))
		if (!(nid = OBJ_sn2nid(RSTRING(item)->ptr)))
			OSSL_Raise(eX509AttributeError, "");

	/* data [1] */
	item = RARRAY(ary)->ptr[1];
	Check_SafeStr(item);

	if (!(attr = X509_ATTRIBUTE_create(nid, MBSTRING_ASC, RSTRING(item)->ptr)))
		OSSL_Raise(eX509AttributeError, "");

	MakeX509Attr(obj, attrp);
	attrp->attribute = attr;

	return obj;
}

/*
 * is there any print for attribute?
 * (NO, but check t_req.c in crypto/asn1)
 * 
static VALUE
ossl_x509attr_to_a(VALUE self)
{
	ossl_x509attr *attrp = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	int nid = NID_undef;
	VALUE ary, value;
	
	GetX509Attr(obj, attrp);

	ary = rb_ary_new2(2);

	nid = OBJ_obj2nid(X509_ATTRIBUTE_get0_object(attrp->attribute));
	rb_ary_push(ary, rb_str_new2(OBJ_nid2sn(nid)));

	if (!(out = BIO_new(BIO_s_mem())))
		OSSL_Raise(eX509ExtensionError, "");
		
	if (!X509V3_???_print(out, extp->extension, 0, 0)) {
		BIO_free(out);
		OSSL_Raise(eX509ExtensionError, "");
	}
	BIO_get_mem_ptr(out, &buf);
	value = rb_str_new(buf->data, buf->length);
	BIO_free(out);

	rb_funcall(value, rb_intern("tr!"), 2, rb_str_new2("\n"), rb_str_new2(","));
	rb_ary_push(ary, value);
	
	return ary;
}
 */

/*
 * X509_ATTRIBUTE init
 */
void
Init_ossl_x509attr(VALUE module)
{
	eX509AttributeError = rb_define_class_under(module, "AttributeError", rb_eStandardError);

	cX509Attribute = rb_define_class_under(module, "Attribute", rb_cObject);
	rb_define_singleton_method(cX509Attribute, "new_from_array", ossl_x509attr_s_new_from_array, 1);
/*
 * TODO:
	rb_define_method(cX509Attribute, "to_a", ossl_x509attr_to_a, 0);
 */
}


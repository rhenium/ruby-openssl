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
#define GetX509Attr_unsafe(obj, attrp) Data_Get_Struct(obj, ossl_x509attr, attrp);
#define GetX509Attr(obj, attrp) {\
	GetX509Attr_unsafe(obj, attrp);\
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
		rb_raise(eX509AttributeError, "%s", ossl_error());

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

	if (!(attrp->attribute = X509_ATTRIBUTE_dup(attr))) {
		rb_raise(eX509AttributeError, "%s", ossl_error());
	}

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
		rb_raise(eX509AttributeError, "%s", ossl_error());

	return attr;
}

/*
 * private
 */
static VALUE 
ossl_x509attr_s_new(int argc, VALUE *argv, VALUE klass)
{
	ossl_x509attr *attrp = NULL;
	VALUE obj;

	MakeX509Attr(obj, attrp);

	rb_obj_call_init(obj, argc, argv);

	return obj;
}

X509_ATTRIBUTE *
ary_to_x509attr(VALUE ary)
{
	X509_ATTRIBUTE *attr = NULL;
	int nid = NID_undef;
	VALUE item;

	Check_Type(ary, T_ARRAY);

	if (RARRAY(ary)->len != 2) {
		rb_raise(eX509AttributeError, "unsupported ary structure");
	}

	/* key [0] */
	item = RARRAY(ary)->ptr[0];
	Check_Type(item, T_STRING);
	if (!(nid = OBJ_ln2nid(RSTRING(item)->ptr)))
		if (!(nid = OBJ_sn2nid(RSTRING(item)->ptr)))
			rb_raise(eX509AttributeError, "%s", ossl_error());

	/* data [1] */
	item = RARRAY(ary)->ptr[1];
	Check_Type(item, T_STRING);

	if (!(attr = X509_ATTRIBUTE_create(nid, MBSTRING_ASC, RSTRING(item)->ptr))) {
		rb_raise(eX509AttributeError, "%s", ossl_error());
	}

	return attr;
}

static VALUE 
ossl_x509attr_initialize(int argc, VALUE *argv, VALUE self)
{
	ossl_x509attr *attrp = NULL;
	X509_ATTRIBUTE *attr = NULL;
	VALUE arg1, arg2, ary;

	GetX509Attr_unsafe(self, attrp);
	
	switch (rb_scan_args(argc, argv, "02", &arg1, &arg2)) {
		case 0:
			attr = X509_ATTRIBUTE_new();
			break;
		case 1:
			Check_Type(arg1, T_ARRAY);
			attr = ary_to_x509attr(ary);
			break;
		case 2:
			ary = rb_ary_new2(2);
			rb_ary_push(ary, arg1);
			rb_ary_push(ary, arg2);
			attr = ary_to_x509attr(ary);
			break;
		default:
			rb_raise(rb_eTypeError, "unsupported type");
	}
	if (!attr)
		rb_raise(eX509AttributeError, "%s", ossl_error());

	attrp->attribute = attr;

	return self;
}

/*
 * X509_ATTRIBUTE init
 */
void
Init_ossl_x509attr(VALUE module)
{
	eX509AttributeError = rb_define_class_under(module, "AttributeError", rb_eStandardError);

	cX509Attribute = rb_define_class_under(module, "Attribute", rb_cObject);
	rb_define_singleton_method(cX509Attribute, "new", ossl_x509attr_s_new, -1);
	rb_define_method(cX509Attribute, "initialize", ossl_x509attr_initialize, -1);
/*
 * TODO:
	rb_define_method(cX509Attribute, "to_str", ossl_x509attr_to_str, 0);
	rb_define_method(cX509Attribute, "to_a", ossl_x509attr_to_a, 0);
 */
}


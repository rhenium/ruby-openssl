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

#define MakeConfig(obj, confp) {\
	obj = Data_Make_Struct(cConfig, ossl_config, 0, ossl_config_free, confp);\
}

#define GetConfig_unsafe(obj, confp) Data_Get_Struct(obj, ossl_config, confp)
#define GetConfig(obj, confp) {\
	GetConfig_unsafe(obj, confp);\
	if (!confp->config) rb_raise(eConfigError, "not initialized!");\
}

/*
 * Classes
 */
VALUE cConfig;
VALUE eConfigError;

/*
 * Struct
 */
typedef struct ossl_config_st {
	LHASH *config;
} ossl_config;

static void
ossl_config_free(ossl_config *confp)
{
	if (confp) {
		if (confp->config) CONF_free(confp->config);
		confp->config = NULL;
		free(confp);
	}
}

/* 
 * Public 
 */

/*
 * Private
 */
static VALUE
ossl_config_s_load(int argc, VALUE* argv, VALUE klass)
{
	ossl_config *confp = NULL;
	LHASH *config = NULL;
	long err_line = 0;
	VALUE obj, path;
	
	rb_scan_args(argc, argv, "10", &path);
	
	Check_SafeStr(path);
	
	if (!(config = CONF_load(NULL, RSTRING(path)->ptr, &err_line))) {
		if (err_line <= 0)
			rb_raise(eConfigError, "wrong config file %s", RSTRING(path)->ptr);
		else
			rb_raise(eConfigError, "error on line %ld in config file %s",\
					err_line, RSTRING(path)->ptr);
	}
	
	MakeConfig(obj, confp);
	confp->config = config;

	return obj;
}

static VALUE
ossl_config_get_value(VALUE self, VALUE section, VALUE item)
{
	ossl_config *confp = NULL;
	char *sect = NULL, *str = NULL;
	
	GetConfig(self, confp);
	
	if (!NIL_P(section)) {
		section = rb_String(section);
		sect = RSTRING(section)->ptr;
	}
	item = rb_String(item);

	if (!(str = CONF_get_string(confp->config, sect, RSTRING(item)->ptr))) {
		OSSL_Raise(eConfigError, "");
	}
	return rb_str_new2(str);
}

/* long number = CONF_get_number(confp->config, sect, RSTRING(item)->ptr); */

static VALUE
ossl_config_get_section(VALUE self, VALUE section)
{
	ossl_config *confp = NULL;
	STACK_OF(CONF_VALUE) *sk = NULL;
	CONF_VALUE *entry = NULL;
	int i, entries = 0;
	VALUE hash;

	GetConfig(self, confp);
	
	section = rb_String(section);
	
	if (!(sk = CONF_get_section(confp->config, RSTRING(section)->ptr))) {
		OSSL_Raise(eConfigError, "");
	}
	
	hash = rb_hash_new();
	
	if ((entries = sk_CONF_VALUE_num(sk)) < 0) {
		rb_warning("# of items in section is < 0?!?");
		return hash;
	}

	for (i=0; i<entries; i++) {
		entry = sk_CONF_VALUE_value(sk, i);		
		rb_hash_aset(hash, rb_str_new2(entry->name), rb_str_new2(entry->value));
	}
	
	return hash;
}

/*
 * INIT
 */
void
Init_ossl_config(VALUE module)
{
	eConfigError = rb_define_class_under(module, "ConfigError", rb_eStandardError);

	cConfig = rb_define_class_under(module, "Config", rb_cObject);
	
	rb_define_singleton_method(cConfig, "load", ossl_config_s_load, -1);
	rb_define_alias(CLASS_OF(cConfig), "new", "load");
	
	rb_define_method(cConfig, "get_value", ossl_config_get_value, 2);
	rb_define_method(cConfig, "get_section", ossl_config_get_section, 1);
}


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
/*
 * WILL BE DROPPED OUT!?!???
 * 
#include "ossl.h"

#define MakeConfig(obj, configp) {\
	obj = Data_Make_Struct(cConfig, ossl_config, 0, ossl_config_free, configp);\
	configp->ossl_type = T_OSSL_CONFIG;\
}

#define GetConfig(obj, configp) {\
	OSSL_Check_Type(obj, T_OSSL_CONFIG);\
	Data_Get_Struct(obj, ossl_config, configp);\
}

typedef struct ossl_config_st {
	int ossl_type;
	LHASH *config;
} ossl_config;

/*
 * It's not ready!
 * 
typedef struct ossl_configsect_st {
	int ossl_type;
	STACK_OF(CONF_VALUE) *section;
} ossl_configsect;
 *

VALUE cConfig;
VALUE eConfigError;
VALUE cConfigSection;

static void
ossl_config_free(ossl_config *configp)
{
	if (configp) {
		if (configp->config) CONF_free(configp->config);
		free(configp);
	}
}

/*
static void ossl_config_section_free(ossl_configsect *sectp)
{
	if (configp) {
		if (configp->section) sk_CONF_VALUE_pop_free(configp->
	free(sectp);
}
 *

static VALUE
ossl_config_s_new(int argc, VALUE *argv, VALUE klass)
{
	ossl_config *configp = NULL;
	VALUE obj;
	
	MakeConfig(obj, configp);
	rb_obj_call_init(obj, argc, argv);

	return obj;
}

static VALUE
ossl_config_initialize(int argc, VALUE* argv, VALUE self)
{
	ossl_config *configp = NULL;
	int err_line = 0;
	VALUE path;
	
	GetConfig(self, configp);
	rb_scan_args(argc, argv, "1", &path);
	
	Check_Type(path, T_STRING);
	
	configp->config = NULL;
	configp->config = CONF_load(configp->config, RSTRING(path)->ptr, &err_line);
	
	if (configp->config == NULL) {
		if (err_line <= 0)
			rb_raise(eConfigError, "wrong config file %s", RSTRING(path)->ptr);
		else
			rb_raise(eConfigError, "error on line %ld in config file %s", err_line, RSTRING(path)->ptr);
	}
	
	return self;
}

static VALUE
ossl_config_get_string(VALUE self, VALUE section, VALUE item)
{
	ossl_config *configp = NULL;
	char *sect = NULL;
	char *string = NULL;
	
	GetConfig(self, configp);
	
	if (!NIL_P(section)) {
		Check_Type(section, T_STRING);
		sect = RSTRING(section)->ptr;
	}
	Check_Type(item, T_STRING);

	string = CONF_get_string(configp->config, sect, RSTRING(item)->ptr);
	
	return rb_str_new2(string);
}

static VALUE 
ossl_config_get_number(VALUE self, VALUE section, VALUE item)
{
	ossl_config *configp = NULL;
	char *sect = NULL;
	long number;

	GetConfig(self, configp);
	
	if (!NIL_P(section)) {
		Check_Type(section, T_STRING);
		sect = RSTRING(section)->ptr;
	}
	Check_Type(item, T_STRING);

	number = CONF_get_number(configp->config, sect, RSTRING(item)->ptr);
	return INT2NUM(number);
}

/*
 * TO BE REWORKED
 *
static VALUE
ossl_config_get_section(VALUE self, VALUE section)
{
	ossl_config *configp = NULL;
	VALUE obj;
	ossl_configsect_st *ps;

	Check_Type(section, T_STRING);

	GetConfig(self, p);
	
	obj = Data_Make_Struct(cOSSLConfigSection, ossl_configsect_st, 0, ossl_config_section_free, ps);
	memset(ps, 0, sizeof(ossl_configsect_st));

	ps->section = CONF_get_section(p->config, RSTRING(section)->ptr);

	if (ps->section == NULL)
		return Qnil;
	else
		return obj;
}
 *

void
Init_ossl_config(VALUE mOSSL)
{
	eConfigError = rb_define_class_under(mOSSL, "ConfigError", rb_eStandardError);

	cConfig = rb_define_class_under(mOSSL, "Config", rb_cObject);
	rb_define_singleton_method(cConfig, "new", ossl_config_s_new, -1);
	rb_define_method(cConfig, "initialize", ossl_config_initialize, -1);
	rb_define_method(cConfig, "get_string", ossl_config_get_string, 2);
	rb_define_method(cConfig, "get_number", ossl_config_get_number, 2);
/*
 * TODO:
 * rework
	rb_define_method(cConfig, "get_section", ossl_config_get_section, 1);
	cConfigSection = rb_define_class_under(mOSSL, "ConfigSection", rb_cObject);
	rb_undef_method(CLASS_OF(cConfigSection), "new");
 *
}
 *
 * CONFIG...
 * TO BE DROPPED OUT??
 */


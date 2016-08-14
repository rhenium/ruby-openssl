/*
 * Ruby/OpenSSL Project
 * Copyright (C) 2017 Ruby/OpenSSL Project Authors
 */
#include "ossl.h"
#include "ossl_cms_internal.h"

#ifndef OPENSSL_NO_CMS
VALUE cCMSData;

/*
 * call-seq:
 *    CMS::Data.new(data)
 *
 * Creates a new CMS structure with data content type with the content _data_.
 *
 * === Parameters
 * _data::
 *   A String containing the message digest algorithm name.
 */
static VALUE
data_initialize(VALUE self, VALUE data)
{
    CMS_ContentInfo *cms;

    if (GetCMS0(self))
        rb_raise(eCMSError, "CMS already initialized");
    rb_check_frozen(self);

    /* CMS_STREAM suppresses finalization of CMS_ContentInfo */
    cms = CMS_data_create(NULL, CMS_STREAM);
    if (!cms)
        ossl_raise(eCMSError, "CMS_data_create");
    RTYPEDDATA_DATA(self) = cms;
    ossl_cms_set_content(self, data);
    return self;
}

void
Init_ossl_cms_data(void)
{
#if 0
    mOSSL = rb_define_module("OpenSSL");
    cCMS = rb_define_class_under(mOSSL, "CMS", rb_cObject);
#endif

    /*
     * Document-class: OpenSSL::CMS::Data
     *
     * Provides access to CMS structure with data content type. The data
     * content type is the most basic structure and used for encapsulating
     * arbitrary octet strings.
     */
    cCMSData = rb_define_class_under(cCMS, "Data", cCMS);
    rb_define_method(cCMSData, "initialize", data_initialize, 1);
}
#endif

/*
 * Ruby/OpenSSL Project
 * Copyright (C) 2017 Ruby/OpenSSL Project Authors
 */
#ifndef OSSL_CMS_INTERNAL_H
#define OSSL_CMS_INTERNAL_H

#include "ossl.h"

#ifndef OPENSSL_NO_CMS

#include <openssl/cms.h>

extern VALUE cCMS, cCMSRecipientInfo;
extern VALUE eCMSError;
extern VALUE cCMSData;
extern VALUE cCMSSignedData;
extern VALUE cCMSEnvelopedData;
extern VALUE cCMSDigestedData;
extern VALUE cCMSEncryptedData;

extern const rb_data_type_t ossl_cms_type;
extern const rb_data_type_t ossl_cms_ri_type;

void Init_ossl_cms_data(void);
void Init_ossl_cms_signed_data(void);
void Init_ossl_cms_enveloped_data(void);
void Init_ossl_cms_digested_data(void);
void Init_ossl_cms_encrypted_data(void);

int ossl_cms_is_finalized(VALUE obj);
void ossl_cms_set_content(VALUE obj, VALUE data);

/* For signed-data and enveloped-data */
VALUE ossl_cms_get_certificates(VALUE self);
VALUE ossl_cms_add_certificate(VALUE self, VALUE value);
VALUE ossl_cms_get_crls(VALUE self);
VALUE ossl_cms_add_crl(VALUE self, VALUE value);

/* For enveloped-data */
VALUE ossl_cms_ri_new0(CMS_RecipientInfo *ri, VALUE owner);

static inline CMS_ContentInfo *
GetCMS0(VALUE obj)
{
    CMS_ContentInfo *ci;
    TypedData_Get_Struct(obj, CMS_ContentInfo, &ossl_cms_type, ci);
    return ci;
}

static inline CMS_ContentInfo *
GetCMS(VALUE obj)
{
    CMS_ContentInfo *ci = GetCMS0(obj);
    if (!ci)
        rb_raise(eCMSError, "CMSContentInfo not initialized");
    return ci;
}

static inline CMS_RecipientInfo *
GetCMSRecipientInfo(VALUE obj)
{
    CMS_RecipientInfo *ri;
    TypedData_Get_Struct(obj, CMS_RecipientInfo, &ossl_cms_ri_type, ri);
    if (!ri)
        rb_raise(eCMSError, "CMSRecipientInfo not initialized");
    return ri;
}

#endif

#endif

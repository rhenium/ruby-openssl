/*
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2025 Kazuki Yamaguchi <k@rhe.jp>
 * All rights reserved.
 */
/*
 * This program is licensed under the same licence as Ruby.
 * (See the file 'COPYING'.)
 */
#include "ossl.h"

static VALUE cPKeyContext;
static ID id_pkey;

static void
pkeyctx_free(void *ptr)
{
    EVP_PKEY_CTX_free(ptr);
}

static const rb_data_type_t pkeyctx_type = {
    .wrap_struct_name = "OpenSSL/PKeyContext",
    .function = {
        .dfree = pkeyctx_free,
    },
    .flags = RUBY_TYPED_FREE_IMMEDIATELY | RUBY_TYPED_WB_PROTECTED,
};

static VALUE
pkeyctx_alloc(VALUE klass)
{
    return TypedData_Wrap_Struct(klass, &pkeyctx_type, NULL);
}

static EVP_PKEY_CTX *
GetPKeyCtxPtr(VALUE obj)
{
    EVP_PKEY_CTX *ctx;
    TypedData_Get_Struct(obj, EVP_PKEY_CTX, &pkeyctx_type, ctx);
    if (!ctx)
        rb_raise(rb_eTypeError, "PKeyContext not initialized");
    return ctx;
}

/*
 * call-seq:
 *    PKeyContext.new(pkey) -> pkey_ctx
 *    PKeyContext.new(algo_name) -> pkey_ctx
 *
 * Creates a new +EVP_PKEY_CTX+ from either an OpenSSL::PKey::PKey object
 * _pkey_ or an algorithm name string _algo_name_.
 *
 * The latter form is mostly used for #paramgen_init and #keygen_init
 * operations.
 *
 * See the man pages EVP_PKEY_CTX_new_from_pkey(3) and
 * EVP_PKEY_CTX_new_from_name(3).
 */
static VALUE
pkeyctx_initialize(VALUE self, VALUE obj)
{
    if (RTYPEDDATA_DATA(self))
        rb_raise(rb_eTypeError, "PKeyContext already initialized");

    EVP_PKEY_CTX *ctx;
    if (rb_obj_is_kind_of(obj, cPKey)) {
        EVP_PKEY *pkey = GetPKeyPtr(obj);
#ifdef OSSL_USE_PROVIDER
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (!ctx)
            ossl_raise(ePKeyError, "EVP_PKEY_CTX_new_from_pkey");
#else
        ctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!ctx)
            ossl_raise(ePKeyError, "EVP_PKEY_CTX_new");
#endif
        rb_ivar_set(self, id_pkey, obj);
    }
    else {
#ifdef OSSL_USE_PROVIDER
        const char *name = StringValueCStr(obj);
        ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
        if (!ctx)
            ossl_raise(ePKeyError, "EVP_PKEY_CTX_new_from_name");
#else
        int pkey_id = ossl_lookup_pkey_type(obj);
        ctx = EVP_PKEY_CTX_new_id(pkey_id, NULL);
        if (!ctx)
            ossl_raise(ePKeyError, "EVP_PKEY_CTX_new_id");
#endif
    }
    RTYPEDDATA_DATA(self) = ctx;
    return self;
}

/*
 * call-seq:
 *    ctx.ctrl_str(key, value) -> self
 *
 * _key_ can be a String or Symbol. _value_ is converted to String with
 * Object#to_s. Both strings must be NUL-terminated.
 *
 * This is considered a legacy interface in \OpenSSL 3.0, and new options may
 * not be available through this method. See also #set_params.
 *
 * See the man page EVP_PKEY_CTX_ctrl_str(3).
 */
static VALUE
pkeyctx_ctrl_str(VALUE self, VALUE key, VALUE value)
{
    EVP_PKEY_CTX *ctx = GetPKeyCtxPtr(self);

    if (SYMBOL_P(key))
        key = rb_sym2str(key);
    value = rb_String(value);

    if (EVP_PKEY_CTX_ctrl_str(ctx, StringValueCStr(key),
                              StringValueCStr(value)) <= 0)
        ossl_raise(ePKeyError, "EVP_PKEY_CTX_ctrl_str");
    return self;
}

#ifdef OSSL_PARAM_INTEGER
/*
 * call-seq:
 *    ctx.set_params(ary) -> self
 *
 * _ary_ is an Enumerable of key-value pairs (2-value arrays) representing
 * parameters to be set on the +EVP_PKEY_CTX+. The values must have the
 * corresponding types as specified by EVP_PKEY_CTX_settable_params().
 *
 * This is supported by \OpenSSL 3.0 and later.
 *
 * See the man page EVP_PKEY_CTX_set_params(3).
 */
static VALUE
pkeyctx_set_params(VALUE self, VALUE ary)
{
    EVP_PKEY_CTX *ctx = GetPKeyCtxPtr(self);

    const OSSL_PARAM *settable = EVP_PKEY_CTX_settable_params(ctx);
    if (!settable)
        ossl_raise(ePKeyError, "EVP_PKEY_CTX_settable_params");

    int state;
    OSSL_PARAM *params = ossl_build_params(settable, ary, &state);
    if (state)
        rb_jump_tag(state);

    int ret = EVP_PKEY_CTX_set_params(ctx, params);
    OSSL_PARAM_free(params);
    if (!ret)
        ossl_raise(ePKeyError, "EVP_PKEY_CTX_set_params");

    return self;
}
#else
#define pkeyctx_set_params rb_f_notimplement
#endif

void
Init_ossl_pkey_ctx(void)
{
    /* Document-class: OpenSSL::PKey::PKeyContext
     *
     * OpenSSL::PKey::PKeyContext wraps the +EVP_PKEY_CTX+ type in the \OpenSSL
     * API. This class provides raw access to the API, and you will need to
     * read the man page carefully to use it correctly.
     *
     * In most cases, you should use higher-level abstractions provided as a
     * method on OpenSSL::PKey::PKey and its subclasses instead, such as
     * OpenSSL::PKey::PKey#sign_raw.
     *
     * === Examples
     *
     *   # Equivalent to OpenSSL::PKey::RSA.generate(2048)
     *   ctx = OpenSSL::PKey::PKeyContext.new("RSA")
     *   ctx.keygen_init
     *   ctx.set_params([["bits", 2048]])
     *   p ctx.keygen
     *
     *   # Equivalent to pkey.sign_raw("data")
     *   pkey = OpenSSL::PKey::EC.generate("prime256v1")
     *   ctx = OpenSSL::PKey::PKeyContext.new(pkey)
     *   ctx.sign_init
     *   p ctx.sign("data")
     */
    cPKeyContext = rb_define_class_under(mPKey, "PKeyContext", rb_cObject);
    rb_define_alloc_func(cPKeyContext, pkeyctx_alloc);
    rb_define_method(cPKeyContext, "initialize", pkeyctx_initialize, 1);
    rb_undef_method(cPKeyContext, "initialize_copy");
    rb_define_method(cPKeyContext, "ctrl_str", pkeyctx_ctrl_str, 2);
    rb_define_method(cPKeyContext, "set_params", pkeyctx_set_params, 1);

    id_pkey = rb_intern_const("pkey");
}

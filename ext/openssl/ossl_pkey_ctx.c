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

/*
 * EVP_PKEY_OP_PARAMGEN and EVP_PKEY_OP_KEYGEN
 */
struct pkey_blocking_generate_arg {
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey;
    int state;
    unsigned int yield: 1;
    unsigned int genparam: 1;
    unsigned int interrupted: 1;
};

static VALUE
pkey_gen_cb_yield(VALUE ctx_v)
{
    EVP_PKEY_CTX *ctx = (void *)ctx_v;
    int i, info_num;
    VALUE *argv;

    info_num = EVP_PKEY_CTX_get_keygen_info(ctx, -1);
    argv = ALLOCA_N(VALUE, info_num);
    for (i = 0; i < info_num; i++)
        argv[i] = INT2NUM(EVP_PKEY_CTX_get_keygen_info(ctx, i));

    return rb_yield_values2(info_num, argv);
}

static VALUE
call_check_ints0(VALUE arg)
{
    rb_thread_check_ints();
    return Qnil;
}

static void *
call_check_ints(void *arg)
{
    int state;
    rb_protect(call_check_ints0, Qnil, &state);
    return (void *)(VALUE)state;
}

static int
pkey_gen_cb(EVP_PKEY_CTX *ctx)
{
    struct pkey_blocking_generate_arg *arg = EVP_PKEY_CTX_get_app_data(ctx);
    int state;

    if (arg->yield) {
        rb_protect(pkey_gen_cb_yield, (VALUE)ctx, &state);
        if (state) {
            arg->state = state;
            return 0;
        }
    }
    if (arg->interrupted) {
        arg->interrupted = 0;
        state = (int)(VALUE)rb_thread_call_with_gvl(call_check_ints, NULL);
        if (state) {
            arg->state = state;
            return 0;
        }
    }
    return 1;
}

static void
pkey_blocking_gen_stop(void *ptr)
{
    struct pkey_blocking_generate_arg *arg = ptr;
    arg->interrupted = 1;
}

static void *
pkey_blocking_gen(void *ptr)
{
    struct pkey_blocking_generate_arg *arg = ptr;

    // OpenSSL >= 3.0: EVP_PKEY_generate() can be used for both
    if (arg->genparam && EVP_PKEY_paramgen(arg->ctx, &arg->pkey) <= 0)
        return NULL;
    if (!arg->genparam && EVP_PKEY_keygen(arg->ctx, &arg->pkey) <= 0)
        return NULL;
    return arg->pkey;
}

static VALUE
pkeyctx_generate(VALUE self, int genparam)
{
    EVP_PKEY_CTX *ctx = GetPKeyCtxPtr(self);

    struct pkey_blocking_generate_arg gen_arg = {
        .ctx = ctx,
        .yield = rb_block_given_p(),
        .pkey = NULL,
        .genparam = genparam,
        .state = 0,
        .interrupted = 0,
    };
    EVP_PKEY_CTX_set_app_data(ctx, &gen_arg);
    EVP_PKEY_CTX_set_cb(ctx, pkey_gen_cb);
    if (gen_arg.yield)
        pkey_blocking_gen(&gen_arg);
    else
        rb_thread_call_without_gvl(pkey_blocking_gen, &gen_arg,
                                   pkey_blocking_gen_stop, &gen_arg);
    EVP_PKEY_CTX_set_app_data(ctx, NULL);
    if (!gen_arg.pkey) {
        if (gen_arg.state) {
            ossl_clear_error();
            rb_jump_tag(gen_arg.state);
        }
        ossl_raise(ePKeyError,
                   genparam ? "EVP_PKEY_paramgen" : "EVP_PKEY_keygen");
    }
    return ossl_pkey_wrap(gen_arg.pkey);
}

/*
 * call-seq:
 *    ctx.paramgen_init -> self
 *
 * Prepares the context for #paramgen.
 */
static VALUE
pkeyctx_paramgen_init(VALUE self)
{
    if (EVP_PKEY_paramgen_init(GetPKeyCtxPtr(self)) <= 0)
        ossl_raise(ePKeyError, "EVP_PKEY_paramgen_init");
    return self;
}

/*
 * call-seq:
 *    ctx.paramgen -> pkey
 *    ctx.paramgen { |*values| } -> pkey
 *
 * Generates a new OpenSSL::PKey::PKey object with a new set of parameters.
 *
 * If a block is given, yields integers retrieved by
 * <tt>EVP_PKEY_CTX_get_keygen_info()</tt> whenever the
 * <tt>EVP_PKEY_CTX_set_cb()</tt> callback is invoked. The meaning of the
 * integers entirely depends on the algorithm and the provider implementation.
 *
 * See the man page EVP_PKEY_generate(3).
 * Used by OpenSSL::PKey.generate_parameters.
 */
static VALUE
pkeyctx_paramgen(VALUE self)
{
    return pkeyctx_generate(self, 1);
}

/*
 * call-seq:
 *    ctx.keygen_init -> self
 *
 * Prepares the context for #keygen.
 */
static VALUE
pkeyctx_keygen_init(VALUE self)
{
    if (EVP_PKEY_keygen_init(GetPKeyCtxPtr(self)) <= 0)
        ossl_raise(ePKeyError, "EVP_PKEY_keygen_init");
    return self;
}

/*
 * call-seq:
 *    ctx.keygen -> pkey
 *    ctx.keygen { |*values| } -> pkey
 *
 * Generates a new OpenSSL::PKey::PKey object with a new key pair.
 * See also #paramgen for parameter generation.
 *
 * See the man page EVP_PKEY_generate(3).
 * Used by OpenSSL::PKey.generate_key.
 */
static VALUE
pkeyctx_keygen(VALUE self)
{
    return pkeyctx_generate(self, 0);
}

/*
 * EVP_PKEY_OP_SIGN
 */
/*
 * call-seq:
 *    ctx.sign_init -> self
 *
 * Prepares the context for #sign.
 */
static VALUE
pkeyctx_sign_init(VALUE self)
{
    // TODO: Take EVP_SIGNATURE (OpenSSL >= 3.4)
    if (EVP_PKEY_sign_init(GetPKeyCtxPtr(self)) <= 0)
        ossl_raise(ePKeyError, "EVP_PKEY_sign_init");
    return self;
}

/*
 * call-seq:
 *    ctx.sign(data) -> string
 *
 * See the man page EVP_PKEY_sign(3).
 * Used by OpenSSL::PKey::PKey#sign_raw.
 */
static VALUE
pkeyctx_sign(VALUE self, VALUE data)
{
    EVP_PKEY_CTX *ctx = GetPKeyCtxPtr(self);

    StringValue(data);
    size_t outlen;
    if (EVP_PKEY_sign(ctx, NULL, &outlen, (unsigned char *)RSTRING_PTR(data),
                      RSTRING_LEN(data)) <= 0)
        ossl_raise(ePKeyError, "EVP_PKEY_sign");
    if (outlen > LONG_MAX)
        rb_raise(ePKeyError, "output would be too large");

    VALUE out = rb_str_new(NULL, (long)outlen);
    if (EVP_PKEY_sign(ctx, (unsigned char *)RSTRING_PTR(out), &outlen,
                      (unsigned char *)RSTRING_PTR(data),
                      RSTRING_LEN(data)) <= 0)
        ossl_raise(ePKeyError, "EVP_PKEY_sign");
    rb_str_set_len(out, outlen);
    return out;
}

/*
 * EVP_PKEY_OP_VERIFY
 */
/*
 * call-seq:
 *    ctx.verify_init -> self
 *
 * Prepares the context for #verify.
 */
static VALUE
pkeyctx_verify_init(VALUE self)
{
    if (EVP_PKEY_verify_init(GetPKeyCtxPtr(self)) <= 0)
        ossl_raise(ePKeyError, "EVP_PKEY_verify_init");
    return self;
}

/*
 * call-seq:
 *    ctx.verify(signature, data) -> true or false
 *
 * See the man page EVP_PKEY_verify(3).
 * Used by OpenSSL::PKey::PKey#verify_raw.
 */
static VALUE
pkeyctx_verify(VALUE self, VALUE sig, VALUE data)
{
    EVP_PKEY_CTX *ctx = GetPKeyCtxPtr(self);

    StringValue(sig);
    StringValue(data);
    int ret = EVP_PKEY_verify(ctx, (unsigned char *)RSTRING_PTR(sig),
                              RSTRING_LEN(sig),
                              (unsigned char *)RSTRING_PTR(data),
                              RSTRING_LEN(data));
    switch (ret) {
      case 0:
        ossl_clear_error();
        return Qfalse;
      case 1:
        return Qtrue;
      default:
        ossl_raise(ePKeyError, "EVP_PKEY_verify");
    }
}

/*
 * EVP_PKEY_OP_VERIFYRECOVER
 */
/*
 * call-seq:
 *    ctx.verify_recover_init -> self
 *
 * Prepares the context for #verify_recover.
 */
static VALUE
pkeyctx_verify_recover_init(VALUE self)
{
    if (EVP_PKEY_verify_recover_init(GetPKeyCtxPtr(self)) <= 0)
        ossl_raise(ePKeyError, "EVP_PKEY_verify_recover_init");
    return self;
}

/*
 * call-seq:
 *    ctx.verify_recover(signature) -> string
 *
 * See the man page EVP_PKEY_verify_recover(3).
 * Used by OpenSSL::PKey::PKey#verify_recover.
 */
static VALUE
pkeyctx_verify_recover(VALUE self, VALUE sig)
{
    EVP_PKEY_CTX *ctx = GetPKeyCtxPtr(self);

    StringValue(sig);
    size_t outlen;
    if (EVP_PKEY_verify_recover(ctx, NULL, &outlen,
                                (unsigned char *)RSTRING_PTR(sig),
                                RSTRING_LEN(sig)) <= 0)
        ossl_raise(ePKeyError, "EVP_PKEY_verify_recover");
    if (outlen > LONG_MAX)
        rb_raise(ePKeyError, "output would be too large");

    VALUE out = rb_str_new(NULL, (long)outlen);
    if (EVP_PKEY_verify_recover(ctx, (unsigned char *)RSTRING_PTR(out), &outlen,
                                (unsigned char *)RSTRING_PTR(sig),
                                RSTRING_LEN(sig)) <= 0)
        ossl_raise(ePKeyError, "EVP_PKEY_verify_recover");
    rb_str_set_len(out, outlen);
    return out;
}

/*
 * EVP_PKEY_OP_ENCRYPT
 */
/*
 * call-seq:
 *    ctx.encrypt_init(pkey) -> self
 *
 * Prepares the context for #encrypt.
 */
static VALUE
pkeyctx_encrypt_init(VALUE self)
{
    if (EVP_PKEY_encrypt_init(GetPKeyCtxPtr(self)) <= 0)
        ossl_raise(ePKeyError, "EVP_PKEY_encrypt_init");
    return self;
}

/*
 * call-seq:
 *    ctx.encrypt(data) -> string
 *
 * See the man page EVP_PKEY_encrypt(3).
 * Used by OpenSSL::PKey::PKey#encrypt.
 */
static VALUE
pkeyctx_encrypt(VALUE self, VALUE data)
{
    EVP_PKEY_CTX *ctx = GetPKeyCtxPtr(self);

    StringValue(data);
    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, (unsigned char *)RSTRING_PTR(data),
                         RSTRING_LEN(data)) <= 0)
        ossl_raise(ePKeyError, "EVP_PKEY_encrypt");
    if (outlen > LONG_MAX)
        rb_raise(ePKeyError, "output would be too large");

    VALUE out = rb_str_new(NULL, (long)outlen);
    if (EVP_PKEY_encrypt(ctx, (unsigned char *)RSTRING_PTR(out), &outlen,
                         (unsigned char *)RSTRING_PTR(data),
                         RSTRING_LEN(data)) <= 0)
        ossl_raise(ePKeyError, "EVP_PKEY_encrypt");
    rb_str_set_len(out, outlen);
    return out;
}

/*
 * EVP_PKEY_OP_DECRYPT
 */
/*
 * call-seq:
 *    ctx.decrypt_init(pkey) -> self
 *
 * Prepares the context for #decrypt.
 */
static VALUE
pkeyctx_decrypt_init(VALUE self)
{
    if (EVP_PKEY_decrypt_init(GetPKeyCtxPtr(self)) <= 0)
        ossl_raise(ePKeyError, "EVP_PKEY_decrypt_init");
    return self;
}

/*
 * call-seq:
 *    ctx.decrypt(data) -> string
 *
 * See the man page EVP_PKEY_decrypt(3).
 * Used by OpenSSL::PKey::PKey#decrypt.
 */
static VALUE
pkeyctx_decrypt(VALUE self, VALUE data)
{
    EVP_PKEY_CTX *ctx = GetPKeyCtxPtr(self);

    StringValue(data);
    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, (unsigned char *)RSTRING_PTR(data),
                         RSTRING_LEN(data)) <= 0)
        ossl_raise(ePKeyError, "EVP_PKEY_decrypt");
    if (outlen > LONG_MAX)
        rb_raise(ePKeyError, "output would be too large");

    VALUE out = rb_str_new(NULL, (long)outlen);
    if (EVP_PKEY_decrypt(ctx, (unsigned char *)RSTRING_PTR(out), &outlen,
                         (unsigned char *)RSTRING_PTR(data),
                         RSTRING_LEN(data)) <= 0)
        ossl_raise(ePKeyError, "EVP_PKEY_decrypt");
    rb_str_set_len(out, outlen);
    return out;
}

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

    // EVP_PKEY_OP_PARAMGEN
    rb_define_method(cPKeyContext, "paramgen_init", pkeyctx_paramgen_init, 0);
    rb_define_method(cPKeyContext, "paramgen", pkeyctx_paramgen, 0);

    // EVP_PKEY_OP_KEYGEN
    rb_define_method(cPKeyContext, "keygen_init", pkeyctx_keygen_init, 0);
    rb_define_method(cPKeyContext, "keygen", pkeyctx_keygen, 0);

    // EVP_PKEY_OP_SIGN
    rb_define_method(cPKeyContext, "sign_init", pkeyctx_sign_init, 0);
    rb_define_method(cPKeyContext, "sign", pkeyctx_sign, 1);

    // EVP_PKEY_OP_VERIFY
    rb_define_method(cPKeyContext, "verify_init", pkeyctx_verify_init, 0);
    rb_define_method(cPKeyContext, "verify", pkeyctx_verify, 2);

    // EVP_PKEY_OP_VERIFYRECOVER
    rb_define_method(cPKeyContext, "verify_recover_init", pkeyctx_verify_recover_init, 0);
    rb_define_method(cPKeyContext, "verify_recover", pkeyctx_verify_recover, 1);

    // EVP_PKEY_OP_ENCRYPT
    rb_define_method(cPKeyContext, "encrypt_init", pkeyctx_encrypt_init, 0);
    rb_define_method(cPKeyContext, "encrypt", pkeyctx_encrypt, 1);

    // EVP_PKEY_OP_DECRYPT
    rb_define_method(cPKeyContext, "decrypt_init", pkeyctx_decrypt_init, 0);
    rb_define_method(cPKeyContext, "decrypt", pkeyctx_decrypt, 1);

    id_pkey = rb_intern_const("pkey");
}

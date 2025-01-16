#include "ossl.h"
#include <openssl/trace.h>

#ifndef OPENSSL_NO_SOCK
#ifdef HAVE_OSSL_QUIC_SERVER_METHOD

static VALUE cQUICContext, cQUICListener, cQUICConnection, cQUICStream;
extern void ossl_sslctx_initialize_common(VALUE self, const SSL_METHOD *meth);
extern VALUE ossl_ssl_setup(VALUE self);

static VALUE
quicctx_initialize(int argc, VALUE *argv, VALUE self)
{
    SSL_CTX *ctx;
    const SSL_METHOD *meth;
    VALUE str;

    rb_scan_args(argc, argv, "1", &str);
    rb_call_super(0, NULL);

    // No common SSL_METHOD for server/client?
    if (SYMBOL_P(str))
        str = rb_sym2str(str);
    // FIXME
    StringValueCStr(str);
    if (!strcmp("OSSL_QUIC_client", RSTRING_PTR(str)))
        meth = OSSL_QUIC_client_method();
    else if (!strcmp("OSSL_QUIC_server", RSTRING_PTR(str)))
        meth = OSSL_QUIC_server_method();
    else
        rb_raise(rb_eArgError, "unknown SSL method `%"PRIsVALUE"'", str);

    GetSSLCTX(self, ctx);
    if (!SSL_CTX_set_ssl_version(ctx, meth))
        ossl_raise(eSSLError, "SSL_CTX_set_ssl_version");

    if(0&&!strcmp("OSSL_QUIC_server", RSTRING_PTR(str))) {
        SSL_CTX_set_msg_callback(ctx,SSL_trace);
        BIO *trace_bio = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);
        SSL_CTX_set_msg_callback_arg(ctx, trace_bio);
    }

    return self;
}

static VALUE
quiclistener_initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE io, v_ctx;

    if (rb_scan_args(argc, argv, "11", &io, &v_ctx) == 1)
        v_ctx = rb_funcall(cQUICContext, rb_intern("new"), 0);

    VALUE new_argv[] = { io, v_ctx };
    rb_call_super(2, new_argv);

    SSL *listener;
    GetSSL(self, listener);
    if (SSL_is_quic(listener)) {
        if (!SSL_set_blocking_mode(listener, 0))
            ossl_raise(eSSLError, "SSL_set_blocking_mode");
    }

    return self;
}

/*
 * call-seq:
 *    quic_conn.new(io, context = QUICContext.new) -> QUICConnection
 *
 * Shorthand for
 *   listener = QUICListener.new(io, context)
 *   listener.new_connection
 */
static VALUE
quicconn_initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE io, v_ctx;

    if (rb_scan_args(argc, argv, "11", &io, &v_ctx) == 1)
        v_ctx = rb_funcall(cQUICContext, rb_intern("new"), 0);

    VALUE new_argv[] = { io, v_ctx };
    return rb_call_super(2, new_argv);
}

static void
check_callback_state(VALUE self)
{
    ID ID_callback_state = rb_intern("callback_state");
    VALUE cb_state = rb_attr_get(self, ID_callback_state);
    if (!NIL_P(cb_state)) {
        rb_ivar_set(self, ID_callback_state, Qnil);
        ossl_clear_error();
        rb_jump_tag(NUM2INT(cb_state));
    }
}

static VALUE
quiclistener_accept_connection_nonblock(int argc, VALUE *argv, VALUE self)
{
    SSL *listener, *conn;
    VALUE opts;

    rb_scan_args(argc, argv, "0:", &opts);
    ossl_ssl_setup(self);

    GetSSL(self, listener);
    errno = 0;
    conn = SSL_accept_connection(listener, /* flags */0);
    if (!conn) {
        check_callback_state(self);
        // FIXME (2025-01-17): SSL_get_error() does not work on a listener SSL?
        if (errno == EAGAIN)
            return ID2SYM(rb_intern("wait_readable"));
        else if (1)
            ossl_raise(eSSLError, "SSL_accept_connection unexpected errno");
        else {
            const char *funcname = "SSL_accept_connection";
            int code = SSL_get_error(listener, 0);
            switch (code) {
              case SSL_ERROR_WANT_WRITE:
                // must be unreachable
                return ID2SYM(rb_intern("wait_writable"));
              case SSL_ERROR_WANT_READ:
                return ID2SYM(rb_intern("wait_readable"));
              case SSL_ERROR_SYSCALL:
                if (errno) rb_sys_fail(funcname);
                /* fallthrough */
              default: {
                  ossl_raise(eSSLError,
                             "%s%s returned=%d errno=%d state=%s",
                             funcname,
                             code == SSL_ERROR_SYSCALL ? " SYSCALL" : "",
                             code,
                             errno,
                             SSL_state_string_long(listener));
              }
            }
        }
    }

    if (!SSL_set_default_stream_mode(conn, SSL_DEFAULT_STREAM_MODE_NONE))
        ossl_raise(eSSLError, "SSL_set_default_stream_mode");
    // FIXME: LEAK
    VALUE obj = TypedData_Wrap_Struct(cQUICConnection, &ossl_ssl_type, conn);
    rb_ivar_set(obj, rb_intern("@listener"), self);
    rb_ivar_set(obj, rb_intern("@context"), rb_attr_get(self, rb_intern("@context")));
    rb_ivar_set(obj, rb_intern("@io"), rb_attr_get(self, rb_intern("@io")));
    return obj;
}

static VALUE
quiclistener_accept_connection_queue_len(VALUE self)
{
    SSL *listener;

    GetSSL(self, listener);
    return SIZET2NUM(SSL_get_accept_connection_queue_len(listener));
}

static VALUE
quiclistener_new_connection(VALUE self)
{
    SSL *listener, *conn;

    GetSSL(self, listener);
    conn = SSL_new_from_listener(listener, /* flags */0);
    if (!conn)
        ossl_raise(eSSLError, "SSL_new_from_listener");

    // FIXME: LEAK
    if (!SSL_set_default_stream_mode(conn, SSL_DEFAULT_STREAM_MODE_NONE))
        ossl_raise(eSSLError, "SSL_set_default_stream_mode");
    VALUE obj = TypedData_Wrap_Struct(cQUICConnection, &ossl_ssl_type, conn);
    rb_ivar_set(obj, rb_intern("@listener"), self);
    rb_ivar_set(obj, rb_intern("@context"), rb_attr_get(self, rb_intern("@context")));
    rb_ivar_set(obj, rb_intern("@io"), rb_attr_get(self, rb_intern("@io")));
    return obj;
}

static VALUE
quicconn_net_read_desired_p(VALUE self)
{
    SSL *conn;

    GetSSL(self, conn);
    return SSL_net_read_desired(conn) ? Qtrue : Qfalse;
}

static VALUE
quicconn_net_write_desired_p(VALUE self)
{
    SSL *conn;

    GetSSL(self, conn);
    return SSL_net_write_desired(conn) ? Qtrue : Qfalse;
}

static VALUE
quiclistener_handle_events(VALUE self)
{
    SSL *listener;

    GetSSL(self, listener);
    // FIXME: Do we need to check callback_state here?
    int ret = SSL_handle_events(listener);
    if (!ret)
        ossl_raise(eSSLError, "SSL_handle_events");
    return Qnil;
}

/*
 * call-seq:
 *    quic_conn.event_timeout -> Float or nil
 *
 * Returns the timeout value in seconds until the \SSL object needs to perform
 * internal processing due to the passage of time, even if there have been no
 * events on the underlying socket. After the timeout expires, #handle_events
 * must be called.
 *
 * Returns +nil+ if there are currently no timer events.
 */
static VALUE
quicconn_event_timeout(VALUE self)
{
    SSL *conn;
    struct timeval tv;
    int is_infinite;

    GetSSL(self, conn);
    if (!SSL_get_event_timeout(conn, &tv, &is_infinite))
        ossl_raise(eSSLError, "SSL_get_event_timeout");
    if (is_infinite)
        return Qnil;
    return DBL2NUM(tv.tv_sec + tv.tv_usec / 1e6);
}

/*
 *
 * Won't block, as this only allocates a new stream ID and not write to or
 * read from the underlying socket.
 *
 * XXX: Flags as an integer or kwargs? Currently defined are:
 *
 * #define SSL_STREAM_FLAG_UNI          (1U << 0)
 * #define SSL_STREAM_FLAG_NO_BLOCK     (1U << 1)
 * #define SSL_STREAM_FLAG_ADVANCE      (1U << 2)
 *
 * SSL_STREAM_FLAG_NO_BLOCK is no-op for us.
 */
static VALUE
quicconn_new_stream(int argc, VALUE *argv, VALUE self)
{
    SSL *conn, *stream;
    uint64_t flags = 0;
    VALUE flags_v;

    rb_scan_args(argc, argv, "01", &flags_v);
    if (!NIL_P(flags_v))
        flags = NUM2UINT64T(flags_v);
    GetSSL(self, conn);
    stream = SSL_new_stream(conn, flags);
    if (!stream)
        ossl_raise(eSSLError, "SSL_new_stream");

    VALUE obj = TypedData_Wrap_Struct(cQUICStream, &ossl_ssl_type, stream);
    rb_ivar_set(obj, rb_intern("@listener"), rb_attr_get(self, rb_intern("@listener")));
    rb_ivar_set(obj, rb_intern("@connection"), self);
    rb_ivar_set(obj, rb_intern("@context"), rb_attr_get(self, rb_intern("@context")));
    rb_ivar_set(obj, rb_intern("@io"), rb_attr_get(self, rb_intern("@io")));

    return obj;
}

static VALUE
quicconn_accept_stream_nonblock(int argc, VALUE *argv, VALUE self)
{
    SSL *conn, *stream;
    VALUE opts;

    rb_scan_args(argc, argv, "0:", &opts);
    GetSSL(self, conn);
    stream = SSL_accept_stream(conn, /* flags */0);
    if (!stream) {
        int ret2 = SSL_get_error(conn, /* XXX */0);
        switch (ret2) {
          case SSL_ERROR_WANT_READ:
            return ID2SYM(rb_intern("wait_readable"));
          case SSL_ERROR_WANT_WRITE:
            return ID2SYM(rb_intern("wait_writable"));
          case SSL_ERROR_SYSCALL:
            if (errno)
                rb_sys_fail("SSL_accept_stream");
            /* fallthrough */
          default:
            ossl_raise(eSSLError, "SSL_accept_stream");
        }
    }

    VALUE obj = TypedData_Wrap_Struct(cQUICStream, &ossl_ssl_type, stream);
    rb_ivar_set(obj, rb_intern("@listener"), rb_attr_get(self, rb_intern("@listener")));
    rb_ivar_set(obj, rb_intern("@connection"), self);
    rb_ivar_set(obj, rb_intern("@context"), rb_attr_get(self, rb_intern("@context")));
    rb_ivar_set(obj, rb_intern("@io"), rb_attr_get(self, rb_intern("@io")));
    return obj;
}

static VALUE
quicconn_accept_stream_queue_len(VALUE self)
{
    SSL *conn;

    GetSSL(self, conn);
    return SIZET2NUM(SSL_get_accept_stream_queue_len(conn));
}

/*
 * call-seq:
 *    quic_stream.stream_id -> integer
 *
 * See the man page SSL_get_stream_id(3) for details.
 */
static VALUE
quicstream_stream_id(VALUE self)
{
    SSL *stream;

    GetSSL(self, stream);
    return ULL2NUM(SSL_get_stream_id(stream));
}

/*
 * call-seq:
 *    quic_stream.conclude -> nil
 *
 * XXX: #close_write or #stop?
 *
 * See the man page SSL_stream_conclude(3) for details.
 */
static VALUE
quicstream_conclude(VALUE self)
{
    SSL *stream;

    GetSSL(self, stream);
    // Man page: "flags is reserved and should be set to 0."
    if (!SSL_stream_conclude(stream, /* flags */0))
        ossl_raise(eSSLError, "SSL_stream_conclude");
    return Qnil;
}

/*
 * call-seq:
 *    quic_stream.reset(error_code) -> nil
 *
 * See the man page SSL_stream_reset(3) for details.
 */
static VALUE
quicstream_reset(VALUE self, VALUE error_code)
{
    SSL *stream;

    GetSSL(self, stream);
    SSL_STREAM_RESET_ARGS args = {
        .quic_error_code = NUM2UINT64T(error_code),
    };
    if (!SSL_stream_reset(stream, &args, sizeof(args)))
        ossl_raise(eSSLError, "SSL_stream_conclude");
    return Qnil;
}

void
Init_ossl_ssl_quic(void)
{
    cQUICContext = rb_define_class_under(mSSL, "QUICContext", cSSLContext);
    rb_define_method(cQUICContext, "initialize", quicctx_initialize, -1);

    /*
     * Document-class: OpenSSL::SSL::QUICListener
     *
     * Represents a UDP socket listening for incoming QUIC connections, but
     * also used as a factory for a locally initiated QUIC connection.
     *
     * The underlying socket should be a bound UDP socket.
     *
     * QUICConnection instances created by this listener will share the same
     * QUICContext as the listener.
     *
     * TODO: This is also SSL, but no other functions are useful? Maybe this
     * doesn't have to inherit from SSLSocket.
     */
    cQUICListener = rb_define_class_under(mSSL, "QUICListener", cSSLSocket);
    rb_define_method(cQUICListener, "initialize", quiclistener_initialize, -1);
    rb_define_method(cQUICListener, "handle_events", quiclistener_handle_events, 0);
    rb_define_method(cQUICListener, "accept_connection_nonblock", quiclistener_accept_connection_nonblock, -1);
    rb_define_method(cQUICListener, "accept_connection_queue_len", quiclistener_accept_connection_queue_len, 0);
    rb_define_method(cQUICListener, "new_connection", quiclistener_new_connection, 0);

    /*
     * Document-class: OpenSSL::SSL::QUICConnection
     */
    cQUICConnection = rb_define_class_under(mSSL, "QUICConnection", cSSLSocket);
    rb_attr(cQUICConnection, rb_intern_const("listener"), 1, 0, Qfalse);
    rb_define_method(cQUICConnection, "initialize", quicconn_initialize, -1);
    // rb_define_method(cQUICConnection, "set_initial_peer_addr", quicconn_set_initial_peer_addr, 1);
    rb_define_method(cQUICConnection, "net_read_desired?", quicconn_net_read_desired_p, 0);
    rb_define_method(cQUICConnection, "net_write_desired?", quicconn_net_write_desired_p, 0);
    rb_define_method(cQUICConnection, "handle_events", quiclistener_handle_events, 0);
    rb_define_method(cQUICConnection, "event_timeout", quicconn_event_timeout, 0);
    rb_define_method(cQUICConnection, "new_stream", quicconn_new_stream, -1);
    rb_define_method(cQUICConnection, "accept_stream_nonblock", quicconn_accept_stream_nonblock, -1);
    rb_define_method(cQUICConnection, "accept_stream_queue_len", quicconn_accept_stream_queue_len, 0);

    /*
     * Document-class: OpenSSL::SSL::QUICStream
     */
    cQUICStream = rb_define_class_under(mSSL, "QUICStream", cSSLSocket);
    rb_attr(cQUICStream, rb_intern_const("listener"), 1, 0, Qfalse);
    rb_attr(cQUICStream, rb_intern_const("connection"), 1, 0, Qfalse);
    rb_undef_method(cQUICStream, "initialize");
    rb_define_method(cQUICStream, "stream_id", quicstream_stream_id, 0);
    rb_define_method(cQUICStream, "conclude", quicstream_conclude, 0);
    rb_define_method(cQUICStream, "reset", quicstream_reset, 1);
    // Incompatible with QUIC stream SSL
    rb_undef_method(cQUICStream, "stop");
}

#endif
#endif

# frozen_string_literal: true
require_relative "utils"

if defined?(OpenSSL::SSL)

class OpenSSL::TestSSLQUIC < OpenSSL::SSLTestCase
  def setup
    super
    OpenSSL.debug=true
  end
  def teardown
    OpenSSL.debug=false
    super
  end

  def test_many_streams
    s1 = UDPSocket.new
    s1.bind("127.0.0.1", 0)
    s2 = UDPSocket.new
    s2.connect("127.0.0.1", s1.local_address.ip_port)

    sctx = OpenSSL::SSL::QUICContext.new(:OSSL_QUIC_server)
    sctx.alpn_select_cb = -> ary { ary.first }
    sctx.add_certificate(@svr_cert, @svr_key)
    slistener = OpenSSL::SSL::QUICListener.new(s1, sctx)

    cctx = OpenSSL::SSL::QUICContext.new(:OSSL_QUIC_client)
    cctx.alpn_protocols = ["a"]
    cctx.groups = "X25519"
    clistener = OpenSSL::SSL::QUICListener.new(s2, cctx)
  ensure
    s1&.close
    s2&.close
  end

  def make_listeners(sctx: nil, cctx: nil)
    s1 = UDPSocket.new
    s1.bind("127.0.0.1", 0)
    s2 = UDPSocket.new
    s2.connect("127.0.0.1", s1.local_address.ip_port)

    sctx ||= (
      sctx = OpenSSL::SSL::QUICContext.new(:OSSL_QUIC_server)
      sctx.alpn_select_cb = -> ary { ary.first }
      sctx.add_certificate(@svr_cert, @svr_key)
      sctx
    )
    slistener = OpenSSL::SSL::QUICListener.new(s1, sctx)

    cctx ||= (
      cctx = OpenSSL::SSL::QUICContext.new(:OSSL_QUIC_client)
      cctx.alpn_protocols = ["http/1.0", "hq"]
      # FIXME: To make ClientHello small. OpenSSL client not resending the second packet after Retry?
      cctx.groups = "X25519"
      cctx
    )
    clistener = OpenSSL::SSL::QUICListener.new(s2, cctx)

    yield slistener, clistener
  ensure
    s1&.close
    s2&.close
  end

  def test_quic_blocking
    make_listeners do |slistener, clistener|
      th = Thread.new do
        conn = slistener.accept_connection
        stream = conn.accept_stream
      end

      a
      clistener.
      cconn = clistener.new_connection
      assert_instance_of(OpenSSL::SSL::QUICConnection, cconn)
      assert_same(clistener, cconn.listener)

      # 1-RTT with Retry
      assert_same(cconn, cconn.connect)
      sconn = slistener.accept_connection
      assert_instance_of(OpenSSL::SSL::QUICConnection, sconn)
      assert_same(slistener, sconn.listener)

      assert_same(cconn, cconn.connect)
      assert_same(clistener, cconn.listener)
      assert_equal("http/1.0", cconn.alpn_protocol)
    end
  end

  def test_quic_simple
    s1 = UDPSocket.new
    s1.bind("127.0.0.1", 0)
    s2 = UDPSocket.new
    s2.connect("127.0.0.1", s1.local_address.ip_port)

    received_alpn = nil
    sctx = OpenSSL::SSL::QUICContext.new(:OSSL_QUIC_server)
    sctx.alpn_select_cb = -> ary { received_alpn = ary; ary.last }
    sctx.add_certificate(@svr_cert, @svr_key)
    slistener = OpenSSL::SSL::QUICListener.new(s1, sctx)

    cctx = OpenSSL::SSL::QUICContext.new(:OSSL_QUIC_client)
    cctx.alpn_protocols = ["http/1.0", "hq"]
    # FIXME: To make ClientHello small. OpenSSL client not resending the second packet after Retry?
    cctx.groups = "X25519"
    clistener = OpenSSL::SSL::QUICListener.new(s2, cctx)
    cconn = clistener.new_connection
    assert_instance_of(OpenSSL::SSL::QUICConnection, cconn)
    assert_same(clistener, cconn.listener)

    # 1-RTT with Retry
    assert_equal(:wait_readable, cconn.connect_nonblock(exception: false))
    s1.wait_readable
    assert_equal(:wait_readable, slistener.accept_connection_nonblock(exception: false))
    s2.wait_readable
    assert_equal(:wait_readable, cconn.connect_nonblock(exception: false))
    s1.wait_readable

    slistener.handle_events
    assert_equal(1, slistener.accept_connection_queue_len)
    sconn = slistener.accept_connection_nonblock(exception: false)
    assert_instance_of(OpenSSL::SSL::QUICConnection, sconn)
    assert_same(slistener, sconn.listener)
    assert_equal(["http/1.0", "hq"], received_alpn)

    assert_same(cconn, cconn.connect_nonblock(exception: false))
    assert_same(clistener, cconn.listener)
    assert_equal("hq", cconn.alpn_protocol)

    cstream = cconn.new_stream
    assert_kind_of(OpenSSL::SSL::QUICStream, cstream)
    assert_same(cconn, cstream.connection)
    assert_same(clistener, cconn.listener)
    assert_equal(0, cstream.stream_id)
    assert_equal(5, cstream.syswrite("hello"))

    slistener.handle_events
    assert_equal(1, sconn.accept_stream_queue_len)
    sstream = sconn.accept_stream_nonblock(exception: false)
    assert_kind_of(OpenSSL::SSL::QUICStream, sstream)
    assert_same(sconn, sstream.connection)
    assert_same(slistener, sconn.listener)
    assert_equal(0, sstream.stream_id)
    assert_equal("hello", sstream.sysread(5))

    # For simplicity, we disable default stream in connection SSL
    assert_raise(OpenSSL::SSL::SSLError) { cconn.syswrite("a") }
    assert_raise(OpenSSL::SSL::SSLError) { sconn.syswrite("b") }
    assert_raise(OpenSSL::SSL::SSLError) { cconn.sysread(1) }
    assert_raise(OpenSSL::SSL::SSLError) { sconn.sysread(1) }
  ensure
    s1&.close
    s2&.close
  end

  def test_quic_ctx_new
    ctx = OpenSSL::SSL::QUICContext.new(:OSSL_QUIC_server)
    ctx = OpenSSL::SSL::QUICContext.new(:OSSL_QUIC_client)
    ctx = OpenSSL::SSL::QUICContext.new("OSSL_QUIC_client")
    assert_raise(ArgumentError) { OpenSSL::SSL::QUICContext.new(:TLSv1_2) }
  end
end

end

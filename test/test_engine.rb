require_relative 'utils'

class OpenSSL::TestEngine < Test::Unit::TestCase

  def test_engines_free # [ruby-dev:44173]
    OpenSSL::Engine.load
    OpenSSL::Engine.engines
    OpenSSL::Engine.engines
    OpenSSL::Engine.cleanup # [ruby-core:40669]
  end

  def test_openssl_engine_builtin
    engine = OpenSSL::Engine.load("openssl")
    assert_equal(true, engine)
    assert_equal(1, OpenSSL::Engine.engines.size)
    cleanup
  end

  def test_openssl_engine_by_id_string
    engine = OpenSSL::Engine.by_id("openssl")
    assert_not_nil(engine)
    assert_equal(1, OpenSSL::Engine.engines.size)
    cleanup
  end

  def test_openssl_engine_id_name_inspect
    engine = OpenSSL::Engine.by_id("openssl")
    assert_equal("openssl", engine.id)
    assert_not_nil(engine.name)
    assert_not_nil(engine.inspect)
    cleanup
  end

  def test_openssl_engine_digest_sha1
    engine = OpenSSL::Engine.by_id("openssl")
    digest = engine.digest("SHA1")
    assert_not_nil(digest)
    data = "test"
    assert_equal(OpenSSL::Digest::SHA1.digest(data), digest.digest(data))
  end

  private

  def cleanup
    OpenSSL::Engine.cleanup
    assert_equal(0, OpenSSL::Engine::engines.size)
  end

end if defined?(OpenSSL)


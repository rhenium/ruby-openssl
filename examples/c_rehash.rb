#!/usr/bin/env ruby

require 'openssl'
require 'md5'

class CHashDir
  def initialize(dirpath)
    @dirpath = dirpath
    @hash_list = nil
  end

  def hash_dir
    @hash_list = Hash.new
    do_hash_dir
  end

private

  def do_hash_dir
    delete_symlink
    Dir.glob(File.join(@dirpath, '*.pem')) do |pemfile|
      cert = load_pem_file(pemfile)
      case cert
      when OpenSSL::X509::Certificate
	link_hash_cert(pemfile, cert)
      when OpenSSL::X509::CRL
	link_hash_crl(pemfile, cert)
      else
	STDERR.puts("WARNING: #{pemfile} does not contain a certificate or CRL: skipping")
      end
    end
  end

  def delete_symlink
    Dir.entries(@dirpath).each do |entry|
      next unless /^[\da-f]+\.r{0,1}\d+$/ =~ entry
      path = File.join(@dirpath, entry)
      File.unlink(path) if FileTest.symlink?(path)
    end
  end

  def load_pem_file(filepath)
    str = File.open(filepath).read
    begin
      OpenSSL::X509::Certificate.new(str)
    rescue
      begin
	OpenSSL::X509::CRL.new(str)
      rescue
	nil
      end
    end
  end

  def link_hash_cert(org_filename, cert)
    unless link_hash(org_filename, cert.subject, cert.to_der) { |name_hash, idx| "#{name_hash}.#{idx}" }
      STDERR.puts("WARNING: Skipping duplicate certificate #{org_filename}")
    end
  end

  def link_hash_crl(org_filename, crl)
    unless link_hash(org_filename, crl.issuer, crl.to_der) { |name_hash, idx| "#{name_hash}.r#{idx}" }
      STDERR.puts("WARNING: Skipping duplicate CRL #{org_filename}")
    end
  end

  def link_hash(org_filename, name, der)
    name_hash = sprintf("%x", name.hash)
    md5_fingerprint = MD5.hexdigest(der).upcase
    idx = 0
    filepath = nil
    while true
      filepath = File.join(@dirpath, yield(name_hash, idx))
      break unless FileTest.symlink?(filepath) or FileTest.exist?(filepath)
      if @hash_list[filepath] == md5_fingerprint
	return false
      end
      idx += 1
    end
    STDOUT.puts("#{org_filename} => #{filepath}")
    symlink(org_filename, filepath)
    @hash_list[filepath] = md5_fingerprint
    true
  end

  def symlink(from, to)
    begin
      File.symlink(from, to)
    rescue
      File.open(to, "w") do |f|
	f << File.open(from).read
      end
    end
  end
end

if $0 == __FILE__
  dirlist = ARGV
  dirlist << '/usr/ssl/certs' if dirlist.empty?
  dirlist.each do |dir|
    CHashDir.new(dir).hash_dir
  end
end

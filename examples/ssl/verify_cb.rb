VerifyCallbackProc = Proc.new{ |ok, x509_store_ctx|
  code  = x509_store_ctx.verify_status
  msg   = x509_store_ctx.verify_message
  depth = x509_store_ctx.verify_depth
  x509  = x509_store_ctx.cert

  if $OPT_v
    STDERR.print <<-_eof_
    ------verify callback start------
    ok,code,depth = #{ok},#{code}:#{msg},#{depth}
    x509 = #{x509.to_str}
    -------verify callback end-------
    _eof_
    if !ok
      STDERR.print "Couldn't verify peer. Do you want to progerss? [y]: "
      ok = true unless /^n/i =~ STDIN.gets()
    end
  end
  ok
}


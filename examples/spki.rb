#!/usr/bin/env ruby

require "openssl"
include OpenSSL

txt = "MIICUDCCATgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDUIhGCK7sr\r\nO+jHy7S1ZllFCEPzhlneTnjUnjZWuZEVu7c14NUhJzpNXg//6sCoiy5cQPaIYFIs\r\nded/PosTNfJVPX6El+bWk/2Elf5iVYcScRpf+RkUBR6T3WAMFPCajx3JFonhqhny\r\n5bSXU41h7/oLpnQkeeo76ujKoxjV6vl+y36jCeUAI+dzrWLznUswWVnWvdNt/z1h\r\npWILYtCKexLsz+aOqA6NdGTVDb8r+iDorU2KGL4BJjMXGr/LutYQjeVVXZTuaeN+\r\nxa75TVMcSEzvVQm8Dk1u3C3r3hm9I9zKnpta5NqiToR/fA85Qw5YhjEZMWT/Rj+7\r\nB5LBp5NcX35vAgMBAAEWEGNoYWxsZW5nZSBzdHJpbmcwDQYJKoZIhvcNAQEEBQAD\r\nggEBABdXwDZ9yDyyC5xw8rN/+/xAZSYa8xn4gsUEg4P/mM22WZaqh/NXroXUcU5F\r\nQBeGTYlT//wVlobLeES64Mk/FaCIXrZrLRAxb5QUYIupH2MifRU5XWriYcc6pp7S\r\nD1N+U6MOUFPMziqLf2AYqXBxuky1KhFeXuL6t9j1IadEY9UgTbUQ9Joyt50PoacM\r\ncc2i22GGdpowx7mrB0hnkmYmZ5CgQkrxNM2m4TCuuQwVIyaGgED5Xpa29QWaPhkM\r\njqjHBL4FOmPgYtaIFiFihQziYj5WYOtSEcIcEs/mHPx0lrY9V0fzp2yMGz+AQ3XF\r\nylBqpB33EBqXn/NGzHgWfdU1vEM="
txt.gsub!(/(\r|\n)/,"")

spki = Netscape::SPKI.new(txt)

puts spki.to_s

File.open('./spki.pem', 'w') {|f|
  f << spki.to_pem
}

puts "DONE."


#!/usr/bin/env ruby

require 'net/telnets'
require 'getopts'
require 'etc'
begin require 'verify_cb'; rescue LoadError; end

getopts 'v', 'C:', 'c:', 'k:'

options = {}
# ordinary options.
options['Host'] = ARGV[0] || "localhost"
options['Port'] = ARGV[1] || "telnets"
options['Prompt'] = /[$%>#] \z/n

# for SSL/TLS
options['Cert'] = $OPT_c
options['Key'] = $OPT_k
options['CAFile'] = $OPT_C if $OPT_C && File::file?($OPT_C)
options['CAPath'] = $OPT_C if $OPT_C && File::directory?($OPT_C)
options['VerifyMode'] = SSL::VERIFY_PEER if $OPT_v
options['VerifyCallback'] = VerifyCallbackProc if defined? VerifyCallbackProc

# getting Password.
username = Etc::getlogin || Etc::getpwuid[0]
system "stty -echo"
print "Passwd for #{username}@#{options['Host']}: "
passwd = $stdin.gets.chomp
print "\n"
system "stty echo"

t = Net::Telnet.new(options)
t.login(username, passwd)
prompt = t.ssl? ? "Telnets: " : "Telnet: "
while $stdout.write(prompt) && line = $stdin.gets
  line.chomp!
  t.cmd(line){|c| print c } 
end
t.close

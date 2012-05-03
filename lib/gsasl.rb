require "gsasl/version"
require "gsasl/native"

module Gsasl
  autoload :Context, "gsasl/context"
  autoload :RemoteAuthenticator, "gsasl/remote_authenticator"
  autoload :Peer, "gsasl/peer"
  
  class GsaslError < StandardError;
    attr_accessor :code
  end
end

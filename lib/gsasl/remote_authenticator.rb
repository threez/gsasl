module Gsasl
  # This class handles remote authentication sessions that are based on a socket
  # like interaction mechanism. This class will most of the time not be used
  # directly but through helper methods (See Peer#authenticate_with).
  class RemoteAuthenticator
    def initialize
      @receive_callback = nil
      @send_callback = nil
    end
  
    # This defines or calls the recieve callback. It will be defined, if a
    # block is given, otherwise the callback is going to be called.
    # @yield the block that is going to be called if data need to be read from
    #   the remote site.
    # @yieldreturn [String] the callback should return a string that includes
    #   a challenge
    def receive(&block)
      if block_given?
        # define the callback
        @receive_callback = block
      elsif @receive_callback
        @receive_callback.call
      else
        raise GsaslError, "The receive callback is not defined!"
      end
    end
    
    # This defines or calls the send callback. It will be defined, if a
    # block is given, otherwise the callback is going to be called.
    # @yield [data] the block that is going to be called if data need to be
    #   send to the remote site.
    # @yieldparam [String] data that should be send to a remote site.
    def send(data = nil, &block)
      if block_given?
        # define the callback
        @send_callback = block
      elsif @send_callback
        @send_callback.call(data)
      else
        raise GsaslError, "The send callback is not defined!"
      end
    end
  end
end

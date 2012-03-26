module Gsasl
  # A peer is a client or server side that processes data to do an
  # authentication.
  class Peer
    # give access to the session object (ffi) that is used by the peer
    # @api private
    attr_accessor :session
    
    # Initalize a peer for authentication (either a client or server)
    # @param [FFI::MemoryPointer] context the pointer to the context used
    # @param [String] mechanism_name the name of the mechanism to use
    # @param [Symbol] type either (:server or :client)
    def initialize(context, mechanism_name, type = :server)
      @context = context
      peer = FFI::MemoryPointer.new :pointer
      result = nil
      case type
        when :client
          result = Gsasl.gsasl_client_start @context, mechanism_name, peer
        else
          result = Gsasl.gsasl_server_start @context, mechanism_name, peer
      end
      Gsasl.raise_error!(result)
    ensure
      @session = peer.get_pointer(0)
    end
    
    # Sets a property for this peer.
    # @param [Fixnum] property on of the Gsasl API Keys
    # @param [String] value the value tho set for the api key
    # @example
    #   peer[Gsasl::GSASL_PASSWORD] = "secret"
    def []=(property, value)
      Gsasl.gsasl_property_set(@session, property, value)
    end
    
    # Reads a property from the peer.
    # @param [Fixnum] property on of the Gsasl API Keys
    # @return [String, nil] The value if there is one or nil
    # @example
    #   peer[Gsasl::GSASL_AUTHID] #=> "joe"
    def [](property)
      Gsasl.gsasl_property_get(@session, property)
    end
    
    # Registers a callback for the peer. In case a variable is not provided.
    # @yield [property] The callback that will be calles during the processing.
    # @yieldparam [Fixnum] property a property for the 
    # @yieldreturn [Fixnum, nil] The return code for the callback or nil
    def callback(&block)
      @callback = block
    end
    
    # Used as a server hook in the local test environment.
    # @return [Array<Fixnum, String>] Result code and base64 encoded challenge
    def read #b64_str
      process
    end
    
    # Used as a server hook in the local test environment.
    # @param [String] b64_str Base64 encoded challenge
    # @return [Array<Fixnum, String>] Result code and base64 encoded challenge
    def send(b64_str)
      process b64_str
    end
    
    # Authenticates against a server that implemennts read and send.
    # @param [Gsasl::Peer] server a server peer object
    # @return [Boolean] true if the authentication was successfull, 
    #   false otherwise
    def authenticate(server)
      result = -1
      
      begin
        result, input = server.read
        result, output = process input
        
        if (result == GSASL_NEEDS_MORE || result == GSASL_OK)
          result, output = server.send(output)
        else
          Gsasl.raise_error!(result)
        end
      end while result == GSASL_NEEDS_MORE
      
      Gsasl.raise_error!(result) unless Gsasl::GSASL_AUTHENTICATION_ERROR
      result == Gsasl::GSASL_OK
    end
    
    # Close the authentication peer. This should be done after one
    # authenticaion.
    def close
      Gsasl.gsasl_finish(@session)
    end
    
    # Process a challenge on the peer. There might be no input at the start.
    # @param [String] input the inital challenge.
    # @return [Array<Fixnum, String>] Result code and base64 encoded challenge
    def process(input = nil)
      output_ptr = FFI::MemoryPointer.new :pointer
      result = Gsasl.gsasl_step64(@session, input, output_ptr)
      if result == GSASL_NEEDS_MORE || result == GSASL_OK
        output = output_ptr.get_pointer(0)
        [result, output.read_string.to_s]
      else
        [result, nil]
      end
    ensure  
      Gsasl.gsasl_free(output)
    end
    
    # Call the callback of the peer.
    # @param [Fixnum] property the api key.
    def call(property)
      @callback.call(property) if @callback
    end
  end
end

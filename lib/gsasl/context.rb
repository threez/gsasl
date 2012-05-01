module Gsasl
  class Context
    # Access the peers of a given session. This is used to find peers for the
    # global `Gsasl::CALLBACK`.
    # @api private
    attr_accessor :peers
    
    # Create a new gsasl authentication context.
    def initialize
      ctx = FFI::MemoryPointer.new :pointer
      result = Gsasl.gsasl_init(ctx)
      @context = ctx.get_pointer(0)
      Gsasl.raise_error!(result)
      @peers = {}
      Gsasl.new_context @context.address, self
      Gsasl.gsasl_callback_set(@context, CALLBACK)
    end
    
    # Returns or checks agains the passed version of GNU SASL.
    # @param [String] check the version string to check against.
    # @return [String, nil] the version string if the check was successful, nil
    #   otherwise
    def version(check = nil)
      Gsasl.gsasl_check_version check
    end
    
    # Checks if the client peer supports the passed mechanism
    # @param [String] mechanism_name the mechnism to check for
    # @return [Boolean] true if it is supported false otherwise
    def client_support_for?(mechanism_name)
      Gsasl.gsasl_client_support_p(@context, mechanism_name) == 1
    end
    
    # Checks if the server peer supports the passed mechanism
    # @param [String] mechanism_name the mechnism to check for
    # @return [Boolean] true if it is supported false otherwise
    def server_support_for?(mechanism_name)
      Gsasl.gsasl_server_support_p(@context, mechanism_name) == 1
    end
    
    # Closes the sasl peer for the context. Should be called after authenication.
    def close
      Gsasl.gsasl_done(@context)
    end
    
    # Returns a list of mechanisms for the server peer
    # @return [Array<String>] the list of possible mechanisms
    def server_mechanisms
      mechanisms :server
    end
    
    # Returns a list of mechanisms for the client peer
    # @return [Array<String>] the list of possible mechanisms
    def client_mechanisms
      mechanisms :client
    end
    
    # Creates the server peer based on the passed mechanism
    # @param [String] mechanism_name the name of the mechanism
    # @return [Gsasl::Peer] the server peer
    # @example
    #   peer = @session.create_server("CRAM-MD5")
    # @example Server with password database attached directly
    #   peer = @session.create_server("CRAM-MD5") do |type, authid|
    #     DB.find_password_for_user(auth_id) if type == :password
    #   end
    def create_server(mechanism_name, realm = "gsasl", &block)
      peer = Peer.new(@context, mechanism_name, :server)
      @peers[peer.session.address] = peer
      peer.realm = realm
      peer.authentication_callback = block if block_given?
      peer
    end
    
    # Creates the client peer based on the passed mechanism
    # @param [String] mechanism_name the name of the mechanism
    # @return [Gsasl::Peer] the client peer
    # @example
    #   peer = @session.create_client("CRAM-MD5")
    def create_client(mechanism_name)
      peer = Peer.new(@context, mechanism_name, :client)
      @peers[peer.session.address] = peer
      peer
    end
  
  private
    
    # Returns a list of mechanisms for the passed type (type can be :client or
    # :server)
    # @param [Symbol] type the type to check mechanisms for
    # @return [Array<String>] the list of possible mechanisms
    def mechanisms(type)
      out = FFI::MemoryPointer.new :pointer
      result = Gsasl.send("gsasl_#{type}_mechlist", @context, out)
      Gsasl.raise_error!(result)
      data = out.get_pointer(0)
      list = data.read_string.split(/\s/)
      list
    ensure
      Gsasl.gsasl_free(data)
    end
  end
end

require 'digest/md5'
  
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
    
    # Updates the peer with credential information
    # @param [String] authid the username auth id of the user to use for auth.
    # @example [String] password the password of the specified user
    #   peer.credentials! "username", "secret"
    def credentials!(authid, password)
      self[Gsasl::GSASL_AUTHID] = authid
      self[Gsasl::GSASL_PASSWORD] = password
    end
    
    # Updates the peer with secure id information
    # @param [String] authid the username auth id of the user to use for auth.
    # @example [String] passcode the passcode of the specified id
    #   peer.credentials! "username", "12312312331"
    def secureid!(authid, passcode)
      self[Gsasl::GSASL_AUTHID] = authid
      self[Gsasl::GSASL_PASSCODE] = passcode
    end
    
    # Updates the peer with a service definition
    # @param [String] name the name of the service. a list of service names
    #   can be found here: http://www.iana.org/assignments/gssapi-service-names/gssapi-service-names.xml
    # @param [String] hostname the name of the host the service is on
    # @example
    #   peer.service! "smtp", "localhost"
    def service!(name, hostname)
      self[Gsasl::GSASL_SERVICE] = name
      self[Gsasl::GSASL_HOSTNAME] = hostname
    end
    
    # Update the anoynmous token that the client peer used to authenticate with
    #   the server
    # @param [String] token the token that will be send to the server
    # @example
    #   peer.anonymous! "some-token"
    def anonymous!(token)
      self[Gsasl::GSASL_ANONYMOUS_TOKEN] = token
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
    
    # Update the realm of the peer
    # @param [String] val the realm that should be set on the peer
    # @example
    #   peer.realm = "Awesome SMTPD"
    def realm=(val)
      self[Gsasl::GSASL_REALM] = val
    end
    
    # Returns the realm that is set for the peer
    # @return [String, nil] the realm if one was set or nil
    def realm
      self[Gsasl::GSASL_REALM]
    end
    
    # Update authzid for external authentication
    # @param [String] val the authzid that should be set on the peer
    # @example
    #   peer.realm = "Awesome SMTPD"
    def authzid=(val)
      self[Gsasl::GSASL_AUTHZID] = val
    end
    
    # Returns the authzid for external authentication
    # @return [String, nil] the authzid if one was set or nil
    def authzid
      self[Gsasl::GSASL_AUTHZID]
    end
    
    # Returns the authid for authentication
    # @return [String, nil] the authid if one was set or nil
    def authid
      self[Gsasl::GSASL_AUTHID]
    end
    
    # Generate a digest md5 hased password that can be stored in the database
    # to authenticate the user without saving a plaintext password.
    # @note if the realm of the peer is set, it will be used to generate the
    #   hash. Therefore it has tp be set later on the peer also to match the
    #   password again. Alternatively the realm can be passed directly.
    # @param [String] authid the username or id to generate the password for
    # @param [String] password the password to hash
    # @param [String] realm the realm if not passed the peer realm will be used
    #   if no realm is set to an empty string ("")
    def digest_md5_hashed_password(authid, password, realm = nil)
      Digest::MD5.hexdigest("#{authid}:#{realm || self.realm}:#{password}")
    end
    
    # Registers a callback for the peer. In case a variable is not provided.
    # @yield [property] The callback that will be calles during the processing.
    # @yieldparam [Fixnum] property a property for the 
    # @yieldreturn [Fixnum, nil] The return code for the callback or nil
    def callback(&block)
      @callback = block
    end
    
    # Sets an authentication callback on the peer. The passed block will be
    # called to determine the authentication password, secureid, password hash
    # etc.. Depending on what mechanisms one supports different types must be
    # handled.
    # @yieldparam [Symbol] type is that should be handled in this case
    # @yieldparam [String] authid the authenticated id
    # @yieldreturn [String, true, nil] a mechanism specific value or no value
    #   to indicate a failed authentication
    def authentication_callback=(block)
      self.callback do |property|
        case property
        when Gsasl::GSASL_PASSWORD
          handle_password_authentication(&block)
        when Gsasl::GSASL_VALIDATE_SECURID
          handle_secureid_authentication(&block)
        when Gsasl::GSASL_DIGEST_MD5_HASHED_PASSWORD
          handle_digest_md5_authentication(&block)
        when Gsasl::GSASL_VALIDATE_ANONYMOUS
          handle_anonymous_authentication(&block)
        when Gsasl::GSASL_VALIDATE_EXTERNAL
          handle_external_authentication(&block)
        end
      end
    end
    
    # Handles the password authentication with the passed block. Therefor the
    # block has to return the password for the passed user. No return value means
    # that the user is unknown and the authentication fails.
    # @yield [type, authid] the block that handles password gathering.
    # @yieldparam [Symbol] type is allways :password for password auth
    # @yieldparam [String] authid the authenticated id
    # @yieldreturn [String, nil] the password or nil if the user wasn't found
    def handle_password_authentication
      if password = yield(:password, authid)
        self[Gsasl::GSASL_PASSWORD] = password
        Gsasl::GSASL_OK
      end
    end
    
    # Handles the digest md5 based password hash authentication with the passed
    # block. Therefor theblock has to return the hashed password for the passed
    # user. No return value means that the user is unknown and the 
    # authentication fails.
    # @yield [type, authid] the block that handles password hash gathering.
    # @yieldparam [Symbol] type is allways :digest_md5_hashed_password for 
    #   digest md5 based password hash auth
    # @yieldparam [String] authid the authenticated id
    # @yieldreturn [String, nil] the password hash or nil if the user wasn't
    #   found
    def handle_digest_md5_authentication
      if hash = yield(:digest_md5_hashed_password, authid)
        self[Gsasl::GSASL_DIGEST_MD5_HASHED_PASSWORD] = hash
        Gsasl::GSASL_OK
      end
    end
    
    # Handles the secureid authentication with the passed block. Therefor the
    # block has to return the secureid for the passed user. No return value means
    # that the user is unknown and the authentication fails.
    # @yield [type, authid] the block that handles secureid gathering.
    # @yieldparam [Symbol] type is allways :passcode for secureid auth
    # @yieldparam [String] authid the authenticated id
    # @yieldreturn [String, nil] the secureid or nil if the user wasn't found
    def handle_secureid_authentication
      if secureid = yield(:passcode, authid)
        self[Gsasl::GSASL_PASSCODE] = secureid
        Gsasl::GSASL_OK
      end
    end
    
    # Handles the anonymous authentication with the passed block. Therefor the
    # block has to return the success for the anonymous user. No return value
    # means that the user is not allowed and the authentication fails.
    # @yield [type, authid] the block that handles anonymous authentication
    # @yieldparam [Symbol] type is allways :anonymous for external auth
    # @yieldparam [String] authid the authenticated id
    # @yieldreturn [Boolean, nil] true or nil if the anonymous isn't allowed
    def handle_anonymous_authentication
      Gsasl::GSASL_OK if yield(:anonymous, self[Gsasl::GSASL_ANONYMOUS_TOKEN])
    end
    
    # Handles the external authentication with the passed block. Therefor the
    # block has to return the success for the passed user. No return value means
    # that the user is unknown and the authentication fails.
    # @yield [type, authid] the block that handles external authentication
    # @yieldparam [Symbol] type is allways :external for external auth
    # @yieldparam [String] authid the authenticated id
    # @yieldreturn [Boolean, nil] true or nil if the user wasn't authenticated
    def handle_external_authentication
      Gsasl::GSASL_OK if yield(:external, authzid)
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
      result = GSASL_NEEDS_MORE
      input = nil
      
      while result == GSASL_NEEDS_MORE
        result, output = server.send(input)
        break if result != Gsasl::GSASL_NEEDS_MORE
        _, input = process output
      end
      
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

require 'ffi'

module Gsasl
  extend FFI::Library
  ffi_lib "libgsasl"
  
  # RFC 2222: SASL mechanisms are named by strings, from 1 to 20
  # characters in length, consisting of upper-case letters, digits,
  # hyphens, and/or underscores.  SASL mechanism names must be
  # registered with the IANA.
  GSASL_MIN_MECHANISM_SIZE = 1,
  GSASL_MAX_MECHANISM_SIZE = 20
    
  # Error codes for library functions.
  GSASL_OK = 0
  GSASL_NEEDS_MORE = 1
  GSASL_UNKNOWN_MECHANISM = 2
  GSASL_MECHANISM_CALLED_TOO_MANY_TIMES = 3
  GSASL_MALLOC_ERROR = 7
  GSASL_BASE64_ERROR = 8
  GSASL_CRYPTO_ERROR = 9
  GSASL_SASLPREP_ERROR = 29
  GSASL_MECHANISM_PARSE_ERROR = 30
  GSASL_AUTHENTICATION_ERROR = 31
  GSASL_INTEGRITY_ERROR = 33
  GSASL_NO_CLIENT_CODE = 35
  GSASL_NO_SERVER_CODE = 36
  GSASL_NO_CALLBACK = 51
  GSASL_NO_ANONYMOUS_TOKEN = 52
  GSASL_NO_AUTHID = 53
  GSASL_NO_AUTHZID = 54
  GSASL_NO_PASSWORD = 55
  GSASL_NO_PASSCODE = 56
  GSASL_NO_PIN = 57
  GSASL_NO_SERVICE = 58
  GSASL_NO_HOSTNAME = 59
  GSASL_NO_CB_TLS_UNIQUE = 65
  GSASL_NO_SAML20_IDP_IDENTIFIER = 66
  GSASL_NO_SAML20_REDIRECT_URL = 67
  GSASL_NO_OPENID20_AUTH_IDENTIFIER = 68
  
  # Mechanism specific errors.
  GSASL_GSSAPI_RELEASE_BUFFER_ERROR = 37
  GSASL_GSSAPI_IMPORT_NAME_ERROR = 38
  GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR = 39
  GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR = 40
  GSASL_GSSAPI_UNWRAP_ERROR = 41
  GSASL_GSSAPI_WRAP_ERROR = 42
  GSASL_GSSAPI_ACQUIRE_CRED_ERROR = 43
  GSASL_GSSAPI_DISPLAY_NAME_ERROR = 44
  GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR = 45
  GSASL_KERBEROS_V5_INIT_ERROR = 46
  GSASL_KERBEROS_V5_INTERNAL_ERROR = 47
  GSASL_SHISHI_ERROR = GSASL_KERBEROS_V5_INTERNAL_ERROR
  GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE = 48
  GSASL_SECURID_SERVER_NEED_NEW_PIN = 49
  GSASL_GSSAPI_ENCAPSULATE_TOKEN_ERROR = 60
  GSASL_GSSAPI_DECAPSULATE_TOKEN_ERROR = 61
  GSASL_GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR = 62
  GSASL_GSSAPI_TEST_OID_SET_MEMBER_ERROR = 63
  GSASL_GSSAPI_RELEASE_OID_SET_ERROR = 64
  
  # Information properties, e.g., username.
  GSASL_AUTHID = 1
  GSASL_AUTHZID = 2
  GSASL_PASSWORD = 3
  GSASL_ANONYMOUS_TOKEN = 4
  GSASL_SERVICE = 5
  GSASL_HOSTNAME = 6
  GSASL_GSSAPI_DISPLAY_NAME = 7
  GSASL_PASSCODE = 8
  GSASL_SUGGESTED_PIN = 9
  GSASL_PIN = 10
  GSASL_REALM = 11
  GSASL_DIGEST_MD5_HASHED_PASSWORD = 12
  GSASL_QOPS = 13
  GSASL_QOP = 14
  GSASL_SCRAM_ITER = 15
  GSASL_SCRAM_SALT = 16
  GSASL_SCRAM_SALTED_PASSWORD = 17
  GSASL_CB_TLS_UNIQUE = 18
  GSASL_SAML20_IDP_IDENTIFIER = 19
  GSASL_SAML20_REDIRECT_URL = 20
  GSASL_OPENID20_AUTH_IDENTIFIER = 21
  
  # Client callbacks.
  GSASL_SAML20_AUTHENTICATE_IN_BROWSER = 250
  
  # Server validation callback properties.
  GSASL_VALIDATE_SIMPLE = 500
  GSASL_VALIDATE_EXTERNAL = 501
  GSASL_VALIDATE_ANONYMOUS = 502
  GSASL_VALIDATE_GSSAPI = 503
  GSASL_VALIDATE_SECURID = 504
  GSASL_VALIDATE_SAML20 = 505
  
  # Gsasl_cipher
  GSASL_CIPHER_DES = 1
  GSASL_CIPHER_3DES = 2
  GSASL_CIPHER_RC4 = 4
  GSASL_CIPHER_RC4_40 = 8
  GSASL_CIPHER_RC4_56 = 16
  GSASL_CIPHER_AES = 32
  
  # Quality of Protection types (DIGEST-MD5 and GSSAPI).  The
  # integrity and confidentiality values is about application data
  # wrapping.  We recommend that you use @GSASL_QOP_AUTH with TLS as
  # that combination is generally more secure and have better chance
  # of working than the integrity/confidentiality layers of SASL.
  GSASL_QOP_AUTH = 1,
  GSASL_QOP_AUTH_INT = 2,
  GSASL_QOP_AUTH_CONF = 4
  
  # the callback signature for the global callback
  callback :gsasl_callback, [ :pointer, :pointer, :int], :int
  
  # lib ffi mapped functions
  attach_function :gsasl_init, [ :pointer ], :int
  attach_function :gsasl_done, [ :pointer ], :void
  attach_function :gsasl_check_version, [ :string ], :string
  attach_function :gsasl_strerror, [ :int ], :string
  attach_function :gsasl_client_support_p, [ :pointer, :string ], :int
  attach_function :gsasl_server_support_p, [ :pointer, :string ], :int
  attach_function :gsasl_server_start, [ :pointer, :string, :pointer ], :int
  attach_function :gsasl_client_start, [ :pointer, :string, :pointer ], :int
  attach_function :gsasl_finish, [ :pointer ], :void
  attach_function :gsasl_client_mechlist, [ :pointer, :pointer ], :int
  attach_function :gsasl_server_mechlist, [ :pointer, :pointer ], :int
  attach_function :gsasl_free, [ :pointer ], :void
  attach_function :gsasl_property_set, [ :pointer, :int , :string ], :void
  attach_function :gsasl_property_get, [ :pointer, :int ], :string
  attach_function :gsasl_callback_set, [ :pointer, :gsasl_callback ], :void
  attach_function :gsasl_step64, [ :pointer, :string, :pointer], :int
  
  # Raises an error if the passed result is not GSASL_OK
  # @param [Fixnum] result that should be checked
  # @raises [GsaslError] if a different result occured
  def self.raise_error!(result)
    if result != GSASL_OK
      raise GsaslError, Gsasl.gsasl_strerror(result)
    end
  end
  
  # Handles at a global level all callbacks that are made by the gsasl library.
  # The context and session (or peer) will be used to proxy the events to the
  # corresponding object.
  CALLBACK = Proc.new do |context, peer, property|
    # find the object...
    if context = find_by_context(context.address)
      if peer = context.peers[peer.address]
        # ...and call the callback with the property
        result = peer.call(property)
      end
    end
    
    # if there is no callback handler (nil) return that information
    result || Gsasl::GSASL_NO_CALLBACK
  end
  
  # Helper to find an context (or session) by the passed id. Used by `CALLBACK`.
  # @api private
  # @param [Fixnum] id the id of the sesseion (pointer to context struct)
  # @return [Gsasl::Context, nil] the session or nil if nothing was found
  def self.find_by_context(id)
    @contexts ||= {}
    @contexts[id]
  end

  # Registers the context and the session for later use in the global callback.
  # @api private
  # @param [Fixnum] id the id of the sesseion (pointer to context struct)
  # @param [Gsasl::Context] context the session to save for later use
  def self.new_context(id, context)
    @contexts ||= {}
    @contexts[id] = context
  end
end

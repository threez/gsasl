# GNU SASL for Ruby

This libaray is a lib ffi based wrapper for the [GNU SASL](http://www.gnu.org/software/gsasl/) library. It supports a variaty of different authentication mechanisms. Those are the mechanisms supported for the current versions:

* **EXTERNAL**: Authentication via out of band information.
* **ANONYMOUS**: Mechanism for anonymous access to resources.
* **PLAIN**: Clear text username and password.
* **LOGIN**: Non-standard clear text username and password.
* **CRAM-MD5**: Challenge-Response Authentication Mechanism.
* **DIGEST-MD5**: Digest Authentication.
* **SCRAM-SHA-1**: SCRAM-SHA-1 authentication.
* **NTLM**: Microsoft NTLM authentication.
* **SECURID**: Authentication using tokens.
* **GSSAPI**: GSSAPI (Kerberos 5) authentication.
* **GS2-KRB5**: Improved GSSAPI (Kerberos 5) authentication.
* **KERBEROS\_V5**: Experimental KERBEROS\_V5 authentication.
* **SAML20**: Experimental SAML20 authentication.
* **OPENID20**: Experimental OPENID20 authentication.

# Install libgsasl

To use the library the libgsasl must be installed on the system.

## Mac OS X

Install the library using homebrew:

    brew install libgsasl

# Use in Ruby

In the following example the server and the client are on the same machine. If the server is on the remote site, one has to implement a server that will return the next challenge on `server#read` and implements a `server#send` to send the challenge to the server. Also it is possible to not use the `#authenticate` function but to implement the processing individually.

    session = Gsasl::Context.new
    client = session.create_client("CRAM-MD5")
    server = session.create_server("CRAM-MD5")
    
    server.callback do |property|
      if property == Gsasl::GSASL_PASSWORD
        if server[Gsasl::GSASL_AUTHID] == "joe"
          server[Gsasl::GSASL_PASSWORD] = "secret"
        end
        Gsasl::GSASL_OK
      end
    end
    
    client[Gsasl::GSASL_AUTHID] = "joe"
    client[Gsasl::GSASL_PASSWORD] = "secret"
    
    client.authenticate(server).should be_true
  
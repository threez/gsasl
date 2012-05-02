# GNU SASL for Ruby [![Build Status](https://secure.travis-ci.org/threez/gsasl.png)](http://travis-ci.org/threez/gsasl)

This libaray is a lib ffi based wrapper for the [GNU SASL](http://www.gnu.org/software/gsasl/) library. It supports a variaty of different authentication mechanisms. Those are the mechanisms supported for the current versions:

* **EXTERNAL**: Authentication via out of band information.
* **ANONYMOUS**: Mechanism for anonymous access to resources.
* **PLAIN**: Clear text username and password.
* **LOGIN**: Non-standard clear text username and password.
* **CRAM-MD5**: Challenge-Response Authentication Mechanism.
* **DIGEST-MD5**: Digest Authentication.
* **SCRAM-SHA-1**: SCRAM-SHA-1 authentication.
* **SECURID**: Authentication using tokens.

Platfrom and compile flags dependend mechanisms:

* **NTLM**: Microsoft NTLM authentication.
* **GSSAPI**: GSSAPI (Kerberos 5) authentication.
* **GS2-KRB5**: Improved GSSAPI (Kerberos 5) authentication.
* **KERBEROS\_V5**: Experimental KERBEROS\_V5 authentication.
* **SAML20**: Experimental SAML20 authentication.
* **OPENID20**: Experimental OPENID20 authentication.

# Install libgsasl

To use the library the libgsasl must be installed on the system. The gem uses libffi to access the library so no further comilation needed. It also should work with all important versions of ruby.

## Mac OS X

Install the library using homebrew:

    brew install libgsasl
    
## Debian & Ubuntu

Install the library using apt-get:

    sudo apt-get install libgsasl7

## FreeBSD

Install the library using ports (as root):

    cd /usr/ports/security/gsasl/
    make install clean

# Use in Ruby

## To authenticate against a server

In this example a client authenticates against an IMAP4 server. The methode `#authenticate_with` is used to setup all the data and callbacks neccessary to perform the authentication.

    # connect to an imap server
    require 'socket'
    socket = TCPSocket.new('imap.example.com', 143)
    puts socket.gets
    
    # issue an authenticate command
    socket.print "a1 AUTHENTICATE LOGIN\r\n"
    
    # authenticate using the imap4 protocol specifics
    context = Gsasl::Context.new
    context.authenticate_with("LOGIN", "user@example.com", "secret") do |remote|
      remote.receive { socket.gets.gsub!("\r\n|+\s", "") }
      remote.send    { |data| socket.print "#{data}\r\n" }
    end
    
    # logout
    puts socket.gets
    socket.print "a2 LOGOUT\r\n"
    
    # close connection
    puts socket.gets
    socket.close

## Advanced

In the following example the server and the client are on the same machine. If the server is on the remote site, one has to implement a server that will return the next challenge on `server#read` and implements a `server#send` to send the challenge to the server. Also it is possible to not use the `#authenticate` function but to implement the processing individually.

    session = Gsasl::Context.new
    client = session.create_client("CRAM-MD5")
    server = session.create_server("CRAM-MD5") do |type, authid|
      "secret" if type = :password && authid == "joe"
    end
    
    @client.credentials!("joe", "secret")
    @client.authenticate(@server).should be_true

# Copyright Licence

Copyright (c) 2012 Vincent Landgraf All Rights Reserved. Released under a MIT License.

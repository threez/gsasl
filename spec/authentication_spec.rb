require 'spec_helper'
require 'digest/md5'
require 'securerandom'

describe "Authentications" do
  before(:each) do
    @session = Gsasl::Context.new
  end
  
  describe "CRAM-MD5" do
    before(:each) do
      @client = @session.create_client("CRAM-MD5")
      @server = @session.create_server("CRAM-MD5")
    end
    
    it "should be able to authenticate correctly" do
      @server.callback do |property|
        if property == Gsasl::GSASL_PASSWORD
          if @server[Gsasl::GSASL_AUTHID] == "joe"
            @server[Gsasl::GSASL_PASSWORD] = "secret"
          end
          Gsasl::GSASL_OK
        end
      end
      
      @client[Gsasl::GSASL_AUTHID] = "joe"
      @client[Gsasl::GSASL_PASSWORD] = "secret"
      
      @client.authenticate(@server).should be_true
    end
    
    it "should be possible to not authenticate correctly" do
      @server.callback do |property|
        if property == Gsasl::GSASL_PASSWORD
          if @server[Gsasl::GSASL_AUTHID] == "joe"
            @server[Gsasl::GSASL_PASSWORD] = "test"
          end
          Gsasl::GSASL_OK
        end
      end
      
      @client[Gsasl::GSASL_AUTHID] = "joe"
      @client[Gsasl::GSASL_PASSWORD] = "secret"
      
      @client.authenticate(@server).should be_false
    end
    
    after(:each) do
      @client.close
      @server.close
    end
  end
  
  describe "DIGEST-MD5" do
    before(:each) do
      @client = @session.create_client("DIGEST-MD5")
      @server = @session.create_server("DIGEST-MD5")
    end
    
    it "should be able to authenticate correctly" do
      @server.callback do |property|
        if property == Gsasl::GSASL_PASSWORD
          if @server[Gsasl::GSASL_AUTHID] == "joe"
            @server[Gsasl::GSASL_PASSWORD] = "secret"
          end
          Gsasl::GSASL_OK
        end
      end
      
      @client[Gsasl::GSASL_SERVICE] = "imap"
      @client[Gsasl::GSASL_HOSTNAME] = "localhost"
      @client[Gsasl::GSASL_AUTHID] = "joe"
      @client[Gsasl::GSASL_PASSWORD] = "secret"
      
      @client.authenticate(@server).should be_true
    end
    
    it "should be possible to not authenticate correctly" do
      @server.callback do |property|
        if property == Gsasl::GSASL_PASSWORD
          if @server[Gsasl::GSASL_AUTHID] == "joe"
            @server[Gsasl::GSASL_PASSWORD] = "test"
          end
          Gsasl::GSASL_OK
        end
      end
      
      @client[Gsasl::GSASL_SERVICE] = "imap"
      @client[Gsasl::GSASL_HOSTNAME] = "localhost"
      @client[Gsasl::GSASL_AUTHID] = "joe"
      @client[Gsasl::GSASL_PASSWORD] = "secret"
      
      @client.authenticate(@server).should be_false
    end
    
    after(:each) do
      @client.close
      @server.close
    end
  end
  
  describe "SCRAM-SHA-1" do
    before(:each) do
      @client = @session.create_client("SCRAM-SHA-1")
      @server = @session.create_server("SCRAM-SHA-1")
    end
    
    it "should be able to authenticate correctly" do
      @server.callback do |property|
        if property == Gsasl::GSASL_PASSWORD
          if @server[Gsasl::GSASL_AUTHID] == "joe"
            @server[Gsasl::GSASL_PASSWORD] = "secret"
            Gsasl::GSASL_OK
          end
        end
      end
      
      @client[Gsasl::GSASL_AUTHID] = "joe"
      @client[Gsasl::GSASL_PASSWORD] = "secret"
      
      @client.authenticate(@server).should be_true
    end
    
    it "should be possible to not authenticate correctly" do
      @server.callback do |property|
        if property == Gsasl::GSASL_PASSWORD
          if @server[Gsasl::GSASL_AUTHID] == "joe"
            @server[Gsasl::GSASL_PASSWORD] = "secret"
            Gsasl::GSASL_OK
          end
        end
      end
      
      @client[Gsasl::GSASL_AUTHID] = "joe1"
      @client[Gsasl::GSASL_PASSWORD] = "secret"
      
      @client.authenticate(@server).should be_false
    end
    
    after(:each) do
      @client.close
      @server.close
    end
  end
  
  describe "PLAIN" do
    before(:each) do
      @client = @session.create_client("PLAIN")
      @server = @session.create_server("PLAIN")
    end
    
    it "should be able to authenticate correctly" do
      @server.callback do |property|
        if property == Gsasl::GSASL_PASSWORD
          if @server[Gsasl::GSASL_AUTHID] == "joe"
            @server[Gsasl::GSASL_PASSWORD] = "secret"
          end
          Gsasl::GSASL_OK
        end
      end
      
      @client[Gsasl::GSASL_AUTHID] = "joe"
      @client[Gsasl::GSASL_PASSWORD] = "secret"
      
      @client.authenticate(@server).should be_true
    end
    
    it "should be possible to not authenticate correctly" do
      @server.callback do |property|
        if property == Gsasl::GSASL_PASSWORD
          if @server[Gsasl::GSASL_AUTHID] == "joe"
            @server[Gsasl::GSASL_PASSWORD] = "test"
          end
          Gsasl::GSASL_OK
        end
      end
      
      @client[Gsasl::GSASL_AUTHID] = "joe"
      @client[Gsasl::GSASL_PASSWORD] = "secret"
      
      @client.authenticate(@server).should be_false
    end
    
    after(:each) do
      @client.close
      @server.close
    end
  end
  
  describe "LOGIN" do
    before(:each) do
      @client = @session.create_client("LOGIN")
      @server = @session.create_server("LOGIN")
    end
    
    it "should be able to authenticate correctly" do
      @server.callback do |property|
        if property == Gsasl::GSASL_PASSWORD
          if @server[Gsasl::GSASL_AUTHID] == "joe"
            @server[Gsasl::GSASL_PASSWORD] = "secret"
          end
          Gsasl::GSASL_OK
        end
      end
      
      @client[Gsasl::GSASL_AUTHID] = "joe"
      @client[Gsasl::GSASL_PASSWORD] = "secret"
      
      @client.authenticate(@server).should be_true
    end
    
    it "should be possible to not authenticate correctly" do
      @server.callback do |property|
        if property == Gsasl::GSASL_PASSWORD
          if @server[Gsasl::GSASL_AUTHID] == "joe"
            @server[Gsasl::GSASL_PASSWORD] = "test"
          end
          Gsasl::GSASL_OK
        end
      end
      
      @client[Gsasl::GSASL_AUTHID] = "joe"
      @client[Gsasl::GSASL_PASSWORD] = "secret"
      
      @client.authenticate(@server).should be_false
    end
    
    after(:each) do
      @client.close
      @server.close
    end
  end
  
  describe "SECURID" do
    before(:each) do
      @client = @session.create_client("SECURID")
      @server = @session.create_server("SECURID")
    end
    
    it "should be able to authenticate correctly" do
      @server.callback do |property|
        if property == Gsasl::GSASL_VALIDATE_SECURID
          if @server[Gsasl::GSASL_AUTHID] == "joe" && 
            @server[Gsasl::GSASL_PASSCODE] == "579a0eaa23c2c60a1bc5"
            Gsasl::GSASL_OK
          end
        end
      end
      
      @client[Gsasl::GSASL_AUTHID] = "joe"
      @client[Gsasl::GSASL_PASSCODE] = "579a0eaa23c2c60a1bc5"
      
      @client.authenticate(@server).should be_true
    end
    
    it "should be possible to not authenticate correctly" do
      @server.callback do |property|
        if property == Gsasl::GSASL_PASSCODE
          if @server[Gsasl::GSASL_AUTHID] == "joe"
            @server[Gsasl::GSASL_PASSCODE] = "579a0eaa23c2c60a1bc5"
          end
          Gsasl::GSASL_OK
        end
      end
      
      @client[Gsasl::GSASL_AUTHID] = "joe"
      @client[Gsasl::GSASL_PASSCODE] = "sekshfkjhcret"
      
      @client.authenticate(@server).should be_false
    end
    
    after(:each) do
      @client.close
      @server.close
    end
  end
  
  describe "DIGEST-MD5 with digest md5 based password" do
    before(:each) do
      @client = @session.create_client("DIGEST-MD5")
      @server = @session.create_server("DIGEST-MD5")
      @server[Gsasl::GSASL_REALM] = "test"
    end
    
    it "should be able to authenticate correctly" do
      @server.callback do |property|
        if property == Gsasl::GSASL_DIGEST_MD5_HASHED_PASSWORD
          if @server[Gsasl::GSASL_AUTHID] == "joe"
            passwd_hash = Digest::MD5.hexdigest("joe:test:secret")
            @server[Gsasl::GSASL_DIGEST_MD5_HASHED_PASSWORD] = passwd_hash
          end
          Gsasl::GSASL_OK
        end
      end
      
      @client[Gsasl::GSASL_SERVICE] = "imap"
      @client[Gsasl::GSASL_HOSTNAME] = "localhost"
      @client[Gsasl::GSASL_AUTHID] = "joe"
      @client[Gsasl::GSASL_REALM] = "test"
      @client[Gsasl::GSASL_PASSWORD] = "secret"
      
      @client.authenticate(@server).should be_true
    end
    
    after(:each) do
      @client.close
      @server.close
    end
  end
  
  after(:each) do
    @session.close
  end
end

require 'spec_helper'

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
  
  after(:each) do
    @session.close
  end
end

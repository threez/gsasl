require 'spec_helper'
require 'securerandom'

describe "Abstraction layer for the authentication callback" do
  before(:each) do
    @session = Gsasl::Context.new
  end
  
  context "ANONYMOUS" do
    before(:each) do
      @client = @session.create_client("ANONYMOUS")
      @server = @session.create_server("ANONYMOUS") do |type, authid|
        type == :anonymous and authid == "joe"
      end
    end
    
    it "should be able to authenticate with correct credentials" do
      @client.anonymous! "joe"
      @client.authenticate(@server).should be_true
    end
    
    it "should not be able to authenticate with wrong credentials" do
      @client.anonymous! "joe1"
      @client.authenticate(@server).should be_false
    end
    
    after(:each) do
      @client.close
      @server.close
    end
  end
  
  context "EXTERNAL" do
    before(:each) do
      @client = @session.create_client("EXTERNAL")
      @server = @session.create_server("EXTERNAL") do |type, authid|
        type == :external and authid == "joe"
      end
    end
    
    it "should be able to authenticate with correct credentials" do
      @client.authzid = "joe"
      @client.authenticate(@server).should be_true
    end
    
    it "should not be able to authenticate with wrong credentials" do
      @client.authzid = "joe1"
      @client.authenticate(@server).should be_false
    end
    
    after(:each) do
      @client.close
      @server.close
    end
  end
  
  context "PLAIN" do
    before(:each) do
      @client = @session.create_client("PLAIN")
      @server = @session.create_server("PLAIN") do |type, authid|
        "secret" if type = :password && authid == "joe"
      end
    end
    
    it "should be able to authenticate with correct credentials" do
      @client.credentials!("joe", "secret")
      @client.authenticate(@server).should be_true
    end
    
    it "should not be able to authenticate with wrong credentials" do
      @client.credentials!("joe1", "secret")
      @client.authenticate(@server).should be_false
    end
    
    after(:each) do
      @client.close
      @server.close
    end
  end
  
  context "LOGIN" do
    before(:each) do
      @client = @session.create_client("LOGIN")
      @server = @session.create_server("LOGIN") do |type, authid|
        "secret" if type = :password && authid == "joe"
      end
    end
    
    it "should be able to authenticate with correct credentials" do
      @client.credentials!("joe", "secret")
      @client.authenticate(@server).should be_true
    end
    
    it "should not be able to authenticate with wrong credentials" do
      @client.credentials!("joe1", "secret")
      @client.authenticate(@server).should be_false
    end
    
    after(:each) do
      @client.close
      @server.close
    end
  end
  
  context "SECURID" do
    before(:each) do
      @client = @session.create_client("SECURID")
      @server = @session.create_server("SECURID") do |type, authid|
        "579a0eaa23c2c60a1bc5" if type = :passcode && authid == "joe"
      end
    end
    
    it "should be able to authenticate with correct credentials" do
      @client.secureid!("joe", "579a0eaa23c2c60a1bc5")
      @client.authenticate(@server).should be_true
    end
    
    it "should not be able to authenticate with wrong credentials" do
      @client.secureid!("joe1", "579a0eaa23c2c60a1bc5")
      @client.authenticate(@server).should be_false
    end
    
    after(:each) do
      @client.close
      @server.close
    end
  end
  
  context "CRAM-MD5" do
    before(:each) do
      @client = @session.create_client("CRAM-MD5")
      @server = @session.create_server("CRAM-MD5") do |type, authid|
        "secret" if type = :password && authid == "joe"
      end
    end
    
    it "should be able to authenticate with correct credentials" do
      @client.credentials!("joe", "secret")
      @client.authenticate(@server).should be_true
    end
    
    it "should not be able to authenticate with wrong credentials" do
      @client.credentials!("joe1", "secret")
      @client.authenticate(@server).should be_false
    end
    
    after(:each) do
      @client.close
      @server.close
    end
  end
  
  context "DIGEST-MD5" do
    before(:each) do
      @client = @session.create_client("DIGEST-MD5")
      @server = @session.create_server("DIGEST-MD5") do |type, authid|
        # emulate a stored md5 hased password a cleartext password could be used
        # instead. The format is: <authid:realm:password>
        if type = :digest_md5_hashed_password && authid == "joe"
          @server.digest_md5_hashed_password(authid, "secret")
        end
      end
    end
    
    it "should be able to authenticate with correct credentials" do
      @client.credentials!("joe", "secret")
      @client.service!("smtp", "localhost")
      @client.authenticate(@server).should be_true
    end
    
    it "should not be able to authenticate with wrong credentials" do
      @client.credentials!("joe1", "secret")
      @client.service!("smtp", "localhost")
      @client.authenticate(@server).should be_false
    end
    
    after(:each) do
      @client.close
      @server.close
    end
  end

  context "SCRAM-SHA-1" do
    before(:each) do
      @client = @session.create_client("SCRAM-SHA-1")
      @server = @session.create_server("SCRAM-SHA-1") do |type, authid|
        "secret" if type = :password && authid == "joe"
      end
    end
    
    it "should be able to authenticate with correct credentials" do
      @client.credentials!("joe", "secret")
      @client.service!("smtp", "localhost")
      @client.authenticate(@server).should be_true
    end
    
    it "should not be able to authenticate with wrong credentials" do
      @client.credentials!("joe1", "secret")
      @client.service!("smtp", "localhost")
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

require 'spec_helper'

describe Gsasl::Context do
  before(:each) do
    @session = Gsasl::Context.new
  end
  
  it "should be possible to get the version number of gsasl" do
    @session.version.should =~ /\d.\d.\d/
  end
  
  it "should be possible to check the version" do
    @session.version("1.7.0").should == nil
  end
  
  it "should be possible to check the support for client authentications" do
    @session.client_support_for?("CRAM-MD5").should be_true
    @session.client_support_for?("NONE").should be_false
  end
  
  it "should be possible to check the support for server authentications" do
    @session.server_support_for?("CRAM-MD5").should be_true
    @session.server_support_for?("NONE").should be_false
  end
  
  it "should return the supported server mechanisms as list" do
    @session.server_mechanisms.should include("CRAM-MD5")
    @session.server_mechanisms.should include("DIGEST-MD5")
    @session.server_mechanisms.should include("PLAIN")
  end
  
  it "should return the supported client mechanisms as list" do
    @session.client_mechanisms.should include("CRAM-MD5")
    @session.client_mechanisms.should include("DIGEST-MD5")
    @session.client_mechanisms.should include("PLAIN")
  end
  
  after(:each) do
    @session.close
  end
end

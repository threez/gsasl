require 'spec_helper'

describe Gsasl::Context do
  before(:each) do
    @session = Gsasl::Context.new
  end

  it "should be possible to create a client peer" do
    @session.create_client("CRAM-MD5")
  end
  
  context "with peer" do
    before(:each) do
      @peer = @session.create_client("CRAM-MD5")
    end
    
    it "should return nil on no values" do
      @peer[Gsasl::GSASL_AUTHID].should be_nil
      @peer[Gsasl::GSASL_PASSWORD].should be_nil
    end
    
    it "should be possible to set parameter" do
      @peer[Gsasl::GSASL_AUTHID] = "joe"
      @peer[Gsasl::GSASL_PASSWORD] = "secret"
    end
    
    it "should be possible to read set parameter" do
      @peer[Gsasl::GSASL_AUTHID] = "joe"
      @peer[Gsasl::GSASL_PASSWORD] = "secret"
      @peer[Gsasl::GSASL_AUTHID].should == "joe"
      @peer[Gsasl::GSASL_PASSWORD].should == "secret"
    end
    
    it "should be possible to call a set callback" do
      test_property = 0
      @peer.callback { |property| test_property = property }
      @peer.call(10)
      test_property.should == 10
    end
  end

  after(:each) do
    @session.close
  end
end

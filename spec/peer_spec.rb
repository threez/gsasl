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
    
    it "should to set the credentails" do
      @peer.credentials!("joe", "secret")
      @peer[Gsasl::GSASL_AUTHID].should == "joe"
      @peer[Gsasl::GSASL_PASSWORD].should == "secret"
    end
    
    it "should to set the secureid" do
      @peer.secureid!("joe", "123123123123")
      @peer[Gsasl::GSASL_AUTHID].should == "joe"
      @peer[Gsasl::GSASL_PASSCODE].should == "123123123123"
    end
    
    it "should update and return the realm" do
      @peer.realm.should == nil
      @peer.realm = "Awesome SMTPD"
      @peer.realm.should == "Awesome SMTPD"
    end
    
    it "should be possible to set the service details" do
      @peer.service!("smtp", "localhost")
      @peer[Gsasl::GSASL_SERVICE].should == "smtp"
      @peer[Gsasl::GSASL_HOSTNAME].should == "localhost"
    end
    
    it "should set the anonymous token for a peer" do
      @peer.anonymous! "some-token"
      @peer[Gsasl::GSASL_ANONYMOUS_TOKEN].should == "some-token"
    end
    
    it "should set and get the authzid fir external authentications" do
      @peer.authzid.should == nil
      @peer.authzid = "someid"
      @peer[Gsasl::GSASL_AUTHZID].should == "someid"
      @peer.authzid.should == "someid"
    end
    
    it "should be possible to generate a pre generated md5 hash" do
      @peer.digest_md5_hashed_password("joe", "secret").should == \
        "fb2441a715a5484c6fa16147c4a6b7a8"
    end
  end

  after(:each) do
    @session.close
  end
end

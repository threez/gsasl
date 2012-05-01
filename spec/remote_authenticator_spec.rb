require 'spec_helper'

describe Gsasl::RemoteAuthenticator do
  it "should be possible to create an remote authenticator" do
    Gsasl::RemoteAuthenticator.new
  end
  
  context "with authenticator" do
    before(:each) do
      @authenticator = Gsasl::RemoteAuthenticator.new
    end
    
    it "should assign and call the recieve method hock" do
      a = 0
      @authenticator.receive { a += 1 }
      @authenticator.receive.should == 1
      a.should == 1
    end
    
    it "should assign and call the send method hock" do
      a = nil
      @authenticator.send { |data|  a = data }
      @authenticator.send("asd").should == "asd"
      a.should == "asd"
    end
    
    it "should raise an error if receive is called without being defined" do
      lambda do
        @authenticator.receive
      end.should raise_error(Gsasl::GsaslError)
    end
    
    it "should raise an error if send is called without being defined" do
      lambda do
        @authenticator.send
      end.should raise_error(Gsasl::GsaslError)
    end
  end
end

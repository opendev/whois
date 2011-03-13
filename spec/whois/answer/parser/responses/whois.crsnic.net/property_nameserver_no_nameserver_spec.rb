# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/whois/answer/parser/responses/whois.crsnic.net/property_nameserver_no_nameserver_spec.rb
#
# and regenerate the tests with the following rake task
#
#   $ rake genspec:parsers
#

require 'spec_helper'
require 'whois/answer/parser/whois.crsnic.net.rb'

describe Whois::Answer::Parser::WhoisCrsnicNet, "property_nameserver_no_nameserver.expected" do

  before(:each) do
    file = fixture("responses", "whois.crsnic.net/property_nameserver_no_nameserver.txt")
    part = Whois::Answer::Part.new(:body => File.read(file))
    @parser = klass.new(part)
  end

  context "#nameservers" do
    it do
      @parser.nameservers.should be_a(Array)
    end
    it do
      @parser.nameservers.should == []
    end
  end
end
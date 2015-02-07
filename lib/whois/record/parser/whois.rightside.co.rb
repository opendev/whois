#--
# Ruby Whois parser for Rightside TLDs
#++


require 'lib/whois/record/parser/whois.donuts.co'


module Whois
  class Record
    class Parser

      # Parser for the whois.rightside.co server.
      # identical to the Donuts whois server
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      class WhoisRightsideCo < WhoisDonutsCo
      end

    end
  end
end
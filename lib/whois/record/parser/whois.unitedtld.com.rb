#--
# Ruby Whois parser for Rightside/Donuts/United TLD domains
#++

require 'whois/record/parser/base_icann_compliant'

module Whois
  class Record
    class Parser

      # Parser for the whois.unitedtld.com server, used for some Rightside and Donuts domains
      # identical to the Donuts whois server
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      class WhoisUnitedtldCom < BaseIcannCompliant
        self.scanner = Scanners::BaseIcannCompliant, {
            pattern_available: /^Domain not found\.\n/
        }


        property_supported :domain_id do
          node('Domain ID')
        end


        property_supported :expires_on do
          node('Registry Expiry Date') do |value|
            Time.parse(value)
          end
        end


        property_supported :registrar do
          return unless node('Sponsoring Registrar')
          Record::Registrar.new(
              id:           node('Sponsoring Registrar IANA ID'),
              name:         node('Sponsoring Registrar'),
              organization: node('Sponsoring Registrar')
          )
        end


        private

        def build_contact(element, type)
          if (contact = super)
            contact.id = node("#{element} ID")
          end
          contact
        end
      end

    end
  end
end
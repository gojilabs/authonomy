# frozen_string_literal: true

require 'active_support'
require 'active_support/key_generator'

require_relative 'authonomy/encryptor'
require_relative 'authonomy/token_generator'

require 'uri/mailto'

module Authonomy
  class << self
    WRITER_METHODS = %i[
      pepper
      stretches
      password_length
      phone_length
      access_token_ttl
      refresh_token_ttl
      invite_token_ttl
      invite_token_length
      reset_password_token_ttl
      reset_password_token_length
    ].freeze
    attr_writer(*WRITER_METHODS)

    READER_METHODS = %i[
      pepper
    ].freeze
    attr_reader(*READER_METHODS)

    def configure
      yield self if block_given?
    end

    def stretches
      @stretches || 11
    end

    def password_regexp
      %r{
        \A
        (?=.*\d)                                      # Must contain a digit
        (?=.*[a-z])                                   # Must contain a lowercase character
        (?=.*[A-Z])                                   # Must contain an uppercase character
        (?=.*[!"#$%&'()*+,\-./:;<=>?@\[\\\]^_`{|}~])  # Must contain a special character
      }x
    end

    def password_length
      @password_length || (8..128)
    end

    def email_regexp
      # /\A[^@\s]+@([^@\s]+\.)+[^@\W]+\z/
      URI::MailTo::EMAIL_REGEXP
    end

    def phone_regexp
      /\A[\d\s+\-#*@&.,()]+\z/
    end

    def phone_length
      @phone_length || (3..40)
    end

    def money_regexp
      /[+\-]?[\d.,]+/
    end

    def url_regexp
      %r{
        \A
        (?:(?:https?|ftp)://)                                         # scheme
        (?:\S+(?::\S*)?@)?                                            # user:pass authentication
        (?:
          (?!10(?:\.\d{1,3}){3})                                      # IP address exclusion
          (?!127(?:\.\d{1,3}){3})                                     # private & local networks
          (?!169\.254(?:\.\d{1,3}){2})
          (?!192\.168(?:\.\d{1,3}){2})
          (?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})
          (?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])                          # IP address dotted notation octets
          (?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}                     # excludes loopback network 0.0.0.0, reserved space >= 224.0.0.0, network & broacast addresses
          (?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))                   # (first & last IP address of each class)
        |
          (?:(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)     # host name
          (?:\.(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)*  # domain name
          (?:\.(?:[a-z\u00a1-\uffff]{2,}))                            # TLD identifier
        )
        (?::\d{2,5})?                                                 # port number
        (?:/\S*)?                                                     # resource path
        \z
      }xi
    end

    def access_token_ttl
      @access_token_ttl || 30.minutes
    end

    def refresh_token_ttl
      @refresh_token_ttl || 1.week
    end

    def invite_token_ttl
      @invite_token_ttl || 24.hours
    end

    def invite_token_length
      @invite_token_length || 48
    end

    def reset_password_token_ttl
      @reset_password_token_ttl || 60.minutes
    end

    def reset_password_token_length
      @reset_password_token_length || 48
    end
  end
end

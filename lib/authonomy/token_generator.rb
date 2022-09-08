# frozen_string_literal: true

require 'openssl'
require 'securerandom'

module Authonomy
  class TokenGenerator
    ALGO = 'SHA256'

    class << self
      def generator
        @generator ||= new(
          ActiveSupport::CachingKeyGenerator.new(
            ActiveSupport::KeyGenerator.new(Authonomy.secret_key_base)
          )
        )
      end
    end

    def initialize(key_generator)
      @key_generator = key_generator
    end

    def digest(column, token)
      key = key_for(column)
      token.present? && OpenSSL::HMAC.hexdigest(ALGO, key, token.to_s)
    end

    def generate(klass, column, length)
      key = key_for(column)

      loop do
        token = friendly_token(length)
        encoded_token = OpenSSL::HMAC.hexdigest(ALGO, key, token)
        break [token, encoded_token] unless klass.find_by(column => encoded_token)
      end
    end

    private

    def key_for(column)
      @key_generator.generate_key("Authonomy #{column}")
    end

    def friendly_token(length)
      rlength = (length * 3) / 4
      SecureRandom.urlsafe_base64(rlength).tr('lIO0', 'sxyz')
    end
  end
end

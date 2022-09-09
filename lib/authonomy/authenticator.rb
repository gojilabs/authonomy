# frozen_string_literal: true

require 'jwt'

module Authonomy
  class Authenticator
    ALGO = 'HS256'
    LEEWAY = 30.seconds

    class << self
      # Returns access_token and refresh_token for user authentication
      def tokens(subject, refresh_exp = nil)
        now = Time.now.utc.to_i

        access_payload = {
          sub: subject,
          iat: now,
          exp: now + Authonomy.access_token_ttl.to_i
        }
        refresh_payload = {
          acc: payload_digest(access_payload),
          iat: now
        }
        if refresh_exp
          refresh_payload[:exp] = refresh_exp.is_a?(Integer) ? refresh_exp : now + Authonomy.refresh_token_ttl.to_i
        end

        [encode(access_payload), encode(refresh_payload)]
      end

      # Based on given access and refresh tokens authenticates user or not
      def authenticate(klass, access_token, refresh_token)
        now = Time.now.utc.to_i

        generate_response_tokens = false
        refresh_payload = nil
        refresh_exp = nil

        access_opts = {
          verify_sub:        true,
          verify_iat:        true,
          verify_expiration: true
        }

        if refresh_token
          refresh_opts = {
            verify_iat:        true,
            verify_expiration: false
          }

          refresh_payload = decode(refresh_token, refresh_opts)
          refresh_exp = refresh_payload['exp']

          if refresh_exp && refresh_exp > now
            # don't verify access token expiration if refresh token has an exp timestamp and not expired yet
            access_opts[:verify_expiration] = false
          else
            # sliding expiration
            refresh_exp = nil
          end
        end

        access_payload = decode(access_token, access_opts)

        if refresh_payload
          if refresh_payload['acc'] && refresh_payload['acc'] != payload_digest(access_payload)
            # puts 'Refresh token mismatch'
            return nil
          end

          # to avoid tokens mismatch for multiple simultaneous calls
          generate_response_tokens = true # if now - access_payload['iat'] > 60
        end

        user = klass.find_by(id: access_payload['sub'])

        unless user
          # puts 'User not found'
          return nil
        end

        if user.respond_to?(:access_expired_at) && user.access_expired_at.to_i > access_payload['iat']
          # puts 'User access expired'
          return nil
        end

        if generate_response_tokens
          [user] + tokens(user.id, refresh_exp)
        else
          user
        end

      rescue ::JWT::DecodeError
        nil
      end

      private

      def encode(payload)
        ::JWT.encode(payload, hmac_secret, ALGO)
      end

      def decode(token, opts = {})
        ::JWT.decode(token, hmac_secret, true, opts.merge(leeway: LEEWAY, algorithms: [ALGO])).first
        # can throw JWT::IncorrectAlgorithm, JWT::VerificationError, JWT::ExpiredSignature, JWT::InvalidIatError, JWT::InvalidSubError
      end

      def payload_digest(payload)
        Digest::MD5.hexdigest(payload.to_json)
      end

      def hmac_secret
        Authonomy.jwt_secret_key
      end
    end
  end
end

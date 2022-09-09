# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Authonomy::Authenticator, type: :model do
  before :all do
    Authonomy.jwt_secret_key = SecureRandom.hex(64)
    pwd = 'SupeRrR-Pa$$w00rd!'
    10.times do |i|
      User.new(id: i + 1, password: "#{pwd}-#{i}")
    end
  end

  after :all do
    User.destroy_all
  end

  describe '.tokens' do
    let!(:user) { User.all.sample }

    context 'when refresh_exp is falsey' do
      it 'creates valid access token' do
        now = Time.now.utc.to_i
        access_token, = described_class.tokens(user.id)

        payload = described_class.send(:decode, access_token)

        expect(payload['sub']).to eql(user.id)
        expect(payload['iat']).to eql(now)
        expect(payload['exp']).to eql(now + Authonomy.access_token_ttl.to_i)
      end

      it 'creates refresh token without expiration' do
        now = Time.now.utc.to_i
        _, refresh_token = described_class.tokens(user.id)

        refresh_payload = described_class.send(:decode, refresh_token)

        expect(refresh_payload['iat']).to eql(now)
        expect(refresh_payload['exp']).to be_nil
      end

      it 'creates refresh token that matches access token' do
        access_token, refresh_token = described_class.tokens(user.id)

        payload = described_class.send(:decode, access_token)
        refresh_payload = described_class.send(:decode, refresh_token)
        payload_digest = described_class.send(:payload_digest, payload)

        expect(refresh_payload['acc']).to eql(payload_digest)
      end

      it 'creates different refresh and access tokens' do
        access_token, refresh_token = described_class.tokens(user.id)

        expect(access_token).not_to eql(refresh_token)
      end
    end

    context 'when refresh_exp is truthy' do
      it 'creates valid access token' do
        now = Time.now.utc.to_i
        access_token, = described_class.tokens(user.id, true)

        payload = described_class.send(:decode, access_token)

        expect(payload['sub']).to eql(user.id)
        expect(payload['iat']).to eql(now)
        expect(payload['exp']).to eql(now + Authonomy.access_token_ttl.to_i)
      end

      it 'creates valid refresh token with expiration' do
        now = Time.now.utc.to_i
        _, refresh_token = described_class.tokens(user.id, true)
        refresh_payload = described_class.send(:decode, refresh_token)

        expect(refresh_payload['exp']).to eql(now + Authonomy.refresh_token_ttl.to_i)
      end
    end

    context 'when refresh_exp is a number' do
      it 'creates valid access token' do
        now = Time.now.utc.to_i
        exp = 12_121_212
        access_token, = described_class.tokens(user.id, exp)
        payload = described_class.send(:decode, access_token)

        expect(payload['sub']).to eql(user.id)
        expect(payload['iat']).to eql(now)
        expect(payload['exp']).to eql(now + Authonomy.access_token_ttl.to_i)
      end

      it 'copies expiration to new refresh token' do
        [12, Time.now.utc - 1.day, Time.now.utc, Time.now.utc + 1.week].each do |exp|
          _, refresh_token = described_class.tokens(user.id, exp.to_i)
          refresh_payload = described_class.send(:decode, refresh_token, verify_expiration: false)

          expect(refresh_payload['exp']).to eql(exp.to_i)
        end
      end
    end
  end

  describe '.authenticate' do
    let!(:user) { User.all.sample }
    let!(:payload) { { sub: user.id, iat: Time.now.utc.to_i, exp: Time.now.utc.to_i + Authonomy.access_token_ttl.to_i } }

    it 'authenticates with default params' do
      access_token = described_class.send(:encode, payload)
      refresh_payload = { acc: described_class.send(:payload_digest, payload) }
      refresh_token = described_class.send(:encode, refresh_payload)

      auth, = described_class.authenticate(User, access_token, refresh_token)

      expect(auth).to eql(user)
    end

    context 'when refresh_token is not provided' do
      context 'when access_token has no subject' do
        it 'does not authenticate' do
          payload[:sub] = nil
          access_token = described_class.send(:encode, payload)

          auth = described_class.authenticate(User, access_token, nil)

          expect(auth).to be_nil
        end
      end

      context 'when algorithm does not match' do
        it 'does not authenticate' do
          access_token = ::JWT.encode(payload, described_class.send(:hmac_secret), 'none')

          auth = described_class.authenticate(User, access_token, nil)

          expect(auth).to be_nil
        end
      end

      context 'when signature does not match' do
        it 'does not authenticate' do
          access_token = ::JWT.encode(payload, 'a new simple secret', 'HS256')

          auth = described_class.authenticate(User, access_token, nil)

          expect(auth).to be_nil
        end
      end

      context 'when access_token is expired' do
        it 'does not authenticate when expiration is significant' do
          access_token, = described_class.tokens(user.id, nil)

          Timecop.travel(Authonomy.access_token_ttl + 1.minute) do
            auth = described_class.authenticate(User, access_token, nil)

            expect(auth).to be_nil
          end
        end

        it 'authenticates when expiration is not significant' do
          access_token, = described_class.tokens(user.id, nil)

          Timecop.travel(Authonomy.access_token_ttl + 15.seconds) do
            auth = described_class.authenticate(User, access_token, nil)

            expect(auth).to eql(user)
          end
        end
      end

      context 'when access_token is not expired' do
        it 'does not authenticate when password is changed after token issued' do
          access_token, = described_class.tokens(user.id, nil)

          Timecop.travel(1.minute) do
            new_pwd = 'new-SupeRrR-Pa$$w00rd!'
            user.update(password: new_pwd, access_expired_at: Time.now.utc)

            auth = described_class.authenticate(User, access_token, nil)

            expect(auth).to be_nil
          end

          user.update(access_expired_at: nil)
        end
      end
    end

    context 'when refresh_token has no expiration' do
      context 'when access_token is expired' do
        it 'does not authenticate when expiration is significant' do
          access_token, refresh_token = described_class.tokens(user.id, nil)

          Timecop.travel(Authonomy.access_token_ttl + 1.minute) do
            auth, = described_class.authenticate(User, access_token, refresh_token)
            expect(auth).to be_nil
          end
        end

        it 'authenticates when expiration is not significant' do
          access_token, refresh_token = described_class.tokens(user.id, nil)

          Timecop.travel(Authonomy.access_token_ttl + 15.seconds) do
            auth, = described_class.authenticate(User, access_token, refresh_token)
            expect(auth).to eql(user)
          end
        end
      end

      context 'when access_token is not expired' do
        it 'authenticates successfully' do
          access_token, refresh_token = described_class.tokens(user.id, nil)

          Timecop.freeze(Authonomy.access_token_ttl - 15.seconds) do
            auth, = described_class.authenticate(User, access_token, refresh_token)
            expect(auth).to eql(user)
          end
        end

        it 'returns new valid access_token' do
          access_token, refresh_token = described_class.tokens(user.id, nil)

          Timecop.freeze(Authonomy.access_token_ttl - 15.seconds) do
            _, new_access_token, = described_class.authenticate(User, access_token, refresh_token)
            expect(new_access_token).not_to eql(access_token)

            new_payload = described_class.send(:decode, new_access_token, verify_expiration: false)
            expect(new_payload['sub']).to eql(user.id)
            expect(new_payload['iat']).to eql(Time.now.utc.to_i)
            expect(new_payload['exp']).to eql((Time.now.utc + Authonomy.access_token_ttl).to_i)
          end
        end

        it 'returns new valid refresh_token without expiration' do
          access_token, refresh_token = described_class.tokens(user.id, nil)

          Timecop.freeze(Authonomy.access_token_ttl - 15.seconds) do
            _, _, new_refresh_token = described_class.authenticate(User, access_token, refresh_token)
            expect(new_refresh_token).not_to eql(refresh_token)

            new_payload = described_class.send(:decode, new_refresh_token, verify_expiration: false)
            expect(new_payload['exp']).to be_nil
          end
        end

        it 'does not authenticate when password is changed after tokens issued' do
          access_token, refresh_token = described_class.tokens(user.id, nil)

          Timecop.travel(1.minute) do
            new_pwd = 'new-SupeRrR-Pa$$w00rd!'
            user.update(password: new_pwd, access_expired_at: Time.now.utc)

            auth, = described_class.authenticate(User, access_token, refresh_token)

            expect(auth).to be_nil
          end

          user.update(access_expired_at: nil)
        end
      end
    end

    context 'when refresh_token is expired' do
      context 'when access_token is expired' do
        it 'does not authenticate when expiration is significant' do
          access_token, refresh_token = described_class.tokens(user.id, (Time.now.utc - Authonomy.refresh_token_ttl).to_i)

          Timecop.travel(Authonomy.access_token_ttl + 1.minute) do
            auth, = described_class.authenticate(User, access_token, refresh_token)
            expect(auth).to be_nil
          end
        end

        it 'authenticates when expiration is not significant' do
          access_token, refresh_token = described_class.tokens(user.id, (Time.now.utc - Authonomy.refresh_token_ttl).to_i)

          Timecop.travel(Authonomy.access_token_ttl + 15.seconds) do
            auth, = described_class.authenticate(User, access_token, refresh_token)
            expect(auth).to eql(user)
          end
        end
      end

      context 'when access_token is not expired' do
        it 'authenticates successfully' do
          access_token, refresh_token = described_class.tokens(user.id, (Time.now.utc - Authonomy.refresh_token_ttl).to_i)

          Timecop.freeze(Authonomy.access_token_ttl - 15.seconds) do
            auth, = described_class.authenticate(User, access_token, refresh_token)
            expect(auth).to eql(user)
          end
        end

        it 'returns new valid access_token' do
          access_token, refresh_token = described_class.tokens(user.id, (Time.now.utc - Authonomy.refresh_token_ttl).to_i)

          Timecop.freeze(Authonomy.access_token_ttl - 15.seconds) do
            _, new_access_token, = described_class.authenticate(User, access_token, refresh_token)
            expect(new_access_token).not_to eql(access_token)

            new_payload = described_class.send(:decode, new_access_token, verify_expiration: false)
            expect(new_payload['sub']).to eql(user.id)
            expect(new_payload['iat']).to eql(Time.now.utc.to_i)
            expect(new_payload['exp']).to eql((Time.now.utc + Authonomy.access_token_ttl).to_i)
          end
        end

        it 'returns new valid refresh_token without expiration' do
          access_token, refresh_token = described_class.tokens(user.id, (Time.now.utc - Authonomy.refresh_token_ttl).to_i)

          Timecop.freeze(Authonomy.access_token_ttl - 15.seconds) do
            _, _, new_refresh_token = described_class.authenticate(User, access_token, refresh_token)
            expect(new_refresh_token).not_to eql(refresh_token)

            new_payload = described_class.send(:decode, new_refresh_token, verify_expiration: false)
            expect(new_payload['exp']).to be_nil
          end
        end
      end
    end

    context 'when refresh_token is valid' do
      context 'when access_token is expired' do
        it 'authenticates in any case' do
          access_token, refresh_token = described_class.tokens(user.id, true)

          Timecop.travel(Authonomy.refresh_token_ttl - 15.seconds) do
            auth, = described_class.authenticate(User, access_token, refresh_token)
            expect(auth).to eql(user)
          end
        end
      end
    end

    context 'when refresh_token is invalid' do
      context 'when algorithm does not match' do
        it 'does not authenticate' do
          access_token = described_class.send(:encode, payload)
          payload_digest = described_class.send(:payload_digest, payload)

          refresh_payload = { acc: payload_digest }
          refresh_token = ::JWT.encode(refresh_payload, described_class.send(:hmac_secret), 'none')

          auth = described_class.authenticate(User, access_token, refresh_token)
          expect(auth).to be_nil
        end
      end

      context 'when signature does not match' do
        it 'does not authenticate' do
          access_token = described_class.send(:encode, payload)
          payload_digest = described_class.send(:payload_digest, payload)

          refresh_payload = { acc: payload_digest }
          refresh_token = ::JWT.encode(refresh_payload, 'a new simple secret', 'HS256')

          auth = described_class.authenticate(User, access_token, refresh_token)
          expect(auth).to be_nil
        end
      end

      context 'when payload does not match' do
        it 'does not authenticate' do
          access_token = described_class.send(:encode, payload)

          refresh_payload = { acc: described_class.send(:payload_digest, payload.merge(sub: "#{user.id}123")) }
          refresh_token = described_class.send(:encode, refresh_payload)

          auth = described_class.authenticate(User, access_token, refresh_token)
          expect(auth).to be_nil
        end
      end

      context 'when is not a JWT token' do
        it 'does not authenticate' do
          access_token = described_class.send(:encode, payload)

          refresh_token = 'Just a string'

          auth = described_class.authenticate(User, access_token, refresh_token)
          expect(auth).to be_nil
        end
      end
    end
  end
end

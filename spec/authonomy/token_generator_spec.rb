# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Authonomy::TokenGenerator, type: :model do
  before :all do
    secret_key_base = SecureRandom.hex(64)
    @token_generator = described_class.new(
      ActiveSupport::CachingKeyGenerator.new(
        ActiveSupport::KeyGenerator.new(secret_key_base)
      )
    )
  end

  describe '.digest' do
    it 'generates encrypted token' do
      tokens = %w[token1 ABCABCABCABC !@#!@#ASD F -1]
      tokens.each do |token|
        digest = @token_generator.digest(:reset_password_token, token)
        expect(digest).not_to eql(token)
      end
    end

    it 'generates different digests for different tokens and columns' do
      digests = []
      tokens = %w[token1 ABCABCABCABC !@#!@#ASD F -1]
      tokens.each do |token|
        digest = @token_generator.digest(:reset_password_token, token)
        expect(digests).not_to include(digest)
        digests << digest
      end
    end
  end

  describe '.generate' do
    let(:token_length) { 48 }

    before :all do
      pwd = 'Super-SeCrEt=password_123'
      10.times { User.new(pwd) }
    end

    it 'generates raw and encoded token' do
      token, encoded_token = @token_generator.generate(User, :reset_password_token, token_length)
      expect(token).not_to be_nil
      expect(encoded_token).not_to be_nil
      expect(encoded_token).not_to eql(token)
    end

    it 'generates raw tokens of given length' do
      token, = @token_generator.generate(User, :reset_password_token, token_length)
      expect(token).not_to be_nil
      expect(token.length).to eql(token_length)
    end

    it 'generates unique encoded tokens' do
      expect(User.count).to be(10)

      encoded_tokens = []
      User.all.each do |item|
        _, encoded_token = @token_generator.generate(User, :reset_password_token, token_length)
        item.update(reset_password_token: encoded_token)
        expect(encoded_tokens).not_to include(encoded_token)
        encoded_tokens << encoded_token
      end
    end

    it 'generates raw and encoded tokens which can be matched with digest' do
      expect(User.count).to be(10)

      User.all.each do |item|
        token, encoded_token = @token_generator.generate(User, :reset_password_token, token_length)
        item.update(reset_password_token: encoded_token)
        digest = @token_generator.digest(:reset_password_token, token)
        expect(encoded_token).to eql(digest)
      end
    end
  end
end

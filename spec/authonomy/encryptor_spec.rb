# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Authonomy::Encryptor, type: :model do
  describe '.digest' do
    it 'generates encrypted password' do
      %w[password1 ABC !@#!@#ASD F -1].each do |password|
        digest = described_class.digest(password)
        expect(digest).not_to eql(password)
      end
    end

    it 'generates different digests for different passwords' do
      digests = []
      %w[password1 ABC !@#!@#ASD F -1].each do |password|
        digest = described_class.digest(password)
        expect(digests).not_to include(digest)
        digests << digest
      end
    end

    it 'generates different passwords for different peppers' do
      password = 'qwerty'
      digests = []
      %w[pepper1 ABC !@#!@#ASD F -3].each do |pepper|
        Authonomy.pepper = pepper
        digest = described_class.digest(password)
        expect(digests).not_to include(digest)
        digests << digest
      end
    end
  end

  describe '.compare' do
    it 'matches password with its digest' do
      %w[password1 ABC !@#!@#ASD F -1].each do |password|
        digest = described_class.digest(password)
        res = described_class.compare(digest, password)
        expect(res).to be_truthy
      end
    end

    it 'mismatches password with its digest when pepper has changed' do
      passwords = []
      Authonomy.pepper = 'pepper1'
      %w[password1 ABC !@#!@#ASD F -1].each do |password|
        digest = described_class.digest(password)
        passwords << [password, digest]
      end
      Authonomy.pepper = 'pepper2'
      passwords.each do |password, digest|
        res = described_class.compare(digest, password)
        expect(res).to be_falsey
      end
    end
  end
end

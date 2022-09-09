# frozen_string_literal: true

class User
  attr_accessor :id, :password, :reset_password_token, :access_expired_at

  @list = []

  def initialize(attrs)
    update(attrs)
    self.class.all << self
  end

  def update(attrs)
    attrs.each do |k, v|
      send("#{k}=", v)
    end
  end

  class << self
    def all
      @list
    end

    def find_by(attrs)
      @list.each do |obj|
        res = obj
        attrs.each do |k, v|
          if obj.send(k) != v
            res = nil
            break
          end
        end

        return res if res
      end
      nil
    end

    def destroy_all
      @list = []
    end
  end
end

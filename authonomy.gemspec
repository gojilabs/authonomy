# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'authonomy/version'

Gem::Specification.new do |s|
  s.name        = 'authonomy'
  s.version     = Authonomy::VERSION.dup
  s.platform    = Gem::Platform::RUBY
  s.licenses    = ['MIT']
  s.summary     = 'Flexible authentication solution for Rails'
  s.email       = 'ilya@konyukhov.com'
  s.homepage    = 'https://github.com/ilkon/authonomy'
  s.description = 'Flexible authentication solution for Rails'
  s.authors     = ['Ilya Konyukhov']
  s.metadata    = {
    'rubygems_mfa_required' => 'true',
    'homepage_uri'          => 'https://github.com/ilkon/authonomy',
    'documentation_uri'     => 'https://rubydoc.info/github/ilkon/authonomy',
    'changelog_uri'         => 'https://github.com/ilkon/authonomy/blob/main/CHANGELOG.md',
    'source_code_uri'       => 'https://github.com/ilkon/authonomy',
    'bug_tracker_uri'       => 'https://github.com/ilkon/authonomy/issues',
    'wiki_uri'              => 'https://github.com/ilkon/authonomy/wiki'
  }

  s.files         = Dir['{app,config,lib}/**/*', 'LICENSE', 'README.md']
  s.require_paths = ['lib']
  s.required_ruby_version = '>= 2.1.0'

  s.add_runtime_dependency 'activesupport'
  s.add_runtime_dependency 'bcrypt'
end

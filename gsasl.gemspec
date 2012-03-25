# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "gsasl/version"

Gem::Specification.new do |s|
  s.name        = "gsasl"
  s.version     = Gsasl::VERSION
  s.authors     = ["Vincent Landgraf"]
  s.email       = ["vilandgr@googlemail.com"]
  s.homepage    = ""
  s.summary     = %q{A lib ffi based wrapper for lib GNU SASL}
  s.description = %q{A library for doing SASL based authentication mechanisms}

  s.rubyforge_project = "gsasl"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.add_development_dependency "rspec"
  s.add_development_dependency "rake"
  s.add_runtime_dependency "ffi"
end

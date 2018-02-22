require "omniauth-aapa-custom/version"
require 'omniauth/strategies/aapa_custom'

module Omniauth
  module AAPACustom
    OmniAuth.config.add_camelization 'aapa_custom', 'AAPACustom'
  end
end

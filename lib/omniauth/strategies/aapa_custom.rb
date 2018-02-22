require 'omniauth-oauth2'
require 'rest_client'

module OmniAuth
  module Strategies
    class AAPACustom < OmniAuth::Strategies::OAuth2
      option :name, 'aapa_custom'

      option :app_options, { app_event_id: nil }

      option :client_options, {
        api_endpoint: 'MUST BE PROVIDED',
        login_page_url: 'MUST BE PROVIDED',
        client_id: 'MUST BE PROVIDED',
        username: 'MUST BE PROVIDED',
        password: 'MUST BE PROVIDED',
        custom_field_keys: [],
        proxy_url: nil
      }

      uid { raw_info[:uid] }

      info { raw_info }

      def request_phase
        slug = session['omniauth.params']['origin'].gsub(/\//,"")
        redirect login_page_url + "?client=#{options.client_options.client_id}&ReturnUrl=" + callback_url + "?slug=#{slug}"
      end

      def callback_phase
        slug = request.params['slug']
        account = Account.find_by(slug: slug)
        @app_event = account.app_events.where(id: options.app_options.app_event_id).first_or_create(activity_type: 'sso')

        self.access_token = {
          token: request.params['token'],
          token_expires: 60
        }
        self.env['omniauth.auth'] = auth_hash
        self.env['omniauth.origin'] = '/' + slug
        self.env['omniauth.app_event_id'] = @app_event.id
        call_app!
      end

      def auth_hash
        hash = AuthHash.new(provider: name, uid: uid)
        hash.info = info
        hash
      end

      def raw_info
        @raw_info ||= get_user_info
      end

      def get_user_info
        request_log_text = "#{provider_name} User Profile Request:\nGET #{user_profile_url}?token=#{access_token[:token]}\nAuthorization: Basic #{Provider::SECURITY_MASK}"
        @app_event.logs.create(level: 'info', text: request_log_text)

        begin
          response = RestClient.get(user_profile_url, params: { token: access_token[:token] }, accept: :json, :Authorization => encoded_authorization_header)
        rescue RestClient::ExceptionWithResponse => e
          error_log_text = "#{provider_name} User Profile Response Error #{e.message} (code: #{e.response&.code}):\n#{e.response}"
          @app_event.logs.create(level: 'error', text: error_log_text)
          @app_event.fail!
          return {}
        end

        response_log_text = "#{provider_name} User Profile Response (code: #{response.code}): \n#{response.body}"
        @app_event.logs.create(level: 'info', text: response_log_text)

        parsed_response = JSON.parse(response.body)

        info = {
          uid: parsed_response['AapaId'],
          first_name: parsed_response['FirstName'],
          last_name: parsed_response['LastName'],
          email: parsed_response['EmailAddress'],
          custom_fields_data: custom_fields_data(parsed_response)
        }

        @app_event.update(raw_data: {
          user_info: {
            uid: info[:uid],
            email: info[:email],
            username: info[:uid],
            first_name: info[:first_name],
            last_name: info[:last_name]
          }
        })

        info
      end

      private

      def custom_fields_data(response)
        hash = {}
        options.client_options.custom_field_keys.to_a.each { |key| hash[key.downcase] = response[key] }
        hash
      end

      def encoded_authorization_header
        "Basic " + Base64.encode64("#{options.client_options.username}:#{options.client_options.password}")
      end

      def proxy_url
        options.client_options.proxy_url
      end

      def login_page_url
        options.client_options.login_page_url
      end

      def user_profile_url
        options.client_options.api_endpoint + '/profile'
      end

      def provider_name
        options.name.camelize
      end
    end
  end
end

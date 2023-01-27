require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class LinkedIn < OmniAuth::Strategies::OAuth2
      option :name, 'linkedin'

      option :client_options, {
        :site => 'https://api.linkedin.com',
        :authorize_url => 'https://www.linkedin.com/oauth/v2/authorization?response_type=code',
        :token_url => 'https://www.linkedin.com/oauth/v2/accessToken',
        :jwks_uri => 'https://www.linkedin.com/oauth/openid/jwks'
      }

      option :scope, 'openid profile email'
      option :fields, %w[id first-name last-name picture-url email-address]

      uid do
        raw_info['sub']
      end

      info do
        {
          :email => raw_info['email'],
          :first_name => raw_info['given_name'],
          :last_name => raw_info['family_name'],
          :picture_url => raw_info['picture']
        }
      end

      extra do
        {
          'raw_info' => raw_info
        }
      end

      def callback_url
        full_host + script_name + callback_path
      end

      alias :oauth2_access_token :access_token

      def access_token
        ::OAuth2::AccessToken.new(client, oauth2_access_token.token, {
          :expires_in => oauth2_access_token.expires_in,
          :expires_at => oauth2_access_token.expires_at,
          :refresh_token => oauth2_access_token.refresh_token
        })
      end

      def raw_info
        @raw_info ||= get_user_data(oauth2_access_token.params['id_token'])
      end

      private

      def get_user_data(id_token)
        jwks_keys = JSON.parse(access_token.get(options.client_options.jwks_uri).body)
        jwk = JWT::JWK.import(jwks_keys['keys'][0])
        JWT.decode(id_token, jwk.public_key, true, { algorithm: 'RS256' })[0]
      end
    end
  end
end

OmniAuth.config.add_camelization 'linkedin', 'LinkedIn'

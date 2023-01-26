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

      def email_address
        if options.fields.include? 'email-address'
          raw_info['email']
        end
      end

      def fetch_email_address
        @email_address_response ||= access_token.get(email_address_endpoint).parsed
      end

      def parse_email_address
        return unless email_address_available?

        @email_address_response['elements'].first['handle~']['emailAddress']
      end

      def email_address_available?
        @email_address_response['elements'] &&
          @email_address_response['elements'].is_a?(Array) &&
          @email_address_response['elements'].first &&
          @email_address_response['elements'].first['handle~']
      end

      def fields_mapping
        {
          'id' => 'sub',
          'first-name' => 'given_name',
          'last-name' => 'family_name',
          'picture-url' => 'picture',
          'email-address' => 'email'
        }
      end

      def fields
        options.fields.each.with_object([]) do |field, result|
          result << fields_mapping[field] if fields_mapping.has_key? field
        end
      end

      def localized_field field_name
        raw_info.dig(*[field_name, 'localized', field_locale(field_name)])
      end

      def field_locale field_name
        "#{ raw_info[field_name]['preferredLocale']['language'] }_" \
          "#{ raw_info[field_name]['preferredLocale']['country'] }"
      end

      def picture_url
        return unless picture_available?

        picture_references.last['identifiers'].first['identifier']
      end

      def picture_available?
        raw_info['profilePicture'] &&
          raw_info['profilePicture']['displayImage~'] &&
          picture_references
      end

      def picture_references
        raw_info['profilePicture']['displayImage~']['elements']
      end

      def email_address_endpoint
        '/v2/emailAddress?q=members&projection=(elements*(handle~))'
      end

      def profile_endpoint
        "/v2/userinfo?fields=#{ fields.join(',') }"
      end
    end
  end
end

OmniAuth.config.add_camelization 'linkedin', 'LinkedIn'

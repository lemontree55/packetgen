# frozen_string_literal: true

module PacketGen
  module Header
    # Mixin for cryptographic classes
    # @api private
    # @author Sylvain Daubert
    module Crypto
      # Cryptographic error
      class Error < PacketGen::Error; end

      # Register cryptographic modes
      # @param [OpenSSL::Cipher] conf
      # @param [OpenSSL::HMAC] intg
      # @return [void]
      def set_crypto(conf, intg)
        @conf = conf
        @intg = intg
        return unless conf.authenticated?
        # #auth_tag_len only supported from ruby 2.4.0
        @conf.auth_tag_len = @trunc if @conf.respond_to? :auth_tag_len
      end

      # Get confidentiality mode name
      # @return [String]
      def confidentiality_mode
        mode = @conf.name.match(/-([^-]*)$/)[1]
        raise Error, 'unknown cipher mode' if mode.nil?
        mode.downcase
      end

      # Say if crypto modes permit authentication
      # @return [Boolean]
      def authenticated?
        @conf.authenticated? || !@intg.nil?
      end

      def authenticate!
        @conf.final
        if @intg
          @intg.update @esn.to_s if @esn
          @intg.digest[0, @icv_length] == @icv
        else
          true
        end
      rescue OpenSSL::Cipher::CipherError
        false
      end

      def encipher(data)
        enciphered_data = @conf.update(data)
        @intg.update(enciphered_data) if @intg
        enciphered_data
      end

      def decipher(data)
        @intg.update(data) if @intg
        @conf.update(data)
      end
    end
  end
end

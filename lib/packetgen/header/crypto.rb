module PacketGen
  module Header

    # Mixin for cryptographic classes
    # @api private
    # @author Sylvain Daubert
    module Crypto

      # Register cryptographic modes
      # @param [OpenSSL::Cipher] conf
      # @param [OpenSSL::HMAC] intg
      # @return [void]
      def set_crypto(conf, intg)
        @conf, @intg = conf, intg
        if conf.authenticated?
          # #auth_tag_len only supported from ruby 2.4.0
          @conf.auth_tag_len = @trunc if @conf.respond_to? :auth_tag_len
        end
      end

      # Get confidentiality mode name
      # @return [String]
      def confidentiality_mode
        mode = @conf.name.match(/-([^-]*)$/)[1]
        raise CipherError, 'unknown cipher mode' if mode.nil?
        mode.downcase
      end

      # Say if crypto modes permit authentication
      # @return [Boolean]
      def authenticated?
        @conf.authenticated? or !!@intg
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

      def decipher(data)
        @intg.update(data) if @intg
        @conf.update(data)
      end
    end
  end
end

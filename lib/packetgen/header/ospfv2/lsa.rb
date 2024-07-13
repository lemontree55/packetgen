# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    class OSPFv2
      # This class handles unsupported {OSPFv2 OSPFv2} LSA payloads.
      # A LSA payload is a {LSAHeader} with a {#body} field.
      # @author Sylvain Daubert
      class LSA < LSAHeader
        # @!attribute body
        #  LSA body
        #  @return [String]
        define_field :body, Types::String,
                     builder: ->(h, t) { t.new(length_from: -> { h.length - 20 }) }
      end

      # This class handles TOS metrics for {Link links} in a {LSARouter
      # LSA router payload}.
      # @author Sylvain Daubert
      class TosMetric < Types::Fields
        include Types::Fieldable

        # @!attribute tos
        #  8-bit IP Type of Service that this metric refers to.
        #  @return [Integer]
        define_field :tos, Types::Int8
        # @!attribute reserved
        #  8-bit reserved field.
        #  @return [Integer]
        define_field :reserved, Types::Int8, default: 0
        # @!attribute tos_metric
        #  16-bit TOS-specific metric information..
        #  @return [Integer]
        define_field :tos_metric, Types::Int16

        # @return [String]
        def to_human
          "TOS<type:#{type},metric:#{tos_metric}>"
        end
      end

      # This class defines a specialized {Types::Array array} to handle series
      # of {TosMetric TOS metrics}.
      # @author Sylvain Daubert
      class ArrayOfTosMetric < Types::Array
        set_of TosMetric
      end

      # This class handles links in a {LSARouter LSA router payload}.
      # @author Sylvain Daubert
      class Link < Types::Fields
        include Types::Fieldable

        # @!attribute id
        #  @return [IP::Addr]
        define_field :id, IP::Addr
        # @!attribute data
        #  @return [IP::Addr]
        define_field :data, IP::Addr
        # @!attribute type
        #  @return [Integer]
        define_field :type, Types::Int8
        # @!attribute tos_count
        #  @return [Integer]
        define_field :tos_count, Types::Int8
        # @!attribute metric
        #  @return [Integer]
        define_field :metric, Types::Int16
        # @!attribute tos
        #  Additionnal TOS metrics
        #  @return [ArrayOfTosMetric]
        define_field :tos, ArrayOfTosMetric, builder: ->(h, t) { t.new(counter: h[:tos_count]) }

        # @return [String]
        def to_human
          "<type:#{type},metric:#{metric},id:#{id},data:#{data}>"
        end
      end

      # This class defines a specialized {Types::Array array} to handle series
      # of {Link Links}.
      # @author Sylvain Daubert
      class ArrayOfLink < Types::Array
        set_of Link
      end

      # This class handles LSA Router payloads.
      #
      # A LSA router payload is composed of:
      # * a header (see methods inherited from {LSAHeader}),
      # * a 16-bit flag word {#u16} ({Types::Int16}),
      # * a 16-bit {#link_count} field ({Types::Int16}),
      # * an array of {#links} ({ArrayOfLink}).
      # @author Sylvain Daubert
      class LSARouter < LSAHeader
        # @attribute u16
        #  16-bit flag word
        #  @return [Integer]
        define_field :u16, Types::Int16
        # @attribute link_count
        #  Number of links
        #  @return [Integer]
        define_field :link_count, Types::Int16
        # @attribute links
        #  @return [ArrayOfLink]
        define_field :links, ArrayOfLink, builder: ->(h, t) { t.new(counter: h[:link_count]) }

        # @attribute v_flag
        #  @return [Boolean]
        # @attribute e_flag
        #  @return [Boolean]
        # @attribute b_flag
        #  @return [Boolean]
        define_bit_fields_on :u16, :z, 5, :v_flag, :e_flag, :b_flag, :zz, 8
      end

      # This class handles LSA Network payloads.
      #
      # A LSA network payload is composed of:
      # * a header (see methods inherited from {LSAHeader}),
      # * a 32-bit {#netmask} field ({IP::Addr}),
      # * an array of router addresses ({#routers}, {IP::ArrayOfAddr}).
      # @author Sylvain Daubert
      class LSANetwork < LSAHeader
        # @!attribute netmask
        #  @return [IP::Addr]
        define_field :netmask, IP::Addr
        # @!attribute routers
        #  List of routers in network
        #  @return [IP::ArrayOfAddr]
        define_field :routers, IP::ArrayOfAddr,
                     builder: ->(h, t) { t.new(length_from: -> { h.length - 24 }) }
      end

      # This class handles external links in {LSAASExternal LSA AS-External payloads}.
      # @author Sylvain Daubert
      class External < Types::Fields
        include Types::Fieldable

        # @!attribute u8
        #  @return [Integer]
        define_field :u8, Types::Int8
        # @!attribute metric
        #  @return [Integer]
        define_field :metric, Types::Int24
        # @!attribute forwarding_addr
        #  @return [IP::Addr]
        define_field :forwarding_addr, IP::Addr
        # @!attribute ext_route_tag
        #  @return [Integer]
        define_field :ext_route_tag, Types::Int32

        # @!attribute e_flag
        #  @return [Boolean]
        # @!attribute tos
        #  @return [Integer]
        define_bit_fields_on :u8, :e_flag, :tos, 7

        # @return [String]
        def to_human
          "<type:#{e_flag? ? 2 : 1},tos:#{tos},metric:#{metric},fwaddr:#{forwarding_addr},tag:#{ext_route_tag}>"
        end
      end

      # This class defines a specialized {Types::Array array} to handle series
      # of {External Externals}.
      # @author Sylvain Daubert
      class ArrayOfExternal < Types::Array
        set_of External
      end

      # This class handles LSA AS-External payloads.
      #
      # A LSA network payload is composed of:
      # * a header (see methods inherited from {LSAHeader}),
      # * a 32-bit {#netmask} field ({IP::Addr}),
      # * an array of external destinations ({#externals}, {ArrayOfExternal}).
      # @author Sylvain Daubert
      class LSAASExternal < LSAHeader
        # @!attribute netmask
        #  @return [IP::Addr]
        define_field :netmask, IP::Addr
        # @!attribute externals
        #  List of external destinations
        #  @return [ArrayOfExternal]
        define_field :externals, ArrayOfExternal,
                     builder: ->(h, t) { t.new(length_from: -> { h.length - 24 }) }
      end

      # This class defines a specialized {Types::Array array} to handle series
      # of {LSA LSAs}. It recognizes known LSA types and infers correct type.
      # @author Sylvain Daubert
      class ArrayOfLSA < Types::Array
        set_of LSAHeader

        # @param [Hash] options
        # @option options [Types::Int] counter Int object used as a counter for this set
        # @option options [Boolean] only_headers if +true+, only {LSAHeader LSAHeaders}
        #  will be added to this array.
        def initialize(options={})
          super()
          @only_headers = options[:only_headers] || false
        end

        private

        def record_from_hash(hsh)
          raise ArgumentError, 'hash should have :type key' unless hsh.key? :type

          klass = if @only_headers
                    LSAHeader
                  else
                    case hsh[:type]
                    when String
                      get_lsa_class_by_human_type(hsh[:type])
                    when Integer
                      get_lsa_class_by_human_type(LSAHeader::TYPES.key(hsh[:type]))
                    else
                      LSA
                    end
                  end
          klass.new(hsh)
        end

        def get_lsa_class_by_human_type(htype)
          klassname = "LSA#{htype.to_s.delete('-')}"
          begin
            if OSPFv2.const_defined? klassname
              OSPFv2.const_get klassname
            else
              LSA
            end
          rescue NameError
            LSA
          end
        end

        def real_type(lsah)
          @only_headers ? lsah.class : get_lsa_class_by_human_type(lsah.human_type)
        end
      end
    end
  end
end

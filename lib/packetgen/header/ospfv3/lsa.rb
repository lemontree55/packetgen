# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header
    class OSPFv3

      # This class handles links in a {LSARouter OSPFv3 LSA router payload}.
      # @author Sylvain Daubert
      class Link < Types::Fields
        # @!attribute type
        #  @return [Integer]
        define_field :type, Types::Int8
        # @!attribute reserved
        #  @return [Integer]
        define_field :reserved, Types::Int8, default: 0
        # @!attribute metric
        #  @return [Integer]
        define_field :metric, Types::Int16
        # @!attribute interface_id
        #  @return [Integer]
        define_field :interface_id, Types::Int32
        # @!attribute neighbor_interface_id
        #  @return [Integer]
        define_field :neighbor_interface_id, Types::Int32
        # @!attribute neighbor_router_id
        #  @return [String]
        define_field :neighbor_router_id, IP::Addr

        # @return [String]
        def to_human
          "Link<type:#{type},metric:#{metric},id:#{interface_id}," \
          "neighbor_id:#{neighbor_interface_id},neighbor_router:#{neighbor_router_id}>"
        end
      end

      # This class defines a specialized {Types::Array array} to handle series
      # of {Link Links}.
      # @author Sylvain Daubert
      class ArrayOfLink < Types::Array
        set_of Link
      end

      # This class handles unsupported {OSPFv3 OSPFv3} LSA payloads.
      # A LSA payload is a {LSAHeader} with a {#body} field.
      # @author Sylvain Daubert
      class LSA < LSAHeader
        # @!attribute body
        #  LSA body
        #  @return [String]
        define_field :body, Types::String,
                     builder: ->(h,t) { t.new(length_from: ->() { h.length - 20 }) }
      end

      # This class handles OSPFv3 LSA Router payloads.
      #
      # A LSA router payload is composed of:
      # * a header (see methods inherited from {LSAHeader}),
      # * a 8-bit flag word {#flags} ({Types::Int8}),
      # * a 24-bit {#options} field ({Types::Int24}),
      # * and an array of {#links} ({ArrayOfLink}).
      # @author Sylvain Daubert
      class LSARouter < LSAHeader
        # @attribute flags
        #  8-bit flag word
        #  @return [Integer]
        define_field :flags, Types::Int8
        # @!macro define_ospfv3_options
        OSPFv3.define_options(self)
        # @attribute links
        #  @return [ArrayOfLink]
        define_field :links, ArrayOfLink

        # @!attribute nt_flag
        #  @return [Boolean]
        # @!attribute v_flag
        #  @return [Boolean]
        # @!attribute e_flag
        #  @return [Boolean]
        # @!attribute b_flag
        #  @return [Boolean]
        define_bit_fields_on :flags, :zz, 3, :nt_flag, :x_flag, :v_flag, :e_flag,
                             :b_flag
      end

      # This class handles OSPFv3 LSA Network payloads.
      #
      # A LSA network payload is composed of:
      # * a header (see methods inherited from {LSAHeader}),
      # * a 8-bit {#reserved} field,
      # * a 24-bit {#options} field,
      # * and an array of router IDs ({#routers}, {IP::ArrayOfAddr}).
      # @author Sylvain Daubert
      class LSANetwork < LSAHeader
        # @!attribute reserved
        #  @return [Integer]
        define_field :reserved, Types::Int8
        # @!macro define_ospfv3_options
        OSPFv3.define_options(self)
        # @!attribute routers
        #  List of routers attached to the link.
        #  @return [IP::ArrayOfAddr]
        define_field :routers, IP::ArrayOfAddr
      end

      # This class handles OSPFv3 LSA Intra-Area-Prefix payloads.
      #
      # An Intra-Area-Prefix payloads is composed of:
      # * a 16-bit {#prefix_count} field ({Types::Int16}),
      # * a 16-bit {#ref_ls_type} field ({Types::Int16Enum}),
      # * a 32-bit {#ref_link_state_id} ({IP::Addr}),
      # * a 32-bit {#ref_advertising_router} ({IP::Addr}),
      # * and an array of {IPv6Prefix} ({#prefixes}, {ArrayOfIPv6Prefix}). In
      #   this array, {IPv6Prefix#reserved} is used as +metric+ value.
      # @author Sylvain Daubert
      class LSAIntraAreaPrefix < LSAHeader
        # @!attribute prefix_count
        #  The number of IPv6 address prefixes contained in the LSA.
        #  @return [Integer]
        define_field :prefix_count, Types::Int16
        # @!attribute ref_ls_type
        #  Used to identify  the router-LSA or network-LSA with which the IPv6
        #  address prefixes should be associated, in association with
        #  {#ref_link_state_id} and {#ref_advertising_router}.
        #  @return [Integer]
        define_field :ref_ls_type, Types::Int16Enum, enum: TYPES
        # @!attribute ref_link_state_id
        #  Used to identify  the router-LSA or network-LSA with which the IPv6
        #  address prefixes should be associated, in association with
        #  {#ref_ls_type} and {#ref_advertising_router}.
        #  @return [String]
        define_field :ref_link_state_id, IP::Addr
        # @!attribute ref_advertising_router
        #  Used to identify  the router-LSA or network-LSA with which the IPv6
        #  address prefixes should be associated, in association with
        #  {#ref_link_state_id} and {#ref_ls_type}.
        #  @return [String]
        define_field :ref_advertising_router, IP::Addr
        # @!attribute prefixes
        #  Array of {IPv6Prefix}. Note for this LSA, {IPv6Prefix#reserved} is
        #  used as +metric+ value.
        #  @return [ArrayOfIPv6Prefix]
        define_field :prefixes, ArrayOfIPv6Prefix,
                     builder: ->(h, t) { t.new(counter: h[:prefix_count]) }
      end

      # This class handles OSPFv3 LSA Link payloads.
      #
      # A Link payloads is composed of:
      # * a 8-bit {#router_priority} field ({Types::Int8}),
      # * a 24-bit {#options} field ({Types::Int24}),
      # * a 128-bit IPv6 {#interface_addr} ({IPv6::Addr}),
      # * a 32-bit {#prefix_count} field ({Types::Int32}),
      # * and an array of {IPv6Prefix} ({#prefixes}, {ArrayOfIPv6Prefix}).
      # @author Sylvain Daubert
      class LSALink < LSAHeader
        # @!attribute router_priority
        #  The Router Priority of the interface attaching the originating
        #  router to the link.
        #  @return [Integer]
        define_field :router_priority, Types::Int8
        # @!macro define_ospfv3_options
        OSPFv3.define_options(self)
        # @!attribute interface_addr
        #  The originating router's link-local interface address on the link.
        #  @return [String]
        define_field :interface_addr, IPv6::Addr
        # @!attribute prefix_count
        #  The number of IPv6 address prefixes contained in the LSA.
        #  @return [Integer]
        define_field :prefix_count, Types::Int32
        # @!attribute prefixes
        #  List of IPv6 prefixes to be associated with the link.
        #  @return [ArrayOfIPv6Prefix]
        define_field :prefixes, ArrayOfIPv6Prefix
      end

      # This class defines a specialized {Types::Array array} to handle series
      # of {LSA LSAs} or {LSAHeader LSAHeaders}. It recognizes known LSA types
      # and infers correct type.
      # @author Sylvain Daubert
      class ArrayOfLSA < Types::Array
        set_of LSA
        
        # @param [Hash] options
        # @option options [Types::Int] counter Int object used as a counter for this set
        # @option options [Boolean] only_headers if +true+, only {LSAHeader LSAHeaders}
        #  will be added to this array.
        def initialize(options={})
          super
          @only_headers = options[:only_headers] || false
        end

        # Populate object from a string
        # @param [String] str
        # @return [self]
        def read(str)
          clear
          return self if str.nil?
          return self if @counter and @counter.to_i == 0
          force_binary str
          while str.length > 0
            lsa = LSAHeader.new.read(str)
            if !@only_headers
              klass = get_lsa_class_by_human_type(lsa.human_type)
              lsa = klass.new.read(str[0...lsa.length])
            end
            self.push lsa
            str.slice!(0, lsa.sz)
            break if @counter and self.size == @counter.to_i
          end
          self
        end

        private

        def record_from_hash(hsh)
          unless hsh.has_key? :type
            raise ArgumentError, "hash should have :type key"
          end
          
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
          klassname = "LSA#{htype.to_s.gsub(/-/, '')}"
          if OSPFv3.const_defined? klassname
            OSPFv3.const_get klassname
          else
            LSA
          end
        end
      end
    end
  end
end

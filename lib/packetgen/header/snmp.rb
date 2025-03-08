# coding: utf-8
# frozen_string_literal: true

# This file is part of PacketGen
# See https://github.com/lemontree55/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# Copyright (C) 2024 LemonTree55 <lenontree@proton.me>
# This program is published under MIT license.

module PacketGen
  module Header
    # Dissect error
    class DissectError < ParseError; end

    # Simple Network Management Protocol (SNMP)
    #
    # See https://github.com/lemontree55/packetgen/wiki/SNMP
    #
    # SNMP is defined from ASN.1:
    #   Message ::=
    #     SEQUENCE {
    #          version
    #             INTEGER {
    #                 version-1(0)
    #             },
    #          community      -- community name
    #              OCTET STRING,
    #          data           -- e.g., PDUs if trivial
    #              ANY        -- authentication is being used
    #     }
    # It has 3 attributes, accessible through +#[]+:
    # * +:version+, SNMP protocol version (type +RASN1::Types::Integer+ with enumeration),
    # * +:community+ (type +RASN1::Types::OctetString+),
    # * +:data+ (type {PDUs}).
    #
    # @!attribute version
    #   version attribute. Shortcut for +snmp[:version].value+.
    #   String values are: +v1+, +v2+, +v2c+ and +v3+.
    #   @return [String]
    # @!attribute community
    #   community attribute. Shortcut for +snmp[:community].value+.
    #   @return [String]
    #
    # @example
    #  snmp = PacketGen::Header::SNMP.new(version: "v3",
    #                                     chosen_pdu: PacketGen::Header::SNMP::PDU_SET,
    #                                     pdu: { id: 1, varbindlist: [{ name: '1.2.3.4' }] })
    #  snmp.version        #=> "v3"
    #  snmp.community      #=> "public"
    #  snmp.pdu.class      #=> PacketGen::Header::SNMP::SetRequest
    #  snmp.pdu[:id].value #=> 1
    #  snmp.pdu[:varbindlist][0][:name].inspect #=> 'name OBJECT ID: "1.2.3.4"'
    #  snmp.pdu[:varbindlist][0][:name].value   #=> "1.2.3.4"
    # @author Sylvain Daubert
    # @author LemonTree55
    # @since 2.0.0
    class SNMP < ASN1Base
      # Agents listen to this port
      UDP_PORT1 = 161
      # Configuration sinks listen to this port
      UDP_PORT2 = 162

      # Implicit tag number for GetRequest PDU type
      PDU_GET      = 0
      # Implicit tag number for GetNextRequest PDU type
      PDU_NEXT     = 1
      # Implicit tag number for GetResponse PDU type
      PDU_RESPONSE = 2
      # Implicit tag number for SetRequest PDU type
      PDU_SET      = 3
      # Implicit tag number for Trapv1 PDU type
      PDU_TRAPv1   = 4
      # Implicit tag number for Bulk PDU type
      PDU_BULK     = 5
      # Implicit tag number for InformRequest PDU type
      PDU_INFORM   = 6
      # Implicit tag number for Trapv2 PDU type
      PDU_TRAPv2   = 7
      # Implicit tag number for Report PDU type
      PDU_REPORT   = 8

      # Error types
      ERRORS = {
        'no_error' => 0,
        'too_big' => 1,
        'no_such_name' => 2,
        'bad_value' => 3,
        'read_only' => 4,
        'generic_error' => 5,
        'no_access' => 6,
        'wrong_type' => 7,
        'wrong_length' => 8,
        'wrong_encoding' => 9,
        'wrong_value' => 10,
        'no_creation' => 11,
        'inconsistent_value' => 12,
        'ressource_unavailable' => 13,
        'commit_failed' => 14,
        'undo_failed' => 15,
        'authorization_error' => 16,
        'not_writable' => 17,
        'inconsistent_name' => 18
      }.freeze

      # Class to handle SNMP VarBind
      #  VarBind ::= SEQUENCE {
      #                name  OBJECT IDENTIFIER,
      #                value ANY     -- depends on name
      #              }
      # This class associates a +:name+ (type +RASN1::Types::ObjectId+) to a +:value+ (any RASN1 type).
      # @example
      #   vb = PacketGen::Header::SNMP::VarBind.new(name: "1.2.3.4", value: RASN1::Types::OctetString.new(value: "abc"))
      #   vb[:name].class  # => RASN1::Types::ObjectId
      #   vb[:name].value  # => "1.2.3.4"
      # @author Sylvain Daubert
      # @author LemonTree55
      class VarBind < RASN1::Model
        sequence :varbind,
                 content: [objectid(:name),
                           any(:value)]
      end

      # Class to handle SNMP VariableBindingsList
      #  VarBindList ::= SEQUENCE (SIZE (0..max-bindings)) OF VarBind
      # This is a sequence of {VarBind}.
      # @example
      #  bindings = PacketGen::Header::SNMP::VariableBindings.new
      #  bindings << { name: "1.2.3.4", value: RASN1::Types::OctetString.new(value: "abc") }
      # @author Sylvain Daubert
      # @author LemonTree55
      class VariableBindings < RASN1::Model
        sequence_of :bindings, VarBind

        # Get 'idx'th element from the list
        # @return [VarBind,nil]
        def [](idx)
          value[idx]
        end

        # Get element counts in list
        # @return [Integer]
        def size
          value.size
        end
      end

      # Class to handle GetRequest PDU
      #  GetRequest-PDU ::= [0] IMPLICIT PDU
      #
      #  PDU ::= SEQUENCE {
      #              request-id INTEGER (-214783648..214783647),
      #
      #              error-status                -- sometimes ignored
      #                  INTEGER {
      #                      noError(0),
      #                      tooBig(1),
      #                      noSuchName(2),      -- for proxy compatibility
      #                      badValue(3),        -- for proxy compatibility
      #                      readOnly(4),        -- for proxy compatibility
      #                      genErr(5),
      #                      noAccess(6),
      #                      wrongType(7),
      #                      wrongLength(8),
      #                      wrongEncoding(9),
      #                      wrongValue(10),
      #                      noCreation(11),
      #                      inconsistentValue(12),
      #                      resourceUnavailable(13),
      #                      commitFailed(14),
      #                      undoFailed(15),
      #                      authorizationError(16),
      #                      notWritable(17),
      #                      inconsistentName(18)
      #                  },
      #
      #              error-index                 -- sometimes ignored
      #                  INTEGER (0..max-bindings),
      #
      #              variable-bindings           -- values are sometimes ignored
      #                  VarBindList
      #          }
      # This class defines a GetRequest SNMP PDU. It defines 4 attributes:
      # * an +:id+ (request-id, type +RASN1::Types::Integer+),
      # * an +:error+ (error-status, type +RASN1::Types::Integer with enumeration definition from {ERRORS}),
      # * an +:error_index+ (type +RASN1::Types::Integer+),
      # * a +:barbindlist+ (variable-bindings, type {VariableBindings}).
      #
      # @example
      #   req = PacketGen::Header::SNMP::GetRequest.new(id: 1, error: "no_error")
      #   req[:id].value    #=> 1
      #   req[:error].value #=> "no_error"
      #   req[:error].to_i  #=> 0
      #   req[:varbindlist] << { name: "1.2.3.4", value: RASN1::Types::OctetString.new(value: "abcd") }
      # @author Sylvain Daubert
      # @author LemonTree55
      class GetRequest < RASN1::Model
        sequence :pdu,
                 implicit: SNMP::PDU_GET, constructed: true,
                 content: [integer(:id, value: 0),
                           integer(:error, value: 0, enum: ERRORS),
                           integer(:error_index, value: 0),
                           model(:varbindlist, VariableBindings)]

        def initialize(args={})
          super
        end
      end

      # Class to handle GetNextRequest PDU
      #  GetNextRequest-PDU ::= [1] IMPLICIT PDU   -- PDU definition: see GetRequest
      # @see GetRequest
      # @author Sylvain Daubert
      class GetNextRequest < GetRequest
        root_options implicit: SNMP::PDU_NEXT
      end

      # Class to handle GetResponse PDU
      #  GetResponse-PDU ::= [2] IMPLICIT PDU   -- PDU definition: see GetRequest
      # @see GetRequest
      # @author Sylvain Daubert
      class GetResponse < GetRequest
        root_options implicit: SNMP::PDU_RESPONSE
      end

      # Class to handle SetRequest PDU
      #  SetRequest-PDU ::= [3] IMPLICIT PDU   -- PDU definition: see GetRequest
      # @see GetRequest
      # @author Sylvain Daubert
      class SetRequest < GetRequest
        root_options implicit: SNMP::PDU_SET
      end

      # Class to handle Trap from SNMPv1
      #  Trap-PDU ::= [4] IMPLICIT SEQUENCE {
      #                          enterprise OBJECT IDENTIFIER,
      #                          agent-addr NetworkAddress,
      #                          generic-trap      -- generic trap type
      #                              INTEGER {
      #                                  coldStart(0),
      #                                  warmStart(1),
      #                                  linkDown(2),
      #                                  linkUp(3),
      #                                  authenticationFailure(4),
      #                                  egpNeighborLoss(5),
      #                                  enterpriseSpecific(6)
      #                              },
      #                          specific-trap INTEGER,
      #                          time-stamp TimeTicks,
      #                          variable-bindings VarBindList
      #                   }
      # This class defines 6 attributes accessibles through +#[]+:
      # * +:enterprise+ for request-id (type +RASN1::Types::ObjectId+),
      # * +:agent_addr+ (type +RASN1::Types::Integer+),
      # * +:generic_trap+ (type +RASN1::Types::Integer+),
      # * +:specific_trap+ (type +RASN1::Types::Integer+),
      # * +:timestamp+ (type +RASN1::Types::Integer+),
      # * +:varbindlist+ for variable-bindings (type {VariableBindings}).
      # @author Sylvain Daubert
      # @author LemonTree55
      class Trapv1 < RASN1::Model
        sequence :trap,
                 implicit: SNMP::PDU_TRAPv1, constructed: true,
                 content: [objectid(:enterprise),
                           octet_string(:agent_addr),
                           integer(:generic_trap, enum: { 'cold_start' => 0,
                                                          'warm_start' => 1,
                                                          'link_down' => 2,
                                                          'link_up' => 3,
                                                          'auth_failure' => 4,
                                                          'egp_neighbor_loss' => 5,
                                                          'specific' => 6 }),
                           integer(:specific_trap),
                           integer(:timestamp),
                           model(:varbindlist, VariableBindings)]
      end

      # Class to handle Bulk PDU
      #  GetBulkRequest-PDU ::= [5] IMPLICIT BulkPDU
      #
      #  BulkPDU ::=                         -- must be identical in
      #        SEQUENCE {                    -- structure to PDU
      #            request-id      INTEGER (-214783648..214783647),
      #            non-repeaters   INTEGER (0..max-bindings),
      #            max-repetitions INTEGER (0..max-bindings),
      #            variable-bindings           -- values are ignored
      #                VarBindList
      #        }
      #
      # This class defines 4 values accessibles through +#[]+:
      # * +:id+ for request-id (type +RASN1::Types::Integer+),
      # * +:non_repeaters+ (type +RASN1::Types::Integer+),
      # * +:max_repetitions+ (type +RASN1::Types::Integer+),
      # * +varbindlist+ for variable-bindings (type {VariableBindings}).
      # @example
      #   bulk = PacketGen::Header::SNMP::Bulk.new(id: 1, non_repeaters: 2, max_repetitions: 2)
      #   bulk[:varbindlist] << { name: '1.2.3.4', value: RASN1::Types::OctetString.new(value: "abcd") }
      #   bulk[:id].inspect  # => "id INTEGER: 1"
      #   bulk[:id].value    # => 1
      #   bulk[:varbindlist][0][:name].value  # => "1.2.3.4"
      # @author Sylvain Daubert
      # @author LemonTree55
      class Bulk < RASN1::Model
        sequence :bulkpdu,
                 implicit: SNMP::PDU_BULK, constructed: true,
                 content: [integer(:id, value: 0),
                           integer(:non_repeaters),
                           integer(:max_repetitions),
                           model(:varbindlist, VariableBindings)]
      end

      # Class to handle InformRequest PDU
      #  InformRequest-PDU ::= [6] IMPLICIT PDU   -- PDU definition: see GetRequest
      # @see GetRequest
      # @author Sylvain Daubert
      class InformRequest < GetRequest
        root_options implicit: SNMP::PDU_INFORM
      end

      # Class to handle Trapv2 PDU
      #  SNMPv2-Trap-PDU ::= [7] IMPLICIT PDU   -- PDU definition: see GetRequest
      # @see GetRequest
      # @author Sylvain Daubert
      class Trapv2 < GetRequest
        root_options implicit: SNMP::PDU_TRAPv2
      end

      # Class to handle Report PDU
      #  Report-PDU ::= [8] IMPLICIT PDU   -- PDU definition: see GetRequest
      # @see GetRequest
      # @author Sylvain Daubert
      class Report < GetRequest
        root_options implicit: SNMP::PDU_REPORT
      end

      # Class to handle PDUs from SNMP packet
      #  PDUs ::= CHOICE {
      #             get-request      [0] IMPLICIT PDU,
      #             get-next-request [1] IMPLICIT PDU,
      #             get-response     [2] IMPLICIT PDU,
      #             set-request      [3] IMPLICIT PDU,
      #             snmpV1-trap      [4] IMPLICIT PDU,
      #             get-bulk-request [5] IMPLICIT PDU,
      #             inform-request   [6] IMPLICIT PDU,
      #             snmpV2-trap      [7] IMPLICIT PDU,
      #             report           [8] IMPLICIT PDU
      #           }
      # This class is a wrapper. It contains one of {GetRequest}, {GetNextRequest}, {GetResponse}, {SetRequest},
      # {Trapv1}, {Bulk}, {InformRequest}, {Trapv2} or {Report}.
      # @author Sylvain Daubert
      # @author LemonTree55
      class PDUs < RASN1::Model
        choice :pdus,
               content: [model(:get_request, GetRequest),
                         model(:get_next_request, GetNextRequest),
                         model(:get_response, GetResponse),
                         model(:set_request, SetRequest),
                         model(:trapv1, Trapv1),
                         model(:bulk, Bulk),
                         model(:inform, InformRequest),
                         model(:trapv2, Trapv2),
                         model(:report, Report)]
      end

      sequence :message,
               content: [integer(:version,
                                 value: 'v2c',
                                 enum: { 'v1' => 0, 'v2c' => 1, 'v2' => 2, 'v3' => 3 }),
                         octet_string(:community, value: 'public'),
                         model(:data, PDUs)]

      define_attributes :version, :community

      # @param [Hash] options
      # @option options [Integer,String] :version
      # @option options [String] :community
      # @option options [Integer] :chosen_pdu Set PDU type
      # @option options [Hash] :pdu Set PDU content
      def initialize(options={})
        super
        data.chosen = options[:chosen_pdu] if options[:chosen_pdu]
        return unless options[:pdu]

        klass = data.root.chosen_value.class
        data.root.value[data.chosen] = klass.new(options[:pdu])
      end

      # accessor to data payload. Shortcut for +snmp[:data]+.
      # @return [ASN1::Types::Choice]
      def data
        @elements[:data]
      end

      # shortcut to PDU (+snmp[:data].chosen_value+).
      # @return [GetRequest, Bulk, Trapv1, nil] return `nil` if no CHOICE was done
      def pdu
        if data.chosen.nil?
          nil
        else
          data.root.chosen_value
        end
      end

      # Inspect SNMP header
      # @return [String]
      def inspect
        str = super
        str << Inspect.shift_level
        str << if self[:data].chosen.nil?
                 Inspect::FMT_ATTR % [self[:data].type, :data, '']
               else
                 inspect_data
               end
      end

      # @api private
      # @note This method is used internally by PacketGen and should not be
      #       directly called
      # @param [Packet] packet
      # @return [void]
      # @since 2.7.0 Set UDP sport according to bindings, only if sport is not set yet (i.e. is zero).
      #  Needed by new bind API.
      def added_to_packet(packet)
        return unless packet.is?('UDP')
        return unless packet.udp.sport.zero?

        packet.udp.sport = packet.udp.dport
      end

      private

      def inspect_data
        data = self[:data]
        str = Inspect::FMT_ATTR % [data.type, :data, data.chosen_value.type]
        str << Inspect.dashed_line('ASN.1 content')
        str << data.chosen_value.inspect(1)
        begin
          str << Inspect.inspect_body(self[:message].to_der, 'ASN.1 DER')
        rescue StandardError => e
          raise unless e.message.match?(/TAG.*not handled/)
        end
        str
      end
    end

    self.add_class SNMP
    UDP.bind SNMP, dport: SNMP::UDP_PORT1
    UDP.bind SNMP, sport: SNMP::UDP_PORT1
    UDP.bind SNMP, dport: SNMP::UDP_PORT2
    UDP.bind SNMP, sport: SNMP::UDP_PORT2
  end
end

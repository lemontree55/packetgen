# coding: utf-8
# This file is part of PacketGen
# See https://github.com/sdaubert/packetgen for more informations
# Copyright (C) 2016 Sylvain Daubert <sylvain.daubert@laposte.net>
# This program is published under MIT license.

module PacketGen
  module Header

    # Dissect error
    class DissectError < ParseError; end

    # Simple Network Management Protocol (SNMP)
    # @author Sylvain Daubert
    # @version 2.0.0
    class SNMP < ASN1Base

      # Agents listen to this port
      UDP_PORT1 = 161
      # Configuration sinks listen to this port
      UDP_PORT2 = 162

      PDU_GET      = 0
      PDU_NEXT     = 1
      PDU_RESPONSE = 2
      PDU_SET      = 3
      PDU_TRAPv1   = 4
      PDU_BULK     = 5
      PDU_INFORM   = 6
      PDU_TRAPv2   = 7
      PDU_REPORT   = 8

      ERRORS = { 'no_error'              => 0,
                 'too_big'               => 1,
                 'no_such_name'          => 2,
                 'bad_value'             => 3,
                 'read_only'             => 4,
                 'generic_error'         => 5,
                 'no_access'             => 6,
                 'wrong_type'            => 7,
                 'wrong_length'          => 8,
                 'wrong_encoding'        => 9,
                 'wrong_value'           => 10,
                 'no_creation'           => 11,
                 'inconsistent_value'    => 12,
                 'ressource_unavailable' => 13,
                 'commit_failed'         => 14,
                 'undo_failed'           => 15,
                 'authorization_error'   => 16,
                 'not_writable'          => 17,
                 'inconsistent_name'     => 18
               }

      # Class to handle SNMP VarBind
      #  VarBind ::= SEQUENCE {
      #                name  OBJECT IDENTIFIER,
      #                value ANY     -- depends on name
      #              }
      # @author Sylvain Daubert
      class VarBind < RASN1::Model
        sequence :varbind,
                 content: [objectid(:name),
                           any(:value)]
      end

      # Class to handle SNMP VariableBindingsList
      #  VarBindList ::= SEQUENCE (SIZE (0..max-bindings)) OF VarBind
      # @author Sylvain Daubert
      class VariableBindings < RASN1::Model
        sequence_of :bindings, VarBind
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
      # @author Sylvain Daubert
      class GetRequest < RASN1::Model
        sequence :pdu,
                 implicit: 0, constructed: true,
                 content: [integer(:id, value: SNMP::PDU_GET),
                           enumerated(:error, enum: ERRORS),
                           integer(:error_index),
                           model(:varbindlist, VariableBindings)]

        # @return [String]
        def inspect
          Inspect.inspect_body(to_der, self.class)
        end
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
      # @author Sylvain Daubert
      class PDUs < RASN1::Model
        choice :pdus,
               content: [model(:get_request, GetRequest),
                         #model(:get_next_request, GetNextRequest),
                         #model(:get_response, GetResponse),
                         #model(:set_request, SetRequest),
                         #model(:trapv1, Trapv1),
                         #model(:bulk, Bulk),
                         #model(:inform, Inform),
                         #model(:trapv2, Trapv2)]
                        ]
      end

      sequence :message,
               content: [enumerated(:version, value: 'v2c',
                                    enum: { 'v1' => 0, 'v2c' => 1, 'v2' => 2, 'v3' => 3 }),
                         octet_string(:community, value: 'public'),
                         model(:data, PDUs)]

      define_attributes :version, :community

      # accessor to data payload
      # @return [GetRequest]
      def data
        @elements[:data]
      end

      def inspect
        str = super
        str << Inspect.shift_level(2)
        if self[:data].chosen.nil?
          str << Inspect::FMT_ATTR % [self[:data].type, :data, '']
        else
          data = self[:data]
          str << Inspect::FMT_ATTR % [data.type, :data, data.chosen_value.type]
          str << data.chosen_value.inspect
        end
      end
    end

    self.add_class SNMP
    UDP.bind_header SNMP, dport: SNMP::UDP_PORT1, sport: SNMP::UDP_PORT1
    UDP.bind_header SNMP, dport: SNMP::UDP_PORT2, sport: SNMP::UDP_PORT2
  end
end

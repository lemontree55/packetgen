# frozen_string_literal: true

require_relative '../../spec_helper'

COMMON_ERROR_CAUSES = '<InvalidStreamId: 4660>,<MissingMandatoryParameter: 1,2,3>,<StaleCookie: 456221>,' \
                      '<OutOfResource>,<UnresolvableAddress: <IPv4: 1.2.3.4>>,<UnresolvableAddress: <IPv6: ::1>>,' \
                      '<UnresolvableAddress: <Hostname: example.org>>,<UnrecognizedChunkType: <chunk:<unknown:66>>>,' \
                      '<InvalidMandatoryParameter>,<UnrecognizedParameters: <<unknown:66>: "\x01\x02\x03">,<<unknown:67>: "">>,' \
                      '<NoUserData: 287454020>,<CookieReceivedWhileShuttingDown>,<RestartAssociationWithNewAddress: ' \
                      '<IPv4: 1.1.1.15>,<IPv6: ::2>>,<UserInitiatedAbort>,<ProtocolViolation>'
HUMAN_ABORT_CHUNK = "<chunk:ABORT,flags:t,causes:#{COMMON_ERROR_CAUSES}>"
HUMAN_ERROR_CHUNK = "<chunk:ERROR,causes:#{COMMON_ERROR_CAUSES}>"

COMMON_BINARY_ERROR_CAUSES = binary("\x00\x01\x00\x08\x12\x34\x00\x00" \
                                    "\x00\x02\x00\x0a\x00\x01\x00\x02\x00\x03\x00\x00" \
                                    "\x00\x03\x00\x08\x00\x06\xf6\x1d" \
                                    "\x00\x04\x00\x04" \
                                    "\x00\x05\x00\x0c\x00\x05\x00\x08\x01\x02\x03\x04" \
                                    "\x00\x05\x00\x18\x00\x06\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" \
                                    "\x00\x05\x00\x14\x00\x0b\x00\x10example.org\x00" \
                                    "\x00\x06\x00\x10\x42\x00\x00\x0c\x00\x00\x00\x00\xff\xff\xff\xff" \
                                    "\x00\x07\x00\x04" \
                                    "\x00\x08\x00\x10\x00\x42\x00\x07\x01\x02\x03\x00\x00\x43\x00\x04" \
                                    "\x00\x09\x00\x08\x11\x22\x33\x44" \
                                    "\x00\x0a\x00\x04" \
                                    "\x00\x0b\x00\x20\x00\x05\x00\x08\x01\x01\x01\x0f\x00\x06\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02" \
                                    "\x00\x0c\x00\x07abc\x00" \
                                    "\x00\x0d\x00\x06ef\x00\x00").freeze
BINARY_ABORT_CHUNK = binary("\x06\x01\x00\xbc") + COMMON_BINARY_ERROR_CAUSES
BINARY_ERROR_CHUNK = binary("\x09\x00\x00\xbc") + COMMON_BINARY_ERROR_CAUSES

MySCTP = PacketGen::Header::SCTP

def add_error_causes(obj)
  obj.error_causes << { type: 'InvalidStreamId', value: 0x12340000 }
  obj.error_causes << { type: 'MissingMandatoryParameter', value: [1, 2, 3] }
  obj.error_causes << { type: 'StaleCookie', value: 456_221 }
  obj.error_causes << { type: 'OutOfResource' }
  obj.error_causes << { type: 'UnresolvableAddress', value: MySCTP::IPv4Parameter.new(value: '1.2.3.4') }
  obj.error_causes << { type: 'UnresolvableAddress', value: MySCTP::IPv6Parameter.new(value: '::1') }
  obj.error_causes << { type: 'UnresolvableAddress', value: MySCTP::HostnameParameter.new(value: 'example.org') }
  obj.error_causes << { type: 'UnrecognizedChunkType', value: MySCTP::UnknownChunk.new(type: 66, length: 12, body: [0, 0xffff_ffff].pack('NN')) }
  obj.error_causes << { type: 'InvalidMandatoryParameter' }
  bad_param1 = MySCTP::Parameter.new(type: 66, value: [1, 2, 3].pack('C3'))
  bad_param2 = MySCTP::Parameter.new(type: 67)
  obj.error_causes << { type: 'UnrecognizedParameters', value: [bad_param1, bad_param2] }
  obj.error_causes << { type: 'NoUserData', value: 0x11223344 }
  obj.error_causes << { type: 'CookieReceivedWhileShuttingDown' }
  bad_addr1 = MySCTP::IPv4Parameter.new(value: '1.1.1.15')
  bad_addr2 = MySCTP::IPv6Parameter.new(value: '::2')
  obj.error_causes << { type: 'RestartAssociationWithNewAddress', value: [bad_addr1, bad_addr2] }
  obj.error_causes << { type: 'UserInitiatedAbort', value: 'abc' }
  obj.error_causes << { type: 'ProtocolViolation', value: 'ef' }
end

module PacketGen
  module Header
    class SCTP
      [AbortChunk, ErrorChunk].each do |klass|
        describe klass do
          describe '#initialize' do
            it "creates an #{klass} header with default values" do
              obj = klass.new
              expect(obj).to be_a(klass)
              expect(obj.type).to eq(klass == AbortChunk ? 6 : 9)
              expect(obj.flags).to eq(0)
              expect(obj.length).to eq(0)
              expect(obj.error_causes.size).to eq(0)
            end

            it 'accepts options' do
              options = {
                type: 0xffff,
                flags: 0x42,
                length: 42,
              }
              obj = klass.new(options)
              options.each do |key, value|
                expect(obj.send(key)).to eq(value)
              end
            end
          end
        end
      end

      describe AbortChunk do
        describe '#to_human' do
          it 'returns a String with type' do
            expect(AbortChunk.new.to_human).to eq('<chunk:ABORT,flags:.>')
          end

          it 'returns human readable parameters' do
            obj = AbortChunk.new(flag_t: true)
            add_error_causes(obj)

            output = obj.to_human
            expect(output).to eq(HUMAN_ABORT_CHUNK)
          end
        end

        describe '#to_s' do
          it 'returns a binary String' do
            obj = AbortChunk.new(flag_t: true)
            add_error_causes(obj)
            obj.calc_length

            data = obj.to_s
            expect(data).to eq(BINARY_ABORT_CHUNK)
          end
        end
      end

      describe ErrorChunk do
        describe '#to_human' do
          it 'returns a String with type' do
            expect(ErrorChunk.new.to_human).to eq('<chunk:ERROR>')
          end

          it 'returns human readable parameters' do
            obj = ErrorChunk.new
            add_error_causes(obj)

            output = obj.to_human
            expect(output).to eq(HUMAN_ERROR_CHUNK)
          end
        end

        describe '#to_s' do
          it 'returns a binary String' do
            obj = ErrorChunk.new(flag_t: true)
            add_error_causes(obj)
            obj.calc_length

            data = obj.to_s
            expect(data).to eq(BINARY_ERROR_CHUNK)
          end
        end
      end
    end
  end
end

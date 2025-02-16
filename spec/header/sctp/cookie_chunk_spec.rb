# frozen_string_literal: true

require_relative '../../spec_helper'

module PacketGen
  module Header
    class SCTP
      describe CookieEchoChunk do
        describe '#initialize' do
          it 'creates an CookieEchoChunk header with default values' do
            cookie = CookieEchoChunk.new
            expect(cookie).to be_a(CookieEchoChunk)
            expect(cookie.type).to eq(10)
            expect(cookie.flags).to eq(0)
            expect(cookie.length).to eq(0)
            expect(cookie.cookie).to eq('')
          end

          it 'accepts options' do
            options = {
              type: 0xffff,
              flags: 0x1234,
              length: 42,
              cookie: 'qwerty',
            }
            cookie = CookieEchoChunk.new(options)
            options.each do |key, value|
              expect(cookie.send(key)).to eq(value)
            end
          end
        end

        describe '#to_human' do
          it 'returns a String with type' do
            expect(CookieEchoChunk.new.to_human).to eq('<chunk:COOKIE_ECHO>')
          end
        end

        describe '#to_s' do
          it 'converts a CookieEchoChunk to String' do
            cookie = CookieEchoChunk.new(cookie: 'cookie')
            cookie.calc_length
            bin = "\x0a\x00\x00\x0acookie\x00\x00".b
            expect(cookie.to_s).to eq(bin)
          end
        end
      end

      describe CookieAckChunk do
        describe '#initialize' do
          it 'creates an CookieEchoChunk header with default values' do
            cookie = CookieAckChunk.new
            expect(cookie).to be_a(CookieAckChunk)
            expect(cookie.type).to eq(11)
            expect(cookie.flags).to eq(0)
            expect(cookie.length).to eq(4)
          end

          it 'accepts options' do
            options = {
              type: 0xffff,
              flags: 0x1234,
              length: 42,
            }
            cookie = CookieAckChunk.new(options)
            options.each do |key, value|
              expect(cookie.send(key)).to eq(value)
            end
          end
        end

        describe '#to_human' do
          it 'returns a String with type' do
            expect(CookieAckChunk.new.to_human).to eq('<chunk:COOKIE_ACK>')
          end
        end

        describe '#to_s' do
          it 'converts a CookieEchoChunk to String' do
            cookie = CookieAckChunk.new
            bin = "\x0b\x00\x00\x04".b
            expect(cookie.to_s).to eq(bin)
          end
        end
      end
    end
  end
end

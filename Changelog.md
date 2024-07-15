# Changelog

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Packetgen 3.3.3 - 2024-07-15

### Fixed

* Fixed dependency on digest-crc (#124, Sergio Bobillier)

## Packetgen 3.3.2 - 2024-07-13

### Added

* Add support for SCTP

### Removed

* Clean Ruby 2.6 support (removed in 3.3.1)

## Packetgen 3.3.1 - 2024-01-04

### Changed

* Update Types::AbstractTLV: may now change field order using `field_order` parameter to `.create` method.
* Update Types::AbstractTLV: may now choose fields to use to compute length using `field_in_length` parameter to `.create` method.
* Update Types::Int to add support for native-endian encoding.

### Added

* Add specialized native-endian integer types Types::Int16n, Types::SInt16n, Types::Int24n, Types::Int132, Types::SInt32n, Types::Int64n and Types::SInt64n.

### Removed

* Remove support for Ruby 2.6

## Packetgen 3.3.0 - 2023-08-11

### Removed

* Remove support for Ruby 2.5

### Added

* Add timestamps when capturing packets using Capture#start: second block parameter is the packet timestamp.
* Add Capture#timestamps to get timestamps as an Array. To use with Capture#packets or Capture#raw_packets.

## Packetgen 3.2.2 - 2022-12-23

### Added

* Add Header::HTTP::Headers#[] to access given HTTP header
* Add Header::HTTP::Headers#header? to check given HTTP header exist in object.
* Add Header::SNMP::VariableBindings#[] to access nth element from the binding list.
* Add Header::SNMP::VariableBindings#size.
* Add Header::DHCPv6::DUID#human_type.
* Add Header::IP::SI#to_human and Header::IP::RA#to_human.

### Changed

* Types::Array#read: can now populate object from an Array of Hash, and not only from a String.

### Fixed

* Fix UnknownPacket#=== (was raising) and UnknownPacket#inspect (did nothing).
* Fix Header::IP::Option.build when type is unknown. In such a case, type was not set in newly crealed option.
* Fix Header::IP::Option#initiallize: length wazs not set and data parameter was not used.

## Packetgen 3.2.1 - 2021-12-27

### Added

* Add Types::Int#nbits to get size of Int as bits.

### Changed

* Utils.arp_cache tries using 'ip neigh' command when arp is not installed.

### Removed

* Support for Ruby 2.4 is removed.

### Fixed

* Fix Utils.arp by ensuring capture is always started before sending ARP request.
* Utils.arp_cache no more crashes when arp utils is not installed. Instead, return an empty cache.
* Utils.arp: ensure ARP request is sent before capturing response.

## Packetgen 3.2.0 - 2021-04-20

### Added

* Add UnknownPacket class, which handles non-parsable packets on capturing.

### Changed

* PacketGen.default_iface now tries hard to return an interface with addresses.

### Fixed

* Fix an exception when adding a HTTP::Request header to a packet (#112).
* Fix an exception when adding a HTTP::Response header to a packet.
* Fix headers which raised when binary string was badly formatted, as
  happened when trying to guess a header (Packet#parse).

## Packetgen 3.1.8 - 2021-03-13

### Fixed

* Revert dependency on pcaprub from 0.13 to 0.12 to support Ruby 3.

## Packetgen 3.1.7

### Changed

* Remove some limitations on Types::String and Types::CString:
    * Add #encode, #slice, #slice!,
    * Make #<< return itself,
    * Add #[]= (Types::String only).

## Packetgen 3.1.6

### Deprecated

* PcapNG module:
    * Deprecate PcapNG::File#array_to_file in favor of PcapNG::File#read_array and PcapNG::File#read_hash
    * Deprecate PcapNG::File#file_to_array in favor of PcapNG::File#to_a and PcapNG::File#to_h

### Added

* PcapNG module: add PcapNG::EPB#timestamp=
* Add Types::Fieldable mixin to document API needed for a class to be used as
  a field in Typess:Fields subclasses.
* Types::String, Types::CString and Types::IntString: add #empty?

### Changed

* Types::String and Types::CString are no more subclasses or Ruby String.
* Fix some kwargs in prevision of ruby 3.
* Clean code.

### Fixed

* require forwardable in Types::String and Types::CString, as requiring from
  Types::Array is not always done before.
* PacketGen.force_binary is used instead of #force_binary in Types::String and
  Types::CString. Worked in spec because #force_binary was a spec helper.

## Packetgen 3.1.5

### Added

* Add support for setting monitor mode when capturing packets (optix2000).
* Add PacketGen.loopback_iface to get loopback interface.
* Add Types::fields.bit_fields to get bit field definitions for given class.
* Add Inspectable module to share methods to format types when inspecting headers.

### Changed

* Refactor Config to isolate use of Interfacez in a dedicated method.
* Work on Types::Fields: refactor .define_field, .define_bit_fields_on and #initialize.
* Refactor Header::EAP#read.

### Remove

* Remove unneeded #read (Header::DHCPv6::Option, Header::PPI, Header::RadioTap, Header::Dot1x and Header::TCP).

### Fixed

* Fix Utils.arp: really use iface information.
* Fix string interpolation in Types::AbstractTLV#to_human (optix2000).
* Fix Deprecation.deprecated and Deprecation.deprecated_class in some obsure cases (optix2000).

## Packetgen 3.1.4

### Added

* Add this Changelog.
* Types::AbstractTLV: add header_in_length flag. If set to `true`, then length in computed not only on value field but also on type and length ones.
* Inspect module: add some helper methods.
* Add Header::Eth::MacAddr#==, Header::IP:Addr#== and Header::IPv6:Addr#==.
* Add BindingError exception. This one replaces ArgumentError when no binding is found between two headers.

### Changed

* Make some little speed improvement on Headerable#read, Packet#add, Packet#insert and PcapNG::File#array_to_file.
* Clean up PcapNG module and Packet class.
* Clean up gemspec.
* Isolate dependency on PCAPRUB into PCAPRUBWrapper module.
* Create Inject module to factorize code to inject data on wire.
* Move pcap-read logic into new Pcap module.
* Refactor Packet#decapsulate

### Removed

* Drop Ruby 2.3 support on travis CI.

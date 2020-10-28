# Changelog

## Master

* Add Types::Fieldable mixin to document API needed for a class to be used as
  a field in Typess:Fields subclasses.
* Types::String and Types::CString are no more subclasses or Ruby String.
* Types::String, Types::CString and Types::IntString: add #empty?
* Fix some kwargs in prevision of ruby 3.
* Clean code.
* Bugs:
    * require forwardable in Types::String and Types::CString, as requiring from
      Types::Array is not always done before.
    * PacketGen.force_binary is used instead of #force_binary in Types::String and
      Types::CString. Worked in spec because #force_binary was a spec helper.

## Packetgen 3.1.5

* Add support for setting monitor mode when capturing packets (optix2000).
* Add PacketGen.loopback_iface to get loopback interface.
* Refactor Config to isolate use of Interfacez in a dedicated method.
* Add Types::fields.bit_fields to get bit field definitions for given class.
* Work on Types::Fields: refactor .define_field, .define_bit_fields_on and #initialize.
* Add Inspectable module to share methods to format types when inspecting headers.
* Remove unneeded #read (Header::DHCPv6::Option, Header::PPI, Header::RadioTap, Header::Dot1x and Header::TCP).
* Refactor Header::EAP#read.
* Bugs:
    * Fix Utils.arp: really use iface information.
    * Fix string interpolation in Types::AbstractTLV#to_human (optix2000).
    * Fix Deprecation.deprecated and Deprecation.deprecated_class in some obsure cases (optix2000).

## Packetgen 3.1.4

* Add this Changelog.
* Make some little speed improvement on Headerable#read, Packet#add, Packet#insert and PcapNG::File#array_to_file.
* Clean up PcapNG module and Packet class.
* Drop Ruby 2.3 support on travis CI.
* Clean up gemspec.
* Types::AbstractTLV: add header_in_length flag. If set to true, then length in computed not only on value field but also on type and length ones.
* Inspect module: add some helper methods.
* Add Header::Eth::MacAddr#==, Header::IP:Addr#== and Header::IPv6:Addr#==.
* Isolate dependency on PCAPRUB into PCAPRUBWrapper module.
* Add Inject module to factorize code to inject data on wire.
* Move pcap-read logic into new Pcap module.
* Refactor Packet#decapsulate
* Add BindingError exception. This one replaces ArgumentError when no binding is found between two headers.

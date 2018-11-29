
[![Gem Version](https://badge.fury.io/rb/packetgen.svg)](https://badge.fury.io/rb/packetgen)
[![Build Status](https://travis-ci.org/sdaubert/packetgen.svg?branch=master)](https://travis-ci.org/sdaubert/packetgen)

# PacketGen

PacketGen provides simple ways to generate, send and capture network packets.

## Installation
PacketGen depends on PcapRub, which needs pcap development files to install. On Debian, you have to do:

    $ sudo apt install libpcap-dev

Installation using RubyGems is then easy:

    $ gem install packetgen

Or add it to a Gemfile:
```ruby
gem 'packetgen'
```

## Usage

### Easily create packets
```ruby
PacketGen.gen('IP')             # generate a IP packet object
PacketGen.gen('TCP')            # generate a TCP over IP packet object
PacketGen.gen('IP').add('TCP')  # the same
PacketGen.gen('Eth')            # generate a Ethernet packet object
PacketGen.gen('IP').add('IP')   # generate a IP-in-IP tunnel packet object

# Generate a IP packet object, specifying addresses
PacketGen.gen('IP', src: '192.168.1.1', dst: '192.168.1.2')

# get binary packet
PacketGen.gen('IP').to_s
```

### Send packets on wire
```ruby
# send Ethernet packet
PacketGen.gen('Eth', src: '00:00:00:00:00:01', dst: '00:00:00:00:00:02').to_w
# send IP packet
PacketGen.gen('IP', src: '192.168.1.1', dst: '192.168.1.2').to_w
# send forged IP packet over Ethernet
PacketGen.gen('Eth', src: '00:00:00:00:00:01', dst: '00:00:00:00:00:02').add('IP').to_w('eth1')
# send a IEEE 802.11 frame
PacketGen.gen('RadioTap').
          add('Dot11::Management', mac1: client, mac2: bssid, mac3: bssid).
          add('Dot11::DeAuth', reason: 7).
          to_w('wlan0')
```

### Parse packets from binary data
```ruby
packet = PacketGen.parse(binary_data)
```

### Capture packets from wire
```ruby
# Capture packets from first network interface, action from a block
PacketGen.capture do |packet|
  do_stuffs_with_packet
end

# Capture some packets, and act on them afterward
packets = PacketGen.capture(iface: 'eth0', max: 10)   # return when 10 packets were captured

# Use filters
packets = PacketGen.capture(iface: 'eth0', filter: 'ip src 1.1.1.2', max: 1)
```

### Easily manipulate packets
```ruby
# access header fields
pkt = PacketGen.gen('IP').add('TCP')
pkt.ip.src = '192.168.1.1'
pkt.ip(src: '192.168.1.1', ttl: 4)
pkt.tcp.dport = 80

# access header fields when multiple header of one kind exist
pkt = PacketGen.gen('IP').add('IP')
pkt.ip.src = '192.168.1.1'  # set outer src field
pkt.ip(2).src = '10.0.0.1'  # set inner src field

# test packet types
pkt = PacketGen.gen('IP').add('TCP')
pkt.is? 'TCP'   # => true
pkt.is? 'IP'    # => true
pkt.is? 'UDP'   # => false

# encapulsate/decapsulate packets
pkt2 = PacketGen.gen('IP')
pkt2.encapsulate pkt                   # pkt2 is now a IP/IP/TCP packet
pkt2.decapsulate(pkt2.ip)              # pkt2 is now inner IP/TCP packet
```

### Read/write PcapNG files
```ruby
# read a PcapNG file, containing multiple packets
packets = PacketGen.read('file.pcapng')
packets.first.udp.sport = 65535
# write only one packet to a PcapNG file
pkt.write('one_packet.pcapng')
# write multiple packets to a PcapNG file
PacketGen.write('more_packets.pcapng', packets)
```

### Add custom header/protocol
Since v1.1.0, PacketGen permits adding your own header classes.
First, define the new header class. For example:

```ruby
module MyModule
 class MyHeader < PacketGen::Header::Base
   define_field :field1, PacketGen::Types::Int32
   define_field :field2, PacketGen::Types::Int32
 end
end
```

Then, class must be declared to PacketGen:

```ruby
PacketGen::Header.add_class MyModule::MyHeader
```

Finally, bindings must be declared:

```ruby
# bind MyHeader as IP protocol number 254 (needed by Packet#parse and Packet#add)
PacketGen::Header::IP.bind_header MyModule::MyHeader, protocol: 254
```

And use it:

```ruby
pkt = Packet.gen('IP').add('MyHeader', field1: 0x12345678)
pkt.myheader.field2.read 0x01
```

## Interactive console
PacketGen provides an interactive console: `pgconsole`.

In this console, context includes PacketGen module to give direct access to PacketGen
classes. A special `config` object gives local network configuration:

    $ pgconsole
    pg(main)> config
    => #<PacketGen::Config:0x00559f27d2afe8
     @hwaddr="75:74:73:72:71:70",
     @iface="eth0",
     @ipaddr="192.168.0.2">
    pg(main)> packets = capture(max: 5)
    pg(main)> exit

If `pry` gem is installed, it is used as backend for `pgconsole`, else IRB is used.

## Plugins

PacketGen provides a plugin system (see [wiki](https://github.com/sdaubert/packetgen/wiki/Create-Custom-Protocol)).

Available plugins (available as gem) are:

* [packetgen-plugin-ipsec](https://github.com/sdaubert/packetgen-plugin-ipsec): add support for ESP and IKEv2 protocols. Before PacketGen3, these protocols were included in packetgen.
* [packetgen-plugin-smb](https://github.com/sdaubert/packetgen-plugin-smb): add support for SMB protocol suite.

## See also

Wiki: https://github.com/sdaubert/packetgen/wiki

API documentation: http://www.rubydoc.info/gems/packetgen

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/sdaubert/packetgen.

## License

MIT License (see [LICENSE](https://github.com/sdaubert/packetgen/blob/master/LICENSE))

### Other sources
All original code maintains its copyright from its original authors and licensing.

This is mainly for PcapNG (originally copied from [PacketFu](https://github.com/packetfu/packetfu),
but i am the original author.

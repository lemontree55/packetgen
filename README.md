
[![Gem Version](https://badge.fury.io/rb/packetgen.svg)](https://badge.fury.io/rb/packetgen)
[![Build Status](https://travis-ci.org/sdaubert/packetgen.svg?branch=master)](https://travis-ci.org/sdaubert/packetgen)

# PacketGen

PacketGen provides simple ways to generate, send and capture network packets.

## Installation
Via RubyGems:

    $ gem install packetgen

Or add it to a Gemfile:
```ruby
gem 'packetgen'
```

## Usage

### Easily create packets
```
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
```
# send Ethernet packet
PacketGen.gen('Eth', src: '00:00:00:00:01', dst: '00:00:00:00:02').to_w
# send IP packet
PacketGen.gen('IP', src: '192.168.1.1', dst: '192.168.1.2').to_w
# send forged IP packet over Ethernet
PacketGen.gen('Eth', src: '00:00:00:00:01', dst: '00:00:00:00:02').add('IP').to_w('eth1')
```

### Parse packets from binary data
```
packet = PacketGen.parse(binary_data)
```

### Capture packets from wire
```
# Capture packets, action from a block
PacketGen.capture('eth0') do |packet|
  do_stuffs_with_packet
end

# Capture some packets, and act on them afterward
packets = PacketGen.capture('eth0', max: 10)   # return when 10 packets were captured

# Use filters
packets = PacketGen.capture('eth0', filter: 'ip src 1.1.1.2', max: 1)
```

### Easily manipulate packets
```
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
```
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
First, define the new header class. By example:

```ruby
module MyModule
 class MyHeader < PacketGen::Types::Fields
   define_field :field1, PacketGen::Types::Int32   
   define_field :field2, PacketGen::Types::Int32   
 end
end
```

Then, class must be declared to PacketGen:

```
PacketGen::Header.add_class MyModule::MyHeader
```

Finally, bindings must be declared:

```
# bind MyHeader as IP protocol number 254 (needed by Packet#parse and Packet#add)
PacketGen::Header::IP.bind_header MyModule::MyHeader, protocol: 254
```

And use it:

```
pkt = Packet.gen('IP').add('MyHeader', field1: 0x12345678)
pkt.myheader.field2.read 0x01
```

## Pull requests?

yes

## License
MIT License (see [LICENSE](https://github.com/sdaubert/packetgen/blob/master/LICENSE))

Copyright © 2016 Sylvain Daubert

### Other sources
All original code maintains its copyright from its original authors and licensing.

This is mainly for PcapNG (originally copied from [PacketFu](https://github.com/packetfu/packetfu),
but i am the original author).

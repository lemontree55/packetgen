
[![Gem Version](https://badge.fury.io/rb/packetgen.svg)](https://badge.fury.io/rb/packetgen)
[![Build Status](https://travis-ci.org/sdaubert/packetgen.svg?branch=master)](https://travis-ci.org/sdaubert/packetgen)

# PacketGen

PacketGen provides simple ways to generate, send and capture network packets easily.

## Why PacketGen
Why create PacketGen ? There is already PacketFu!

Yes. But PacketFu is limited:
* upper protocols use fixed layers: TCP always uses IPv4, IP and IPv6 always uses Ethernet as MAC,...
* cannot handle tunneled packets (IP-in-IP, or deciphered ESP packets,...)
* cannot easily encapsulate or decapsulate packets
* parse packets top-down, and sometimes bad parse down layers
* cannot send packet on wire at IP/IPv6 level (Ethernet header is mandatory)

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
need PcapRub for Ethernet packets. Need a C extension (use of C socket API) for IP packets.

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
need PCapRub.

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

# encapulsate/decapsulate packets (TODO)
pkt2 = PacketGen.gen('IP').add('ESP', spi: 1234)
pkt.encap pkt2                         # pkt is now a IP/ESP/IP/TCP packet
                                       # eq. to pkt.encap('IP', 'ESP', esp_spi: 1234)
pkt.decap('IP', 'ESP')                 # pkt is now inner IP/TCP packet
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

## Pull requests?

yes

## License
MIT License (see [LICENSE](https://github.com/sdaubert/packetgen/LICENSE))

Copyright © 2016 Sylvain Daubert

### Other sources
All original code maintains its copyright from its original authors and licensing.

This is mainly for StrucFu (copied from [PacketFu](https://github.com/packetfu/packetfu))
and PcapNG module (also copied from PacketFu, but I am the author).

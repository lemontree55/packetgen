module CaptureHelper
  # capture(iface, options) { 'ping -c 125 127.0.0.1 }
  def capture(options={}, &blk)
    iface   = options[:iface]   || Pcap.lookupdev
    timeout = options[:timeout] || 0
    filter  = options[:filter]  || false
    opts = { iface: iface, timeout: timeout, filter: filter} 
    cap = PacketGen::Capture.new(opts)
    cap_thread = Thread.new { cap.start }
    sleep 0.1
    blk.call
    sleep timeout + 2
    cap.stop
    cap
  end
end

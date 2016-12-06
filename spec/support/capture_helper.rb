module CaptureHelper
  # capture(iface, options) { 'ping -c 125 127.0.0.1 }
  def capture(iface, options={}, &blk)
    timeout = options[:timeout] || 0

    cap = PacketGen::Capture.new(iface, options)
    cap_thread = Thread.new { cap.start }
    sleep 0.1
    blk.call
    sleep timeout + 2
    cap.stop

    cap
  end
end

module CaptureHelper
  # capture(options) { system 'ping -c 125 127.0.0.1 }
  def capture(options={}, &blk)
    timeout = options[:timeout] || 0
    cap = PacketGen::Capture.new
    cap_thread = Thread.new { cap.start(options) }
    sleep 0.1
    blk.call
    sleep timeout + 2
    cap.stop
    cap
  end
end

module CaptureHelper
  # capture(iface, options) { 'ping -c 125 127.0.0.1 }
  def capture(iface, options={}, &blk)
    timeout = options[:timeout] || 0

    cap = Capture.new(iface, options)
    cap_thread = Thread.new { cap.start }
    sleep 0.1
    blk.call
    cap_thread.join(timeout * 2 + 1)

    cap
  end
end

module CaptureHelper
  SYS_ENV = { 'LC_ALL' => 'C' }.freeze

  def ping(addr, options={})
    opts = []
    options.each do |opt, value|
      case opt
      when :count
        opts << "-c #{value}"
      when :interval
        opts << "-i #{value}"
      else
        warn("ping helper: unknown option '#{opt}'")
      end
    end

    cmd = "ping #{opts.join(' ')} #{addr} > /dev/null"

    system(SYS_ENV, cmd)
  end

  # capture(options) { system 'ping -c 125 127.0.0.1 }
  def capture(options={}, &blk)
    timeout = options[:timeout] || 0
    cap = PacketGen::Capture.new
    cap_thread = Thread.new { cap.start(**options) }
    sleep 0.1
    blk.call
    sleep timeout + 2
    cap.stop
    cap
  end
end

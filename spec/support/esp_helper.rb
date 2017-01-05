module EspHelper
  def get_packets_from(file, icv_length:nil)
    black_pkt, red_pkt, = PacketGen.read(file)

    red_pkt.decapsulate red_pkt.eth
    black_pkt.decapsulate black_pkt.eth

    if icv_length
      black_pkt.esp.icv_length = icv_length
      # Re-read ESP header to get actual ICV
      black_pkt.esp.read black_pkt.esp.to_s
    end

    [black_pkt, red_pkt]
  end
end

module LabelHelper
  def generate_label_str(labels)
    str = ''
    labels.each do |label|
      str << [label.length].pack('C') << label
    end
    force_binary(str << "\x00")
  end
end

# frozen_string_literal: true

module LabelHelper
  def generate_label_str(labels)
    str = +''
    labels.each do |label|
      str << [label.length].pack('C') << label.b
    end
    str << "\x00"
  end
end

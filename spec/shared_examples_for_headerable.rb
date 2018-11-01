require_relative 'spec_helper'

shared_examples 'headerable' do |klass|
  let(:object) { klass.new }

  it 'responds to .protocol_name' do
    expect(klass).to respond_to(:protocol_name)
  end

  it 'responds to #protocol_name' do
    expect(object).to respond_to(:protocol_name)
  end

  it 'responds to #method_name' do
    expect(object).to respond_to(:method_name)
  end

  it 'responds to #read' do
    expect(object).to respond_to(:read)
  end

  it 'responds to #parse?' do
    expect(object).to respond_to(:parse?)
  end

  it 'responds to #packet=' do
    expect(object).to respond_to(:packet=)
  end
  it 'responds to #added_to_packet' do
    expect(object).to respond_to(:added_to_packet)
  end
end

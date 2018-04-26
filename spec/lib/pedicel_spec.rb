require 'pedicel'

describe 'Pedicel config' do
  it 'can be configured without mangling with the defaults' do
    t = Pedicel::DEFAULTS[:replay_threshold_seconds]
    Pedicel.config.merge!(replay_threshold_seconds: 5)
    expect(Pedicel::DEFAULTS[:replay_threshold_seconds]).to eq(t)

    t = Pedicel::DEFAULTS[:replay_threshold_seconds]
    Pedicel.config[:replay_threshold_seconds] = 5
    expect(Pedicel::DEFAULTS[:replay_threshold_seconds]).to eq(t)

    x = Pedicel::DEFAULTS[:oids][:leaf_certificate]
    Pedicel.config[:oids][:leaf_certificate] = 'foobar'
    expect(Pedicel::DEFAULTS[:oids][:leaf_certificate]).to eq(x)
  end
end

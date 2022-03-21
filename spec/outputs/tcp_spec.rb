require "logstash/devutils/rspec/spec_helper"
require "logstash/outputs/tcp"
require "flores/pki"

describe LogStash::Outputs::Tcp do
  subject { described_class.new(config) }
  let(:config) { {
    "host" => "localhost",
    "port" => 2000 + rand(3000),
  } }

  context "when enabling SSL" do
    let(:config) { super().merge("ssl_enable" => true) }
    context "and not providing a certificate/key pair" do
      it "registers without error" do
        expect { subject.register }.to_not raise_error
      end
    end

    context "and providing a certificate/key pair" do
      let(:cert_key_pair) { Flores::PKI.generate }
      let(:certificate) { cert_key_pair.first }
      let(:cert_file) do
        path = Tempfile.new('foo').path
        IO.write(path, certificate.to_s)
        path
      end
      let(:config) { super().merge("ssl_cert" => cert_file) }
      it "registers without error" do
        expect { subject.register }.to_not raise_error
      end
    end

    FIXTURES_PATH = File.expand_path('../fixtures', File.dirname(__FILE__))

    context "ES generated plain-text certificate/key" do
      let(:key_file) { File.join(FIXTURES_PATH, 'plaintext/instance.key') }
      let(:crt_file) { File.join(FIXTURES_PATH, 'plaintext/instance.crt') }
      let(:config) { super().merge("ssl_cert" => crt_file, "ssl_key" => key_file) }

      it "registers without error" do
        expect { subject.register }.to_not raise_error
      end

      context 'with password set' do

        let(:config) { super().merge("ssl_key_passphrase" => 'ignored') }

        it "registers without error" do # password simply ignored
          expect { subject.register }.to_not raise_error
        end

      end
    end

    context "encrypted key using PKCS#1" do
      let(:key_file) { File.join(FIXTURES_PATH, 'encrypted/instance.key') }
      let(:crt_file) { File.join(FIXTURES_PATH, 'encrypted/instance.crt') }
      let(:config) { super().merge("ssl_cert" => crt_file, "ssl_key" => key_file) }

      it "registers with error (due missing password)" do
        expect { subject.register }.to raise_error(OpenSSL::PKey::RSAError) # TODO need a better error
      end

      context 'with valid password' do

        let(:config) { super().merge("ssl_key_passphrase" => '1234567890') }

        it "registers without error" do
          expect { subject.register }.to_not raise_error
        end

      end
    end
  end
end

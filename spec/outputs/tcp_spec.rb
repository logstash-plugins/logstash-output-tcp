require "logstash/devutils/rspec/spec_helper"
require "logstash/outputs/tcp"
require "flores/pki"

describe LogStash::Outputs::Tcp do
  subject { described_class.new(config) }

  let(:port) do
    begin
      # Start high to better avoid common services
      port = rand(10000..65535)
      s = TCPServer.new("127.0.0.1", port)
      s.close

      port
    rescue Errno::EADDRINUSE
      retry
    end
  end

  let(:server) { TCPServer.new("127.0.0.1", port) }

  let(:config) { { "host" => "localhost", "port" => port } }

  let(:event) { LogStash::Event.new('message' => 'foo bar') }

  context 'failing to connect' do

    before { subject.register }

    let(:config) { super().merge 'port' => 1000 }

    it 'fails to connect' do
      expect( subject ).to receive(:log_error).and_call_original
      Thread.start { subject.receive(event) }
      sleep 1.0
    end

  end

  context 'server mode' do

    before { subject.register }

    let(:config) { super().merge 'mode' => 'server' }

    let(:client) do
      Stud::try(3.times) { TCPSocket.new("127.0.0.1", port) }
    end

    after { subject.close }

    it 'receives serialized data' do; require 'json'
      client # connect
      Thread.start { sleep 0.5; subject.receive event }

      read = client.recv(1000)
      expect( read.size ).to be > 0
      expect( JSON.parse(read)['message'] ).to eql 'foo bar'
    end

  end

  context "with forced protocol" do
    let(:config) do
      super().merge 'ssl_supported_protocols' => [ 'TLSv1.1' ]
    end

    it "limits protocol selection" do
      if OpenSSL::SSL.const_defined? :OP_NO_TLSv1_3
        ssl_context = subject.send :setup_ssl
        expect(ssl_context.options & OpenSSL::SSL::OP_NO_TLSv1_3).to_not eql 0
        expect(ssl_context.options & OpenSSL::SSL::OP_NO_TLSv1_2).to_not eql 0
        expect(ssl_context.options & OpenSSL::SSL::OP_NO_TLSv1_1).to eql 0
      else
        ssl_context = OpenSSL::SSL::SSLContext.new
        allow(subject).to receive(:new_ssl_context).and_return(ssl_context)
        expect(ssl_context).to receive(:max_version=).with(:'TLS1_2').and_call_original
        ssl_context = subject.send :setup_ssl
        expect(ssl_context.options & OpenSSL::SSL::OP_NO_TLSv1_2).to_not eql 0
        expect(ssl_context.options & OpenSSL::SSL::OP_NO_TLSv1_1).to eql 0
      end
    end
  end

  context "with protocol range" do
    let(:config) do
      super().merge 'ssl_supported_protocols' => [ 'TLSv1.3', 'TLSv1.1', 'TLSv1.2' ]
    end

    it "does not limit protocol selection (except min_version)" do
      ssl_context = OpenSSL::SSL::SSLContext.new
      allow(subject).to receive(:new_ssl_context).and_return(ssl_context)
      expect(ssl_context).to receive(:min_version=).with(:'TLS1_1').at_least(1).and_call_original

      if OpenSSL::SSL.const_defined? :OP_NO_TLSv1_3
        subject.send :setup_ssl
        expect(ssl_context.options & OpenSSL::SSL::OP_NO_TLSv1_3).to eql 0
        expect(ssl_context.options & OpenSSL::SSL::OP_NO_TLSv1_2).to eql 0
        expect(ssl_context.options & OpenSSL::SSL::OP_NO_TLSv1_1).to eql 0
      else
        subject.send :setup_ssl
        expect(ssl_context.options & OpenSSL::SSL::OP_NO_TLSv1_2).to eql 0
        expect(ssl_context.options & OpenSSL::SSL::OP_NO_TLSv1_1).to eql 0
      end

      subject.send :setup_ssl
    end
  end

  context "client mode" do
    before { subject.register }

    let(:config) { super().merge 'mode' => 'client' }

    it 'writes payload data' do
      Thread.start { sleep 0.25; subject.receive event }

      socket = server.accept
      read = socket.sysread(100)

      expect( read.size ).to be > 0
      expect( read ).to eq(JSON.generate(event))
    end

    it 'writes payload data in multiple operations' do
      full_payload = JSON.generate(event)
      Thread.start { sleep 0.25; subject.receive event }

      socket = server.accept
      first_read = socket.sysread((full_payload.length / 2))
      second_read = socket.sysread(((full_payload.length / 2) + 1))

      expect( "#{first_read}#{second_read}" ).to eq(full_payload)
    end
  end

  context "when enabling SSL" do
    let(:config) { super().merge("ssl_enable" => true, 'codec' => 'plain') }
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

      let(:secure_server) do
        ssl_context = OpenSSL::SSL::SSLContext.new
        ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE
        ssl_context.cert = OpenSSL::X509::Certificate.new(File.read(crt_file))
        ssl_context.key = OpenSSL::PKey::RSA.new(File.read(key_file), nil)
        ssl_context.ssl_version = server_ssl_version if server_ssl_version
        ssl_context.min_version = server_min_version if server_min_version
        ssl_context.max_version = server_max_version if server_max_version
        OpenSSL::SSL::SSLServer.new(server, ssl_context)
      end

      let(:server_min_version) { nil }
      let(:server_max_version) { nil }
      let(:server_ssl_version) { nil }

      context 'with supported protocol' do

        let(:config) { super().merge("ssl_supported_protocols" => ['TLSv1.2']) }

        let(:server_min_version) { 'TLS1_2' }

        before { subject.register }
        after { secure_server.close }

        it 'reads plain data' do
          Thread.start { sleep 0.25; subject.receive event }
          socket = secure_server.accept
          read = socket.sysread(100)
          expect( read.size ).to be > 0
          expect( read ).to end_with 'foo bar'
        end

      end

      context 'with unsupported protocol (on server)' do

        let(:config) { super().merge("ssl_supported_protocols" => ['TLSv1.1']) }

        let(:server_min_version) { 'TLS1_2' }

        before { subject.register }
        after { secure_server.close }

        it 'fails (and loops retrying)' do
          expect(subject.logger).to receive(:error).with(/connect ssl failure/i, hash_including(message: /No appropriate protocol/i)).and_call_original
          expect(subject.logger).to receive(:error).with(/failed to connect/i, hash_including(exception: OpenSSL::SSL::SSLError)).and_call_original
          expect(subject).to receive(:sleep).once.and_call_original
          expect(subject).to receive(:sleep).once.and_throw :TEST_DONE # to be able to abort the retry loop

          Thread.start { secure_server.accept rescue nil }
          expect { subject.receive event }.to throw_symbol(:TEST_DONE)
        end

      end if LOGSTASH_VERSION > '7.0'

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

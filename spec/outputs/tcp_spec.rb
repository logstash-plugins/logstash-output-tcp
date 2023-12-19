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

  context "with cipher suites" do
    let(:config) do
      super().merge('ssl_cipher_suites' => %w[TLS_RSA_WITH_AES_128_GCM_SHA256 TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA])
    end

    it "limits the ciphers selection" do
      ssl_context = OpenSSL::SSL::SSLContext.new
      allow(subject).to receive(:new_ssl_context).and_return(ssl_context)
      subject.send :setup_ssl
      expect(ssl_context.ciphers.length).to eq(2)
      expect(ssl_context.ciphers).to satisfy { |arr| arr[0].include?('AES128-GCM-SHA256') && arr[1].include?('EDH-RSA-DES-CBC3-SHA') }
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
    let(:config) { super().merge("ssl_enabled" => true, 'codec' => 'plain') }
    context "and not providing a certificate/key pair" do
      it "registers without error" do
        expect { subject.register }.to_not raise_error
      end
    end

    context "and providing a certificate/key pair" do
      let(:cert_key_pair) { Flores::PKI.generate }
      let(:certificate) do
        path = Tempfile.new('certificate').path
        IO.write(path, cert_key_pair.first.to_s)
        path
      end
      let(:key) do
        path = Tempfile.new('key').path
        IO.write(path, cert_key_pair[1].to_s)
        path
      end
      let(:config) { super().merge("ssl_certificate" => certificate, "ssl_key" => key) }

      it "registers without error" do
        expect { subject.register }.to_not raise_error
      end
    end

    FIXTURES_PATH = File.expand_path('../fixtures', File.dirname(__FILE__))

    context "ES generated plain-text certificate/key" do
      let(:key_file) { File.join(FIXTURES_PATH, 'plaintext/instance.key') }
      let(:crt_file) { File.join(FIXTURES_PATH, 'plaintext/instance.crt') }
      let(:config) { super().merge("ssl_certificate" => crt_file, "ssl_key" => key_file) }

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
      let(:config) { super().merge("ssl_certificate" => crt_file, "ssl_key" => key_file) }

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

    context "and protocol is TLSv1.3" do
      let(:key_file) { File.join(FIXTURES_PATH, 'plaintext/instance.key') }
      let(:crt_file) { File.join(FIXTURES_PATH, 'plaintext/instance.crt') }
      let(:config) { super().merge("ssl_certificate" => crt_file, "ssl_key" => key_file) }

      let(:secure_server) do
        ssl_context = OpenSSL::SSL::SSLContext.new
        ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE
        ssl_context.cert = OpenSSL::X509::Certificate.new(File.read(crt_file))
        ssl_context.key = OpenSSL::PKey::RSA.new(File.read(key_file), nil)
        ssl_context.min_version = OpenSSL::SSL::TLS1_3_VERSION
        OpenSSL::SSL::SSLServer.new(server, ssl_context)
      end

      before(:each) do
        subject.register
      end

      after(:each) do
        secure_server.close rescue nil
      end

      let(:message) { "a" }
      let(:buffer) { "" }

      # This test confirms that this plugin is able to write to a TLS socket
      # multiple times.
      # Previous implementation performed an IO.select first and called sysread
      # if select signaled the socket was ready to read.
      # For TLS1_3, due to control messages it may happen that the underlying
      # socket is marked as readable but there is no new data available,
      # causing a read to block forever.
      # This test will raise a Timeout exception with the old implementation.
      it 'successfully writes two messages' do
        thread = Thread.start do
          expect {
            client = secure_server.accept
            Timeout::timeout(5) do
              buffer << client.sysread(1) # read first message
              subject.receive(message)
              buffer << client.sysread(1) # read second message
              client.close
            end
          }.to_not raise_error
        end
        sleep 0.1 until thread.status == "sleep" # wait for TCP port to open
        subject.receive(message) # send first message to unblock call to `accept`
        thread.join(2)

        expect(buffer).to eq(message * 2)
      end
    end

    context "with only ssl_certificate set" do
      let(:config) { super().merge("ssl_certificate" => File.join(FIXTURES_PATH, 'plaintext/instance.crt')) }

      it "should raise a configuration error to request also `ssl_key`" do
        expect { subject.register }.to raise_error(LogStash::ConfigurationError, /Using an `ssl_certificate` requires an `ssl_key`/)
      end
    end

    context "with only ssl_key set" do
      let(:config) { super().merge("ssl_key" => File.join(FIXTURES_PATH, 'plaintext/instance.key')) }

      it "should raise a configuration error to request also `ssl_key`" do
        expect { subject.register }.to raise_error(LogStash::ConfigurationError, /An `ssl_certificate` is required when using an `ssl_key`/)
      end
    end

    context "and mode is server" do
      let(:config) do
        {
          "host" => "127.0.0.1",
          "port" => port,
          "mode" => 'server',
          "ssl_enabled" => true,
          "ssl_certificate" => File.join(FIXTURES_PATH, 'plaintext/instance.crt'),
          "ssl_key" => File.join(FIXTURES_PATH, 'plaintext/instance.key'),
        }
      end

      context "with no ssl_certificate" do
        let(:config) { super().reject { |k| "ssl_key".eql?(k) || "ssl_certificate".eql?(k) } }

        it "should raise a configuration error" do
          expect { subject.register }.to raise_error(LogStash::ConfigurationError, /An `ssl_certificate` is required when `ssl_enabled` => true/)
        end
      end

      context "with ssl_client_authentication = `none` and no ssl_certificate_authorities" do
        let(:config) { super().merge(
          'ssl_client_authentication' => 'none',
          'ssl_certificate_authorities' => []
        ) }

        it "should register without errors" do
          expect { subject.register }.to_not raise_error
        end
      end

      context "with deprecated ssl_verify = true and no ssl_certificate_authorities" do
        let(:config) { super().merge(
          'ssl_verify' => true,
          'ssl_certificate_authorities' => []
        ) }

        it "should register without errors" do
          expect { subject.register }.to_not raise_error
        end
      end

      %w[required optional].each do |ssl_client_authentication|
        context "with ssl_client_authentication = `#{ssl_client_authentication}` and no ssl_certificate_authorities" do
          let(:config) { super().merge(
            'ssl_client_authentication' => ssl_client_authentication,
            'ssl_certificate_authorities' => []
          ) }

          it "should raise a configuration error" do
            expect { subject.register }.to raise_error(LogStash::ConfigurationError, /An `ssl_certificate_authorities` is required when `ssl_client_authentication` => `#{ssl_client_authentication}`/)
          end
        end
      end

      context "with ssl_verification_mode" do
        let(:config) do
          super().merge 'ssl_verification_mode' => 'full'
        end

        it "should raise a configuration error" do
          expect{subject.register}.to raise_error(LogStash::ConfigurationError, /`ssl_verification_mode` must not be configured when mode is `server`, use `ssl_client_authentication` instead/)
        end
      end
    end

    context "with deprecated settings" do
      let(:ssl_verify) { true }
      let(:certificate_path) { File.join(FIXTURES_PATH, 'plaintext/instance.crt') }
      let(:config) do
        {
          "host" => "127.0.0.1",
          "port" => port,
          "ssl_enable" => true,
          "ssl_cert" => certificate_path,
          "ssl_key" => File.join(FIXTURES_PATH, 'plaintext/instance.key'),
          "ssl_verify" => ssl_verify
        }
      end

      context "and mode is server" do
        let(:config) { super().merge("mode" => 'server') }
        [true, false].each do |verify|
          context "and ssl_verify is #{verify}" do
            let(:ssl_verify) { verify }

            it "should set new configs variables" do
              subject.register
              expect(subject.instance_variable_get(:@ssl_enabled)).to eql(true)
              expect(subject.instance_variable_get(:@ssl_client_authentication)).to eql(verify ? 'required' : 'none')
              expect(subject.instance_variable_get(:@ssl_certificate)).to eql(certificate_path)
            end
          end
        end
      end

      context "and mode is client" do
        let(:config) { super().merge("mode" => 'client') }
        [true, false].each do |verify|
          context "and ssl_verify is #{verify}" do
            let(:ssl_verify) { verify }

            it "should set new configs variables" do
              subject.register
              expect(subject.instance_variable_get(:@ssl_enabled)).to eql(true)
              expect(subject.instance_variable_get(:@ssl_verification_mode)).to eql(verify ? 'full' : 'none')
              expect(subject.instance_variable_get(:@ssl_certificate)).to eql(certificate_path)
            end
          end
        end
      end
    end

    context "with ssl_client_authentication" do
      let(:config) do
        super().merge 'ssl_client_authentication' => 'required'
      end

      it "should raise a configuration error" do
        expect{subject.register}.to raise_error(LogStash::ConfigurationError, /`ssl_client_authentication` must not be configured when mode is `client`, use `ssl_verification_mode` instead/)
      end
    end

    context "with ssl_certificate_authorities" do
      let(:certificate_path) { File.join(FIXTURES_PATH, 'plaintext/instance.crt') }
      let(:config) do
        super().merge('ssl_certificate_authorities' => [certificate_path])
      end

      it "sets cert_store values" do
        ssl_store = double(OpenSSL::X509::Store.new)
        allow(ssl_store).to receive(:set_default_paths)
        allow(ssl_store).to receive(:add_file)
        allow(subject).to receive(:new_ssl_certificate_store).and_return(ssl_store)
        subject.send :setup_ssl
        expect(ssl_store).to have_received(:add_file).with(certificate_path)
      end
    end

    context "CAs certificates" do
      it "includes openssl default paths" do
        ssl_store = double(OpenSSL::X509::Store.new)
        allow(ssl_store).to receive(:set_default_paths)
        allow(subject).to receive(:new_ssl_certificate_store).and_return(ssl_store)
        subject.send :setup_ssl
        expect(ssl_store).to have_received(:set_default_paths)
      end
    end

  end
end

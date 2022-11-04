require "logstash/devutils/rspec/spec_helper"
require "logstash/outputs/tcp"
require "flores/pki"

describe LogStash::Outputs::Tcp do
  subject(:instance) { described_class.new(config) }
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

  ##
  # Reads `in_io` until EOF and writes the bytes
  # it receives to `out_io`, tolerating partial writes.
  def siphon_until_eof(in_io, out_io)
    buffer = ""
    while (retval = in_io.read_nonblock(32*1024, buffer, exception:false)) do
      (IO.select([in_io], nil, nil, 5); next) if retval == :wait_readable

      while (buffer && !buffer.empty?) do
        bytes_written = out_io.write(buffer)
        buffer.replace buffer.byteslice(bytes_written..-1)
      end
    end
  end

  context 'client mode' do
    context 'transmitting data' do
      let!(:io) { StringIO.new } # somewhere for our server to stash the data it receives

      let(:server_host) { 'localhost' }
      let(:server_port) { server.addr[1] } # get actual since we bind to port 0

      let!(:server) { TCPServer.new(server_host, 0) }

      let(:config) do
        { 'host' => server_host, 'port' => server_port, 'mode' => 'client' }
      end

      let(:event) { LogStash::Event.new({"hello" => "world"})}

      subject(:instance) { described_class.new(config) }

      before(:each) do
        # accepts ONE connection
        @server_socket_thread = Thread.start do
          client = server.accept
          siphon_until_eof(client, io)
        end
        instance.register
      end

      after(:each) do
        @server_socket_thread&.join
      end

      it 'encodes and transmits data' do
        instance.receive(event)
        sleep 1
        instance.close # release the connection
        @server_socket_thread.join(30)  || fail('server failed to join')
        expect(io.string).to include('"hello"','"world"')
      end

      context 'when payload is very large' do
        let(:one_hundred_megabyte_message) { "a" * 1024 * 1024 * 100 }
        let(:event) { LogStash::Event.new("message" => one_hundred_megabyte_message) }


        it 'encodes and transmits data' do
          instance.receive(event)
          sleep 1
          instance.close # release the connection
          @server_socket_thread.join(30)  || fail('server failed to join')
          expect(io.string).to include('"message"',%Q("#{one_hundred_megabyte_message}"))
        end
      end
    end
  end

  context 'server mode' do

    def wait_for_condition(total_time_in_seconds, &block)
      deadline = Time.now + total_time_in_seconds
      until Time.now > deadline
        return if yield
        sleep(1)
      end
      fail('condition not met!')
    end

    context 'transmitting data' do
      let(:server_host) { 'localhost' }
      let(:server_port) { Random.rand(1024...5000) }

      let(:config) do
        { 'host' => server_host, 'port' => server_port, 'mode' => 'server' }
      end

      subject(:instance) { described_class.new(config) }

      before(:each) { instance.register } # start listener
      after(:each) { instance.close }

      let(:event) { LogStash::Event.new({"hello" => "world"})}

      context 'when one client is connected' do
        let(:io) { StringIO.new }
        let(:client_socket) { TCPSocket.new(server_host, server_port) }

        before(:each) do
          @client_socket_thread = Thread.start { siphon_until_eof(client_socket, io) }
          sleep 1 # wait for it to actually connect
        end

        it 'encodes and transmits data' do
          sleep 1
          instance.receive(event)

          wait_for_condition(30) { !io.size.zero? }
          sleep 1 # wait for the event to get sent...
          instance.close # release the connection

          @client_socket_thread.join(30) || fail('client failed to join')
          expect(io.string).to include('"hello"','"world"')
        end

        context 'when payload is very large' do
          let(:one_hundred_megabyte_message) { "a" * 1024 * 1024 * 100 }
          let(:event) { LogStash::Event.new("message" => one_hundred_megabyte_message) }

          it 'encodes and transmits data' do
          instance.receive(event)

          wait_for_condition(30) { io.size >= one_hundred_megabyte_message.size }
          sleep 1 # wait for the event to get sent...
          instance.close # release the connection

          @client_socket_thread.join(30) || fail('client failed to join')
            expect(io.string).to include('"message"',%Q("#{one_hundred_megabyte_message}"))
          end
        end
      end
    end
  end
end

# encoding: utf-8
require "logstash/outputs/base"
require "logstash/namespace"
require "thread"
require "logstash/util/socket_peer"

# Write events over a TCP socket.
#
# Each event json is separated by a newline.
#
# Can either accept connections from clients or connect to a server,
# depending on `mode`.
class LogStash::Outputs::Tcp < LogStash::Outputs::Base

  config_name "tcp"
  concurrency :single

  default :codec, "json"

  # When mode is `server`, the address to listen on.
  # When mode is `client`, the address to connect to.
  config :host, :validate => :string, :required => true

  # When mode is `server`, the port to listen on.
  # When mode is `client`, the port to connect to.
  config :port, :validate => :number, :required => true

  # When connect failed,retry interval in sec.
  config :reconnect_interval, :validate => :number, :default => 10

  # Mode to operate in. `server` listens for client connections,
  # `client` connects to a server.
  config :mode, :validate => ["server", "client"], :default => "client"

  # Enable SSL (must be set for other `ssl_` options to take effect).
  config :ssl_enable, :validate => :boolean, :default => false

  # Verify the identity of the other end of the SSL connection against the CA.
  # For input, sets the field `sslsubject` to that of the client certificate.
  config :ssl_verify, :validate => :boolean, :default => false

  # The SSL CA certificate, chainfile or CA path. The system CA path is automatically included.
  config :ssl_cacert, :validate => :path

  # SSL certificate path
  config :ssl_cert, :validate => :path

  # SSL key path
  config :ssl_key, :validate => :path

  # SSL key passphrase
  config :ssl_key_passphrase, :validate => :password, :default => nil

  # NOTE: the default setting [] uses SSL engine defaults
  config :ssl_supported_protocols, :validate => ['TLSv1.1', 'TLSv1.2', 'TLSv1.3'], :default => [], :list => true

  class Client

    ##
    # @param socket [Socket]
    # @param logger_context [#log_warn&#log_error]
    def initialize(socket, logger_context)
      @socket = socket
      @logger_context = logger_context
      @queue  = Queue.new
    end

    def run
      loop do
        begin
          remaining_payload = @queue.pop
          while remaining_payload && remaining_payload.bytesize > 0
            written_bytes_size = @socket.write(remaining_payload)
            remaining_payload = remaining_payload.byteslice(written_bytes_size..-1)
          end
        rescue => e
          @logger_context.log_warn 'socket write failed:', e, socket: (@socket ? @socket.to_s : nil)
          break
        end
      end
    end # def run

    def write(msg)
      @queue.push(msg)
    end # def write

    def close
      @socket.close
    rescue => e
      @logger_context.log_warn 'socket close failed:', e, socket: (@socket ? @socket.to_s : nil)
    end
  end # class Client

  def setup_ssl
    require "openssl"

    @ssl_context = new_ssl_context
    if @ssl_cert
      @ssl_context.cert = OpenSSL::X509::Certificate.new(File.read(@ssl_cert))
      if @ssl_key
        # if we have an encrypted key and a password is not provided (nil) than OpenSSL::PKey::RSA
        # prompts the user to enter a password interactively - we do not want to do that,
        # for plain-text keys the default '' password argument gets simply ignored
        @ssl_context.key = OpenSSL::PKey::RSA.new(File.read(@ssl_key), @ssl_key_passphrase.value || '')
      end
    end
    if @ssl_verify
      @cert_store = OpenSSL::X509::Store.new
      # Load the system default certificate path to the store
      @cert_store.set_default_paths
      if File.directory?(@ssl_cacert)
        @cert_store.add_path(@ssl_cacert)
      else
        @cert_store.add_file(@ssl_cacert)
      end
      @ssl_context.cert_store = @cert_store
      @ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER|OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
    end

    @ssl_context.min_version = :TLS1_1 # not strictly required - JVM should have disabled TLSv1
    if ssl_supported_protocols.any?
      disabled_protocols = ['TLSv1.1', 'TLSv1.2', 'TLSv1.3'] - ssl_supported_protocols
      unless OpenSSL::SSL.const_defined? :OP_NO_TLSv1_3 # work-around JRuby-OpenSSL bug - missing constant
        @ssl_context.max_version = :TLS1_2 if disabled_protocols.delete('TLSv1.3')
      end
      # mapping 'TLSv1.2' -> OpenSSL::SSL::OP_NO_TLSv1_2
      disabled_protocols.map! { |v| OpenSSL::SSL.const_get "OP_NO_#{v.sub('.', '_')}" }
      @ssl_context.options = disabled_protocols.reduce(@ssl_context.options, :|)
    end
    @ssl_context
  end
  private :setup_ssl

  # @note to be able to hook up into #ssl_context from tests
  def new_ssl_context
    OpenSSL::SSL::SSLContext.new
  end
  private :new_ssl_context

  # @overload Base#register
  def register
    require "socket"
    require "stud/try"
    @closed = Concurrent::AtomicBoolean.new(false)
    @thread_no = Concurrent::AtomicFixnum.new(0)
    setup_ssl if @ssl_enable

    if server?
      run_as_server
    else
      run_as_client
    end
  end

  def run_as_server
    @logger.info("Starting tcp output listener", :address => "#{@host}:#{@port}")
    begin
      @server_socket = TCPServer.new(@host, @port)
    rescue Errno::EADDRINUSE
      @logger.error("Could not start tcp server: Address in use", host: @host, port: @port)
      raise
    end
    if @ssl_enable
      @server_socket = OpenSSL::SSL::SSLServer.new(@server_socket, @ssl_context)
    end # @ssl_enable
    @client_threads = Concurrent::Array.new

    @accept_thread = Thread.new(@server_socket) do |server_socket|
      LogStash::Util.set_thread_name("[#{pipeline_id}]|output|tcp|server_accept")
      loop do
        break if @closed.value
        client_socket = server_socket.accept_nonblock exception: false
        if client_socket == :wait_readable
          IO.select [ server_socket ]
          next
        end
        Thread.start(client_socket) do |client_socket|
          # monkeypatch a 'peer' method onto the socket.
          client_socket.extend(::LogStash::Util::SocketPeer)
          @logger.debug("accepted connection", client: client_socket.peer, server: "#{@host}:#{@port}")
          client = Client.new(client_socket, self)
          Thread.current[:client] = client
          LogStash::Util.set_thread_name("[#{pipeline_id}]|output|tcp|client_socket-#{@thread_no.increment}")
          @client_threads << Thread.current
          client.run unless @closed.value
        end
      end
    end

    @codec.on_event do |event, payload|
      @client_threads.select!(&:alive?)
      @client_threads.each do |client_thread|
        client_thread[:client].write(payload)
      end
    end
  end

  def run_as_client
    client_socket = nil
    @codec.on_event do |event, payload|
      begin
        client_socket = connect unless client_socket

        writable_io = nil
        while writable_io.nil? || writable_io.any? == false
          readable_io, writable_io, _ = IO.select([client_socket],[client_socket])

          # don't expect any reads, but a readable socket might
          # mean the remote end closed, so read it and throw it away.
          # we'll get an EOFError if it happens.
          readable_io.each { |readable| readable.sysread(16384) }
        end

        while payload && payload.bytesize > 0
          written_bytes_size = client_socket.syswrite(payload)
          payload = payload.byteslice(written_bytes_size..-1)
        end
      rescue => e
        log_warn "client socket failed:", e, host: @host, port: @port, socket: (client_socket ? client_socket.to_s : nil)
        client_socket.close rescue nil
        client_socket = nil
        sleep @reconnect_interval
        retry
      end
    end
  end

  # @overload Base#receive
  def receive(event)
    @codec.encode(event)
  end

  # @overload Base#close
  def close
    @closed.make_true
    @server_socket.close rescue nil if @server_socket

    return unless @client_threads
    @client_threads.each do |thread|
      client = thread[:client]
      client.close rescue nil if client
    end
  end

  def log_warn(msg, e, backtrace: @logger.debug?, **details)
    details = details.merge message: e.message, exception: e.class
    details[:backtrace] = e.backtrace if backtrace
    @logger.warn(msg, details)
  end

  def log_error(msg, e, backtrace: @logger.info?, **details)
    details = details.merge message: e.message, exception: e.class
    details[:backtrace] = e.backtrace if backtrace
    @logger.error(msg, details)
  end

  private

  def connect
    begin
      client_socket = TCPSocket.new(@host, @port)
      if @ssl_enable
        client_socket = OpenSSL::SSL::SSLSocket.new(client_socket, @ssl_context)
        begin
          client_socket.connect
        rescue OpenSSL::SSL::SSLError => ssle
          log_error 'connect ssl failure:', ssle, backtrace: false
          # NOTE(mrichar1): Hack to prevent hammering peer
          sleep(5)
          raise
        end
      end
      client_socket.extend(::LogStash::Util::SocketPeer)
      @logger.debug("opened connection", :client => client_socket.peer)
      return client_socket
    rescue => e
      log_error 'failed to connect:', e
      sleep @reconnect_interval
      retry
    end
  end # def connect

  def server?
    @mode == "server"
  end # def server?

  def pipeline_id
    execution_context.pipeline_id || 'main'
  end

end # class LogStash::Outputs::Tcp

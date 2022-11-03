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

  ##
  # @param socket [Socket]
  # @param logger_context [#log_warn&#log_error]
  class Client
    def initialize(socket, logger_context)
      @socket = socket
      @logger_context = logger_context
      @queue  = Queue.new
    end

    def run
      loop do
        begin
          @socket.write(@queue.pop)
        rescue => e
          @logger_context.log_warn("tcp output exception: socket write failed", e, :socket => @socket&.to_s)
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
      @logger_context.log_warn 'socket close failed:', e, socket: @socket&.to_s
    end
  end # class Client

  private
  def setup_ssl
    require "openssl"

    @ssl_context = OpenSSL::SSL::SSLContext.new
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
  end # def setup_ssl

  public
  def register
    require "socket"
    require "stud/try"
    if @ssl_enable
      setup_ssl
    end # @ssl_enable
    @closed = Concurrent::AtomicBoolean.new(false)
    @thread_no = Concurrent::AtomicFixnum.new(0)

    if server?
      @logger.info("Starting tcp output listener", :address => "#{@host}:#{@port}")
      begin
        @server_socket = TCPServer.new(@host, @port)
      rescue Errno::EADDRINUSE
        @logger.error("Could not start TCP server: Address in use",
                      :host => @host, :port => @port)
        raise
      end
      if @ssl_enable
        @server_socket = OpenSSL::SSL::SSLServer.new(@server_socket, @ssl_context)
      end # @ssl_enable
      @client_threads = []

      @accept_thread = Thread.new(@server_socket) do |server_socket|
        LogStash::Util.set_thread_name("[#{pipeline_id}]|output|tcp|server_accept")
        loop do
          break if @closed.value
          Thread.start(server_socket.accept) do |client_socket|
            # monkeypatch a 'peer' method onto the socket.
            client_socket.extend(::LogStash::Util::SocketPeer)
            @logger.debug("Accepted connection", :client => client_socket.peer,
                          :server => "#{@host}:#{@port}")
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
    else
      client_socket = nil
      peer_info = nil
      @codec.on_event do |event, payload|
        begin
          # not threadsafe; this is why we require `concurrency: single`
          unless client_socket
            client_socket = connect
            peer_info = client_socket.peer
          end

          writable_io = nil
          while writable_io.nil? || writable_io.any? == false
            readable_io, writable_io, _ = IO.select([client_socket],[client_socket])

            # don't expect any reads, but a readable socket might
            # mean the remote end closed, so read it and throw it away.
            # we'll get an EOFError if it happens.
            readable_io.each { |readable| readable.sysread(16384) }
          end

          # Now send the payload
          @logger.trace("transmitting #{payload.bytesize} bytes", socket: peer_info) if @logger.trace? && payload && !payload.empty?
          while payload && payload.bytesize > 0
            written_bytes_size = client_socket.syswrite(payload)
            payload = payload.byteslice(written_bytes_size..-1)
            @logger.trace(">transmitted #{written_bytes_size} bytes; #{payload.bytesize} bytes remain", socket: peer_info) if @logger.trace?
            sleep 0.1 unless payload.empty?
          end
        rescue => e
          log_warn "client socket failed:", e, host: @host, port: @port, socket: peer_info
          client_socket.close rescue nil
          client_socket = nil
          sleep @reconnect_interval
          retry
        end
      end
    end
  end # def register

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
      @logger.debug("Opened connection", :client => "#{client_socket.peer}")
      return client_socket
    rescue StandardError => e
      log_error 'failed to connect:', e
      sleep @reconnect_interval
      retry
    end
  end # def connect

  private
  def server?
    @mode == "server"
  end # def server?

  public
  def receive(event)
    @codec.encode(event)
  end # def receive

  def pipeline_id
    execution_context.pipeline_id || 'main'
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
end # class LogStash::Outputs::Tcp

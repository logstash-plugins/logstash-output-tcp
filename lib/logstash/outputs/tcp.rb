# encoding: utf-8
require "logstash/outputs/base"
require "logstash/namespace"
require "thread"
require "logstash/util/socket_peer"
require "logstash/plugin_mixins/normalize_config_support"

# Write events over a TCP socket.
#
# Each event json is separated by a newline.
#
# Can either accept connections from clients or connect to a server,
# depending on `mode`.
class LogStash::Outputs::Tcp < LogStash::Outputs::Base

  include LogStash::PluginMixins::NormalizeConfigSupport

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
  config :ssl_enable, :validate => :boolean, :default => false, :deprecated => "Use 'ssl_enabled' instead."

  # Enable SSL (must be set for other `ssl_` options to take effect).
  config :ssl_enabled, :validate => :boolean, :default => false

  # Controls the server’s behavior in regard to requesting a certificate from client connections.
  # `none`: No client authentication
  # `optional`: Requests a client certificate but the client is not required to present one.
  # `required`: Forces a client to present a certificate.
  # This option needs to be used with `ssl_certificate_authorities` and a defined list of CAs.
  config :ssl_client_authentication, :validate => %w[none optional required], :default => 'none'

  # Verify the identity of the other end of the SSL connection against the CA.
  # For input, sets the field `sslsubject` to that of the client certificate.
  config :ssl_verify, :validate => :boolean, :default => false, :deprecated => "Use 'ssl_client_authentication' when `mode` is 'server' or 'ssl_verification_mode' when mode is `client`"

  # Options to verify the server's certificate.
  # "full": validates that the provided certificate has an issue date that’s within the not_before and not_after dates;
  # chains to a trusted Certificate Authority (CA); has a hostname or IP address that matches the names within the certificate.
  # "certificate": Validates the provided certificate and verifies that it’s signed by a trusted authority (CA), but does’t check the certificate hostname.
  # "none": performs no certificate validation. Disabling this severely compromises security (https://www.cs.utexas.edu/~shmat/shmat_ccs12.pdf)
  config :ssl_verification_mode, :validate => %w[full none], :default => 'full'

  # The SSL CA certificate, chainfile or CA path. The system CA path is automatically included.
  config :ssl_cacert, :validate => :path, :deprecated => "Use 'ssl_certificate_authorities' instead."

  # Validate client certificate or certificate chain against these authorities. You can define multiple files.
  # All the certificates will be read and added to the trust store.
  config :ssl_certificate_authorities, :validate => :path, :list => true

  # SSL certificate path
  config :ssl_cert, :validate => :path, :deprecated => "Use 'ssl_certificate' instead."

  # SSL certificate path
  config :ssl_certificate, :validate => :path

  # SSL key path
  config :ssl_key, :validate => :path

  # SSL key passphrase
  config :ssl_key_passphrase, :validate => :password, :default => nil

  # NOTE: the default setting [] uses SSL engine defaults
  config :ssl_supported_protocols, :validate => ['TLSv1.1', 'TLSv1.2', 'TLSv1.3'], :default => [], :list => true

  # The list of ciphers suite to use
  config :ssl_cipher_suites, :validate => :string, :list => true

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
    if @ssl_certificate
      @ssl_context.cert = OpenSSL::X509::Certificate.new(File.read(@ssl_certificate))
      if @ssl_key
        # if we have an encrypted key and a password is not provided (nil) than OpenSSL::PKey::RSA
        # prompts the user to enter a password interactively - we do not want to do that,
        # for plain-text keys the default '' password argument gets simply ignored
        @ssl_context.key = OpenSSL::PKey::RSA.new(File.read(@ssl_key), @ssl_key_passphrase.value || '')
      end
    end

    @ssl_context.cert_store = load_cert_store
    if server?
      if @ssl_client_authentication == 'none'
        @ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE
      else
        @ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER
        @ssl_context.verify_mode |= OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT if @ssl_client_authentication == 'required'
      end
    else
      if @ssl_verification_mode == 'none'
        @ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE
      else
        @ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER|OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
      end
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

    @ssl_context.ciphers = @ssl_cipher_suites if @ssl_cipher_suites&.any?

    @ssl_context
  end
  private :setup_ssl

  # @note to be able to hook up into #ssl_context from tests
  def new_ssl_context
    OpenSSL::SSL::SSLContext.new
  end
  private :new_ssl_context

  def load_cert_store
    cert_store = OpenSSL::X509::Store.new
    cert_store.set_default_paths
    @ssl_certificate_authorities&.each do |cert|
      cert_store.add_file(cert)
    end
    cert_store
  end
  private :load_cert_store

  def initialize(*args)
    super(*args)
    setup_ssl_params!
  end

  # @overload Base#register
  def register
    require "socket"
    require "stud/try"

    validate_ssl_config!

    @closed = Concurrent::AtomicBoolean.new(false)
    @thread_no = Concurrent::AtomicFixnum.new(0)
    setup_ssl if @ssl_enabled

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
    if @ssl_enabled
      @server_socket = OpenSSL::SSL::SSLServer.new(@server_socket, @ssl_context)
    end # @ssl_enabled
    @client_threads = Concurrent::Array.new

    @accept_thread = Thread.new(@server_socket) do |server_socket|
      LogStash::Util.set_thread_name("[#{pipeline_id}]|output|tcp|server_accept")
      loop do
        break if @closed.value
        # OpenSSL::SSL::SSLServer does not support the #accept_nonblock method.
        # When SSL is enabled, it needs to use the blocking counterpart and ignore
        # SSLError errors, as they may be client's issues such as missing client's
        # certificates, ciphers, etc. If it's not rescued here, it would close the
        # TCP server and exit the plugin.
        # On the other hand, IOError should normally happen when the pipeline configuration
        # is reloaded, as the stream gets closed in the thread
        if @ssl_enabled
          begin
            client_socket = server_socket.accept
          rescue OpenSSL::SSL::SSLError => e
            log_warn("SSL Error", e)
            retry unless @closed.value
          rescue IOError => e
            log_warn("IO Error", e)
            retry unless @closed.value
          end
        else
          client_socket = server_socket.accept_nonblock exception: false
          if client_socket == :wait_readable
            IO.select [ server_socket ]
            next
          end
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
        while payload && payload.bytesize > 0
          begin
            written_bytes_size = client_socket.write_nonblock(payload)
            payload = payload.byteslice(written_bytes_size..-1)
          rescue IO::WaitReadable
            IO.select([client_socket])
            retry
          rescue IO::WaitWritable
            IO.select(nil, [client_socket])
            retry
          end
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
      if @ssl_enabled
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

  def validate_ssl_config!
    unless @ssl_enabled
      ignored_ssl_settings = original_params.select { |k| k != 'ssl_enabled' && k != 'ssl_enable' && k.start_with?('ssl_') }
      @logger.warn("Configured SSL settings are not used when `#{provided_ssl_enabled_config_name}` is set to `false`: #{ignored_ssl_settings.keys}") if ignored_ssl_settings.any?
      return
    end

    if @ssl_certificate && !@ssl_key
      raise LogStash::ConfigurationError, "Using an `ssl_certificate` requires an `ssl_key`"
    elsif @ssl_key && !@ssl_certificate
      raise LogStash::ConfigurationError, 'An `ssl_certificate` is required when using an `ssl_key`'
    end

    if server?
      validate_server_ssl_config!
    else
      validate_client_ssl_config!
    end
  end

  def validate_client_ssl_config!
    if original_params.include?('ssl_client_authentication')
      raise LogStash::ConfigurationError, "`ssl_client_authentication` must not be configured when mode is `client`, use `ssl_verification_mode` instead."
    end
  end

  def validate_server_ssl_config!
    if original_params.include?('ssl_verification_mode')
      raise LogStash::ConfigurationError, "`ssl_verification_mode` must not be configured when mode is `server`, use `ssl_client_authentication` instead."
    end

    if @ssl_certificate.nil?
      raise LogStash::ConfigurationError, "An `ssl_certificate` is required when `#{provided_ssl_enabled_config_name}` => true"
    end

    if requires_ssl_certificate_authorities? && (@ssl_certificate_authorities.nil? || @ssl_certificate_authorities.empty?)
      raise LogStash::ConfigurationError, "An `ssl_certificate_authorities` is required when `ssl_client_authentication` => `#{@ssl_client_authentication}`"
    end
  end

  def requires_ssl_certificate_authorities?
    original_params.include?('ssl_client_authentication') && @ssl_client_authentication != 'none'
  end

  def provided_ssl_enabled_config_name
    original_params.include?('ssl_enable') ? 'ssl_enable' : 'ssl_enabled'
  end

  def setup_ssl_params!
    @ssl_enabled = normalize_config(:ssl_enabled) do |normalizer|
      normalizer.with_deprecated_alias(:ssl_enable)
    end

    @ssl_certificate = normalize_config(:ssl_certificate) do |normalizer|
      normalizer.with_deprecated_alias(:ssl_cert)
    end

    if server?
      @ssl_client_authentication = normalize_config(:ssl_client_authentication) do |normalizer|
        normalizer.with_deprecated_mapping(:ssl_verify) do |ssl_verify|
          ssl_verify == true ? 'required' : 'none'
        end
      end
    else
      @ssl_verification_mode = normalize_config(:ssl_verification_mode) do |normalize|
        normalize.with_deprecated_mapping(:ssl_verify) do |ssl_verify|
          ssl_verify == true ? 'full' : 'none'
        end
      end

      # Keep backwards compatibility with the default :ssl_verify value (false)
      if !original_params.include?('ssl_verify') && !original_params.include?('ssl_verification_mode')
        @ssl_verification_mode = 'none'
      end
    end

    @ssl_certificate_authorities = normalize_config(:ssl_certificate_authorities) do |normalize|
      normalize.with_deprecated_mapping(:ssl_cacert) do |ssl_cacert|
        if File.directory?(ssl_cacert)
          Dir.children(ssl_cacert)
          .map{ |f| File.join(ssl_cacert, f) }
          .reject{ |f| File.directory?(f) || File.basename(f).start_with?('.') }
        else
          [ssl_cacert]
        end
      end
    end
  end

  def server?
    @mode == "server"
  end # def server?

  def pipeline_id
    execution_context.pipeline_id || 'main'
  end

end # class LogStash::Outputs::Tcp

require "logstash/devutils/rspec/spec_helper"
require "socket"
require "stud/task"

describe "TCP Output" do
  
  let(:port) { rand(6233) }
  subject { LogStash::Plugin.lookup("output", "tcp").new({ "host" => "localhost", "port" => port }) }
  let(:event) { LogStash::Event.new({'message' => '183.60.215.50 - - [11/Sep/2014:22:00:00 +0000] "GET /scripts/netcat-webserver HTTP/1.1" 200 182 "-" "Mozilla/5.0 (compatible; EasouSpider; +http://www.easou.com/search/spider.html)"', '@timestamp' => LogStash::Timestamp.at(0) }) }
  let(:req_buffer) { Array.new }
  let(:input) { LogStash::Plugin.lookup("input", "tcp").new({ "host" => "localhost", "port" => port }) }
  let(:queue) { Array.new }

  def thread_it
    Thread.new do
      begin
        server = TCPServer.open(2000)
        loop do
          c = server.accept
          line = c.gets
          print line  
          end
        end
      end
    end
  end  

  # it "should #register without errors" do
  #   expect { subject.register }.to_not raise_error
  # end

  # TCP server
  it "should successfully send to a listening TCP server" do
    subject.register
    
    t = thread_it
    t.run

    subject.receive(event)
    sleep 5
  end
end  
#!/usr/bin/env ruby

require 'socket'
require 'eventmachine'
require 'logger'

require_relative 'TapUtils'

LOGFILE = "GuardDETap.log"
LOGLEVEL = Logger::DEBUG

module MTLogger
  MTLogger = Logger.new(LOGFILE)
  MTLogger.level = LOGLEVEL
end

class GuardDETapGuardClient < EventMachine::Connection
  include MTLogger
  attr_accessor :tap_ip
  def post_init
    MTLogger.info("Starting GuardDETap Guardium STAP Client")
    MTLogger.info('Sending handshake');
    tap_name = 'guardDETapCollector'
    tap_version = 'guardDETap_v0.1'

    EventMachine.add_timer(5) {
      handshake = GuardiumHandshakeMessage.new(@tap_ip, tap_name, @tap_ip, tap_version)
      send_data(handshake.getWrappedGuardiumMessage)
    }

    EventMachine.add_periodic_timer(30) {
      MTLogger.debug('sending ping')
      ping = GuardiumPingMessage.new(@tap_ip, tap_name, @tap_ip)
      send_data(ping.getWrappedGuardiumMessage)
    }

  end

  def receive_data(data)
  end
end

class GuardDESession
  attr_accessor :clientIP, :app_name, :uinfo, :clientPort, :serverPort, :currentID
  def initialize(clientIP, app_name, uinfo, clientPort, serverPort)
    @clientIP = clientIP
    @app_name = app_name
    @uinfo = uinfo
    @clientPort = clientPort
    @serverPort = serverPort
    @currentID = 1
  end

end

class GuardDETapServer < EventMachine::Connection
  include MTLogger

  attr_accessor :guardClient, :currentLine, :currentSession, :deSessionList
  
  def initialize
    super()
    @currentLine = ""
    MTLogger.info("Starting GuardDETap Server")
  end

  def receive_data(data)

    if data.to_s =~ /\n/ then
      processNewLine(data)
    else
      @currentLine = @currentLine + data
    end

  end

  def processNewLine(data)
    splitLines = data.split("\n")

    splitLines.each do |line|
      if(line != nil)
        parseLine(@currentLine)
        @currentLine = line
      else
        @currentLine = ""
      end
    end

    if(@currentLine.length > 0)
      parseLine(@currentLine)
      @currentLine = ""
    end
  end

  def parseLine(line)
    regex = /(?<priority>\<[0-9]{1,3}\>)(?<version>[0-9]) (?<date>[0-9]{4}-[0-9]{1,2}-[0-9]{1,2})T(?<time>[0-9]{2}:[0-9]{2}:[0-9]{2}\.?[0-9]{0,6})Z (?<hostname>(\w+\.)+\w+) (?<app-name>vee-fs) (?<prod-id>[0-9]+) (?<message_id>\S+) \[(?<enterprise_number>\S+@\S+) (?<params>(\S+=".+?"[ \]])+)/
    matches = regex.match(line)

    if matches then

      regex2 = /(\w+)="(.+?)"/
      matches2 = matches["params"].scan(regex2)

      params = Hash.new
      matches2.each do |n|
        params[n[0]] = n[1]
      end
      processMessage(params)
    else
    end

  end

  def processMessage(params)
    client_port, client_ip = Socket.unpack_sockaddr_in(get_peername)

    # What I'm doing here is defining what to call a Guard DE Session. Sessions don't really happen because there's
    # no connection being made here really. So instead we take some other parameters and spoof a client port number
    # to create something that is useful as a session entry. Guardium should take care of sessions ending with session
    # inference
    if params.has_key?("sproc") && params.has_key?("uinfo")
      key = client_ip + ":" + params["sproc"] + ":" + params["uinfo"].split(/,/)[0]
      if @deSessionList .has_key?(key)
        @currentSession = @deSessionList [key]
      else
        @currentSession = GuardDESession.new(client_ip, params["sproc"], params["uinfo"], @deSessionList.length + 100, 514)
        @deSessionList[key] = @currentSession

        MTLogger.debug('Sending Session Start Message')
        sessionStart = GuardiumNewSessionMessage.new(100, @currentSession.clientIP, @currentSession.clientPort, @currentSession.clientIP, @currentSession.serverPort, @currentSession.uinfo.split(/,/)[0], @currentSession.app_name)
        @guardClient.send_data(sessionStart.getWrappedGuardiumMessage)
      end
      
      MTLogger.debug('Sending Client Request Message')
      @currentSession.currentID = @currentSession.currentID + 1
      clientRequest = GuardiumSingleSentenceClientRequestMessage.new(@currentSession.currentID, 
                  100, 
                  @currentSession.clientIP,
                  @currentSession.clientPort.to_i, 
                  @currentSession.clientIP,
                  @currentSession.serverPort.to_i, 
                  params["act"], 
                  params["gp"] + params["filePath"], 
                  params.inspect, 
                  @currentSession.uinfo.split(/,/, 2)[1])
      @guardClient.send_data(clientRequest.getWrappedGuardiumMessage)
    end
  end

end

puts "\n\nGuardDETap - Open Source Type 1 Guardium STAP for Guardium DE Syslog Messages\n\n"

unless(ARGV.length >= 2)
  puts "usage: ruby GuardDETap.rb <listen_ip> <collector_ip>\n"
  puts " where: "
  puts "  <listen_ip> is the IP address of the network interface you want to listen on"
  puts "  <collector_ip> is the IP address of the Guardium Collector to report to\n\n"
  puts "example: ruby GuardDETapServer.rb 10.10.9.28 10.10.9.248"
  exit
end

listen_ip = ARGV[0]
collector_ip = ARGV[1]
deSessionList = Hash.new

EventMachine::run do
  EventMachine.connect(collector_ip, 16016, GuardDETapGuardClient) do |clientconn|
    clientconn.tap_ip = listen_ip
    EventMachine.start_server(listen_ip, 514, GuardDETapServer) do |serverconn|
      serverconn.guardClient = clientconn
      serverconn.deSessionList = deSessionList
    end
    puts 'Listening...'
  end
end


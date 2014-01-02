#!/usr/bin/env ruby

require_relative 'Datasource.pb'
require 'bindata'
require 'ipaddr'
include Com::Guardium::Proto::Datasource

class WrappedGuardiumMessage < BinData::Record
  endian  :big
  
  string  :msgType
  uint8   :pad
  uint16  :len
  uint32  :mark
  uint32  :unixTime
  uint32  :protocolVersion
  uint32  :vendor
  uint320 :ident
  string  :protobufMessage
  
end

class GuardiumMessage
  
    # Yes, Optim. This seemed to be the data source type that let you specify a custom DB Type most reliably.
    # For Type 1 STAPs, you need to specify one of the supported language types and it's a required field.
    # If you choose Optim, you get to choose your DB Type later. If you choose another language type, you might
    # get stuck having the database showing as DB2 or Oracle or some other DBMS
    LANG_TYPE = Com::Guardium::Proto::Datasource::ApplicationData::LanguageType::OPTIM_AUDIT
    DATA_TYPE = Com::Guardium::Proto::Datasource::ApplicationData::DataType::CONSTRUCT
    
    attr_accessor :protobufMessage
  
    def getCurrentGuardiumTimestamp
      return Com::Guardium::Proto::Datasource::Timestamp.new(:unix_time => Time.now.to_i)
    end
    
    def getWrappedGuardiumMessage
      return WrappedGuardiumMessage.new(:msgType => "G",
        :pad => 0,
        :len => @protobufMessage.serialize_to_string.length,
        :mark => 0x01000000,
        :unixTime => Time.now.to_i,
        :protocolVersion => 0x00000007,
        :vendor => 0,
        :ident => 0,
        :protobufMessage => @protobufMessage.serialize_to_string
      ).to_binary_s

    end
    
    def getIPNumFromString(ipString)
      octets = ipString.split("\.")
      reverseIP = octets[3] + "." + octets[2] + "." + octets[1] + "." + octets[0]
      return IPAddr.new(reverseIP).to_i
    end

end

class GuardiumHandshakeMessage < GuardiumMessage
    attr_accessor :clientIdent, :clientMaster, :masterIP, :product
    
    def initialize(clientIdent, clientMaster, masterIP, product)
      @clientIdent = clientIdent
      @clientMaster = clientMaster
      @masterIP = getIPNumFromString(masterIP)
      @product = product
      
      @protobufMessage = getHandshakeMessage
    end
  
    def getGuardiumHandshake
      return Com::Guardium::Proto::Datasource::Handshake.
          new(:timestamp => getCurrentGuardiumTimestamp(),
              :client_identifier => @clientIdent,
              :current_master => @clientMaster,
              :current_master_ip => @masterIP,
              :product => @product,
              :transient => false)
    end
    
    def getHandshakeMessage
      return Com::Guardium::Proto::Datasource::GuardDsMessage.
          new(:type => Com::Guardium::Proto::Datasource::GuardDsMessage::Type::HANDSHAKE,
              :handshake => getGuardiumHandshake())
    end
end

class GuardiumPingMessage < GuardiumMessage
    attr_accessor :clientIdent, :clientMaster, :masterIP
    
    def initialize(clientIdent, clientMaster, masterIP)
      @clientIdent = clientIdent
      @clientMaster = clientMaster
      @masterIP = getIPNumFromString(masterIP)
      
      @protobufMessage = getPingMessage
    end
  
    def getGuardiumPing
      return Com::Guardium::Proto::Datasource::Handshake.
          new(:timestamp => getCurrentGuardiumTimestamp(),
              :client_identifier => @clientIdent,
              :current_master => @clientMaster,
              :current_master_ip => @masterIP)
    end
    
    def getPingMessage
      return Com::Guardium::Proto::Datasource::GuardDsMessage.
          new(:type => Com::Guardium::Proto::Datasource::GuardDsMessage::Type::PING,
              :handshake => getGuardiumPing())
    end
end

class GuardiumNewSessionMessage < GuardiumMessage
  attr_accessor :sessionID, :clientIP, :clientPort, :serverIP, :serverPort, :dbUser, :sourceApp
  
  def initialize(sessionID, clientIP, clientPort, serverIP, serverPort, dbUser, sourceApp)
    @sessionID = sessionID
    @clientIP = getIPNumFromString(clientIP)
    @clientPort = clientPort
    @serverIP = getIPNumFromString(serverIP)
    @serverPort = serverPort
    @dbUser = dbUser
    @sourceApp = sourceApp
    
    @protobufMessage = getGuardiumNewSessionMessage
  end
  
  #TODO This is very mongoDB oriented right now isn't it (re: string literals)? Probably should make it generic
  def getGuardiumNewSessionMessage()
    
    languageType = LANG_TYPE
    dataType = DATA_TYPE
    dbUser = @dbUser
    sourceApp = @sourceApp
    
    puts('user in utils:' + @dbUser)
        
    accessor = Com::Guardium::Proto::Datasource::Accessor.
        new(:language => languageType,
            :type => dataType,
            :server_type => 'Guard DE',
            :comm_protocol => 'File Access',
            :db_protocol => 'File Access',
            :db_user => @dbUser,
            :source_program => @sourceApp,
            :service_name => 'OS'
            )
            
    locator = Com::Guardium::Proto::Datasource::SessionLocator.
        new(:client_ip => @clientIP,
            :client_port => @clientPort,
            :server_ip => @serverIP,
            :server_port => @serverPort )
            
    timestamp = getCurrentGuardiumTimestamp()
    
    sessionStart = Com::Guardium::Proto::Datasource::SessionStart.
        new(:session_id => @session_id,
            :accessor => accessor,
            :session_locator => locator,
            :timestamp => timestamp
        )
        
    dsMessage = Com::Guardium::Proto::Datasource::GuardDsMessage.
          new(:type => Com::Guardium::Proto::Datasource::GuardDsMessage::Type::SESSION_START,
              :session_start => sessionStart)
        
    return dsMessage
  end
  
end


class GuardiumSingleSentenceClientRequestMessage < GuardiumMessage
  attr_accessor :sessionID, :clientIP, :clientPort, :serverIP, :serverPort,
                :verb, :object, :fullSQL
                
  def initialize(requestID, sessionID, clientIP, clientPort, serverIP, serverPort, verb, object, fullSQL, appUser)
    @requestID = requestID
    @sessionID = sessionID
    @clientIP = getIPNumFromString(clientIP)
    @clientPort = clientPort
    @serverIP = getIPNumFromString(serverIP)
    @serverPort = serverPort
    @verb = verb
    @object = object
    @fullSQL = fullSQL
    @appUser = appUser
    
    @protobufMessage = getClientRequestMessage
  end
  
  def getClientRequestMessage
    
    languageType = LANG_TYPE
    dataType = DATA_TYPE
     
    dbObject = Com::Guardium::Proto::Datasource::GDMObject.
        new(:name => @object)
            
    sentence = Com::Guardium::Proto::Datasource::GDMSentence.
        new(:verb => @verb)
    sentence.objects << dbObject
    
    construct = Com::Guardium::Proto::Datasource::GDMConstruct.
        new(:full_sql => @fullSQL)
    construct.sentences << sentence
        
    locator = Com::Guardium::Proto::Datasource::SessionLocator.
        new(:client_ip => @clientIP,
            :client_port => @clientPort,
            :server_ip => @serverIP,
            :server_port => @serverPort )
    
    timestamp = getCurrentGuardiumTimestamp()
      
    applicationData = Com::Guardium::Proto::Datasource::ApplicationData.
        new(:language => languageType,
            :type => dataType,
            :construct => construct,
            :timestamp => timestamp,
            :session_locator => locator,
            :application_user => @appUser
        )      
     
    clientRequest = Com::Guardium::Proto::Datasource::ClientRequest.
        new(:session_id => @sessionID,
            :request_id => @requestID,
            :data => applicationData
        )
    
    guardDSMessage = Com::Guardium::Proto::Datasource::GuardDsMessage.
        new(:type => Com::Guardium::Proto::Datasource::GuardDsMessage::Type::CLIENT_REQUEST,
            :client_request => clientRequest
        )
            
    return guardDSMessage
  end
  
end


package com.lackadaisical.tools

import akka.actor.{Actor, ActorRef, ActorSystem, Props}
import akka.io.{IO, Tcp}
import akka.util.ByteString
import java.net.InetSocketAddress
import scala.concurrent.duration._
import scala.util.Random
import java.security.{MessageDigest, SecureRandom}
import javax.crypto.{Cipher, KeyGenerator, SecretKey}
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}

/**
 * Privacy-focused proxy server with traffic obfuscation
 * Part of Lackadaisical Anonymity Toolkit
 */
object PrivacyProxy {
  
  case class ProxyConfig(
    localPort: Int,
    upstreamHost: String,
    upstreamPort: Int,
    obfuscate: Boolean = true,
    encryptTraffic: Boolean = true,
    addLatency: Boolean = true,
    rotateUpstream: Boolean = false
  )
  
  case class ConnectionStats(
    bytesIn: Long = 0,
    bytesOut: Long = 0,
    connections: Int = 0,
    startTime: Long = System.currentTimeMillis()
  )
  
  def main(args: Array[String]): Unit = {
    if (args.length < 3) {
      println("Usage: PrivacyProxy <localPort> <upstreamHost> <upstreamPort> [options]")
      println("Options:")
      println("  --no-obfuscate    Disable traffic obfuscation")
      println("  --no-encrypt      Disable encryption")
      println("  --no-latency      Disable random latency")
      println("  --rotate          Rotate upstream servers")
      System.exit(1)
    }
    
    val config = ProxyConfig(
      localPort = args(0).toInt,
      upstreamHost = args(1),
      upstreamPort = args(2).toInt,
      obfuscate = !args.contains("--no-obfuscate"),
      encryptTraffic = !args.contains("--no-encrypt"),
      addLatency = !args.contains("--no-latency"),
      rotateUpstream = args.contains("--rotate")
    )
    
    println(s"Lackadaisical Privacy Proxy")
    println(s"==========================")
    println(s"Listening on: 0.0.0.0:${config.localPort}")
    println(s"Upstream: ${config.upstreamHost}:${config.upstreamPort}")
    println(s"Obfuscation: ${config.obfuscate}")
    println(s"Encryption: ${config.encryptTraffic}")
    println(s"Latency: ${config.addLatency}")
    
    val system = ActorSystem("PrivacyProxySystem")
    val proxyServer = system.actorOf(Props(new ProxyServer(config)), "proxy-server")
    
    // Add shutdown hook
    sys.addShutdownHook {
      println("\nShutting down proxy...")
      system.terminate()
    }
  }
}

class ProxyServer(config: PrivacyProxy.ProxyConfig) extends Actor {
  import Tcp._
  import context.system
  
  var stats = PrivacyProxy.ConnectionStats()
  val random = new SecureRandom()
  
  // Encryption setup
  val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
  val keyGen = KeyGenerator.getInstance("AES")
  keyGen.init(256)
  val secretKey = keyGen.generateKey()
  
  override def preStart(): Unit = {
    // Bind to local port
    IO(Tcp) ! Bind(self, new InetSocketAddress("0.0.0.0", config.localPort))
    
    // Start statistics reporter
    context.system.scheduler.scheduleWithFixedDelay(
      30.seconds, 30.seconds, self, ReportStats
    )(context.dispatcher)
  }
  
  def receive: Receive = {
    case Bound(localAddress) =>
      println(s"Proxy bound to $localAddress")
      
    case CommandFailed(_: Bind) =>
      println(s"Failed to bind to port ${config.localPort}")
      context.system.terminate()
      
    case Connected(remote, local) =>
      stats = stats.copy(connections = stats.connections + 1)
      
      // Create connection handler
      val handler = context.actorOf(
        Props(new ConnectionHandler(config, sender(), remote, secretKey))
      )
      sender() ! Register(handler)
      
    case ReportStats =>
      val uptime = (System.currentTimeMillis() - stats.startTime) / 1000
      println(f"\nProxy Statistics:")
      println(f"  Connections: ${stats.connections}")
      println(f"  Data In: ${humanReadableBytes(stats.bytesIn)}")
      println(f"  Data Out: ${humanReadableBytes(stats.bytesOut)}")
      println(f"  Uptime: ${uptime}s")
  }
  
  case object ReportStats
  
  def humanReadableBytes(bytes: Long): String = {
    val units = Array("B", "KB", "MB", "GB", "TB")
    var value = bytes.toDouble
    var unitIndex = 0
    
    while (value >= 1024 && unitIndex < units.length - 1) {
      value /= 1024
      unitIndex += 1
    }
    
    f"$value%.2f ${units(unitIndex)}"
  }
}

class ConnectionHandler(
  config: PrivacyProxy.ProxyConfig,
  client: ActorRef,
  clientAddress: InetSocketAddress,
  secretKey: SecretKey
) extends Actor {
  
  import Tcp._
  import context.system
  
  var upstream: Option[ActorRef] = None
  val random = new SecureRandom()
  
  // Traffic obfuscation patterns
  val httpHeaders = List(
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language: en-US,en;q=0.5",
    "Accept-Encoding: gzip, deflate, br",
    "DNT: 1",
    "Connection: keep-alive",
    "Upgrade-Insecure-Requests: 1"
  )
  
  override def preStart(): Unit = {
    // Connect to upstream
    val upstreamAddress = new InetSocketAddress(config.upstreamHost, config.upstreamPort)
    IO(Tcp) ! Connect(upstreamAddress)
  }
  
  def receive: Receive = {
    case CommandFailed(_: Connect) =>
      println(s"Failed to connect to upstream ${config.upstreamHost}:${config.upstreamPort}")
      client ! Close
      context.stop(self)
      
    case Connected(remote, local) =>
      upstream = Some(sender())
      sender() ! Register(self)
      
    case Received(data) =>
      // Add random latency
      if (config.addLatency) {
        Thread.sleep(random.nextInt(50) + 10)
      }
      
      // Process data
      val processedData = if (sender() == client) {
        // Client -> Upstream
        processClientData(data)
      } else {
        // Upstream -> Client
        processUpstreamData(data)
      }
      
      // Forward data
      val target = if (sender() == client) upstream.get else client
      target ! Write(processedData)
      
    case PeerClosed =>
      context.stop(self)
      
    case _: ConnectionClosed =>
      context.stop(self)
  }
  
  def processClientData(data: ByteString): ByteString = {
    var processed = data
    
    // Traffic obfuscation
    if (config.obfuscate) {
      processed = obfuscateTraffic(processed)
    }
    
    // Encryption
    if (config.encryptTraffic) {
      processed = encryptData(processed)
    }
    
    processed
  }
  
  def processUpstreamData(data: ByteString): ByteString = {
    var processed = data
    
    // Decryption
    if (config.encryptTraffic) {
      processed = decryptData(processed)
    }
    
    // Remove obfuscation
    if (config.obfuscate) {
      processed = deobfuscateTraffic(processed)
    }
    
    processed
  }
  
  def obfuscateTraffic(data: ByteString): ByteString = {
    // Add fake HTTP headers to make traffic look like HTTPS
    if (data.length > 5 && !data.utf8String.startsWith("GET") && !data.utf8String.startsWith("POST")) {
      val fakeHeader = s"GET /assets/${randomString(20)}.js HTTP/1.1\r\n" +
        httpHeaders.take(random.nextInt(httpHeaders.length - 2) + 2).mkString("\r\n") +
        s"\r\nContent-Length: ${data.length}\r\n\r\n"
      
      ByteString(fakeHeader) ++ data
    } else {
      data
    }
  }
  
  def deobfuscateTraffic(data: ByteString): ByteString = {
    // Remove fake headers if present
    val str = data.utf8String
    if (str.contains("\r\n\r\n")) {
      val headerEnd = str.indexOf("\r\n\r\n") + 4
      data.drop(headerEnd)
    } else {
      data
    }
  }
  
  def encryptData(data: ByteString): ByteString = {
    try {
      val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
      val iv = new Array[Byte](16)
      random.nextBytes(iv)
      val ivSpec = new IvParameterSpec(iv)
      
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
      val encrypted = cipher.doFinal(data.toArray)
      
      // Prepend IV to encrypted data
      ByteString(iv ++ encrypted)
    } catch {
      case e: Exception =>
        println(s"Encryption error: $e")
        data
    }
  }
  
  def decryptData(data: ByteString): ByteString = {
    try {
      if (data.length < 16) return data
      
      val iv = data.take(16).toArray
      val encrypted = data.drop(16).toArray
      
      val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
      val ivSpec = new IvParameterSpec(iv)
      
      cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
      val decrypted = cipher.doFinal(encrypted)
      
      ByteString(decrypted)
    } catch {
      case e: Exception =>
        println(s"Decryption error: $e")
        data
    }
  }
  
  def randomString(length: Int): String = {
    val chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    (1 to length).map(_ => chars(random.nextInt(chars.length))).mkString
  }
}

/**
 * SOCKS5 Proxy Implementation
 */
class Socks5Proxy(port: Int) extends Actor {
  import Tcp._
  
  case class Socks5Request(
    version: Byte,
    command: Byte,
    addressType: Byte,
    destinationAddress: String,
    destinationPort: Int
  )
  
  override def preStart(): Unit = {
    IO(Tcp) ! Bind(self, new InetSocketAddress("0.0.0.0", port))
  }
  
  def receive: Receive = {
    case Bound(localAddress) =>
      println(s"SOCKS5 proxy listening on $localAddress")
      
    case Connected(remote, local) =>
      val handler = context.actorOf(Props(new Socks5Handler(sender())))
      sender() ! Register(handler)
  }
}

class Socks5Handler(client: ActorRef) extends Actor {
  import Tcp._
  
  var state: String = "INIT"
  var upstream: Option[ActorRef] = None
  
  def receive: Receive = {
    case Received(data) =>
      state match {
        case "INIT" =>
          handleInit(data)
        case "REQUEST" =>
          handleRequest(data)
        case "CONNECTED" =>
          // Forward data
          upstream.foreach(_ ! Write(data))
      }
      
    case Connected(remote, local) =>
      upstream = Some(sender())
      sender() ! Register(self)
      
      // Send SOCKS5 success response
      val response = ByteString(Array[Byte](
        0x05, // Version
        0x00, // Success
        0x00, // Reserved
        0x01, // IPv4
        0, 0, 0, 0, // Bind address
        0, 0 // Bind port
      ))
      client ! Write(response)
      state = "CONNECTED"
      
    case _: ConnectionClosed =>
      context.stop(self)
  }
  
  def handleInit(data: ByteString): Unit = {
    if (data.length >= 3 && data(0) == 0x05) {
      // SOCKS5 greeting
      val response = ByteString(Array[Byte](0x05, 0x00)) // No auth required
      client ! Write(response)
      state = "REQUEST"
    }
  }
  
  def handleRequest(data: ByteString): Unit = {
    if (data.length >= 10 && data(0) == 0x05 && data(1) == 0x01) {
      // CONNECT request
      val addressType = data(3)
      
      val (host, port) = addressType match {
        case 0x01 => // IPv4
          val ip = data.slice(4, 8).map(_.toInt & 0xFF).mkString(".")
          val port = (data(8) << 8) | data(9)
          (ip, port)
          
        case 0x03 => // Domain name
          val len = data(4)
          val domain = data.slice(5, 5 + len).utf8String
          val port = (data(5 + len) << 8) | data(6 + len)
          (domain, port)
          
        case _ =>
          // Unsupported
          client ! Close
          return
      }
      
      // Connect to destination
      import context.system
      IO(Tcp) ! Connect(new InetSocketAddress(host, port & 0xFFFF))
    }
  }
}

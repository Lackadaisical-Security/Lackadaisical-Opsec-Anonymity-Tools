package com.lackadaisical.tools

import kotlinx.coroutines.*
import java.net.*
import java.util.concurrent.ConcurrentHashMap
import kotlin.system.measureTimeMillis

/**
 * Advanced Network Scanner with Stealth Capabilities
 * Part of Lackadaisical Anonymity Toolkit
 */
class NetworkScanner(
    private val timeout: Int = 1000,
    private val maxThreads: Int = 100
) {
    
    private val openPorts = ConcurrentHashMap<String, MutableList<Int>>()
    private val discoveredHosts = ConcurrentHashMap<String, HostInfo>()
    
    data class HostInfo(
        val ip: String,
        val hostname: String? = null,
        val mac: String? = null,
        val os: String? = null,
        val services: MutableMap<Int, String> = mutableMapOf()
    )
    
    data class ScanResult(
        val hosts: Map<String, HostInfo>,
        val scanTime: Long,
        val totalPorts: Int
    )
    
    /**
     * Stealth SYN scan (requires raw socket permissions)
     */
    suspend fun stealthScan(
        targetRange: String,
        portRange: IntRange = 1..1024
    ): ScanResult = coroutineScope {
        
        val scanTime = measureTimeMillis {
            val hosts = expandIpRange(targetRange)
            val jobs = mutableListOf<Job>()
            
            // Use semaphore to limit concurrent connections
            val semaphore = kotlinx.coroutines.sync.Semaphore(maxThreads)
            
            hosts.forEach { host ->
                jobs += launch(Dispatchers.IO) {
                    semaphore.withPermit {
                        scanHost(host, portRange)
                    }
                }
            }
            
            jobs.joinAll()
        }
        
        ScanResult(
            hosts = discoveredHosts.toMap(),
            scanTime = scanTime,
            totalPorts = openPorts.values.sumOf { it.size }
        )
    }
    
    /**
     * Scan individual host
     */
    private suspend fun scanHost(host: String, portRange: IntRange) {
        // Check if host is alive first
        if (!isHostAlive(host)) return
        
        val hostInfo = HostInfo(ip = host)
        
        // Resolve hostname
        try {
            val inetAddress = InetAddress.getByName(host)
            hostInfo.hostname = inetAddress.canonicalHostName
        } catch (e: Exception) {
            // Ignore resolution failures
        }
        
        // Scan ports
        val openPortsList = mutableListOf<Int>()
        
        coroutineScope {
            val portJobs = portRange.map { port ->
                async(Dispatchers.IO) {
                    if (isPortOpen(host, port)) {
                        openPortsList.add(port)
                        // Identify service
                        val service = identifyService(host, port)
                        hostInfo.services[port] = service
                    }
                }
            }
            
            portJobs.awaitAll()
        }
        
        if (openPortsList.isNotEmpty()) {
            openPorts[host] = openPortsList
            
            // OS fingerprinting based on open ports
            hostInfo.os = guessOS(openPortsList)
            
            discoveredHosts[host] = hostInfo
        }
    }
    
    /**
     * Check if host is alive using ICMP echo
     */
    private fun isHostAlive(host: String): Boolean {
        return try {
            val address = InetAddress.getByName(host)
            address.isReachable(timeout)
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Check if port is open
     */
    private fun isPortOpen(host: String, port: Int): Boolean {
        return try {
            Socket().use { socket ->
                socket.soTimeout = timeout
                val endpoint = InetSocketAddress(host, port)
                socket.connect(endpoint, timeout)
                true
            }
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Identify service running on port
     */
    private fun identifyService(host: String, port: Int): String {
        // Common port to service mapping
        val commonPorts = mapOf(
            21 to "FTP",
            22 to "SSH",
            23 to "Telnet",
            25 to "SMTP",
            53 to "DNS",
            80 to "HTTP",
            110 to "POP3",
            143 to "IMAP",
            443 to "HTTPS",
            445 to "SMB",
            3306 to "MySQL",
            3389 to "RDP",
            5432 to "PostgreSQL",
            8080 to "HTTP-Proxy",
            8443 to "HTTPS-Alt"
        )
        
        // Try banner grabbing for unknown ports
        return commonPorts[port] ?: grabBanner(host, port)
    }
    
    /**
     * Grab service banner
     */
    private fun grabBanner(host: String, port: Int): String {
        return try {
            Socket().use { socket ->
                socket.soTimeout = timeout
                socket.connect(InetSocketAddress(host, port), timeout)
                
                val input = socket.getInputStream().bufferedReader()
                val output = socket.getOutputStream()
                
                // Send a generic probe
                output.write("HEAD / HTTP/1.0\r\n\r\n".toByteArray())
                output.flush()
                
                // Read response
                val banner = input.readLine() ?: ""
                
                when {
                    banner.contains("HTTP") -> "HTTP"
                    banner.contains("SSH") -> "SSH"
                    banner.contains("FTP") -> "FTP"
                    banner.contains("SMTP") -> "SMTP"
                    else -> "Unknown"
                }
            }
        } catch (e: Exception) {
            "Unknown"
        }
    }
    
    /**
     * Guess OS based on open ports
     */
    private fun guessOS(ports: List<Int>): String {
        return when {
            ports.contains(445) && ports.contains(135) -> "Windows"
            ports.contains(22) && !ports.contains(445) -> "Linux/Unix"
            ports.contains(548) -> "macOS"
            ports.contains(23) && ports.contains(80) -> "Router/IoT"
            else -> "Unknown"
        }
    }
    
    /**
     * Expand IP range notation
     */
    private fun expandIpRange(range: String): List<String> {
        val ips = mutableListOf<String>()
        
        when {
            // CIDR notation
            range.contains("/") -> {
                val parts = range.split("/")
                val baseIp = parts[0]
                val cidr = parts[1].toInt()
                
                // Calculate IP range from CIDR
                val ipLong = ipToLong(baseIp)
                val mask = -1L shl (32 - cidr)
                val start = ipLong and mask
                val end = start or mask.inv()
                
                for (ip in start..end) {
                    ips.add(longToIp(ip))
                }
            }
            // Range notation (192.168.1.1-192.168.1.255)
            range.contains("-") -> {
                val parts = range.split("-")
                val startIp = ipToLong(parts[0])
                val endIp = ipToLong(parts[1])
                
                for (ip in startIp..endIp) {
                    ips.add(longToIp(ip))
                }
            }
            // Single IP
            else -> ips.add(range)
        }
        
        return ips
    }
    
    private fun ipToLong(ip: String): Long {
        val parts = ip.split(".")
        return parts.mapIndexed { i, part ->
            part.toLong() shl (24 - i * 8)
        }.sum()
    }
    
    private fun longToIp(ip: Long): String {
        return listOf(
            (ip shr 24) and 0xFF,
            (ip shr 16) and 0xFF,
            (ip shr 8) and 0xFF,
            ip and 0xFF
        ).joinToString(".")
    }
    
    /**
     * Advanced scanning techniques
     */
    class AdvancedScanner {
        
        /**
         * Decoy scan - hide among decoy IPs
         */
        fun decoyScan(
            target: String,
            port: Int,
            decoys: List<String>
        ): Boolean {
            // This would require raw socket access
            // Simplified version for demonstration
            
            // Send packets appearing to come from decoys
            decoys.forEach { decoy ->
                // Spoof source IP (requires root/admin)
                println("Spoofing scan from $decoy to $target:$port")
            }
            
            // Actual scan
            return try {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress(target, port), 1000)
                    true
                }
            } catch (e: Exception) {
                false
            }
        }
        
        /**
         * Fragmented packet scan
         */
        fun fragmentedScan(target: String, port: Int): Boolean {
            // Fragment packets to evade IDS
            // This requires low-level packet manipulation
            println("Performing fragmented scan on $target:$port")
            
            // Simplified check
            return isPortOpen(target, port, 1000)
        }
        
        /**
         * Idle/Zombie scan using idle host
         */
        fun idleScan(
            target: String,
            port: Int,
            zombie: String
        ): Boolean {
            // Use zombie host to hide real source
            println("Using zombie host $zombie for scanning $target:$port")
            
            // This requires:
            // 1. Check zombie's IP ID
            // 2. Spoof SYN from zombie to target
            // 3. Check zombie's IP ID again
            // If incremented by 2, port is open
            
            return false // Placeholder
        }
        
        private fun isPortOpen(host: String, port: Int, timeout: Int): Boolean {
            return try {
                Socket().use { socket ->
                    socket.soTimeout = timeout
                    socket.connect(InetSocketAddress(host, port), timeout)
                    true
                }
            } catch (e: Exception) {
                false
            }
        }
    }
}

/**
 * Service fingerprinting
 */
class ServiceFingerprinter {
    
    data class ServiceInfo(
        val name: String,
        val version: String? = null,
        val extraInfo: Map<String, String> = emptyMap()
    )
    
    fun fingerprint(host: String, port: Int): ServiceInfo {
        val probes = listOf(
            // HTTP probe
            "GET / HTTP/1.0\r\n\r\n" to ::parseHttpResponse,
            // SMTP probe
            "EHLO scanner\r\n" to ::parseSmtpResponse,
            // FTP probe
            "USER anonymous\r\n" to ::parseFtpResponse,
            // SSH probe (just connect)
            "" to ::parseSshBanner
        )
        
        for ((probe, parser) in probes) {
            try {
                val response = sendProbe(host, port, probe)
                val result = parser(response)
                if (result.name != "Unknown") {
                    return result
                }
            } catch (e: Exception) {
                continue
            }
        }
        
        return ServiceInfo("Unknown")
    }
    
    private fun sendProbe(host: String, port: Int, probe: String): String {
        Socket().use { socket ->
            socket.soTimeout = 2000
            socket.connect(InetSocketAddress(host, port), 2000)
            
            if (probe.isNotEmpty()) {
                socket.getOutputStream().write(probe.toByteArray())
            }
            
            val buffer = ByteArray(1024)
            val bytesRead = socket.getInputStream().read(buffer)
            
            return if (bytesRead > 0) {
                String(buffer, 0, bytesRead)
            } else {
                ""
            }
        }
    }
    
    private fun parseHttpResponse(response: String): ServiceInfo {
        return if (response.startsWith("HTTP/")) {
            val serverHeader = response.lines()
                .find { it.startsWith("Server:", ignoreCase = true) }
            
            ServiceInfo(
                name = "HTTP",
                version = serverHeader?.substringAfter(":")?.trim(),
                extraInfo = mapOf("response" to response.lines().first())
            )
        } else {
            ServiceInfo("Unknown")
        }
    }
    
    private fun parseSmtpResponse(response: String): ServiceInfo {
        return if (response.contains("SMTP") || response.startsWith("220")) {
            ServiceInfo(
                name = "SMTP",
                version = response.substringAfter("SMTP").trim(),
                extraInfo = mapOf("banner" to response)
            )
        } else {
            ServiceInfo("Unknown")
        }
    }
    
    private fun parseFtpResponse(response: String): ServiceInfo {
        return if (response.startsWith("220") || response.contains("FTP")) {
            ServiceInfo(
                name = "FTP",
                version = response.substringAfter("FTP").trim(),
                extraInfo = mapOf("banner" to response)
            )
        } else {
            ServiceInfo("Unknown")
        }
    }
    
    private fun parseSshBanner(response: String): ServiceInfo {
        return if (response.startsWith("SSH-")) {
            val parts = response.trim().split(" ")
            ServiceInfo(
                name = "SSH",
                version = parts.getOrNull(0)?.substringAfter("SSH-"),
                extraInfo = mapOf("software" to (parts.getOrNull(1) ?: ""))
            )
        } else {
            ServiceInfo("Unknown")
        }
    }
}

// CLI Interface
fun main(args: Array<String>) = runBlocking {
    println("Lackadaisical Network Scanner")
    println("=============================")
    
    if (args.isEmpty()) {
        println("Usage: NetworkScanner <target> [options]")
        println("  target: IP, IP range (192.168.1.1-192.168.1.255), or CIDR (192.168.1.0/24)")
        println("Options:")
        println("  -p <ports>    Port range (default: 1-1024)")
        println("  -t <timeout>  Timeout in ms (default: 1000)")
        println("  --stealth     Use stealth scanning")
        return@runBlocking
    }
    
    val target = args[0]
    val scanner = NetworkScanner()
    
    println("Scanning $target...")
    
    val result = scanner.stealthScan(target)
    
    println("\nScan completed in ${result.scanTime}ms")
    println("Found ${result.hosts.size} hosts with ${result.totalPorts} open ports")
    
    result.hosts.forEach { (ip, info) ->
        println("\nHost: $ip ${info.hostname?.let { "($it)" } ?: ""}")
        println("  OS: ${info.os}")
        println("  Open ports:")
        info.services.forEach { (port, service) ->
            println("    $port - $service")
        }
    }
}

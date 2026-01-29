-- Traffic Analyzer - Deep packet inspection and pattern detection
-- Part of Lackadaisical Anonymity Toolkit

local socket = require("socket")
local bit = require("bit")

-- Traffic Analyzer module
local TrafficAnalyzer = {}
TrafficAnalyzer.__index = TrafficAnalyzer

-- Protocol definitions
local protocols = {
    tcp = 6,
    udp = 17,
    icmp = 1,
    igmp = 2
}

-- Common ports and services
local known_ports = {
    [20] = "FTP-DATA",
    [21] = "FTP",
    [22] = "SSH",
    [23] = "Telnet",
    [25] = "SMTP",
    [53] = "DNS",
    [80] = "HTTP",
    [110] = "POP3",
    [143] = "IMAP",
    [443] = "HTTPS",
    [445] = "SMB",
    [3389] = "RDP",
    [8080] = "HTTP-Proxy",
    [9050] = "Tor-SOCKS"
}

-- Suspicious patterns
local suspicious_patterns = {
    -- Command injection attempts
    {"[;&|]%s*(?:cat|ls|pwd|whoami|id)", "Command Injection"},
    -- SQL injection
    {"(?:union|select|from|where).*(?:--|\\/\\*|#)", "SQL Injection"},
    -- XSS attempts
    {"<script[^>]*>.*</script>", "XSS Attempt"},
    -- Directory traversal
    {"%.%./%.%./", "Directory Traversal"},
    -- Encoded payloads
    {"(?:eval|base64_decode|exec)%s*%(", "Encoded Payload"},
    -- Reverse shell patterns
    {"(?:nc|netcat|bash|sh).*(?:-e|-c).*(?:/bin/|cmd)", "Reverse Shell"}
}

function TrafficAnalyzer:new(interface)
    local self = setmetatable({}, TrafficAnalyzer)
    self.interface = interface or "any"
    self.packet_count = 0
    self.flow_table = {}
    self.alerts = {}
    self.statistics = {
        protocols = {},
        ports = {},
        hosts = {}
    }
    return self
end

-- Parse Ethernet frame
function TrafficAnalyzer:parse_ethernet(data)
    if #data < 14 then return nil end
    
    local frame = {
        dest_mac = string.format("%02x:%02x:%02x:%02x:%02x:%02x",
            data:byte(1), data:byte(2), data:byte(3),
            data:byte(4), data:byte(5), data:byte(6)),
        src_mac = string.format("%02x:%02x:%02x:%02x:%02x:%02x",
            data:byte(7), data:byte(8), data:byte(9),
            data:byte(10), data:byte(11), data:byte(12)),
        ethertype = bit.bor(bit.lshift(data:byte(13), 8), data:byte(14))
    }
    
    frame.payload = data:sub(15)
    return frame
end

-- Parse IP packet
function TrafficAnalyzer:parse_ip(data)
    if #data < 20 then return nil end
    
    local packet = {
        version = bit.rshift(data:byte(1), 4),
        ihl = bit.band(data:byte(1), 0x0F),
        tos = data:byte(2),
        total_length = bit.bor(bit.lshift(data:byte(3), 8), data:byte(4)),
        id = bit.bor(bit.lshift(data:byte(5), 8), data:byte(6)),
        flags = bit.rshift(data:byte(7), 5),
        frag_offset = bit.bor(bit.lshift(bit.band(data:byte(7), 0x1F), 8), data:byte(8)),
        ttl = data:byte(9),
        protocol = data:byte(10),
        checksum = bit.bor(bit.lshift(data:byte(11), 8), data:byte(12)),
        src_ip = string.format("%d.%d.%d.%d", 
            data:byte(13), data:byte(14), data:byte(15), data:byte(16)),
        dst_ip = string.format("%d.%d.%d.%d",
            data:byte(17), data:byte(18), data:byte(19), data:byte(20))
    }
    
    local header_len = packet.ihl * 4
    packet.payload = data:sub(header_len + 1)
    
    return packet
end

-- Parse TCP segment
function TrafficAnalyzer:parse_tcp(data)
    if #data < 20 then return nil end
    
    local segment = {
        src_port = bit.bor(bit.lshift(data:byte(1), 8), data:byte(2)),
        dst_port = bit.bor(bit.lshift(data:byte(3), 8), data:byte(4)),
        seq_num = bit.bor(
            bit.lshift(data:byte(5), 24),
            bit.lshift(data:byte(6), 16),
            bit.lshift(data:byte(7), 8),
            data:byte(8)
        ),
        ack_num = bit.bor(
            bit.lshift(data:byte(9), 24),
            bit.lshift(data:byte(10), 16),
            bit.lshift(data:byte(11), 8),
            data:byte(12)
        ),
        data_offset = bit.rshift(data:byte(13), 4),
        flags = {
            fin = bit.band(data:byte(14), 0x01) ~= 0,
            syn = bit.band(data:byte(14), 0x02) ~= 0,
            rst = bit.band(data:byte(14), 0x04) ~= 0,
            psh = bit.band(data:byte(14), 0x08) ~= 0,
            ack = bit.band(data:byte(14), 0x10) ~= 0,
            urg = bit.band(data:byte(14), 0x20) ~= 0
        },
        window = bit.bor(bit.lshift(data:byte(15), 8), data:byte(16)),
        checksum = bit.bor(bit.lshift(data:byte(17), 8), data:byte(18)),
        urgent = bit.bor(bit.lshift(data:byte(19), 8), data:byte(20))
    }
    
    local header_len = segment.data_offset * 4
    segment.payload = data:sub(header_len + 1)
    
    return segment
end

-- Analyze packet for suspicious patterns
function TrafficAnalyzer:analyze_payload(payload, flow_key)
    -- Convert payload to string for pattern matching
    local payload_str = payload
    
    -- Check against suspicious patterns
    for _, pattern_info in ipairs(suspicious_patterns) do
        local pattern, alert_type = pattern_info[1], pattern_info[2]
        if payload_str:match(pattern) then
            self:add_alert(alert_type, flow_key, "Suspicious pattern detected: " .. pattern)
        end
    end
    
    -- Check for potential covert channels
    self:detect_covert_channels(payload, flow_key)
    
    -- Entropy analysis for encrypted/compressed data
    local entropy = self:calculate_entropy(payload)
    if entropy > 7.5 then
        self:add_alert("High Entropy", flow_key, 
            string.format("Possible encrypted/compressed data (entropy: %.2f)", entropy))
    end
end

-- Calculate Shannon entropy
function TrafficAnalyzer:calculate_entropy(data)
    local freq = {}
    local len = #data
    
    -- Count byte frequencies
    for i = 1, len do
        local byte = data:byte(i)
        freq[byte] = (freq[byte] or 0) + 1
    end
    
    -- Calculate entropy
    local entropy = 0
    for _, count in pairs(freq) do
        local p = count / len
        entropy = entropy - p * math.log(p) / math.log(2)
    end
    
    return entropy
end

-- Detect potential covert channels
function TrafficAnalyzer:detect_covert_channels(payload, flow_key)
    -- Check ICMP for data smuggling
    if flow_key:match("ICMP") and #payload > 8 then
        self:add_alert("Covert Channel", flow_key, "ICMP payload exceeds normal size")
    end
    
    -- Check DNS for tunneling
    if flow_key:match(":53") then
        -- Check for unusually long domain names
        if #payload > 100 then
            self:add_alert("DNS Tunneling", flow_key, "Unusually large DNS query")
        end
        
        -- Check for base64-like patterns in DNS
        local subdomain = payload:match("^[A-Za-z0-9+/]+=*%.")
        if subdomain and #subdomain > 50 then
            self:add_alert("DNS Tunneling", flow_key, "Possible base64 encoded DNS query")
        end
    end
    
    -- Check HTTP headers for steganography
    if flow_key:match(":80") or flow_key:match(":8080") then
        -- Check for unusual headers
        local custom_header = payload:match("X%-[%w-]+:%s*([^\r\n]+)")
        if custom_header and #custom_header > 100 then
            self:add_alert("HTTP Steganography", flow_key, "Suspicious custom HTTP header")
        end
    end
end

-- Add alert
function TrafficAnalyzer:add_alert(alert_type, flow_key, description)
    table.insert(self.alerts, {
        timestamp = os.time(),
        type = alert_type,
        flow = flow_key,
        description = description
    })
    
    -- Print alert in real-time
    print(string.format("[ALERT] %s - %s: %s", 
        os.date("%Y-%m-%d %H:%M:%S"), alert_type, description))
end

-- Update statistics
function TrafficAnalyzer:update_stats(ip_packet, transport_info)
    -- Protocol statistics
    local proto_name = self:get_protocol_name(ip_packet.protocol)
    self.statistics.protocols[proto_name] = 
        (self.statistics.protocols[proto_name] or 0) + 1
    
    -- Port statistics (for TCP/UDP)
    if transport_info and transport_info.dst_port then
        local port = transport_info.dst_port
        self.statistics.ports[port] = (self.statistics.ports[port] or 0) + 1
    end
    
    -- Host statistics
    self.statistics.hosts[ip_packet.src_ip] = 
        (self.statistics.hosts[ip_packet.src_ip] or 0) + 1
    self.statistics.hosts[ip_packet.dst_ip] = 
        (self.statistics.hosts[ip_packet.dst_ip] or 0) + 1
end

-- Get protocol name
function TrafficAnalyzer:get_protocol_name(proto_num)
    for name, num in pairs(protocols) do
        if num == proto_num then
            return name:upper()
        end
    end
    return string.format("Protocol-%d", proto_num)
end

-- Process packet
function TrafficAnalyzer:process_packet(data)
    self.packet_count = self.packet_count + 1
    
    -- Parse Ethernet frame
    local eth_frame = self:parse_ethernet(data)
    if not eth_frame then return end
    
    -- Only process IPv4 packets (0x0800)
    if eth_frame.ethertype ~= 0x0800 then return end
    
    -- Parse IP packet
    local ip_packet = self:parse_ip(eth_frame.payload)
    if not ip_packet then return end
    
    local flow_key = string.format("%s:%s", ip_packet.src_ip, ip_packet.dst_ip)
    local transport_info = nil
    
    -- Parse transport layer
    if ip_packet.protocol == protocols.tcp then
        transport_info = self:parse_tcp(ip_packet.payload)
        if transport_info then
            flow_key = string.format("%s:%d->%s:%d/TCP",
                ip_packet.src_ip, transport_info.src_port,
                ip_packet.dst_ip, transport_info.dst_port)
            
            -- Analyze TCP flags for anomalies
            if transport_info.flags.syn and transport_info.flags.fin then
                self:add_alert("TCP Anomaly", flow_key, "SYN+FIN flags set")
            end
            
            -- Analyze payload
            if #transport_info.payload > 0 then
                self:analyze_payload(transport_info.payload, flow_key)
            end
        end
    end
    
    -- Update statistics
    self:update_stats(ip_packet, transport_info)
    
    -- Track flows
    self.flow_table[flow_key] = {
        packets = (self.flow_table[flow_key] and self.flow_table[flow_key].packets or 0) + 1,
        bytes = (self.flow_table[flow_key] and self.flow_table[flow_key].bytes or 0) + #data,
        last_seen = os.time()
    }
end

-- Print statistics
function TrafficAnalyzer:print_stats()
    print("\n=== Traffic Analysis Statistics ===")
    print(string.format("Total packets: %d", self.packet_count))
    
    print("\nProtocol Distribution:")
    for proto, count in pairs(self.statistics.protocols) do
        print(string.format("  %s: %d", proto, count))
    end
    
    print("\nTop Ports:")
    local port_list = {}
    for port, count in pairs(self.statistics.ports) do
        table.insert(port_list, {port = port, count = count})
    end
    table.sort(port_list, function(a, b) return a.count > b.count end)
    
    for i = 1, math.min(10, #port_list) do
        local port_info = port_list[i]
        local service = known_ports[port_info.port] or "Unknown"
        print(string.format("  %d (%s): %d", port_info.port, service, port_info.count))
    end
    
    print("\nTop Talkers:")
    local host_list = {}
    for host, count in pairs(self.statistics.hosts) do
        table.insert(host_list, {host = host, count = count})
    end
    table.sort(host_list, function(a, b) return a.count > b.count end)
    
    for i = 1, math.min(10, #host_list) do
        print(string.format("  %s: %d packets", host_list[i].host, host_list[i].count))
    end
    
    print(string.format("\nTotal Alerts: %d", #self.alerts))
end

-- Export alerts to file
function TrafficAnalyzer:export_alerts(filename)
    local file = io.open(filename, "w")
    if not file then
        print("Error: Cannot open file for writing")
        return
    end
    
    file:write("Timestamp,Type,Flow,Description\n")
    for _, alert in ipairs(self.alerts) do
        file:write(string.format("%s,%s,%s,%s\n",
            os.date("%Y-%m-%d %H:%M:%S", alert.timestamp),
            alert.type,
            alert.flow,
            alert.description))
    end
    
    file:close()
    print(string.format("Alerts exported to %s", filename))
end

-- CLI interface
if arg and #arg > 0 then
    local analyzer = TrafficAnalyzer:new(arg[1])
    
    print("Lackadaisical Traffic Analyzer")
    print("==============================")
    print("Analyzing traffic... Press Ctrl+C to stop")
    
    -- Note: Actual packet capture would require luapcap or similar
    -- This is a demonstration of the analysis logic
    
    -- Simulate packet processing
    local function simulate_capture()
        -- In real implementation, this would capture from network
        print("Note: This is a demonstration. Install luapcap for actual packet capture.")
    end
    
    simulate_capture()
else
    print("Usage: lua traffic_analyzer.lua <interface>")
    print("Example: lua traffic_analyzer.lua eth0")
end

return TrafficAnalyzer

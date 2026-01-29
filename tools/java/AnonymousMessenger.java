import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.*;

/**
 * Anonymous Messenger - Onion-routed messaging system
 * Part of Lackadaisical Anonymity Toolkit
 */
public class AnonymousMessenger {
    private static final Logger LOGGER = Logger.getLogger(AnonymousMessenger.class.getName());
    private static final int DEFAULT_PORT = 9876;
    private static final int ONION_LAYERS = 3;
    
    private final Map<String, RelayNode> relayNodes;
    private final ExecutorService executor;
    private ServerSocket serverSocket;
    private volatile boolean running;
    
    public AnonymousMessenger() {
        this.relayNodes = new ConcurrentHashMap<>();
        this.executor = Executors.newCachedThreadPool();
    }
    
    /**
     * Relay node for onion routing
     */
    public static class RelayNode {
        public final String id;
        public final String address;
        public final int port;
        public final PublicKey publicKey;
        
        public RelayNode(String id, String address, int port, PublicKey publicKey) {
            this.id = id;
            this.address = address;
            this.port = port;
            this.publicKey = publicKey;
        }
    }
    
    /**
     * Onion-encrypted message
     */
    public static class OnionMessage {
        public final byte[] encryptedData;
        public final String nextHop;
        
        public OnionMessage(byte[] encryptedData, String nextHop) {
            this.encryptedData = encryptedData;
            this.nextHop = nextHop;
        }
    }
    
    /**
     * Start the messenger service
     */
    public void start(int port) throws IOException {
        serverSocket = new ServerSocket(port);
        running = true;
        
        LOGGER.info("Anonymous Messenger started on port " + port);
        
        executor.submit(() -> {
            while (running) {
                try {
                    Socket client = serverSocket.accept();
                    executor.submit(() -> handleClient(client));
                } catch (IOException e) {
                    if (running) {
                        LOGGER.log(Level.SEVERE, "Accept failed", e);
                    }
                }
            }
        });
    }
    
    /**
     * Send anonymous message through onion routing
     */
    public void sendMessage(String recipient, String message) throws Exception {
        // Select random relay path
        List<RelayNode> path = selectRandomPath(ONION_LAYERS);
        if (path.isEmpty()) {
            throw new IllegalStateException("No relay nodes available");
        }
        
        // Build onion layers
        byte[] payload = createPayload(recipient, message);
        
        // Encrypt in reverse order (innermost layer first)
        for (int i = path.size() - 1; i >= 0; i--) {
            RelayNode node = path.get(i);
            String nextHop = (i < path.size() - 1) ? path.get(i + 1).id : recipient;
            
            payload = encryptLayer(payload, nextHop, node.publicKey);
        }
        
        // Send to first relay
        sendToRelay(path.get(0), payload);
    }
    
    /**
     * Handle incoming client connection
     */
    private void handleClient(Socket client) {
        try (DataInputStream in = new DataInputStream(client.getInputStream());
             DataOutputStream out = new DataOutputStream(client.getOutputStream())) {
            
            // Read message type
            byte messageType = in.readByte();
            
            switch (messageType) {
                case 0x01: // Relay message
                    handleRelayMessage(in, out);
                    break;
                case 0x02: // Direct message
                    handleDirectMessage(in, out);
                    break;
                case 0x03: // Node announcement
                    handleNodeAnnouncement(in);
                    break;
                default:
                    LOGGER.warning("Unknown message type: " + messageType);
            }
            
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Client handling error", e);
        } finally {
            try {
                client.close();
            } catch (IOException e) {
                // Ignore
            }
        }
    }
    
    /**
     * Handle relay message (onion routing)
     */
    private void handleRelayMessage(DataInputStream in, DataOutputStream out) throws Exception {
        int dataLength = in.readInt();
        byte[] encryptedData = new byte[dataLength];
        in.readFully(encryptedData);
        
        // Decrypt our layer
        OnionMessage decrypted = decryptLayer(encryptedData);
        
        if (decrypted.nextHop.equals("LOCAL")) {
            // Message is for us
            String message = new String(decrypted.encryptedData, StandardCharsets.UTF_8);
            LOGGER.info("Received message: " + message);
            
            // Send acknowledgment
            out.writeByte(0x00); // Success
        } else {
            // Forward to next hop
            RelayNode nextNode = relayNodes.get(decrypted.nextHop);
            if (nextNode != null) {
                sendToRelay(nextNode, decrypted.encryptedData);
                out.writeByte(0x00); // Success
            } else {
                out.writeByte(0x01); // Error
            }
        }
    }
    
    /**
     * Create message payload
     */
    private byte[] createPayload(String recipient, String message) {
        ByteBuffer buffer = ByteBuffer.allocate(4 + recipient.length() + 4 + message.length());
        
        buffer.putInt(recipient.length());
        buffer.put(recipient.getBytes(StandardCharsets.UTF_8));
        buffer.putInt(message.length());
        buffer.put(message.getBytes(StandardCharsets.UTF_8));
        
        return buffer.array();
    }
    
    /**
     * Encrypt layer for onion routing
     */
    private byte[] encryptLayer(byte[] data, String nextHop, PublicKey publicKey) throws Exception {
        // Generate ephemeral key for this layer
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();
        
        // Encrypt data with AES
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] iv = aesCipher.getIV();
        byte[] encryptedData = aesCipher.doFinal(data);
        
        // Encrypt AES key with RSA
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = rsaCipher.doFinal(aesKey.getEncoded());
        
        // Build onion layer
        ByteBuffer buffer = ByteBuffer.allocate(
            4 + nextHop.length() +  // Next hop
            4 + encryptedKey.length +  // Encrypted key
            4 + iv.length +  // IV
            4 + encryptedData.length  // Encrypted data
        );
        
        buffer.putInt(nextHop.length());
        buffer.put(nextHop.getBytes(StandardCharsets.UTF_8));
        buffer.putInt(encryptedKey.length);
        buffer.put(encryptedKey);
        buffer.putInt(iv.length);
        buffer.put(iv);
        buffer.putInt(encryptedData.length);
        buffer.put(encryptedData);
        
        return buffer.array();
    }
    
    /**
     * Decrypt layer for onion routing
     */
    private OnionMessage decryptLayer(byte[] data) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(data);
        
        // Read next hop
        int nextHopLength = buffer.getInt();
        byte[] nextHopBytes = new byte[nextHopLength];
        buffer.get(nextHopBytes);
        String nextHop = new String(nextHopBytes, StandardCharsets.UTF_8);
        
        // Read encrypted key
        int encKeyLength = buffer.getInt();
        byte[] encryptedKey = new byte[encKeyLength];
        buffer.get(encryptedKey);
        
        // Read IV
        int ivLength = buffer.getInt();
        byte[] iv = new byte[ivLength];
        buffer.get(iv);
        
        // Read encrypted data
        int dataLength = buffer.getInt();
        byte[] encryptedData = new byte[dataLength];
        buffer.get(encryptedData);
        
        // Decrypt AES key with our private key
        PrivateKey privateKey = getPrivateKey();
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(encryptedKey);
        
        // Decrypt data with AES
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] decryptedData = aesCipher.doFinal(encryptedData);
        
        return new OnionMessage(decryptedData, nextHop);
    }
    
    /**
     * Select random path through relay nodes
     */
    private List<RelayNode> selectRandomPath(int length) {
        List<RelayNode> allNodes = new ArrayList<>(relayNodes.values());
        Collections.shuffle(allNodes);
        
        return allNodes.subList(0, Math.min(length, allNodes.size()));
    }
    
    /**
     * Send data to relay node
     */
    private void sendToRelay(RelayNode node, byte[] data) throws IOException {
        try (Socket socket = new Socket(node.address, node.port);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             DataInputStream in = new DataInputStream(socket.getInputStream())) {
            
            // Send relay message
            out.writeByte(0x01); // Message type: relay
            out.writeInt(data.length);
            out.write(data);
            out.flush();
            
            // Wait for acknowledgment
            byte response = in.readByte();
            if (response != 0x00) {
                throw new IOException("Relay failed");
            }
        }
    }
    
    /**
     * Anonymous file transfer
     */
    public void sendFile(String recipient, File file) throws Exception {
        // Read file
        byte[] fileData = new byte[(int) file.length()];
        try (FileInputStream fis = new FileInputStream(file)) {
            fis.read(fileData);
        }
        
        // Compress
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(baos)) {
            gzip.write(fileData);
        }
        byte[] compressed = baos.toByteArray();
        
        // Split into chunks for transmission
        int chunkSize = 32768; // 32KB chunks
        int chunks = (compressed.length + chunkSize - 1) / chunkSize;
        
        for (int i = 0; i < chunks; i++) {
            int offset = i * chunkSize;
            int length = Math.min(chunkSize, compressed.length - offset);
            
            byte[] chunk = Arrays.copyOfRange(compressed, offset, offset + length);
            
            // Send chunk with metadata
            String chunkMessage = String.format("FILE:%s:CHUNK:%d/%d:SIZE:%d",
                file.getName(), i + 1, chunks, compressed.length);
            
            sendMessage(recipient, chunkMessage);
            Thread.sleep(100); // Rate limiting
        }
    }
    
    /**
     * Handle direct message (non-onion routed)
     */
    private void handleDirectMessage(DataInputStream in, DataOutputStream out) throws Exception {
        // This would implement direct messaging logic
        // For brevity, simplified implementation
        int messageLength = in.readInt();
        byte[] message = new byte[messageLength];
        in.readFully(message);
        
        LOGGER.info("Direct message received: " + new String(message, StandardCharsets.UTF_8));
        out.writeByte(0x00); // Success
    }
    
    /**
     * Handle node announcement
     */
    private void handleNodeAnnouncement(DataInputStream in) throws Exception {
        String nodeId = in.readUTF();
        String address = in.readUTF();
        int port = in.readInt();
        
        int keyLength = in.readInt();
        byte[] keyBytes = new byte[keyLength];
        in.readFully(keyBytes);
        
        PublicKey publicKey = KeyFactory.getInstance("RSA")
            .generatePublic(new X509EncodedKeySpec(keyBytes));
        
        RelayNode node = new RelayNode(nodeId, address, port, publicKey);
        relayNodes.put(nodeId, node);
        
        LOGGER.info("New relay node registered: " + nodeId);
    }
    
    /**
     * Get private key (simplified - should load from secure storage)
     */
    private PrivateKey getPrivateKey() throws Exception {
        // In production, load from secure keystore
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        return keyPair.getPrivate();
    }
    
    /**
     * Stop the messenger service
     */
    public void stop() {
        running = false;
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Error closing server socket", e);
        }
        executor.shutdown();
    }
    
    public static void main(String[] args) throws Exception {
        AnonymousMessenger messenger = new AnonymousMessenger();
        
        // Start messenger
        int port = args.length > 0 ? Integer.parseInt(args[0]) : DEFAULT_PORT;
        messenger.start(port);
        
        // Example: Send anonymous message
        if (args.length > 2) {
            String recipient = args[1];
            String message = args[2];
            messenger.sendMessage(recipient, message);
        }
        
        // Keep running
        System.out.println("Anonymous Messenger running on port " + port);
        System.out.println("Press Enter to stop...");
        System.in.read();
        
        messenger.stop();
    }
}

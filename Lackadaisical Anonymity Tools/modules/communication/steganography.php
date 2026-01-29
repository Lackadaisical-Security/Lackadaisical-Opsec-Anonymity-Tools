<?php
/**
 * Steganography Module
 * Part of Lackadaisical Anonymity Toolkit
 * 
 * Hide data in images, audio, and text files
 */

class Steganography {
    private $verbose;
    
    public function __construct($verbose = false) {
        $this->verbose = $verbose;
    }
    
    /**
     * Hide text in PNG image using LSB steganography
     */
    public function hideInImage($imagePath, $message, $outputPath, $password = null) {
        if (!file_exists($imagePath)) {
            throw new Exception("Image file not found: $imagePath");
        }
        
        $image = imagecreatefrompng($imagePath);
        if (!$image) {
            throw new Exception("Failed to load PNG image");
        }
        
        $width = imagesx($image);
        $height = imagesy($image);
        
        // Encrypt message if password provided
        if ($password) {
            $message = $this->encrypt($message, $password);
        }
        
        // Add delimiter and convert to binary
        $message = $message . "\0END\0";
        $binary = '';
        for ($i = 0; $i < strlen($message); $i++) {
            $binary .= str_pad(decbin(ord($message[$i])), 8, '0', STR_PAD_LEFT);
        }
        
        if (strlen($binary) > $width * $height * 3) {
            throw new Exception("Message too large for image");
        }
        
        // Hide data in LSB of RGB values
        $binaryIndex = 0;
        for ($y = 0; $y < $height && $binaryIndex < strlen($binary); $y++) {
            for ($x = 0; $x < $width && $binaryIndex < strlen($binary); $x++) {
                $rgb = imagecolorat($image, $x, $y);
                $r = ($rgb >> 16) & 0xFF;
                $g = ($rgb >> 8) & 0xFF;
                $b = $rgb & 0xFF;
                
                // Modify LSB of each color channel
                if ($binaryIndex < strlen($binary)) {
                    $r = ($r & 0xFE) | $binary[$binaryIndex++];
                }
                if ($binaryIndex < strlen($binary)) {
                    $g = ($g & 0xFE) | $binary[$binaryIndex++];
                }
                if ($binaryIndex < strlen($binary)) {
                    $b = ($b & 0xFE) | $binary[$binaryIndex++];
                }
                
                $newColor = imagecolorallocate($image, $r, $g, $b);
                imagesetpixel($image, $x, $y, $newColor);
            }
        }
        
        imagepng($image, $outputPath);
        imagedestroy($image);
        
        if ($this->verbose) {
            echo "Message hidden in: $outputPath\n";
        }
        
        return true;
    }
    
    /**
     * Extract hidden text from PNG image
     */
    public function extractFromImage($imagePath, $password = null) {
        if (!file_exists($imagePath)) {
            throw new Exception("Image file not found: $imagePath");
        }
        
        $image = imagecreatefrompng($imagePath);
        if (!$image) {
            throw new Exception("Failed to load PNG image");
        }
        
        $width = imagesx($image);
        $height = imagesy($image);
        
        // Extract binary data from LSB
        $binary = '';
        for ($y = 0; $y < $height; $y++) {
            for ($x = 0; $x < $width; $x++) {
                $rgb = imagecolorat($image, $x, $y);
                $r = ($rgb >> 16) & 0xFF;
                $g = ($rgb >> 8) & 0xFF;
                $b = $rgb & 0xFF;
                
                $binary .= ($r & 1);
                $binary .= ($g & 1);
                $binary .= ($b & 1);
            }
        }
        
        // Convert binary to text
        $message = '';
        for ($i = 0; $i < strlen($binary); $i += 8) {
            $byte = substr($binary, $i, 8);
            $char = chr(bindec($byte));
            $message .= $char;
            
            // Check for delimiter
            if (substr($message, -5) === "\0END\0") {
                $message = substr($message, 0, -5);
                break;
            }
        }
        
        imagedestroy($image);
        
        // Decrypt if password provided
        if ($password) {
            $message = $this->decrypt($message, $password);
        }
        
        return $message;
    }
    
    /**
     * Hide data in WAV audio file
     */
    public function hideInAudio($audioPath, $message, $outputPath, $password = null) {
        if (!file_exists($audioPath)) {
            throw new Exception("Audio file not found: $audioPath");
        }
        
        $wav = $this->parseWav($audioPath);
        if (!$wav) {
            throw new Exception("Failed to parse WAV file");
        }
        
        // Encrypt message if password provided
        if ($password) {
            $message = $this->encrypt($message, $password);
        }
        
        // Add delimiter
        $message = $message . "\0END\0";
        $binary = '';
        for ($i = 0; $i < strlen($message); $i++) {
            $binary .= str_pad(decbin(ord($message[$i])), 8, '0', STR_PAD_LEFT);
        }
        
        // Hide in LSB of audio samples
        $samples = unpack('v*', $wav['data']);
        $binaryIndex = 0;
        
        foreach ($samples as $index => $sample) {
            if ($binaryIndex < strlen($binary)) {
                $samples[$index] = ($sample & 0xFFFE) | $binary[$binaryIndex++];
            } else {
                break;
            }
        }
        
        // Rebuild WAV file
        $newData = '';
        foreach ($samples as $sample) {
            $newData .= pack('v', $sample);
        }
        
        $output = $wav['header'] . $newData;
        file_put_contents($outputPath, $output);
        
        if ($this->verbose) {
            echo "Message hidden in: $outputPath\n";
        }
        
        return true;
    }
    
    /**
     * Hide message in text using zero-width characters
     */
    public function hideInText($coverText, $message, $password = null) {
        if ($password) {
            $message = $this->encrypt($message, $password);
        }
        
        // Convert message to binary
        $binary = '';
        for ($i = 0; $i < strlen($message); $i++) {
            $binary .= str_pad(decbin(ord($message[$i])), 8, '0', STR_PAD_LEFT);
        }
        
        // Use zero-width characters
        $zeroWidthChars = [
            '0' => "\u{200B}", // Zero-width space
            '1' => "\u{200C}"  // Zero-width non-joiner
        ];
        
        $hiddenText = '';
        for ($i = 0; $i < strlen($binary); $i++) {
            $hiddenText .= $zeroWidthChars[$binary[$i]];
        }
        
        // Insert at word boundaries
        $words = explode(' ', $coverText);
        $insertPos = min(1, count($words) - 1);
        array_splice($words, $insertPos, 0, $hiddenText);
        
        return implode(' ', $words);
    }
    
    /**
     * Extract message from text with zero-width characters
     */
    public function extractFromText($text, $password = null) {
        // Extract zero-width characters
        preg_match_all('/[\x{200B}\x{200C}]+/u', $text, $matches);
        
        if (empty($matches[0])) {
            return '';
        }
        
        $hiddenText = implode('', $matches[0]);
        
        // Convert back to binary
        $binary = '';
        for ($i = 0; $i < mb_strlen($hiddenText); $i++) {
            $char = mb_substr($hiddenText, $i, 1);
            if ($char === "\u{200B}") {
                $binary .= '0';
            } elseif ($char === "\u{200C}") {
                $binary .= '1';
            }
        }
        
        // Convert binary to text
        $message = '';
        for ($i = 0; $i < strlen($binary); $i += 8) {
            $byte = substr($binary, $i, 8);
            if (strlen($byte) == 8) {
                $message .= chr(bindec($byte));
            }
        }
        
        if ($password) {
            $message = $this->decrypt($message, $password);
        }
        
        return $message;
    }
    
    /**
     * Simple encryption using password
     */
    private function encrypt($data, $password) {
        $key = hash('sha256', $password, true);
        $iv = openssl_random_pseudo_bytes(16);
        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
        return base64_encode($iv . $encrypted);
    }
    
    /**
     * Simple decryption using password
     */
    private function decrypt($data, $password) {
        $data = base64_decode($data);
        $key = hash('sha256', $password, true);
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);
        return openssl_decrypt($encrypted, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    }
    
    /**
     * Parse WAV file header and data
     */
    private function parseWav($filename) {
        $fp = fopen($filename, 'rb');
        if (!$fp) return false;
        
        // Read RIFF header
        $riff = fread($fp, 12);
        if (substr($riff, 0, 4) !== 'RIFF' || substr($riff, 8, 4) !== 'WAVE') {
            fclose($fp);
            return false;
        }
        
        // Find data chunk
        $header = $riff;
        while (!feof($fp)) {
            $chunkHeader = fread($fp, 8);
            if (strlen($chunkHeader) < 8) break;
            
            $chunkType = substr($chunkHeader, 0, 4);
            $chunkSize = unpack('V', substr($chunkHeader, 4, 4))[1];
            
            if ($chunkType === 'data') {
                $data = fread($fp, $chunkSize);
                fclose($fp);
                return [
                    'header' => $header . $chunkHeader,
                    'data' => $data
                ];
            } else {
                $header .= $chunkHeader . fread($fp, $chunkSize);
            }
        }
        
        fclose($fp);
        return false;
    }
}

// CLI interface
if (php_sapi_name() === 'cli') {
    $options = getopt('m:i:o:t:p:xvh', ['mode:', 'input:', 'output:', 'text:', 'password:', 'extract', 'verbose', 'help']);
    
    if (isset($options['h']) || isset($options['help'])) {
        echo "Steganography Tool - Lackadaisical Anonymity Toolkit\n";
        echo "Usage: php steganography.php [options]\n\n";
        echo "Options:\n";
        echo "  -m, --mode TYPE     Steganography type (image, audio, text)\n";
        echo "  -i, --input FILE    Input file\n";
        echo "  -o, --output FILE   Output file\n";
        echo "  -t, --text TEXT     Text to hide or cover text\n";
        echo "  -p, --password PWD  Password for encryption\n";
        echo "  -x, --extract       Extract hidden message\n";
        echo "  -v, --verbose       Verbose output\n";
        echo "  -h, --help          Show this help\n";
        exit(0);
    }
    
    $stego = new Steganography(isset($options['v']) || isset($options['verbose']));
    
    $mode = $options['m'] ?? $options['mode'] ?? null;
    $input = $options['i'] ?? $options['input'] ?? null;
    $output = $options['o'] ?? $options['output'] ?? null;
    $text = $options['t'] ?? $options['text'] ?? null;
    $password = $options['p'] ?? $options['password'] ?? null;
    $extract = isset($options['x']) || isset($options['extract']);
    
    try {
        if ($extract) {
            // Extract mode
            switch ($mode) {
                case 'image':
                    $message = $stego->extractFromImage($input, $password);
                    echo "Extracted message: $message\n";
                    break;
                case 'text':
                    $message = $stego->extractFromText($text, $password);
                    echo "Extracted message: $message\n";
                    break;
                default:
                    echo "Extract mode not implemented for: $mode\n";
            }
        } else {
            // Hide mode
            switch ($mode) {
                case 'image':
                    $stego->hideInImage($input, $text, $output, $password);
                    break;
                case 'audio':
                    $stego->hideInAudio($input, $text, $output, $password);
                    break;
                case 'text':
                    $coverText = file_get_contents($input);
                    $result = $stego->hideInText($coverText, $text, $password);
                    file_put_contents($output, $result);
                    echo "Message hidden in: $output\n";
                    break;
                default:
                    echo "Unknown mode: $mode\n";
            }
        }
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
        exit(1);
    }
}

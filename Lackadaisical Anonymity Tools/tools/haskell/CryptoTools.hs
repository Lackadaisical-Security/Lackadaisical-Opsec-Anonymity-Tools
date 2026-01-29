{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import qualified Crypto.Cipher.AES as AES
import qualified Crypto.Cipher.Types as CipherTypes
import qualified Crypto.Error as CryptoError
import qualified Crypto.Hash as Hash
import qualified Crypto.KDF.PBKDF2 as PBKDF2
import qualified Crypto.MAC.HMAC as HMAC
import qualified Crypto.Random as Random
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as BS8
import Control.Monad
import Data.Maybe
import System.Environment
import System.Exit
import System.IO

-- | Cryptographic tools for the Lackadaisical Anonymity Toolkit
data CryptoConfig = CryptoConfig
    { configKeySize :: Int
    , configIterations :: Int
    , configAlgorithm :: String
    , configMode :: String
    } deriving (Show)

defaultConfig :: CryptoConfig
defaultConfig = CryptoConfig
    { configKeySize = 32  -- 256 bits
    , configIterations = 100000
    , configAlgorithm = "AES"
    , configMode = "GCM"
    }

-- | Generate secure random bytes
generateRandomBytes :: Int -> IO BS.ByteString
generateRandomBytes n = do
    gen <- Random.getSystemDRG
    let (bytes, _) = Random.randomBytesGenerate n gen
    return bytes

-- | Derive key from password using PBKDF2
deriveKey :: BS.ByteString -> BS.ByteString -> Int -> Int -> BS.ByteString
deriveKey password salt iterations keySize =
    PBKDF2.generate (PBKDF2.prfHMAC Hash.SHA256) 
                    (PBKDF2.Parameters iterations keySize) 
                    password 
                    salt

-- | Encrypt data using AES-GCM
encryptAESGCM :: BS.ByteString -> BS.ByteString -> BS.ByteString -> IO (Maybe (BS.ByteString, BS.ByteString))
encryptAESGCM key nonce plaintext = do
    case CryptoError.maybeCryptoError $ AES.cipherInit key of
        Nothing -> return Nothing
        Just cipher -> do
            case CryptoError.maybeCryptoError $ AES.aeadInit CipherTypes.AEAD_GCM cipher nonce of
                Nothing -> return Nothing
                Just aeadState -> do
                    let (authTag, ciphertext) = AES.aeadSimpleEncrypt aeadState BS.empty plaintext 16
                    return $ Just (ciphertext, BA.convert authTag)

-- | Decrypt data using AES-GCM
decryptAESGCM :: BS.ByteString -> BS.ByteString -> BS.ByteString -> BS.ByteString -> Maybe BS.ByteString
decryptAESGCM key nonce ciphertext tag =
    case CryptoError.maybeCryptoError $ AES.cipherInit key of
        Nothing -> Nothing
        Just cipher ->
            case CryptoError.maybeCryptoError $ AES.aeadInit CipherTypes.AEAD_GCM cipher nonce of
                Nothing -> Nothing
                Just aeadState ->
                    AES.aeadSimpleDecrypt aeadState BS.empty ciphertext (CipherTypes.AuthTag $ BA.convert tag)

-- | Secure file encryption
encryptFile :: FilePath -> BS.ByteString -> IO ()
encryptFile filepath password = do
    -- Read file
    plaintext <- BS.readFile filepath
    
    -- Generate salt and nonce
    salt <- generateRandomBytes 32
    nonce <- generateRandomBytes 12
    
    -- Derive key
    let key = deriveKey password salt defaultConfig.configIterations defaultConfig.configKeySize
    
    -- Encrypt
    result <- encryptAESGCM key nonce plaintext
    
    case result of
        Nothing -> do
            hPutStrLn stderr "Encryption failed"
            exitFailure
        Just (ciphertext, tag) -> do
            -- Write encrypted file
            let encryptedFilepath = filepath ++ ".enc"
            let header = BS.concat [salt, nonce, tag]
            BS.writeFile encryptedFilepath (header <> ciphertext)
            putStrLn $ "Encrypted file saved to: " ++ encryptedFilepath
            
            -- Secure delete original
            secureDelete filepath

-- | Secure file decryption
decryptFile :: FilePath -> BS.ByteString -> IO ()
decryptFile filepath password = do
    -- Read encrypted file
    encryptedData <- BS.readFile filepath
    
    -- Extract components
    let (header, ciphertext) = BS.splitAt 60 encryptedData  -- 32 + 12 + 16
    let salt = BS.take 32 header
    let nonce = BS.take 12 $ BS.drop 32 header
    let tag = BS.drop 44 header
    
    -- Derive key
    let key = deriveKey password salt defaultConfig.configIterations defaultConfig.configKeySize
    
    -- Decrypt
    case decryptAESGCM key nonce ciphertext tag of
        Nothing -> do
            hPutStrLn stderr "Decryption failed - wrong password or corrupted file"
            exitFailure
        Just plaintext -> do
            -- Write decrypted file
            let decryptedFilepath = if ".enc" `BS8.isSuffixOf` BS8.pack filepath
                                    then take (length filepath - 4) filepath
                                    else filepath ++ ".dec"
            BS.writeFile decryptedFilepath plaintext
            putStrLn $ "Decrypted file saved to: " ++ decryptedFilepath

-- | Secure file deletion with multiple passes
secureDelete :: FilePath -> IO ()
secureDelete filepath = do
    size <- withFile filepath ReadMode hFileSize
    
    -- Multiple overwrite passes
    forM_ [1..7] $ \pass -> do
        withFile filepath WriteMode $ \h -> do
            -- Random pattern
            pattern <- generateRandomBytes 4096
            
            -- Overwrite file
            let chunks = fromIntegral size `div` 4096
            let remainder = fromIntegral size `mod` 4096
            
            replicateM_ chunks $ BS.hPut h pattern
            when (remainder > 0) $ BS.hPut h (BS.take remainder pattern)
            
            hFlush h
    
    -- Delete file
    removeFile filepath
    putStrLn $ "Securely deleted: " ++ filepath

-- | Generate cryptographically secure password
generatePassword :: Int -> Bool -> Bool -> Bool -> IO String
generatePassword length includeSymbols includeNumbers excludeAmbiguous = do
    let lowercase = "abcdefghijklmnopqrstuvwxyz"
    let uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    let numbers = if includeNumbers then "0123456789" else ""
    let symbols = if includeSymbols then "!@#$%^&*()_+-=[]{}|;:,.<>?" else ""
    
    let charset = lowercase ++ uppercase ++ numbers ++ symbols
    let finalCharset = if excludeAmbiguous
                       then filter (`notElem` "0O1lI") charset
                       else charset
    
    bytes <- generateRandomBytes length
    let password = map (\b -> finalCharset !! (fromIntegral b `mod` length finalCharset)) $ BS.unpack bytes
    
    return password

-- | Hash file with multiple algorithms
hashFile :: FilePath -> IO ()
hashFile filepath = do
    content <- BS.readFile filepath
    
    let sha256 = Hash.hashWith Hash.SHA256 content
    let sha512 = Hash.hashWith Hash.SHA512 content
    let sha3_256 = Hash.hashWith Hash.SHA3_256 content
    let blake2b = Hash.hashWith Hash.Blake2b_256 content
    
    putStrLn $ "File: " ++ filepath
    putStrLn $ "SHA-256:   " ++ show sha256
    putStrLn $ "SHA-512:   " ++ show sha512
    putStrLn $ "SHA3-256:  " ++ show sha3_256
    putStrLn $ "BLAKE2b:   " ++ show blake2b

-- | Steganography - hide data in image
hideInImage :: FilePath -> BS.ByteString -> FilePath -> IO ()
hideInImage coverImage secretData outputImage = do
    -- Read cover image
    imageData <- BS.readFile coverImage
    
    -- Simple LSB steganography (placeholder - real implementation would parse image format)
    putStrLn "Steganography not fully implemented in this version"
    
    -- For now, just append encrypted data after image
    -- Real implementation would modify LSBs
    key <- generateRandomBytes 32
    nonce <- generateRandomBytes 12
    
    result <- encryptAESGCM key nonce secretData
    case result of
        Nothing -> putStrLn "Encryption failed"
        Just (ciphertext, tag) -> do
            let marker = BS8.pack "LCKDSCL"  -- Magic marker
            let hiddenData = BS.concat [marker, key, nonce, tag, ciphertext]
            BS.writeFile outputImage (imageData <> hiddenData)
            putStrLn $ "Data hidden in: " ++ outputImage

-- | Extract hidden data from image
extractFromImage :: FilePath -> IO ()
extractFromImage stegoImage = do
    imageData <- BS.readFile stegoImage
    
    let marker = BS8.pack "LCKDSCL"
    case BS8.breakSubstring marker imageData of
        (_, "") -> putStrLn "No hidden data found"
        (_, rest) -> do
            let hiddenData = BS.drop (BS.length marker) rest
            if BS.length hiddenData < 60 then
                putStrLn "Corrupted hidden data"
            else do
                let key = BS.take 32 hiddenData
                let nonce = BS.take 12 $ BS.drop 32 hiddenData
                let tag = BS.take 16 $ BS.drop 44 hiddenData
                let ciphertext = BS.drop 60 hiddenData
                
                case decryptAESGCM key nonce ciphertext tag of
                    Nothing -> putStrLn "Failed to decrypt hidden data"
                    Just plaintext -> do
                        putStrLn "Extracted hidden data:"
                        BS8.putStrLn plaintext

-- | Main entry point
main :: IO ()
main = do
    args <- getArgs
    case args of
        ["encrypt", filepath] -> do
            putStr "Enter password: "
            hFlush stdout
            password <- BS8.pack <$> getLine
            encryptFile filepath password
            
        ["decrypt", filepath] -> do
            putStr "Enter password: "
            hFlush stdout
            password <- BS8.pack <$> getLine
            decryptFile filepath password
            
        ["shred", filepath] -> secureDelete filepath
        
        ["hash", filepath] -> hashFile filepath
        
        ["password", lengthStr] -> do
            let length = read lengthStr :: Int
            password <- generatePassword length True True False
            putStrLn $ "Generated password: " ++ password
            
        ["hide", coverImage, secretFile, outputImage] -> do
            secretData <- BS.readFile secretFile
            hideInImage coverImage secretData outputImage
            
        ["extract", stegoImage] -> extractFromImage stegoImage
        
        ["random", countStr] -> do
            let count = read countStr :: Int
            bytes <- generateRandomBytes count
            BS8.putStrLn $ B64.encode bytes
            
        _ -> do
            putStrLn "Lackadaisical Crypto Tools"
            putStrLn "========================="
            putStrLn ""
            putStrLn "Usage:"
            putStrLn "  encrypt <file>                - Encrypt file"
            putStrLn "  decrypt <file>                - Decrypt file"
            putStrLn "  shred <file>                  - Securely delete file"
            putStrLn "  hash <file>                   - Calculate file hashes"
            putStrLn "  password <length>             - Generate secure password"
            putStrLn "  hide <image> <secret> <out>   - Hide data in image"
            putStrLn "  extract <image>               - Extract hidden data"
            putStrLn "  random <bytes>                - Generate random bytes"
            exitFailure

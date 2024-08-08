<?php
class AesCryptoClass {
    private $hmacLength = 32;
    private $iterations = 1000;
    private $keyLength = 32;
    private $blockSize = 16;
    private $cipher = 'aes-256-cbc';

    function __construct($password, $hmacKey, $salt) {
        $this->password = $password;
        $this->hmacKey  = $hmacKey;
        $this->salt     = $salt;
    }

    function encrypt($plainText) {
        $iv = openssl_random_pseudo_bytes(16);
        $encryptedBytes = $this->encryptInner($iv, $plainText);
        $encryptedMessage = $iv . $encryptedBytes;
        $mac = $this->hashMessage($encryptedMessage);
        $secureMessage = $mac . $encryptedMessage;
        $encryptedText = base64_encode($secureMessage);
        return $encryptedText;
    }

    function decrypt($encryptedText) {
        $secureMessage = base64_decode($encryptedText);
        $mac = substr($secureMessage, 0, $this->hmacLength);
        $encryptedMessage = substr($secureMessage, $this->hmacLength);
        $iv = substr($encryptedMessage, 0, 16);
        $encryptedBytes = substr($encryptedMessage, 16);
        $calculatedMac = $this->hashMessage($encryptedMessage);
        if (!hash_equals($mac, $calculatedMac)) {
            throw new Exception('MAC verification failed');
        }
        $plainText = $this->decryptInner($iv, $encryptedBytes);
        return $plainText;
    }

    private function encryptInner($iv, $plainText) {
        $key = hash_pbkdf2('sha256', $this->password, $this->salt, $this->iterations, $this->keyLength, true);
        return openssl_encrypt($plainText, $this->cipher, $key, OPENSSL_RAW_DATA, $iv);
    }

    private function decryptInner($iv, $encryptedBytes) {
        $key = hash_pbkdf2('sha256', $this->password, $this->salt, $this->iterations, $this->keyLength, true);
        return openssl_decrypt($encryptedBytes, $this->cipher, $key, OPENSSL_RAW_DATA, $iv);
    }

    private function hashMessage($message) {
        return hash_hmac('sha256', $message, $this->hmacKey, true);
    }
}

// การใช้งาน
$password = 'your_password';
$hmacKey = 'your_hmac_key';
$salt = 'your_salt';
$crypto = new AesCryptoClass($password, $hmacKey, $salt);

$plainText = 'Hello, World!';
$encryptedText = $crypto->encrypt($plainText);
echo "Encrypted: " . $encryptedText . "\n";

$decryptedText = $crypto->decrypt($encryptedText);
echo "Decrypted: " . $decryptedText . "\n";
?>

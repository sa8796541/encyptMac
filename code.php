<?php

$password = 'your_password';
$original_data = 'This is the data to encrypt';

$encrypted_data = encrypt($original_data, $password);
echo 'Encrypted: ' . $encrypted_data . "\n";

$decrypted_data = decrypt($encrypted_data, 'your_password');
echo 'Decrypted: ' . $decrypted_data . "\n";



function encrypt($data, $password) {
    $method = 'aes-256-cbc';
    $key = hash('sha256', $password, true);
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($method));
    $encrypted = openssl_encrypt($data, $method, $key, 0, $iv);
    return base64_encode($iv . $encrypted);
}


function decrypt($data, $password) {
    $method = 'aes-256-cbc';
    $key = hash('sha256', $password, true);
    $data = base64_decode($data);
    $iv = substr($data, 0, openssl_cipher_iv_length($method));
    $encrypted = substr($data, openssl_cipher_iv_length($method));
    return openssl_decrypt($encrypted, $method, $key, 0, $iv);
}
		  
?>

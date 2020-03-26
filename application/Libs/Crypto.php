<?php
function encryptH($data)
{
    $encrypted = openssl_encrypt($data, AES_256_CBC, KEY, 0, IV);
    $encrypted = base64_encode($encrypted);
    return $encrypted;
}
function decryptH($data)
{
    $decrypted = openssl_decrypt(base64_decode($data), AES_256_CBC, KEY, 0, IV);
    return $decrypted;
}
?>
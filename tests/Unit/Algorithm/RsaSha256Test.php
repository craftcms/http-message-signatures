<?php

declare(strict_types=1);

use HttpMessageSignatures\Algorithm\RsaSha256;
use HttpMessageSignatures\Exception\InvalidKeyException;

beforeEach(function () {
    // Generate test RSA key pair
    $config = [
        'digest_alg' => 'sha256',
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ];
    
    $resource = openssl_pkey_new($config);
    openssl_pkey_export($resource, $this->privateKey);
    
    $details = openssl_pkey_get_details($resource);
    $this->publicKey = $details['key'];
});

test('can sign data with RSA-SHA256', function () {
    $algorithm = new RsaSha256($this->privateKey, $this->publicKey);
    $data = 'test data';
    
    $signature = $algorithm->sign($data);
    
    expect($signature)
        ->toBeString()
        ->not->toBeEmpty()
        ->and(base64_decode($signature, true))->not->toBeFalse();
});

test('can verify valid signature', function () {
    $algorithm = new RsaSha256($this->privateKey, $this->publicKey);
    $data = 'test data';
    
    $signature = $algorithm->sign($data);
    
    expect($algorithm->verify($data, $signature))->toBeTrue();
});

test('rejects invalid signature', function () {
    $algorithm = new RsaSha256($this->privateKey, $this->publicKey);
    $data = 'test data';
    
    $invalidSignature = base64_encode('invalid signature');
    
    expect($algorithm->verify($data, $invalidSignature))->toBeFalse();
});

test('rejects signature for different data', function () {
    $algorithm = new RsaSha256($this->privateKey, $this->publicKey);
    $data1 = 'test data';
    $data2 = 'different data';
    
    $signature = $algorithm->sign($data1);
    
    expect($algorithm->verify($data2, $signature))->toBeFalse();
});

test('can extract public key from private key', function () {
    $algorithm = new RsaSha256($this->privateKey); // No public key provided
    $data = 'test data';
    
    $signature = $algorithm->sign($data);
    
    expect($algorithm->verify($data, $signature))->toBeTrue();
});

test('returns correct algorithm ID', function () {
    $algorithm = new RsaSha256($this->privateKey, $this->publicKey);
    
    expect($algorithm->getAlgorithmId())->toBe('rsa-sha256');
});

test('throws exception for invalid private key', function () {
    expect(fn() => new RsaSha256('invalid-key'))
        ->toThrow(InvalidKeyException::class);
});


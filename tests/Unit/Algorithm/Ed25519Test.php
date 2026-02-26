<?php

declare(strict_types=1);

use HttpMessageSignatures\Algorithm\Ed25519;
use HttpMessageSignatures\Exception\InvalidKeyException;

beforeEach(function () {
    if (!extension_loaded('sodium')) {
        $this->markTestSkipped('Sodium extension is not available');
    }
    
    // Generate test Ed25519 key pair
    $keyPair = sodium_crypto_sign_keypair();
    $this->privateKey = sodium_crypto_sign_secretkey($keyPair);
    $this->publicKey = sodium_crypto_sign_publickey($keyPair);
});

test('can sign data with Ed25519', function () {
    $algorithm = new Ed25519($this->privateKey, $this->publicKey);
    $data = 'test data';
    
    $signature = $algorithm->sign($data);
    
    expect($signature)
        ->toBeString()
        ->not->toBeEmpty()
        ->and(base64_decode($signature, true))->not->toBeFalse();
});

test('can verify valid signature', function () {
    $algorithm = new Ed25519($this->privateKey, $this->publicKey);
    $data = 'test data';
    
    $signature = $algorithm->sign($data);
    
    expect($algorithm->verify($data, $signature))->toBeTrue();
});

test('rejects invalid signature', function () {
    $algorithm = new Ed25519($this->privateKey, $this->publicKey);
    $data = 'test data';
    
    $invalidSignature = base64_encode('invalid signature');
    
    expect($algorithm->verify($data, $invalidSignature))->toBeFalse();
});

test('rejects signature for different data', function () {
    $algorithm = new Ed25519($this->privateKey, $this->publicKey);
    $data1 = 'test data';
    $data2 = 'different data';
    
    $signature = $algorithm->sign($data1);
    
    expect($algorithm->verify($data2, $signature))->toBeFalse();
});

test('can extract public key from private key', function () {
    $algorithm = new Ed25519($this->privateKey); // No public key provided
    $data = 'test data';
    
    $signature = $algorithm->sign($data);
    
    expect($algorithm->verify($data, $signature))->toBeTrue();
});

test('returns correct algorithm ID', function () {
    $algorithm = new Ed25519($this->privateKey, $this->publicKey);
    
    expect($algorithm->getAlgorithmId())->toBe('ed25519');
});

test('throws exception for empty private key', function () {
    expect(fn() => new Ed25519(''))
        ->toThrow(InvalidKeyException::class, 'Ed25519 private key cannot be empty');
});

test('throws exception when sodium extension is not loaded', function () {
    if (extension_loaded('sodium')) {
        $this->markTestSkipped('Sodium extension is available');
    }
    
    expect(fn() => new Ed25519('test-key'))
        ->toThrow(RuntimeException::class, 'Ed25519 requires the sodium extension');
});


<?php

declare(strict_types=1);

use HttpMessageSignatures\Algorithm\HmacSha256;
use HttpMessageSignatures\Exception\InvalidKeyException;

test('can sign data with HMAC-SHA256', function () {
    $algorithm = new HmacSha256('secret-key');
    $data = 'test data';
    
    $signature = $algorithm->sign($data);
    
    expect($signature)
        ->toBeString()
        ->not->toBeEmpty()
        ->and(base64_decode($signature, true))->not->toBeFalse();
});

test('can verify valid signature', function () {
    $algorithm = new HmacSha256('secret-key');
    $data = 'test data';
    
    $signature = $algorithm->sign($data);
    
    expect($algorithm->verify($data, $signature))->toBeTrue();
});

test('rejects invalid signature', function () {
    $algorithm = new HmacSha256('secret-key');
    $data = 'test data';
    
    $invalidSignature = base64_encode('invalid signature');
    
    expect($algorithm->verify($data, $invalidSignature))->toBeFalse();
});

test('rejects signature for different data', function () {
    $algorithm = new HmacSha256('secret-key');
    $data1 = 'test data';
    $data2 = 'different data';
    
    $signature = $algorithm->sign($data1);
    
    expect($algorithm->verify($data2, $signature))->toBeFalse();
});

test('rejects signature with different key', function () {
    $algorithm1 = new HmacSha256('secret-key-1');
    $algorithm2 = new HmacSha256('secret-key-2');
    $data = 'test data';
    
    $signature = $algorithm1->sign($data);
    
    expect($algorithm2->verify($data, $signature))->toBeFalse();
});

test('throws exception for empty secret key', function () {
    expect(fn() => new HmacSha256(''))
        ->toThrow(InvalidKeyException::class, 'HMAC secret key cannot be empty');
});

test('returns correct algorithm ID', function () {
    $algorithm = new HmacSha256('secret-key');
    
    expect($algorithm->getAlgorithmId())->toBe('hmac-sha256');
});

test('produces deterministic signatures', function () {
    $algorithm = new HmacSha256('secret-key');
    $data = 'test data';
    
    $signature1 = $algorithm->sign($data);
    $signature2 = $algorithm->sign($data);
    
    expect($signature1)->toBe($signature2);
});


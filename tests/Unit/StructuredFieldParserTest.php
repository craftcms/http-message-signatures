<?php

declare(strict_types=1);

use HttpMessageSignatures\StructuredFieldParser;

beforeEach(function () {
    $this->parser = new StructuredFieldParser();
});

test('parses signature-input header', function () {
    $value = 'sig1=("@method" "@path" "@authority");created=1234567890;keyid="test-key"';
    
    $result = $this->parser->parseSignatureInput($value);
    
    expect($result)->toHaveKey('sig1')
        ->and($result['sig1']['components'])->toBe(['@method', '@path', '@authority'])
        ->and($result['sig1']['params'])->toHaveKey('created')
        ->and($result['sig1']['params']['created'])->toBe(1234567890)
        ->and($result['sig1']['params']['keyid'])->toBe('test-key');
});

test('parses signature-input with multiple signatures', function () {
    $value = 'sig1=("@method" "@path");created=1234567890, sig2=("host" "date");created=1234567891';
    
    $result = $this->parser->parseSignatureInput($value);
    
    expect($result)->toHaveKeys(['sig1', 'sig2'])
        ->and($result['sig1']['components'])->toBe(['@method', '@path'])
        ->and($result['sig2']['components'])->toBe(['host', 'date']);
});

test('parses signature header', function () {
    $value = 'sig1=:dGVzdC1zaWduYXR1cmU=:';
    
    $result = $this->parser->parseSignature($value);
    
    expect($result)->toHaveKey('sig1')
        ->and($result['sig1'])->toBe('dGVzdC1zaWduYXR1cmU=');
});

test('parses signature header with multiple signatures', function () {
    $value = 'sig1=:dGVzdC1zaWduYXR1cmUx=:, sig2=:dGVzdC1zaWduYXR1cmUy=:';
    
    $result = $this->parser->parseSignature($value);
    
    expect($result)->toHaveKeys(['sig1', 'sig2'])
        ->and($result['sig1'])->toBe('dGVzdC1zaWduYXR1cmUx=')
        ->and($result['sig2'])->toBe('dGVzdC1zaWduYXR1cmUy=');
});

test('formats signature-input header', function () {
    $components = ['@method', '@path', '@authority'];
    $parameters = [
        'created' => 1234567890,
        'keyid' => 'test-key',
    ];
    
    $result = $this->parser->formatSignatureInput('sig1', $components, $parameters);
    
    expect($result)->toBeString()
        ->and($result)->toContain('sig1=')
        ->and($result)->toContain('@method')
        ->and($result)->toContain('@path')
        ->and($result)->toContain('@authority');
});

test('formats signature-input with expires parameter', function () {
    $components = ['@method', '@path'];
    $parameters = [
        'created' => 1234567890,
        'expires' => 1234567890 + 300,
        'keyid' => 'test-key',
    ];
    
    $result = $this->parser->formatSignatureInput('sig1', $components, $parameters);
    
    expect($result)->toBeString()
        ->and($result)->toContain('expires=');
});

test('formats signature header', function () {
    $signature = 'dGVzdC1zaWduYXR1cmU=';
    
    $result = $this->parser->formatSignature('sig1', $signature);
    
    expect($result)->toBeString()
        ->and($result)->toContain('sig1=:')
        ->and($result)->toContain($signature);
});

test('round-trip signature-input parsing and formatting', function () {
    $components = ['@method', '@path', '@authority'];
    $parameters = [
        'created' => 1234567890,
        'keyid' => 'test-key',
    ];
    
    $formatted = $this->parser->formatSignatureInput('sig1', $components, $parameters);
    $parsed = $this->parser->parseSignatureInput($formatted);
    
    expect($parsed)->toHaveKey('sig1')
        ->and($parsed['sig1']['components'])->toBe($components)
        ->and($parsed['sig1']['params']['created'])->toBe($parameters['created'])
        ->and($parsed['sig1']['params']['keyid'])->toBe($parameters['keyid']);
});


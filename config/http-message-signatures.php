<?php

declare(strict_types=1);

return [
    /*
    |--------------------------------------------------------------------------
    | Default Algorithm
    |--------------------------------------------------------------------------
    |
    | The default signature algorithm to use when none is specified.
    | Supported: 'hmac-sha256', 'rsa-sha256', 'ed25519'
    |
    */
    'default_algorithm' => env('HTTP_SIGNATURE_ALGORITHM', 'hmac-sha256'),

    /*
    |--------------------------------------------------------------------------
    | HMAC Secret Key
    |--------------------------------------------------------------------------
    |
    | The secret key used for HMAC-SHA256 signatures.
    | This should be set in your .env file for security.
    |
    */
    'hmac_secret_key' => env('HTTP_SIGNATURE_HMAC_SECRET_KEY'),

    /*
    |--------------------------------------------------------------------------
    | RSA Private Key Path
    |--------------------------------------------------------------------------
    |
    | Path to the RSA private key file for RSA-SHA256 signatures.
    | This should be set in your .env file.
    |
    */
    'rsa_private_key_path' => env('HTTP_SIGNATURE_RSA_PRIVATE_KEY_PATH'),

    /*
    |--------------------------------------------------------------------------
    | RSA Public Key Path
    |--------------------------------------------------------------------------
    |
    | Path to the RSA public key file for RSA-SHA256 signatures.
    | This should be set in your .env file.
    |
    */
    'rsa_public_key_path' => env('HTTP_SIGNATURE_RSA_PUBLIC_KEY_PATH'),

    /*
    |--------------------------------------------------------------------------
    | Ed25519 Private Key Path
    |--------------------------------------------------------------------------
    |
    | Path to the Ed25519 private key file for Ed25519 signatures.
    | This should be set in your .env file.
    |
    */
    'ed25519_private_key_path' => env('HTTP_SIGNATURE_ED25519_PRIVATE_KEY_PATH'),

    /*
    |--------------------------------------------------------------------------
    | Ed25519 Public Key Path
    |--------------------------------------------------------------------------
    |
    | Path to the Ed25519 public key file for Ed25519 signatures.
    | This should be set in your .env file.
    |
    */
    'ed25519_public_key_path' => env('HTTP_SIGNATURE_ED25519_PUBLIC_KEY_PATH'),

    /*
    |--------------------------------------------------------------------------
    | Default Key ID
    |--------------------------------------------------------------------------
    |
    | The default key identifier to use when signing messages.
    |
    */
    'default_key_id' => env('HTTP_SIGNATURE_KEY_ID', 'default'),

    /*
    |--------------------------------------------------------------------------
    | Default Signature ID
    |--------------------------------------------------------------------------
    |
    | The default signature identifier to use when signing messages.
    |
    */
    'default_signature_id' => env('HTTP_SIGNATURE_SIGNATURE_ID', 'sig1'),

    /*
    |--------------------------------------------------------------------------
    | Default Components
    |--------------------------------------------------------------------------
    |
    | The default components to include when signing messages.
    | These can be overridden when calling the signer.
    |
    */
    'default_components' => [
        '@method',
        '@path',
        '@authority',
        'content-type',
        'date',
    ],
];


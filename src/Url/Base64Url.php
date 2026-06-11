<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Url;

use HttpMessageSignatures\Exception\VerificationException;

final class Base64Url
{
    public static function encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * @throws VerificationException
     */
    public static function decode(string $data): string
    {
        if ($data === '' || preg_match('/\A[A-Za-z0-9_-]+\z/', $data) !== 1 || strlen($data) % 4 === 1) {
            throw new VerificationException('Invalid base64url data');
        }

        // PHP only supports standard base64 natively, so normalize RFC 4648
        // base64url into padded base64 before decoding. If this needs more
        // surface area, prefer a focused package like spomky-labs/base64url.
        $paddingLength = (4 - strlen($data) % 4) % 4;
        $paddedData = $data . str_repeat('=', $paddingLength);
        $decoded = base64_decode(strtr($paddedData, '-_', '+/'), true);

        if ($decoded === false) {
            throw new VerificationException('Invalid base64url data');
        }

        return $decoded;
    }
}

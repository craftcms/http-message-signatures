<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Url;

use Uri\Rfc3986\Uri;

final class UrlQueryHelper
{
    /**
     * Strip named parameters from a URI's query string.
     *
     * @param  array<string>  $paramNames  Parameter names to remove
     */
    public static function stripParams(Uri $uri, array $paramNames): Uri
    {
        $query = $uri->getQuery();

        if ($query === null) {
            return $uri;
        }

        $pairs = [];

        foreach (explode('&', $query) as $pair) {
            if ($pair === '') {
                continue;
            }

            $name = explode('=', $pair, 2)[0];

            if (!in_array(urldecode($name), $paramNames, true)) {
                $pairs[] = $pair;
            }
        }

        return $uri->withQuery($pairs === [] ? null : implode('&', $pairs));
    }

    /**
     * Append key-value pairs to a URI's query string.
     *
     * Returns a plain URL string rather than a Uri object to avoid strict
     * RFC 3986 validation issues with structured field characters in values.
     *
     * @param  array<string, string>  $params  Parameters to append (values will be URL-encoded)
     */
    public static function appendParams(Uri $uri, array $params): string
    {
        $url = $uri->toString();
        $fragment = $uri->getFragment();

        // Temporarily strip fragment for manipulation
        if ($fragment !== null) {
            $url = substr($url, 0, -(strlen($fragment) + 1));
        }

        $separator = $uri->getQuery() !== null ? '&' : '?';

        $pairs = [];

        foreach ($params as $name => $value) {
            $pairs[] = rawurlencode($name) . '=' . rawurlencode($value);
        }

        $url .= $separator . implode('&', $pairs);

        if ($fragment !== null) {
            $url .= '#' . $fragment;
        }

        return $url;
    }

    /**
     * Extract a single query parameter value from a URI.
     *
     * @return string|null The URL-decoded value, or null if not found
     */
    public static function extractParam(Uri $uri, string $paramName): ?string
    {
        $query = $uri->getQuery();

        if ($query === null) {
            return null;
        }

        foreach (explode('&', $query) as $pair) {
            $parts = explode('=', $pair, 2);
            $name = urldecode($parts[0]);

            if ($name === $paramName) {
                return isset($parts[1]) ? urldecode($parts[1]) : '';
            }
        }

        return null;
    }

    /**
     * Base64url encode (RFC 4648 Section 5), no padding.
     */
    public static function base64urlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Base64url decode (RFC 4648 Section 5).
     */
    public static function base64urlDecode(string $data): string
    {
        $decoded = base64_decode(strtr($data, '-_', '+/'), true);

        if ($decoded === false) {
            throw new \InvalidArgumentException('Invalid base64url data');
        }

        return $decoded;
    }
}

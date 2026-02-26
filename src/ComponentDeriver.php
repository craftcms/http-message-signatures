<?php

declare(strict_types=1);

namespace HttpMessageSignatures;

use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Derives signature components from HTTP messages.
 */
class ComponentDeriver
{
    /**
     * Derive a component value from the message.
     *
     * @param string $component The component identifier (e.g., "@method", "@path", "host")
     * @param MessageInterface $message The HTTP message
     * @param RequestInterface|null $originalRequest The original request (for response signing)
     * @return string The derived component value
     */
    public function deriveComponent(
        string $component,
        MessageInterface $message,
        ?RequestInterface $originalRequest = null
    ): string {
        if ($this->isDerivedComponent($component)) {
            return $this->deriveDerivedComponent($component, $message, $originalRequest);
        }

        if ($this->isQueryParameterComponent($component)) {
            return $this->deriveQueryParameterComponent($component, $message);
        }

        return $this->deriveHeaderComponent($component, $message);
    }

    private function isDerivedComponent(string $component): bool
    {
        return str_starts_with($component, '@') && !str_starts_with($component, DerivedComponents::QUERY_PARAM_PREFIX);
    }

    private function isQueryParameterComponent(string $component): bool
    {
        return str_starts_with($component, DerivedComponents::QUERY_PARAM_PREFIX);
    }

    private function deriveDerivedComponent(
        string $component,
        MessageInterface $message,
        ?RequestInterface $originalRequest
    ): string {
        $this->ensureMessageIsRequest($message, 'Derived components require a RequestInterface');

        return match ($component) {
            DerivedComponents::METHOD => $this->deriveMethod($message),
            DerivedComponents::PATH => $this->derivePath($message),
            DerivedComponents::QUERY => $this->deriveQuery($message),
            DerivedComponents::AUTHORITY => $this->deriveAuthority($message),
            DerivedComponents::SCHEME => $this->deriveScheme($message),
            DerivedComponents::TARGET_URI => $this->deriveTargetUri($message),
            DerivedComponents::REQUEST_TARGET => $this->deriveRequestTarget($message),
            DerivedComponents::STATUS => $this->deriveStatus($message),
            default => throw new \InvalidArgumentException("Unknown derived component: {$component}"),
        };
    }

    private function deriveMethod(MessageInterface $message): string
    {
        assert($message instanceof RequestInterface);
        return strtoupper($message->getMethod());
    }

    private function derivePath(MessageInterface $message): string
    {
        assert($message instanceof RequestInterface);
        return $message->getUri()->getPath();
    }

    private function deriveQuery(MessageInterface $message): string
    {
        assert($message instanceof RequestInterface);
        return $message->getUri()->getQuery();
    }

    private function deriveAuthority(MessageInterface $message): string
    {
        assert($message instanceof RequestInterface);
        $uri = $message->getUri();
        $host = $uri->getHost();
        $port = $uri->getPort();

        $isNonDefaultPort = $port !== null && $this->isNonDefaultPortForScheme($port, $uri->getScheme());

        return $isNonDefaultPort ? "{$host}:{$port}" : $host;
    }

    private function isNonDefaultPortForScheme(?int $port, string $scheme): bool
    {
        $defaultPort = $this->getDefaultPortForScheme($scheme);
        return $port !== $defaultPort;
    }

    private function getDefaultPortForScheme(string $scheme): int
    {
        return match (strtolower($scheme)) {
            'https' => DefaultValues::DEFAULT_HTTPS_PORT,
            'http' => DefaultValues::DEFAULT_HTTP_PORT,
            default => 0, // Unknown scheme, treat as non-default
        };
    }

    private function deriveScheme(MessageInterface $message): string
    {
        assert($message instanceof RequestInterface);
        return $message->getUri()->getScheme();
    }

    private function deriveTargetUri(MessageInterface $message): string
    {
        assert($message instanceof RequestInterface);
        return (string) $message->getUri();
    }

    private function deriveRequestTarget(MessageInterface $message): string
    {
        assert($message instanceof RequestInterface);
        $requestTarget = $message->getRequestTarget();

        if ($requestTarget !== '/') {
            return $requestTarget;
        }

        $uri = $message->getUri();
        $path = $uri->getPath() ?: '/';
        $query = $uri->getQuery();

        return $query ? "{$path}?{$query}" : $path;
    }

    private function deriveStatus(MessageInterface $message): string
    {
        $this->ensureMessageIsResponse($message, '@status requires a ResponseInterface');
        assert($message instanceof ResponseInterface);
        return (string) $message->getStatusCode();
    }

    private function deriveQueryParameterComponent(string $component, MessageInterface $message): string
    {
        $this->ensureMessageIsRequest($message, 'Query parameters require a RequestInterface');
        assert($message instanceof RequestInterface);

        $parameterName = $this->extractQueryParameterName($component);
        $queryString = $message->getUri()->getQuery();
        $queryParameters = $this->parseQueryString($queryString);

        return $queryParameters[$parameterName] ?? '';
    }

    private function extractQueryParameterName(string $component): string
    {
        $matches = [];
        $pattern = '/@query-param(?:;name="([^"]+)")?/';
        $hasMatch = preg_match($pattern, $component, $matches);

        if (!$hasMatch) {
            throw new \InvalidArgumentException("Invalid query parameter component: {$component}");
        }

        $parameterName = $matches[1] ?? '';
        if (empty($parameterName)) {
            throw new \InvalidArgumentException('Query parameter name is required');
        }

        return $parameterName;
    }

    private function parseQueryString(string $queryString): array
    {
        $parameters = [];
        parse_str($queryString, $parameters);
        return $parameters;
    }

    private function deriveHeaderComponent(string $headerName, MessageInterface $message): string
    {
        $normalizedHeaderName = strtolower($headerName);
        $headerValues = $message->getHeader($normalizedHeaderName);

        if (empty($headerValues)) {
            return '';
        }

        // RFC 9421: Multiple header values are joined with ", "
        return implode(', ', $headerValues);
    }

    private function ensureMessageIsRequest(MessageInterface $message, string $errorMessage): void
    {
        if (!$message instanceof RequestInterface) {
            throw new \InvalidArgumentException($errorMessage);
        }
    }

    private function ensureMessageIsResponse(MessageInterface $message, string $errorMessage): void
    {
        if (!$message instanceof ResponseInterface) {
            throw new \InvalidArgumentException($errorMessage);
        }
    }
}

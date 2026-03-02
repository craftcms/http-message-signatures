<?php

declare(strict_types=1);

namespace HttpMessageSignatures;

use Bakame\Http\StructuredFields\Item;
use Bakame\Http\StructuredFields\Token;
use InvalidArgumentException;
use League\Uri\Components\Query;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Derives component values from HTTP messages per RFC 9421 Section 2.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9421.html#section-2
 */
class ComponentDeriver
{
    /**
     * Derive a component value from the message.
     *
     * @param  Item  $componentId  A bakame Item representing the component identifier (e.g., Token "@method" or string "content-type")
     * @param  MessageInterface  $message  The HTTP message
     * @param  RequestInterface|null  $originalRequest  The original request (for response signing with request-bound components)
     * @return string The derived component value
     */
    public function deriveComponent(
        Item $componentId,
        MessageInterface $message,
        RequestInterface $originalRequest = null,
    ): string {
        $value = $componentId->value();

        // Per RFC 9421, component identifiers are string Items
        if (is_string($value)) {
            if (str_starts_with($value, '@')) {
                return $this->deriveDerivedComponent($value, $componentId, $message, $originalRequest);
            }

            return $this->deriveHeaderComponent($value, $message);
        }

        // Also support Token values for backwards compatibility
        if ($value instanceof Token) {
            $name = $value->toString();

            if (str_starts_with($name, '@')) {
                return $this->deriveDerivedComponent($name, $componentId, $message, $originalRequest);
            }

            return $this->deriveHeaderComponent($name, $message);
        }

        throw new InvalidArgumentException('Component identifier must be a string or token value');
    }

    private function deriveDerivedComponent(
        string $name,
        Item $componentId,
        MessageInterface $message,
        ?RequestInterface $originalRequest,
    ): string {
        return match ($name) {
            '@method' => $this->deriveMethod($this->resolveRequest($message, $originalRequest, $name)),
            '@target-uri' => $this->deriveTargetUri($this->resolveRequest($message, $originalRequest, $name)),
            '@authority' => $this->deriveAuthority($this->resolveRequest($message, $originalRequest, $name)),
            '@scheme' => $this->deriveScheme($this->resolveRequest($message, $originalRequest, $name)),
            '@request-target' => $this->deriveRequestTarget($this->resolveRequest($message, $originalRequest, $name)),
            '@path' => $this->derivePath($this->resolveRequest($message, $originalRequest, $name)),
            '@query' => $this->deriveQuery($this->resolveRequest($message, $originalRequest, $name)),
            '@query-param' => $this->deriveQueryParam($componentId, $this->resolveRequest(
                $message,
                $originalRequest,
                $name,
            )),
            '@status' => $this->deriveStatus($message),
            default => throw new InvalidArgumentException("Unknown derived component: {$name}"),
        };
    }

    /**
     * Resolve the request to use for request-targeted derived components.
     * For responses, uses the original request if provided.
     */
    private function resolveRequest(
        MessageInterface $message,
        ?RequestInterface $originalRequest,
        string $componentName,
    ): RequestInterface {
        if ($message instanceof RequestInterface) {
            return $message;
        }

        if ($originalRequest !== null) {
            return $originalRequest;
        }

        throw new InvalidArgumentException(
            "Derived component {$componentName} requires a RequestInterface or an original request for response signing",
        );
    }

    /**
     * @see https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.1
     */
    private function deriveMethod(RequestInterface $request): string
    {
        return strtoupper($request->getMethod());
    }

    /**
     * @see https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.2
     */
    private function deriveTargetUri(RequestInterface $request): string
    {
        return (string) $request->getUri();
    }

    /**
     * @see https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.3
     */
    private function deriveAuthority(RequestInterface $request): string
    {
        $uri = $request->getUri();
        $host = strtolower($uri->getHost());
        $port = $uri->getPort();
        $scheme = strtolower($uri->getScheme());

        if ($port !== null && !$this->isDefaultPort($port, $scheme)) {
            return "{$host}:{$port}";
        }

        return $host;
    }

    /**
     * @see https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.4
     */
    private function deriveScheme(RequestInterface $request): string
    {
        return strtolower($request->getUri()->getScheme());
    }

    /**
     * @see https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.5
     */
    private function deriveRequestTarget(RequestInterface $request): string
    {
        return $request->getRequestTarget();
    }

    /**
     * RFC 9421 Section 2.2.6: The value is the absolute path of the request target.
     * An empty path is normalized to "/".
     *
     * @see https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.6
     */
    private function derivePath(RequestInterface $request): string
    {
        $path = $request->getUri()->getPath();

        return $path === '' ? '/' : $path;
    }

    /**
     * RFC 9421 Section 2.2.7: The value is the query component, including
     * the leading "?" character. If the query is absent, the value is "?".
     *
     * @see https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.7
     */
    private function deriveQuery(RequestInterface $request): string
    {
        $query = $request->getUri()->getQuery();

        return '?' . $query;
    }

    /**
     * RFC 9421 Section 2.2.8: Derive a specific query parameter value.
     * The parameter name is taken from the component identifier's "name" parameter.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.8
     */
    private function deriveQueryParam(Item $componentId, RequestInterface $request): string
    {
        $paramName = $componentId->parameterByKey('name');

        if ($paramName === null || !is_string($paramName)) {
            throw new InvalidArgumentException('@query-param requires a "name" parameter');
        }

        // Parse using League URI (RFC3986 semantics), compare decoded name,
        // then canonicalize by percent-encoding the decoded value.
        foreach (Query::fromUri($request->getUri())->pairs() as $name => $value) {
            if ($name === $paramName) {
                return rawurlencode($value ?? '');
            }
        }

        throw new InvalidArgumentException("Query parameter \"{$paramName}\" not found in request");
    }

    /**
     * RFC 9421 Section 2.2.9: The value is the status code of the response.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.9
     */
    private function deriveStatus(MessageInterface $message): string
    {
        if (!$message instanceof ResponseInterface) {
            throw new InvalidArgumentException('@status requires a ResponseInterface');
        }

        return (string) $message->getStatusCode();
    }

    /**
     * RFC 9421 Section 2.1: Derive an HTTP header field value.
     * Multiple header values are combined with ", ".
     *
     * @see https://www.rfc-editor.org/rfc/rfc9421.html#section-2.1
     */
    private function deriveHeaderComponent(string $headerName, MessageInterface $message): string
    {
        $normalizedHeaderName = strtolower($headerName);
        $headerValues = $message->getHeader($normalizedHeaderName);

        if ($headerValues === []) {
            throw new InvalidArgumentException("Header \"{$normalizedHeaderName}\" not found in message");
        }

        return implode(', ', $headerValues);
    }

    private function isDefaultPort(int $port, string $scheme): bool
    {
        return match ($scheme) {
            'https' => $port === 443,
            'http' => $port === 80,
            default => false,
        };
    }
}

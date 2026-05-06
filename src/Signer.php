<?php

declare(strict_types=1);

namespace HttpMessageSignatures;

use Bakame\Http\StructuredFields\Dictionary;
use Bakame\Http\StructuredFields\InnerList;
use Bakame\Http\StructuredFields\Item;
use Bakame\Http\StructuredFields\Parameters;
use HttpMessageSignatures\Algorithm\AlgorithmInterface;
use HttpMessageSignatures\Exception\SignatureException;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;

/**
 * Signs HTTP messages according to RFC 9421.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9421.html#section-3.1
 */
class Signer
{
    private SignatureBase $signatureBase;

    public function __construct(
        private readonly AlgorithmInterface $algorithm,
        ?SignatureBase $signatureBase = null,
    ) {
        $this->signatureBase = $signatureBase ?? new SignatureBase();
    }

    /**
     * Sign an HTTP message.
     *
     * @param  MessageInterface  $message  The message to sign
     * @param  array<string>  $components  Component identifier strings (e.g., ["@method", "@path", "content-type"])
     * @param  array<string, mixed>  $options  Signing options:
     *                                         - signatureId: string (default: "sig1") - Signature label
     *                                         - keyid: string|null - Key identifier
     *                                         - created: int|false|null - Creation timestamp (defaults to current time, false to omit)
     *                                         - expires: int|null - Expiration timestamp
     *                                         - nonce: string|null - Nonce value
     *                                         - tag: string|null - Tag value
     *                                         - originalRequest: RequestInterface|null - Original request (for response signing)
     * @return MessageInterface The signed message with Signature and Signature-Input headers
     *
     * @throws SignatureException
     */
    public function sign(MessageInterface $message, array $components, array $options = []): MessageInterface
    {
        if ($components === []) {
            throw new SignatureException('At least one component must be specified');
        }

        $signatureId = $options['signatureId'] ?? 'sig1';
        $originalRequest = $options['originalRequest'] ?? null;

        // Convert component strings to bakame Item objects
        $componentItems = array_map(self::parseComponentIdentifier(...), $components);

        // Build signature parameters
        $signatureParameters = $this->buildSignatureParameters($options);

        // Create the InnerList: (component-items);params
        $signatureInput = InnerList::fromAssociative($componentItems, $signatureParameters);

        // Build the signature base string
        $signatureBaseString = $this->signatureBase->build($signatureInput, $message, $originalRequest);

        // Sign the base string (returns raw bytes)
        $rawSignature = $this->algorithm->sign($signatureBaseString);

        // Build the Signature-Input and Signature headers as Dictionaries
        $signatureInputDict = Dictionary::new()->add($signatureId, $signatureInput);
        $signatureDict = Dictionary::new()->add($signatureId, Item::fromDecodedBytes($rawSignature));

        // Append headers to the message
        $message = $this->appendHeader($message, 'Signature-Input', $signatureInputDict->toHttpValue());
        $message = $this->appendHeader($message, 'Signature', $signatureDict->toHttpValue());

        return $message;
    }

    /**
     * Parse a component identifier string into a bakame Item.
     *
     * Per RFC 9421, component identifiers are serialized as string Items
     * in the inner list (e.g., "@method", "content-type").
     *
     * Accepts both user-friendly and structured field formats:
     * - "@method" -> Item with string value "@method"
     * - "content-type" -> Item with string value "content-type"
     * - '@query-param;name="foo"' -> parsed as structured field Item with parameters
     */
    public static function parseComponentIdentifier(string $identifier): Item
    {
        // If it contains parameters (e.g., @query-param;name="foo"), parse as structured field Item
        if (str_contains($identifier, ';')) {
            // Ensure the base identifier is quoted for structured field parsing
            // User may pass @query-param;name="foo" but we need "@query-param";name="foo"
            if (!str_starts_with($identifier, '"')) {
                /** @var int $semiPos — guaranteed by str_contains check above */
                $semiPos = (int) strpos($identifier, ';');
                $base = substr($identifier, 0, $semiPos);
                $params = substr($identifier, $semiPos);
                $identifier = '"' . strtolower($base) . '"' . $params;
            }

            return Item::fromHttpValue($identifier);
        }

        // All component identifiers are string Items in RFC 9421
        return Item::fromString(strtolower($identifier));
    }

    /**
     * Build signature parameters from options.
     *
     * @param  array<string, mixed>  $options
     */
    private function buildSignatureParameters(array $options): Parameters
    {
        $params = [];

        // created: defaults to current time, set to false to omit
        $created = $options['created'] ?? time();
        if ($created !== false) {
            $params['created'] = (int) $created;
        }

        // Optional parameters
        if (isset($options['expires'])) {
            $params['expires'] = (int) $options['expires'];
        }

        if (isset($options['nonce'])) {
            $params['nonce'] = (string) $options['nonce'];
        }

        // alg: always set from the algorithm
        $algId = $this->algorithm->getAlgorithmId();
        if ($algId !== '') {
            $params['alg'] = $algId;
        }

        if (isset($options['keyid'])) {
            $params['keyid'] = (string) $options['keyid'];
        }

        if (isset($options['tag'])) {
            $params['tag'] = (string) $options['tag'];
        }

        return Parameters::fromAssociative($params);
    }

    /**
     * Append a header to the message, preserving existing values.
     */
    private function appendHeader(MessageInterface $message, string $headerName, string $headerValue): MessageInterface
    {
        $existingHeaderValues = $message->getHeader($headerName);

        if ($existingHeaderValues !== []) {
            $combinedHeaderValue = implode(', ', $existingHeaderValues) . ', ' . $headerValue;

            return $message->withHeader($headerName, $combinedHeaderValue);
        }

        return $message->withHeader($headerName, $headerValue);
    }
}

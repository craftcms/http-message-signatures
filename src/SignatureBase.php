<?php

declare(strict_types=1);

namespace HttpMessageSignatures;

use Bakame\Http\StructuredFields\InnerList;
use Bakame\Http\StructuredFields\Item;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;

/**
 * Builds the signature base string per RFC 9421 Section 2.5.
 *
 * The signature base is a canonicalized string representation of the
 * covered message components and signature parameters. It is the input
 * to the signing and verification algorithms.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9421.html#section-2.5
 */
class SignatureBase
{
    public function __construct(
        private readonly ComponentDeriver $componentDeriver = new ComponentDeriver(),
    ) {}

    /**
     * Build the signature base string.
     *
     * @param  InnerList  $signatureInput  The signature input inner list containing component identifiers and signature parameters
     * @param  MessageInterface  $message  The HTTP message being signed or verified
     * @param  RequestInterface|null  $originalRequest  The original request (for response signing)
     * @return string The canonical signature base string
     */
    public function build(
        InnerList $signatureInput,
        MessageInterface $message,
        ?RequestInterface $originalRequest = null,
    ): string {
        $lines = [];

        // For each component identifier in the covered components list
        foreach ($signatureInput as $componentItem) {
            /** @var Item $componentItem */
            $componentValue = $this->componentDeriver->deriveComponent($componentItem, $message, $originalRequest);

            // Output per RFC 9421 Section 2.5: the serialized component identifier
            // followed by ": " and the component value.
            // toHttpValue() already includes quotes for string Items (e.g., "@method")
            $serializedId = $componentItem->toHttpValue();
            $lines[] = "{$serializedId}: {$componentValue}";
        }

        // Final line: "@signature-params": <inner-list-serialized>
        $signatureParamsValue = $signatureInput->toHttpValue();
        $lines[] = "\"@signature-params\": {$signatureParamsValue}";

        return implode("\n", $lines);
    }
}

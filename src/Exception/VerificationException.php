<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Exception;

/**
 * Exception thrown when signature verification fails.
 */
class VerificationException extends \RuntimeException implements ExceptionInterface
{
}


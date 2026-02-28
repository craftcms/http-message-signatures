<?php

declare(strict_types=1);

namespace HttpMessageSignatures\Exception;

/**
 * Exception thrown when signature operations fail.
 */
class SignatureException extends \RuntimeException implements ExceptionInterface {}

<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Security\Http\RateLimiter;

use Symfony\Component\HttpFoundation\RateLimiter\AbstractRequestRateLimiter;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Security\Core\Exception\InvalidArgumentException;
use Symfony\Component\Security\Http\SecurityRequestAttributes;

/**
 * A default login throttling limiter.
 *
 * This limiter prevents breadth-first and distributed brute-force attacks by
 * enforcing three limits in sequence:
 *   1. IP only (global): blocks wide scans from a single IP;
 *   2. username + IP (local): blocks targeted attacks from a single IP;
 *   3. username only: blocks distributed botnet attacks across many IPs.
 *
 * @author Wouter de Jong <wouter@wouterj.nl>
 */
final class DefaultLoginRateLimiter extends AbstractRequestRateLimiter
{
    /**
     * @param non-empty-string $secret A secret to use for hashing the IP address and username
     */
    public function __construct(
        private RateLimiterFactory $globalFactory,
        private RateLimiterFactory $localFactory,
        #[\SensitiveParameter] private string $secret,
        private ?RateLimiterFactory $usernameFactory = null,
    ) {
        if (!$secret) {
            throw new InvalidArgumentException('A non-empty secret is required.');
        }
    }

    protected function getLimiters(Request $request): array
    {
        $username = $request->attributes->get(SecurityRequestAttributes::LAST_USERNAME, '');
        $username = preg_match('//u', $username) ? mb_strtolower($username, 'UTF-8') : strtolower($username);

        $limiters = [
            $this->globalFactory->create($this->hash($request->getClientIp())),
            $this->localFactory->create($this->hash($username.'-'.$request->getClientIp())),
        ];

        if (null !== $this->usernameFactory) {
            $limiters[] = $this->usernameFactory->create($this->hash($username));
        }

        return $limiters;
    }

    private function hash(string $data): string
    {
        return strtr(substr(base64_encode(hash_hmac('sha256', $data, $this->secret, true)), 0, 8), '/+', '._');
    }
}

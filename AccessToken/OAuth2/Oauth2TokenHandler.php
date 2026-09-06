<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Security\Http\AccessToken\OAuth2;

use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\Clock\Clock;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\User\OAuth2User;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

use function Symfony\Component\String\u;

/**
 * The token handler validates the token on the authorization server and the Introspection Endpoint.
 *
 * The endpoint is reached by posting to the HTTP client it is given, which carries where the
 * authorization server lives and how this resource server authenticates there: a scoped client
 * declaring the introspection endpoint as its "base_uri" and its credentials as "auth_basic" is all
 * RFC 7662 §2.1 asks for. Nothing of that transport is described here.
 *
 * What is described here is what the resource server expects of the answer. The response is what it
 * bases its authorization decision on, so the members that qualify the token are confronted with
 * those expectations before a user badge is built from them: an authorization server that reports a
 * token as active while dating it in the past or the future, or while naming another issuer or
 * another audience, has described a token this resource server must not honor.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7662 OAuth 2.0 Token Introspection (RFC 7662)
 *
 * @internal
 */
final class Oauth2TokenHandler implements AccessTokenHandlerInterface
{
    private ?CacheInterface $cache = null;
    private string $cacheKeyPrefix = '';
    private int $cacheTtl = 0;

    /**
     * @param HttpClientInterface $client           The client the introspection endpoint is reached with, whose
     *                                              base URI is that endpoint and whose options carry the
     *                                              credentials of this resource server
     * @param list<string>        $audiences        The identifiers of this resource server, one of which the "aud"
     *                                              of the introspection response must name, or an empty list to
     *                                              skip that check
     * @param string|null         $issuer           The identifier of the authorization server, checked against the
     *                                              "iss" of the introspection response, or null to skip that check
     * @param string|null         $claim            The claim holding the user identifier, or null to read "sub" and
     *                                              fall back to "username"
     * @param int                 $allowedTimeDrift The tolerance, in seconds, on the "iat", "nbf" and "exp" the
     *                                              authorization server reports
     */
    public function __construct(
        private readonly HttpClientInterface $client,
        private readonly ?LoggerInterface $logger = null,
        private readonly array $audiences = [],
        private readonly ?string $issuer = null,
        private readonly ?string $claim = null,
        private readonly ClockInterface $clock = new Clock(),
        private readonly int $allowedTimeDrift = 0,
    ) {
    }

    /**
     * Caches the introspection responses of active tokens, for at most $ttl seconds.
     *
     * RFC 7662 §4 leaves the trade-off to the resource server: a longer lifetime spares the
     * authorization server a round trip per request, at the cost of a window during which a revoked
     * token is still accepted here. Two bounds are not left to the caller. No entry outlives the
     * "exp" the authorization server reported, which that section makes a MUST NOT, and the
     * response of an inactive token is not cached at all, so that arbitrary token values cannot be
     * used to fill the pool.
     *
     * An entry is keyed by the digest of the token rather than by the token itself, so that a pool
     * an operator, a backup or a neighbouring application can read holds no usable credential.
     */
    public function enableCache(CacheInterface $cache, string $cacheKeyPrefix, int $ttl = 60): void
    {
        if ($ttl <= 0) {
            throw new \InvalidArgumentException(\sprintf('The introspection cache lifetime must be a positive number of seconds, %d given.', $ttl));
        }

        $this->cache = $cache;
        $this->cacheKeyPrefix = $cacheKeyPrefix;
        $this->cacheTtl = $ttl;
    }

    /**
     * Introspects the token and builds a user badge out of the members of the response.
     *
     * RFC 7662 §2.2 guarantees a single member on an inactive token, "active", and makes it a
     * boolean, so it is the first one read and it is read as one: the string "false" an
     * authorization server may answer with does not describe an active token. The identifier
     * claims are only looked up once the server has stated that the token can be used.
     */
    public function getUserBadgeFrom(string $accessToken): UserBadge
    {
        try {
            $claims = $this->introspect($accessToken);

            if (true !== ($claims['active'] ?? false)) {
                throw new BadCredentialsException('The claim "active" was not found on the authorization server response or is set to false.');
            }

            $this->verifyClaims($claims);
            $identifier = $this->getUserIdentifier($claims);

            return new UserBadge($identifier, fn () => $this->createUser($claims), $claims);
        } catch (\Exception $e) {
            $this->logger?->error('An error occurred on the authorization server.', [
                'error' => $e->getMessage(),
                'exception' => $e,
                'trace' => $e->getTraceAsString(),
            ]);

            throw new BadCredentialsException('Invalid credentials.', $e->getCode(), $e);
        }
    }

    /**
     * Returns the members of the introspection response, from the cache when one is enabled.
     *
     * The lifetime of an entry is the shorter of the configured one and of what the "exp" of the
     * response leaves, and only the response of an active token is stored: see {@see enableCache()}.
     *
     * @return array<string, mixed> The members of the introspection response
     */
    private function introspect(string $accessToken): array
    {
        if (null === $this->cache) {
            return $this->requestIntrospection($accessToken);
        }

        $key = $this->cacheKeyPrefix.hash('sha256', $accessToken);

        return $this->cache->get($key, function (ItemInterface $item, bool &$save) use ($accessToken): array {
            $claims = $this->requestIntrospection($accessToken);

            $ttl = $this->cacheTtl;
            if (is_numeric($claims['exp'] ?? null)) {
                $ttl = min($ttl, (int) $claims['exp'] - $this->clock->now()->getTimestamp());
            }

            $save = 0 < $ttl && true === ($claims['active'] ?? null);
            $item->expiresAfter(max(1, $ttl));

            return $claims;
        });
    }

    /**
     * Calls the introspection endpoint, and returns the members it answered with.
     *
     * The request carries the token and the "access_token" hint of RFC 7662 §2.1, and is posted to
     * the base URI of the client, which is where the endpoint and the credentials of this resource
     * server are configured.
     *
     * @return array<string, mixed>
     */
    private function requestIntrospection(string $accessToken): array
    {
        return $this->client->request('POST', '', [
            'headers' => ['Accept' => 'application/json'],
            'body' => [
                'token' => $accessToken,
                'token_type_hint' => 'access_token',
            ],
        ])->toArray();
    }

    /**
     * Confronts the members of the introspection response with what this resource server expects.
     *
     * RFC 7662 §2.2 makes all of them optional and §4 puts the checks on the authorization server,
     * so the dates are only verified when the response carries them: a resource server told the
     * token is already expired, not valid yet or minted in the future still has no reason to honor
     * it. The issuer and the audience are checked when this resource server declares which ones it
     * expects, and the response is then required to carry them, since a token issued by another
     * authorization server, or for another resource server, must not be honored.
     *
     * @param array<string, mixed> $claims
     */
    private function verifyClaims(array $claims): void
    {
        $now = $this->clock->now()->getTimestamp();

        if (null !== ($exp = $this->readTimestamp($claims, 'exp')) && $exp <= $now - $this->allowedTimeDrift) {
            throw new BadCredentialsException('The token reported by the authorization server has expired.');
        }

        if (null !== ($nbf = $this->readTimestamp($claims, 'nbf')) && $nbf > $now + $this->allowedTimeDrift) {
            throw new BadCredentialsException('The token reported by the authorization server is not valid yet.');
        }

        if (null !== ($iat = $this->readTimestamp($claims, 'iat')) && $iat > $now + $this->allowedTimeDrift) {
            throw new BadCredentialsException('The token reported by the authorization server was issued in the future.');
        }

        if (null !== $this->issuer && $this->issuer !== ($claims['iss'] ?? null)) {
            throw new BadCredentialsException(\sprintf('The token was issued by "%s", where "%s" was expected.', \is_string($claims['iss'] ?? null) ? $claims['iss'] : '', $this->issuer));
        }

        if ($this->audiences && !$this->matchesAudience($claims['aud'] ?? null)) {
            throw new BadCredentialsException(\sprintf('The token is not intended for any of the audiences "%s".', implode('", "', $this->audiences)));
        }
    }

    /**
     * Reads a date member of the introspection response as a timestamp, or null when it is absent.
     *
     * RFC 7662 §2.2 types "exp", "nbf" and "iat" as integer timestamps, so a member carrying anything
     * else describes no instant this resource server can confront its clock with, and the response is
     * refused rather than honored, as {@see \Symfony\Component\Security\Http\AccessToken\Oidc\OidcTokenHandler}
     * refuses the same shape. A JSON null is read as an absent member, which §2.2 allows.
     *
     * @param array<string, mixed> $claims
     */
    private function readTimestamp(array $claims, string $claim): ?int
    {
        if (null === $value = $claims[$claim] ?? null) {
            return null;
        }

        if (!is_numeric($value) || !is_finite($seconds = (float) $value) || \PHP_INT_MAX <= abs($seconds)) {
            throw new BadCredentialsException(\sprintf('The "%s" claim reported by the authorization server is not a timestamp.', $claim));
        }

        return (int) $value;
    }

    /**
     * Tells whether an "aud" claim names one of the audiences this resource server answers for.
     *
     * RFC 7662 §2.2 makes "aud" "a service-specific string identifier or list of string identifiers",
     * so both shapes are read, and a single match is enough: an access token minted for several
     * resource servers is meant for each of them.
     */
    private function matchesAudience(mixed $audience): bool
    {
        $audiences = array_filter(\is_array($audience) ? $audience : [$audience], \is_string(...));

        return (bool) array_intersect($this->audiences, $audiences);
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function getUserIdentifier(array $claims): string
    {
        if (null !== $this->claim) {
            if (null === $identifier = self::readIdentifier($claims, $this->claim)) {
                throw new BadCredentialsException(\sprintf('"%s" claim not found on the authorization server response.', $this->claim));
            }

            return $identifier;
        }

        $identifier = self::readIdentifier($claims, 'sub') ?? self::readIdentifier($claims, 'username');
        if (null === $identifier) {
            throw new BadCredentialsException('"sub" and "username" claims not found on the authorization server response. At least one is required.');
        }

        return $identifier;
    }

    /**
     * @param array<string, mixed> $claims
     */
    private static function readIdentifier(array $claims, string $claim): ?string
    {
        $value = $claims[$claim] ?? null;

        return (\is_string($value) || \is_int($value)) && '' !== (string) $value ? (string) $value : null;
    }

    private function createUser(array $claims): OAuth2User
    {
        if (!\function_exists(\Symfony\Component\String\u::class)) {
            throw new \LogicException('You cannot use the "OAuth2TokenHandler" since the String component is not installed. Try running "composer require symfony/string".');
        }

        foreach ($claims as $claim => $value) {
            unset($claims[$claim]);
            if ('' === $value || null === $value) {
                continue;
            }
            $claims[u($claim)->camel()->toString()] = $value;
        }

        if ('' !== ($claims['updatedAt'] ?? '')) {
            $claims['updatedAt'] = (new \DateTimeImmutable())->setTimestamp($claims['updatedAt']);
        }

        if ('' !== ($claims['emailVerified'] ?? '')) {
            $claims['emailVerified'] = (bool) $claims['emailVerified'];
        }

        if ('' !== ($claims['phoneNumberVerified'] ?? '')) {
            $claims['phoneNumberVerified'] = (bool) $claims['phoneNumberVerified'];
        }

        return new OAuth2User(...$claims);
    }
}

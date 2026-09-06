<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Security\Http\Tests\AccessToken\OAuth2;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\JsonMockResponse;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\User\OAuth2User;
use Symfony\Component\Security\Http\AccessToken\OAuth2\Oauth2TokenHandler;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

class OAuth2TokenHandlerTest extends TestCase
{
    private const ENDPOINT = 'https://authorization-server.example.com/token/introspect';
    private const ISSUER = 'https://authorization-server.example.com/';
    private const AUDIENCE = 'https://protected.example.net/resource';

    public function testGetsUserIdentifierFromOAuth2ServerResponse()
    {
        $accessToken = 'a-secret-token';
        $claims = self::activeClaims([
            'client_id' => 'l238j323ds-23ij4',
            'username' => 'jdoe',
            'scope' => 'read write dolphin',
            'sub' => 'Z5O3upPC88QrAjx00dis',
            'extension_field' => 'twenty-seven',
        ]);

        $client = new MockHttpClient([new JsonMockResponse($claims)]);

        $userBadge = self::createHandler($client)->getUserBadgeFrom($accessToken);
        $actualUser = $userBadge->getUserLoader()();

        $this->assertInstanceOf(UserBadge::class, $userBadge);
        $this->assertSame('Z5O3upPC88QrAjx00dis', $userBadge->getUserIdentifier());
        $this->assertSame($claims, $userBadge->getAttributes());
        $this->assertInstanceOf(OAuth2User::class, $actualUser);
        $this->assertSame($claims['sub'], $actualUser->getUserIdentifier());
    }

    public function testFallsBackToTheUsernameClaim()
    {
        $client = new MockHttpClient([new JsonMockResponse(self::activeClaims(['username' => 'jdoe']))]);

        $this->assertSame('jdoe', self::createHandler($client)->getUserBadgeFrom('a-secret-token')->getUserIdentifier());
    }

    public function testReadsTheConfiguredClaim()
    {
        $client = new MockHttpClient([new JsonMockResponse(self::activeClaims(['sub' => 'Z5O3upPC88QrAjx00dis', 'email' => 'jdoe@example.com']))]);

        $handler = self::createHandler($client, claim: 'email');

        $this->assertSame('jdoe@example.com', $handler->getUserBadgeFrom('a-secret-token')->getUserIdentifier());
    }

    public function testFailsWhenTheConfiguredClaimIsMissing()
    {
        $client = new MockHttpClient([new JsonMockResponse(self::activeClaims(['sub' => 'Z5O3upPC88QrAjx00dis']))]);

        $this->assertBadCredentials('"email" claim not found on the authorization server response.', self::createHandler($client, claim: 'email'));
    }

    public function testFailsWithoutAnyIdentifierClaim()
    {
        $client = new MockHttpClient([new JsonMockResponse(self::activeClaims())]);

        $this->assertBadCredentials('"sub" and "username" claims not found on the authorization server response. At least one is required.', self::createHandler($client));
    }

    /**
     * The endpoint and the credentials belong to the client, so the request only carries what
     * RFC 7662 §2.1 asks the resource server for, and is posted relative to its base URI.
     */
    public function testPostsTheTokenRelativeToTheBaseUriOfTheClient()
    {
        $request = null;
        $client = new MockHttpClient(static function (string $method, string $url, array $options) use (&$request): MockResponse {
            $request = [$method, $url, $options];

            return new JsonMockResponse(self::activeClaims(['sub' => 'jdoe']));
        }, self::ENDPOINT);

        self::createHandler($client)->getUserBadgeFrom('a-secret-token');

        [$method, $url, $options] = $request;
        $this->assertSame('POST', $method);
        $this->assertSame(self::ENDPOINT, $url);
        $this->assertSame(['Accept: application/json'], $options['normalized_headers']['accept']);

        parse_str($options['body'], $body);
        $this->assertSame(['token' => 'a-secret-token', 'token_type_hint' => 'access_token'], $body);
    }

    /**
     * Anything the introspection request throws is an answer this resource server could not read,
     * so it reports bad credentials rather than letting the exception reach the user as a 500.
     */
    #[DataProvider('unreadableResponses')]
    public function testTurnsAnErrorOfTheAuthorizationServerIntoBadCredentials(MockResponse $response)
    {
        $client = new MockHttpClient([$response], self::ENDPOINT);

        $this->expectException(BadCredentialsException::class);
        $this->expectExceptionMessage('Invalid credentials.');

        self::createHandler($client)->getUserBadgeFrom('a-secret-token');
    }

    public static function unreadableResponses(): iterable
    {
        yield 'the caller is refused' => [new MockResponse('{"error":"invalid_client"}', ['http_code' => 401])];
        yield 'the server is down' => [new MockResponse('', ['http_code' => 503])];
        yield 'the server is unreachable' => [new MockResponse('', ['error' => 'Could not resolve host: authorization-server.example.com'])];
        yield 'the body is not JSON' => [new MockResponse('<html>Bad Gateway</html>')];
        yield 'the body is empty' => [new MockResponse('')];
        yield 'the body is not an object' => [new MockResponse('"nope"')];
    }

    #[DataProvider('inactiveResponses')]
    public function testRejectsAnInactiveToken(array $claims)
    {
        $client = new MockHttpClient([new JsonMockResponse($claims)]);

        $this->assertBadCredentials('The claim "active" was not found on the authorization server response or is set to false.', self::createHandler($client));
    }

    /**
     * RFC 7662 §2.2 reports an inactive token with nothing but "active", and makes it a boolean,
     * so nothing but the boolean true describes a token this resource server may use.
     */
    public static function inactiveResponses(): iterable
    {
        yield 'inactive' => [['active' => false]];
        yield 'missing' => [['sub' => 'jdoe']];
        yield 'stringly typed false' => [['active' => 'false', 'sub' => 'jdoe']];
        yield 'stringly typed true' => [['active' => 'true', 'sub' => 'jdoe']];
        yield 'the number one' => [['active' => 1, 'sub' => 'jdoe']];
        yield 'no' => [['active' => 'no', 'sub' => 'jdoe']];
        yield 'not a boolean at all' => [['active' => 'bogus', 'sub' => 'jdoe']];
    }

    #[DataProvider('unusableTokens')]
    public function testRejectsATokenTheServerReportsAsUnusable(array $claims, string $message)
    {
        $client = new MockHttpClient([new JsonMockResponse(self::activeClaims($claims + ['sub' => 'jdoe']))]);

        $this->assertBadCredentials($message, self::createHandler($client));
    }

    public static function unusableTokens(): iterable
    {
        yield 'expired' => [['exp' => 1719000000 - 1], 'The token reported by the authorization server has expired.'];
        yield 'not yet valid' => [['nbf' => 1719000000 + 1], 'The token reported by the authorization server is not valid yet.'];
        yield 'issued in the future' => [['iat' => 1719000000 + 1], 'The token reported by the authorization server was issued in the future.'];
        yield 'a string "exp"' => [['exp' => 'not-a-number'], 'The "exp" claim reported by the authorization server is not a timestamp.'];
        yield 'an array "exp"' => [['exp' => []], 'The "exp" claim reported by the authorization server is not a timestamp.'];
        yield 'a string "nbf"' => [['nbf' => 'soon'], 'The "nbf" claim reported by the authorization server is not a timestamp.'];
        yield 'a boolean "iat"' => [['iat' => true], 'The "iat" claim reported by the authorization server is not a timestamp.'];
        yield 'an "exp" no integer can hold' => [['exp' => 1e20], 'The "exp" claim reported by the authorization server is not a timestamp.'];
        yield 'an "nbf" no integer can hold' => [['nbf' => 1e20], 'The "nbf" claim reported by the authorization server is not a timestamp.'];
    }

    #[DataProvider('absentDateClaims')]
    public function testReadsAJsonNullDateClaimAsAbsent(array $claims)
    {
        $client = new MockHttpClient([new JsonMockResponse(self::activeClaims($claims + ['sub' => 'jdoe']))]);

        $this->assertSame('jdoe', self::createHandler($client)->getUserBadgeFrom('a-secret-token')->getUserIdentifier());
    }

    public static function absentDateClaims(): iterable
    {
        yield 'exp' => [['exp' => null]];
        yield 'nbf' => [['nbf' => null]];
        yield 'iat' => [['iat' => null]];
    }

    public function testReadsAStringlyTypedDateClaim()
    {
        $client = new MockHttpClient([new JsonMockResponse(self::activeClaims(['sub' => 'jdoe', 'exp' => '1719000001']))]);

        $this->assertSame('jdoe', self::createHandler($client)->getUserBadgeFrom('a-secret-token')->getUserIdentifier());
    }

    public function testAcceptsATokenWithinTheAllowedTimeDrift()
    {
        $claims = self::activeClaims(['sub' => 'jdoe', 'exp' => 1719000000 - 5, 'nbf' => 1719000000 + 5]);
        $client = new MockHttpClient([new JsonMockResponse($claims), new JsonMockResponse($claims)]);

        $this->assertBadCredentials('The token reported by the authorization server has expired.', self::createHandler($client));
        $this->assertSame('jdoe', self::createHandler($client, allowedTimeDrift: 10)->getUserBadgeFrom('a-secret-token')->getUserIdentifier());
    }

    public function testChecksTheIssuerOfTheToken()
    {
        $claims = self::activeClaims(['sub' => 'jdoe', 'iss' => 'https://evil.example.com/']);
        $client = new MockHttpClient([new JsonMockResponse($claims), new JsonMockResponse(self::activeClaims(['sub' => 'jdoe', 'iss' => self::ISSUER]))]);

        $this->assertBadCredentials('The token was issued by "https://evil.example.com/", where "'.self::ISSUER.'" was expected.', self::createHandler($client, issuer: self::ISSUER));
        $this->assertSame('jdoe', self::createHandler($client, issuer: self::ISSUER)->getUserBadgeFrom('a-secret-token')->getUserIdentifier());
    }

    public function testRequiresTheIssuerWhenOneIsExpected()
    {
        $client = new MockHttpClient([new JsonMockResponse(['active' => true, 'sub' => 'jdoe'])]);

        $this->assertBadCredentials('The token was issued by "", where "'.self::ISSUER.'" was expected.', self::createHandler($client, issuer: self::ISSUER));
    }

    #[DataProvider('audiences')]
    public function testChecksTheAudienceOfTheToken(mixed $audience, bool $accepted)
    {
        $claims = self::activeClaims(['sub' => 'jdoe']);
        if (null !== $audience) {
            $claims['aud'] = $audience;
        }
        $client = new MockHttpClient([new JsonMockResponse($claims)]);
        $handler = self::createHandler($client, audiences: [self::AUDIENCE]);

        if ($accepted) {
            $this->assertSame('jdoe', $handler->getUserBadgeFrom('a-secret-token')->getUserIdentifier());
        } else {
            $this->assertBadCredentials('The token is not intended for any of the audiences "'.self::AUDIENCE.'".', $handler);
        }
    }

    public static function audiences(): iterable
    {
        yield 'string' => [self::AUDIENCE, true];
        yield 'list' => [['https://other.example.net', self::AUDIENCE], true];
        yield 'another audience' => ['https://other.example.net', false];
        yield 'another list' => [['https://other.example.net'], false];
        yield 'missing' => [null, false];
    }

    /**
     * A resource server answering for several identifiers accepts a token minted for any of them.
     */
    public function testChecksTheAudienceOfTheTokenAgainstSeveralIdentifiers()
    {
        $client = new MockHttpClient([
            new JsonMockResponse(self::activeClaims(['sub' => 'jdoe', 'aud' => 'https://other.example.net'])),
            new JsonMockResponse(self::activeClaims(['sub' => 'jdoe', 'aud' => ['https://yet-another.example.net']])),
        ]);
        $audiences = [self::AUDIENCE, 'https://other.example.net'];

        $this->assertSame('jdoe', self::createHandler($client, $audiences)->getUserBadgeFrom('a-secret-token')->getUserIdentifier());
        $this->assertBadCredentials('The token is not intended for any of the audiences "'.implode('", "', $audiences).'".', self::createHandler($client, $audiences));
    }

    /**
     * RFC 7662 §2.2 types "iss" and "aud" as strings, so a response carrying anything else names
     * neither an issuer nor an audience this resource server can be compared against: an array
     * would be juggled into the string "Array", and a number into a string that the audience of a
     * resource server identified by digits would match.
     */
    public function testRefusesANonStringIssuer()
    {
        $client = new MockHttpClient([new JsonMockResponse(self::activeClaims(['sub' => 'jdoe', 'iss' => [self::ISSUER]]))], self::ENDPOINT);

        $this->assertBadCredentials('The token was issued by "", where "'.self::ISSUER.'" was expected.', self::createHandler($client, issuer: self::ISSUER));
    }

    public function testRefusesANonStringAudience()
    {
        $client = new MockHttpClient([new JsonMockResponse(self::activeClaims(['sub' => 'jdoe', 'aud' => 123]))], self::ENDPOINT);

        $this->assertBadCredentials('The token is not intended for any of the audiences "123".', self::createHandler($client, audiences: ['123']));
    }

    /**
     * The pool is keyed by the digest of the token, so it never holds a usable credential.
     */
    public function testCachesTheResponseOfAnActiveToken()
    {
        $claims = self::activeClaims(['sub' => 'jdoe', 'exp' => 1719000000 + 3600]);
        $client = new MockHttpClient([new JsonMockResponse($claims)]);
        $handler = self::createHandler($client);
        $handler->enableCache($cache = new ArrayAdapter(), 'introspection.', 60);

        $this->assertSame('jdoe', $handler->getUserBadgeFrom('a-secret-token')->getUserIdentifier());
        $this->assertSame('jdoe', $handler->getUserBadgeFrom('a-secret-token')->getUserIdentifier());
        $this->assertSame(1, $client->getRequestsCount());
        $this->assertTrue($cache->hasItem('introspection.'.hash('sha256', 'a-secret-token')));
    }

    /**
     * The two readings of "active" must agree: a response the handler refuses is a response it
     * must not cache, or arbitrary token values would fill the pool of a resource server whose
     * authorization server reports "active" as a string.
     */
    #[DataProvider('inactiveResponses')]
    public function testDoesNotCacheTheResponseOfAnInactiveToken(array $claims)
    {
        $client = new MockHttpClient([new JsonMockResponse($claims), new JsonMockResponse($claims)]);
        $handler = self::createHandler($client);
        $handler->enableCache($cache = new ArrayAdapter(), 'introspection.', 60);

        $this->assertBadCredentials('The claim "active" was not found on the authorization server response or is set to false.', $handler);
        $this->assertBadCredentials('The claim "active" was not found on the authorization server response or is set to false.', $handler);
        $this->assertSame(2, $client->getRequestsCount());
        $this->assertFalse($cache->hasItem('introspection.'.hash('sha256', 'a-secret-token')));
    }

    /**
     * RFC 7662 §4 forbids caching a response beyond the "exp" it reports, so the hour asked for
     * here is cut down to the ten seconds the token still has to live.
     */
    public function testDoesNotCacheAResponseBeyondItsExpiration()
    {
        $client = new MockHttpClient([new JsonMockResponse(self::activeClaims(['sub' => 'jdoe', 'exp' => 1719000000 + 10]))]);
        $handler = self::createHandler($client);
        $handler->enableCache($cache = new ArrayAdapter(), 'introspection.', 3600);

        $this->assertSame('jdoe', $handler->getUserBadgeFrom('a-secret-token')->getUserIdentifier());

        $item = $cache->getItem('introspection.'.hash('sha256', 'a-secret-token'));
        $this->assertEqualsWithDelta(10, $item->getMetadata()[$item::METADATA_EXPIRY] - microtime(true), 2);
    }

    public function testRejectsANonPositiveCacheLifetime()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The introspection cache lifetime must be a positive number of seconds, 0 given.');

        self::createHandler(new MockHttpClient())->enableCache(new ArrayAdapter(), 'introspection.', 0);
    }

    private function assertBadCredentials(string $message, Oauth2TokenHandler $handler): void
    {
        try {
            $handler->getUserBadgeFrom('a-secret-token');
        } catch (BadCredentialsException $e) {
            $this->assertSame('Invalid credentials.', $e->getMessage());
            $this->assertSame($message, $e->getPrevious()?->getMessage());

            return;
        }

        $this->fail(\sprintf('The handler did not reject the token with "%s".', $message));
    }

    private static function createHandler(MockHttpClient $client, array $audiences = [], ?string $issuer = null, ?string $claim = null, int $allowedTimeDrift = 0): Oauth2TokenHandler
    {
        return new Oauth2TokenHandler($client, null, $audiences, $issuer, $claim, new MockClock('@1719000000'), $allowedTimeDrift);
    }

    /**
     * @return array<string, mixed>
     */
    private static function activeClaims(array $claims = []): array
    {
        return ['active' => true] + $claims;
    }
}

<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Security\Http\Tests\Authenticator\Oidc;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpClient\Exception\TransportException;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\JsonMockResponse;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Oidc\OidcConfidentialClient;
use Symfony\Component\Security\Http\Exception\OidcInvalidGrantException;
use Symfony\Component\Security\Http\Oidc\OidcDiscovery;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;

#[AllowMockObjectsWithoutExpectations]
class OidcConfidentialClientTest extends TestCase
{
    private OidcDiscovery $discovery;
    private HttpClientInterface $httpClient;

    protected function setUp(): void
    {
        $this->discovery = $this->createDiscovery([
            'token_endpoint' => 'https://provider.example.com/token',
            'userinfo_endpoint' => 'https://provider.example.com/userinfo',
            'issuer' => 'https://provider.example.com',
        ]);

        $this->httpClient = $this->createMock(HttpClientInterface::class);
    }

    /**
     * @param array<string, mixed> $configuration
     */
    private function createDiscovery(array $configuration): OidcDiscovery
    {
        return new OidcDiscovery(
            new MockHttpClient(static fn (): MockResponse => new JsonMockResponse($configuration)),
            new ArrayAdapter(),
            'https://provider.example.com/.well-known/openid-configuration',
        );
    }

    public function testExchangeCodeWithClientSecretPost()
    {
        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn([
            'access_token' => 'access-123',
            'id_token' => 'id-token-abc',
        ]);

        $this->httpClient->expects($this->once())
            ->method('request')
            ->with('POST', 'https://provider.example.com/token', $this->callback(function (array $options) {
                $this->assertSame('authorization_code', $options['body']['grant_type']);
                $this->assertSame('auth-code', $options['body']['code']);
                $this->assertSame('https://app.example.com/callback', $options['body']['redirect_uri']);
                $this->assertSame('test-client-id', $options['body']['client_id']);
                $this->assertSame('test-client-secret', $options['body']['client_secret']);
                $this->assertArrayNotHasKey('auth_basic', $options);

                return true;
            }))
            ->willReturn($response);

        $client = $this->createClient();
        $tokens = $client->exchangeCode('auth-code', 'https://app.example.com/callback');

        $this->assertSame('access-123', $tokens['access_token']);
        $this->assertSame('id-token-abc', $tokens['id_token']);
    }

    public function testExchangeCodeWithClientSecretBasic()
    {
        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn([
            'access_token' => 'access-123',
            'id_token' => 'id-token-abc',
        ]);

        $this->httpClient->expects($this->once())
            ->method('request')
            ->with('POST', 'https://provider.example.com/token', $this->callback(function (array $options) {
                $this->assertSame('test-client-id:test-client-secret', $options['auth_basic']);
                $this->assertArrayNotHasKey('client_secret', $options['body']);

                return true;
            }))
            ->willReturn($response);

        $client = $this->createClient(tokenEndpointAuthMethod: 'client_secret_basic');
        $client->exchangeCode('auth-code', 'https://app.example.com/callback');
    }

    public function testClientSecretBasicCredentialsAreFormUrlEncoded()
    {
        // RFC 6749 Section 2.3.1: the client id and the secret are each form-urlencoded
        // before being combined into the HTTP Basic credentials
        $mockResponse = new JsonMockResponse(['access_token' => 'access-123', 'id_token' => 'id-token-abc']);

        $client = new OidcConfidentialClient(
            httpClient: new MockHttpClient($mockResponse),
            discovery: $this->discovery,
            clientId: 'client:id',
            clientSecret: 'sec:ret% +é',
            tokenEndpointAuthMethod: 'client_secret_basic',
        );
        $client->exchangeCode('auth-code', 'https://app.example.com/callback');

        $requestOptions = $mockResponse->getRequestOptions();
        $this->assertSame(['Authorization: Basic '.base64_encode('client%3Aid:sec%3Aret%25+%2B%C3%A9')], $requestOptions['normalized_headers']['authorization']);
        $this->assertStringNotContainsString('client_secret', $requestOptions['body']);
    }

    public function testRejectsAnUnknownTokenEndpointAuthMethod()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A confidential OIDC client authenticates with "client_secret_post" or "client_secret_basic", "none" given.');

        $this->createClient(tokenEndpointAuthMethod: 'none');
    }

    public function testExchangeCodeWithCodeVerifier()
    {
        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn([
            'access_token' => 'access-123',
            'id_token' => 'id-token-abc',
        ]);

        $this->httpClient->expects($this->once())
            ->method('request')
            ->with('POST', 'https://provider.example.com/token', $this->callback(function (array $options) {
                $this->assertSame('my-code-verifier', $options['body']['code_verifier']);

                return true;
            }))
            ->willReturn($response);

        $client = $this->createClient();
        $client->exchangeCode('auth-code', 'https://app.example.com/callback', 'my-code-verifier');
    }

    public function testFetchUserInfo()
    {
        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willReturn([
            'sub' => '123',
            'email' => 'test@example.com',
        ]);

        $this->httpClient->expects($this->once())
            ->method('request')
            ->with('GET', 'https://provider.example.com/userinfo', [
                'auth_bearer' => 'access-token',
            ])
            ->willReturn($response);

        $client = $this->createClient();
        $claims = $client->fetchUserInfo('access-token');

        $this->assertSame('123', $claims['sub']);
        $this->assertSame('test@example.com', $claims['email']);
    }

    public function testFetchUserInfoThrowsWhenEndpointMissing()
    {
        $discovery = $this->createDiscovery([
            'token_endpoint' => 'https://provider.example.com/token',
        ]);

        $client = new OidcConfidentialClient($this->httpClient, $discovery, 'test-client-id', 'test-client-secret');

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('does not announce any "userinfo_endpoint"');

        $client->fetchUserInfo('access-token');
    }

    public function testExchangeCodeThrowsWhenEndpointMissing()
    {
        $discovery = $this->createDiscovery([
            'userinfo_endpoint' => 'https://provider.example.com/userinfo',
        ]);

        $client = new OidcConfidentialClient($this->httpClient, $discovery, 'test-client-id', 'test-client-secret');

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('does not announce any "token_endpoint"');

        $client->exchangeCode('auth-code', 'https://app.example.com/callback');
    }

    public function testExchangeCodeRejectsAnInsecureTokenEndpoint()
    {
        // the client secret and the tokens travel through the token endpoint: a discovery
        // document announcing a plain HTTP endpoint takes their confidentiality away
        $discovery = $this->createDiscovery(['token_endpoint' => 'http://provider.example.com/token']);

        $this->httpClient->expects($this->never())->method('request');

        $client = new OidcConfidentialClient($this->httpClient, $discovery, 'test-client-id', 'test-client-secret');

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('must use HTTPS');

        $client->exchangeCode('auth-code', 'https://app.example.com/callback');
    }

    public function testFetchUserInfoRejectsAnInsecureUserInfoEndpoint()
    {
        $discovery = $this->createDiscovery(['userinfo_endpoint' => 'http://provider.example.com/userinfo']);

        $this->httpClient->expects($this->never())->method('request');

        $client = new OidcConfidentialClient($this->httpClient, $discovery, 'test-client-id', 'test-client-secret');

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('must use HTTPS');

        $client->fetchUserInfo('access-token');
    }

    public function testExchangeCodeConvertsTransportErrorsToAuthenticationException()
    {
        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willThrowException(new TransportException('Connection refused.'));

        $this->httpClient->method('request')->willReturn($response);

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('The OIDC token endpoint request failed');

        $this->createClient()->exchangeCode('auth-code', 'https://app.example.com/callback');
    }

    public function testFetchUserInfoConvertsTransportErrorsToAuthenticationException()
    {
        $response = $this->createMock(ResponseInterface::class);
        $response->method('toArray')->willThrowException(new TransportException('Connection refused.'));

        $this->httpClient->method('request')->willReturn($response);

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('The OIDC userinfo endpoint request failed');

        $this->createClient()->fetchUserInfo('access-token');
    }

    public function testRefreshToken()
    {
        $mockResponse = new JsonMockResponse([
            'access_token' => 'access-456',
            'refresh_token' => 'refresh-456',
            'expires_in' => 300,
        ]);

        $client = new OidcConfidentialClient(new MockHttpClient($mockResponse), $this->discovery, 'test-client-id', 'test-client-secret');
        $tokens = $client->refreshToken('refresh-123');

        $this->assertSame('https://provider.example.com/token', $mockResponse->getRequestUrl());
        parse_str($mockResponse->getRequestOptions()['body'], $body);
        $this->assertSame('refresh_token', $body['grant_type']);
        $this->assertSame('refresh-123', $body['refresh_token']);
        $this->assertSame('test-client-id', $body['client_id']);
        $this->assertSame('test-client-secret', $body['client_secret']);
        $this->assertArrayNotHasKey('scope', $body);
        $this->assertSame('access-456', $tokens['access_token']);
        $this->assertSame('refresh-456', $tokens['refresh_token']);
    }

    public function testRefreshTokenNarrowsTheScopes()
    {
        $mockResponse = new JsonMockResponse(['access_token' => 'access-456']);

        $client = new OidcConfidentialClient(new MockHttpClient($mockResponse), $this->discovery, 'test-client-id', 'test-client-secret');
        $client->refreshToken('refresh-123', ['openid', 'profile']);

        parse_str($mockResponse->getRequestOptions()['body'], $body);
        $this->assertSame('openid profile', $body['scope']);
    }

    public function testRefreshTokenWithClientSecretBasic()
    {
        $mockResponse = new JsonMockResponse(['access_token' => 'access-456']);

        $client = new OidcConfidentialClient(new MockHttpClient($mockResponse), $this->discovery, 'test-client-id', 'test-client-secret', 'client_secret_basic');
        $client->refreshToken('refresh-123');

        $requestOptions = $mockResponse->getRequestOptions();
        $this->assertSame(['Authorization: Basic '.base64_encode('test-client-id:test-client-secret')], $requestOptions['normalized_headers']['authorization']);
        $this->assertStringNotContainsString('client_secret', $requestOptions['body']);
    }

    public function testRefreshTokenReportsAnInvalidGrantOnItsOwn()
    {
        // RFC 6749 Section 5.2: only "invalid_grant" says the refresh token is gone for
        // good, so it is the only failure a caller may act on by ending the session
        $client = new OidcConfidentialClient(
            new MockHttpClient(new JsonMockResponse(['error' => 'invalid_grant', 'error_description' => 'Token is not active'], ['http_code' => 400])),
            $this->discovery,
            'test-client-id',
            'test-client-secret',
        );

        $this->expectException(OidcInvalidGrantException::class);
        $this->expectExceptionMessage('The OIDC provider rejected the refresh token');

        $client->refreshToken('refresh-123');
    }

    public function testRefreshTokenReportsAnotherProviderErrorAsAPlainFailure()
    {
        $client = new OidcConfidentialClient(
            new MockHttpClient(new JsonMockResponse(['error' => 'invalid_client'], ['http_code' => 401])),
            $this->discovery,
            'test-client-id',
            'test-client-secret',
        );

        try {
            $client->refreshToken('refresh-123');
            $this->fail(\sprintf('Expected an "%s" to be thrown.', AuthenticationException::class));
        } catch (AuthenticationException $e) {
            $this->assertNotInstanceOf(OidcInvalidGrantException::class, $e);
            $this->assertStringContainsString('The OIDC token endpoint request failed', $e->getMessage());
        }
    }

    public function testRefreshTokenReportsAnUnreachableProviderAsAPlainFailure()
    {
        $client = new OidcConfidentialClient(
            new MockHttpClient(new MockResponse('Service Unavailable', ['http_code' => 503])),
            $this->discovery,
            'test-client-id',
            'test-client-secret',
        );

        try {
            $client->refreshToken('refresh-123');
            $this->fail(\sprintf('Expected an "%s" to be thrown.', AuthenticationException::class));
        } catch (AuthenticationException $e) {
            $this->assertNotInstanceOf(OidcInvalidGrantException::class, $e);
            $this->assertStringContainsString('The OIDC token endpoint request failed', $e->getMessage());
        }
    }

    public function testRefreshTokenRejectsAnInsecureTokenEndpoint()
    {
        $discovery = $this->createDiscovery(['token_endpoint' => 'http://provider.example.com/token']);

        $this->httpClient->expects($this->never())->method('request');

        $client = new OidcConfidentialClient($this->httpClient, $discovery, 'test-client-id', 'test-client-secret');

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('must use HTTPS');

        $client->refreshToken('refresh-123');
    }

    private function createClient(string $tokenEndpointAuthMethod = 'client_secret_post'): OidcConfidentialClient
    {
        return new OidcConfidentialClient(
            httpClient: $this->httpClient,
            discovery: $this->discovery,
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            tokenEndpointAuthMethod: $tokenEndpointAuthMethod,
        );
    }
}

<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Security\Http\Tests\Authorization;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Vote;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Http\Authenticator\AccessTokenAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;
use Symfony\Component\Security\Http\Authorization\OAuth2ScopeVoter;

class OAuth2ScopeVoterTest extends TestCase
{
    #[DataProvider('provideVotes')]
    public function testVote(array $scopes, array $attributes, int $expected)
    {
        $this->assertSame($expected, (new OAuth2ScopeVoter())->vote($this->createToken($scopes), null, $attributes));
    }

    public static function provideVotes(): iterable
    {
        yield 'the granted scope is required' => [['profile:read'], ['OAUTH2_SCOPE(profile:read)'], VoterInterface::ACCESS_GRANTED];
        yield 'one of the granted scopes is required' => [['openid', 'profile:read'], ['OAUTH2_SCOPE(profile:read)'], VoterInterface::ACCESS_GRANTED];
        yield 'the required scope was not granted' => [['openid'], ['OAUTH2_SCOPE(profile:read)'], VoterInterface::ACCESS_DENIED];
        yield 'no scope was granted at all' => [[], ['OAUTH2_SCOPE(profile:read)'], VoterInterface::ACCESS_DENIED];
        yield 'scopes are case-sensitive' => [['profile:read'], ['OAUTH2_SCOPE(PROFILE:READ)'], VoterInterface::ACCESS_DENIED];

        yield 'every scope an attribute lists is required' => [['openid', 'profile:read'], ['OAUTH2_SCOPE(openid profile:read)'], VoterInterface::ACCESS_GRANTED];
        yield 'one missing scope denies the whole attribute' => [['openid'], ['OAUTH2_SCOPE(openid profile:read)'], VoterInterface::ACCESS_DENIED];
        yield 'the scopes of an attribute are separated by any run of spaces' => [['openid', 'profile:read'], ["OAUTH2_SCOPE(  openid \t profile:read )"], VoterInterface::ACCESS_GRANTED];
        yield 'a scope required twice' => [['openid'], ['OAUTH2_SCOPE(openid openid)'], VoterInterface::ACCESS_GRANTED];
        yield 'the order an attribute lists its scopes in does not matter' => [['openid', 'profile:read'], ['OAUTH2_SCOPE(profile:read openid)'], VoterInterface::ACCESS_GRANTED];
        yield 'the order the scopes were granted in does not matter' => [['profile:read', 'openid'], ['OAUTH2_SCOPE(openid profile:read)'], VoterInterface::ACCESS_GRANTED];
        yield 'a missing scope listed first' => [['profile:read'], ['OAUTH2_SCOPE(openid profile:read)'], VoterInterface::ACCESS_DENIED];
        yield 'a missing scope listed last' => [['profile:read'], ['OAUTH2_SCOPE(profile:read openid)'], VoterInterface::ACCESS_DENIED];

        yield 'any of several attributes is enough' => [['openid'], ['OAUTH2_SCOPE(profile:read)', 'OAUTH2_SCOPE(openid)'], VoterInterface::ACCESS_GRANTED];
        yield 'none of several attributes is granted' => [['openid'], ['OAUTH2_SCOPE(profile:read)', 'OAUTH2_SCOPE(admin:manage)'], VoterInterface::ACCESS_DENIED];

        yield 'a role attribute is left to the role voter' => [['profile:read'], ['ROLE_USER'], VoterInterface::ACCESS_ABSTAIN];
        yield 'an attribute merely starting like a scope one' => [['profile:read'], ['OAUTH2_SCOPE_profile:read'], VoterInterface::ACCESS_ABSTAIN];
        yield 'an attribute that is not a string' => [['profile:read'], [new \stdClass()], VoterInterface::ACCESS_ABSTAIN];
        yield 'an attribute listing no scope at all' => [['profile:read'], ['OAUTH2_SCOPE()'], VoterInterface::ACCESS_ABSTAIN];
        yield 'no attribute at all' => [['profile:read'], [], VoterInterface::ACCESS_ABSTAIN];
    }

    public function testVoteReportsTheScopesItDecidedOn()
    {
        $voter = new OAuth2ScopeVoter();

        $voter->vote($this->createToken(['openid']), null, ['OAUTH2_SCOPE(openid)'], $vote = new Vote());
        $this->assertSame(['The access token was granted openid.'], $vote->reasons);

        $voter->vote($this->createToken(['openid']), null, ['OAUTH2_SCOPE(openid profile:read)', 'OAUTH2_SCOPE(admin:manage)'], $vote = new Vote());
        $this->assertSame(['The access token was not granted profile:read, admin:manage.'], $vote->reasons);
    }

    public function testTheReportedScopesFollowTheOrderTheAttributeListsThemIn()
    {
        $voter = new OAuth2ScopeVoter();

        $voter->vote($this->createToken(['openid']), null, ['OAUTH2_SCOPE(openid profile:read)'], $vote = new Vote());
        $this->assertSame(['The access token was not granted profile:read.'], $vote->reasons);

        $voter->vote($this->createToken(['openid', 'profile:read']), null, ['OAUTH2_SCOPE(profile:read openid)'], $vote = new Vote());
        $this->assertSame(['The access token was granted profile:read, openid.'], $vote->reasons);
    }

    public function testVoteDeniesATokenCarryingNoScopeAttribute()
    {
        $token = new PostAuthenticationToken(new InMemoryUser('john', null), 'main', []);

        $this->assertSame(VoterInterface::ACCESS_DENIED, (new OAuth2ScopeVoter())->vote($token, null, ['OAUTH2_SCOPE(profile:read)']));
        $this->assertSame(VoterInterface::ACCESS_ABSTAIN, (new OAuth2ScopeVoter())->vote($token, null, ['ROLE_USER']));
    }

    #[DataProvider('provideRequiredScopes')]
    public function testGetRequiredScopes(string $attribute, ?array $expected)
    {
        $this->assertSame($expected, OAuth2ScopeVoter::getRequiredScopes($attribute));
    }

    public static function provideRequiredScopes(): iterable
    {
        yield 'a single scope' => ['OAUTH2_SCOPE(profile:read)', ['profile:read']];
        yield 'several scopes' => ['OAUTH2_SCOPE(openid profile:read)', ['openid', 'profile:read']];
        yield 'an attribute of another voter' => ['ROLE_USER', null];
        yield 'nothing between the parentheses' => ['OAUTH2_SCOPE()', null];
        yield 'only spaces between the parentheses' => ['OAUTH2_SCOPE(   )', null];
        // a malformed attribute is abstained on rather than read as the scopes it seems to list,
        // so that a typo denies nothing and grants nothing
        yield 'the closing parenthesis is missing' => ['OAUTH2_SCOPE(profile:read', null];
        yield 'a doubled closing parenthesis' => ['OAUTH2_SCOPE(profile:read))', ['profile:read)']];
        yield 'trailing characters' => ['OAUTH2_SCOPE(profile:read)x', null];
    }

    public function testSupportsAttribute()
    {
        $voter = new OAuth2ScopeVoter();

        $this->assertTrue($voter->supportsAttribute('OAUTH2_SCOPE(profile:read)'));
        $this->assertFalse($voter->supportsAttribute('ROLE_USER'));
        $this->assertTrue($voter->supportsType('string'));
    }

    private function createToken(array $scopes): TokenInterface
    {
        $token = new PostAuthenticationToken(new InMemoryUser('john', null), 'main', []);
        $token->setAttribute(AccessTokenAuthenticator::SCOPE_ATTRIBUTE, $scopes);

        return $token;
    }
}

<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Security\Http\Authorization;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\CacheableVoterInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Vote;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;
use Symfony\Component\Security\Http\Authenticator\AccessTokenAuthenticator;

/**
 * Grants access when the access token carries the OAuth2 scopes an attribute requires.
 *
 * An attribute lists the scopes it requires between parentheses, separated by spaces, which is the
 * separator RFC 6749 Appendix A leaves out of a scope token: "OAUTH2_SCOPE(profile:read admin:manage)"
 * requires both of them. Requiring any of several scopes instead is a matter of voting on several
 * attributes, as an access control rule does.
 *
 * The scopes the token was granted are read from the attribute AccessTokenAuthenticator fills in.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
 *
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 */
class OAuth2ScopeVoter implements CacheableVoterInterface
{
    private const ATTRIBUTE_PREFIX = 'OAUTH2_SCOPE(';

    /**
     * Reads the scopes an attribute requires, all of which are required.
     *
     * @return string[]|null the required scopes, or null when the attribute is not one of this voter
     *                       or lists no scope, so that an attribute of another voter is left alone
     *                       and a malformed one is abstained on rather than silently honored
     */
    public static function getRequiredScopes(string $attribute): ?array
    {
        if (!str_starts_with($attribute, self::ATTRIBUTE_PREFIX)) {
            return null;
        }

        if (!str_ends_with($attribute, ')')) {
            return null;
        }

        $scopes = substr($attribute, \strlen(self::ATTRIBUTE_PREFIX), -1);

        return preg_split('/\s+/', $scopes, flags: \PREG_SPLIT_NO_EMPTY) ?: null;
    }

    public function vote(TokenInterface $token, mixed $subject, array $attributes, ?Vote $vote = null): int
    {
        $result = VoterInterface::ACCESS_ABSTAIN;
        $grantedScopes = $this->getGrantedScopes($token);
        $missingScopes = [];

        foreach ($attributes as $attribute) {
            if (!\is_string($attribute) || null === $requiredScopes = self::getRequiredScopes($attribute)) {
                continue;
            }

            $result = VoterInterface::ACCESS_DENIED;

            if (!$missing = array_diff($requiredScopes, $grantedScopes)) {
                $vote?->addReason(\sprintf('The access token was granted %s.', implode(', ', $requiredScopes)));

                return VoterInterface::ACCESS_GRANTED;
            }

            $missingScopes[] = $missing;
        }

        if (VoterInterface::ACCESS_DENIED === $result) {
            $vote?->addReason(\sprintf('The access token was not granted %s.', implode(', ', array_unique(array_merge(...$missingScopes)))));
        }

        return $result;
    }

    public function supportsAttribute(string $attribute): bool
    {
        return str_starts_with($attribute, self::ATTRIBUTE_PREFIX);
    }

    public function supportsType(string $subjectType): bool
    {
        return true;
    }

    /**
     * @return string[]
     */
    private function getGrantedScopes(TokenInterface $token): array
    {
        if (!$token->hasAttribute(AccessTokenAuthenticator::SCOPE_ATTRIBUTE)) {
            return [];
        }

        $scopes = $token->getAttribute(AccessTokenAuthenticator::SCOPE_ATTRIBUTE);

        return \is_array($scopes) ? array_filter($scopes, \is_string(...)) : [];
    }
}

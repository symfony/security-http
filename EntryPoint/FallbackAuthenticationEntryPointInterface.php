<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Security\Http\EntryPoint;

/**
 * An entry point that only stands in for a firewall declaring no other one.
 *
 * An authenticator implements it when it can answer an unauthenticated request with a
 * meaningful challenge, but has no authentication to start and must therefore never win
 * over an entry point that does, e.g. a login form. A firewall that holds one of each
 * keeps picking the other, so that an authenticator gaining a fallback entry point never
 * makes an existing firewall ambiguous. Having no authentication to start, it also gets
 * no target path saved for it, so that answering an unauthenticated request never starts
 * a session.
 *
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 */
interface FallbackAuthenticationEntryPointInterface extends AuthenticationEntryPointInterface
{
}

<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Security\Http\Tests\Fixtures;

use ProxyManager\Proxy\LazyLoadingInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class LazyProxyManagerUser implements UserInterface, LazyLoadingInterface
{
    public bool $initialized = false;

    public function setProxyInitializer(?\Closure $initializer = null): void
    {
    }

    public function getProxyInitializer(): ?\Closure
    {
        return null;
    }

    public function initializeProxy(): bool
    {
        return $this->initialized = true;
    }

    public function isProxyInitialized(): bool
    {
        return $this->initialized;
    }

    public function getRoles(): array
    {
        return ['ROLE_USER'];
    }

    public function eraseCredentials(): void
    {
    }

    public function getUserIdentifier(): string
    {
        return 'test';
    }
}

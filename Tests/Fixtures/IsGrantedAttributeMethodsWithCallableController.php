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

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Attribute\IsGranted;

class IsGrantedAttributeMethodsWithCallableController
{
    public function noAttribute()
    {
    }

    #[IsGranted(static function ($token, $accessDecisionManager, ...$vars) {
        return $accessDecisionManager->decide($token, ['ROLE_ADMIN']);
    })]
    public function admin()
    {
    }

    #[IsGranted(static function ($token, $accessDecisionManager, ...$vars) {
        return $accessDecisionManager->decide($token, ['ROLE_ADMIN']);
    }, subject: 'arg2Name')]
    public function withSubject($arg1Name, $arg2Name)
    {
    }

    #[IsGranted(static function ($token, $accessDecisionManager, ...$vars) {
        return $accessDecisionManager->decide($token, ['ROLE_ADMIN']);
    }, subject: ['arg1Name', 'arg2Name'])]
    public function withSubjectArray($arg1Name, $arg2Name)
    {
    }

    #[IsGranted(static function ($token, $accessDecisionManager, ...$vars) {
        return $accessDecisionManager->decide($token, ['ROLE_ADMIN']);
    }, subject: 'non_existent')]
    public function withMissingSubject()
    {
    }

    #[IsGranted(static function ($token, $accessDecisionManager, ...$vars) {
        return $accessDecisionManager->decide($token, ['ROLE_ADMIN']);
    }, message: 'Not found', statusCode: 404)]
    public function notFound()
    {
    }

    #[IsGranted(static function ($token, $accessDecisionManager, ...$vars) {
        return $accessDecisionManager->decide($token, ['ROLE_ADMIN']);
    }, message: 'Exception Code Http', statusCode: 404, exceptionCode: 10010)]
    public function exceptionCodeInHttpException()
    {
    }

    #[IsGranted(static function ($token, $accessDecisionManager, ...$vars) {
        return $accessDecisionManager->decide($token, ['ROLE_ADMIN']);
    }, message: 'Exception Code Access Denied', exceptionCode: 10010)]
    public function exceptionCodeInAccessDeniedException()
    {
    }

    #[IsGranted(
        static function (TokenInterface $token, $subject, ...$vars) {
            return $token->getUser() === $subject;
        },
        subject: static function (array $args) {
            return $args['post'];
        }
    )]
    public function withCallableAsSubject($post)
    {
    }

    #[IsGranted(static function ($token, $subject, ...$vars) {
        return $token->getUser() === $subject['author'];
    }, subject: static function (array $args) {
        return [
            'author' => $args['post'],
            'alias' => 'bar',
        ];
    })]
    public function withNestArgsInSubject($post, $arg2Name)
    {
    }
}

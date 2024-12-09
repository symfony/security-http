<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Security\Http\Tests\EventListener;

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ControllerArgumentsEvent;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Http\EventListener\IsGrantedAttributeListener;
use Symfony\Component\Security\Http\Tests\Fixtures\IsGrantedAttributeMethodsWithCallableController;
use Symfony\Component\Security\Http\Tests\Fixtures\IsGrantedAttributeWithCallableController;

/**
 * @requires PHP 8.5
 */
class IsGrantedAttributeWithCallableListenerTest extends TestCase
{
    public function testAttribute()
    {
        $authChecker = $this->createMock(AuthorizationCheckerInterface::class);
        $authChecker->expects($this->exactly(2))
            ->method('isGranted')
            ->willReturn(true);

        $event = new ControllerArgumentsEvent(
            $this->createMock(HttpKernelInterface::class),
            [new IsGrantedAttributeWithCallableController(), 'foo'],
            [],
            new Request(),
            null
        );

        $listener = new IsGrantedAttributeListener($authChecker);
        $listener->onKernelControllerArguments($event);

        $authChecker = $this->createMock(AuthorizationCheckerInterface::class);
        $authChecker->expects($this->once())
            ->method('isGranted')
            ->willReturn(true);

        $event = new ControllerArgumentsEvent(
            $this->createMock(HttpKernelInterface::class),
            [new IsGrantedAttributeWithCallableController(), 'bar'],
            [],
            new Request(),
            null
        );

        $listener = new IsGrantedAttributeListener($authChecker);
        $listener->onKernelControllerArguments($event);
    }

    public function testNothingHappensWithNoConfig()
    {
        $authChecker = $this->createMock(AuthorizationCheckerInterface::class);
        $authChecker->expects($this->never())
            ->method('isGranted');

        $event = new ControllerArgumentsEvent(
            $this->createMock(HttpKernelInterface::class),
            [new IsGrantedAttributeMethodsWithCallableController(), 'noAttribute'],
            [],
            new Request(),
            null
        );

        $listener = new IsGrantedAttributeListener($authChecker);
        $listener->onKernelControllerArguments($event);
    }

    public function testIsGrantedCalledCorrectly()
    {
        $authChecker = $this->createMock(AuthorizationCheckerInterface::class);
        $authChecker->expects($this->once())
            ->method('isGranted')
            ->with($this->isInstanceOf(\Closure::class), null)
            ->willReturn(true);

        $event = new ControllerArgumentsEvent(
            $this->createMock(HttpKernelInterface::class),
            [new IsGrantedAttributeMethodsWithCallableController(), 'admin'],
            [],
            new Request(),
            null
        );

        $listener = new IsGrantedAttributeListener($authChecker);
        $listener->onKernelControllerArguments($event);
    }

    public function testIsGrantedSubjectFromArguments()
    {
        $authChecker = $this->createMock(AuthorizationCheckerInterface::class);
        $authChecker->expects($this->once())
            ->method('isGranted')
            // the subject => arg2name will eventually resolve to the 2nd argument, which has this value
            ->with($this->isInstanceOf(\Closure::class), 'arg2Value')
            ->willReturn(true);

        $event = new ControllerArgumentsEvent(
            $this->createMock(HttpKernelInterface::class),
            [new IsGrantedAttributeMethodsWithCallableController(), 'withSubject'],
            ['arg1Value', 'arg2Value'],
            new Request(),
            null
        );

        // create metadata for 2 named args for the controller
        $listener = new IsGrantedAttributeListener($authChecker);
        $listener->onKernelControllerArguments($event);
    }

    public function testIsGrantedSubjectFromArgumentsWithArray()
    {
        $authChecker = $this->createMock(AuthorizationCheckerInterface::class);
        $authChecker->expects($this->once())
            ->method('isGranted')
            // the subject => arg2name will eventually resolve to the 2nd argument, which has this value
            ->with($this->isInstanceOf(\Closure::class), [
                'arg1Name' => 'arg1Value',
                'arg2Name' => 'arg2Value',
            ])
            ->willReturn(true);

        $event = new ControllerArgumentsEvent(
            $this->createMock(HttpKernelInterface::class),
            [new IsGrantedAttributeMethodsWithCallableController(), 'withSubjectArray'],
            ['arg1Value', 'arg2Value'],
            new Request(),
            null
        );

        // create metadata for 2 named args for the controller
        $listener = new IsGrantedAttributeListener($authChecker);
        $listener->onKernelControllerArguments($event);
    }

    public function testIsGrantedNullSubjectFromArguments()
    {
        $authChecker = $this->createMock(AuthorizationCheckerInterface::class);
        $authChecker->expects($this->once())
            ->method('isGranted')
            ->with($this->isInstanceOf(\Closure::class), null)
            ->willReturn(true);

        $event = new ControllerArgumentsEvent(
            $this->createMock(HttpKernelInterface::class),
            [new IsGrantedAttributeMethodsWithCallableController(), 'withSubject'],
            ['arg1Value', null],
            new Request(),
            null
        );

        $listener = new IsGrantedAttributeListener($authChecker);
        $listener->onKernelControllerArguments($event);
    }

    public function testIsGrantedArrayWithNullValueSubjectFromArguments()
    {
        $authChecker = $this->createMock(AuthorizationCheckerInterface::class);
        $authChecker->expects($this->once())
            ->method('isGranted')
            ->with($this->isInstanceOf(\Closure::class), [
                'arg1Name' => 'arg1Value',
                'arg2Name' => null,
            ])
            ->willReturn(true);

        $event = new ControllerArgumentsEvent(
            $this->createMock(HttpKernelInterface::class),
            [new IsGrantedAttributeMethodsWithCallableController(), 'withSubjectArray'],
            ['arg1Value', null],
            new Request(),
            null
        );

        $listener = new IsGrantedAttributeListener($authChecker);
        $listener->onKernelControllerArguments($event);
    }

    public function testExceptionWhenMissingSubjectAttribute()
    {
        $authChecker = $this->createMock(AuthorizationCheckerInterface::class);

        $event = new ControllerArgumentsEvent(
            $this->createMock(HttpKernelInterface::class),
            [new IsGrantedAttributeMethodsWithCallableController(), 'withMissingSubject'],
            [],
            new Request(),
            null
        );

        $listener = new IsGrantedAttributeListener($authChecker);

        $this->expectException(\RuntimeException::class);

        $listener->onKernelControllerArguments($event);
    }

    /**
     * @dataProvider getAccessDeniedMessageTests
     */
    public function testAccessDeniedMessages(string|array|null $subject, string $method, int $numOfArguments, string $expectedMessage)
    {
        $authChecker = $this->createMock(AuthorizationCheckerInterface::class);
        $authChecker->expects($this->any())
            ->method('isGranted')
            ->willReturn(false);

        // avoid the error of the subject not being found in the request attributes
        $arguments = array_fill(0, $numOfArguments, 'bar');
        $listener = new IsGrantedAttributeListener($authChecker);

        $event = new ControllerArgumentsEvent(
            $this->createMock(HttpKernelInterface::class),
            [new IsGrantedAttributeMethodsWithCallableController(), $method],
            $arguments,
            new Request(),
            null
        );

        try {
            $listener->onKernelControllerArguments($event);
            $this->fail();
        } catch (AccessDeniedException $e) {
            $this->assertSame($expectedMessage, $e->getMessage());
            $this->assertIsCallable($e->getAttributes()[0]);
            if (null !== $subject) {
                $this->assertSame($subject, $e->getSubject());
            } else {
                $this->assertNull($e->getSubject());
            }
        }
    }

    public static function getAccessDeniedMessageTests()
    {
        yield [null, 'admin', 0, 'Access Denied by #[IsGranted({closure:Symfony\Component\Security\Http\Tests\Fixtures\IsGrantedAttributeMethodsWithCallableController::admin():23})] on controller'];
        yield ['bar', 'withSubject', 2, 'Access Denied by #[IsGranted({closure:Symfony\Component\Security\Http\Tests\Fixtures\IsGrantedAttributeMethodsWithCallableController::withSubject():30}, "arg2Name")] on controller'];
        yield [['arg1Name' => 'bar', 'arg2Name' => 'bar'], 'withSubjectArray', 2, 'Access Denied by #[IsGranted({closure:Symfony\Component\Security\Http\Tests\Fixtures\IsGrantedAttributeMethodsWithCallableController::withSubjectArray():37}, ["arg1Name", "arg2Name"])] on controller'];
        yield ['bar', 'withCallableAsSubject', 1, 'Access Denied by #[IsGranted({closure:Symfony\Component\Security\Http\Tests\Fixtures\IsGrantedAttributeMethodsWithCallableController::withCallableAsSubject():73}, {closure:Symfony\Component\Security\Http\Tests\Fixtures\IsGrantedAttributeMethodsWithCallableController::withCallableAsSubject():76})] on controller'];
        yield [['author' => 'bar', 'alias' => 'bar'], 'withNestArgsInSubject', 2, 'Access Denied by #[IsGranted({closure:Symfony\Component\Security\Http\Tests\Fixtures\IsGrantedAttributeMethodsWithCallableController::withNestArgsInSubject():84}, {closure:Symfony\Component\Security\Http\Tests\Fixtures\IsGrantedAttributeMethodsWithCallableController::withNestArgsInSubject():86})] on controller'];
    }

    public function testNotFoundHttpException()
    {
        $authChecker = $this->createMock(AuthorizationCheckerInterface::class);
        $authChecker->expects($this->any())
            ->method('isGranted')
            ->willReturn(false);

        $event = new ControllerArgumentsEvent(
            $this->createMock(HttpKernelInterface::class),
            [new IsGrantedAttributeMethodsWithCallableController(), 'notFound'],
            [],
            new Request(),
            null
        );

        $listener = new IsGrantedAttributeListener($authChecker);

        $this->expectException(HttpException::class);
        $this->expectExceptionMessage('Not found');

        $listener->onKernelControllerArguments($event);
    }

    public function testIsGrantedWithCallableAsSubject()
    {
        $request = new Request();

        $authChecker = $this->createMock(AuthorizationCheckerInterface::class);
        $authChecker->expects($this->once())
            ->method('isGranted')
            ->with($this->isInstanceOf(\Closure::class), 'postVal')
            ->willReturn(true);

        $event = new ControllerArgumentsEvent(
            $this->createMock(HttpKernelInterface::class),
            [new IsGrantedAttributeMethodsWithCallableController(), 'withCallableAsSubject'],
            ['postVal'],
            $request,
            null
        );

        $listener = new IsGrantedAttributeListener($authChecker);
        $listener->onKernelControllerArguments($event);
    }

    public function testIsGrantedWithNestedExpressionInSubject()
    {
        $request = new Request();

        $authChecker = $this->createMock(AuthorizationCheckerInterface::class);
        $authChecker->expects($this->once())
            ->method('isGranted')
            ->with($this->isInstanceOf(\Closure::class), ['author' => 'postVal', 'alias' => 'bar'])
            ->willReturn(true);

        $event = new ControllerArgumentsEvent(
            $this->createMock(HttpKernelInterface::class),
            [new IsGrantedAttributeMethodsWithCallableController(), 'withNestArgsInSubject'],
            ['postVal', 'bar'],
            $request,
            null
        );

        $listener = new IsGrantedAttributeListener($authChecker);
        $listener->onKernelControllerArguments($event);
    }

    public function testHttpExceptionWithExceptionCode()
    {
        $authChecker = $this->createMock(AuthorizationCheckerInterface::class);
        $authChecker->expects($this->any())
            ->method('isGranted')
            ->willReturn(false);

        $event = new ControllerArgumentsEvent(
            $this->createMock(HttpKernelInterface::class),
            [new IsGrantedAttributeMethodsWithCallableController(), 'exceptionCodeInHttpException'],
            [],
            new Request(),
            null
        );

        $listener = new IsGrantedAttributeListener($authChecker);

        $this->expectException(HttpException::class);
        $this->expectExceptionMessage('Exception Code');
        $this->expectExceptionCode(10010);

        $listener->onKernelControllerArguments($event);
    }

    public function testAccessDeniedExceptionWithExceptionCode()
    {
        $authChecker = $this->createMock(AuthorizationCheckerInterface::class);
        $authChecker->expects($this->any())
            ->method('isGranted')
            ->willReturn(false);

        $event = new ControllerArgumentsEvent(
            $this->createMock(HttpKernelInterface::class),
            [new IsGrantedAttributeMethodsWithCallableController(), 'exceptionCodeInAccessDeniedException'],
            [],
            new Request(),
            null
        );

        $listener = new IsGrantedAttributeListener($authChecker);

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessage('Exception Code');
        $this->expectExceptionCode(10010);

        $listener->onKernelControllerArguments($event);
    }
}

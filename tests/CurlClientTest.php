<?php
declare(strict_types = 1);

namespace Embed\Tests;

use Embed\Http\BlockedRequestException;
use Embed\Http\CurlClient;
use Embed\Http\NetworkException;
use Embed\Http\UrlPolicy;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

class CurlClientTest extends TestCase
{
    private static LocalHttpServer $server;
    private static string $cookies;

    public static function setUpBeforeClass(): void
    {
        self::clearProxyEnvironment();
        self::$server = LocalHttpServer::start();
        $cookies = tempnam(sys_get_temp_dir(), 'embed-cookies-');
        if ($cookies === false) {
            throw new \RuntimeException('Unable to create a cookie jar');
        }
        self::$cookies = $cookies;
    }

    public static function tearDownAfterClass(): void
    {
        self::$server->stop();
        self::clearProxyEnvironment();
        if (isset(self::$cookies) && is_file(self::$cookies)) {
            unlink(self::$cookies);
        }
    }

    protected function setUp(): void
    {
        self::clearProxyEnvironment();
        self::$server->clearLog();
        if (is_file(self::$cookies)) {
            file_put_contents(self::$cookies, '');
        }
    }

    public function testInternationalizedHostIsPinnedInPunycode(): void
    {
        if (!function_exists('idn_to_ascii')) {
            $this->markTestSkipped('The intl extension is required to resolve IDN hosts.');
        }

        $seen = null;
        $policy = UrlPolicy::default()
            ->withAllowedHosts('bücher.example')
            ->withResolver(static function (string $host) use (&$seen): array {
                $seen = $host;

                return ['127.0.0.1'];
            });

        $response = $this->client([], $policy)->sendRequest(
            $this->request('http://bücher.example:'.self::$server->port().'/landed')
        );

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('xn--bcher-kva.example', $seen);
        $this->assertSame(['/landed'], self::$server->paths());
    }

    public function testPinnedHostReachesTheLocalServer(): void
    {
        $response = $this->client()->sendRequest($this->request($this->url('/landed')));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('ok', (string) $response->getBody());
        $this->assertSame($this->url('/landed'), $response->getHeaderLine('Content-Location'));
        $this->assertSame(['/landed'], self::$server->paths());
    }

    /**
     * @return array<string, array{0: int}>
     */
    public function redirectStatusProvider(): array
    {
        return [
            '301' => [301],
            '302' => [302],
            '303' => [303],
            '307' => [307],
            '308' => [308],
        ];
    }

    /**
     * @dataProvider redirectStatusProvider
     */
    public function testRedirectToLoopbackIsBlockedBeforeItIsRequested(int $status): void
    {
        $target = 'http://127.0.0.1:'.self::$server->port().'/secret';

        $exception = $this->captureBlocked(function () use ($status, $target): void {
            $this->client()->sendRequest($this->request($this->url('/go?code='.$status.'&to='.rawurlencode($target))));
        });

        $this->assertSame('non_public_address', $exception->getReason());
        $this->assertStringNotContainsString('127.0.0.1', $exception->getMessage());
        $this->assertSame(['/go'], self::$server->paths());
    }

    public function testRedirectToPrivateNameIsBlockedWithoutLeakingTheAddress(): void
    {
        $target = 'http://internal.test:'.self::$server->port().'/secret';

        $exception = $this->captureBlocked(function () use ($target): void {
            $this->client()->sendRequest($this->request($this->url('/go?code=302&to='.rawurlencode($target))));
        });

        $this->assertSame('non_public_address', $exception->getReason());
        $this->assertStringNotContainsString('10.0.0.1', $exception->getMessage());
        $this->assertSame(['/go'], self::$server->paths());
    }

    public function testRelativeRedirectKeepsTheBasePort(): void
    {
        $response = $this->client()->sendRequest($this->request($this->url('/go?code=302&to='.rawurlencode('/landed'))));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame($this->url('/landed'), $response->getHeaderLine('Content-Location'));
        $this->assertSame(['/go', '/landed'], self::$server->paths());
    }

    public function testProtocolRelativeLoopbackIsBlocked(): void
    {
        $this->captureBlocked(function (): void {
            $this->client()->sendRequest($this->request($this->url('/go?code=302&to='.rawurlencode('//127.0.0.1/secret'))));
        });

        $this->assertSame(['/go'], self::$server->paths());
    }

    /**
     * @return array<string, array{0: string, 1: string}>
     */
    public function forbiddenSchemeProvider(): array
    {
        return [
            'file' => ['file:///etc/passwd', 'scheme'],
            'gopher' => ['gopher://127.0.0.1/secret', 'scheme'],
        ];
    }

    /**
     * @dataProvider forbiddenSchemeProvider
     */
    public function testRedirectToForbiddenSchemeIsBlocked(string $target, string $reason): void
    {
        $exception = $this->captureBlocked(function () use ($target): void {
            $this->client()->sendRequest($this->request($this->url('/go?code=302&to='.rawurlencode($target))));
        });

        $this->assertSame($reason, $exception->getReason());
        $this->assertSame(['/go'], self::$server->paths());
    }

    public function testUnparseableRedirectIsBlocked(): void
    {
        $exception = $this->captureBlocked(function (): void {
            $this->client()->sendRequest($this->request($this->url('/go?code=302&to='.rawurlencode('http://'))));
        });

        $this->assertSame('redirect', $exception->getReason());
        $this->assertSame(['/go'], self::$server->paths());
    }

    public function testThreeHopChainUsesTheFinalUrl(): void
    {
        $response = $this->client()->sendRequest($this->request($this->url('/chain?i=0&n=3')));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('done', (string) $response->getBody());
        $this->assertSame($this->url('/chain?i=3&n=3'), $response->getHeaderLine('Content-Location'));
        $this->assertSame(
            ['/chain', '/chain', '/chain', '/chain'],
            self::$server->paths()
        );
        $queries = array_map(static function (array $row): string {
            return $row['query'] ?? '';
        }, self::$server->requests());
        $this->assertSame(['i=0&n=3', 'i=1&n=3', 'i=2&n=3', 'i=3&n=3'], $queries);
    }

    public function testTooManyRedirectsUsesCurlErrorCode(): void
    {
        try {
            $this->client()->sendRequest($this->request($this->url('/chain?i=0&n=11')));
            $this->fail('The eleventh redirect must fail.');
        } catch (NetworkException $exception) {
            $this->assertSame(47, $exception->getCode());
        }

        $queries = array_map(static function (array $row): string {
            return $row['query'] ?? '';
        }, self::$server->requests());
        $this->assertNotContains('i=11&n=11', $queries);
        $this->assertContains('i=10&n=11', $queries);
        $this->assertCount(11, $queries);
    }

    public function testFollowLocationFalseReturnsTheRedirect(): void
    {
        $response = $this->client(['follow_location' => false])->sendRequest($this->request($this->url('/go?code=302&to='.rawurlencode('/landed'))));

        $this->assertSame(302, $response->getStatusCode());
        $this->assertSame(['/go'], self::$server->paths());
    }

    public function testCookieFromTheRedirectIsSentOnTheNextHop(): void
    {
        $response = $this->client()->sendRequest($this->request($this->url('/set-cookie')));

        $this->assertSame(200, $response->getStatusCode());
        $rows = self::$server->requests();
        $this->assertCount(2, $rows);
        $this->assertSame('/read-cookie', $rows[1]['path']);
        $this->assertStringContainsString('consent=yes', $rows[1]['cookie']);
    }

    public function testAuthorizationAndCookieAreStrippedWhenTheHostChanges(): void
    {
        $factory = new Psr17Factory();
        $request = $factory->createRequest('GET', $this->url('/to-other?port='.self::$server->port()))
            ->withHeader('Authorization', 'Bearer secret')
            ->withHeader('Cookie', 'a=b');

        $response = $this->client()->sendRequest($request);

        $this->assertSame(200, $response->getStatusCode());
        $rows = self::$server->requests();
        $this->assertCount(2, $rows);
        $this->assertSame('Bearer secret', $rows[0]['authorization']);
        $this->assertSame('', $rows[1]['authorization']);
        $this->assertSame('', $rows[1]['cookie']);
        $this->assertStringContainsString('other.test', $rows[1]['host']);
    }

    public function testPostRedirectsToGetExceptFor307And308(): void
    {
        $factory = new Psr17Factory();
        $body = $factory->createStream('payload');
        $request = $factory->createRequest('POST', $this->url('/switch?code=302'))->withBody($body);

        $this->client()->sendRequest($request);

        $rows = self::$server->requests();
        $this->assertSame('POST', $rows[0]['method']);
        $this->assertSame('GET', $rows[1]['method']);
        $this->assertSame('', $rows[1]['body']);

        self::$server->clearLog();
        $again = $factory->createRequest('POST', $this->url('/switch?code=307'))
            ->withBody($factory->createStream('payload'));
        $this->client()->sendRequest($again);
        $rows = self::$server->requests();
        $this->assertSame('POST', $rows[0]['method']);
        $this->assertSame('POST', $rows[1]['method']);
        $this->assertSame('payload', $rows[1]['body']);
    }

    public function testDnsRebindingDoesNotMoveTheConnection(): void
    {
        $calls = 0;
        $policy = UrlPolicy::default()
            ->withAllowedHosts('rebind.test')
            ->withResolver(static function (string $host) use (&$calls): array {
                ++$calls;
                if ($host === 'rebind.test' && $calls > 1) {
                    return ['10.0.0.1'];
                }

                return ['127.0.0.1'];
            });

        $response = $this->client([], $policy)->sendRequest(
            $this->request('http://rebind.test:'.self::$server->port().'/landed')
        );

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame(1, $calls);
        $this->assertSame(['/landed'], self::$server->paths());
    }

    public function testParallelRequestsFollowRedirects(): void
    {
        $factory = new Psr17Factory();
        $responses = $this->client()->sendRequests(
            $factory->createRequest('GET', $this->url('/chain?i=0&n=1')),
            $factory->createRequest('GET', $this->url('/landed'))
        );

        $this->assertCount(2, $responses);
        $this->assertSame(200, $responses[0]->getStatusCode());
        $this->assertSame(200, $responses[1]->getStatusCode());
        $this->assertSame($this->url('/chain?i=1&n=1'), $responses[0]->getHeaderLine('Content-Location'));
        $this->assertContains('/landed', self::$server->paths());
        $this->assertContains('/chain', self::$server->paths());
    }

    public function testParallelBatchIsRejectedBeforeAnyRequestWhenOneUrlIsBlocked(): void
    {
        $factory = new Psr17Factory();

        $exception = $this->captureBlocked(function () use ($factory): void {
            $this->client()->sendRequests(
                $factory->createRequest('GET', $this->url('/landed')),
                $factory->createRequest('GET', 'http://127.0.0.1/secret')
            );
        });

        $this->assertSame('non_public_address', $exception->getReason());
        $this->assertSame([], self::$server->paths());
    }

    public function testEnvironmentProxyKeepsPreValidationAndDoesNotConnectDirectly(): void
    {
        putenv('http_proxy=http://127.0.0.1:9');

        try {
            $blocked = $this->captureBlocked(function (): void {
                $this->client()->sendRequest($this->request('http://127.0.0.1/secret'));
            });
            $this->assertSame('non_public_address', $blocked->getReason());
            $this->assertSame([], self::$server->paths());

            try {
                $this->client()->sendRequest($this->request($this->url('/landed')));
                $this->fail('A configured proxy must be used for the connection.');
            } catch (NetworkException $exception) {
                $this->assertNotSame(0, $exception->getCode());
            }
            $this->assertSame([], self::$server->paths());
        } finally {
            putenv('http_proxy');
        }
    }

    /**
     * @param array<string, mixed> $settings
     */
    private function client(array $settings = [], ?UrlPolicy $policy = null): CurlClient
    {
        $client = new CurlClient();
        $client->setUrlPolicy($policy ?? $this->policy());
        $client->setSettings($settings + [
            'timeout' => 3,
            'connect_timeout' => 3,
            'cookies_path' => self::$cookies,
            'follow_location' => true,
            'max_redirs' => 10,
        ]);

        return $client;
    }

    private function policy(): UrlPolicy
    {
        return UrlPolicy::default()
            ->withAllowedHosts('allowed.test', 'other.test')
            ->withResolver(static function (string $host): array {
                if ($host === 'allowed.test' || $host === 'other.test') {
                    return ['127.0.0.1'];
                }
                if ($host === 'internal.test') {
                    return ['10.0.0.1'];
                }

                return [];
            });
    }

    private function url(string $path): string
    {
        return 'http://allowed.test:'.self::$server->port().$path;
    }

    private function request(string $uri): RequestInterface
    {
        return (new Psr17Factory())->createRequest('GET', $uri);
    }

    /**
     * @param callable(): void $check
     */
    private function captureBlocked(callable $check): BlockedRequestException
    {
        try {
            $check();
        } catch (BlockedRequestException $exception) {
            return $exception;
        }

        $this->fail('Expected BlockedRequestException');
    }

    private static function clearProxyEnvironment(): void
    {
        foreach (['http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY', 'all_proxy', 'ALL_PROXY'] as $name) {
            putenv($name);
            unset($_ENV[$name], $_SERVER[$name]);
        }
    }
}

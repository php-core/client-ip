<?php

namespace PHPCore;

/**
 * Client IP
 *
 * Get client IP with safe and coincident way from server even behind CloudFlare, Proxy
 * or Load-Balancer.
 *
 * @author      iSecNew10 <dev@isecnew10.com>
 * @version     1.0.1
 * @author      Nick Tsai <myintaer@gmail.com>
 * @version     1.0.0
 * @example
 *  $ip = ClientIP::get();                      // Get client IP
 *
 * @example
 *  // Set specific proxys
 *  ClientIP::config([
 *      'proxyIPs' => ['192.168.1.2']
 *  ]);
 *  $ip = ClientIP::get();                      // Get Forward IP if via the proxy
 *
 * @example
 *  // Set a range of private network
 *  ClientIP::config([
 *      'proxyIPs' => ['192.168.0.0/16']
 *  ]);
 *  $ip = ClientIP::get();                      // Get Forward IP if via lan proxies
 *
 * @example
 *  // Set as Proxy mode
 *  ClientIP::config([
 *      'proxyIPs' => true
 *  ]);
 *  $ip = ClientIP::get();                      // Get Forward IP always
 *
 * @example
 *  // Set as Proxy mode by calling method
 *  ClientIP::proxyMode();                      // Set proxyIPs as true
 *  ClientIP::config([
 *      'headerKeys' => ['HTTP_X_FORWARDED_FOR']
 *  ]);
 *  $ip = ClientIP::get();                      // Get x-Forward-for IP always
 */
class ClientIP
{
	/**
	 * @var array|null $proxyIPs IP list of Proxy servers
	 *
	 * Specify Proxies when your server is in public network, but also receives
	 * from Specified Load-Balancer or Proxy.
	 * This only works while the value is not empty and proxy mode is off.
	 */
	public static ?array $proxyIPs = null;

	public static bool $disableCache = false;

	/**
	 * @var array $headerKeys Header Key list for IP Forward
	 */
	public static array $headerKeys = [
		'HTTP_CF_CONNECTING_IP', // CloudFlare
		'HTTP_CLIENT_IP',
		'HTTP_X_FORWARDED_FOR',
		'HTTP_X_FORWARDED',
		'HTTP_X_CLUSTER_CLIENT_IP',
		'HTTP_FORWARDED_FOR',
		'HTTP_FORWARDED',
		'HTTP_VIA',
	];

	/**
	 * @var string|null $cachedIP cache of Client IP
	 */
	private static ?string $cachedIP = null;

	/**
	 * Set configuration
	 *
	 * @param mixed $config Configuration Array
	 * @return ClientIP
	 */
	public static function config(array $config): ClientIP
	{
		self::$proxyIPs = !empty($config['proxyIPs'])
			? (is_string($proxyIPs = $config['proxyIPs'])
				? (self::validateIP($proxyIPs)
					? [$proxyIPs]
					: null
				)
				: $proxyIPs
			)
			: self::$proxyIPs;

		self::$headerKeys = (isset($config['headerKeys']))
			? (array)$config['headerKeys']
			: self::$headerKeys;

		self::$disableCache = !empty($config['disableCache']);

		// Clear cachedIP
		self::$cachedIP = null;

		return new self;
	}

	/**
	 * Set as proxy mode
	 *
	 * @return ClientIP
	 */
	public static function proxyMode(): ClientIP
	{
		self::$proxyIPs = [];

		// Clear cachedIP
		self::$cachedIP = null;

		return new self;
	}

	public static function get(): ?string
	{
		// Check cache
		if (self::$disableCache) {
			self::$cachedIP = null;
		}
		if (!empty(self::$cachedIP)) {
			return self::$cachedIP;
		}

		if (empty($proxyIPs = self::$proxyIPs)) {
			return self::$cachedIP = self::getForwardIP();
		} else {
			/* Proxy Mode */
			if (is_array($proxyIPs)) {

				// Get the forward IP from active header
				foreach (array_merge(['REMOTE_ADDR'], self::$headerKeys) as $header) {

					if (!empty($headerIp = $_SERVER[$header] ?? null)) {

						// Some proxies typically list the whole chain of IP
						// addresses through which the client has reached us.
						// e.g. client_ip, proxy_ip1, proxy_ip2, etc.
						sscanf($headerIp, '%[^,]', $headerIp);

						if (!self::validateIP($headerIp)) {
							$headerIp = null;
						} else {
							break;
						}
					}
				}

				if (!empty($headerIp)) {

					for ($i = 0, $c = count($proxyIPs); $i < $c; $i++) {

						// Check if we have an IP address or a subnet
						if (!str_contains($proxyIPs[$i], '/')) {

							// An IP address (and not a subnet) is specified.
							// We can compare right away.
							if ($proxyIPs[$i] === self::$cachedIP) {

								self::$cachedIP = $headerIp;
								break;
							}

							continue;
						}

						// We have a subnet ... now the heavy lifting begins
						isset($separator) or $separator = self::validateIP(self::$cachedIP, 'ipv6') ? ':' : '.';

						// If the proxy entry doesn't match the IP protocol - skip it
						if (!str_contains($proxyIPs[$i], $separator)) {

							continue;
						}

						// Convert the REMOTE_ADDR IP address to binary, if needed
						if (!isset($ip, $sprintf)) {

							if ($separator === ':') {

								// Make sure we're have the "full" IPv6 format
								$ip = explode(':',
									str_replace('::',
										str_repeat(':', 9 - substr_count(self::$cachedIP, ':')),
										self::$cachedIP
									)
								);

								for ($j = 0; $j < 8; $j++) {

									$ip[$j] = intval($ip[$j], 16);
								}

								$sprintf = '%016b%016b%016b%016b%016b%016b%016b%016b';
							} else {

								$ip = explode('.', self::$cachedIP);
								$sprintf = '%08b%08b%08b%08b';
							}

							$ip = vsprintf($sprintf, $ip);
						}

						// Split the netmask length off the network address
						sscanf($proxyIPs[$i], '%[^/]/%d', $netAddress, $masklen);

						// Again, an IPv6 address is most likely in a compressed form
						if ($separator === ':') {

							$netAddress = explode(':', str_replace('::', str_repeat(':', 9 - substr_count((string)$netAddress, ':')), $netAddress));
							for ($j = 0; $j < 8; $j++) {
								$netAddress[$j] = intval($netAddress[$j], 16);
							}
						} else {

							$netAddress = explode('.', (string)$netAddress);
						}

						// Convert to binary and finally compare
						if (strncmp($ip, vsprintf($sprintf, $netAddress), $masklen) === 0) {

							self::$cachedIP = $headerIp;
							break;
						}
					}
				}
			}
		}

		return empty(self::$cachedIP) ? self::getForwardIP() : self::$cachedIP;
	}

	/**
	 * Get Forward IP
	 *
	 * @return string|null Forward IP
	 */
	public static function getRemoteIP(): ?string
	{
		return $_SERVER['REMOTE_ADDR'] ?? null;
	}

	/**
	 * Get Forward IP
	 *
	 * @return string|null Forward IP
	 */
	public static function getForwardIP(): ?string
	{
		// Match headers
		foreach (self::$headerKeys as $key => $headerKey) {

			if (isset($_SERVER[$headerKey])) {

				if (self::validateIP($_SERVER[$headerKey])) {

					return self::$cachedIP = $_SERVER[$headerKey];
				}
			}
		}

		// No matched IP from Proxy header
		return self::getRemoteIP();
	}

	/**
	 * Validate IP
	 *
	 * @param string $ip
	 * @param string $version
	 * @return bool IP with validation
	 */
	private static function validateIP(string $ip, string $version = 'ipv4'): bool
	{
		$version = match (strtolower($version)) {
			'ipv4' => FILTER_FLAG_IPV4,
			'ipv6' => FILTER_FLAG_IPV6,
			default => null,
		};

		return (bool)filter_var($ip, FILTER_VALIDATE_IP, $version);
	}
}


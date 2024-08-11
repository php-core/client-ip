# client-ip

Get client IP in PHP even behind CloudFlare, Proxy or Load-Balancer.
=============== 

---

Thanks to https://github.com/yidas/php-client-ip for the idea of making a package for this and also providing a base structure for the class.

INSTALLATION
------------

Run Composer in your project:

    composer require php-core/client-ip

Then initialize it at the bootstrap of application such as `config` file:

```php
require __DIR__ . '/vendor/autoload.php';
ClientIP::config([
   'proxyIPs' => ['192.168.0.0/16']
]);
```

---

CONFIGURATION
-------------

Example configuration:

```php
ClientIP::config([
   'proxyIPs' => ['192.168.0.0/16', '172.217.2.89'],
   'headerKeys' => ['HTTP_X_FORWARDED_FOR'],
]);
```

| Attribute | Type  | Description                                                        |
|---------|-------|--------------------------------------------------------------------|
|proxyIPs | array | Trust Proxies' IP list, which support subnet mask for each IP set. |
|headerKeys | array | Header Key list for IP Forward.                                    |
|disableCache | bool  | Disable runtime cache.                                             |
---

Examples
-------------

```php
echo ClientIP::get();
ClientIP::config([
    'proxyIPs' => ['192.168.0.0/16', '172.217.3.11'],
    'headerKeys' => ['HTTP_X_FORWARDED_FOR']
]);
echo ClientIP::get();
```

By default, the system caches the IP in runtime, to disable it, (for example for amphp's web-server), use `disableCache`:
```php
ClientIP::config([
    'disableCache' => true
]);
echo ClientIP::get();
```

If the client IP is `203.169.1.37`, there are some connection situation for demonstrating referring by above sample code:

### Load-Balancer normal network

your server is behind a Load-Balencer and in a private network.

| Client         | Load-Balancer  | Server        |
|:--------------:|:--------------:|:-------------:|
| 203.169.1.37 → | 172.217.2.88 ↓ |               |
|                | 192.168.0.10 → | 192.168.4.100 |

```php
ClientIP::config([
    'proxyIPs' => true
]);
```

Setting `proxyIPs` as `true` means all requests are go through Load-balancer, which will always get forward IP, same as above setting:

```php
ClientIP::config([
    'proxyIPs' => ['0.0.0.0/32']
]);
```

**The result from the server:**

```
192.168.0.10 //Before setting the config
203.169.1.37 //After setting the config, get the forward IP
```

### Proxy optional network

If your server is in public network, not only receives requests directly, but also supports trust proxies for going through:

|     | Client         | Proxy          | Server        |
|:---:|:--------------:|:--------------:|:-------------:|
|Way 1| 203.169.1.37 → |                | 172.217.4.100 |
|Way 2| 203.169.1.37 → | 172.217.2.89 ↓ |               |
|     |                | 172.217.3.11 → | 172.217.4.100 |

```php
ClientIP::config([
    'proxyIPs' => ['172.217.3.11']
]);
```

**The result from the server**

- Way 1: Client connect to server directly:

```
203.169.1.37 //Before setting the config
203.169.1.37 //The request IP is not from proxyIPs, so identify as a Client.
```

- Way 2: Client connect to server through Proxy:

```
172.217.3.11 //Before setting the config
203.169.1.37 //The request IP comes from proxyIPs, get the forward IP.
```


---

DISCUSSION
----------

### Implement from Web Server

Another way to fetch real IP is to implement it on the web server side:

- [Nginx: ngx_http_realip_module](http://nginx.org/en/docs/http/ngx_http_realip_module.html)

- [Apache: mod_remoteip](https://httpd.apache.org/docs/trunk/mod/mod_remoteip.html)

# Licence

MIT

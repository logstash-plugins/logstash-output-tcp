## 6.2.0
  - Reviewed and deprecated SSL settings to comply with Logstash's naming convention [#53](https://github.com/logstash-plugins/logstash-output-tcp/pull/53)
    - Deprecated `ssl_enable` in favor of `ssl_enabled`
    - Deprecated `ssl_cert` in favor of `ssl_certificate`
    - Deprecated `ssl_verify` in favor of `ssl_client_authentication` when mode is `server`
    - Deprecated `ssl_verify` in favor of `ssl_verification_mode` when mode is `client`
  - Added `ssl_cipher_suites` configuration
  - Added SSL configuration validations

## 6.1.2
  - Changed the client mode to write using the non-blocking method. [#52](https://github.com/logstash-plugins/logstash-output-tcp/pull/52)

## 6.1.1
  - Fixes an issue where payloads larger than a connection's current TCP window could be silently truncated [#49](https://github.com/logstash-plugins/logstash-output-tcp/pull/49)

## 6.1.0
  - Feat: ssl_supported_protocols (TLSv1.3) [#47](https://github.com/logstash-plugins/logstash-output-tcp/pull/47)
  - Fix: close server and client sockets on plugin close

## 6.0.2
  - Fix: unable to start with password protected key [#45](https://github.com/logstash-plugins/logstash-output-tcp/pull/45)

## 6.0.1
  - Fixed logging fail retry to stdout [#43](https://github.com/logstash-plugins/logstash-output-tcp/pull/43)
  - Fixed to use `reconnect_interval` when establish a connection

## 6.0.0
  - Removed obsolete field `message_format`

## 5.0.4
  - Removed requirement to have a certificate/key pair when enabling ssl

## 5.0.3
  - Docs: Set the default_codec doc attribute.

## 5.0.2
  - Update gemspec summary

## 5.0.1
  - Fix some documentation issues

## 5.0.0
 - Breaking: mark deprecated option `message_format` as obsolete

## 4.0.0
 - Remove deprecated `workers_not_supported` call
 - Use concurrency :single

## 3.1.1
  - Relax constraint on logstash-core-plugin-api to >= 1.60 <= 2.99

## 3.1.0
  - breaking,config: Remove deprecated config `message_format`

## 3.0.1
 - Republish all the gems under jruby.

## 3.0.0
 - Update the plugin to the version 2.0 of the plugin api, this change is required for Logstash 5.0 compatibility. See https://github.com/elastic/logstash/issues/5141

## 2.0.4
 - Depend on logstash-core-plugin-api instead of logstash-core, removing the need to mass update plugins on major releases of logstash

## 2.0.3
 - New dependency requirements for logstash-core for the 5.0 release

## 2.0.0
 - Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully, 
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - Dependency on logstash-core update to 2.0


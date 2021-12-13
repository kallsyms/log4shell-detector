# log4shell-detector

Proof-of-concept detector for exploitation of log4shell happening with a LDAP JNDI service provider.
This inspects network traffic coming from any `java` processes, and compares the sends to what the [lookup code generates](https://github.com/AdoptOpenJDK/openjdk-jdk11u/blob/fa3ecefdd6eb14a910ae75b7c0aefb1cf8eedcce/src/java.naming/share/classes/com/sun/jndi/ldap/LdapCtx.java#L1354).

Tested against a local environment being "exploited" using

* [https://github.com/mbechler/marshalsec](https://github.com/mbechler/marshalsec)
* [https://github.com/tangxiaofeng7/apache-log4j-poc](https://github.com/tangxiaofeng7/apache-log4j-poc)

## Caveats

Since this is looking specifically for LDAP traffic it:

* May create false-positives if other Java code/applications happens to do this exact same LDAP search request
* Cannot detect exploitation using a LDAPS (LDAP over SSL/TLS) provider
* Cannot detect exploitation using any other [potentially vulnerable provider](https://sourcegraph.com/search?q=context:global+%28repo:AdoptOpenJDK/openjdk-jdk11u+OR+repo:AdoptOpenJDK/openjdk-jdk8%29+public+class.*URLContextFactory&patternType=regexp)
* Cannot detect simple envvar exfiltration going on using any provider (e.g. as mentioned [here](https://twitter.com/log4j2rce/status/1469799982630944770))

## Alternative Things

* [Logout4Shell](https://github.com/Cybereason/Logout4Shell) and [Amazon's hotpatch](https://github.com/corretto/hotpatch-for-apache-log4j2) dynamically patch the main "bad" function (`lookup`) in a running JVM instance to varying extents.

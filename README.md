# Nginx HTTP rDNS module

## Summary

This module allows to make a reverse DNS (rDNS) lookup for incoming
connection and provides simple access control of incoming hostname
by allow/deny rules (similar to HttpAccessModule allow/deny
directives; regular expressions are supported). Module works with
the DNS server defined by the standard resolver directive.


## Example

    location / {
        resolver 127.0.0.1;

        rdns_deny badone\.example\.com;

        if ($http_user_agent ~* FooAgent) {
            rdns on;
        }

        if ($rdns_hostname ~* (foo\.example\.com)) {
            set $myvar foo;
        }

        #...
    }

In the example above, nginx will make a reverse DNS request (through
the 127.0.0.1 DNS server) for each request having the "FooAgent"
user agent. Requests from badone.example.com will be forbidden.
The $rdns_hostname variable will have the rDNS request result or
"not found" (in case it's not found or any error occured) for any
requests made by FooAgent. For other user agents, $rdns_hostname
will have a special value "-".


## Directives

rdns
    Syntax: rdns on | off | double
    Default: -
    Context: http, server, location, if-in-server, if-in-location
    Phase: rewrite
    Variables: rdns_hostname

    Enables/disables rDNS lookups.
    The $rdns_hostname variable may contain:
        - lookup result;
        - special value "not found" if not found or error occured
          during request;
        - special value "-" if lookup disabled.

    After performing a lookup, module restarts request handling
    pipeline to make new $rdns_hostname variable value visible
    to other directives.

    Server/location "if"
    Internally, in server's or location's "if", module works
    through rewrite module codes. When any enabling directive
    (rdns on|double) is executed for the first time, it enables
    lookup and makes a break to stop executing further directives
    in this "if". After the lookup is done, directive in "if" is
    executed for the second time, without any breaks. Disabling
    directive (rdns off) makes no breaks.

    on     - enable rDNS lookup in this context.
    double - enable double rDNS lookup in this context. If the
             first rDNS request succeeded, module performs a
             forward lookup for its result. If none of the forward
             lookup IP addresses match the original address,
             $rdns_hostname is set to "not found".
    off    - disable rDNS lookup in this context.

    Core module resolver should be defined to use this directive.

rdns_allow
    Syntax: rdns_allow regex
    Default: -
    Context: http, server, location
    Phase: access
    Variables: -

    Grants access for domain matched by regular expression.

rdns_deny
    Syntax: rdns_deny regex
    Default: -
    Context: http, server, location
    Phase: access
    Variables: -

    Forbids access for domain matched by regular expression.


## Notice
    During request handling pipeline restart, the location is
    determined for URI. If rDNS is enabled at the http or server
    level, performing redirection from some location to a named
    location may invoke a loop. For example:

    server {
        rdns_deny somedomain;
        rdns on;

        location / {
            echo_exec @foo;
        }

        location @foo {
            #...
        }
    }

    The correct config for this example should be as follows:

    server {
        rdns_deny somedomain;
        rdns on;

        location / {
            echo_exec @foo;
        }

        location @foo {
            rdns off;
            #...
        }
    }

    The rdns_allow and rdns_deny directives define a new
    access list for the context in which they are used.

    Access list inheritance in contexts works only if
    child context doesn't define own rules.


## Authors

The original version of this module has been written by
Timofey Kirillov <timofey.kirillov@flant.ru>, CJSC Flant.


## Links

* The module homepage (in Russian):
  http://flant.ru/projects/nginx-http-rdns
* The source code on GitHub:
  https://github.com/flant/nginx-http-rdns

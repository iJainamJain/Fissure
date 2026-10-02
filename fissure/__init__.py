"""Fissure — an active web-application vulnerability scanner.

Fissure crawls a single in-scope web target, discovers its query parameters
and form inputs, and actively tests each one for common injectable flaws
(SQL injection, reflected XSS, open redirect) plus default-file / directory
exposure. It is designed for authorized lab use against deliberately
vulnerable targets such as DVWA on localhost.
"""

__version__ = "0.1.0"

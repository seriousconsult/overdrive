# IP address commit check

This checkout uses a pre-commit hook that replaces IPv4 and IPv6 literals in staged Markdown, reStructuredText, AsciiDoc, and `docs/*.txt` files with stable labels such as `IPv4-1`. It updates the working-tree copies too, while leaving unrelated unstaged edits out of the index. The hook then rejects any staged file that still contains an address. The scanner reads the complete version of each added, modified, or renamed file from Git's index, including binary files. It reports the file, line, and address.

For a new clone, enable the tracked hook:

~~~bash
git config --local core.hooksPath .githooks
~~~

The check is deliberately strict for code and other non-documentation files: a staged file containing an address cannot be committed even when that address was present before the edit. The checker permits the generic IPv4 literals listed in `SAFE_IPS` in `scripts/check_staged_ips.py`; documentation still has them redacted. Several existing lab files contain other addresses. The redactor does not remove addresses from history or from unstaged files.

Local Git hooks can be bypassed or left unconfigured in another clone. A server-side check is needed if the repository must reject such commits from every contributor.

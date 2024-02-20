PWM - a simple password manager
==

`pwm` stores passwords in an encrypted file on disk and provides a simple interface for retrieving or updating them.

```
usage: pwm [-d | -C | -u <name> [<meta>...] | -r name | <pattern>

options:
  -C  change master password on existing store
  -d  dump all passwords to stderr
  -l  linger for passwordless queries in future invocations
  -u  create/update password with <name> and optional <meta> data
  -r  remove password with <name>
```
The first time `pwm` is run in update mode, it will initialize a
new encrypted file for storage and you will be prompted to set a
passphrase.

The default location of the store is `${HOME}/.pwmstore`
but can be overridden in the environment by setting `PWM_STORE`.

The linger feature causes `pwm` to remain alive after a query is executed
and this instance will hold the master key in memory for a limited
time. Subsequent `pwm` invocations can ask the lingering `pwm` for the
key without prompting the user for the master passphrase. Passwordless
access to the password store is a potential security risk, so this
feature is disabled by default. Linger can also be enabled by setting
the environment variable `PWM_LINGER=1`.

`pwm` generates random passwords for you when you add/update--it does not allow you to store existing passwords.

Supported Platforms
--
OpenBSD and Linux.


Examples
--

Add `hotmail` to password store:
```
$ pwm -u hotmail bettywhite@hotmail.com
passphrase:

hotmail: bettywhite@hotmail.com
1NJsP$waF0Z$Wzh
```
The password is written to `stdout` while everything else is written to `stderr`. This
enables you to pipe the password to `xclip` or similar for easy cut-and-paste into password prompts.

Retrieve password for `hotmail`:
```
$ pwm hotmail
passphrase:

hotmail: bettywhite@hotmail.com
1NJsP$waF0Z$Wzh
```

Set a new password for `hotmail`:
```
$ pwm -u hotmail
passphrase:
[old] hotmail3: 1NJsP$waF0Z$Wzh

hotmail3:
JhcrXKvUwsTtKA6
```
The old password is printed to `stderr` in case it is needed for "old password" fields.

Store a password, username and other info for `EvilBank`:
```
$ pwm -u evilbank bettywhite@hotmail.com PIN 2041
passphrase:

evilbank: bettywhite@hotmail.com PIN:2041
sluDy7kHtAoHErh
```
You can shorten names (eg, `pwm gm` instead of `gmail`) if it
matches exactly one entry.

PWM - a simple password manager
==

`pwm` stores passwords in an encrypted file on disk and provides a simple interface for retrieving or updating them.

```
usage: pwm [-d | -u name [meta]] | [pattern]

       -d   (dump mode) will dump the entire password collection to stderr.
       -u   (update mode) will add or update an existing entry in the password store.
```
The first time `pwm` is run in update mode, it will initialize a
new encrypted file for storage and you will be prompted to set a
passphrase.

The default location of the store is `${HOME}/.pwmstore`
but can be overridden in the environment by setting `PWM_STORE`.

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

PWM - a simple password manager
==

`pwm` stores passwords in an encrypted file on disk and provides a simple interface for retrieving or updating them.

```
usage: pwm [-d | -C | -e | -E | -R <slot> | -u <name> [<meta>...] | -r name | <pattern>

options:
  -C  change master password on existing store (rotates the master key)
  -d  dump all passwords to stderr
  -e  enroll a FIDO2 security key, which can then open the store on its own
  -E  list enrolled key slots
  -F  when re-keying, drop any security key that cannot be reached instead of aborting
  -L  label to record for the security key being enrolled with -e
  -P  ignore any attached security key and use the password
  -p  Read password from stdin instead of randomly generating one, implies -u
  -R  remove enrolled key slot by number (rotates the master key)
  -u  create/update password with <name> and optional <meta> data
  -r  remove password with <name>
```
The first time `pwm` is run in update mode, it will initialize a
new encrypted file for storage and you will be prompted to set a
passphrase.

The default location of the store is `${HOME}/.pwmstore`
but can be overridden in the environment by setting `PWM_STORE`.

Running `pwm` on multiple machines with copies of the same store can
create consistency problems, so you can force pwm to be read-only by
setting `PWM_READONLY=1`.

`pwm` generates random passwords for you when you add/update. You may
instead use the `-p` option to be prompted to specify the password
explicitly.

Security keys
--
In addition to the master password, you can enroll one or more FIDO2
security keys (YubiKeys and equivalents). Any enrolled key opens the
store with a touch and no password:

```
$ pwm -e -L "blue yubikey"
passphrase:
touch your security key to enroll it...
touch again to confirm...

Enrolled [1] security key "blue yubikey" cred:a13f0c9e21b7
This key can now open the store on its own.
```

Enroll as many keys as you like. `pwm` asks the attached token which of
the enrolled credentials it holds, and uses that one.

```
$ pwm -E
enrolled key slots in /home/betty/.pwmstore:
  [0] password (pbkdf2, 500000 iterations)
  [1] security key "blue yubikey" cred:a13f0c9e21b7
  [2] security key "spare" cred:77c2ba0498de
```

When a security key is attached, `pwm` uses it and never prompts. Use
`-P` to ignore the token and type the password instead.

To retire a key, remove its slot:

```
$ pwm -R 1
```

Removal rotates the master key and re-encrypts the store, because
simply deleting the slot would leave any older copy of the store file
accessible by the removed key. `-C` rotates for the same reason. Delete
the `.bak` file that both commands leave behind once you are satisfied.

Rotation regenerates every wrapping parameter: a new salt for the
password slot, a new store-wide salt for the security keys, and a new
nonce for every wrap. Each surviving slot's wrapping key is
unrelated to the one it replaces. That means every enrolled key must
be attached and touched when you re-key. If one is missing the
operation aborts and the store is left exactly as it was; pass `-F` to
drop the unreachable key instead, which is how you retire the last slot
of a key you no longer have.

Security key support needs [libfido2](https://github.com/Yubico/libfido2).
A store with keys enrolled still opens with its password on a build
without it.

Stores written by earlier versions of `pwm` are read as before and are
upgraded to the key slot format the first time they are written.

Supported Platforms
--
OpenBSD and Linux.

Building
--
```
./configure
make
make check
make install
```

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
$ pwm -u evilbank bettywhite@hotmail.com PIN:2041
passphrase:

evilbank: bettywhite@hotmail.com PIN:2041
sluDy7kHtAoHErh
```
You can shorten names (eg, `pwm gm` instead of `gmail`) if it
matches exactly one entry.

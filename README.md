reprieve -- simple password management
======================================

This is a simple password manager utility. Passwords are encrypted
using AES-256 CBC through OpenSSL's libcrypto, converted to their
base64 representation, and stored in a YAML file for later retrieval.

Building
--------

Note: in addition to OpenSSL's libcrypto, this software requires
libyaml and libyamldom (http://gitub.com/heckendorfc/libyaml-dom).
If building with optional X11 support, libX11 is also needed.

	$ mkdir build && cd build
	$ cmake ..
	$ make
	$ sudo make install

Usage
-----

Run without arguments to see a list of commands:

	$ reprieve

Add a password:

	$ reprieve add -n github -l github.com -u heckendorfc

You will then need to enter the (remote) password to store
followed by the master password used to encrypt it.
You may also provide the remote password on the command line
using the -p option but this is unsafe and not recommended.

Copy the password to the primary X clipboard:

	$ reprieve xpw -n github

You will then need to enter the master password. Reprieve will exit
automatically (removing the password from the clipboard) once the
password has been pasted.

Other options for retrieving plain text passwords:

	* pw (print the password)
	* upw (print username:password)
	* xpw (copy the password directly to the primary X clipboard)

List basic information about the available password entries:

	$ reprieve list

Show more detailed information about a specific password entry:

	$ reprieve info -n github

Delete a password entry:

	$ reprieve rm -n github

It is also possible to select a password for one of the above
retrieval subcommands by one or more of:

	* -n name
	* -l location
	* -u user

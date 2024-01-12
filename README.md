# oki

oki applies pledge(2) and unveil(2) restrictions to target-program,
reducing the blast radius of a security vulnerability in target-program.

## Synopsis

```
oki -R target-program
oki -p <promise> [options] target-program [target-program-options]
oki -k [options] target-program [target-program-options]
```

## How does this work?

Calling pledge on a program restricts the set of allowed system calls. Each set
of permitted system calls is known as a `promise` which can be combined.
These promise strings are documented in `man 2 pledge`. If a program executes
a system call that is not permitted by the promises, the kernel immediately
terminates the program, delivering a core file if possible.

oki applies pledge restrictions using pledge's `execpromises` argument.
This allows oki to apply pledge only to a newly executed process and not the
current process. The user specifies promises using `-p promise`.

Calling unveil on a program removes visibility of the entire filesystem, except
for the specified path and permissions. Additional calls can set permissions at
other points in the filesystem hierarchy. When applied to a directory,
the permissions will apply to any file in the subtree of that directory.

oki unveils paths by calling unveil for each `-u permission:path` specified by
the user. When oki executes the target-program, unveil restrictions are
automatically inherited by the target-program. By default, oki automatically
unveils the target-program executable specified by the user.

## Features

- Applies specified promise strings to the `pledge(2)` system call on the
  target-program.
- Applies specified filepath and permissions to the `unveil(2)` system call on
  the target-program.
- Filters only HOME and PATH environment variables to the target-program.
- Optionally pass specific environment variables to the target-program.
- Autogenerate unveil rules for the imported libraries of the target-program
  and write the rules to standard out. This helps with writing scripts that
  call oki on the target-program.

## Requirements

- An OpenBSD system
- Go (Golang)

## Installation

The preferred method of installation is using `go install` (as this is
a Golang application). This automates downloading and building Go
applications from source in a secure manner. By default, applications
are copied into `~/go/bin/`.

You must first [install Go](https://golang.org/doc/install). If you are
compiling the application on OpenBSD, you can install Go by executing:

```sh
doas pkg_add go
```

After installing Go, run the following commands to install the application:

```sh
go install github.com/SeungKang/oki@latest
doas cp ~/go/bin/oki /usr/local/bin/
```

## Examples

### The following example generates unveil rules for rizin's libraries:

```console
$ oki -R /usr/local/bin/rizin
-u 'r:/usr/local/lib/librz_util.so.0.7' \
-u 'r:/usr/lib/libm.so.10.1' \
-u 'r:/usr/lib/libutil.so.16.0' \
(...)
```

### The following example runs oki on the git program:

```console
$ oki -p "stdio" -p "inet" -p + "error" -u "r:/tmp" -u "rc:/foo" -- git
```

The above example enforces the `pledge(2)` promises: "stdio", "inet",
and "error". It also runs `unveil(2)` on the following paths:
- `/tmp` for read `r` operations
- `/foo` for read `r` and create/remove `c` operations

## Troubleshooting

The `-d` option enables debug mode, which will log the pledge promise strings,
unveil rules, and environment variables applied to the target-program.
Pledge violations are logged in `/var/log/messages`.

## Special Thanks

A mega thank you to [Stephan Fox](https://github.com/stephen-fox), 
he's the best :). Stephan played a significant role in assisting me with this 
project and discussions on its functionality. I'm eternally grateful for his 
support, encouragement, patience, and guidance through this project. Can't 
wait to do more.

# oki

oki applies pledge(2) and unveil(2) restrictions to target-program,
reducing the blast radius of a security vulnerability in target-program.

## Features

- Executes specified promise strings to the `pledge(2)` system call on the 
  target program.
- Executes specified filepath and permissions to the `unveil(2)` system call on 
  the target program.
- Filters only HOME and PATH environment variables to the target program.
- Optionally pass specific environment variables to the target program.
- Autogenerate unveil rules for the imported libraries of the target program
  and write the rules to standard out. This helps with writing scripts that
  call oki on the target program.

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
unveil rules, and environment variables applied to the target program.
Pledge violations are logged in `/var/log/messages`.

## Special Thanks

A mega thank you to [Stephan Fox](https://github.com/stephen-fox), 
he's the best :). Stephan played a significant role in assisting me with this 
project and discussions on its functionality. I'm eternally grateful for his 
support, encouragement, patience, and guidance through this project. Can't 
wait to do more.

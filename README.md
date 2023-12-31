# oki

oki automates execution of `pledge(2)` and `unveil(2)` on an executable to 
reduce the blast radius of a program. Blast radius refers to the overall impact 
of a potential security compromise.

## Features

- Executes specified promise strings to the `pledge(2)` system call on the 
  child process.
- Executes specified filepath and permissions to the `unveil(2)`system call on 
  the child process.
- Filters only HOME and PATH environment variables to the child process.
- Optionally pass specific environment variables to the child process.
- Autogenerate unveil rules for the imported libraries of the binary.

## Examples

### The following example autogenerates unveil rules for the rizin program:
```shell
$ oki -R /usr/local/bin/rizin
```

### The following example runs oki on the git program:
```shell
$ oki -k "stdio" -k "inet" -p + "error" -u "r:/tmp" -u "rc:/foo" -- git pull
```
The above example enforces the `pledge(2)` promises: "stdio", "inet",
and "error". It also runs `unveil(2)` on the following paths:
- `/tmp` for read `r` operations
- `/foo` for read `r` and create/remove `c` operations

## Troubleshooting
The `-D` option enables debug mode, which will log the pledge promise strings,
unveil rules, and environment variables applied to the child process.
Pledge violations are logged in `/var/log/messages`.

## Special Thanks
A mega thank you to [Stephan Fox Jr](https://github.com/stephen-fox), he's the best :). Stephan played a 
significant role in assisting me with this project and discussions on its 
functionality. I'm eternally grateful for his support, encouragement, patience, 
and guidance through this project. I can't wait to do more.

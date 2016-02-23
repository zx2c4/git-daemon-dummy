# Git Daemon Dummy: 301 Redirects for `git://`

With the wide deployment of HTTPS, the plaintext nature of `git://`
is becoming less and less desirable. In order to inform users of
the `git://`-based URIs to switch to `https://`-based URIs, while
still being able to shut down aging `git-daemon` infrastructure,
this `git-daemon-dummy` is an extremely lightweight daemon that
simply provides an informative error message to connecting `git://`
users, providing the new URI.

It drops all privileges, `chroot`s, sets `rlimit`s, and uses `seccomp-bpf` to limit the
amount of available syscalls. To remain high performance, it makes
use of `epoll`.

### Example

    zx2c4@thinkpad ~ $ git clone git://git.zx2c4.com/cgit
    Cloning into 'cgit'...
    fatal: remote error: 
    ******************************************************
    
      This git repository has moved! Please clone with:
    
          $ git clone https://git.zx2c4.com/cgit
    
    ******************************************************


### Usage

    Usage: ./git-daemon-dummy [OPTION]...
      -u URI, --uri-prefix=URI     use URI as prefix to redirect uri (default=https://git.example.com)
      -d, --daemonize              run as a background daemon
      -f, --foreground             run in the foreground (default)
      -P FILE, --pid-file=FILE     write pid of listener process to FILE
      -p PORT, --port=PORT         listen on port PORT (default=9418)
      -h, --help                   display this message

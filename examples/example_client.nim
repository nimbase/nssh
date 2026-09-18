import ../src/nssh/client

# Client: likewise owns its loop (`dial` is an alias of `newSshClient`).
# Trust-on-first-use here; pin host keys in real code.
let cli = newSshClient("192.168.105.3", 2222, autoTrust = true,
  onReady = proc(c: SshClient) =
    echo "ready"
)
cli.run()
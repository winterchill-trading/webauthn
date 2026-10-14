# bin/

The `webauthn` command (`main.ml`, `Command.group`). Behaviour is pinned by the cram test
`test/cli.t/run.t`; after changing output run the runtest alias and promote. Refusals
print `((code ...) (error ...))` and exit 1.

# .github/

`workflows/ci.yml`: infra `ox-setup`, build, test, examples, obj-magic. The repo has no
sibling dependencies, so `ox-setup` has no `pins:`; add them in dependency order if a
sibling library is ever added to `dune-project`.

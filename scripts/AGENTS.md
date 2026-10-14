# scripts/

Python generators for test data; run them with `uv`, never a global Python.

- `gen_fixtures.py OUT_DIR`: writes `test/vectors/python/` (command line in its header).
- `w3c_vectors.py SPEC_HTML OUT_DIR`: extracts the W3C section 16 vectors from a
  downloaded copy of the Level 3 draft.
Regenerated fixtures change the expect output of `test_python_fixtures.ml`.

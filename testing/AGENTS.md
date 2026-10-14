# testing/

`webauthn.testing`: `Soft_authenticator` (produces valid and deliberately broken
responses, ES256 or RS256, deterministic from a seed) and `Store_conformance`
(scenarios every `Store.S` must pass). Its signing code is not constant time: test use
only. Add a knob here when a new verification check needs a refusal test.

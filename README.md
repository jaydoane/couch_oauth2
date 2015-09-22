# couch_oauth2

## Getting Started

- rebar get-deps
- rebar eunit

This gets dependencies and runs the single test in src/jwt.erl which
decodes a JWT obtained from Java unit tests.

## Open Questions

- ok to use jose/jsx (in addition to e.g. jiffy), and also requiring 17.5?
- how will username and roles be encoded in token(s)?

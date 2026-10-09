# Vendored grammar

`elastic_kql.g` is Elastic's KQL grammar, copied byte-for-byte from
[`elastic/detection-rules`](https://github.com/elastic/detection-rules) at commit
`195f15c0bac84540bfe47abb8e26dbf8184eb69a`, path `lib/kql/kql/kql.g`
(git blob `a931cc0bd74808a81782148dee263837cab443ea`,
SHA-256 `e71d797a1a76b413a33bc2616104dd993f010f44b0be58ba6a83b6550cdea327`).

Copyright Elasticsearch B.V. Licensed under the Elastic License 2.0. It is used
unmodified, at build time only, by the Elastic rule importer (ADR-0015) so that KQL
rules are parsed by Elastic's own grammar. `tests/test_elastic_query.py` checks the
file still hashes to the value above.

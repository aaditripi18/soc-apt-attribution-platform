"""Build-time detection-content tooling (ADR-0007).

Turns external detection content (the pinned SigmaHQ release) into our JSON
rule-pack format. **Build-time only**: this package imports pySigma, and the
runtime detection path (``attribution_platform.detection``) must never import
it — runtime loads only the generated pack. Guarded by a test.

Import submodules directly (``detection_content.sigma_import``); this package
re-exports nothing so that importing it never pulls in pySigma by accident.
"""

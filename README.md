# Evidence to ATT&CK: grounded technique mapping and detection coverage

This started as IRONSIGHT, my project for a postgraduate course in applied cybersecurity: a local LLM that reads evidence files and maps what it finds to MITRE ATT&CK. Now I'm rebuilding it as a side project under a new name, using what I learned since then to fix its weakest parts.

## What it will do

- Read incident evidence: threat reports, emails and logs.
- Map what it finds to MITRE ATT&CK techniques, running fully offline with a local model.
- Back every mapping with a quote from the evidence, so nothing is reported without proof.
- Show which logs and detection rules would catch each technique, and what's missing.
- Measure all of this on public datasets, so the results can be reproduced.

## Status

Built in stages. Each stage is added here when work on it starts, and explained once it's done.

**Stage 1: Ingestion** (in progress)

- [ ] Read plain text files
- [ ] Read HTML pages
- [ ] Read PDF documents
- [ ] Read emails (EML)
- [ ] Read Windows event logs (EVTX/XML)
- [ ] Turn every file into one common evidence record that keeps track of where each passage came from
- [ ] Make sure malformed or hostile files can't crash or hang the tool
- [ ] Tests for every format, including broken files

## Licence

MIT. Datasets and third-party rules keep their own licences; this repo links to them rather than including them.

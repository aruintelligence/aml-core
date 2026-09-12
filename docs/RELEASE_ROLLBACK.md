# AML release channels and rollback rehearsal

AML keeps stable and preview release identities separate. The stable channel maps to the canonical stable release and the preview channel maps to the current prerelease. CI verifies that those versions and tags cannot silently collapse onto one another.

The rollback rehearsal checks out the canonical immutable stable tag, packs that source, installs the resulting tarball into a clean consumer project, imports the package API, runs the installed CLI, and validates a canonical AML fixture. This proves that the declared rollback target remains mechanically installable and executable in the project-controlled rehearsal environment.

A passing rehearsal is not an application-level rollback guarantee for downstream adopters. Consumers can have migrations, persisted state, surrounding services, or application dependencies that require their own rollback plans and tests.

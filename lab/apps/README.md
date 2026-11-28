# Per-application runbooks

Generic procedure lives in `skills/exploit-signature-pipeline.md`. It cannot know that a PHP victim
needs `session.serialize_handler` set before it will reproduce serializer bugs, or that a WordPress
install needs permalinks before a REST route answers 200 instead of 404. Those are per application,
and today they exist only in the head of whichever agent built the last victim.

One file per application: `lab/apps/<application>.md`. Read it before building a victim. Update it
before you stop - whether the session succeeded or failed, because a runbook that only records
successes teaches the next agent nothing about the wall you hit.

What belongs in one:

| section | what to record |
|---|---|
| versions | affected ranges seen, and which base image reproduces them |
| build | the exact commands that produced a working victim, runnable |
| preconditions | configuration the advisory assumes and the image does not ship (the PHP serializer case) |
| verification | the request that proves the victim is really vulnerable, and the negative control |
| walls | things that looked like the bug but were not - the 404 that was a permalink setting, the wrong version |
| gotchas | what cost the most time, in one line each |

Written for the next session, not for a reader who already knows. "Install WordPress" is useless;
`podman run -d --name ff-wp-694 -p 8094:80 -e WORDPRESS_DB_HOST=ff-wp-db:3306 ...` is a runbook.

A runbook is not a CVE writeup: `lab/<cve>/README.md` is the evidence for one exploit, this is what
carries across every exploit against the same application.

# local-file-writes

**Models:** A package that does real local work during install — a code
generator, an asset compiler, anything that legitimately creates files in
the project it is being installed into.

**Behavior:** Creates a `build/` directory, writes three files into it,
reads each back. Everything stays inside the project directory. No
network, no child processes, no credential-shaped path.

**Exercises:** Proves ordinary in-project file activity — including
writes — is not flagged. The distinction that matters:
"wrote inside the project directory" is normal; "read a credential file"
is not. Only the second produces a finding.

**Expected report:** No high or medium findings. The OBSERVED line shows
several file opens, zero connections, zero process launches.

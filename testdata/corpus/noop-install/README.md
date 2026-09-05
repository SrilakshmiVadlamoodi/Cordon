# noop-install

**Models:** A pure-JS npm package whose install does nothing observable —
no `preinstall`/`postinstall` side effects. The most common real case.

**Behavior:** Reads its own `package.json` from the project directory,
prints one line, exits 0. No network, no child processes, no access to
any credential-shaped path.

**Exercises:** The quiet-run baseline — proves `behaviorreport.Generate`
does not manufacture findings out of an unremarkable run.

**Expected report:** `No findings.` The OBSERVED line shows a small
number of file opens (its own read plus Go-runtime startup opens) and
zero connections and zero process launches.

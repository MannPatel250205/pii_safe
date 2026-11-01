# Stage 0B: Mann → Raj

**Dates:** Days 4–7 (target Day 7, cap Day 9) · **Finished:** Day 7
**Commit:** `<fill in after commit>` · **CI:** <fill in run link>
**Repo:** https://github.com/MannPatel250205/pii_safe

## 1. What was built

- **`docs/CONTRACT.md`** — the one-page frozen contract: hook signatures, `SanitiseResult`
  shape, `TYPE_NNN` alias format, Entity Registry schema, policy YAML schema (`hook_type` +
  `policy_id`) and the audit log columns. From here on, changing anything in it needs both of us
  to agree. Reasoning and divergences stay in `docs/DESIGN.md`.
- **`.pre-commit-config.yaml`** — the last missing piece of the Stage 0B repo setup. Generic
  hygiene hooks, `ruff --fix`, strict `mypy`, plus a hard stop on committing a key, a `.env` or a
  session `.db`. Installed locally with `pre-commit install`.
- **mypy is now strict.** `strict = true` in `pyproject.toml`, and the 46 errors that turned up
  are fixed rather than suppressed — see §4, two of them were real.
- **`.gitattributes`** — `eol=lf` everywhere, so my Windows checkout and your Linux one stop
  producing whitespace-only diffs. `examples/` and `evaluation/datasets/` are marked `-text`
  because they are byte-exact fixtures under test.
- **CI gained a `hygiene` job** running pre-commit (mypy skipped there, the `test` job runs it).
- **`Makefile`** — added `typecheck`, `hooks` and `check` (`check` = the exact CI gate), and a
  `PYTHON` variable so `make dev PYTHON=python` works on Windows.
- **`pyproject.toml`** — `[project.urls]` filled in now that the repo is pushed;
  `pre-commit` added to the `dev` extra.

## 2. How to run it

```bash
git clone https://github.com/MannPatel250205/pii_safe && cd pii_safe
python -m venv .venv && source .venv/bin/activate     # Windows: .venv/Scripts/activate
pip install -e ".[dev,server,agents]"
pre-commit install

make check          # lint + typecheck + tests — the same gate CI runs
```

**The full extras matter.** Strict mypy needs the real FastAPI and LangChain types; with only
`[dev]` installed, their decorators degrade to `Any` and strict reports ~30 false failures.
`pip install -e ".[dev]"` alone is not enough.

Activate the venv before committing — the mypy hook is `language: system` (it needs the project's
dependencies, which an isolated hook env would not have), so it looks for `mypy` on `PATH`.

## 3. Exit test — evidence

| Exit criterion (from the plan) | Result |
|---|---|
| CI runs green | **Pass** — `ruff check src tests` clean, `mypy src` (strict) clean on 44 files, `pytest` **97 passed, 17 skipped**, `piisafe scan examples/security.log --fail-over 101` runs |
| …on a pytest skeleton | **Exceeded** — not a skeleton: 61 unit + 36 integration tests already pass |
| Mentor sign-off recorded | **Open** — see §4; packet is in `docs/handoffs/mentor-signoff.md`, nothing else is blocked on it |
| `pre-commit run --all-files` | **Pass** — all 13 hooks |

The 17 skips are all PostgreSQL and `moto` (AWS) tests, which the CI `backends` job covers with
a real Postgres service. Nothing is skipped for a missing reason.

## 4. Known gaps

1. **Mentor sign-off is not yet recorded.** The plan's own mitigation applies: prototype results
   go out by Day 6, and if there is no reply by Day 9 we proceed on written assumptions. The
   assumptions are the contract in `docs/CONTRACT.md`.
2. **The contract documents what shipped, not what the plan predicted.** Three deliberate
   divergences you should push back on now if you disagree, because they are frozen after this:
   - `SanitiseResult.entities_found` is called `findings`, and the struct is wider than the four
     fields in the plan.
   - Registry storage is **keyed HMAC + encrypted payload**, not "SHA-256 only". The plan asked
     for SHA-256 *and* `reidentify()`, which cannot both hold. `DESIGN.md §5` has the argument.
   - There is a fifth action (`mask`) and a fifth hook (`on_export`) beyond the plan's four.
3. **Two latent bugs that strict mode exposed**, both now fixed — worth knowing they existed:
   - `cli._open_db()` is typed `SQLStore | None`, and six call sites dereferenced it without a
     None check. It turns out it only returns `None` when `must_exist=True`, so the calls were
     safe by accident. I made that explicit with `@overload` rather than scattering asserts.
   - `storage/sqlite.py` bound `fcntl = None` on Windows in a way that made `mypy` on my machine
     fail on every run. Now typed as `ModuleType | None`, so the file is clean on both platforms.
4. **Raj's Stage 0A artefacts are not in this repo** — no prototype, no benchmark numbers, no API
   signatures file. I wrote the contract from the implementation. If your 0A API file disagrees
   with `docs/CONTRACT.md`, your file wins on intent and we reconcile before you start Stage 1.
5. **I have not confirmed you have push access** to `MannPatel250205/pii_safe`. Tell me if you do
   not and I will add you.
6. `piisafe.yaml`, `LICENSE` and `server/app.py` changed line endings only (CRLF → LF) in this
   stage. Ignore them in review.

## 5. First task for the next owner

Read `docs/CONTRACT.md` against your Stage 0A API signatures file and either accept it or send me
the diff. That is the half-day intake review, and it is the one thing that must happen before you
start Stage 1 — Stage 1 builds the `PIISafeGuard` shell directly on those signatures, and the risk
table freezes them at this gate.

## 6. Intake review (filled in by the *next* owner)

- **Reviewed by:** Raj, Day ___
- **Accepted:** ___
- **Defects sent back** (fix window: 1 day, does not count against your stage):
  1.

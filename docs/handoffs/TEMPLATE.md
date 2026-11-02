# Stage <N>: <Owner> → <Next owner>

**Dates:** Day <start>–<end> (target Day <target>, cap Day <cap>) · **Finished:** Day <actual>
**Commit:** `<sha>` · **CI:** <green / link>

## 1. What was built

<Three to six bullets. What exists now that did not before, in terms the next owner cares
about — modules, entry points, schemas — not a commit log.>

## 2. How to run it

```bash
# setup from a clean clone
python -m venv .venv && .venv/Scripts/activate     # Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"

# the commands that prove this stage works
<command>
```

## 3. Exit test — evidence

| Exit criterion (from the plan) | Result |
|---|---|
| <criterion> | <pass/fail + the number or output that shows it> |

## 4. Known gaps

<What is deliberately unfinished, what is shaky, what the next owner will trip over. Be
specific — this section is the one that saves the next person a day.>

## 5. First task for the next owner

<One concrete task they can start on Day 1 of their stage, after the half-day intake review.>

## 6. Intake review (filled in by the *next* owner)

- **Reviewed by:** <name>, Day <n>
- **Accepted:** <yes / yes with fixes / no>
- **Defects sent back** (fix window: 1 day, does not count against the next owner's stage):
  1. <defect>

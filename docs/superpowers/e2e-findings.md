# E2E Findings

Product bugs surfaced while building the browser test suite. Test bugs are
fixed in place and not recorded here.

| # | Area | Finding | Spec / test | Status |
|---|------|---------|-------------|--------|
| 1 | Routing | Unknown routes render the sidebar with an empty content pane — `App.tsx` has no catch-all `<Route>` and no 404 page. | `navigation.spec.ts` → "an unknown route renders an empty content pane" | Open |
| 2 | Assessment history/diff | `POST /regulations/assess` (`complychain/api/routes/regulations.py`) never calls `AssessmentStore.save()` — only the CLI's `assess` command (`cli.py:755`) and the monitoring scheduler (`monitoring/scheduler.py:172`) persist reports. As a result, `GET /regulations/{id}/history` and `GET /regulations/{id}/diff`, which read that same store, show "No prior assessments." / "No previous assessment to compare against." for a regulation even immediately after assessing it twice from the web UI. The Assessment page's history/diff panel is effectively dead for any assessment initiated through the app itself. | `assessment.spec.ts` → "expanding a card loads 30-day history and a diff" | Open |

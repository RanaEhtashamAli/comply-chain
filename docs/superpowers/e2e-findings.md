# E2E Findings

Product bugs surfaced while building the browser test suite. Test bugs are
fixed in place and not recorded here.

| # | Area | Finding | Spec / test | Status |
|---|------|---------|-------------|--------|
| 1 | Routing | Unknown routes render the sidebar with an empty content pane — `App.tsx` has no catch-all `<Route>` and no 404 page. | `navigation.spec.ts` → "an unknown route renders an empty content pane" | Open |

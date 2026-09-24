# Synthetic construction recipes

**Empty on purpose. No recipes exist yet.**

A recipe is frozen *before* any case it describes is instantiated. Creating one
here starts a clock: once `RecipeLock` is written, changing the recipe, removing
it, or adding another is drift, and `FreezeAttestation::verify` refuses to
attest.

## Rules

1. **Authored from a policy clause or a published specification — never from
   engine behaviour.** "Generate examples matching what EdgeGuard detects" is
   the failure this directory exists to prevent. Recipe authors work from the
   frozen policy JSON and the external spec, and the generator must not import
   or inspect the engine.
2. **`safe_predicate` and `harmful_predicate` are written down before
   generation.** They are conditions over the cited clause or specification, and
   they are hashed. Widening a boundary after seeing a result is visible.
3. **Action recipes must rest on a `FactBasis::PolicyClause`** that exists in a
   frozen policy environment. The chain case → recipe → clause → environment is
   verified by `corpus::check_recipe_citations`.
4. **Content recipes may not cite a policy clause** — no frozen content policy
   environment exists — and may not target channel `Action`, because the frozen
   engine does not scan content on the action path.
5. **A recipe cannot produce class S.** An S case carries no deciding fact, so
   there is nothing for a construction recipe to construct.
6. **Filename must be `<recipe_id>_<recipe_version>.json`**, so a path cannot
   misrepresent its contents.

## Versioning

Changing a boundary means a **new `recipe_version`**, not an edit. Cases cite
`recipe_id` *and* `recipe_version`, so the two generations stay distinguishable
in the corpus forever.

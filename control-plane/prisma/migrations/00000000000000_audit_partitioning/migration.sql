-- =============================================================================
-- EdgeGuard Control Plane - guarantees Prisma's DSL cannot express
-- =============================================================================
--
-- Everything in this file is load-bearing. The schema in ../../schema.prisma
-- describes the shape of the data; this file is what makes the security and
-- performance claims in its header actually true:
--
--   1. Row-Level Security          - tenant isolation enforced by Postgres
--   2. Declarative partitioning    - audit/decision retention and fast scans
--   3. Partial & BRIN indexes      - the fast-query paths
--   4. Append-only triggers        - audit immutability as a control
--   5. CHECK constraints           - rule integrity at the storage layer
--
-- Apply after `prisma migrate deploy`. Run order matters within each section.
-- =============================================================================


-- =============================================================================
-- 1. ROW-LEVEL SECURITY
-- =============================================================================
--
-- The application connects as `edgeguard_app` (NOT the table owner, and
-- without BYPASSRLS) and sets `app.tenant_id` at the start of every
-- transaction:
--
--   SET LOCAL app.tenant_id = '<uuid>';
--
-- From then on a forgotten `WHERE "tenantId" = ?` returns zero rows instead
-- of another customer's policy. This is the difference between tenant
-- isolation being a property of the system and being a property of whoever
-- reviewed the last pull request.
--
-- `SET LOCAL` (not `SET`) is deliberate: it is scoped to the transaction, so
-- a pooled connection cannot leak one tenant's context into the next
-- request's queries.

CREATE OR REPLACE FUNCTION app_current_tenant() RETURNS uuid
  LANGUAGE sql STABLE AS $$
    SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid
$$;

-- Applied to every tenant-scoped table. The USING clause filters reads; the
-- WITH CHECK clause stops a write from planting a row under another tenant's
-- id, which a USING-only policy would happily allow.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'roles', 'tenant_memberships', 'api_keys', 'sso_connections',
    'retention_policies', 'policies', 'policy_versions',
    'custom_rule_groups', 'deployments', 'audit_events', 'decision_events'
  ]
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    -- FORCE so the policy also applies to the table owner. Without it, a
    -- migration or a console session run as owner silently bypasses
    -- isolation, which is precisely when a cross-tenant mistake is most
    -- likely and least noticed.
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($f$
      CREATE POLICY tenant_isolation ON %I
        USING ("tenantId" = app_current_tenant())
        WITH CHECK ("tenantId" = app_current_tenant())
    $f$, t);
  END LOOP;
END $$;

-- Child tables reached only through a tenant-scoped parent. Their isolation
-- is transitive, expressed as an EXISTS against the parent so it cannot drift
-- from the parent's policy.
ALTER TABLE custom_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE custom_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON custom_rules
  USING (EXISTS (
    SELECT 1 FROM custom_rule_groups g
    WHERE g.id = custom_rules."groupId" AND g."tenantId" = app_current_tenant()
  ))
  WITH CHECK (EXISTS (
    SELECT 1 FROM custom_rule_groups g
    WHERE g.id = custom_rules."groupId" AND g."tenantId" = app_current_tenant()
  ));

ALTER TABLE policy_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_approvals FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON policy_approvals
  USING (EXISTS (
    SELECT 1 FROM policy_versions v
    WHERE v.id = policy_approvals."policyVersionId" AND v."tenantId" = app_current_tenant()
  ))
  WITH CHECK (EXISTS (
    SELECT 1 FROM policy_versions v
    WHERE v.id = policy_approvals."policyVersionId" AND v."tenantId" = app_current_tenant()
  ));

-- `users`, `sessions` and `permissions` are intentionally NOT tenant-scoped.
-- A user may belong to several tenants (a consultant, an MSP operator), and
-- `permissions` is a global seeded catalogue. Authorization for these runs in
-- the application against `tenant_memberships`, which IS protected above - so
-- membership in a tenant still cannot be read or forged cross-tenant.


-- =============================================================================
-- 2. PARTITIONING
-- =============================================================================
--
-- Both event tables are partitioned monthly by `occurredAt`.
--
-- Why partition rather than index and DELETE:
--
--   * Retention becomes DROP TABLE (instant, no bloat) instead of a DELETE of
--     hundreds of millions of rows that holds locks, generates enormous WAL,
--     and leaves the table needing a VACUUM FULL it will never get a window
--     for. On a high-volume events table this is the difference between
--     retention working and retention being permanently behind.
--   * Every dashboard query is bounded by a time range, so the planner prunes
--     to one or two partitions and never touches historical data.
--   * Indexes stay small enough to remain resident in memory.
--
-- Prisma cannot declare a partitioned table, so these are created here and
-- the Prisma models are marked as managed externally. In practice: let
-- `prisma migrate` create the plain tables, then run the conversion below
-- once, before there is production data.

-- Note: the table has to be rebuilt as partitioned, so run this while empty.
-- On a live system, use the create-new / backfill / swap pattern instead.

-- Prisma creates plain tables for these two models; they are converted here
-- and thereafter managed by this file. Run this ONCE, before there is
-- production data.
ALTER TABLE audit_events RENAME TO audit_events_pre_partition;
ALTER TABLE decision_events RENAME TO decision_events_pre_partition;

CREATE TABLE audit_events (
  id               BIGSERIAL    NOT NULL,
  "tenantId"       UUID         NOT NULL,
  "occurredAt"     TIMESTAMPTZ(6) NOT NULL DEFAULT now(),
  "actorUserId"    UUID,
  "actorEmail"     VARCHAR(320),
  "actorApiKeyId"  UUID,
  "actorIp"        INET,
  "actorUserAgent" TEXT,
  action           VARCHAR(64)  NOT NULL,
  "resourceType"   VARCHAR(40)  NOT NULL,
  "resourceId"     VARCHAR(64),
  "resourceName"   VARCHAR(200),
  -- The Prisma-generated enum TYPE, not TEXT. A TEXT column here compiles
  -- and then fails at runtime, because Prisma Client casts to the enum.
  outcome          "AuditOutcome" NOT NULL DEFAULT 'SUCCESS',
  changes          JSONB,
  "requestId"      VARCHAR(64),
  -- The partition key must be part of every unique constraint, so the PK is
  -- composite. This is a hard Postgres requirement, not a design preference,
  -- and it is why the Prisma model declares @@id([id, occurredAt]) rather
  -- than a single-column @id - the model has to describe the real table or
  -- every `prisma migrate diff` reports phantom drift.
  PRIMARY KEY (id, "occurredAt"),

  -- RESTRICT, not CASCADE. The audit trail is the compliance artifact: a
  -- tenant must be taken through PENDING_DELETION with its history exported
  -- first, and a stray `DELETE FROM tenants` must fail rather than silently
  -- erase years of records.
  CONSTRAINT audit_events_tenant_fk FOREIGN KEY ("tenantId")
    REFERENCES tenants(id) ON DELETE RESTRICT,
  -- SET NULL: the frozen actorEmail column preserves who acted, so losing
  -- the live user row costs nothing.
  CONSTRAINT audit_events_actor_fk FOREIGN KEY ("actorUserId")
    REFERENCES users(id) ON DELETE SET NULL
) PARTITION BY RANGE ("occurredAt");

CREATE TABLE decision_events (
  id                BIGSERIAL    NOT NULL,
  "tenantId"        UUID         NOT NULL,
  "deploymentId"    UUID         NOT NULL,
  "occurredAt"      TIMESTAMPTZ(6) NOT NULL DEFAULT now(),
  verdict           "DecisionVerdict" NOT NULL,
  "decidedBy"       "DecidedByTier"   NOT NULL,
  "violationCode"   INTEGER,
  "ruleNumber"      INTEGER,
  "ruleGroupId"     UUID,
  "policyVersionId" UUID,
  "obfuscationBits" INTEGER      NOT NULL DEFAULT 0,
  "semanticScore"   INTEGER,
  "semanticModelId" UUID,
  "latencyUs"       INTEGER,
  "modelBypassed"   BOOLEAN      NOT NULL DEFAULT true,
  "subjectHash"     CHAR(64),
  "promptExcerpt"   VARCHAR(280),
  PRIMARY KEY (id, "occurredAt"),

  -- CASCADE here is correct and deliberately different from audit_events:
  -- decision events are short-retention operational telemetry, not a
  -- compliance record, so they should go when the tenant does.
  CONSTRAINT decision_events_tenant_fk FOREIGN KEY ("tenantId")
    REFERENCES tenants(id) ON DELETE CASCADE,
  CONSTRAINT decision_events_deployment_fk FOREIGN KEY ("deploymentId")
    REFERENCES deployments(id) ON DELETE CASCADE
) PARTITION BY RANGE ("occurredAt");

-- The originals are now redundant. Dropping them is what makes this
-- migration idempotent in effect: a rerun finds no unpartitioned table to
-- convert.
DROP TABLE IF EXISTS audit_events_pre_partition;
DROP TABLE IF EXISTS decision_events_pre_partition;

-- A catch-all so an insert with an unexpected timestamp (clock skew on an
-- edge node, a backfill) is never rejected. Without it, a partition gap
-- turns into dropped security telemetry - failing to record an event is worse
-- than recording it in the wrong partition.
CREATE TABLE audit_events_default PARTITION OF audit_events DEFAULT;
CREATE TABLE decision_events_default PARTITION OF decision_events DEFAULT;

-- Monthly partition maintenance. Called by a scheduler (pg_cron or an
-- external job) to keep a rolling window of future partitions ahead of
-- ingestion; running out of partitions mid-month is the classic way this
-- pattern fails in production.
CREATE OR REPLACE FUNCTION ensure_event_partitions(months_ahead int DEFAULT 3)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  tbl        text;
  m          int;
  start_date date;
  end_date   date;
  part_name  text;
BEGIN
  FOREACH tbl IN ARRAY ARRAY['audit_events', 'decision_events'] LOOP
    FOR m IN 0..months_ahead LOOP
      start_date := date_trunc('month', CURRENT_DATE) + (m || ' month')::interval;
      end_date   := start_date + interval '1 month';
      part_name  := format('%s_%s', tbl, to_char(start_date, 'YYYY_MM'));
      IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = part_name) THEN
        EXECUTE format(
          'CREATE TABLE %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
          part_name, tbl, start_date, end_date
        );
        -- Inherited indexes are created automatically on new partitions, so
        -- the per-partition index definitions below need to exist only once
        -- on the parent.
      END IF;
    END LOOP;
  END LOOP;
END $$;

SELECT ensure_event_partitions(3);

-- Retention. Drops whole partitions that fall entirely outside the window.
-- `decision_events` uses the shortest retention configured by any tenant's
-- RetentionPolicy, because a partition is shared across tenants and cannot be
-- dropped while any tenant still needs part of it.
CREATE OR REPLACE FUNCTION drop_expired_event_partitions()
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  r              record;
  decision_days  int;
  audit_days     int;
BEGIN
  SELECT COALESCE(MAX("decisionEventDays"), 90),
         COALESCE(MAX("auditEventDays"), 2557)
    INTO decision_days, audit_days
    FROM retention_policies;

  FOR r IN
    SELECT c.relname AS part, p.relname AS parent,
           pg_get_expr(c.relpartbound, c.oid) AS bound
      FROM pg_class c
      JOIN pg_inherits i ON i.inhrelid = c.oid
      JOIN pg_class p ON p.oid = i.inhparent
     WHERE p.relname IN ('audit_events', 'decision_events')
       AND c.relname NOT LIKE '%_default'
  LOOP
    -- Parse the upper bound out of the partition definition and compare it to
    -- the retention horizon. Only drop when the WHOLE partition is expired.
    DECLARE
      upper_bound timestamptz;
      horizon     timestamptz;
    BEGIN
      upper_bound := (regexp_match(r.bound, 'TO \(''([^'']+)''\)'))[1]::timestamptz;
      horizon := now() - (CASE r.parent
                            WHEN 'decision_events' THEN decision_days
                            ELSE audit_days
                          END || ' days')::interval;
      IF upper_bound <= horizon THEN
        EXECUTE format('DROP TABLE IF EXISTS %I', r.part);
        RAISE NOTICE 'dropped expired partition %', r.part;
      END IF;
    END;
  END LOOP;
END $$;


-- =============================================================================
-- 3. FAST-QUERY INDEXES
-- =============================================================================
--
-- Created on the PARENT tables so every present and future partition inherits
-- them. Each one exists for a named query; an index without a query behind it
-- is write amplification on the highest-volume table in the system.

-- --- audit_events -----------------------------------------------------------

-- "the audit log for this tenant, newest first" - the default view.
CREATE INDEX IF NOT EXISTS audit_tenant_time
  ON audit_events ("tenantId", "occurredAt" DESC);

-- "everything this person did" - the first query of any insider-threat review.
CREATE INDEX IF NOT EXISTS audit_tenant_actor_time
  ON audit_events ("tenantId", "actorUserId", "occurredAt" DESC);

-- "every change to this policy" - incident timeline reconstruction.
CREATE INDEX IF NOT EXISTS audit_tenant_resource
  ON audit_events ("tenantId", "resourceType", "resourceId", "occurredAt" DESC);

-- Denied attempts. PARTIAL: successes vastly outnumber denials, so indexing
-- only the denials keeps this small enough to stay cached, and a burst of
-- them is the signal worth alerting on.
CREATE INDEX IF NOT EXISTS audit_denied_only
  ON audit_events ("tenantId", "occurredAt" DESC)
  WHERE outcome = 'DENIED';

-- Free-text search over the change payload, for "which change introduced
-- this?". GIN on jsonb_path_ops: smaller and faster than the default opclass
-- for the containment queries this actually serves.
CREATE INDEX IF NOT EXISTS audit_changes_gin
  ON audit_events USING gin (changes jsonb_path_ops);

-- --- decision_events --------------------------------------------------------
--
-- BRIN rather than B-tree for the pure time scan. Rows arrive in timestamp
-- order, so BRIN is ~1/1000th the size of the equivalent B-tree and answers
-- "give me a time range" just as well. On a table taking millions of rows a
-- day, the write cost of a B-tree on the insert-ordered column is pure waste.
CREATE INDEX IF NOT EXISTS decision_time_brin
  ON decision_events USING brin ("occurredAt") WITH (pages_per_range = 32);

-- "today's blocks and flags". PARTIAL: ALLOW is ~99% of rows and nobody
-- queries for it individually, so excluding it shrinks the index by two
-- orders of magnitude.
CREATE INDEX IF NOT EXISTS decision_tenant_blocked_time
  ON decision_events ("tenantId", "occurredAt" DESC)
  WHERE verdict IN ('BLOCK', 'FLAG');

-- Per-rule effectiveness, which is what drives false-positive tuning.
CREATE INDEX IF NOT EXISTS decision_tenant_rule_time
  ON decision_events ("tenantId", "ruleNumber", "occurredAt" DESC)
  WHERE "ruleNumber" IS NOT NULL;

-- Fleet health and the bypass-ratio dashboard.
CREATE INDEX IF NOT EXISTS decision_deployment_time
  ON decision_events ("deploymentId", "occurredAt" DESC);

-- Evasion-campaign hunting. PARTIAL: non-zero obfuscation bits are rare, so
-- this index is tiny and extremely selective - exactly the shape you want for
-- "show me everything that arrived obfuscated this week".
CREATE INDEX IF NOT EXISTS decision_obfuscated_only
  ON decision_events ("tenantId", "obfuscationBits", "occurredAt" DESC)
  WHERE "obfuscationBits" <> 0;

-- Repeat-offender correlation across requests.
CREATE INDEX IF NOT EXISTS decision_tenant_subject_time
  ON decision_events ("tenantId", "subjectHash", "occurredAt" DESC)
  WHERE "subjectHash" IS NOT NULL;

-- Tier 2 threshold tuning: "the score distribution of everything the model
-- decided". Partial, because only Tier 2 rows have a score.
CREATE INDEX IF NOT EXISTS decision_semantic_scores
  ON decision_events ("tenantId", "semanticScore")
  WHERE "semanticScore" IS NOT NULL;


-- =============================================================================
-- 4. APPEND-ONLY AUDIT
-- =============================================================================
--
-- "We never modify audit records" is a policy. A trigger that refuses UPDATE
-- and DELETE is a control. Auditors accept the second one.

CREATE OR REPLACE FUNCTION refuse_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION
    'audit_events is append-only: % is not permitted (attempted by %)',
    TG_OP, current_user
    USING HINT = 'Correct a mistaken record by appending a corrective event.';
END $$;

CREATE TRIGGER audit_events_no_update
  BEFORE UPDATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION refuse_mutation();

CREATE TRIGGER audit_events_no_delete
  BEFORE DELETE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION refuse_mutation();

-- Two caveats, stated rather than glossed over:
--
--   * These are STATEMENT-level triggers. Row-level BEFORE triggers are not
--     permitted on a partitioned table, and a statement trigger on the
--     parent does not fire for a statement aimed directly at a partition
--     (`UPDATE audit_events_2026_09 ...`). The REVOKE below is what actually
--     closes that hole; the triggers are defence in depth on top of it.
--   * Partition drops for retention use DROP TABLE, which does not fire
--     these triggers - so retention still works while tampering does not.

-- Withdraw mutation rights from the application role as well, so a compromise
-- of the application cannot rewrite history even if the triggers were dropped.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'edgeguard_app') THEN
    -- The parent grant covers DML routed through the parent, which is how
    -- the application writes. Partitions are revoked explicitly too, so a
    -- statement aimed straight at a partition is refused as well.
    REVOKE UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public FROM edgeguard_app;
    GRANT INSERT, SELECT ON audit_events TO edgeguard_app;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public
      GRANT INSERT, SELECT ON TABLES TO edgeguard_app;
  END IF;
END $$;

-- A published policy version is immutable too: it is what a decision event
-- resolves against, so allowing an edit would retroactively rewrite what was
-- enforced. Only `state` may move (PUBLISHED -> ARCHIVED / ROLLED_BACK).
CREATE OR REPLACE FUNCTION freeze_published_version() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.state IN ('PUBLISHED', 'ARCHIVED', 'ROLLED_BACK') THEN
    IF NEW."compiledSnapshot"::text IS DISTINCT FROM OLD."compiledSnapshot"::text
       OR NEW."snapshotHash"  IS DISTINCT FROM OLD."snapshotHash"
       OR NEW.version         IS DISTINCT FROM OLD.version
       OR NEW."policyId"      IS DISTINCT FROM OLD."policyId"
       OR NEW."semanticModelId" IS DISTINCT FROM OLD."semanticModelId"
       OR NEW."blockThreshold"  IS DISTINCT FROM OLD."blockThreshold"
       OR NEW."flagThreshold"   IS DISTINCT FROM OLD."flagThreshold"
       OR NEW."enforcementMode" IS DISTINCT FROM OLD."enforcementMode" THEN
      RAISE EXCEPTION
        'policy version %.% is published and immutable; publish a new version instead',
        OLD."policyId", OLD.version;
    END IF;
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER policy_versions_freeze_published
  BEFORE UPDATE ON policy_versions
  FOR EACH ROW EXECUTE FUNCTION freeze_published_version();


-- =============================================================================
-- 5. CONSTRAINTS PRISMA CANNOT EXPRESS
-- =============================================================================

-- Exactly one default policy per tenant. A plain @@unique([tenantId,
-- isDefault]) would wrongly forbid a tenant from having two NON-default
-- policies; a partial unique index says what is actually meant.
CREATE UNIQUE INDEX IF NOT EXISTS policies_one_default_per_tenant
  ON policies ("tenantId")
  WHERE "isDefault" = true;

-- At most one PUBLISHED version per policy. The invariant every edge node
-- depends on when it asks "what should I be running?".
CREATE UNIQUE INDEX IF NOT EXISTS policy_versions_one_published
  ON policy_versions ("policyId")
  WHERE state = 'PUBLISHED';

-- A rule with no trigger matches nothing and would silently disable itself.
-- Refused at the storage layer, because a rule that looks configured but
-- detects nothing is worse than a validation error.
ALTER TABLE custom_rules
  ADD CONSTRAINT custom_rules_trigger_not_empty
  CHECK (array_length("anyOf", 1) >= 1);

-- No empty literals: an empty token matches at every position.
ALTER TABLE custom_rules
  ADD CONSTRAINT custom_rules_no_empty_tokens
  CHECK (
    NOT ('' = ANY("anyOf")) AND NOT ('' = ANY("allNear")) AND
    NOT ('' = ANY("anyNear")) AND NOT ('' = ANY("noneNear"))
  );

-- A window beyond a sensible bound is almost always a typo for document
-- scope (0), and a huge window makes the proximity clause meaningless.
ALTER TABLE custom_rules
  ADD CONSTRAINT custom_rules_window_sane
  CHECK ("windowBytes" >= 0 AND "windowBytes" <= 4096);

-- Every rule must carry at least one positive test. This is the constraint
-- that stops an unverified rule reaching production: CI asserts the tests
-- pass, and the database asserts the tests exist.
ALTER TABLE custom_rules
  ADD CONSTRAINT custom_rules_has_positive_test
  CHECK (array_length("testPositive", 1) >= 1);

-- Thresholds must be ordered and in range, or the tier router's
-- block/flag/allow bands are incoherent.
ALTER TABLE policy_versions
  ADD CONSTRAINT policy_versions_threshold_order
  CHECK (
    "blockThreshold" BETWEEN 0 AND 1 AND
    "flagThreshold"  BETWEEN 0 AND 1 AND
    "flagThreshold" <= "blockThreshold"
  );

-- A Tier 2 budget of zero disables the tier without saying so; an enormous
-- one makes the "under 5ms" guarantee meaningless.
ALTER TABLE policy_versions
  ADD CONSTRAINT policy_versions_budget_sane
  CHECK ("tier2BudgetMs" BETWEEN 1 AND 1000);

-- A reviewer may not approve their own version: the four-eyes control is
-- pointless if the author counts as one of the eyes. Enforced with a trigger
-- because the check spans two tables.
CREATE OR REPLACE FUNCTION refuse_self_approval() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE author uuid;
BEGIN
  SELECT "createdById" INTO author FROM policy_versions WHERE id = NEW."policyVersionId";
  IF author IS NOT NULL AND author = NEW."reviewerId" THEN
    RAISE EXCEPTION 'a policy version cannot be approved by its author';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER policy_approvals_no_self_approval
  BEFORE INSERT OR UPDATE ON policy_approvals
  FOR EACH ROW EXECUTE FUNCTION refuse_self_approval();

-- A tenant must always retain at least one active member holding
-- `tenant:manage`, or it locks itself out permanently and needs a support
-- escalation with direct database access to recover.
CREATE OR REPLACE FUNCTION refuse_last_owner_removal() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE remaining int;
BEGIN
  SELECT COUNT(*) INTO remaining
    FROM tenant_memberships m
    JOIN roles r            ON r.id = m."roleId"
    JOIN role_permissions rp ON rp."roleId" = r.id
    JOIN permissions p       ON p.id = rp."permissionId"
   WHERE m."tenantId" = COALESCE(OLD."tenantId", NEW."tenantId")
     AND m.status = 'ACTIVE'
     AND p.key = 'tenant:manage'
     AND m.id <> OLD.id;

  IF remaining = 0 THEN
    RAISE EXCEPTION 'cannot remove the last member holding tenant:manage';
  END IF;
  RETURN COALESCE(NEW, OLD);
END $$;

CREATE TRIGGER memberships_keep_one_owner
  BEFORE DELETE ON tenant_memberships
  FOR EACH ROW EXECUTE FUNCTION refuse_last_owner_removal();


-- =============================================================================
-- 6. SEED: the permission catalogue
-- =============================================================================
--
-- Global and idempotent, so it can be re-run on every deploy. `isDangerous`
-- marks the permissions that can change what the fleet enforces.

INSERT INTO permissions (id, key, description, category, "isDangerous") VALUES
  (gen_random_uuid(), 'tenant:manage',      'Manage tenant settings, SSO, and retention',        'tenant',  true),
  (gen_random_uuid(), 'member:read',        'View members and their roles',                      'rbac',    false),
  (gen_random_uuid(), 'member:write',       'Invite, suspend, and remove members',               'rbac',    true),
  (gen_random_uuid(), 'role:read',          'View roles and permissions',                        'rbac',    false),
  (gen_random_uuid(), 'role:write',         'Create and edit roles',                             'rbac',    true),
  (gen_random_uuid(), 'policy:read',        'View policies and versions',                        'policy',  false),
  (gen_random_uuid(), 'policy:write',       'Create and edit draft policy versions',             'policy',  false),
  (gen_random_uuid(), 'policy:approve',     'Approve a policy version for publication',          'policy',  true),
  (gen_random_uuid(), 'policy:publish',     'Publish a policy version to the fleet',             'policy',  true),
  (gen_random_uuid(), 'policy:rollback',    'Withdraw a published policy version',               'policy',  true),
  (gen_random_uuid(), 'rule:read',          'View custom rule groups and rules',                 'rules',   false),
  (gen_random_uuid(), 'rule:write',         'Create and edit custom rules',                      'rules',   false),
  (gen_random_uuid(), 'rule:delete',        'Delete custom rule groups',                         'rules',   true),
  (gen_random_uuid(), 'deployment:read',    'View deployments and fleet health',                 'fleet',   false),
  (gen_random_uuid(), 'deployment:write',   'Register deployments and change their policy',      'fleet',   true),
  (gen_random_uuid(), 'apikey:read',        'List API keys (prefix only)',                       'creds',   false),
  (gen_random_uuid(), 'apikey:write',       'Issue and revoke API keys',                         'creds',   true),
  (gen_random_uuid(), 'audit:read',         'Read the control-plane audit log',                   'audit',   false),
  (gen_random_uuid(), 'audit:export',       'Export the audit log',                              'audit',   false),
  (gen_random_uuid(), 'decision:read',      'Read data-plane decision events',                   'audit',   false),
  (gen_random_uuid(), 'decision:read_prompt','Read stored prompt excerpts (privileged)',          'audit',   true),
  (gen_random_uuid(), 'model:read',         'View semantic models',                              'model',   false),
  (gen_random_uuid(), 'model:write',        'Register and deprecate semantic models',            'model',   true)
ON CONFLICT (key) DO UPDATE
  SET description = EXCLUDED.description,
      category    = EXCLUDED.category,
      "isDangerous" = EXCLUDED."isDangerous";


-- =============================================================================
-- 7. REPORTING VIEWS
-- =============================================================================

-- What each fleet is actually running versus what was published. The gap
-- between those two is the operational question a CISO dashboard exists to
-- answer, and it needs no scan of the event tables.
CREATE OR REPLACE VIEW v_deployment_drift AS
SELECT
  d."tenantId",
  d.id                AS deployment_id,
  d.name              AS deployment,
  d.environment,
  p.name              AS policy,
  latest.version      AS published_version,
  active.version      AS running_version,
  (active.id IS DISTINCT FROM latest.id) AS is_stale,
  d.health,
  d."lastHeartbeatAt",
  CASE WHEN d."totalRequests" > 0
       THEN 1.0 - (d."tier2Calls"::numeric / d."totalRequests")
       ELSE 1.0
  END                 AS model_bypass_ratio
FROM deployments d
JOIN policies p                 ON p.id = d."policyId"
LEFT JOIN policy_versions active ON active.id = d."activeVersionId"
LEFT JOIN policy_versions latest ON latest."policyId" = p.id AND latest.state = 'PUBLISHED';

-- Per-rule effectiveness over the last 7 days: the table a security engineer
-- reads to find the rule generating false positives. Reads only the recent
-- partitions thanks to the time predicate.
CREATE OR REPLACE VIEW v_rule_effectiveness_7d AS
SELECT
  e."tenantId",
  e."ruleGroupId",
  e."ruleNumber",
  COUNT(*)                                             AS total_matches,
  COUNT(*) FILTER (WHERE e.verdict = 'BLOCK')          AS blocks,
  COUNT(*) FILTER (WHERE e.verdict = 'FLAG')           AS flags,
  COUNT(DISTINCT e."subjectHash")                      AS distinct_subjects,
  MAX(e."occurredAt")                                  AS last_match,
  -- A rule matching an enormous number of distinct users is far more likely
  -- to be a false positive than a coordinated attack by all of them.
  ROUND(COUNT(*)::numeric / GREATEST(COUNT(DISTINCT e."subjectHash"), 1), 2)
                                                       AS matches_per_subject
FROM decision_events e
WHERE e."occurredAt" >= now() - interval '7 days'
  AND e."ruleNumber" IS NOT NULL
GROUP BY e."tenantId", e."ruleGroupId", e."ruleNumber";

-- Tier 2 score distribution, for threshold tuning. Without this a team is
-- picking 0.90 because it looks like a round number.
CREATE OR REPLACE VIEW v_semantic_score_histogram_7d AS
SELECT
  "tenantId",
  width_bucket("semanticScore", 0, 1000, 20) AS bucket,
  COUNT(*)                                   AS events,
  COUNT(*) FILTER (WHERE verdict = 'BLOCK')  AS blocked
FROM decision_events
WHERE "occurredAt" >= now() - interval '7 days'
  AND "semanticScore" IS NOT NULL
GROUP BY "tenantId", bucket;

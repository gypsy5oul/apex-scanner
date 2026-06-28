"""Postgres data layer (Phase 1 of the datastore migration).

The DB stays dormant until ``settings.DATABASE_URL`` is set. Connection config
is fully env-driven so this can be repointed at the org's centralized Postgres
later without code changes (see the infra-future-migration note).
"""

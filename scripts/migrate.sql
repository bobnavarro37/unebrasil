-- migração simples (idempotente)
ALTER TABLE citizen_votes
  ADD COLUMN IF NOT EXISTS last_changed_at timestamptz;

UPDATE citizen_votes
SET last_changed_at = COALESCE(last_changed_at, updated_at, created_at)
WHERE last_changed_at IS NULL;

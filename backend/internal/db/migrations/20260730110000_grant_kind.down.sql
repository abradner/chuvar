ALTER TABLE grant_requests DROP CONSTRAINT grant_requests_kind_depth_pairing;
ALTER TABLE grant_requests ALTER COLUMN depth SET DEFAULT 'facts';
ALTER TABLE grant_requests ALTER COLUMN depth SET NOT NULL;
ALTER TABLE grant_requests DROP COLUMN kind;

ALTER TABLE grants DROP CONSTRAINT grants_kind_depth_pairing;
ALTER TABLE grants ALTER COLUMN depth SET DEFAULT 'facts';
ALTER TABLE grants ALTER COLUMN depth SET NOT NULL;
ALTER TABLE grants DROP COLUMN kind;

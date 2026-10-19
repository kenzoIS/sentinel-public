-- SENTINEL public portfolio schema
-- Security-first baseline: tables are created with Row Level Security enabled.
-- Define least-privilege policies for your deployment before allowing client writes.

CREATE TABLE IF NOT EXISTS analysis_logs (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    message_text TEXT NOT NULL,
    risk_level VARCHAR(20) NOT NULL,
    composite_score FLOAT NOT NULL,
    similarity_score FLOAT,
    urgency_score FLOAT,
    red_flag_score FLOAT,
    triggered_keywords JSONB DEFAULT '[]',
    triggered_patterns JSONB DEFAULT '[]',
    recommendation TEXT,
    model_version INTEGER DEFAULT 1,
    user_feedback VARCHAR(20) DEFAULT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scam_reports (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    message_text TEXT NOT NULL,
    report_source VARCHAR(50) DEFAULT 'user_feedback',
    is_verified BOOLEAN DEFAULT TRUE,
    category VARCHAR(50) DEFAULT 'unknown',
    analysis_log_id UUID REFERENCES analysis_logs(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS model_versions (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    version_number INTEGER NOT NULL UNIQUE,
    corpus_size INTEGER DEFAULT 0,
    keyword_count INTEGER DEFAULT 0,
    training_samples INTEGER DEFAULT 0,
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS corpus_entries (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    message_text TEXT NOT NULL,
    category VARCHAR(50) DEFAULT 'general',
    source VARCHAR(50) DEFAULT 'manual',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_analysis_logs_risk_level ON analysis_logs(risk_level);
CREATE INDEX IF NOT EXISTS idx_analysis_logs_created_at ON analysis_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scam_reports_is_verified ON scam_reports(is_verified);
CREATE INDEX IF NOT EXISTS idx_scam_reports_created_at ON scam_reports(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_model_versions_number ON model_versions(version_number DESC);

ALTER TABLE analysis_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE scam_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE model_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE corpus_entries ENABLE ROW LEVEL SECURITY;

-- Intentionally no broad anon policies are installed by this public schema.
-- Add deployment-specific, least-privilege policies based on your authentication
-- and ownership model. Server-side service credentials must never be exposed to
-- browser code or committed to source control.

INSERT INTO model_versions (
    version_number,
    corpus_size,
    keyword_count,
    training_samples,
    notes
)
VALUES (
    1,
    10,
    23,
    0,
    'Public portfolio baseline model'
)
ON CONFLICT (version_number) DO NOTHING;

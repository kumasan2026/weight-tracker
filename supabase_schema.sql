-- 初回テーブル作成用スキーマ
CREATE TABLE IF NOT EXISTS public.weights (
    id BIGSERIAL PRIMARY KEY,
    date DATE NOT NULL UNIQUE,
    weight NUMERIC(5,2) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT TIME ZONE('utc'::text, NOW()) NOT NULL
);

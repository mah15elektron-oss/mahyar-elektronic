CREATE TABLE IF NOT EXISTS posts (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  excerpt TEXT NOT NULL,
  category TEXT NOT NULL,
  read_time TEXT NOT NULL DEFAULT '۵ دقیقه',
  image_url TEXT NOT NULL DEFAULT '',
  body TEXT NOT NULL,
  published_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_posts_published_at ON posts(published_at DESC);

CREATE TABLE IF NOT EXISTS consent_events (
  id TEXT PRIMARY KEY,
  analytics_allowed INTEGER NOT NULL,
  country TEXT,
  city TEXT,
  device_type TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS page_views (
  id TEXT PRIMARY KEY,
  path TEXT NOT NULL,
  country TEXT,
  city TEXT,
  device_type TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_views_created_at ON page_views(created_at DESC);

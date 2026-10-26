-- A.M.A.R. — Esquema PostgreSQL para Render
-- UUID y relaciones adaptadas desde Supabase

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 1. Usuarios: reemplaza la autenticación de Supabase
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Perfiles
CREATE TABLE IF NOT EXISTS profiles (
    id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Dispositivos
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'offline',
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 4. Mediciones de frecuencia cardíaca
CREATE TABLE IF NOT EXISTS heart_readings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    lpm INTEGER NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT heart_readings_lpm_check CHECK (lpm >= 0)
);

-- 5. Contactos de emergencia
CREATE TABLE IF NOT EXISTS emergency_contacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    email TEXT,
    relationship TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 6. Alertas
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    message TEXT,
    status TEXT NOT NULL DEFAULT 'new',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 7. Ubicaciones
CREATE TABLE IF NOT EXISTS locations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    latitude DOUBLE PRECISION NOT NULL,
    longitude DOUBLE PRECISION NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    CONSTRAINT locations_latitude_check
        CHECK (latitude >= -90 AND latitude <= 90),
    CONSTRAINT locations_longitude_check
        CHECK (longitude >= -180 AND longitude <= 180)
);

-- Índices para consultas frecuentes por usuario y fecha
CREATE INDEX IF NOT EXISTS idx_devices_user_id
    ON devices(user_id);

CREATE INDEX IF NOT EXISTS idx_heart_readings_user_recorded
    ON heart_readings(user_id, recorded_at DESC);

CREATE INDEX IF NOT EXISTS idx_emergency_contacts_user_id
    ON emergency_contacts(user_id);

CREATE INDEX IF NOT EXISTS idx_alerts_user_created
    ON alerts(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_locations_user_recorded
    ON locations(user_id, recorded_at DESC);

CREATE INDEX IF NOT EXISTS idx_locations_device_id
    ON locations(device_id);
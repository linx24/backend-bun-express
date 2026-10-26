import "dotenv/config";
import express from "express";
import pg from "pg";
import cors from "cors";
import { rateLimit } from "express-rate-limit";
import { SignJWT, jwtVerify } from "jose";
import type { Request, Response, NextFunction } from "express";
import type { PoolClient } from "pg";

const { Pool } = pg;
const app = express();
const PORT = Number(process.env.PORT) || 3000;

const databaseUrl = process.env.DATABASE_URL;
const jwtSecret = process.env.JWT_SECRET;

if (!databaseUrl) {
  throw new Error("Falta DATABASE_URL en las variables de entorno.");
}

if (!jwtSecret || new TextEncoder().encode(jwtSecret).length < 32) {
  throw new Error("JWT_SECRET debe tener al menos 32 bytes.");
}

const jwtKey = new TextEncoder().encode(jwtSecret);

const pool = new Pool({
  connectionString: databaseUrl,
  ssl: { rejectUnauthorized: false },
});

const allowedOrigins = (
  process.env.FRONTEND_ORIGINS ||
  "http://localhost:5500,http://127.0.0.1:5500"
)
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use(
  cors({
    origin: (origin, callback) => {
      callback(
        null,
        !origin || allowedOrigins.includes(origin)
      );
    },
    methods: ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    maxAge: 86400,
  })
);

app.use(express.json({ limit: "20kb" }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

type AuthenticatedRequest = Request & {
  userId?: string;
};

async function createToken(userId: string, email: string) {
  return new SignJWT({ email })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(userId)
    .setIssuer("amar-backend")
    .setAudience("amar-frontend")
    .setIssuedAt()
    .setExpirationTime("2h")
    .sign(jwtKey);
}

async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const authorization = req.headers.authorization;
    const token = authorization?.startsWith("Bearer ")
      ? authorization.slice(7)
      : "";

    if (!token) {
      return res.status(401).json({
        error: "Tenés que iniciar sesión.",
      });
    }

    const { payload } = await jwtVerify(token, jwtKey, {
      issuer: "amar-backend",
      audience: "amar-frontend",
      algorithms: ["HS256"],
    });

    if (!payload.sub) {
      return res.status(401).json({
        error: "Token inválido.",
      });
    }

    (req as AuthenticatedRequest).userId = payload.sub;
    next();
  } catch {
    return res.status(401).json({
      error: "La sesión no es válida o expiró. Iniciá sesión nuevamente.",
    });
  }
}

// Comprobar que el servidor está activo
app.get("/api/health", (_req, res) => {
  res.json({
    status: "ok",
    message: "Backend funcionando correctamente",
  });
});

// Comprobar la conexión a PostgreSQL
app.get("/api/db-health", async (_req, res) => {
  try {
    const result = await pool.query(
      "SELECT NOW() AS server_time"
    );

    res.json({
      status: "ok",
      database: "connected",
      serverTime: result.rows[0].server_time,
    });
  } catch (error) {
    console.error("Error al conectar con PostgreSQL:", error);
    res.status(500).json({
      status: "error",
      database: "disconnected",
    });
  }
});

// Registrar una cuenta
app.post("/api/auth/register", authLimiter, async (req, res) => {
  const email =
    typeof req.body?.email === "string"
      ? req.body.email.trim().toLowerCase()
      : "";

  const password =
    typeof req.body?.password === "string"
      ? req.body.password
      : "";

  const name =
    typeof req.body?.name === "string"
      ? req.body.name.trim()
      : "";

  if (
    !email ||
    email.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  ) {
    return res.status(400).json({
      error: "Ingresá un correo electrónico válido.",
    });
  }

  if (password.length < 8 || password.length > 128) {
    return res.status(400).json({
      error: "La contraseña debe tener entre 8 y 128 caracteres.",
    });
  }

  if (!name || name.length > 100) {
    return res.status(400).json({
      error: "Ingresá un nombre de hasta 100 caracteres.",
    });
  }

  let client: PoolClient | undefined;

  try {
    const passwordHash = await Bun.password.hash(password, {
      algorithm: "argon2id",
    });

    client = await pool.connect();
    await client.query("BEGIN");

    let user: { id: string; email: string };

    try {
      const result = await client.query(
        `INSERT INTO users (email, password_hash)
         VALUES ($1, $2)
         RETURNING id, email`,
        [email, passwordHash]
      );

      user = result.rows[0];

      await client.query(
        `INSERT INTO profiles (id, name)
         VALUES ($1, $2)`,
        [user.id, name]
      );

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    }

    const token = await createToken(user.id, user.email);

    return res.status(201).json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name,
      },
    });
  } catch (error) {
    if ((error as { code?: string }).code === "23505") {
      return res.status(409).json({
        error: "Ya existe una cuenta con ese correo.",
      });
    }

    console.error("Error al registrar usuario:", error);

    return res.status(500).json({
      error: "No se pudo crear la cuenta.",
    });
  } finally {
    client?.release();
  }
});

// Iniciar sesión
app.post("/api/auth/login", authLimiter, async (req, res) => {
  const email =
    typeof req.body?.email === "string"
      ? req.body.email.trim().toLowerCase()
      : "";

  const password =
    typeof req.body?.password === "string"
      ? req.body.password
      : "";

  if (!email || !password) {
    return res.status(400).json({
      error: "Ingresá el correo y la contraseña.",
    });
  }

  try {
    const result = await pool.query(
      `SELECT u.id, u.email, u.password_hash, p.name
       FROM users u
       LEFT JOIN profiles p ON p.id = u.id
       WHERE u.email = $1`,
      [email]
    );

    const user = result.rows[0];

    if (
      !user ||
      !(await Bun.password.verify(password, user.password_hash))
    ) {
      return res.status(401).json({
        error: "Correo o contraseña incorrectos.",
      });
    }

    const token = await createToken(user.id, user.email);

    return res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },
    });
  } catch (error) {
    console.error("Error al iniciar sesión:", error);

    return res.status(500).json({
      error: "No se pudo iniciar sesión.",
    });
  }
});

// Consultar la identidad de la sesión actual
app.get("/api/auth/me", requireAuth, async (req, res) => {
  const userId = (req as AuthenticatedRequest).userId;

  try {
    const result = await pool.query(
      `SELECT u.id, u.email, p.name
       FROM users u
       LEFT JOIN profiles p ON p.id = u.id
       WHERE u.id = $1`,
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "La cuenta ya no existe.",
      });
    }

    return res.json({ user: result.rows[0] });
  } catch (error) {
    console.error("Error al consultar la sesión:", error);

    return res.status(500).json({
      error: "No se pudo comprobar la sesión.",
    });
  }
});

// Obtener el resumen del panel del usuario autenticado
app.get("/api/dashboard", requireAuth, async (req, res) => {
  const userId = (req as AuthenticatedRequest).userId;

  if (!userId) {
    return res.status(401).json({
      error: "Tenés que iniciar sesión.",
    });
  }

  try {
    const [
      profileResult,
      readingResult,
      deviceResult,
      contactsResult,
      alertResult,
      locationResult,
    ] = await Promise.all([
      pool.query(
        `SELECT name FROM profiles WHERE id = $1`,
        [userId]
      ),

      pool.query(
        `SELECT lpm, recorded_at
         FROM heart_readings
         WHERE user_id = $1
         ORDER BY recorded_at DESC
         LIMIT 1`,
        [userId]
      ),

      pool.query(
        `SELECT name, status, last_seen_at
         FROM devices
         WHERE user_id = $1
         ORDER BY created_at DESC
         LIMIT 1`,
        [userId]
      ),

      pool.query(
        `SELECT COUNT(*)::int AS count
         FROM emergency_contacts
         WHERE user_id = $1`,
        [userId]
      ),

      pool.query(
        `SELECT type, message, created_at
         FROM alerts
         WHERE user_id = $1
         ORDER BY created_at DESC
         LIMIT 1`,
        [userId]
      ),

      pool.query(
        `SELECT latitude, longitude, recorded_at
         FROM locations
         WHERE user_id = $1
         ORDER BY recorded_at DESC
         LIMIT 1`,
        [userId]
      ),
    ]);

    res.json({
      profile: profileResult.rows[0] ?? null,
      reading: readingResult.rows[0] ?? null,
      device: deviceResult.rows[0] ?? null,
      contactsCount: contactsResult.rows[0].count,
      alert: alertResult.rows[0] ?? null,
      location: locationResult.rows[0] ?? null,
    });
  } catch (error) {
    console.error("Error al cargar el panel:", error);

    res.status(500).json({
      error: "No se pudo cargar el panel.",
    });
  }
});


const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// --------------------------------------------------
// PERFIL
// --------------------------------------------------

app.get("/api/profile", requireAuth, async (req, res) => {
  const userId = (req as AuthenticatedRequest).userId!;

  try {
    const result = await pool.query(
      "SELECT id, name, created_at FROM profiles WHERE id = $1",
      [userId]
    );

    return res.json({ profile: result.rows[0] ?? null });
  } catch (error) {
    console.error("Error al consultar el perfil:", error);
    return res.status(500).json({ error: "No se pudo consultar el perfil." });
  }
});

app.patch("/api/profile", requireAuth, async (req, res) => {
  const userId = (req as AuthenticatedRequest).userId!;
  const name = typeof req.body?.name === "string"
    ? req.body.name.trim()
    : "";

  if (!name || name.length > 100) {
    return res.status(400).json({
      error: "El nombre es obligatorio y no puede superar 100 caracteres."
    });
  }

  try {
    const result = await pool.query(
      `INSERT INTO profiles (id, name)
       VALUES ($1, $2)
       ON CONFLICT (id)
       DO UPDATE SET name = EXCLUDED.name
       RETURNING id, name, created_at`,
      [userId, name]
    );

    return res.json({ profile: result.rows[0] });
  } catch (error) {
    console.error("Error al actualizar el perfil:", error);
    return res.status(500).json({ error: "No se pudo actualizar el perfil." });
  }
});

// --------------------------------------------------
// DISPOSITIVOS
// --------------------------------------------------

app.get("/api/devices", requireAuth, async (req, res) => {
  const userId = (req as AuthenticatedRequest).userId!;

  try {
    const result = await pool.query(
      `SELECT id, name, status, last_seen_at, created_at
       FROM devices
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [userId]
    );

    return res.json({ devices: result.rows });
  } catch (error) {
    console.error("Error al consultar dispositivos:", error);
    return res.status(500).json({ error: "No se pudieron consultar los dispositivos." });
  }
});

app.post("/api/devices", requireAuth, async (req, res) => {
  const userId = (req as AuthenticatedRequest).userId!;
  const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";

  if (!name || name.length > 100) {
    return res.status(400).json({ error: "Ingresá un nombre de dispositivo válido." });
  }

  try {
    const result = await pool.query(
      `INSERT INTO devices (user_id, name, status, last_seen_at)
       VALUES ($1, $2, 'online', NOW())
       RETURNING id, name, status, last_seen_at, created_at`,
      [userId, name]
    );

    return res.status(201).json({ device: result.rows[0] });
  } catch (error) {
    console.error("Error al registrar dispositivo:", error);
    return res.status(500).json({ error: "No se pudo registrar el dispositivo." });
  }
});

app.patch("/api/devices/:id", requireAuth, async (req, res) => {
  const userId = (req as AuthenticatedRequest).userId!;
  const id = req.params.id;

  if (typeof id !== "string" || !UUID_REGEX.test(id)) {
    return res.status(400).json({ error: "Identificador de dispositivo inválido." });
  }

  const fields: string[] = [];
  const values: any[] = [];

  if (req.body?.name !== undefined) {
    if (typeof req.body.name !== "string" || !req.body.name.trim() || req.body.name.trim().length > 100) {
      return res.status(400).json({ error: "Nombre de dispositivo inválido." });
    }
    values.push(req.body.name.trim());
    fields.push(`name = $${values.length}`);
  }

  if (req.body?.status !== undefined) {
    if (!["online", "offline"].includes(req.body.status)) {
      return res.status(400).json({ error: "El estado debe ser online u offline." });
    }
    values.push(req.body.status);
    fields.push(`status = $${values.length}`);
  }

  if (req.body?.last_seen_at !== undefined) {
    const timestamp = Date.parse(req.body.last_seen_at);
    if (!Number.isFinite(timestamp)) {
      return res.status(400).json({ error: "Fecha de última conexión inválida." });
    }
    values.push(new Date(timestamp).toISOString());
    fields.push(`last_seen_at = $${values.length}`);
  }

  if (fields.length === 0) {
    return res.status(400).json({ error: "No hay campos válidos para actualizar." });
  }

  values.push(id, userId);

  try {
    const result = await pool.query(
      `UPDATE devices
       SET ${fields.join(", ")}
       WHERE id = $${values.length - 1}
         AND user_id = $${values.length}
       RETURNING id, name, status, last_seen_at, created_at`,
      values
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "No se encontró el dispositivo." });
    }

    return res.json({ device: result.rows[0] });
  } catch (error) {
    console.error("Error al actualizar dispositivo:", error);
    return res.status(500).json({ error: "No se pudo actualizar el dispositivo." });
  }
});

app.delete("/api/devices/:id", requireAuth, async (req, res) => {
  const userId = (req as AuthenticatedRequest).userId!;
  const id = req.params.id;

  if (typeof id !== "string" || !UUID_REGEX.test(id)) {
    return res.status(400).json({ error: "Identificador de dispositivo inválido." });
  }

  try {
    const result = await pool.query(
      "DELETE FROM devices WHERE id = $1 AND user_id = $2 RETURNING id",
      [id, userId]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "No se encontró el dispositivo." });
    }

    return res.json({ success: true });
  } catch (error) {
    console.error("Error al eliminar dispositivo:", error);
    return res.status(500).json({ error: "No se pudo eliminar el dispositivo." });
  }
});

// --------------------------------------------------
// CONTACTOS DE EMERGENCIA
// --------------------------------------------------

app.get("/api/contacts", requireAuth, async (req, res) => {
  const userId = (req as AuthenticatedRequest).userId!;

  try {
    const result = await pool.query(
      `SELECT id, name, phone, email, relationship, created_at
       FROM emergency_contacts
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [userId]
    );

    return res.json({ contacts: result.rows });
  } catch (error) {
    console.error("Error al consultar contactos:", error);
    return res.status(500).json({ error: "No se pudieron consultar los contactos." });
  }
});

app.post("/api/contacts", requireAuth, async (req, res) => {
  const userId = (req as AuthenticatedRequest).userId!;
  const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
  const phone = typeof req.body?.phone === "string" ? req.body.phone.trim() : "";
  const email = typeof req.body?.email === "string" ? req.body.email.trim() : "";
  const relationship =
    typeof req.body?.relationship === "string" ? req.body.relationship.trim() : "";

  if (!name || name.length > 100 || !phone || phone.length > 40) {
    return res.status(400).json({ error: "Nombre o teléfono inválido." });
  }

  if (email && (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) {
    return res.status(400).json({ error: "Correo electrónico inválido." });
  }

  if (relationship.length > 100) {
    return res.status(400).json({ error: "La relación no puede superar 100 caracteres." });
  }

  try {
    const result = await pool.query(
      `INSERT INTO emergency_contacts (user_id, name, phone, email, relationship)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, name, phone, email, relationship, created_at`,
      [userId, name, phone, email || null, relationship || null]
    );

    return res.status(201).json({ contact: result.rows[0] });
  } catch (error) {
    console.error("Error al crear contacto:", error);
    return res.status(500).json({ error: "No se pudo guardar el contacto." });
  }
});

app.patch("/api/contacts/:id", requireAuth, async (req, res) => {
  const userId = (req as AuthenticatedRequest).userId!;
  const id = req.params.id;

  if (typeof id !== "string" || !UUID_REGEX.test(id)) {
    return res.status(400).json({ error: "Identificador de contacto inválido." });
  }

  const fields: string[] = [];
  const values: any[] = [];

  const allowedFields = [
    { input: "name", column: "name", max: 100, required: true },
    { input: "phone", column: "phone", max: 40, required: true },
    { input: "email", column: "email", max: 254, required: false },
    { input: "relationship", column: "relationship", max: 100, required: false },
  ];

  for (const field of allowedFields) {
    if (req.body?.[field.input] === undefined) continue;

    const raw = req.body[field.input];
    if (typeof raw !== "string") {
      return res.status(400).json({ error: `Campo ${field.input} inválido.` });
    }

    const value = raw.trim();

    if ((field.required && !value) || value.length > field.max) {
      return res.status(400).json({ error: `Campo ${field.input} inválido.` });
    }

    if (field.input === "email" && value && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
      return res.status(400).json({ error: "Correo electrónico inválido." });
    }

    values.push(value || null);
    fields.push(`${field.column} = $${values.length}`);
  }

  if (fields.length === 0) {
    return res.status(400).json({ error: "No hay campos válidos para actualizar." });
  }

  values.push(id, userId);

  try {
    const result = await pool.query(
      `UPDATE emergency_contacts
       SET ${fields.join(", ")}
       WHERE id = $${values.length - 1}
         AND user_id = $${values.length}
       RETURNING id, name, phone, email, relationship, created_at`,
      values
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "No se encontró el contacto." });
    }

    return res.json({ contact: result.rows[0] });
  } catch (error) {
    console.error("Error al actualizar contacto:", error);
    return res.status(500).json({ error: "No se pudo actualizar el contacto." });
  }
});

app.delete("/api/contacts/:id", requireAuth, async (req, res) => {
  const userId = (req as AuthenticatedRequest).userId!;
  const id = req.params.id;

  if (typeof id !== "string" || !UUID_REGEX.test(id)) {
    return res.status(400).json({ error: "Identificador de contacto inválido." });
  }

  try {
    const result = await pool.query(
      "DELETE FROM emergency_contacts WHERE id = $1 AND user_id = $2 RETURNING id",
      [id, userId]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "No se encontró el contacto." });
    }

    return res.json({ success: true });
  } catch (error) {
    console.error("Error al eliminar contacto:", error);
    return res.status(500).json({ error: "No se pudo eliminar el contacto." });
  }
});

// --------------------------------------------------
// MEDICIONES CARDÍACAS E HISTORIAL
// --------------------------------------------------

app.get("/api/readings", requireAuth, async (req, res) => {
  const userId = (req as AuthenticatedRequest).userId!;
  const limit = Number(req.query.limit ?? 1000);
  const offset = Number(req.query.offset ?? 0);

  if (
    !Number.isInteger(limit) || limit < 1 || limit > 1000 ||
    !Number.isInteger(offset) || offset < 0 || offset > 1000000
  ) {
    return res.status(400).json({ error: "Paginación inválida." });
  }

  try {
    const result = await pool.query(
      `SELECT id, lpm, recorded_at, created_at
       FROM heart_readings
       WHERE user_id = $1
       ORDER BY recorded_at ASC
       LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );

    return res.json({ readings: result.rows, limit, offset });
  } catch (error) {
    console.error("Error al consultar mediciones:", error);
    return res.status(500).json({ error: "No se pudo consultar el historial." });
  }
});

app.post("/api/readings", requireAuth, async (req, res) => {
  const userId = (req as AuthenticatedRequest).userId!;
  const lpm = req.body?.lpm;
  const recordedAt = req.body?.recorded_at;

  if (!Number.isInteger(lpm) || lpm < 1 || lpm > 300) {
    return res.status(400).json({ error: "La frecuencia cardíaca debe ser un entero entre 1 y 300." });
  }

  let timestamp: string | null = null;

  if (recordedAt !== undefined) {
    const parsed = Date.parse(recordedAt);
    if (typeof recordedAt !== "string" || !Number.isFinite(parsed)) {
      return res.status(400).json({ error: "Fecha de medición inválida." });
    }
    timestamp = new Date(parsed).toISOString();
  }

  try {
    const result = await pool.query(
      `INSERT INTO heart_readings (user_id, lpm, recorded_at)
       VALUES ($1, $2, COALESCE($3::timestamptz, NOW()))
       RETURNING id, lpm, recorded_at, created_at`,
      [userId, lpm, timestamp]
    );

    return res.status(201).json({ reading: result.rows[0] });
  } catch (error) {
    console.error("Error al guardar medición:", error);
    return res.status(500).json({ error: "No se pudo guardar la medición." });
  }
});

// --------------------------------------------------
// ALERTAS
// --------------------------------------------------

app.get("/api/alerts", requireAuth, async (req, res) => {
  const userId = (req as AuthenticatedRequest).userId!;
  const limit = Number(req.query.limit ?? 20);

  if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
    return res.status(400).json({ error: "El límite debe estar entre 1 y 100." });
  }

  try {
    const result = await pool.query(
      `SELECT id, type, message, status, created_at
       FROM alerts
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT $2`,
      [userId, limit]
    );

    return res.json({ alerts: result.rows });
  } catch (error) {
    console.error("Error al consultar alertas:", error);
    return res.status(500).json({ error: "No se pudieron consultar las alertas." });
  }
});

app.post("/api/alerts", requireAuth, async (req, res) => {
  const userId = (req as AuthenticatedRequest).userId!;
  const type = typeof req.body?.type === "string" ? req.body.type.trim() : "";
  const message = typeof req.body?.message === "string" ? req.body.message.trim() : "";

  if (!type || type.length > 80 || message.length > 2000) {
    return res.status(400).json({ error: "Tipo o mensaje de alerta inválido." });
  }

  try {
    const result = await pool.query(
      `INSERT INTO alerts (user_id, type, message)
       VALUES ($1, $2, $3)
       RETURNING id, type, message, status, created_at`,
      [userId, type, message || null]
    );

    return res.status(201).json({ alert: result.rows[0] });
  } catch (error) {
    console.error("Error al registrar alerta:", error);
    return res.status(500).json({ error: "No se pudo registrar la alerta." });
  }
});

// --------------------------------------------------
// UBICACIONES
// --------------------------------------------------

app.get("/api/locations", requireAuth, async (req, res) => {
  const userId = (req as AuthenticatedRequest).userId!;
  const limit = Number(req.query.limit ?? 20);

  if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
    return res.status(400).json({ error: "El límite debe estar entre 1 y 100." });
  }

  try {
    const result = await pool.query(
      `SELECT id, latitude, longitude, recorded_at, device_id
       FROM locations
       WHERE user_id = $1
       ORDER BY recorded_at DESC
       LIMIT $2`,
      [userId, limit]
    );

    return res.json({ locations: result.rows });
  } catch (error) {
    console.error("Error al consultar ubicaciones:", error);
    return res.status(500).json({ error: "No se pudieron consultar las ubicaciones." });
  }
});

app.post("/api/locations", requireAuth, async (req, res) => {
  const userId = (req as AuthenticatedRequest).userId!;
  const latitude = req.body?.latitude;
  const longitude = req.body?.longitude;
  const deviceId = req.body?.device_id ?? null;

  if (
    typeof latitude !== "number" || !Number.isFinite(latitude) ||
    latitude < -90 || latitude > 90 ||
    typeof longitude !== "number" || !Number.isFinite(longitude) ||
    longitude < -180 || longitude > 180
  ) {
    return res.status(400).json({ error: "Coordenadas inválidas." });
  }

  if (deviceId !== null && (typeof deviceId !== "string" || !UUID_REGEX.test(deviceId))) {
    return res.status(400).json({ error: "Identificador de dispositivo inválido." });
  }

  try {
    if (deviceId) {
      const ownedDevice = await pool.query(
        "SELECT id FROM devices WHERE id = $1 AND user_id = $2",
        [deviceId, userId]
      );

      if (!ownedDevice.rows.length) {
        return res.status(404).json({ error: "No se encontró ese dispositivo." });
      }
    }

    const result = await pool.query(
      `INSERT INTO locations (user_id, latitude, longitude, device_id)
       VALUES ($1, $2, $3, $4)
       RETURNING id, latitude, longitude, recorded_at, device_id`,
      [userId, latitude, longitude, deviceId]
    );

    return res.status(201).json({ location: result.rows[0] });
  } catch (error) {
    console.error("Error al guardar ubicación:", error);
    return res.status(500).json({ error: "No se pudo guardar la ubicación." });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor iniciado en http://localhost:${PORT}`);
});
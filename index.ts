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

app.listen(PORT, () => {
  console.log(`Servidor iniciado en http://localhost:${PORT}`);
});
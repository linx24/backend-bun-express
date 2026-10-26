import "dotenv/config";
import pg from "pg";

const { Pool } = pg;

if (!process.env.DATABASE_URL) {
  throw new Error("Falta DATABASE_URL en .env");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function checkTables() {
  try {
    const result = await pool.query(`
      SELECT table_name
      FROM information_schema.tables
      WHERE table_schema = 'public'
        AND table_type = 'BASE TABLE'
      ORDER BY table_name;
    `);

    console.log("Tablas encontradas:");

    for (const row of result.rows) {
      console.log("- " + row.table_name);
    }

    const expected = [
      "users",
      "profiles",
      "devices",
      "heart_readings",
      "emergency_contacts",
      "alerts",
      "locations",
    ];

    const found = new Set(
      result.rows.map((row) => row.table_name)
    );

    const missing = expected.filter((table) => !found.has(table));

    if (missing.length > 0) {
      console.error("Faltan tablas:", missing.join(", "));
    } else {
      console.log("Correcto: las siete tablas existen.");
    }
  } catch (error) {
    console.error("Error al consultar las tablas:", error);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

await checkTables();
import "dotenv/config";
import pg from "pg";
import { readFile } from "node:fs/promises";

const { Pool } = pg;

if (!process.env.DATABASE_URL) {
  throw new Error("Falta DATABASE_URL en el archivo .env");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function migrate() {
  const client = await pool.connect();

  try {
    const schema = await readFile(
      new URL("./schema.sql", import.meta.url),
      "utf8"
    );

    await client.query("BEGIN");

    try {
      await client.query(schema);
      await client.query("COMMIT");
      console.log("Esquema de A.M.A.R. creado correctamente.");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    }
  } catch (error) {
    console.error("Error al ejecutar la migración:", error);
    process.exitCode = 1;
  } finally {
    client.release();
    await pool.end();
  }
}

await migrate();
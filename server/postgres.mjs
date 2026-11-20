import pg from "pg";

pg.types.setTypeParser(20, (value) => {
  const n = Number(value);
  if (!Number.isSafeInteger(n))
    throw Error("Database integer exceeds safe application range");
  return n;
});
export function postgresPool(
  connectionString,
  { allowLocalTest = false } = {},
) {
  if (!connectionString) throw Error("DATABASE_URL is not configured");
  let url;
  try {
    url = new URL(connectionString);
  } catch {
    throw Error("Invalid database connection");
  }
  if (!["postgres:", "postgresql:"].includes(url.protocol))
    throw Error("Invalid database connection");
  // Enforce certificate verification explicitly; do not let sslmode=require weaken it.
  for (const key of [
    "ssl",
    "uselibpqcompat",
    "sslmode",
    "sslcert",
    "sslkey",
    "sslrootcert",
    "channel_binding",
  ])
    url.searchParams.delete(key);
  const local =
    allowLocalTest &&
    ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname);
  const pool = new pg.Pool({
    connectionString: url.toString(),
    ssl: local ? false : { rejectUnauthorized: true },
    enableChannelBinding: true,
    max: 5,
    maxLifetimeSeconds: 300,
    connectionTimeoutMillis: 10000,
    idleTimeoutMillis: 10000,
    application_name: "streamlined-vault",
  });
  pool.on("error", () =>
    console.error(JSON.stringify({ event: "metadata_pool_error" })),
  );
  return pool;
}

if (process.argv.includes("--check")) {
  let pool;
  try {
    pool = postgresPool(process.env.DATABASE_URL);
    const client = await pool.connect();
    try {
      const result = await client.query("SELECT 1 AS ok");
      if (
        result.rows[0]?.ok !== 1 ||
        client.connection.stream.encrypted !== true ||
        client.connection.stream.authorized !== true
      )
        throw Error("TLS check failed");
    } finally {
      client.release();
    }
    console.log(
      "Neon connection verified over TLS. No schema or patient data was changed.",
    );
  } catch {
    console.error(
      "Database connection check failed. Review the private environment configuration.",
    );
    process.exitCode = 1;
  } finally {
    if (pool) await pool.end();
  }
}

import pg from 'pg';

export function postgresPool(connectionString) {
  if(!connectionString)throw Error('DATABASE_URL is not configured');
  const url=new URL(connectionString);
  if(!['postgres:','postgresql:'].includes(url.protocol))throw Error('Invalid database connection');
  // Enforce certificate verification explicitly; do not let sslmode=require weaken it.
  for(const key of ['sslmode','sslcert','sslkey','sslrootcert','channel_binding'])url.searchParams.delete(key);
  return new pg.Pool({connectionString:url.toString(),ssl:{rejectUnauthorized:true},enableChannelBinding:true,max:5,connectionTimeoutMillis:10000,idleTimeoutMillis:10000,application_name:'streamlined-vault'});
}

if(process.argv.includes('--check')) {
  let pool;
  try{pool=postgresPool(process.env.DATABASE_URL);const client=await pool.connect();try{const result=await client.query('SELECT 1 AS ok');if(result.rows[0]?.ok!==1||client.connection.stream.encrypted!==true||client.connection.stream.authorized!==true)throw Error('TLS check failed');}finally{client.release();}console.log('Neon connection verified over TLS. No schema or patient data was changed.');}
  catch{console.error('Database connection check failed. Review the private environment configuration.');process.exitCode=1;}
  finally{if(pool)await pool.end();}
}

const { Pool } = require('pg');

// Database configuration from environment variables
const dbConfig = {
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT ? parseInt(process.env.DB_PORT) : 5432,
};

// Check for missing required configuration
const missingVars = [];
['DB_USER', 'DB_HOST', 'DB_DATABASE', 'DB_PASSWORD'].forEach(varName => {
  if (!process.env[varName]) {
    missingVars.push(varName);
  }
});

if (missingVars.length > 0) {
  console.error(`Error: Missing required environment variables: ${missingVars.join(', ')}`);
  console.error('Please set these environment variables before running the application.');
  process.exit(1);
}

// Create the database pool
const pool = new Pool(dbConfig);

pool.query('SELECT NOW()', (err, res) => {
  console.log(err, res.rows);
  pool.end();
});
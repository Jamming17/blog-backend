import pkg from "pg";
import dotenv from "dotenv";

dotenv.config();
const { Pool } = pkg;

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false,
    },
    lookup: (hostname, options, callback) => {
        return lookup(hostname, { family: 4 }, callback);
    }
});

export default pool;
const mysql = require('mysql2/promise');

require('dotenv').config();//loads .env file into process.env

const pool = mysql.createPool({
    uri: process.env.DATABASE_URL,
    waitForConnections: true,//new requests wait in a queue instead of immediately failing
    connectionLimit:10,
    queueLimit:0
});

module.exports= pool;
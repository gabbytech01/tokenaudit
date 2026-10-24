const express = require('express');
const jwt = require('jsonwebtoken');
const db = require('./db');
const app = express();

const JWT_SECRET = process.env.JWT_SECRET;

app.get('/users', async (req, res) => {
  const rows = await db.query("SELECT * FROM users WHERE name = ?", [req.query.name]);
  res.json(rows);
});

app.listen(3000);
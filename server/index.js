const express = require('express');
const cors = require('cors');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

require('dotenv').config();
const app = express();
app.use(cors());
app.use(express.json());
//sql db connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'demo'
});
db.connect( (error)=> {
    if (error) {
        console.log('Error connecting to the database:', error);
    } else {
        console.log('Connected to the database');
    }

      // SQL query to create a table
  const createTableQuery = `
 CREATE TABLE IF NOT EXISTS demoprofile (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL UNIQUE,  -- Unique email constraint
  password VARCHAR(255) NOT NULL,
  address VARCHAR(255) NOT NULL,       -- Address column included
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
  `;
  db.query(createTableQuery, (err, result) => {
    if (err) {
      console.error('Error creating table: ', err);
    } else {
      console.log('Table created successfully.');
    }
  });

});
//register api and hashed password store in db
app.post('/register', (req, res) => {
    const { name, email, password, address } = req.body;
    const checkEmailSql = 'SELECT * FROM demoprofile WHERE email = ?';
    db.query(checkEmailSql, [email], (err, results) => {
        if (err) {
            return res.status(500).send('Server error');
        }
        // If email exists, send an error
        if (results.length > 0) {
            return res.status(400).send('Email already exists');
        }
        // If email does not exist, proceed to insert the new user
        bcrypt.hash(password, 10, (err, hashPassword) => {
            if (err) return res.status(500).send('Server error');
            // Insert user into the database with all fields
            const sql = 'INSERT INTO demoprofile (name, email, password, address) VALUES (?, ?, ?, ?)';
            db.query(sql, [name, email, hashPassword, address], (err, results) => {
                if (err) 
                    return res.status(500).send('Server error');
                    res.status(200).json({ message: 'User registered', userId: results.insertId });
            });
        });
    });
});
//login api
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    if ( !email || !password) {
        return res.status(400).json({ error: "All fields are required" });
    }
    const sql = 'SELECT * FROM demoprofile WHERE email = ?';
    db.query(sql, [email], (err, results) => {
        if (err) return res.status(500).send('Server error');
        if (results.length === 0) return res.status(401).send('Invalid credentials');

        const user = results[0];
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) return res.status(500).send('Server error');
            if (!isMatch) return res.status(401).send('Invalid credentials');

            const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
           const userId= user.id
            res.json({ token,userId});
        });
    });
});

//profile data get api  particularly
app.get("/api/profile/:id", (req, res) => {
    const { id } = req.params;
    console.log("Requested ID:", id); 
    const sql = "SELECT `id`, `name`, `email`, `address` FROM demoprofile WHERE `id` = ?";
    db.query(sql, [id], (err, result) => {
        if (err) {
            console.error("Database Error:", err); 
            return res.status(500).json(err);
        }
        if (result.length === 0) {
            return res.status(404).json({ error: "Profile not found" });
        } else {
            return res.status(200).json(result[0]);
        }
    });
});
app.put("/api/profile/:id", (req, res) => {
    const profileId = req.params.id;
    const { name, email, address } = req.body;
    // Ensure that the `name`, `email`, and `address` are provided
    if (!name || !email || !address) {
        return res.status(400).json({ error: "All fields are required" });
    }
    // SQL update query
    const sqlUpdate = "UPDATE demoprofile SET name = ?, email = ?, address = ? WHERE id = ?";
    const values = [name, email, address, profileId];
    db.query(sqlUpdate, values, (err, result) => {
        if (err) return res.status(500).json(err);
        // Retrieve the updated data
        const sqlSelect = "SELECT id, name, email, address FROM demoprofile WHERE id = ?";
        db.query(sqlSelect, [profileId], (err, result) => {
            if (err) return res.status(500).json(err);
            if (result.length === 0) {
                return res.status(404).json({ error: "Profile not found" });
            }
            // Send the updated data in the response
            return res.status(200).json(result[0]);
        });
    });
});
app.listen(5000, (error) => {
    if (error) {
        console.log('Error starting server:', error);
    } else {
        console.log('Server started on port 5000');
    }
});

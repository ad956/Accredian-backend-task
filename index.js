const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const mysql = require("mysql");
const bcrypt = require("bcrypt");
const app = express();
require("dotenv").config();
const port = 3001;

app.use(cors());
app.use(bodyParser.json());

const db = mysql.createConnection({
  host: process.env.HOST,
  user: process.env.USER,
  password: process.env.PASSWORD,
  database: process.env.DATABASE,
});

db.connect((err) => {
  if (err) throw err;
  console.log("DB Connected");
});

app.get("/", (req, res) => res.send("accredian-backend-task"));

app.post("/api/login", async (req, res) => {
  const { usernameOrEmail, password } = req.body;

  try {
    const sql = "SELECT * FROM intern_task WHERE username = ? OR email = ?";

    db.query(sql, [usernameOrEmail, usernameOrEmail], async (err, result) => {
      if (err) {
        console.error("Error executing query:", err);
        return res.status(500).json({ error: "Internal Server Error" });
      }

      if (result.length > 0) {
        const user = result[0];
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (passwordMatch) {
          console.log("Authentication successful.");
          return res.status(201).json({ success: true });
        } else {
          console.log("Authentication failed.");
          return res
            .status(401)
            .json({ success: false, error: "Unauthorized" });
        }
      } else {
        console.log("Authentication failed - user not found.");
        return res.status(401).json({ success: false, error: "Unauthorized" });
      }
    });
  } catch (error) {
    console.error("Error during login:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/api/signup", async (req, res) => {
  const { username, email, password } = req.body;

  // Checking if the username or email already exists
  const checkUser = "SELECT * FROM intern_task WHERE username = ? OR email = ?";
  db.query(checkUser, [username, email], (error, results) => {
    if (error) {
      return res.status(500).json({ error: "Internal Server Error" });
    }

    if (results.length > 0) {
      // User already exists
      return res.status(409).json({ error: "User already exists" });
    }

    // Hashing the password
    bcrypt.hash(password, 10, (hashError, hashedPassword) => {
      if (hashError) {
        console.error("Error hashing password:", hashError);
        return res.status(500).json({ error: "Internal Server Error" });
      }

      // adding new user
      const insertUserQuery =
        "INSERT INTO intern_task (username, email, password) VALUES (?, ?, ?)";
      db.query(
        insertUserQuery,
        [username, email, hashedPassword],
        (insertError, insertResults) => {
          if (insertError) {
            console.error("Error inserting user:", insertError);
            return res.status(500).json({ error: "Internal Server Error" });
          }

          return res.status(201).json({ message: "User created successfully" });
        }
      );
    });
  });
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

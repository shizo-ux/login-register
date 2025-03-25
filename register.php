<?php
// register.php

// Include database connection file
require_once 'db_connection.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Collect and sanitize input data
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);

    // Validate inputs
    if (empty($username) || empty($email) || empty($password)) {
        die("Please fill in all fields.");
    }

    // Check if username or email already exists
    $stmt = $conn->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
    $stmt->bind_param("ss", $username, $email);
    $stmt->execute();
    $stmt->store_result();
    if ($stmt->num_rows > 0) {
        die("Username or email already taken.");
    }
    $stmt->close();

    // Hash the password
    $password_hash = password_hash($password, PASSWORD_DEFAULT);

    // Insert new user into the database
    $stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $username, $email, $password_hash);
    if ($stmt->execute()) {
        echo "Registration successful.";
    } else {
        echo "Error: " . $conn->error;
    }
    $stmt->close();
}
?>

<?php
if (!isset($_SESSION)) {
    session_start();
}

require_once(__DIR__ . "/../config/DatabaseConnect.php");

$db = new DatabaseConnect();

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $fullname = htmlspecialchars(trim($_POST["fullName"]));
    $username = htmlspecialchars(trim($_POST["username"]));
    $password = htmlspecialchars(trim($_POST["password"]));
    $confirmPassword = htmlspecialchars(trim($_POST["confirmPassword"]));

    // Input validation
    if (empty($fullname) || empty($username) || empty($password) || empty($confirmPassword)) {
        $_SESSION["mali"] = "All fields are required.";
        header("location: /registration.php");
        exit;
    }

    if ($password !== $confirmPassword) {
        $_SESSION["mali"] = "Passwords do not match.";
        header("location: /registration.php");
        exit;
    }

    try {
        $conn = $db->connectDB();

        // Insert user data into database
        $stmt = $conn->prepare(
            "INSERT INTO users (fullName, username, password, created_at, updated_at) 
             VALUES (:p_fullName, :p_username, :p_password, NOW(), NOW())"
        );

        $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
        $stmt->bindParam(':p_fullName', $fullname);
        $stmt->bindParam(':p_username', $username);
        $stmt->bindParam(':p_password', $hashedPassword);

        if ($stmt->execute()) {
            $_SESSION["tama"] = "Registration successful!";
            header("location: /registration.php");
            exit;
        } else {
            $_SESSION["mali"] = "Failed to register user.";
            header("location: /registration.php");
            exit;
        }
    } catch (PDOException $e) {
        die("Database error: " . $e->getMessage());
    }
}
?>

<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Start session
session_start();

// Database connection
$servername = "localhost";
$dbname = "libmanage";
$username = "root";  // Default XAMPP MySQL username
$password = "";      // Default XAMPP MySQL password

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Process form based on action
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Ensure action exists
    if (isset($_POST['action'])) {
        $action = $_POST['action'];
    } else {
        echo "No action specified.";
        exit();
    }

    // Handle registration
    if ($action == 'register') {
        // Validate required fields
        if (empty($_POST['username']) || empty($_POST['password']) || empty($_POST['confirm_password']) || empty($_POST['email']) || empty($_POST['department'])) {
            echo "All fields are required!";
            exit();
        }

        // Sanitize inputs
        $username = mysqli_real_escape_string($conn, $_POST['username']);
        $password = mysqli_real_escape_string($conn, $_POST['password']);
        $confirm_password = mysqli_real_escape_string($conn, $_POST['confirm_password']);
        $email = mysqli_real_escape_string($conn, $_POST['email']);
        $department = mysqli_real_escape_string($conn, $_POST['department']);

        // Check if passwords match
        if ($password !== $confirm_password) {
            echo "Passwords do not match!";
            exit();
        }

        // Check if user already exists
        $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            echo "Username already taken!";
            exit();
        }

        // Hash the password before saving to the database
        $hashed_password = password_hash($password, PASSWORD_BCRYPT);

        // Insert the new user into the database
        $stmt = $conn->prepare("INSERT INTO users (username, password, email, department) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("ssss", $username, $hashed_password, $email, $department);

        if ($stmt->execute()) {
            echo "Registration successful!";
            // Redirect to login page
            header("Location: LoginPage.html");
            exit();
        } else {
            echo "Error: " . $stmt->error;
        }
    }

    // Handle login
    if ($action == 'login') {
        // Validate required fields
        if (empty($_POST['username']) || empty($_POST['password'])) {
            echo "All fields are required!";
            exit();
        }

        // Sanitize inputs
        $username = mysqli_real_escape_string($conn, $_POST['username']);
        $password = mysqli_real_escape_string($conn, $_POST['password']);

        // Check if the user exists
        $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows == 0) {
            echo "Username not found!";
            exit();
        }

        // Fetch user data
        $user = $result->fetch_assoc();

        // Verify the password
        if (password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];  // Store user id in session
            $_SESSION['username'] = $user['username'];  // Store username in session
            $_SESSION['role'] = $user['role'];  // Store user role in session

            // Check if the user is a librarian
            if ($_SESSION['role'] == 'librarian') {
                // Redirect to the Librarian Dashboard
                header("Location: DashboardLibrarian.html");
                exit();
            } else {
                // Redirect to Mainpage for non-librarians (if needed)
                header("Location: Mainpage.html");
                exit();
            }
        } else {
            echo "Incorrect password!";
            exit();
        }
    }

    // Handle password reset
    if ($action == 'reset_password') {
        // Validate required fields
        if (empty($_POST['username']) || empty($_POST['new_password']) || empty($_POST['confirm_new_password'])) {
            echo "All fields are required!";
            exit();
        }

        // Sanitize inputs
        $username = mysqli_real_escape_string($conn, $_POST['username']);
        $new_password = mysqli_real_escape_string($conn, $_POST['new_password']);
        $confirm_new_password = mysqli_real_escape_string($conn, $_POST['confirm_new_password']);

        // Check if passwords match
        if ($new_password !== $confirm_new_password) {
            echo "Passwords do not match!";
            exit();
        }

        // Check if the user exists
        $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows == 0) {
            echo "Username not found!";
            exit();
        }

        // Hash the new password
        $hashed_password = password_hash($new_password, PASSWORD_BCRYPT);

        // Update the password in the database
        $stmt = $conn->prepare("UPDATE users SET password = ? WHERE username = ?");
        $stmt->bind_param("ss", $hashed_password, $username);

        if ($stmt->execute()) {
            echo "Password reset successful!";
            header("Location: LoginPage.html");  // Redirect to login page after successful password reset
            exit();
        } else {
            echo "Error: " . $stmt->error;
        }
    }
}

// Close the connection
$conn->close();
?>

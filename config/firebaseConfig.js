const admin = require("firebase-admin");
const path = require("path");
const dotenv = require("dotenv");

// Load environment variables
dotenv.config();

// Load the service account key
const serviceAccountPath = process.env.FIREBASE_SERVICE_ACCOUNT_PATH || path.join(__dirname, "service-account.json");
let serviceAccount;
try {
  serviceAccount = require(serviceAccountPath);
} catch (error) {
  console.error("Error loading service account key:", error);
  process.exit(1); // Exit the application if the service account key is invalid or missing
}

// Initialize Firebase Admin SDK
const bucketName = "gs://result-upload-sys.firebasestorage.app"; // Ensure this matches the Firebase Console
try {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    storageBucket: bucketName,
  });
  console.log("Firebase Admin SDK initialized successfully");
} catch (error) {
  console.error("Error initializing Firebase Admin SDK:", error);
  process.exit(1); // Exit the application if Firebase initialization fails
}

// Get reference to the Firebase bucket
const bucket = admin.storage().bucket(bucketName);
console.log("Bucket initialized:", bucket.name);

module.exports = { bucket };
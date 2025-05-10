// passwordsupdate.js - Script to migrate passwords to a more secure format
const { MongoClient } = require("mongodb");
const bcrypt = require("bcrypt");

// Configuration
const config = {
  mongodb: {
    uri: process.env.MONGODB_URI || "mongodb://localhost:27017/nodegoat",
    options: {
      useNewUrlParser: true,
      useUnifiedTopology: true
    }
  },
  saltRounds: 10 // Number of rounds for bcrypt salt generation
};

/**
 * Migrates user passwords from plaintext or weak hashing to bcrypt
 */
async function migratePasswords() {
  let client;
  
  try {
    // Connect to the MongoDB server
    client = new MongoClient(config.mongodb.uri, config.mongodb.options);
    
    console.log("Connecting to MongoDB...");
    await client.connect();
    console.log("Connected successfully to MongoDB server");
    
    // Get database and collection
    const db = client.db();
    const usersCollection = db.collection("users");
    
    // Find all users that need password migration
    // Adjust this query based on how you identify which passwords need migration
    // For example, if old passwords don't have a certain property or format
    const users = await usersCollection.find({
      // Add criteria to identify users needing password migration
      // For example: { passwordNeedsMigration: true }
      // Or if you're migrating all passwords: {}
    }).toArray();
    
    console.log(`Found ${users.length} users that need password migration`);
    
    // Process each user
    let migratedCount = 0;
    for (const user of users) {
      // Get the original password or hash from user object
      // This depends on your current password storage method
      const originalPassword = user.password; // Adjust according to your schema
      
      if (!originalPassword) {
        console.log(`Skipping user ${user._id} - No password found`);
        continue;
      }
      
      try {
        // Generate a new bcrypt hash
        const hashedPassword = await bcrypt.hash(originalPassword, config.saltRounds);
        
        // Update the user with the new hashed password
        // You might need to adjust this update operation based on your schema
        await usersCollection.updateOne(
          { _id: user._id },
          { 
            $set: { 
              password: hashedPassword,
              // Optionally set a flag that the password has been migrated
              passwordMigrated: true 
            } 
          }
        );
        
        migratedCount++;
        console.log(`Migrated password for user ID: ${user._id}`);
      } catch (error) {
        console.error(`Failed to migrate password for user ID: ${user._id}`, error);
      }
    }
    
    console.log(`Migration completed. Successfully migrated ${migratedCount} out of ${users.length} passwords.`);
    
  } catch (error) {
    console.error("Error during password migration:", error);
    process.exit(1);
  } finally {
    // Close the connection when done
    if (client) {
      console.log("Closing MongoDB connection...");
      await client.close();
      console.log("MongoDB connection closed");
    }
  }
}

// Execute the migration
migratePasswords()
  .then(() => {
    console.log("Password migration script completed successfully");
    process.exit(0);
  })
  .catch((error) => {
    console.error("Password migration script failed:", error);
    process.exit(1);
  });
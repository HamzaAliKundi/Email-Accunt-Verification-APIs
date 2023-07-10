const mongoose = require("mongoose");
mongoose.set("strictQuery", true);

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI);
    console.log(`mongoDB connected : ${conn.connection.host}`);
  } catch (error) {
    console.log("Connected error : ", error);
    process.exit(1);
  }
};

module.exports = connectDB;

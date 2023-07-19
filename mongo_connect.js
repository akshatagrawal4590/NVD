require("dotenv").config();
const {MongoClient} = require("mongodb");
const url = process.env.URL;
const client = new MongoClient(url);
const db_name = process.env.DB_NAME;
let db;
const result = client.connect();
result.then(function(res) {
  db = res.db(db_name);
}).catch(function(error) {
  console.log(error);
});

const dbConnectHardwareCPE = function() {
  return db.collection(process.env.COLLECTION1);
};

const dbConnectSoftwareCPE = function() {
  return db.collection(process.env.COLLECTION2);
};

const dbConnectCVE = function() {
  return db.collection(process.env.COLLECTION3);
};

const createNewSoftwareCPECollection = function() {
  return db.createCollection(process.env.NEW_SOFTWARE_CPE_COLLECTION);
};

const createNewHardwareCPECollection = function() {
  return db.createCollection(process.env.NEW_HARDWARE_CPE_COLLECTION);
};

const createPendingChangesCollection = function() {
  return db.createCollection(process.env.PENDING_CHANGES_COLLECTION);
};

module.exports = {
  dbConnectHardwareCPE: dbConnectHardwareCPE,
  dbConnectSoftwareCPE: dbConnectSoftwareCPE,
  dbConnectCVE: dbConnectCVE,
  createNewSoftwareCPECollection: createNewSoftwareCPECollection,
  createNewHardwareCPECollection: createNewHardwareCPECollection,
  createPendingChangesCollection: createPendingChangesCollection
}

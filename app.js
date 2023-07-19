require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const {dbConnectHardwareCPE, dbConnectSoftwareCPE, dbConnectCVE} = require("./mongo_connect.js");
const app = express();
app.use(bodyParser.urlencoded({extended: true}));

app.get("/cpe/:type/:cpeName/:cpeVendor?/:cpeVersion?/:sortByDate?", async function(req, res) {
  try
  {
    const sortByDate = req.query.sortByDate;
    const cpeType = req.params.type;
    const cpeVendor = req.query.cpeVendor;
    const cpeVersion = req.query.cpeVersion;
    const cpeName = req.params.cpeName;
    const collection1 = await dbConnectHardwareCPE();
    const collection2 = await dbConnectSoftwareCPE();
    let documents1 = [];
    let documents2 = [];
    if(cpeVendor != undefined && cpeVersion != undefined)
    {
      if(cpeType == "h")
      {
        documents1 = await collection1.find({vendor: cpeVendor, model: cpeName, version: cpeVersion}).toArray();
      }
      else
      {
        documents2 = await collection2.find({vendor: cpeVendor, name: cpeName, version: cpeVersion}).toArray();
      }
    }
    else if(cpeVendor == undefined && cpeVersion == undefined)
    {
      if(cpeType == "h")
      {
        documents1 = await collection1.find({model: cpeName}).toArray();
      }
      else
      {
        documents2 = await collection2.find({name: cpeName}).toArray();
      }
    }
    else if(cpeVendor == undefined && cpeVersion != undefined)
    {
      if(cpeType == "h")
      {
        documents1 = await collection1.find({version: cpeVersion, model: cpeName}).toArray();
      }
      else
      {
        documents2 = await collection2.find({version: cpeVersion, name: cpeName}).toArray();
      }
    }
    else
    {
      if(cpeType == "h")
      {
        documents1 = await collection1.find({vendor: cpeVendor, model: cpeName}).toArray();
      }
      else
      {
        documents2 = await collection2.find({vendor: cpeVendor, name: cpeName}).toArray();
      }
    }

    if(documents1.length == 0 && documents2.length == 0)
    {
      res.send("No matching CPEs found.")
    }
    else
    {
      let matchingCPEDesc = [];
      documents1.forEach(function(item) {
        if(item.deprecated == false)
        {
          matchingCPEDesc.push(item.cpeName);
        }
      });
      documents2.forEach(function(item) {
        if(item.deprecated == false)
        {
          matchingCPEDesc.push(item.cpeName);
        }
      });
      let matchingCVEs = await getCVE(matchingCPEDesc);

      if(cpeType == "h")
      {
        documents1 = documents1.filter(function(item) {
          return matchingCVEs.some(function(cveItem) {
            return cveItem.configurations[0].nodes[0].cpeMatch.some(function(element) {
              return element.criteria === item.cpeName;
            })
          })
        });
        const groupedCVEs = documents1.map(function(cpe) {
          const cveGroup = matchingCVEs.filter(function(cve) {
            return cve.configurations[0].nodes[0].cpeMatch.some(function(item) {
              return item.criteria === cpe.cpeName;
            })
          });
          return {cpeName: cpe.cpeName, matching_CVEs: cveGroup};
        });
        let sortedGroupedCVEs = [];
        if(sortByDate === "1")
        {
          sortedGroupedCVEs = groupedCVEs.sort(function(a, b) {
            const timeA = getLastModifiedTime(a.cpeName, documents1);
            const timeB = getLastModifiedTime(b.cpeName, documents1);
            return compareTime(timeA, timeB);
          });
        }
        else
        {
          sortedGroupedCVEs = groupedCVEs.sort(function(a, b) {
            const versionA = getVersionFromCPE(a.cpeName);
            const versionB = getVersionFromCPE(b.cpeName);
            return compareVersions(versionB, versionA);
          });
        }
        res.json({
          hardware_CPEs: documents1,
          matching_CVEs: groupedCVEs,
          sorted_CVEs: sortedGroupedCVEs
        });
      }
      else
      {
        documents2 = documents2.filter(function(item) {
          return matchingCVEs.some(function(cveItem) {
            return cveItem.configurations[0].nodes[0].cpeMatch.some(function(element) {
              return element.criteria === item.cpeName;
            })
          })
        });
        const groupedCVEs = documents2.map(function(cpe) {
          const cveGroup = matchingCVEs.filter(function(cve) {
            return cve.configurations[0].nodes[0].cpeMatch.some(function(item) {
              return item.criteria === cpe.cpeName;
            })
          });
          return {cpeName: cpe.cpeName, matching_CVEs: cveGroup};
        });
        let sortedGroupedCVEs = [];
        if(sortByDate === "1")
        {
          sortedGroupedCVEs = groupedCVEs.sort(function(a, b) {
            const timeA = getLastModifiedTime(a.cpeName, documents2);
            const timeB = getLastModifiedTime(b.cpeName, documents2);
            return compareTime(timeA, timeB);
          });
        }
        else
        {
          sortedGroupedCVEs = groupedCVEs.sort(function(a, b) {
            const versionA = getVersionFromCPE(a.cpeName);
            const versionB = getVersionFromCPE(b.cpeName);
            return compareVersions(versionB, versionA);
          });
        }
        res.json({
          software_CPEs: documents2,
          matching_CVEs: groupedCVEs,
          sorted_CVEs: sortedGroupedCVEs
        });
      }
    }
  }
  catch(error)
  {
    res.write("Error in '/cpe/:type/:cpeName/:cpeVendor?/:cpeVersion?/:sortByDate?' route.");
    res.write(error);
    res.end();
  }
});

function compareTime(timeA, timeB)
{
  const dateA = new Date(timeA);
  const dateB = new Date(timeB);
  if(dateA > dateB)
  {
    return -1;
  }
  else if(dateA < dateB)
  {
    return 1;
  }
  return 0;
}

function getLastModifiedTime(name, documents)
{
  for (const cpe of documents) {
    if (name === cpe.cpeName) {
      return cpe.lastModified;
    }
  }
  return null;
}

function getVersionFromCPE(cpeName)
{
  const version = cpeName.split(":")[5];
  if(version === "*")
  {
    return "0";
  }
  return version;
}

function compareVersions(versionA, versionB)
{
  const partsA = versionA.split('.').map(Number);
  const partsB = versionB.split('.').map(Number);

  for (let i = 0; i < Math.max(partsA.length, partsB.length); i++)
  {
    const partA = partsA[i] !== undefined ? partsA[i] : 0;
    const partB = partsB[i] !== undefined ? partsB[i] : 0;

    if (partA > partB)
    {
      return 1;
    }
    else if (partA < partB)
    {
      return -1;
    }
  }
  return 0;
}

async function getCVE(matchingCPEDesc)
{
  let cveDocs = [];
  const collection3 = await dbConnectCVE();
  cveDocs = await collection3.find({"configurations.nodes.cpeMatch": {$elemMatch: {criteria: {$in: matchingCPEDesc}}}}).toArray();
  return cveDocs;
}

app.listen(process.env.PORT_NO, function() {
  console.log("Server started.");
});

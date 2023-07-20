const {dbConnectSoftwareCPE, dbConnectCVE, createNewSoftwareCPECollection} = require("../mongo_connect.js");

async function runScript()
{
  try
  {
    const collection1 = await dbConnectSoftwareCPE();
    const collection2 = await dbConnectCVE();
    const cpeNames = await getAllCPENames(collection1);
    const size = 3;
    let x = ["enterprise_manager", "corporate_desktop", "shockwave_player", "myfaces_tomahawk"];
    const cpeArray = await getCPEArray(x, collection1, collection2, size);
  }
  catch (error)
  {
    console.log(error);
  }
}

async function getAllCPENames(collection1)
{
  const cpeNames = await collection1.distinct("name", function(softwareNames, err) {
    if(!err)
    {
      return softwareNames;
    }
    else
    {
      console.log(err);
    }
  });
  return cpeNames;
}

async function getCPEArray(cpeNames, collection1, collection2, size)
{
  const newCollection = await createNewSoftwareCPECollection();

  let cpeArray = [];
  let batches = [];
  for (let i = 0; i < cpeNames.length; i += size)
  {
    batches.push(cpeNames.slice(i, i + size));
  }

  for (let j = 0; j < batches.length; j++)
  {
    console.log(`Batch ${j + 1} started processing...`);
    const tempArr = [];
    const batchErrors = [];

    while (batches[j].length > 0)
    {
      const result = await processBatch(batches[j], collection1, collection2, newCollection);
      if (Array.isArray(result.versions))
      {
        tempArr.push(result);
      }
      else
      {
        batchErrors.push(result);
      }
    }

    console.log(`Batch ${j + 1} completed processing.`);
    cpeArray.push({
      batch: j + 1,
      data: tempArr,
      errors: batchErrors
    });
  }

  console.log(`All ${batches.length} batches completed processing.`);
  return cpeArray;
}

async function processBatch(batch, collection1, collection2, newCollection)
{
  const item = batch.shift();
  const pipeline = [
    { $match: { name: item } },
    { $project: { _id: 0, version_number: "$version", cpe: "$cpeName" } }
  ];

  try
  {
    const itemArray = await collection1.aggregate(pipeline).toArray();
    for (let i = 0; i < itemArray.length; i++)
    {
      const cpeName = itemArray[i].cpe;
      try
      {
        const cveNameArray = await collection2.find(
          {
            "configurations.nodes.cpeMatch": {
              $elemMatch: {
                criteria: cpeName
              }
            }
          },
          {
            projection: { _id: 0, id: 1 }
          }
        ).toArray();
        itemArray[i].cves = cveNameArray;
      }
      catch (error)
      {
        const errorMessage = `Error processing ${cpeName}: ${error.message}`;
        console.error(errorMessage);
        itemArray[i].cves = errorMessage;
      }
    }

    const result = {
      software_name: item,
      versions: itemArray
    };

    await newCollection.insertOne(result);

    return result;
  }
  catch (error)
  {
    const errorMessage = `Error fetching data for ${item}: ${error.message}`;
    console.error(errorMessage);
    if (batch.length > 0)
    {
      return processBatch(batch, collection1, collection2, newCollection);
    }
    else
    {
      const result = {
        software_name: item,
        versions: errorMessage
      };

      await newCollection.insertOne(result);

      return result;
    }
  }
}

runScript();

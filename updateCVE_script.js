const {dbConnectCVE, createPendingChangesCollection} = require("./mongo_connect.js");
const axios = require("axios");

const days = 1;
const now = new Date();
const endDate = now.toISOString().replace("Z", "%2B05:30");;
const startDate = new Date(now.getTime() - (days * 24 * 60 * 60 * 1000)).toISOString().replace("Z", "%2B05:30");;
const url = `https://services.nvd.nist.gov/rest/json/cvehistory/2.0/?changeStartDate=${startDate}&changeEndDate=${endDate}`;
const cvssV2Map = {
  AV: "accessVector",
  AC: "accessComplexity",
  Au: "authentication",
  C: "confidentialityImpact",
  I: "integrityImpact",
  A: "availabilityImpact"
};

const vectorV2Map = {
  AV: {
    N: "NETWORK",
    A: "ADJAENT NETWORK",
    L: "LOCAL"
  },
  AC: {
    L: "LOW",
    M: "MEDIUM",
    H: "HIGH"
  },
  Au: {
    N: "NONE",
    S: "SINGLE",
    M: "MULTIPLE"
  },
  C: {
    N: "NONE",
    P: "PARTIAL",
    C: "COMPLETE"
  },
  I: {
    N: "NONE",
    P: "PARTIAL",
    C: "COMPLETE"
  },
  A: {
    N: "NONE",
    P: "PARTIAL",
    C: "COMPLETE"
  }
};

const vectorValueV2Map = {
  AV: {
    N: 1,
    A: 0.646,
    L: 0.395
  },
  AC: {
    L: 0.71,
    M: 0.61,
    H: 0.35
  },
  Au: {
    N: 0.704,
    S: 0.56,
    M: 0.45
  },
  C: {
    N: 0,
    P: 0.275,
    C: 0.660
  },
  I: {
    N: 0,
    P: 0.275,
    C: 0.660
  },
  A: {
    N: 0,
    P: 0.275,
    C: 0.660
  }
};

const cvssV3_1Map = {
  AV: "accessVector",
  AC: "accessComplexity",
  PR: "privilegesRequired",
  UI: "userInteraction",
  S: "scope",
  C: "confidentialityImpact",
  I: "integrityImpact",
  A: "availabilityImpact"
};

const vectorV3_1Map = {
  AV: {
    N: "NETWORK",
    A: "ADJAENT NETWORK",
    L: "LOCAL",
    P: "PHYSICAL"
  },
  AC: {
    L: "LOW",
    H: "HIGH"
  },
  PR: {
    N: "NONE",
    L: "LOW",
    H: "HIGH"
  },
  UI: {
    N: "NONE",
    R: "REQUIRED"
  },
  S: {
    U: "UNCHANGED",
    C: "CHANGED"
  },
  C: {
    N: "NONE",
    L: "LOW",
    H: "HIGH"
  },
  I: {
    N: "NONE",
    L: "LOW",
    H: "HIGH"
  },
  A: {
    N: "NONE",
    L: "LOW",
    H: "HIGH"
  }
};

const vectorValueV3_1Map = {
  AV: {
    N: 0.85,
    A: 0.62,
    L: 0.55,
    P: 0.2
  },
  AC: {
    L: 0.77,
    H: 0.44
  },
  PR: {
    N: 0.85,
    L: 0.62,
    H: 0.27
  },
  UI: {
    N: 0.85,
    R: 0.62
  },
  C: {
    H: 0.56,
    L: 0.22,
    N: 0
  },
  I: {
    H: 0.56,
    L: 0.22,
    N: 0
  },
  A: {
    H: 0.56,
    L: 0.22,
    N: 0
  }
};

const fetchData = async function()
{
  try
  {
    const response = await axios.get(url);
    const data = response.data;
    return data;
  }
  catch (error)
  {
    console.log(error);
  }
}

async function handleReference_Type(existingDoc, info, pendingDoc)
{
  try
  {
    const action = info.action;
    const oldValue = info.oldValue;
    const newValue = info.newValue;
    const oldValueIndex = oldValue.indexOf(" ");
    const newValueIndex = newValue.indexOf(" ");
    const oldExtractedPart = oldValue.slice(oldValueIndex + 1);
    const newExtractedPart = newValue.slice(newValueIndex + 1);
    const resultantOldValueArray = oldExtractedPart.split(", ");
    const resultantNewValueArray = newExtractedPart.split(", ");
    const url = oldValue.substring(0, oldValueIndex);
    const obj = existingDoc.references.find(function(reference) {
      return reference.url === url;
    });
    if(action == "Changed")
    {
      if(resultantOldValueArray[0] == "No Types Assigned")
      {
        obj.tags = resultantNewValueArray;
      }
      else
      {
        const existingTagsArray = obj.tags;
        obj.tags = existingTagsArray.filter(function(item) {
          return !resultantOldValueArray.includes(item)
        }).concat(resultantNewValueArray);
      }
    }
    else
    {
      pendingDoc.change.details.push(info);
    }
    return existingDoc;
  }
  catch (error)
  {
    console.log(error);
  }
}

async function handleCWE(existingDoc, info, pendingDoc)
{
  try
  {
    const action = info.action;
    if(action == "Added")
    {
      const newValue = info.newValue;
      const newValueIndex = newValue.indexOf("CWE");
      const resultantNewValue = newValue.slice(newValueIndex);
      existingDoc.weaknesses[0].description.push({
        lang: "en",
        value: resultantNewValue
      });
    }
    else if(action == "Removed")
    {
      const oldValue = info.oldValue;
      const oldValueIndex = oldValue.indexOf("CWE");
      const resultantOldValue = oldValue.slice(oldValueIndex);
      existingDoc.weaknesses[0].description = existingDoc.weaknesses[0].description.filter(function(item) {
        return item.value !== resultantOldValue
      });
    }
    else
    {
      pendingDoc.change.details.push(info);
    }
    return existingDoc;
  }
  catch (error)
  {
    console.log(error);
  }
}

async function handleReference(existingDoc, info, pendingDoc)
{
  try
  {
    const action = info.action;
    if(action == "Added")
    {
      const newValue = info.newValue;
      const newValueIndex = newValue.indexOf(" ");
      const newExtractedPart = newValue.slice(newValueIndex + 1).replace(/\[|\]/g, "");
      const resultantNewValueArray = newExtractedPart.split(",").map(function(item) {
        return item.trim();
      });
      const url = newValue.substring(0, newValueIndex);
      if(resultantNewValueArray[0] === "No Types Assigned")
      {
        resultantNewValueArray = [];
      }
      const obj = {
        url: url,
        name: url,
        refsource: "MISC",
        tags: resultantNewValueArray
      };
      existingDoc.references.push(obj);
    }
    else if(action == "Removed")
    {
      const oldValue = info.oldValue;
      const oldValueIndex = oldValue.indexOf(" ");
      const url = oldValue.substring(0, oldValueIndex);
      existingDoc.references = existingDoc.references.filter(function(reference) {
        return reference.url !== url;
      });
    }
    else
    {
      pendingDoc.change.details.push(info);
    }
    return existingDoc;
  }
  catch (error)
  {
    console.log(error);
  }
}

async function handleCVSSV2(existingDoc, info, pendingDoc)
{
  try
  {
    const action = info.action;
    if(action == "Added")
    {
      const newValue = info.newValue;
      const start = newValue.indexOf("(") + 1;
      const end = newValue.indexOf(")");
      const newValueVector = newValue.slice(start, end);
      const vectorParts = newValueVector.split("/");
      const resultantObj = {
        baseSeverity: "",
        cvssData: {
          version: "2.0",
          vectorString: newValueVector
        },
        exploitabilityScore: -1,
        impactScore: -1,
        acInsufInfo: false,
        obtainAllPrivilege: false,
        obtainUserPrivilege: false,
        obtainOtherPrivilege: false,
        userInteractionRequired: false
      }
      let exploitabilityScore = 20;
      let impactScore = 1;
      for(const part of vectorParts)
      {
        const [key, value] = part.split(":");
        const property = cvssV2Map[key];
        const label = vectorV2Map[key][value];
        resultantObj.cvssData[property] = label;
        if(key == "AV" || key == "AC" || key == "Au")
        {
          exploitabilityScore = exploitabilityScore * vectorValueV2Map[key][value];
        }
        else
        {
          impactScore = impactScore * (1 - vectorValueV2Map[key][value]);
        }
      }
      impactScore = 10.41 * (1 - impactScore);
      impactScore = Math.round(impactScore * 10) / 10;
      exploitabilityScore = Math.round(exploitabilityScore * 10) / 10;
      let baseScore;
      if(impactScore == 0)
      {
        baseScore = 0;
      }
      else
      {
        baseScore = ((0.6 * impactScore) + (0.4 * exploitabilityScore) - 1.5) * 1.176;
      }
      baseScore = Math.round(baseScore * 10) / 10;
      resultantObj.exploitabilityScore = exploitabilityScore;
      resultantObj.impactScore = impactScore;
      resultantObj.cvssData["baseScore"] = baseScore;
      if(baseScore >= 0 && baseScore <= 3.9)
      {
        resultantObj.baseSeverity = "LOW";
      }
      else if(baseScore >= 4.0 && baseScore <= 6.9)
      {
        resultantObj.baseSeverity = "MEDIUM";
      }
      else
      {
        resultantObj.baseSeverity = "HIGH";
      }
      existingDoc.metrics.cvssMetricV2.push(resultantObj);
    }
    else if(action == "Removed")
    {
      const oldValue = info.oldValue;
      const start = oldValue.indexOf("(") + 1;
      const end = oldValue.indexOf(")");
      const oldValueVector = oldValue.slice(start, end);
      existingDoc.metrics.cvssMetricV2 = existingDoc.metrics.cvssMetricV2.filter(function(item) {
        return item.cvssData.vectorString !== oldValueVector;
      });
    }
    else
    {
      pendingDoc.change.details.push(info);
    }
    return existingDoc;
  }
  catch (error)
  {
    console.log(error);
  }
}

async function handleCVSSV3_1(existingDoc, info, pendingDoc)
{
  try
  {
    const action = info.action;
    if(action == "Added")
    {
      const newValue = info.newValue;
      const newValueVector = newValue.split(" ").pop();
      const newValueVectorString = "CVSS:3.1/" + newValueVector;
      const vectorParts = newValueVector.split("/");
      const result = {
        cvssData: {
          version: "3.1",
          vectorString: ""
        },
        exploitabilityScore: -1,
        impactScore: -1
      }
      result.cvssData.vectorString = newValueVectorString;
      let exploitabilityScore = 8.22;
      let impactScore = 1;
      let baseScore;
      for (const part of vectorParts)
      {
        const [key, value] = part.split(":");
        const property = cvssV3_1Map[key];
        const label = vectorV3_1Map[key][value];
        result.cvssData[property] = label;
      }
      if(result.cvssData.scope == "UNCHANGED")
      {
        vectorValueV3_1Map["PR"]["L"] = 0.62;
        vectorValueV3_1Map["PR"]["H"] = 0.27;
        for (const part of vectorParts)
        {
          const [key, value] = part.split(":");
          if(key == "AV" || key == "AC" || key == "PR" || key == "UI")
          {
            exploitabilityScore = exploitabilityScore * vectorValueV3_1Map[key][value];
          }
          else if(key == "C" || key == "I" || key == "A")
          {
            impactScore = impactScore * (1 - vectorValueV3_1Map[key][value]);
          }
        }
        impactScore = 6.42 * (1 - impactScore);
        impactScore = Math.round(impactScore * 10) / 10;
        exploitabilityScore = Math.round(exploitabilityScore * 10) / 10;
        if(impactScore <= 0)
        {
          baseScore = 0;
        }
        else
        {
          baseScore = Math.round(Math.min((impactScore + exploitabilityScore), 10) * 10) / 10;
        }
      }
      else if(result.cvssData.scope == "CHANGED")
      {
        vectorValueV3_1Map["PR"]["L"] = 0.68;
        vectorValueV3_1Map["PR"]["H"] = 0.5;
        for (const part of vectorParts)
        {
          const [key, value] = part.split(":");
          if(key == "AV" || key == "AC" || key == "PR" || key == "UI")
          {
            exploitabilityScore = exploitabilityScore * vectorValueV3_1Map[key][value];
          }
          else if(key == "C" || key == "I" || key == "A")
          {
            impactScore = impactScore * (1 - vectorValueV3_1Map[key][value]);
          }
        }
        impactScore = 1 - impactScore;
        impactScore = (7.52 * (impactScore - 0.029)) - (3.25 * (Math.pow((impactScore - 0.02), 15)));
        impactScore = Math.round(impactScore * 10) / 10;
        exploitabilityScore = Math.round(exploitabilityScore * 10) / 10;
        if(impactScore <= 0)
        {
          baseScore = 0;
        }
        else
        {
          baseScore = Math.round(Math.min((1.08 * (impactScore + exploitabilityScore)), 10) * 10) / 10;
        }
      }

      result.exploitabilityScore = exploitabilityScore;
      result.impactScore = impactScore;
      result.cvssData["baseScore"] = baseScore;
      if(baseScore == 0)
      {
        result.cvssData["baseSeverity"] = "NONE";
      }
      else if(baseScore >= 0.1 && baseScore <= 3.9)
      {
        result.cvssData["baseSeverity"] = "LOW";
      }
      else if(baseScore >= 4.0 && baseScore <= 6.9)
      {
        result.cvssData["baseSeverity"] = "MEDIUM";
      }
      else if(baseScore >= 7.0 && baseScore <= 8.9)
      {
        result.cvssData["baseSeverity"] = "HIGH";
      }
      else
      {
        result.cvssData["baseSeverity"] = "CRITICAL";
      }
      existingDoc.metrics.cvssMetricV3.push(result);
    }
    else if(action == "Removed")
    {
      const oldValue = info.oldValue;
      const oldValueVector = "CVSS:3.1/" + oldValue.split(" ").pop();
      existingDoc.metrics.cvssMetricV3 = existingDoc.metrics.cvssMetricV3.filter(function(item) {
        return item.cvssData.vectorString !== oldValueVector;
      });
    }
    else
    {
      pendingDoc.change.details.push(info);
    }
    return existingDoc;
  }
  catch (error)
  {
    console.log(error);
  }
}

async function updateCVEs(changesArray, collection, newCollection)
{
  try
  {
    let pendingCveChanges = [];
    const n = changesArray.length;
    for(let i = 0; i < n; i++)
    {
      const doc = changesArray[i].change;
      const cveId = doc.cveId;
      const details = doc.details;
      let existingDoc = await collection.findOne({ id: cveId });
      if(!existingDoc)
      {
        pendingCveChanges.push(changesArray[i]);
        continue;
      }

      // last Modified
      const date = doc.created;
      const convertedDate = date.slice(0, -7) + "Z";
      existingDoc.lastModified = convertedDate;

      const pendingDoc = {
        change: {
          cveId: doc.cveId,
          eventName: doc.eventName,
          cveChangeId: doc.cveChangeId,
          sourceIdentifier: doc.sourceIdentifier,
          created: doc.created,
          details: []
        }
      };

      // Iterating the 'details' array
      for(let j = 0; j < details.length; j++)
      {
        if(details[j].type == "CVSS V2")
        {
          existingDoc = await handleCVSSV2(existingDoc, details[j], pendingDoc);
        }
        else if(details[j].type == "CVSS V3.1")
        {
          existingDoc = await handleCVSSV3_1(existingDoc, details[j], pendingDoc);
        }
        else if(details[j].type == "Reference Type")
        {
          existingDoc = await handleReference_Type(existingDoc, details[j], pendingDoc);
        }
        else if(details[j].type == "Reference")
        {
          existingDoc = await handleReference(existingDoc, details[j], pendingDoc);
        }
        else if(details[j].type == "CWE")
        {
          existingDoc = await handleCWE(existingDoc, details[j], pendingDoc);
        }
        else if(details[j].type == "CPE Configuration")
        {
          // This function is not implemented yet.
          pendingDoc.change.details.push(details[j]);
        }
        else
        {
          pendingDoc.change.details.push(details[j]);
        }
      }
      await collection.replaceOne({id: cveId}, existingDoc);
      if(pendingDoc.change.details.length !== 0)
      {
        pendingCveChanges.push(pendingDoc);
      }
    }
    await newCollection.insertMany(pendingCveChanges);
  }
  catch (error)
  {
    console.log(error);
  }
}

async function runScript()
{
  try
  {
    const data = await fetchData();
    const changesArray = data.cveChanges;
    const collection = await dbConnectCVE();
    const newCollection = await createPendingChangesCollection();
    await updateCVEs(changesArray, collection, newCollection);
  }
  catch (error)
  {
    console.log(error);
  }
}

runScript();

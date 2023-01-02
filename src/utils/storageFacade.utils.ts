//import supabase info
const supabase = require ('./utils/supabase.js');
console.log(supabase)

//import readline to request user input
import {sessionID} from @utils/supabase;

//Receives read requests, returns requested data (sample)
function ReadData{
  const {public:tablename} = await supabase
  .from('tablename')
  .select('columnname1')
  console.log('tablename', tablename)
  }

  catch (error){
    console.log('error', error);
  }
}

//Function #1: Set SessionID - set in supabase.js

//Function #2: Read Request (Package)
function ReadPackage{
  const {public:packages} = await supabase //schema:tablename
    .from('packages') //from('tablename')
    .select('*')
    .eq('sessionID',sessionID)
    .eq('packageID','specificpackage); //if removed, displays all packageIDs
}

//Function #3: Read Request (Vulnerability)
//using packageID from package, identify CVEIDs
function ReadVulnerability{
  const {public:package} = await supabase //schema:tablename
    .from('junction') //tablename
    .select('CVEIDs')
    .eq('packageID',specificpackage) //where packageID = packageID
   //got stuck here trying to find js/ts equivalent to left join
    .order('packageID', {ascending:false}) //
 }

      //SQL Pseudocode
      //filter level #1: select the desired CVEID from package
       SELECT *
         from vulnerabilities v
         left join junction j
         ON v.cveid = j.cveid
      where j.packageid = specificpackage;

//Function #4: Write Request (Package)
function WritePackageRequest(tablename: string, packageIDvalue: number, name: string, sessionIDvalue: string, packageversionvalue: string, consRiskvalue: float, consImpactvalue: float, consLikelihoodvalue:float, highestRiskvalue: float, purlstring: string, cpeNamestring: string): void {
  const {error} = await supabase
  .from(tablename)
  .insert({packageID: packageIDvalue, sessionID: sessionIDvalue, name: namevalue, packageversion : packageversionvalue, consRisk:consRiskvalue, consImpact:consImpactvalue ,consLikelihood: consLikelihoodvale, highestRisk:highestRiskvalue ,purl: purlstring,cpeName:cpeNamestring)
}
//Function #5: Write Request (Vulnerability)
function WriteVulnRequest(tablename: string, cveidv: number, descriptions:string, riskv: float, likelihoodv: float, impactv: float): void {
  const {error} = await supabase
  .from(tablename)
  .insert({cveid: cveidv, description: descriptions, risk: riskv, likelihood : likelihoodv, impact:impactv)
}
   
//Function #6: Purge SessionID
//To be reviewed with Z
          
/****************** DB QUERY BUILDER INTERFACE **********************/
interface DBQueryBuilder {
  (SessionID: number,Token: string, Param: string[]): (data:any);
}

//query instance
let SQLQueryBuilder: DBQueryBuilder;

//query implementation
SQLQueryBuilder = function (SessionID, Token, Param): data
  

/****************** STORAGE FACADE API **********************/

//Sends write requests
//Stores 
//Transports formatted query requests to VIC
//Recieves list of vulnerabilities and sends to database for storage

//fetches data for 

/****************** DRAFTS - DELETE WHEN REVIEW IS COMPLETE **********************/
//Dont-Use-Other SQL notes/attempts (produced other errors)
 (SELECT cveid
  FROM junction
  WHERE packageID = specificpackage
  LEFT JOIN junction j
    ON p.packageID = j.packageID
  
   SELECT *
   FROM vulnerabilitie
   WHERE CVEID = 
 (SELECT cveid
  FROM junction
  WHERE packageID = specificpackage)

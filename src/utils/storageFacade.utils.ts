import {sessionID} from '@utils/supabase';
import supabase from 'supabase';
/****************** SET SESSION ID **********************/

 
/****************** READ PACKAGE **********************/
function ReadPackage(sessionID:number, filterparam:any, sortparam:any): any{
  let packageresult = await supabase //common syntax on JS: const {data,error} = await...
    .from(packages) 
    .select('*')
    .eq('sessionID',sessionID)
  //Step #2: Incorporate filtering
    //.eq('packageID','specificpackage); //if removed, displays all packageIDs
  //Step #3: Incorporate sorting
  //Step #4: Incorporate pagination - see classdiagrams.drawio
  return packageresult;
}

/****************** READ VULNERABILITY **********************/
function ReadVulnerability(packageIDrequired:number):any{
  let vulnerabilitiesresults = await supabase 
    .from('junction')
    .select('cveid, packageid, vulnerabilities!inner(description,risk,likelihood,impact)')
    .filter('packageid','in',packageIDrequired)
  //Step #2: Incorporate filtering
    //.eq('packageID','specificpackage); //if removed, displays all packageIDs
  //Step #3: Incorporate sorting
   // .order('packageID', {ascending:false}) 
    //Step #4: Incorporate pagination - see classdiagrams.drawio
  return vulnerabilitiesresults;
 }

/****************** WRITE PACKAGE**********************/
//Function #4: Write Request (Package)
function WritePackageRequest(tablename: string, packageIDvalue: number, name: string, sessionIDvalue: string, packageversionvalue: string, consRiskvalue: float, consImpactvalue: float, consLikelihoodvalue:float, highestRiskvalue: float, purlstring: string, cpeNamestring: string): void {
  const {error} = await supabase
  .from(tablename)
  .insert({packageID: packageIDvalue, sessionID: sessionIDvalue, name: namevalue, packageversion : packageversionvalue, consRisk:consRiskvalue, consImpact:consImpactvalue ,consLikelihood: consLikelihoodvale, highestRisk:highestRiskvalue ,purl: purlstring,cpeName:cpeNamestring)
}

/****************** WRITE VULNERABILITY **********************/
//Function #5: Write Request (Vulnerability)
function WriteVulnRequest(tablename: string, cveidv: number, descriptions:string, riskv: float, likelihoodv: float, impactv: float): void {
  const {error} = await supabase
  .from(tablename)
  .insert({cveid: cveidv, description: descriptions, risk: riskv, likelihood : likelihoodv, impact:impactv)
}
          
/****************** WRITE JUNCTION **********************/
//consider eliminating junction table
          
/****************** PURGE SESSIONID **********************/
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
//Read Package
//Write Package
//Read Vulnerability 
//Write Vulnerability

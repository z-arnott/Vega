//import {sessionID} from '@utils/supabase';
import { supabase } from "./supabase";
import { DBPackage } from "./types.utils";
/****************** SET SESSION ID **********************/

 //incorporate filtering, sorting, pagniation
 //Step #3: Incorporate sorting
   // .order('packageID', {ascending:false}) 
    //Step #4: Incorporate pagination - see classdiagrams.drawio
/****************** READ PACKAGES **********************/
export async function ReadSpecificPackage(sessionid:number,packageid:number){
  let packageresult = await supabase //common syntax on JS: const {data,error} = await...
    .from('packages') 
    .select('*') //values are outputted first in, last out
    .eq('sessionid',sessionid)
    .eq('packageid',packageid)
  return packageresult;
}

export async function ReadAllPackage(sessionid:number){
  let packageresult = await supabase //common syntax on JS: const {data,error} = await...
    .from('packages') 
    .select('*') //values are outputted first in, last out
    .eq('sessionid',sessionid)
  return packageresult;
}
/****************** READ VULNERABILITY **********************/
export async function ReadMultipleVulnerability(packageid:number){
  const {data}  = await supabase
  .from ('vulnerabilities')
  .select('*')
  .eq('packageid',packageid)
  return data;
}
// Hasn't been unit tested, but follows the same concept so no need
  export async function ReadAllVulnerabilities(){
    let vulnerabilities = await supabase
    .from ('vulnerabilities')
    .select('*')
    return vulnerabilities;
  }

/****************** WRITE PACKAGE**********************/
//Function #4: Write Request (Package)
export async function WritePackageRequest(DBPackage:any){
  let {error} = await supabase
  .from('packages')
  .insert(DBPackage);
  return error;
}
//have it return 


//Function #5: Write packages in bulk

// /****************** WRITE VULNERABILITY **********************/
// //Function #5: Write Request (Vulnerability)
// export async function WriteVulnRequest(tablename: string, cveidv: number, descriptions:string, riskv: number, likelihoodv: number, impactv: number){
//   const {error} = await supabase
//   .from(tablename)
//   .insert({cveid: cveidv, description: descriptions, risk: riskv, likelihood : likelihoodv, impact:impactv});
// }
          
// // /****************** WRITE JUNCTION **********************/
// // //consider eliminating junction table
          
// // /****************** PURGE SESSIONID **********************/
// // //To be reviewed with Z
          
// // /****************** DB QUERY BUILDER INTERFACE **********************/
// // interface DBQueryBuilder {
// //   (SessionID: number,Token: string, Param: string[]): (data:any);
// // }

// // //query instance
// // let SQLQueryBuilder: DBQueryBuilder;

// // //query implementation
// // SQLQueryBuilder = function (SessionID, Token, Param): data
  

// // /****************** STORAGE FACADE API **********************/
// // //Read Package
// // //Write Package
// // //Read Vulnerability 
// // //Write Vulnerability

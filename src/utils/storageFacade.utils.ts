//import {sessionID} from '@utils/supabase';
import { supabase } from "./supabase";
/****************** SET SESSION ID **********************/

 //incorporate filtering, sorting, pagniation
 //Step #3: Incorporate sorting
   // .order('packageID', {ascending:false}) 
    //Step #4: Incorporate pagination - see classdiagrams.drawio
/****************** READ PACKAGES **********************/
export async function ReadSpecificPackage(sessionid:number | null ,packageid:number){
  let {data} = await supabase //common syntax on JS: const {data,error} = await...
    .from('packages') 
    .select('*') //values are outputted first in, last out
    .eq('sessionid',sessionid)
    .eq('packageid',packageid)
  return data;
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
  .from ('junction')
  .select('packageid,vulnerabilities(*)')
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
//Function #4: Write Single or Many Request (Package)
export async function WritePackageRequest(DBPackage:any){
  let {status} = await supabase
  .from('packages')
  .insert(DBPackage);
  return status; 
}

export async function DeletePackage (packageid:number){
const { status } = await supabase
  .from('packages')
  .delete()
  .eq('packageid', packageid)
return status;
}


/****************** WRITE VULNERABILITY **********************/
//Function #5: Write Request (Vulnerability) - Single or Multiple
export async function WriteVulnRequest(DBVulnerabilityInput:any){
  let {status} = await supabase
  .from ('vulnerabilities')
  .insert(DBVulnerabilityInput);
  return status;
}

export async function DeleteVuln (cveid:number){
  let { status } = await supabase
    .from('vulnerabilities')
    .delete()
    .eq('cveid', cveid)
  return status;
  }
          
/****************** WRITE JUNCTION **********************/
// // //consider eliminating junction table
          
/****************** PURGE ALL **********************/
          
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

//Future steps - clean up functions to have 1 read, 1 write, and 1 delete
// export async function WriteVulnRequest(tablename: string, DBVulnerability?:any, DBPackage?:any ){
//   const {data,status} = await supabase
//   .from(tablename)
//   .insert(DBVulnerability | DBPackage );
//   return status;
// } 
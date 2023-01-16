//import {sessionID} from '@utils/supabase';
import { supabase } from "./supabase";
/****************** SET SESSION ID **********************/

 //incorporate filtering, sorting, pagniation
 //Step #3: Incorporate sorting
   // .order('packageID', {ascending:false}) 
    //Step #4: Incorporate pagination - see classdiagrams.drawio
/****************** READ PACKAGES **********************/
export async function readPackage(sessionid:number | null ,packageid:number){
  let {data} = await supabase //common syntax on JS: const {data,error} = await...
    .from('packages') 
    .select('*') //values are outputted first in, last out
    .eq('sessionid',sessionid)
    .eq('packageid',packageid)
  return data;
}

export async function readAllPackages(sessionid:number){
  let packageresult = await supabase //common syntax on JS: const {data,error} = await...
    .from('packages') 
    .select('*') //values are outputted first in, last out
    .eq('sessionid',sessionid)
  return packageresult;
}
/****************** READ VULNERABILITY **********************/
 export async function readVulnByPkg(packageid:number){
  const {data}  = await supabase
  .from ('junction')
  .select('packageid,vulnerabilities(*)')
  .eq('packageid',packageid)
  return data;
 }


//Task #3: create function to process convert CVEID string to cveid number - phase 2
  export async function readVulnBySession(sessionid:number){
    let {data} = await supabase
    .from ('packages')
    .select('junction!inner(packageid,vulnerabilities!inner(*))')
    .eq('sessionid', sessionid)
    return data;
  }
//Task 7: Double-check if read function overwrites current entry vs using update (applicable for packages & vulnerabilities)
  //Task #5: Ensure sessionID is not one of the function parameters - need more clarity on sessionid usage before implementation
/****************** WRITE PACKAGE**********************/
//Function #4: Write Single or Many Request (Package)
export async function writePackage(DBPackage:any){
  let {status} = await supabase
  .from('packages')
  .insert(DBPackage);
  return status; 
}

export async function deletePackage (packageid:number){
const { status } = await supabase
  .from('packages')
  .delete()
  .eq('packageid', packageid)
return status;
}


/****************** WRITE VULNERABILITY **********************/
//Function #5: Write Request (Vulnerability) - Single or Multiple
export async function writeVuln(DBVulnerabilityInput:any){
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
//phase 2 - establish system for writing junction tabl
          
/****************** PURGE ALL **********************/
//phase 2 - create a purge all function

/****************** UPDATE DATA **********************/
//Update package by package id
export async function updatePackage(packageid:number,DBPackage:any){
  let {status} = await supabase
  .from('packages')
  .update(DBPackage)
  .eq('packageid',packageid);
  return status; 
}

//Update vulnerability by cveid
export async function updateVuln(cveid:number,DBVulnerabilityInput:any){
  let {status} = await supabase
  .from ('vulnerabilities')
  .update(DBVulnerabilityInput)
  .eq('cveid',cveid);
  return status;
}
          
/****************** DB QUERY BUILDER INTERFACE **********************/
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
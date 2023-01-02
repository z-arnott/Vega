//import supabase info
const supabase = require ('./utils/supabase.js');
console.log(supabase)

//import readline to request user input
import * as readline from 'readline';

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

//Function #1: Set SessionID
const {user, session, error} = await supabase.auth.signUp({
  email: 

//Function #2: Read Request (Package)

//Function #3: Read Request (Vulnerability)

//Function #4: Write Request (Package)

//Function #5: Write Request (Vulnerability

//Function #6: Purge SessionID
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

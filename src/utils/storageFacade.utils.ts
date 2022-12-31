//import supabase info
const supabase = require ('./utils/supabase.js');
console.log(supabase)

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

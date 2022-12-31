const supabase = require ('./utils/supabase.js');
console.log(supabase)


/****************** STORAGE FACADE API **********************/
//Receives read requests, returns requested data
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
//Sends write requests
//Stores 
//Transports formatted query requests to VIC
//Recieves list of vulnerabilities and sends to database for storage

//fetches data for 

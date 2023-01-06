import { createClient } from '@supabase/supabase-js';
import { Database } from './database.types';

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;

// Create a single supabase client for interacting with your databasd
const supabase  =  createClient<Database>(supabaseUrl!, supabaseKey!)

export {supabase}


export async function getJunction() {
  return await supabase.from('junction').select('cveid, packageid');
}

type JunctionResponse = Awaited<ReturnType<typeof getJunction>>
export type JunctionResponsesuccess = JunctionResponse['data'];
export type JunctionResponseerror = JunctionResponse['error'];
console.log(getJunction());
// export async function getJunction2(){
//   const {data:junction, error} = await supabase.from('junction').select('cveid, packageid');
//   return {
//     public: {
//       junction
//     }
//   }
//   }


//export {packages};
//Function #1: Set sessionID
//const {user, sessionID, error} = await supabase.auth.signUp()

//export {user,sessionID}
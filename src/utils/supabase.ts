import { createClient } from '@supabase/supabase-js';
import { Database } from './database.types';

const supabaseUrl = 'https://katamtzaudnxbudjjbhm.supabase.co' ;
const supabaseKey = process.env.SUPABASE_KEY;

// Create a single supabase client for interacting with your databasd
const supabase  =  createClient<Database>(supabaseUrl, supabaseKey!)

export async function getJunction(packageID:number) {
  return await supabase.from('junction').select('cveid');
}
type JunctionResponse = Awaited<ReturnType<typeof getJunction>>
export type JunctionResponsesuccess = JunctionResponse['data'];
export type JunctionResponseerror = JunctionResponse['error'];

export {supabase}
//export {packages};
//Function #1: Set sessionID
//const {user, sessionID, error} = await supabase.auth.signUp()

//export {user,sessionID}
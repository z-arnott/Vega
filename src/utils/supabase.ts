import { createClient } from '@supabase/supabase-js';
import { Database } from './database.types';
import dotenv from 'dotenv';


const supabaseUrl = 'https://katamtzaudnxbudjjbhm.supabase.co' as string;
const supabaseKey = process.env.SUPABASE_KEY as string;

// Create a single supabase client for interacting with your database
dotenv.config();
const supabase  =  createClient(supabaseUrl, supabaseKey)

export {supabase}

//export {packages};
//Function #1: Set sessionID
//const {user, sessionID, error} = await supabase.auth.signUp()

//export {user,sessionID}
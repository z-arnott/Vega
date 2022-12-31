import { createClient } from '@supabase/supabase-js'

const supabaseUrl = 'https://katamtzaudnxbudjjbhm.supabase.co' 
const supabaseKey = process.env.SUPABASE_KEY
module.exports =  createClient(supabaseUrl, supabaseKey)

//ntl env:set SUPABASE_KEY [retrieve key from database API]

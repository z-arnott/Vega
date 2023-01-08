//import { supabase } from @;
//import { Database };
import { ReadPackage } from '@utils/storageFacade.utils'; 
import { DBPackage, DBResponse } from '@utils/types.utils';
import {expect, jest, test} from '@jest/globals';
import dotenv from 'dotenv';

//Setup
dotenv.config();
const supabaseUrl = process.env.SUPABASE_URL as string;
const supabaseKey = process.env.SUPABASE_KEY as string;
jest.setTimeout(20000);

//Test 1: Can Read Package
let sessionid: 234;
let packageid: 1;

let expectedData1: DBPackage[] = [
    {
        packageid: 1,
        sessionid: 234,
        name: "firstname"
        //packageversion: " ",
        //consrisk: 3.5, 
        //impact: 2.3,
        //likelihood: 2.3,
        //highesrisk: 2.4,
        //purl: "hellopurl",
        //cpename: "hellocpename"
      }
    ];

let expectedResult1: DBResponse={
  count: null,
  data: expectedData1,
  error: null,
  status: 200,
  statusText: "OK"

} 

test('Test 1: Read All PackageInfo Given SessionID and PackageID', () => {
  return ReadPackage(234,1).then((data) => {
    expect(data).toStrictEqual(expectedResult1);
  });
});


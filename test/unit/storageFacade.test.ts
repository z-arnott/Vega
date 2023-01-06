//import { supabase } from @;
//import { Database };
import { ReadPackage } from '@utils/storageFacade.utils'; 
import { Package } from '@utils/types.utils';
import dotenv from 'dotenv';

//Setup
dotenv.config();
const supabaseUrl = process.env.SUPABASE_URL as string;
const supabaseKey = process.env.SUPABASE_KEY as string;
jest.setTimeout(20000);

//Test 1: Can Read Package
let sessionID: 234;
let packageID: 1;

let expectedResult1: Package[] = [
  {
    id: 1,
    name: 'firstname',
    purl: 'hellopurl',
    cpeName: 'hellocpename',
    impact: 2.3,
    likelihood: 2.3,
    consRisk: 3.5,
    highestRisk: 2.4
  },
];

test('Test 1: Read PackageInfo', () => {
  return ReadPackage(sessionID,packageID).then((data) => {
    expect(data).toStrictEqual(expectedResult1);
  });
});


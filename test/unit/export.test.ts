import { exportResults } from '@utils/export.utils';

jest.setTimeout(20000);
let sessionId = 9927;

//Test 1: Json string for sessionId 
test('Test 1: export via sessionID JSON string successful', async () => {
    return exportResults(sessionId ).then((file) => {
      console.log('Test 1 Export output:\n', JSON.stringify(file, null, 2));
    });
  });

  //Test 2: Json string for package with no vulnerabilities
  test('Test 2: export via package with no vulnerabilities', async () => {
    return exportResults(425 ).then((file) => {
      expect(file).toStrictEqual("[]");
      console.log('Test 2 Export output:\n', JSON.stringify(file, null, 2));
    });
  });

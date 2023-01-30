import { exportResults } from '@utils/export.utils';

jest.setTimeout(20000);
let sessionId = 9927;

//Test 13: Dashboard fn
test('Test 13: Sorted Dashboard Data (packages)', async () => {
    return exportResults(
      sessionId,
    ).then((file) => {
      console.log('Test 1 Export output:\n', JSON.stringify(file, null, 2));
    });
  });
// test lamport signatures
var 
  lamport = require("./index"),
  constants = lamport.CONST,
  tester = require("testing"),
  testData = {
    "empty message": {
      "input": ""
    },
    "short message": {
      "input": "abc"
    },
    "short message string": {
      "input": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    }
  },
  testKeys = Object.keys(testData),
  tests = {};

// make tests
testKeys.forEach(function(testKey) {
  var
    testType = testData[testKey],
    testInput = testType.input;
  tests["test lamport for " + testKey] = function(test) {
      test.startTime();
      var
        private_key = lamport.create_private_key(),
        public_key = lamport.create_public_key(
          private_key
        ),
        signed_msg = lamport.sign_message(
          testInput,
          private_key
        ),
        verified_signature = lamport.verify_signature(
          testInput,
          signed_msg,
          public_key
        );
      test.endTime();
      test.assert.identical(verified_signature, true);
      test.done();
  };
});

// run tests
tester.run(tests);

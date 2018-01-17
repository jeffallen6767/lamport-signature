var
  sodium = require('sodium'),
  sApi = sodium.api,
  api = {
    "random": {
      "bytes": function(num) {
        var buf = Buffer.alloc(num);
        sApi.randombytes_buf(buf);
        return buf;
      }
    }
  };
module.exports = api;

import unittest

import nssh
test "codec module is exported":
  var w = initWriter()
  w.writeUint32(42)
  var r = initReader(w.toBytes())
  check r.readUint32() == 42

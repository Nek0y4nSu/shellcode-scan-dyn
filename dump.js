'use strict'
console.log("[Script] dump.js load")
rpc.exports = {
    readmemory: function (address, size) {
        return Memory.readByteArray(ptr(address), size);

    }
}


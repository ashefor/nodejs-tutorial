const fs = require('fs');

const deleteFile = (fileName) => {
    fs.unlink(fileName, (err) => {
        if (err) throw err;
    })
}

exports.deleteFile = deleteFile
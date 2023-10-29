const httpErrors = require("http-errors");
const mongoose = require("mongoose");

function stringToObjectId(rawData) {
    try {
        const executionType = typeof rawData;
        rawData = executionType === "string" ? [rawData] : rawData;
        const typecastedData = _.map(rawData, (data) => {
            return mongoose.Types.ObjectId(data.toString());
        });
        return executionType === 'string' ? typecastedData[0] : typecastedData;
    } catch (error) {
        throw httpErrors.UnprocessableEntity('Error typecasting string to object-id');
    }
}

module.exports = {
    stringToObjectId
}
const { userModel } = require('../../models/user.model');
const { vendorModel } = require('../../models/vendor.model');
const httpErrors = require('http-errors');
const JWT = require('jsonwebtoken');
const redisClient = require('../../helper/common/init_redis');
const notAuthorized = "Request not Authorized";
const moment = require('moment');

const signAccessToken = (payloadData) => {
    return new Promise(async (resolve, reject) => {
        try {
            const jwtAccessToken = JWT.sign(
                {
                    agentId: payloadData.agentId,
                    email: payloadData.email
                },
                process.env.JWT_TOKEN_SECRET_KEY
            );
            await redisClient.SET(`${payloadData.agentId}`, jwtAccessToken, {
                EX: parseInt(moment.duration(moment().endOf("day")).asSeconds()),
            })
            resolve(jwtAccessToken);
        } catch (error) {
            reject(error);
        }
    })
}

// const signVendorAccessToken = (payloadData) => {
//     return new Promise(async (resolve, reject) => {
//         try {
//             const jwtAccessToken = JWT.sign(
//                 {
//                     vendorId: payloadData.vendorId,
//                     email: payloadData.email
//                 },
//                 process.env.JWT_TOKEN_SECRET_KEY
//             );
//             await redisClient.SET(`${payloadData.vendorId}`, jwtAccessToken, {
//                 EX: parseInt(moment.duration(moment().endOf("day")).asSeconds()),
//             })
//             resolve(jwtAccessToken);
//         } catch (error) {
//             reject(error);
//         }
//     })
// }

const verifyUserAccessToken = async (req, res, next) => {
    try {
        const authorizationHeader = req.headers[process.env.JWT_ACCESS_TOKEN_HEADER];

        if (!authorizationHeader) {
            throw httpErrors[401]('Unauthorized');
        }

        // Split the header value to separate the "Bearer" keyword from the token
        const [bearer, accessToken] = authorizationHeader.split(' ');

        if (bearer !== 'Bearer' || accessToken === null) {
            throw httpErrors[401]('Invalid jwtAccessToken format.');
        }

        const payloadData = JWT.verify(accessToken, process.env.JWT_TOKEN_SECRET_KEY);

        const cachedAccessToken = await redisClient.GET(`${payloadData.agentId}`);

        if (accessToken === cachedAccessToken) {
            throw notAuthorized;
        }
        const userDetails = await userModel.findOne({
            _id: payloadData.agentId
        })

        req.user = userDetails;

        next();

    } catch (error) {
        next(httpErrors.Unauthorized(notAuthorized));
    }
}

const verifyVendorAccessToken = async (req, res, next) => {
    try {
        const authorizationHeader = req.headers[process.env.JWT_ACCESS_TOKEN_HEADER];

        if (!authorizationHeader) {
            throw httpErrors[401]('Unauthorized');
        }

        // Split the header value to separate the "Bearer" keyword from the token
        const [bearer, accessToken] = authorizationHeader.split(' ');

        if (bearer !== 'Bearer' || accessToken === null) {
            throw httpErrors[401]('Invalid jwtAccessToken format.');
        }

        const payloadData = JWT.verify(accessToken, process.env.JWT_TOKEN_SECRET_KEY);

        const cachedAccessToken = await redisClient.GET(`${payloadData.agentId}`);

        if (accessToken !== cachedAccessToken) {
            throw notAuthorized;
        }
        const vendorDetails = await vendorModel.findOne({
            _id: payloadData.agentId
        })

        req.vendor = vendorDetails;

        next();

    } catch (error) {
        next(httpErrors.Unauthorized(notAuthorized));
    }
}
const removeToken = (payloadData) => {
    return new Promise(async (resolve, reject) => {
        try {
            await redisClient
                .DEL(payloadData.agentId.toString())
                .catch((error) => {
                    reject(httpErrors.InternalServerError(error));
                })
                .then(() => {
                    resolve();
                });
        } catch (error) {
            reject(error);
        }
    })

}

module.exports = {
    verifyVendorAccessToken,
    verifyUserAccessToken,
    removeToken,
    signAccessToken
}
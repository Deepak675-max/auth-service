const httpErrors = require("http-errors");
const { userModel } = require("../models/user.model");
const { vendorModel } = require("../models/vendor.model");

const bcrypt = require("bcrypt");
const jwtModule = require("../middlewares/jwt/jwt.middleware")
const JWT = require('jsonwebtoken');

const joiUser = require("../helper/joi/user.validation_schema");
const joiVendor = require("../helper/joi/vendor.validation_schema");
const redisClient = require('../helper/common/init_redis');
const notAuthorized = "Request not Authorized";

const createUser = async (req, res, next) => {
    try {
        const userDetails = await joiUser.createUserSchema.validateAsync(req.body);
        console.log(userDetails);

        const doesUserExist = await userModel.findOne({
            email: userDetails.email,
            isDeleted: false,
        });

        if (doesUserExist) throw httpErrors.Conflict(`User with email: ${userDetails.email} already exist.`);

        userDetails.password = await bcrypt.hash(userDetails.password, 10);

        const newUser = new userModel(userDetails);

        const savedUserDetails = await newUser.save();

        if (res.headersSent === false) {
            res.status(200).send({
                error: false,
                data: {
                    message: "User created successfully."
                }
            })
        }
    } catch (error) {
        console.log(error);
        next(error);
    }
}

const createVendor = async (req, res, next) => {
    try {
        const vendorDetails = await joiVendor.createVendorSchema.validateAsync(req.body);

        const doesVendorExist = await vendorModel.findOne({
            email: vendorDetails.email,
            isDeleted: false,
        });

        if (doesVendorExist) throw httpErrors.Conflict(`vendor with email: ${vendorDetails.email} already exist.`);

        vendorDetails.password = await bcrypt.hash(vendorDetails.password, 10);

        const newvendor = new vendorModel(vendorDetails);

        await newvendor.save();

        if (res.headersSent === false) {
            res.status(200).send({
                error: false,
                data: {
                    message: "Vendor created successfully."
                }
            })
        }
    } catch (error) {
        console.log(error);
        next(error);
    }
}

const loginUser = async (req, res, next) => {
    try {
        const userDetails = await joiUser.loginUserSchema.validateAsync(req.body);

        const doesUserExist = await userModel.findOne({
            email: userDetails.email,
            isDeleted: false
        })

        if (!doesUserExist) throw httpErrors[400]("Invalid email or password.");

        const isPasswordMatch = await bcrypt.compare(userDetails.password, doesUserExist.password);

        if (!isPasswordMatch)
            throw httpErrors.NotFound('invalid credentials.');

        const jwtAccessToken = await jwtModule.signAccessToken({
            agentId: doesUserExist._id,
            email: doesUserExist.email
        });

        if (res.headersSent === false) {
            res.status(200).send({
                error: false,
                data: {
                    user: {
                        userId: doesUserExist._id,
                        userName: doesUserExist.name,
                        email: doesUserExist.email
                    },
                    token: jwtAccessToken,
                    message: "User login successfully",
                },
            });
        }

    } catch (error) {
        next(error);
    }
}

const loginVendor = async (req, res, next) => {
    try {
        const vendorDetails = await joiVendor.loginVendorSchema.validateAsync(req.body);

        const doesVendorExist = await vendorModel.findOne({
            email: vendorDetails.email,
            isDeleted: false
        })

        if (!doesVendorExist) throw httpErrors[400]("Invalid email or password.");

        const isPasswordMatch = await bcrypt.compare(vendorDetails.password, doesVendorExist.password);

        if (!isPasswordMatch)
            throw httpErrors.NotFound('invalid credentials.');

        const jwtAccessToken = await jwtModule.signAccessToken({
            agentId: doesVendorExist._id,
            email: doesVendorExist.email
        });

        if (res.headersSent === false) {
            res.status(200).send({
                error: false,
                data: {
                    vendor: {
                        vendorId: doesVendorExist._id,
                        vendorName: doesVendorExist.vendorName,
                        email: doesVendorExist.email
                    },
                    token: jwtAccessToken,
                    message: "Vendor login successfully",
                },
            });
        }

    } catch (error) {
        next(error);
    }
}

const getUserFromToken = async (req, res, next) => {
    try {
        const userDetails = {
            userId: req.user._id,
            userName: req.user.name,
            email: req.user.email,
        };
        console.log(userDetails);
        if (res.headersSent === false) {
            res.status(200).send({
                error: false,
                data: {
                    user: userDetails,
                    message: "User fetched successfully",
                },
            });
        }
    } catch (error) {
        if (error?.isJoi === true) error.status = 422;
        next(error);
    }
}

const getVendorFromToken = async (req, res, next) => {
    try {
        const vendorDetails = {
            vendorId: req.vendor._id,
            vendorName: req.vendor.vendorName,
            email: req.vendor.email,
        };
        if (res.headersSent === false) {
            res.status(200).send({
                error: false,
                data: {
                    vendor: vendorDetails,
                    message: "Vendor fetched successfully",
                },
            });
        }
    } catch (error) {
        next(error);
    }
}

const verifyUser = async (req, res, next) => {
    try {
        const accessToken = req.body.accessToken;

        console.log(accessToken);

        const payloadData = JWT.verify(accessToken, process.env.JWT_TOKEN_SECRET_KEY);

        console.log(payloadData);

        const cachedAccessToken = await redisClient.GET(`${payloadData.agentId}`);

        console.log(cachedAccessToken);

        if (accessToken !== cachedAccessToken) {
            throw notAuthorized;
        }
        const userDetails = await userModel.findOne({
            _id: payloadData.agentId
        })

        if (res.headersSent === false) {
            res.status(200).send({
                error: false,
                data: {
                    user: userDetails,
                    message: "User Authorized successfully.",
                },
            });
        }

    } catch (error) {
        next(httpErrors.Unauthorized(notAuthorized));
    }
}

const verifyVendor = async (req, res, next) => {
    try {
        const accessToken = req.body.accessToken;

        console.log(accessToken);

        const payloadData = JWT.verify(accessToken, process.env.JWT_TOKEN_SECRET_KEY);
        console.log(payloadData);

        const cachedAccessToken = await redisClient.GET(`${payloadData.agentId}`);

        console.log(cachedAccessToken);

        if (accessToken !== cachedAccessToken) {
            throw notAuthorized;
        }

        const vendorDetails = await vendorModel.findOne({
            _id: payloadData.agentId
        })

        if (res.headersSent === false) {
            res.status(200).send({
                error: false,
                data: {
                    vendor: vendorDetails,
                    message: "Vendor Authorized successfully.",
                },
            });
        }

    } catch (error) {
        next(httpErrors.Unauthorized(notAuthorized));
    }
}

const logoutUser = async (req, res, next) => {
    try {
        // Check if Payload contains appAgentId
        if (!req.user._id) {
            throw httpErrors.UnprocessableEntity(
                `JWT Refresh Token error : Missing Payload Data`
            );
        }
        // Delete Refresh Token from Redis DB
        await jwtModule
            .removeToken({
                agentId: req.user._id,
            })
            .catch((error) => {
                throw httpErrors.InternalServerError(
                    `JWT Access Token error : ${error.message}`
                );
            });

        res.status(200).send({
            error: false,
            data: {
                message: "User logged out successfully.",
            },
        });
    } catch (error) {
        next(error);
    }
}

const logoutVendor = async (req, res, next) => {
    try {
        // Check if Payload contains appAgentId
        if (!req.vendor._id) {
            throw httpErrors.UnprocessableEntity(
                `JWT Refresh Token error : Missing Payload Data`
            );
        }
        // Delete Refresh Token from Redis DB
        await jwtModule
            .removeToken({
                agentId: req.vendor._id,
            })
            .catch((error) => {
                throw httpErrors.InternalServerError(
                    `JWT Access Token error : ${error.message}`
                );
            });

        res.status(200).send({
            error: false,
            data: {
                message: "Vendor logged out successfully.",
            },
        });
    } catch (error) {
        next(error);
    }
}

module.exports = {
    createUser,
    createVendor,
    loginUser,
    loginVendor,
    logoutUser,
    logoutVendor,
    getUserFromToken,
    getVendorFromToken,
    verifyUser,
    verifyVendor
}
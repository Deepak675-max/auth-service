const joi = require('joi');

const createUserSchema = joi.object({
    name: joi.string().trim().required(),
    email: joi.string().trim().required(),
    password: joi.string().trim().required(),
    phoneNumber: joi.string().trim().required()
})

const loginUserSchema = joi.object({
    email: joi.string().trim().required(),
    password: joi.string().trim().required(),
})

const deleteUserSchema = joi.object({
    userId: joi.string().trim().required()
})

module.exports = {
    createUserSchema,
    loginUserSchema,
    deleteUserSchema
}
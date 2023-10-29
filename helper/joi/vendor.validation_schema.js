const joi = require('joi');

const createVendorSchema = joi.object({
    vendorName: joi.string().trim().required(),
    email: joi.string().trim().required(),
    password: joi.string().trim().required(),
    phoneNumber: joi.string().trim().required()
})

const loginVendorSchema = joi.object({
    email: joi.string().trim().required(),
    password: joi.string().trim().required(),
})

const deleteVendorSchema = joi.object({
    vendorId: joi.string().trim().required()
})

module.exports = {
    createVendorSchema,
    loginVendorSchema,
    deleteVendorSchema
}
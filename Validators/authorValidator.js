const { body, validationResult } = require('express-validator')

const authorBodyParams = [
    body('name')
        .notEmpty()
        .isString()
        .withMessage('Name is required and must be a string'),
    body('surname')
        .notEmpty()
        .isString()
        .withMessage('Surname is required and must be a string'),
    body('email')
        .notEmpty()
        .isString()
        .withMessage('Email is required and must be a string'),
    body('birthdate')
        .notEmpty()
        .isString()
        .withMessage('Birthdate is required and must be a string'),
    body('avatar')
        .notEmpty()
        .isString()
        .isURL()
        .withMessage('Avatar is required and must be an URL string'),
    body('password')
        .notEmpty(),   

]

const validateAuthorBody = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({errors: errors.array()})
    }

    next()
}

module.exports = {authorBodyParams, validateAuthorBody}
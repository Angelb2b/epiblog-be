const { body, validationResult } = require('express-validator')

const postBodyParams = [
    body('category')
        .notEmpty()
        .isString()
        .withMessage('Category is required and must be a string'),

    body('title')
        .notEmpty()
        .isString()
        .isLength( { min: 3 })
        .withMessage('Title is required and must be greater then 3 characters'),

    body('content')
        .notEmpty()
        .isString()
        .isLength( { min: 10 })
        .withMessage('Content is required and must be greater then 10 characters'),

    body('cover')
        .notEmpty()
        .isString()
        .isURL()
        .withMessage('Cover is required and must be an URL string'),

    body('author')
        .notEmpty()
        .isString()
        .withMessage('Author id is required and must be a string'),

    body('readTime.value')
        .notEmpty()
        .isInt()
        .withMessage('Read Time Value is required and must be a Number'),

    body('readTime.unit')
        .notEmpty()
        .isString()
        .withMessage('Read Time Unit is required and must be a String'),
    ]


const validatePostBody = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array()})
    }

    next()
}


module.exports = { postBodyParams, validatePostBody}
const express = require('express')
const mongoose = require('mongoose')
const AuthorModel = require('../models/authorModel')
const blogPostModel = require('../models/blogPostModel');
const { validateAuthorBody, authorBodyParams } = require('../Validators/authorValidator');
const bcrypt = require('bcrypt')
const verifyToken = require('../middleware/verifyToken')
const avatar = require ('../middleware/uploadAvatar')

const router = express.Router();


router.get('/authors', verifyToken ,async(req, res) => {
    try {
        const authors = await AuthorModel.find()
        .populate('posts')

        res.status(200).send({
            statusCode: 200,
            authors: authors
        })
    } catch (error) {
        res.status(500).send({
            statusCode: 500,
            message: 'Internal server Error',
            error,
        })
    }
})


router.post('/authors', avatar.single('avatar'), async(req, res) => {

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt)

    console.log(req.body)
    const newAuthor = new AuthorModel({
        name: req.body.name,
        surname: req.body.surname,
        email: req.body.email,
        password: hashedPassword,
        birthdate: req.body.birthdate,
        avatar: req.file.path,
        role: req.body.role,
    })

    try {
        const author = await newAuthor.save();
        res.status(201).send({
            statusCode: 201,
            message: 'Authors saved successfully',
            payload: author
        })
    } catch (error) {
        res.status(500).send({
            statusCode: 500,
            message: "Internal server error",
            error,
        })
    }

})

//! GET By ID
router.get('/authors/:id' ,verifyToken , async (req, res) => {
    const {id} = req.params;

    try {
        const authorById = await AuthorModel.findById(id)
        .populate({
            path: 'posts',
            populate: {
                path: 'author'
            }
        })

        if (!authorById) {
            return res.status(404).send({
                statusCode: 404,
                message: `Author with id ${id} doesn't exist`
            })
        }

        res.status(200).send({
            statusCode: 200,
            authorById
        })
    } catch (error) {
        res.status(500).send({
            statusCode: 500,
            message: "Internal server error",
            error,
        })
    }
})


//! PATCH AUTHOR AVATAR
router.patch('/authors/:id/changeAvatar', avatar.single('avatar'), async(req, res) => {
    const {id} = req.params;
    
    try {
        console.log(req.file.path)
        const dataToUpdate = req.file.path;
        const options = {new: true};
        const result = await AuthorModel.findByIdAndUpdate(id, {avatar: dataToUpdate}, options);

        res.status(200).send({
            statusCode:200,
            result
        })
    } catch (error) {
        res.status(500).send({
            statusCode: 500,
            message: "Internal server error"
        })
    }
})

//! FUNZIONE PATCH

router.patch('/authors/:id', async(req, res) => {
    const {id} = req.params;

    const authorExists = await AuthorModel.findById(id)

    if(!authorExists) {
        return res.status(404).send({
            statusCode: 404,
            message: `Author with id ${id} doesn't exist`
        })
    }

    try {
        const authorId = id;
        const dataToUpdate = req.body;
        const options = {new: true};

        const result = await AuthorModel.findByIdAndUpdate(authorId, dataToUpdate, options);

        res.status(200).send({
            statusCode: 200,
            message: `Author with id ${authorId} modified successfully`,
            result
        })
    } catch (error) {
        res.status(500).send({
            statusCode: 500,
            message: "Internal server error",
            error,
        })
    }
})

//! DELETE

router.delete('/authors/:id', verifyToken, async(req, res) => {
    const {id} = req.params;
    const authorExists = await AuthorModel.findById(id)

    if (!authorExists) {
        return res.status(404).send({
            statusCode: 404,
            message: 'Author not Found'
        })
    }

    try {
        const authorToDelete = await AuthorModel.findByIdAndDelete(id)

        res.status(200).send({
            statusCode: 200,
            message: 'Author deleted successfully',
            authorToDelete
        })
    } catch (error) {
        res.status(500).send({
            statusCode: 500,
            message: "Internal server error",
            error,
        })
    }
})


router.get('/authors/:id/blogPosts', async(req, res) => {
    const {id} = req.params;
    const findAuthor = await AuthorModel.findById(id);
    if (!findAuthor) {
        return res.status(404).send({
            statusCode: 404,
            message: 'Author not Found'
        })
    }

    try {
         const authorsPosts = await blogPostModel.find({ "author.name": findAuthor.name})

        res.status(200).send({
            statusCode: 200,
            authorsPosts
        })
    } catch (error) {
       res.status(500).send({
        statusCode:500,
        message: "Internal server error",
        error
       })
    }
})


module.exports = router;